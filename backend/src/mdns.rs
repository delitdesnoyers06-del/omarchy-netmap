//! mDNS / DNS-SD discovery.
//!
//! Two independent implementations run in parallel on purpose:
//!   * a native browser (mdns-sd binds 5353 and joins the multicast group);
//!   * avahi-browse, which asks the system daemon over D-Bus.
//! On a desktop with avahi already running, either one can be the one that
//! works - a second 5353 socket sometimes only sees its own traffic. Records
//! are deduplicated by (type, instance, address) so running both costs
//! nothing but a few milliseconds.
//!
//! The meta query (_services._dns-sd._udp.local.) enumerates whatever service
//! types the LAN actually advertises, and each discovered type is browsed in
//! turn, so a device announcing something unusual is still found.

use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::UnboundedSender;

use crate::model::MdnsRecord;
use crate::util;

/// Meta query: returns the service types advertised on the link.
pub const META_QUERY: &str = "_services._dns-sd._udp.local.";

/// Service types browsed up front, before (and in case) the meta query answers.
pub static SEED_TYPES: &[&str] = &[
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_sftp-ssh._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_nfs._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_sonos._tcp.local.",
    "_hap._tcp.local.",
    "_homekit._tcp.local.",
    "_home-assistant._tcp.local.",
    "_esphomelib._tcp.local.",
    "_apple-mobdev2._tcp.local.",
    "_companion-link._tcp.local.",
    "_sleep-proxy._udp.local.",
    "_rdlink._tcp.local.",
    "_rfb._tcp.local.",
    "_telnet._tcp.local.",
    "_ftp._tcp.local.",
    "_mqtt._tcp.local.",
    "_coap._udp.local.",
    "_matter._tcp.local.",
    "_http-alt._tcp.local.",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MdnsMode {
    /// Native browser plus avahi when available (the default).
    Auto,
    /// Native browser only.
    Native,
    /// avahi-browse only.
    Avahi,
    Off,
}

impl MdnsMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" | "both" | "on" | "true" => Some(MdnsMode::Auto),
            "native" | "mdns" | "mdns-sd" => Some(MdnsMode::Native),
            "avahi" | "dbus" => Some(MdnsMode::Avahi),
            "off" | "none" | "false" | "no" => Some(MdnsMode::Off),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MdnsMode::Auto => "auto",
            MdnsMode::Native => "native",
            MdnsMode::Avahi => "avahi",
            MdnsMode::Off => "off",
        }
    }
}

/// Called for every resolved service, from either implementation.
pub type RecordSink = Arc<dyn Fn(MdnsRecord) + Send + Sync>;

/// Strip the type suffix off a full service name: "Living Room" out of
/// "Living Room._airplay._tcp.local.".
pub fn instance_name(fullname: &str, ty_domain: &str) -> String {
    let trimmed = fullname.trim_end_matches('.');
    let ty = ty_domain.trim_end_matches('.');
    trimmed
        .strip_suffix(ty)
        .map(|rest| rest.trim_end_matches('.').to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| trimmed.to_string())
}

/// Normalise a service type into "_x._tcp.local." form.
pub fn canonical_type(ty: &str) -> String {
    let ty = ty.trim_matches('.').to_ascii_lowercase();
    if ty.is_empty() {
        return String::new();
    }
    if ty.starts_with('_') {
        format!("{ty}.")
    } else {
        format!("_{ty}._tcp.local.")
    }
}

/// Run discovery for the given duration, calling the sink for every resolved
/// service. Returns which implementations ran, for the report and status line.
pub async fn discover(mode: MdnsMode, duration: Duration, sink: RecordSink) -> String {
    if mode == MdnsMode::Off {
        return "off".to_string();
    }

    // Deduplicate across implementations before anything downstream sees it.
    let seen: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let deduped_sink: RecordSink = {
        let seen = seen.clone();
        let sink = sink.clone();
        Arc::new(move |record: MdnsRecord| {
            let key = format!(
                "{}|{}|{}",
                record.service_type,
                record.name,
                record.ip.clone().unwrap_or_default()
            );
            let fresh = seen.lock().map(|mut set| set.insert(key)).unwrap_or(true);
            if fresh {
                sink(record);
            }
        })
    };

    let want_native = matches!(mode, MdnsMode::Auto | MdnsMode::Native);
    let want_avahi = matches!(mode, MdnsMode::Auto | MdnsMode::Avahi)
        && util::find_on_path("avahi-browse").is_some();

    match (want_native, want_avahi) {
        (true, true) => {
            let (native, avahi) = tokio::join!(
                native_browse(duration, deduped_sink.clone()),
                avahi_browse(duration, deduped_sink.clone())
            );
            match (native, avahi) {
                (true, true) => "mdns+avahi".to_string(),
                (true, false) => "mdns".to_string(),
                (false, true) => "avahi".to_string(),
                (false, false) => "unavailable".to_string(),
            }
        }
        (true, false) => {
            if native_browse(duration, deduped_sink.clone()).await {
                "mdns".to_string()
            } else {
                "unavailable".to_string()
            }
        }
        (false, true) => {
            if avahi_browse(duration, deduped_sink.clone()).await {
                "avahi".to_string()
            } else {
                "unavailable".to_string()
            }
        }
        (false, false) => "unavailable".to_string(),
    }
}

fn subscribe(daemon: &ServiceDaemon, service_type: &str, tx: &UnboundedSender<ServiceEvent>) -> bool {
    match daemon.browse(service_type) {
        Ok(receiver) => {
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Ok(event) = receiver.recv_async().await {
                    if tx.send(event).is_err() {
                        break;
                    }
                }
            });
            true
        }
        Err(_) => false,
    }
}

/// Native DNS-SD browser. False when the daemon could not bind at all.
async fn native_browse(duration: Duration, sink: RecordSink) -> bool {
    let Ok(daemon) = ServiceDaemon::new() else {
        return false;
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ServiceEvent>();

    let mut browsed: HashSet<String> = HashSet::new();
    if subscribe(&daemon, META_QUERY, &tx) {
        browsed.insert(META_QUERY.to_string());
    }
    for service_type in SEED_TYPES {
        if subscribe(&daemon, service_type, &tx) {
            browsed.insert((*service_type).to_string());
        }
    }

    let deadline = Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let event = match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(event)) => event,
            _ => break,
        };
        match event {
            ServiceEvent::ServiceFound(service_type, fullname) => {
                // The meta query answers with the service type as the instance
                // name, which is how new types are discovered on the fly.
                if service_type == META_QUERY {
                    let discovered = canonical_type(fullname.trim_end_matches('.'));
                    if !discovered.is_empty() && browsed.insert(discovered.clone()) {
                        subscribe(&daemon, &discovered, &tx);
                    }
                }
            }
            ServiceEvent::ServiceResolved(resolved) => {
                let addresses: Vec<Ipv4Addr> = resolved.get_addresses_v4().into_iter().collect();
                let txt: BTreeMap<String, String> = resolved
                    .txt_properties
                    .clone()
                    .into_property_map_str()
                    .into_iter()
                    .collect();
                let name = instance_name(&resolved.fullname, &resolved.ty_domain);
                let record = |ip: Option<String>| MdnsRecord {
                    name: name.clone(),
                    service_type: resolved.ty_domain.clone(),
                    port: resolved.port,
                    host: resolved.host.clone(),
                    ip,
                    txt: txt.clone(),
                    source: "mdns".to_string(),
                };
                if addresses.is_empty() {
                    sink(record(None));
                } else {
                    for ip in addresses {
                        sink(record(Some(ip.to_string())));
                    }
                }
            }
            _ => {}
        }
    }
    let _ = daemon.shutdown();
    true
}

/// avahi-browse fallback: the system daemon already holds 5353, so asking it
/// over D-Bus is the reliable path when a second socket would see nothing.
async fn avahi_browse(duration: Duration, sink: RecordSink) -> bool {
    let mut child = match Command::new("avahi-browse")
        .args(["-arp", "--no-db-lookup", "-l"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return false,
    };
    let Some(stdout) = child.stdout.take() else {
        return false;
    };
    let mut lines = BufReader::new(stdout).lines();
    let deadline = Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Some(record) = parse_avahi_line(&line) {
                    sink(record);
                }
            }
            _ => break,
        }
    }
    let _ = child.kill().await;
    true
}

/// Undo avahi's parsable-output escaping. avahi prints each escaped byte as a
/// backslash followed by three DECIMAL digits (a space is \032), not octal.
pub fn unescape_avahi(value: &str) -> String {
    let bytes: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == '\\' && index + 3 < bytes.len() {
            let digits: String = bytes[index + 1..index + 4].iter().collect();
            if let Ok(code) = u8::from_str_radix(&digits, 10) {
                out.push(code as char);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// Parse one resolved (line starting with "=") avahi-browse -p record.
pub fn parse_avahi_line(line: &str) -> Option<MdnsRecord> {
    if !line.starts_with('=') {
        return None;
    }
    let parts: Vec<&str> = line.splitn(10, ';').collect();
    if parts.len() < 10 || parts[2] != "IPv4" {
        return None;
    }
    let ip = parts[7];
    if ip.parse::<Ipv4Addr>().is_err() {
        return None;
    }
    let mut txt = BTreeMap::new();
    for entry in parts[9].trim_matches('"').split("\" \"") {
        let entry = unescape_avahi(entry);
        if entry.trim().is_empty() {
            continue;
        }
        match entry.split_once('=') {
            Some((key, value)) => {
                txt.insert(key.to_string(), value.to_string());
            }
            None => {
                txt.insert(entry, String::new());
            }
        }
    }
    // avahi splits the type and the domain into separate fields; DNS-SD
    // consumers (and the classifier) expect the fully qualified form.
    let domain = parts[5].trim();
    let service_type = if domain.is_empty() {
        format!("{}.", parts[4].trim())
    } else {
        format!("{}.{}.", parts[4].trim(), domain)
    };
    Some(MdnsRecord {
        name: unescape_avahi(parts[3]),
        service_type,
        port: parts[8].parse().unwrap_or(0),
        host: parts[6].to_string(),
        ip: Some(ip.to_string()),
        txt,
        source: "avahi".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_avahi_records() {
        let line = "=;wlan0;IPv4;Living\\032Room;_airplay._tcp;local;appletv.local;192.168.1.20;7000;\"model=AppleTV6,2\"";
        let record = parse_avahi_line(line).expect("record");
        assert_eq!(record.name, "Living Room");
        assert_eq!(record.service_type, "_airplay._tcp.local.");
        assert_eq!(record.ip.as_deref(), Some("192.168.1.20"));
        assert_eq!(record.port, 7000);
        assert_eq!(record.txt.get("model").map(|v| v.as_str()), Some("AppleTV6,2"));
        assert_eq!(record.source, "avahi");
    }

    #[test]
    fn ignores_other_avahi_lines() {
        assert!(parse_avahi_line("+;wlan0;IPv4;Name;_http._tcp;local").is_none());
        assert!(parse_avahi_line("=;wlan0;IPv6;Name;_http._tcp;local;host;::1;80;**").is_none());
    }

    #[test]
    fn instance_names() {
        assert_eq!(
            instance_name("Living Room._airplay._tcp.local.", "_airplay._tcp.local."),
            "Living Room"
        );
        assert_eq!(
            instance_name("printer._ipp._tcp.local.", "_ipp._tcp.local."),
            "printer"
        );
    }

    #[test]
    fn canonical_types() {
        assert_eq!(canonical_type("_http._tcp.local."), "_http._tcp.local.");
        assert_eq!(canonical_type("_http._tcp"), "_http._tcp.");
    }

    #[test]
    fn unescapes_decimal_escapes() {
        assert_eq!(unescape_avahi("Living\\032Room"), "Living Room");
        assert_eq!(unescape_avahi("plain"), "plain");
        assert_eq!(unescape_avahi("a\\044b"), "a,b");
        assert_eq!(unescape_avahi("trailing\\"), "trailing\\");
    }

    #[test]
    fn parses_modes() {
        assert_eq!(MdnsMode::parse("off"), Some(MdnsMode::Off));
        assert_eq!(MdnsMode::parse("avahi"), Some(MdnsMode::Avahi));
        assert_eq!(MdnsMode::parse("nope"), None);
    }
}
