//! The data model that both the JSON stream and the human report render from.
//!
//! The stream is a sequence of upserts: every event that changes a host emits
//! the whole host record, so a consumer can replace it by IP without keeping
//! its own merge logic. That is what lets the Quickshell panel update live
//! while a scan is still running.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::util::{now_ms, u32_to_ip};

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct DeviceClass {
    pub key: String,
    pub label: String,
    pub glyph: String,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct PortRecord {
    pub port: u16,
    /// Canonical service name for the port number.
    pub service: String,
    /// Protocol actually observed, which can differ from the port default.
    pub proto: String,
    pub state: String,
    pub tls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Free-form probe note, e.g. "TLS handshake ok" or "redirects to https".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct MdnsRecord {
    /// Instance name, e.g. "Living Room".
    pub name: String,
    /// Service type, e.g. "_airplay._tcp.local.".
    pub service_type: String,
    pub port: u16,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub txt: BTreeMap<String, String>,
    /// "mdns" for the native browser, "avahi" for the avahi-browse fallback.
    pub source: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct HostRecord {
    pub ip: String,
    #[serde(skip)]
    pub ip_num: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    pub is_gateway: bool,
    pub is_self: bool,
    /// True when something answered on this address (TCP accept or refuse).
    pub alive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    /// Best display name first.
    pub names: Vec<String>,
    /// Every signal that contributed: arp, mdns, tcp, netbios, self, neighbor.
    pub sources: Vec<String>,
    pub open_ports: usize,
    pub ports: Vec<PortRecord>,
    /// The URL of the most likely web UI, when one is listening. The panel's
    /// primary action is "open this"; it must be in the JSON, not just a Rust
    /// helper.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_url: Option<String>,
    /// Port of the ssh service, when one is listening.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,
    pub services: Vec<MdnsRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<DeviceClass>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

impl HostRecord {
    pub fn new(ip: std::net::Ipv4Addr) -> Self {
        let now = now_ms();
        Self {
            ip: ip.to_string(),
            ip_num: u32::from(ip),
            mac: None,
            vendor: None,
            iface: None,
            is_gateway: false,
            is_self: false,
            alive: false,
            rtt_ms: None,
            names: Vec::new(),
            sources: Vec::new(),
            open_ports: 0,
            ports: Vec::new(),
            web_url: None,
            ssh_port: None,
            services: Vec::new(),
            class: None,
            first_seen_ms: now,
            last_seen_ms: now,
        }
    }

    /// Record a source of evidence. True when it was not already known.
    pub fn add_source(&mut self, source: &str) -> bool {
        if self.sources.iter().any(|s| s == source) {
            return false;
        }
        self.sources.push(source.to_string());
        self.sources.sort();
        true
    }

    /// Add a hostname alias. True when it was not already known.
    pub fn add_name(&mut self, name: &str) -> bool {
        let name = name.trim().trim_end_matches('.').to_string();
        if name.is_empty() || name == self.ip {
            return false;
        }
        if self.names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
            return false;
        }
        self.names.push(name);
        // Prefer dotted names over bare NetBIOS names, shortest first.
        self.names.sort_by_key(|n| {
            let has_dot = if n.contains('.') { 0 } else { 1 };
            (has_dot, n.len())
        });
        true
    }

    pub fn display_name(&self) -> String {
        self.names
            .first()
            .cloned()
            .or_else(|| self.vendor.clone())
            .unwrap_or_else(|| self.ip.clone())
    }

    /// Insert or replace a port record. Returns true when the record changed,
    /// which is the signal to re-emit the host.
    pub fn set_port(&mut self, record: PortRecord) -> bool {
        match self.ports.iter_mut().find(|p| p.port == record.port) {
            Some(existing) => {
                if *existing == record {
                    false
                } else {
                    *existing = record;
                    self.open_ports = self.ports.len();
                    self.refresh_actions();
                    true
                }
            }
            None => {
                self.ports.push(record);
                self.ports.sort_by_key(|p| p.port);
                self.open_ports = self.ports.len();
                self.refresh_actions();
                true
            }
        }
    }

    /// Keep the derived "what can I do with this host" fields in step with the
    /// port list. Called from set_port, so the JSON is always current.
    fn refresh_actions(&mut self) {
        self.web_url = self
            .ports
            .iter()
            .filter(|port| port.url.is_some())
            .min_by_key(|port| web_rank(port.port))
            .and_then(|port| port.url.clone());
        self.ssh_port = self
            .ports
            .iter()
            .find(|port| {
                port.proto == "ssh" || port.service == "ssh" || port.service == "ssh-alt"
            })
            .map(|port| port.port);
    }

    pub fn add_mdns(&mut self, record: MdnsRecord) -> bool {
        let key = format!("{}|{}", record.service_type, record.name);
        if self
            .services
            .iter()
            .any(|s| format!("{}|{}", s.service_type, s.name) == key)
        {
            return false;
        }
        self.services.push(record);
        self.services
            .sort_by(|a, b| (a.service_type.clone(), a.name.clone()).cmp(&(b.service_type.clone(), b.name.clone())));
        true
    }

    pub fn protos(&self) -> BTreeSet<String> {
        self.ports.iter().map(|p| p.proto.clone()).collect()
    }
}

/// Lower is more likely to be the device's main web UI.
fn web_rank(port: u16) -> u16 {
    match port {
        443 | 8443 | 9443 => 0,
        80 => 1,
        8080 | 8000 | 8888 => 2,
        5000 | 5001 | 8123 | 8096 | 32400 => 3,
        other => 100 + other,
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct IfaceInfo {
    pub name: String,
    pub ip: String,
    pub prefix: u8,
    pub network: String,
    pub mac: Option<String>,
    pub is_default: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct Meta {
    pub version: String,
    pub tool: String,
    pub hostname: Option<String>,
    pub started_ms: u64,
    /// 0 for a one-shot scan; incremented per round in watch mode, so a
    /// consumer can tell a fresh scan from the next round of a running one.
    pub round: u32,
    pub interfaces: Vec<IfaceInfo>,
    pub targets: usize,
    pub ports: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub mdns: String,
    pub gateway: Option<String>,
    pub truncated: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct Summary {
    pub elapsed_ms: u64,
    pub hosts: usize,
    pub alive: usize,
    pub open_ports: usize,
    pub services: usize,
    pub classes: BTreeMap<String, usize>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Meta(Meta),
    Host(Box<HostRecord>),
    Mdns(MdnsRecord),
    /// What changed since the previous round. Only emitted in watch mode, and
    /// only when something actually changed.
    Diff(crate::diff::Diff),
    Progress {
        phase: String,
        done: u64,
        total: u64,
        alive: usize,
        open_ports: usize,
        elapsed_ms: u64,
    },
    Status {
        message: String,
    },
    Error {
        message: String,
    },
    Done(Summary),
}

/// Mutable map state, owned behind a mutex by the scan driver.
pub struct MapState {
    pub hosts: BTreeMap<u32, HostRecord>,
    pub mdns: Vec<MdnsRecord>,
    gateway: Option<u32>,
    self_ips: Vec<u32>,
}

impl MapState {
    pub fn new(gateway: Option<std::net::Ipv4Addr>, self_ips: Vec<std::net::Ipv4Addr>) -> Self {
        Self {
            hosts: BTreeMap::new(),
            mdns: Vec::new(),
            gateway: gateway.map(u32::from),
            self_ips: self_ips.into_iter().map(u32::from).collect(),
        }
    }

    /// Mutate (creating if needed) the record for ip. Returns a snapshot when
    /// emit is true so the caller can push it onto the event stream.
    pub fn update<F>(&mut self, ip: std::net::Ipv4Addr, emit: bool, f: F) -> Option<HostRecord>
    where
        F: FnOnce(&mut HostRecord),
    {
        let key = u32::from(ip);
        let record = self
            .hosts
            .entry(key)
            .or_insert_with(|| HostRecord::new(ip));
        record.last_seen_ms = now_ms();
        if let Some(gw) = self.gateway {
            record.is_gateway = key == gw;
        }
        record.is_self = self.self_ips.contains(&key);
        f(record);
        if emit {
            Some(record.clone())
        } else {
            None
        }
    }

    /// This machine's own interface addresses.
    pub fn self_ips(&self) -> Vec<std::net::Ipv4Addr> {
        self.self_ips.iter().map(|value| u32_to_ip(*value)).collect()
    }

    pub fn get(&self, ip: std::net::Ipv4Addr) -> Option<&HostRecord> {
        self.hosts.get(&u32::from(ip))
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn alive_count(&self) -> usize {
        self.hosts.values().filter(|h| h.alive).count()
    }

    pub fn open_port_count(&self) -> usize {
        self.hosts.values().map(|h| h.open_ports).sum()
    }

    /// Hosts ordered for display: gateway first, then by IP.
    pub fn ordered(&self) -> Vec<HostRecord> {
        let mut all: Vec<HostRecord> = self.hosts.values().cloned().collect();
        all.sort_by_key(|h| {
            let gateway = if h.is_gateway { 0 } else { 1 };
            (gateway, h.ip_num)
        });
        all
    }

    pub fn set_mdns(&mut self, records: Vec<MdnsRecord>) {
        self.mdns = records;
    }

    pub fn mdns_records(&self) -> &[MdnsRecord] {
        &self.mdns
    }

    pub fn gateway_ip(&self) -> Option<String> {
        self.gateway.map(u32_to_ip).map(|ip| ip.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn port(n: u16, proto: &str, url: Option<&str>) -> PortRecord {
        PortRecord {
            port: n,
            service: proto.to_string(),
            proto: proto.to_string(),
            state: "open".into(),
            tls: false,
            banner: None,
            product: None,
            version: None,
            title: None,
            server: None,
            url: url.map(|u| u.to_string()),
            status: None,
            note: None,
            rtt_ms: Some(1.0),
        }
    }

    #[test]
    fn diff_events_serialise_with_a_type_tag() {
        let diff = crate::diff::Diff {
            added_hosts: vec![crate::diff::DiffHost {
                ip: "10.0.0.9".into(),
                name: "lamp.local".into(),
                class: "IoT device".into(),
                open_ports: 1,
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(Event::Diff(diff)).expect("serialises");
        assert_eq!(json["type"], "diff");
        assert_eq!(json["added_hosts"][0]["ip"], "10.0.0.9");
        // Empty vectors are skipped, so a consumer never sees noise keys.
        assert!(json.get("removed_hosts").is_none());
    }

    #[test]
    fn port_upsert_is_idempotent() {
        let mut host = HostRecord::new(Ipv4Addr::new(10, 0, 0, 1));
        assert!(host.set_port(port(80, "http", Some("http://10.0.0.1/"))));
        assert!(!host.set_port(port(80, "http", Some("http://10.0.0.1/"))));
        assert!(host.set_port(port(22, "ssh", None)));
        assert_eq!(host.open_ports, 2);
        assert_eq!(host.ports[0].port, 22);
        assert_eq!(host.ssh_port, Some(22));
        assert_eq!(host.web_url.as_deref(), Some("http://10.0.0.1/"));
    }

    #[test]
    fn prefers_the_main_web_port() {
        let mut host = HostRecord::new(Ipv4Addr::new(10, 0, 0, 2));
        host.set_port(port(8080, "http", Some("http://10.0.0.2:8080/")));
        assert_eq!(host.web_url.as_deref(), Some("http://10.0.0.2:8080/"));
        host.set_port(port(443, "https", Some("https://10.0.0.2/")));
        assert_eq!(host.web_url.as_deref(), Some("https://10.0.0.2/"));
    }

    #[test]
    fn action_fields_are_in_the_json() {
        let mut host = HostRecord::new(Ipv4Addr::new(10, 0, 0, 7));
        host.set_port(port(22, "ssh", None));
        host.set_port(port(80, "http", Some("http://10.0.0.7/")));
        assert_eq!(host.ssh_port, Some(22));
        let json = serde_json::to_string(&host).expect("serialises");
        assert!(json.contains("\"web_url\":\"http://10.0.0.7/\""), "json: {json}");
        assert!(json.contains("\"ssh_port\":22"), "json: {json}");
        // A host with neither must not carry empty keys the panel would read.
        let bare = HostRecord::new(Ipv4Addr::new(10, 0, 0, 8));
        let bare_json = serde_json::to_string(&bare).expect("serialises");
        assert!(!bare_json.contains("web_url"));
        assert!(!bare_json.contains("ssh_port"));
    }

    #[test]
    fn names_prefer_dotted_and_dedupe() {
        let mut host = HostRecord::new(Ipv4Addr::new(10, 0, 0, 3));
        assert!(host.add_name("DESKTOP-ABC"));
        assert!(host.add_name("desktop-abc.local"));
        assert!(!host.add_name("Desktop-ABC.local"));
        assert!(host.add_source("arp"));
        assert!(!host.add_source("arp"));
        assert_eq!(host.display_name(), "desktop-abc.local");
        assert_eq!(host.names.len(), 2);
    }

    #[test]
    fn map_ordering_puts_gateway_first() {
        let mut map = MapState::new(Some(Ipv4Addr::new(10, 0, 0, 1)), vec![]);
        map.update(Ipv4Addr::new(10, 0, 0, 9), false, |h| h.alive = true);
        map.update(Ipv4Addr::new(10, 0, 0, 1), false, |h| h.alive = true);
        map.update(Ipv4Addr::new(10, 0, 0, 5), false, |h| h.alive = true);
        let ordered = map.ordered();
        assert_eq!(ordered[0].ip, "10.0.0.1");
        assert!(ordered[0].is_gateway);
        assert_eq!(map.alive_count(), 3);
        assert_eq!(ordered[1].ip, "10.0.0.5");
    }
}
