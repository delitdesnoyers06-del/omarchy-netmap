//! Event rendering: JSON Lines for the panel, JSON for scripts, a table for
//! humans. Only this module writes to stdout, so output never interleaves.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;

use tokio::sync::mpsc::UnboundedReceiver;

use crate::diff::Diff;
use crate::model::{Event, HostRecord, MdnsRecord, Meta, PortRecord, Summary};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutputFormat {
    Human,
    JsonLines,
    Json,
}

pub struct Emitter {
    format: OutputFormat,
    quiet: bool,
    meta: Option<Meta>,
    hosts: BTreeMap<u32, HostRecord>,
    services: Vec<MdnsRecord>,
    summary: Option<Summary>,
    diffs: Vec<Diff>,
    printed_ports: HashSet<(String, u16)>,
    printed_services: HashSet<String>,
    printed_status: Option<String>,
}

impl Emitter {
    pub fn new(format: OutputFormat, quiet: bool) -> Self {
        Self {
            format,
            quiet,
            meta: None,
            hosts: BTreeMap::new(),
            services: Vec::new(),
            summary: None,
            diffs: Vec::new(),
            printed_ports: HashSet::new(),
            printed_services: HashSet::new(),
            printed_status: None,
        }
    }

    /// Consume the event stream until the sender is dropped.
    pub async fn run(mut self, mut rx: UnboundedReceiver<Event>) {
        while let Some(event) = rx.recv().await {
            self.handle(event);
        }
        self.flush();
    }

    fn handle(&mut self, event: Event) {
        match self.format {
            OutputFormat::JsonLines => self.handle_jsonl(&event),
            OutputFormat::Json => self.handle_json(&event),
            OutputFormat::Human => self.handle_human(&event),
        }
    }

    fn handle_jsonl(&mut self, event: &Event) {
        if let Ok(line) = serde_json::to_string(event) {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{line}");
            let _ = stdout.flush();
        }
    }

    fn handle_json(&mut self, event: &Event) {
        match event {
            Event::Meta(meta) => self.meta = Some(meta.clone()),
            Event::Host(host) => {
                self.hosts.insert(host.ip_num, (**host).clone());
            }
            Event::Mdns(record) => self.services.push(record.clone()),
            Event::Diff(diff) => self.diffs.push(diff.clone()),
            Event::Done(summary) => self.summary = Some(summary.clone()),
            _ => {}
        }
    }

    fn handle_human(&mut self, event: &Event) {
        match event {
            Event::Meta(meta) => {
                // A new round replaces the previous map: the report at the end
                // describes the latest scan, and the diffs describe the changes
                // between rounds.
                if meta.round > 0 {
                    self.hosts.clear();
                }
                self.meta = Some(meta.clone());
            }
            Event::Diff(diff) => {
                self.diffs.push(diff.clone());
                if self.quiet {
                    return;
                }
                for host in &diff.added_hosts {
                    eprintln!(
                        "  + {} appeared: {} ({} open ports)",
                        host.ip, host.name, host.open_ports
                    );
                }
                for port in &diff.added_ports {
                    eprintln!("  + {}:{} {} opened", port.ip, port.port, port.proto);
                }
                for host in &diff.removed_hosts {
                    eprintln!("  - {} gone: {}", host.ip, host.name);
                }
                for port in &diff.removed_ports {
                    eprintln!("  - {}:{} {} closed", port.ip, port.port, port.proto);
                }
            }
            Event::Host(host) => {
                self.hosts.insert(host.ip_num, (**host).clone());
                if self.quiet {
                    return;
                }
                // Print a line the first time a port shows up, which is the
                // live view of a scan in progress.
                for port in &host.ports {
                    let key = (host.ip.clone(), port.port);
                    if self.printed_ports.insert(key) {
                        let name = host.display_name();
                        eprintln!("  + {}:{}  {}", host.ip, port.port, describe_port(port, &name));
                    }
                }
            }
            Event::Mdns(record) => {
                self.services.push(record.clone());
                if self.quiet {
                    return;
                }
                let key = format!("{}|{}|{:?}", record.service_type, record.name, record.ip);
                if self.printed_services.insert(key) {
                    eprintln!(
                        "  + mdns {} ({}) {}:{}",
                        record.name,
                        record.service_type,
                        record.ip.clone().unwrap_or_else(|| record.host.clone()),
                        record.port
                    );
                }
            }
            Event::Status { message } => {
                if self.quiet {
                    return;
                }
                if self.printed_status.as_deref() != Some(message.as_str()) {
                    eprintln!("  . {message}");
                    self.printed_status = Some(message.clone());
                }
            }
            Event::Progress {
                done,
                total,
                alive,
                open_ports,
                elapsed_ms,
                ..
            } => {
                if self.quiet {
                    return;
                }
                let percent = if *total > 0 {
                    (*done as f64 / *total as f64) * 100.0
                } else {
                    0.0
                };
                eprint!(
                    "\r  .. {:>5.1}%  {}/{} probes  {} alive  {} open  {}   ",
                    percent,
                    done,
                    total,
                    alive,
                    open_ports,
                    crate::util::fmt_ms(*elapsed_ms)
                );
                let _ = std::io::stderr().flush();
            }
            Event::Error { message } => eprintln!("  ! {message}"),
            Event::Done(summary) => {
                self.summary = Some(summary.clone());
                if !self.quiet {
                    eprintln!();
                }
            }
        }
    }

    fn flush(&mut self) {
        match self.format {
            OutputFormat::Json => {
                let document = serde_json::json!({
                    "meta": self.meta,
                    "hosts": self.hosts.values().collect::<Vec<_>>(),
                    "services": self.services,
                    "diffs": self.diffs,
                    "summary": self.summary,
                });
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string())
                );
                let _ = stdout.flush();
            }
            OutputFormat::Human => {
                let report = render_human(
                    self.meta.as_ref(),
                    self.hosts.values().cloned().collect::<Vec<_>>().as_slice(),
                    &self.services,
                    self.summary.as_ref(),
                );
                let mut stdout = std::io::stdout().lock();
                let _ = write!(stdout, "{report}");
                let _ = stdout.flush();
            }
            OutputFormat::JsonLines => {}
        }
    }
}

fn short(value: &str, width: usize) -> String {
    let cleaned: String = value.chars().take(width).collect();
    cleaned
}

/// One-line description of an open port for the live view.
pub fn describe_port(port: &PortRecord, hostname: &str) -> String {
    let mut parts = vec![port.proto.clone()];
    if port.tls {
        parts.push("tls".to_string());
    }
    if let Some(title) = &port.title {
        parts.push(format!("{title:?}"));
    }
    if let Some(product) = &port.product {
        let version = port
            .version
            .as_ref()
            .map(|v| format!("/{v}"))
            .unwrap_or_default();
        parts.push(format!("{product}{version}"));
    } else if let Some(banner) = &port.banner {
        parts.push(short(banner, 48));
    }
    if let Some(note) = &port.note {
        parts.push(note.clone());
    }
    let _ = hostname;
    parts.join(" ")
}

fn render_human(
    meta: Option<&Meta>,
    hosts: &[HostRecord],
    services: &[MdnsRecord],
    summary: Option<&Summary>,
) -> String {
    let mut out = String::new();
    if let Some(meta) = meta {
        let iface = meta
            .interfaces
            .iter()
            .find(|i| i.is_default)
            .or_else(|| meta.interfaces.first());
        out.push_str(&format!(
            "netmap {}  {} targets x {} ports  {} concurrent  {}ms timeout  mdns={}\n",
            meta.version, meta.targets, meta.ports, meta.concurrency, meta.timeout_ms, meta.mdns
        ));
        if let Some(iface) = iface {
            out.push_str(&format!(
                "local {} {}/{} ({})  ",
                iface.name, iface.ip, iface.prefix, iface.network
            ));
        }
        if let Some(gateway) = &meta.gateway {
            out.push_str(&format!("gateway {gateway}  "));
        }
        if let Some(hostname) = &meta.hostname {
            out.push_str(&format!("host {hostname}"));
        }
        out.push('\n');
        if meta.truncated {
            out.push_str("note: target list was truncated by --max-hosts\n");
        }
        out.push('\n');
    }

    for host in hosts {
        let name = host.display_name();
        let class = host
            .class
            .as_ref()
            .map(|c| c.label.clone())
            .unwrap_or_else(|| "Host".to_string());
        let mut flags = Vec::new();
        if host.is_self {
            flags.push("this machine");
        }
        if host.is_gateway {
            flags.push("gateway");
        }
        if !host.alive {
            flags.push("no response");
        }
        let flag_text = if flags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", flags.join(", "))
        };
        out.push_str(&format!(
            "  {:<15}  {:<24}  {:<20}  {}{}\n",
            host.ip,
            short(&name, 24),
            class,
            host.mac.clone().unwrap_or_else(|| "no mac".to_string()),
            flag_text
        ));
        if let Some(vendor) = &host.vendor {
            out.push_str(&format!("      vendor {vendor}\n"));
        }
        for port in &host.ports {
            let mut detail = describe_port(port, &name);
            if port.state != "open" {
                detail.push_str(&format!(" ({})", port.state));
            }
            out.push_str(&format!("      {}/tcp  {}\n", port.port, detail));
        }
        for service in &host.services {
            out.push_str(&format!(
                "      mdns   {} ({}){}\n",
                service.name,
                service.service_type,
                if service.port > 0 {
                    format!(" port {}", service.port)
                } else {
                    String::new()
                }
            ));
        }
    }

    let orphan: Vec<&MdnsRecord> = services
        .iter()
        .filter(|service| service.ip.is_none())
        .collect();
    if !orphan.is_empty() {
        out.push_str("\n  mDNS services without an IPv4 address:\n");
        for service in orphan {
            out.push_str(&format!(
                "      {:<24} {:<28} {}\n",
                short(&service.name, 24),
                service.service_type,
                service.host
            ));
        }
    }

    if let Some(summary) = summary {
        out.push_str(&format!(
            "\n{} hosts ({} alive), {} open ports, {} mDNS services in {}\n",
            summary.hosts,
            summary.alive,
            summary.open_ports,
            summary.services,
            crate::util::fmt_ms(summary.elapsed_ms)
        ));
        if !summary.classes.is_empty() {
            let classes: Vec<String> = summary
                .classes
                .iter()
                .map(|(label, count)| format!("{label} x{count}"))
                .collect();
            out.push_str(&format!("{}\n", classes.join(", ")));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(n: u16, proto: &str) -> PortRecord {
        PortRecord {
            port: n,
            service: proto.into(),
            proto: proto.into(),
            state: "open".into(),
            tls: false,
            banner: None,
            product: None,
            version: None,
            title: None,
            server: None,
            url: None,
            status: None,
            note: None,
            rtt_ms: None,
        }
    }

    #[test]
    fn human_diff_lines_are_written() {
        // The diff arm must not panic on any of the four kinds.
        let diff = Diff {
            added_hosts: vec![crate::diff::DiffHost {
                ip: "10.0.0.1".into(),
                name: "lamp".into(),
                class: "IoT device".into(),
                open_ports: 1,
            }],
            removed_ports: vec![crate::diff::DiffPort {
                ip: "10.0.0.2".into(),
                port: 445,
                proto: "microsoft-ds".into(),
                service: "microsoft-ds".into(),
            }],
            ..Default::default()
        };
        let mut emitter = Emitter::new(OutputFormat::Human, true);
        emitter.handle(Event::Diff(diff));
        assert_eq!(emitter.diffs.len(), 1);
    }

    #[test]
    fn describes_ports() {
        let mut record = port(80, "http");
        record.product = Some("nginx".into());
        record.version = Some("1.24.0".into());
        record.title = Some("Router admin".into());
        let text = describe_port(&record, "gw");
        assert!(text.contains("http"));
        assert!(text.contains("nginx/1.24.0"));
        assert!(text.contains("Router admin"));
    }

    #[test]
    fn renders_a_report() {
        let mut host = HostRecord::new(std::net::Ipv4Addr::new(192, 168, 1, 1));
        host.is_gateway = true;
        host.alive = true;
        host.mac = Some("aa:bb:cc:dd:ee:ff".into());
        host.set_port(port(80, "http"));
        host.class = Some(crate::classify::classify(&host));
        let report = render_human(None, &[host], &[], None);
        assert!(report.contains("192.168.1.1"));
        assert!(report.contains("80/tcp"));
        assert!(report.contains("gateway"));
    }
}
