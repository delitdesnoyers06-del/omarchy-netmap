//! Snapshot and diff between two consecutive scans.
//!
//! The watch loop keeps the snapshot of the last scan and calls [`diff`] with
//! the snapshot of the new one. Only what changed is reported: a host that
//! appeared or vanished (carrying the name, class and port count of the side
//! that saw it), and ports that opened or closed on hosts that stayed. A brand
//! new host is reported once, as a host, never repeated as a burst of ports.

use std::collections::BTreeMap;

use crate::model::MapState;

/// A cheap, comparable view of one scan. A host is present when it is alive or
/// has at least one port, so dead ARP-only records stay out of the diff.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    hosts: BTreeMap<u32, SnapshotHost>,
}

#[derive(Clone, Debug)]
struct SnapshotHost {
    ip: String,
    name: String,
    class: String,
    /// port number -> (proto, service)
    ports: BTreeMap<u16, (String, String)>,
}

impl SnapshotHost {
    fn diff_host(&self) -> DiffHost {
        DiffHost {
            ip: self.ip.clone(),
            name: self.name.clone(),
            class: self.class.clone(),
            open_ports: self.ports.len(),
        }
    }
}

/// Capture every present host of a map, ordered by numeric address.
pub fn snapshot(map: &MapState) -> Snapshot {
    let mut hosts: BTreeMap<u32, SnapshotHost> = BTreeMap::new();
    for record in map.hosts.values() {
        if !record.alive && record.ports.is_empty() {
            continue;
        }
        let mut ports: BTreeMap<u16, (String, String)> = BTreeMap::new();
        for port in &record.ports {
            ports.insert(port.port, (port.proto.clone(), port.service.clone()));
        }
        hosts.insert(
            record.ip_num,
            SnapshotHost {
                ip: record.ip.clone(),
                name: record.display_name(),
                class: record
                    .class
                    .as_ref()
                    .map(|c| c.label.clone())
                    .unwrap_or_default(),
                ports,
            },
        );
    }
    Snapshot { hosts }
}

impl Snapshot {
    /// Number of present hosts.
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

#[derive(serde::Serialize, Clone, Debug, Default, PartialEq)]
pub struct DiffPort {
    pub ip: String,
    pub port: u16,
    pub proto: String,
    pub service: String,
}

#[derive(serde::Serialize, Clone, Debug, Default, PartialEq)]
pub struct DiffHost {
    pub ip: String,
    pub name: String,
    pub class: String,
    pub open_ports: usize,
}

#[derive(serde::Serialize, Clone, Debug, Default, PartialEq)]
pub struct Diff {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub added_hosts: Vec<DiffHost>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub removed_hosts: Vec<DiffHost>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub added_ports: Vec<DiffPort>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub removed_ports: Vec<DiffPort>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.added_hosts.is_empty()
            && self.removed_hosts.is_empty()
            && self.added_ports.is_empty()
            && self.removed_ports.is_empty()
    }
}

/// What changed between two snapshots. Ordering is deterministic: hosts by
/// numeric address, ports by address then port number. Ports are reported only
/// for hosts present in both snapshots, so a host that appeared or vanished is
/// listed once as a host and its ports are never repeated.
pub fn diff(previous: &Snapshot, current: &Snapshot) -> Diff {
    let mut out = Diff::default();

    for (ip_num, host) in &previous.hosts {
        if !current.hosts.contains_key(ip_num) {
            out.removed_hosts.push(host.diff_host());
        }
    }
    for (ip_num, host) in &current.hosts {
        if !previous.hosts.contains_key(ip_num) {
            out.added_hosts.push(host.diff_host());
        }
    }

    for (ip_num, now) in &current.hosts {
        let Some(before) = previous.hosts.get(ip_num) else {
            continue;
        };
        for (port, (proto, service)) in &now.ports {
            if !before.ports.contains_key(port) {
                out.added_ports.push(DiffPort {
                    ip: now.ip.clone(),
                    port: *port,
                    proto: proto.clone(),
                    service: service.clone(),
                });
            }
        }
        for (port, (proto, service)) in &before.ports {
            if !now.ports.contains_key(port) {
                out.removed_ports.push(DiffPort {
                    ip: before.ip.clone(),
                    port: *port,
                    proto: proto.clone(),
                    service: service.clone(),
                });
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MapState, PortRecord};
    use std::net::Ipv4Addr;

    fn port(n: u16, proto: &str) -> PortRecord {
        PortRecord {
            port: n,
            service: proto.to_string(),
            proto: proto.to_string(),
            state: "open".to_string(),
            tls: false,
            banner: None,
            product: None,
            version: None,
            title: None,
            server: None,
            url: None,
            status: None,
            note: None,
            rtt_ms: Some(1.0),
        }
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn alive_host(map: &mut MapState, addr: Ipv4Addr, ports: &[(u16, &str)]) {
        map.update(addr, false, |host| {
            host.alive = true;
            for (n, proto) in ports {
                host.set_port(port(*n, proto));
            }
        });
    }

    #[test]
    fn brand_new_host_is_added_once() {
        let previous = snapshot(&MapState::new(None, vec![]));
        let mut current = MapState::new(None, vec![]);
        alive_host(&mut current, ip(10, 0, 0, 5), &[(80, "http")]);

        let d = diff(&previous, &snapshot(&current));
        assert_eq!(d.added_hosts.len(), 1);
        assert_eq!(d.added_hosts[0].ip, "10.0.0.5");
        assert_eq!(d.added_hosts[0].open_ports, 1);
        assert!(d.removed_hosts.is_empty());
        assert!(d.added_ports.is_empty());
        assert!(d.removed_ports.is_empty());
    }

    #[test]
    fn vanished_host_is_removed_with_previous_details() {
        let mut previous = MapState::new(None, vec![]);
        previous.update(ip(10, 0, 0, 9), false, |host| {
            host.alive = true;
            host.add_name("old-box.local");
            host.set_port(port(22, "ssh"));
        });
        let current = MapState::new(None, vec![]);

        let d = diff(&snapshot(&previous), &snapshot(&current));
        assert_eq!(d.removed_hosts.len(), 1);
        assert_eq!(d.removed_hosts[0].ip, "10.0.0.9");
        assert_eq!(d.removed_hosts[0].name, "old-box.local");
        assert_eq!(d.removed_hosts[0].open_ports, 1);
        assert!(d.added_hosts.is_empty());
        assert!(d.removed_ports.is_empty());
    }

    #[test]
    fn new_port_on_existing_host() {
        let mut previous = MapState::new(None, vec![]);
        alive_host(&mut previous, ip(10, 0, 0, 2), &[(80, "http")]);
        let mut current = MapState::new(None, vec![]);
        alive_host(&mut current, ip(10, 0, 0, 2), &[(80, "http"), (22, "ssh")]);

        let d = diff(&snapshot(&previous), &snapshot(&current));
        assert!(d.added_hosts.is_empty());
        assert!(d.removed_hosts.is_empty());
        assert_eq!(d.added_ports.len(), 1);
        assert_eq!(d.added_ports[0].ip, "10.0.0.2");
        assert_eq!(d.added_ports[0].port, 22);
        assert_eq!(d.added_ports[0].proto, "ssh");
        assert!(d.removed_ports.is_empty());
    }

    #[test]
    fn closed_port_on_existing_host() {
        let mut previous = MapState::new(None, vec![]);
        alive_host(&mut previous, ip(10, 0, 0, 3), &[(80, "http"), (22, "ssh")]);
        let mut current = MapState::new(None, vec![]);
        alive_host(&mut current, ip(10, 0, 0, 3), &[(80, "http")]);

        let d = diff(&snapshot(&previous), &snapshot(&current));
        assert!(d.added_hosts.is_empty());
        assert!(d.removed_hosts.is_empty());
        assert!(d.added_ports.is_empty());
        assert_eq!(d.removed_ports.len(), 1);
        assert_eq!(d.removed_ports[0].ip, "10.0.0.3");
        assert_eq!(d.removed_ports[0].port, 22);
        assert_eq!(d.removed_ports[0].service, "ssh");
    }

    #[test]
    fn identical_snapshots_produce_default() {
        let mut map = MapState::new(None, vec![]);
        alive_host(&mut map, ip(10, 0, 0, 4), &[(80, "http"), (443, "https")]);

        let a = snapshot(&map);
        let b = snapshot(&map);
        assert_eq!(a.len(), 1);
        assert!(!a.is_empty());

        let d = diff(&a, &b);
        assert_eq!(d, Diff::default());
        assert!(d.is_empty());
    }

    #[test]
    fn appearing_host_with_ports_is_not_repeated_as_ports() {
        let previous = snapshot(&MapState::new(None, vec![]));
        let mut current = MapState::new(None, vec![]);
        alive_host(&mut current, ip(10, 0, 0, 6), &[(22, "ssh"), (80, "http")]);

        let d = diff(&previous, &snapshot(&current));
        assert_eq!(d.added_hosts.len(), 1);
        assert_eq!(d.added_hosts[0].open_ports, 2);
        assert!(
            d.added_ports.is_empty(),
            "ports of a brand new host must not be repeated"
        );
    }

    #[test]
    fn vanishing_host_with_ports_is_not_repeated_as_ports() {
        let mut previous = MapState::new(None, vec![]);
        alive_host(&mut previous, ip(10, 0, 0, 6), &[(22, "ssh"), (80, "http")]);
        let current = snapshot(&MapState::new(None, vec![]));

        let d = diff(&snapshot(&previous), &current);
        assert_eq!(d.removed_hosts.len(), 1);
        assert_eq!(d.removed_hosts[0].open_ports, 2);
        assert!(
            d.removed_ports.is_empty(),
            "ports of a vanished host must not be repeated"
        );
    }

    #[test]
    fn ordering_is_by_address_then_port() {
        let mut previous = MapState::new(None, vec![]);
        alive_host(&mut previous, ip(10, 0, 0, 7), &[(80, "http")]);
        alive_host(&mut previous, ip(10, 0, 0, 9), &[(22, "ssh")]);

        let mut current = MapState::new(None, vec![]);
        // Inserted out of order on purpose; the diff must sort them.
        alive_host(
            &mut current,
            ip(10, 0, 0, 7),
            &[(443, "https"), (80, "http"), (22, "ssh")],
        );
        alive_host(&mut current, ip(10, 0, 0, 2), &[(8080, "http-alt")]);

        let d = diff(&snapshot(&previous), &snapshot(&current));

        assert_eq!(
            d.added_hosts.iter().map(|h| h.ip.as_str()).collect::<Vec<_>>(),
            vec!["10.0.0.2"]
        );
        assert_eq!(
            d.removed_hosts.iter().map(|h| h.ip.as_str()).collect::<Vec<_>>(),
            vec!["10.0.0.9"]
        );
        assert_eq!(
            d.added_ports
                .iter()
                .map(|p| (p.ip.as_str(), p.port))
                .collect::<Vec<_>>(),
            vec![("10.0.0.7", 22), ("10.0.0.7", 443)]
        );
        assert!(
            d.removed_ports.is_empty(),
            "10.0.0.9 vanished as a host, its port must not repeat"
        );
    }

    #[test]
    fn empty_snapshots_are_empty() {
        let empty = snapshot(&MapState::new(None, vec![]));
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
        let d = diff(&empty, &empty);
        assert!(d.is_empty());
        assert_eq!(d, Diff::default());
    }

    #[test]
    fn record_without_life_is_absent() {
        let mut map = MapState::new(None, vec![]);
        map.update(ip(10, 0, 0, 8), false, |_host| {});

        let snap = snapshot(&map);
        assert!(snap.is_empty());
        let d = diff(&snapshot(&MapState::new(None, vec![])), &snap);
        assert!(d.is_empty());
    }
}
