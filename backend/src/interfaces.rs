//! Local interface, route and neighbour-table enumeration.
//!
//! Everything here reads the kernel through files that are always present on
//! Linux (/proc/net/route, /proc/net/arp, /sys/class/net/*/address) plus
//! getifaddrs through the if-addrs crate. No netlink library, no shelling out,
//! no privileges: an unprivileged TCP connect scan needs none of that.

use std::net::Ipv4Addr;

use crate::util::{ip_to_u32, prefix_mask, u32_to_ip};

#[derive(Clone, Debug)]
pub struct LocalIface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub netmask: Ipv4Addr,
    pub mac: Option<String>,
    pub is_link_local: bool,
}

impl LocalIface {
    pub fn network(&self) -> Ipv4Addr {
        u32_to_ip(ip_to_u32(self.ip) & prefix_mask(self.prefix))
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        u32_to_ip((ip_to_u32(self.ip) & prefix_mask(self.prefix)) | !prefix_mask(self.prefix))
    }

    /// Every usable host address in this interface subnet. Network and
    /// broadcast addresses are dropped, and max_hosts caps the damage on an
    /// accidentally wide mask (a /16 would otherwise be 65k probes per port).
    pub fn hosts(&self, max_hosts: usize) -> (Vec<Ipv4Addr>, bool) {
        let net = ip_to_u32(self.network());
        let mask = prefix_mask(self.prefix);
        let first = net + 1;
        let last = (net & mask) | !mask;
        let mut out = Vec::new();
        let mut truncated = false;
        let mut current = first;
        while current < last {
            let ip = u32_to_ip(current);
            if self.ip != ip {
                if out.len() >= max_hosts {
                    truncated = true;
                    break;
                }
                out.push(ip);
            }
            current += 1;
        }
        (out, truncated)
    }
}

/// All non-loopback IPv4 interfaces, lowest address first.
pub fn local_interfaces() -> Vec<LocalIface> {
    let mut out = Vec::new();
    let Ok(addrs) = if_addrs::get_if_addrs() else {
        return out;
    };
    for iface in addrs {
        let if_addrs::IfAddr::V4(v4) = iface.addr else {
            continue;
        };
        if v4.ip.is_loopback() || v4.ip.is_unspecified() {
            continue;
        }
        out.push(LocalIface {
            mac: read_mac(&iface.name),
            name: iface.name.clone(),
            ip: v4.ip,
            prefix: v4.prefixlen,
            netmask: v4.netmask,
            is_link_local: v4.ip.is_link_local(),
        });
    }
    out.sort_by_key(|i| ip_to_u32(i.ip));
    out
}

/// MAC of an interface, from sysfs. None for interfaces without one (tunnels).
pub fn read_mac(name: &str) -> Option<String> {
    let raw = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
    let mac = raw.trim().to_ascii_lowercase();
    if mac.is_empty() || mac == "00:00:00:00:00:00" {
        None
    } else {
        Some(mac)
    }
}

/// (gateway IP, interface) of the IPv4 default route.
pub fn default_route() -> Option<(Ipv4Addr, String)> {
    let raw = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        // Destination and Mask both zero means the default route. The address
        // columns are little-endian hex, hence swap_bytes.
        if cols[1] != "00000000" || cols[7] != "00000000" {
            continue;
        }
        let gw = u32::from_str_radix(cols[2], 16)
            .ok()
            .map(|v| Ipv4Addr::from(v.swap_bytes()))?;
        if gw.is_unspecified() {
            continue;
        }
        return Some((gw, cols[0].to_string()));
    }
    None
}

/// IPv4 neighbours the kernel already knows from the ARP cache.
/// Returns (ip, mac, interface).
pub fn arp_table() -> Vec<(Ipv4Addr, String, String)> {
    let mut out = Vec::new();
    let Ok(raw) = std::fs::read_to_string("/proc/net/arp") else {
        return out;
    };
    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let (ip_raw, flags, mac, iface) = (cols[0], cols[2], cols[3], cols[5]);
        let Ok(ip) = ip_raw.parse::<Ipv4Addr>() else {
            continue;
        };
        // 0x2 = ATF_COM: a complete entry, i.e. the MAC was actually seen.
        let complete = u32::from_str_radix(flags.trim_start_matches("0x"), 16)
            .map(|f| f & 0x2 != 0)
            .unwrap_or(false);
        if !complete || mac == "00:00:00:00:00:00" {
            continue;
        }
        out.push((ip, mac.to_ascii_lowercase(), iface.to_string()));
    }
    out
}

/// Best guess at "the" interface to scan: the one holding the default route,
/// falling back to the first non-link-local IPv4 interface.
pub fn primary_interface() -> Option<LocalIface> {
    let ifaces = local_interfaces();
    if let Some((_, name)) = default_route() {
        if let Some(found) = ifaces.iter().find(|i| i.name == name) {
            return Some(found.clone());
        }
    }
    ifaces
        .iter()
        .find(|i| !i.is_link_local)
        .cloned()
        .or_else(|| ifaces.first().cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(ip: [u8; 4], prefix: u8) -> LocalIface {
        LocalIface {
            name: "test0".into(),
            ip: Ipv4Addr::from(ip),
            prefix,
            netmask: Ipv4Addr::from(prefix_mask(prefix)),
            mac: None,
            is_link_local: false,
        }
    }

    #[test]
    fn subnet_math() {
        let i = iface([192, 168, 1, 42], 24);
        assert_eq!(i.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(i.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
        let (hosts, truncated) = i.hosts(10_000);
        assert!(!truncated);
        assert_eq!(hosts.len(), 253);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 42)));
        assert_eq!(*hosts.last().unwrap(), Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn wide_subnet_is_capped() {
        let i = iface([10, 0, 0, 5], 16);
        let (hosts, truncated) = i.hosts(64);
        assert!(truncated);
        assert_eq!(hosts.len(), 64);
    }

    #[test]
    fn point_to_point_range_is_sane() {
        let i = iface([10, 8, 8, 1], 30);
        let (hosts, truncated) = i.hosts(64);
        assert!(!truncated);
        assert_eq!(hosts, vec![Ipv4Addr::new(10, 8, 8, 2)]);
    }
}
