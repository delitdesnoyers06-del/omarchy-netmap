//! Wake-on-LAN: parse a MAC, build the magic packet, and send it.
//!
//! The desktop panel pins a machine by MAC, so waking it has to work while the
//! host sleeps. The packet is broadcast on every local subnet (plus the
//! limited broadcast) and may be repeated to the address the host last held,
//! because plenty of switches do not forward a broadcast to a sleeping port.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::interfaces::local_interfaces;

/// Parse a MAC in any of the usual shapes: aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF,
/// aabb.ccdd.eeff, aabbccddeeff. None when it is not 6 hex octets.
pub fn parse_mac(input: &str) -> Option<[u8; 6]> {
    let text = input.trim();
    if text.is_empty() {
        return None;
    }

    let mut octets = [0u8; 6];
    if text.contains(':') || text.contains('-') {
        let sep = if text.contains(':') { ':' } else { '-' };
        let parts: Vec<&str> = text.split(sep).collect();
        if parts.len() != 6 {
            return None;
        }
        for (i, part) in parts.iter().enumerate() {
            octets[i] = hex_byte(part)?;
        }
    } else if text.contains('.') {
        let parts: Vec<&str> = text.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        for (i, part) in parts.iter().enumerate() {
            if part.len() != 4 || !part.is_ascii() {
                return None;
            }
            octets[2 * i] = hex_byte(&part[0..2])?;
            octets[2 * i + 1] = hex_byte(&part[2..4])?;
        }
    } else {
        if text.len() != 12 || !text.is_ascii() {
            return None;
        }
        for i in 0..6 {
            octets[i] = hex_byte(&text[2 * i..2 * i + 2])?;
        }
    }

    Some(octets)
}

/// Exactly two hex digits into one byte; anything else (including a value that
/// overflows a byte) is rejected instead of panicking.
fn hex_byte(part: &str) -> Option<u8> {
    if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(part, 16).ok()
}

/// The classic magic packet: 6 x 0xFF then the MAC repeated 16 times.
pub fn magic_packet(mac: [u8; 6]) -> [u8; 102] {
    let mut packet = [0xFFu8; 102];
    for i in 0..16 {
        let base = 6 + i * 6;
        packet[base..base + 6].copy_from_slice(&mac);
    }
    packet
}

/// Where a magic packet should go: every local interface broadcast address,
/// the limited broadcast 255.255.255.255, all on the given port.
pub fn broadcast_targets(port: u16) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut seen: HashSet<Ipv4Addr> = HashSet::new();

    for iface in local_interfaces() {
        let broadcast = iface.broadcast();
        if broadcast.is_unspecified() || broadcast.is_loopback() {
            continue;
        }
        if seen.insert(broadcast) {
            out.push(SocketAddr::new(IpAddr::V4(broadcast), port));
        }
    }

    // The limited broadcast reaches whatever the interface table could not
    // describe, and is the whole answer when there are no interfaces at all.
    if seen.insert(Ipv4Addr::BROADCAST) {
        out.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), port));
    }

    out
}

#[derive(serde::Serialize, Clone, Debug, PartialEq)]
pub struct WakeOutcome {
    pub mac: String,
    pub sent: usize,
    pub targets: Vec<String>,
}

/// Send the magic packet. `ip` is the address the machine last had, included as an
/// extra unicast target because some switches do not forward broadcasts to a sleeping host.
pub async fn wake(
    mac: &str,
    ip: Option<Ipv4Addr>,
    extra_targets: &[SocketAddr],
    port: u16,
    repeat: usize,
) -> Result<WakeOutcome, String> {
    let parsed = parse_mac(mac).ok_or_else(|| format!("invalid MAC address: {mac}"))?;
    let packet = magic_packet(parsed);
    let repeat = repeat.clamp(1, 10);

    // Broadcast first, then the unicast targets, deduplicated in that order so
    // no address ever receives the same datagram twice.
    let mut targets: Vec<SocketAddr> = broadcast_targets(port);
    if let Some(ip) = ip {
        targets.push(SocketAddr::new(IpAddr::V4(ip), port));
    }
    targets.extend(extra_targets.iter().copied());
    let mut seen = HashSet::new();
    targets.retain(|target| seen.insert(*target));

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("cannot bind UDP socket: {e}"))?;
    socket
        .set_broadcast(true)
        .map_err(|e| format!("cannot enable UDP broadcast: {e}"))?;

    let mut sent = 0usize;
    let mut reached: Vec<String> = Vec::new();
    let mut last_error: Option<String> = None;

    // One unreachable target must not stop the rest: collect whatever got out
    // and only fail if nothing at all could be sent.
    for _ in 0..repeat {
        for target in &targets {
            match socket.send_to(&packet, target).await {
                Ok(_) => {
                    sent += 1;
                    let label = target.to_string();
                    if !reached.contains(&label) {
                        reached.push(label);
                    }
                }
                Err(e) => last_error = Some(format!("{target}: {e}")),
            }
        }
    }

    if sent == 0 {
        return Err(match last_error {
            Some(e) => format!("no magic packet could be sent to any target: {e}"),
            None => "no magic packet targets were available".to_string(),
        });
    }

    Ok(WakeOutcome {
        mac: mac.to_string(),
        sent,
        targets: reached,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    const MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    fn count_mac(packet: &[u8; 102], mac: [u8; 6]) -> usize {
        packet.windows(6).filter(|window| *window == mac).count()
    }

    #[test]
    fn parses_all_mac_shapes() {
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff"), Some(MAC));
        assert_eq!(parse_mac("AA-BB-CC-DD-EE-FF"), Some(MAC));
        assert_eq!(parse_mac("aabb.ccdd.eeff"), Some(MAC));
        assert_eq!(parse_mac("aabbccddeeff"), Some(MAC));
        assert_eq!(parse_mac("AABBCCDDEEFF"), Some(MAC));
    }

    #[test]
    fn rejects_bad_macs() {
        assert_eq!(parse_mac(""), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(parse_mac("aabbccddee"), None);
        assert_eq!(parse_mac("gg:bb:cc:dd:ee:ff"), None);
        assert_eq!(parse_mac("not-a-mac"), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff:00"), None);
        assert_eq!(parse_mac("aabbccddeeff00"), None);
        assert_eq!(parse_mac("aabb.ccdd.eeff.0011"), None);
    }

    #[test]
    fn magic_packet_layout() {
        let packet = magic_packet(MAC);
        assert_eq!(packet.len(), 102);
        assert_eq!(&packet[..6], &[0xFF; 6]);
        assert_eq!(count_mac(&packet, MAC), 16);
        assert_eq!(&packet[6..12], &MAC);
    }

    #[test]
    fn different_macs_give_different_packets() {
        let a = magic_packet(parse_mac("aabbccddeeff").unwrap());
        let b = magic_packet(parse_mac("010203040506").unwrap());
        assert_ne!(a, b);
        assert_ne!(a[6..], b[6..]);
    }

    #[test]
    fn broadcast_targets_include_limited_broadcast() {
        let targets = broadcast_targets(9);
        assert!(targets.contains(&"255.255.255.255:9".parse().unwrap()));
        assert!(!targets.iter().any(|t| t.ip().is_unspecified()));
    }

    #[test]
    fn port_is_applied_to_every_target() {
        for port in [0u16, 9, 4343, 65535] {
            let targets = broadcast_targets(port);
            assert!(!targets.is_empty());
            assert!(targets.iter().all(|t| t.port() == port));
        }
    }

    #[tokio::test]
    async fn sends_exact_magic_packet_to_unicast_target() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ip = match addr.ip() {
            IpAddr::V4(v4) => v4,
            other => panic!("expected an IPv4 listener, got {other}"),
        };

        let outcome = wake("aa:bb:cc:dd:ee:ff", Some(ip), &[addr], addr.port(), 1)
            .await
            .unwrap();
        assert!(outcome.sent >= 1);
        assert!(outcome.targets.contains(&addr.to_string()));

        let mut buf = [0u8; 256];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut buf))
            .await
            .expect("timed out waiting for the magic packet")
            .unwrap();
        assert_eq!(n, 102);
        assert_eq!(&buf[..n], &magic_packet(MAC)[..]);
    }

    #[tokio::test]
    async fn invalid_mac_is_an_error_naming_the_input() {
        let err = wake("nope", None, &[], 9, 1).await.unwrap_err();
        assert!(err.contains("nope"), "message was {err:?}");
    }
}
