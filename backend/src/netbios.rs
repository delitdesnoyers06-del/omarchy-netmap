//! NetBIOS name query (NBSTAT).
//!
//! Windows machines, Samba boxes and a surprising number of printers answer a
//! name request on UDP 137 even when nothing else is exposed. It costs one UDP
//! round trip per host and turns "192.168.1.42" into "DESKTOP-7H3K2L".

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::UdpSocket;

/// Encode a NetBIOS name: 16 bytes, padded with spaces, each nibble turned
/// into a letter A-P. The first byte is then the length (32).
fn encode_name(name: &str) -> [u8; 34] {
    let mut padded = [b' '; 16];
    for (index, byte) in name.bytes().take(15).enumerate() {
        padded[index] = byte.to_ascii_uppercase();
    }
    // 0x00 marks a workstation name record.
    padded[15] = 0x00;
    let mut out = [0u8; 34];
    out[0] = 32;
    for (index, byte) in padded.iter().enumerate() {
        out[1 + index * 2] = b'A' + (byte >> 4);
        out[2 + index * 2] = b'A' + (byte & 0x0F);
    }
    out[33] = 0x00;
    out
}

fn build_query() -> Vec<u8> {
    let mut packet = Vec::with_capacity(50);
    packet.extend_from_slice(&[0x13, 0x37]); // transaction id
    packet.extend_from_slice(&[0x00, 0x00]); // flags: standard query
    packet.extend_from_slice(&[0x00, 0x01]); // qdcount
    packet.extend_from_slice(&[0x00, 0x00]); // ancount
    packet.extend_from_slice(&[0x00, 0x00]); // nscount
    packet.extend_from_slice(&[0x00, 0x00]); // arcount
    packet.extend_from_slice(&encode_name("*"));
    packet.extend_from_slice(&[0x00, 0x21]); // NBSTAT
    packet.extend_from_slice(&[0x00, 0x01]); // IN
    packet
}

/// Pull the first workstation or server name out of an NBSTAT response.
fn parse_response(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    let answers = u16::from_be_bytes([data[6], data[7]]) as usize;
    if answers == 0 {
        return None;
    }
    // Skip the question section: 34-byte encoded name plus 4 bytes of type/class.
    let mut offset = 12 + 34 + 4;
    if offset >= data.len() {
        return None;
    }
    // The answer name is either a compression pointer (2 bytes) or another
    // 34-byte encoded name.
    if data[offset] & 0xC0 == 0xC0 {
        offset += 2;
    } else {
        offset += 35;
    }
    offset += 8; // type, class, ttl
    if offset + 2 > data.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if offset + 1 > data.len() || rdlength == 0 {
        return None;
    }
    let count = data[offset] as usize;
    offset += 1;
    let mut best: Option<String> = None;
    for index in 0..count {
        let start = offset + index * 18;
        if start + 16 > data.len() {
            break;
        }
        let raw = &data[start..start + 15];
        let suffix = data[start + 15];
        // 0x00 = workstation/domain, 0x03 = messenger, 0x20 = file server.
        if suffix != 0x00 && suffix != 0x20 {
            continue;
        }
        let name: String = raw
            .iter()
            .take_while(|b| **b != 0 && **b != b' ')
            .map(|b| *b as char)
            .collect();
        let name = name.trim().to_string();
        if name.len() < 2 || name.contains('\u{0}') {
            continue;
        }
        let is_group = data[start + 15 + 1] & 0x80 != 0;
        if is_group {
            continue;
        }
        if best.is_none() {
            best = Some(name);
        }
    }
    best
}

/// Ask a host for its NetBIOS name. None when nothing answers in time.
pub async fn query_name(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect((ip, 137)).await.ok()?;
    socket.send(&build_query()).await.ok()?;
    let mut buffer = [0u8; 1024];
    let read = tokio::time::timeout(timeout, socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;
    parse_response(&buffer[..read])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_encoding_is_16_bytes_of_nibbles() {
        let encoded = encode_name("TEST");
        assert_eq!(encoded[0], 32);
        // 'T' is 0x54: high nibble 5 becomes 'A' + 5 = 'F', low nibble 4 is 'E'.
        assert_eq!(encoded[1], b'F');
        assert_eq!(encoded[2], b'E');
        assert_eq!(encoded[33], 0);
        // The name is space padded to 15 bytes plus a 0x00 suffix byte.
        assert_eq!(encode_name("A")[1 + 2 * 1], b'A' + 2);
        assert_eq!(encode_name("A")[1 + 2 * 14], b'A' + 2);
    }

    #[test]
    fn query_has_the_right_shape() {
        let packet = build_query();
        assert_eq!(packet.len(), 12 + 34 + 4);
        assert_eq!(&packet[0..2], &[0x13, 0x37]);
        assert_eq!(&packet[4..6], &[0x00, 0x01]);
        assert_eq!(&packet[46..48], &[0x00, 0x21]);
    }

    #[test]
    fn parses_a_synthetic_response() {
        let mut packet = build_query();
        packet[2] = 0x84; // response, recursion available
        packet[3] = 0x00;
        packet[6] = 0x00;
        packet[7] = 0x01; // one answer
        packet.extend_from_slice(&[0xC0, 0x0C]); // name pointer
        packet.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // NBSTAT IN
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ttl
        let names = b"DESKTOP-ABC    \x00\x00";
        packet.extend_from_slice(&(names.len() as u16 + 1).to_be_bytes());
        packet.push(1); // one name
        packet.extend_from_slice(names);
        assert_eq!(parse_response(&packet).as_deref(), Some("DESKTOP-ABC"));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_response(&[0u8; 4]), None);
    }
}
