//! Small helpers shared by the scanner modules.

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch. Used for the seen-at timestamps in the
/// JSON stream; the shell renders relative ages from it.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// This machine's hostname, so the map can label its own node.
pub fn hostname() -> Option<String> {
    if let Ok(raw) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let name = raw.trim().to_string();
        if !name.is_empty() {
            return Some(name);
        }
    }
    std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty())
}

pub fn ip_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

pub fn u32_to_ip(value: u32) -> Ipv4Addr {
    Ipv4Addr::from(value)
}

/// Network mask as a u32 for a CIDR prefix length.
pub fn prefix_mask(prefix: u8) -> u32 {
    let p = prefix.min(32) as u32;
    if p == 0 {
        0
    } else {
        u32::MAX << (32 - p)
    }
}

/// Three-octet OUI key from a MAC address, uppercase hex without separators.
pub fn oui_key(mac: &str) -> Option<String> {
    let clean: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect();
    if clean.len() < 6 {
        return None;
    }
    Some(clean.to_ascii_uppercase())
}

/// Locate an executable on PATH without shelling out to which.
pub fn find_on_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(name);
        if candidate.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = candidate.metadata() {
                    if meta.permissions().mode() & 0o111 != 0 {
                        return Some(candidate);
                    }
                }
            }
            #[cfg(not(unix))]
            return Some(candidate);
        }
    }
    None
}

/// Human duration for the status lines.
pub fn fmt_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}m{:02}s", ms / 60_000, (ms % 60_000) / 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_and_oui() {
        assert_eq!(prefix_mask(24), 0xFFFFFF00);
        assert_eq!(prefix_mask(0), 0);
        assert_eq!(prefix_mask(32), u32::MAX);
        assert_eq!(oui_key("Aa:BB:cc:dd:ee:ff").as_deref(), Some("AABBCC"));
        assert_eq!(oui_key("bogus"), None);
    }

    #[test]
    fn formats_durations() {
        assert_eq!(fmt_ms(400), "400ms");
        assert_eq!(fmt_ms(2500), "2.5s");
        assert_eq!(fmt_ms(61_000), "1m01s");
    }
}
