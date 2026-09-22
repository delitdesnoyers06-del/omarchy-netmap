//! Curated port table: which ports are worth probing, what each is called,
//! and how to identify what is listening.
//!
//! The default scan set is this table rather than 1-65535: on a home LAN it is
//! the difference between a two second scan and a two minute one, and the
//! interesting services are all in here. Use --ports all when you mean it.

use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Probe {
    /// Report the port as open, do not speak to it.
    None,
    /// Read whatever the service says first (SSH, SMTP, IMAP, MySQL, VNC...).
    Banner,
    /// Send a minimal HTTP/1.0 GET and parse status, Server header and title.
    Http,
    /// TLS handshake first, then an HTTP GET over the encrypted stream.
    Https,
    /// TLS handshake only (IMAPS, LDAPS, MQTT-TLS...).
    Tls,
    /// Inline PING for Redis.
    Redis,
    /// version command for memcached.
    Memcached,
    /// OPTIONS for RTSP cameras and media servers.
    Rtsp,
}

#[derive(Clone, Copy, Debug)]
pub struct PortInfo {
    pub port: u16,
    pub name: &'static str,
    pub probe: Probe,
}

const fn p(port: u16, name: &'static str, probe: Probe) -> PortInfo {
    PortInfo { port, name, probe }
}

use Probe::{Banner, Http, Https, Memcached, Redis, Rtsp, Tls};

/// Ports worth a look on a LAN. Ordered by port number for readability only;
/// lookup uses a sorted copy built once.
static TABLE: &[PortInfo] = &[
    p(21, "ftp", Banner),
    p(22, "ssh", Banner),
    p(23, "telnet", Banner),
    p(25, "smtp", Banner),
    p(53, "dns", Probe::None),
    p(70, "gopher", Banner),
    p(79, "finger", Banner),
    p(80, "http", Http),
    p(81, "http-alt", Http),
    p(88, "kerberos", Probe::None),
    p(102, "iso-tsap", Probe::None),
    p(110, "pop3", Banner),
    p(111, "rpcbind", Probe::None),
    p(113, "ident", Banner),
    p(119, "nntp", Banner),
    p(123, "ntp", Probe::None),
    p(135, "msrpc", Probe::None),
    p(137, "netbios-ns", Probe::None),
    p(138, "netbios-dgm", Probe::None),
    p(139, "netbios-ssn", Probe::None),
    p(143, "imap", Banner),
    p(161, "snmp", Probe::None),
    p(179, "bgp", Probe::None),
    p(194, "irc", Banner),
    p(389, "ldap", Probe::None),
    p(443, "https", Https),
    p(445, "microsoft-ds", Probe::None),
    p(465, "smtps", Tls),
    p(500, "isakmp", Probe::None),
    p(502, "modbus", Probe::None),
    p(512, "exec", Banner),
    p(513, "login", Banner),
    p(514, "shell", Banner),
    p(515, "lpd", Probe::None),
    p(548, "afp", Probe::None),
    p(554, "rtsp", Rtsp),
    p(587, "submission", Banner),
    p(623, "ipmi", Probe::None),
    p(631, "ipp", Http),
    p(636, "ldaps", Tls),
    p(646, "ldp", Probe::None),
    p(873, "rsync", Banner),
    p(888, "accessbuilder", Http),
    p(902, "vmware-auth", Probe::None),
    p(990, "ftps", Tls),
    p(993, "imaps", Tls),
    p(995, "pop3s", Tls),
    p(1025, "nfs-or-iis", Banner),
    p(1080, "socks", Probe::None),
    p(1099, "rmi", Banner),
    p(1194, "openvpn", Probe::None),
    p(1433, "ms-sql", Probe::None),
    p(1521, "oracle", Banner),
    p(1701, "l2tp", Probe::None),
    p(1723, "pptp", Probe::None),
    p(1883, "mqtt", Probe::None),
    p(1900, "upnp", Probe::None),
    p(2000, "cisco-sccp", Probe::None),
    p(2049, "nfs", Probe::None),
    p(2082, "cpanel", Http),
    p(2083, "cpanel-tls", Https),
    p(2086, "whm", Http),
    p(2087, "whm-tls", Https),
    p(2095, "webmail", Http),
    p(2096, "webmail-tls", Https),
    p(2181, "zookeeper", Banner),
    p(2222, "ssh-alt", Banner),
    p(2375, "docker", Http),
    p(2376, "docker-tls", Https),
    p(3000, "dev-server", Http),
    p(3128, "squid", Http),
    p(3260, "iscsi", Probe::None),
    p(3306, "mysql", Banner),
    p(3389, "rdp", Probe::None),
    p(3478, "stun", Probe::None),
    p(3689, "daap", Http),
    p(4000, "icq", Probe::None),
    p(4369, "epmd", Banner),
    p(4443, "https-alt", Https),
    p(44818, "ethernet-ip", Probe::None),
    p(5000, "upnp-synology", Http),
    p(5001, "synology-tls", Https),
    p(5060, "sip", Probe::None),
    p(5061, "sips", Tls),
    p(5222, "xmpp", Banner),
    p(5269, "xmpp-server", Banner),
    p(5280, "xmpp-http", Http),
    p(5357, "wsd", Http),
    p(5432, "postgresql", Probe::None),
    p(5555, "adb", Probe::None),
    p(5601, "kibana", Http),
    p(5672, "amqp", Banner),
    p(5683, "coap", Probe::None),
    p(5900, "vnc", Banner),
    p(5901, "vnc-1", Banner),
    p(5984, "couchdb", Http),
    p(5985, "winrm", Http),
    p(5986, "winrm-tls", Https),
    p(6000, "x11", Probe::None),
    p(6379, "redis", Redis),
    p(6443, "kubernetes-api", Https),
    p(6514, "syslog-tls", Tls),
    p(6667, "irc", Banner),
    p(6697, "ircs", Tls),
    p(6881, "bittorrent", Probe::None),
    p(7000, "airplay", Http),
    p(7443, "https-alt", Https),
    p(7547, "tr-069", Http),
    p(8000, "http-alt", Http),
    p(8008, "chromecast", Http),
    p(8009, "google-cast", Probe::None),
    p(8010, "http-alt", Http),
    p(8022, "ssh-alt", Banner),
    p(8060, "roku-ecp", Http),
    p(8080, "http-proxy", Http),
    p(8081, "http-alt", Http),
    p(8086, "influxdb", Http),
    p(8088, "http-alt", Http),
    p(8090, "http-alt", Http),
    p(8096, "jellyfin", Http),
    p(8123, "home-assistant", Http),
    p(8161, "activemq", Http),
    p(8181, "http-alt", Http),
    p(8200, "vault", Http),
    p(8291, "mikrotik-winbox", Http),
    p(8384, "syncthing", Http),
    p(8443, "https-alt", Https),
    p(8500, "consul", Http),
    p(8529, "arangodb", Http),
    p(8554, "rtsp-alt", Rtsp),
    p(8880, "http-alt", Http),
    p(8883, "mqtt-tls", Tls),
    p(8888, "http-alt", Http),
    p(8920, "jellyfin-tls", Https),
    p(8983, "solr", Http),
    p(9000, "http-alt", Http),
    p(9001, "tor-or-portainer", Http),
    p(9042, "cassandra", Banner),
    p(9090, "cockpit", Http),
    p(9091, "transmission", Http),
    p(9092, "kafka", Probe::None),
    p(9100, "printer-raw", Probe::None),
    p(9200, "elasticsearch", Http),
    p(9300, "elasticsearch-node", Probe::None),
    p(9418, "git", Banner),
    p(9443, "https-alt", Https),
    p(10000, "webmin", Http),
    p(10250, "kubelet", Https),
    p(10255, "kubelet-readonly", Http),
    p(10443, "https-alt", Https),
    p(11211, "memcached", Memcached),
    p(15672, "rabbitmq-mgmt", Http),
    p(25565, "minecraft", Probe::None),
    p(27017, "mongodb", Probe::None),
    p(32400, "plex", Http),
    p(37777, "dahua-dvr", Probe::None),
    p(50051, "grpc", Http),
    p(62078, "iphone-sync", Probe::None),
];

/// The table, sorted by port, built once.
fn sorted() -> &'static [PortInfo] {
    static SORTED: OnceLock<Vec<PortInfo>> = OnceLock::new();
    SORTED.get_or_init(|| {
        let mut v = TABLE.to_vec();
        v.sort_unstable_by_key(|entry| entry.port);
        v
    })
}

pub fn lookup(port: u16) -> Option<&'static PortInfo> {
    let table = sorted();
    table
        .binary_search_by_key(&port, |entry| entry.port)
        .ok()
        .map(|index| &table[index])
}

/// Port number to display name, for a port we know about.
pub fn name_of(port: u16) -> String {
    match lookup(port) {
        Some(info) => info.name.to_string(),
        None => "unknown".to_string(),
    }
}

/// Every port in the curated table, ascending.
pub fn curated() -> Vec<u16> {
    sorted().iter().map(|entry| entry.port).collect()
}

/// Ports whose probe is HTTP or HTTPS - used by the web shortcut.
pub fn web_ports() -> Vec<u16> {
    sorted()
        .iter()
        .filter(|entry| matches!(entry.probe, Http | Https))
        .map(|entry| entry.port)
        .collect()
}

/// Parse a port specification:
///   top | default | curated   the curated table above
///   all | full                 1-65535
///   web                        only ports that speak HTTP(S)
///   22,80,443 | 1-1024 | 8000-8100,9000
pub fn parse_spec(spec: &str) -> Result<Vec<u16>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(curated());
    }
    match spec.to_ascii_lowercase().as_str() {
        "top" | "default" | "curated" | "common" => return Ok(curated()),
        "all" | "full" | "1-65535" => return Ok((1..=65535u16).collect()),
        "web" | "http" => return Ok(web_ports()),
        _ => {}
    }
    let mut out: Vec<u16> = Vec::new();
    for chunk in spec.split([',', ' ', ';']).filter(|c| !c.is_empty()) {
        if let Some((start, end)) = chunk.split_once('-').or_else(|| chunk.split_once(':')) {
            let start: u16 = start
                .trim()
                .parse()
                .map_err(|_| format!("bad port range start in {chunk}"))?;
            let end: u16 = end
                .trim()
                .parse()
                .map_err(|_| format!("bad port range end in {chunk}"))?;
            if start == 0 || end == 0 || start > end {
                return Err(format!("invalid port range {chunk}"));
            }
            out.extend(start..=end);
        } else {
            let port: u16 = chunk
                .trim()
                .parse()
                .map_err(|_| format!("bad port number {chunk}"))?;
            if port == 0 {
                return Err("port 0 is not valid".to_string());
            }
            out.push(port);
        }
    }
    if out.is_empty() {
        return Err(format!("port spec {spec} matched nothing"));
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sane() {
        let curated = curated();
        assert!(curated.len() >= 120, "curated table shrank: {}", curated.len());
        for pair in curated.windows(2) {
            assert!(pair[0] < pair[1], "duplicate port in table: {}", pair[0]);
        }
        assert_eq!(lookup(22).map(|i| i.name), Some("ssh"));
        assert_eq!(lookup(443).map(|i| i.name), Some("https"));
        assert_eq!(lookup(8123).map(|i| i.probe), Some(Probe::Http));
        assert!(lookup(65533).is_none());
    }

    #[test]
    fn parses_specs() {
        assert_eq!(parse_spec("22,80").unwrap(), vec![22, 80]);
        assert_eq!(parse_spec("80,22,80").unwrap(), vec![22, 80]);
        assert_eq!(parse_spec("8000-8003").unwrap(), vec![8000, 8001, 8002, 8003]);
        assert_eq!(parse_spec("443:445").unwrap(), vec![443, 444, 445]);
        assert_eq!(parse_spec("all").unwrap().len(), 65535);
        assert!(parse_spec("top").unwrap().len() > 100);
        assert!(parse_spec("70000").is_err());
        assert!(parse_spec("90-80").is_err());
        assert!(parse_spec("nonsense").is_err());
    }
}
