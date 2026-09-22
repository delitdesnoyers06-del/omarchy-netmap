//! Command line surface.

use std::net::Ipv4Addr;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use crate::mdns::MdnsMode;
use crate::ports;
use crate::scan::ScanConfig;
use crate::util::{ip_to_u32, u32_to_ip};

#[derive(Parser, Debug)]
#[command(
    name = "netmap",
    version,
    about = "Map the local network: mDNS/DNS-SD, ARP, and a mass-parallel port scan with service identification",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan the LAN: hosts, open ports, protocols, names, device classes.
    Scan(Box<ScanArgs>),
    /// Print local interfaces, the default route and the ARP cache.
    Ifaces,
    /// Print the curated port table (or a custom spec).
    Ports {
        /// Port spec: top, all, web, 22,80, 1-1024.
        spec: Option<String>,
    },
    /// Print version and capability summary.
    Version,
    /// Wake a machine over the LAN (Wake-on-LAN magic packet).
    Wol(Box<WolArgs>),
}

#[derive(Args, Debug, Clone)]
pub struct WolArgs {
    /// MAC address in any usual form. Optional when --ip is in the ARP cache.
    #[arg(value_name = "MAC")]
    pub mac: Option<String>,

    /// Address the machine last had; used as a unicast target as well.
    #[arg(long = "ip", value_name = "IP")]
    pub ip: Option<String>,

    /// Extra target, repeatable: an address or address:port.
    #[arg(long = "broadcast", value_name = "ADDR", num_args = 0..)]
    pub broadcasts: Vec<String>,

    /// UDP port: 9 is the standard, 7 works on most hardware too.
    #[arg(long, default_value_t = 9)]
    pub port: u16,

    /// How many times to send the packet.
    #[arg(long, default_value_t = 3)]
    pub repeat: usize,

    /// Print the result as JSON.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Subnet(s) to scan, e.g. 192.168.1.0/24. Repeatable; default is every
    /// local interface subnet.
    #[arg(long = "subnet", value_name = "CIDR", num_args = 0..)]
    pub subnets: Vec<String>,

    /// Explicit hosts, comma separated. Takes precedence over --subnet.
    #[arg(long = "hosts", value_name = "IP,IP")]
    pub hosts: Option<String>,

    /// Ports: top (default), all, web, 22,80, 1-1024, 8000-8100.
    #[arg(long, short = 'p', default_value = "top")]
    pub ports: String,

    /// Parallel connect attempts in flight.
    #[arg(long, default_value_t = 1024)]
    pub concurrency: usize,

    /// Per-connect timeout in milliseconds.
    #[arg(long = "timeout", default_value_t = 400)]
    pub timeout_ms: u64,

    /// Consecutive timeouts on one host before its remaining ports are skipped.
    #[arg(long = "host-failures", default_value_t = 12)]
    pub host_failures: u32,

    /// Cap on hosts probed from a subnet (guards a wide mask).
    #[arg(long = "max-hosts", default_value_t = 1024)]
    pub max_hosts: usize,

    /// Do not speak to open ports; report them without identification.
    #[arg(long = "no-probe")]
    pub no_probe: bool,

    /// Skip NetBIOS name queries.
    #[arg(long = "no-netbios")]
    pub no_netbios: bool,

    /// mDNS mode: auto, native, avahi, off.
    #[arg(long = "mdns", default_value = "auto")]
    pub mdns: String,

    /// How long to listen for mDNS answers, in milliseconds.
    #[arg(long = "mdns-ms", default_value_t = 2500)]
    pub mdns_ms: u64,

    /// Emit JSON Lines on stdout as results arrive (what the panel consumes).
    #[arg(long = "jsonl")]
    pub jsonl: bool,

    /// Emit a single JSON document when the scan finishes.
    #[arg(long = "json")]
    pub json: bool,

    /// Suppress the progress and status lines on stderr.
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// Repeat the scan every N seconds (0 runs once).
    #[arg(long, default_value_t = 0)]
    pub watch: u64,
}

impl ScanArgs {
    pub fn to_config(&self) -> Result<ScanConfig, String> {
        let mdns = MdnsMode::parse(&self.mdns).ok_or_else(|| {
            format!(
                "unknown --mdns value {:?} (expected auto, native, avahi or off)",
                self.mdns
            )
        })?;
        let ports = ports::parse_spec(&self.ports)?;
        let concurrency = self.concurrency.clamp(1, 20_000);
        let targets = self.targets()?;
        Ok(ScanConfig {
            targets,
            ports,
            concurrency,
            timeout: Duration::from_millis(self.timeout_ms.clamp(20, 30_000)),
            host_failures: self.host_failures.max(1),
            deep_probe: !self.no_probe,
            netbios: !self.no_netbios,
            mdns,
            mdns_duration: Duration::from_millis(self.mdns_ms.min(30_000)),
            max_hosts: self.max_hosts.clamp(1, 65_534),
            round: 0,
        })
    }

    /// Explicit targets from --hosts or --subnet, empty when neither is given.
    pub fn targets(&self) -> Result<Vec<Ipv4Addr>, String> {
        if let Some(raw) = &self.hosts {
            let mut out = Vec::new();
            for item in raw.split([',', ' ', ';']).filter(|s| !s.is_empty()) {
                out.push(
                    item.trim()
                        .parse::<Ipv4Addr>()
                        .map_err(|_| format!("bad host address {item:?}"))?,
                );
            }
            if out.is_empty() {
                return Err("--hosts matched no addresses".to_string());
            }
            return Ok(out);
        }
        if self.subnets.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for spec in &self.subnets {
            let mut hosts = parse_subnet(spec)?;
            out.append(&mut hosts);
        }
        out.sort_by_key(|ip| ip_to_u32(*ip));
        out.dedup();
        if out.is_empty() {
            return Err("the given subnets contained no host addresses".to_string());
        }
        Ok(out)
    }
}

/// Parse "192.168.1.0/24", "192.168.1.7" or "192.168.1.7-192.168.1.20".
pub fn parse_subnet(spec: &str) -> Result<Vec<Ipv4Addr>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("empty subnet".to_string());
    }
    if let Some((base, range)) = spec.split_once('-') {
        let start: Ipv4Addr = base
            .trim()
            .parse()
            .map_err(|_| format!("bad range start in {spec:?}"))?;
        let end: Ipv4Addr = range
            .trim()
            .parse()
            .map_err(|_| format!("bad range end in {spec:?}"))?;
        let (start, end) = (ip_to_u32(start), ip_to_u32(end));
        if start > end {
            return Err(format!("inverted range {spec:?}"));
        }
        return Ok((start..=end).map(u32_to_ip).collect());
    }
    let (addr, prefix) = match spec.split_once('/') {
        Some((addr, prefix)) => (
            addr.trim()
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("bad address in {spec:?}"))?,
            prefix
                .trim()
                .parse::<u8>()
                .map_err(|_| format!("bad prefix in {spec:?}"))?,
        ),
        None => (
            spec.parse::<Ipv4Addr>()
                .map_err(|_| format!("bad address {spec:?}"))?,
            32,
        ),
    };
    if prefix > 32 {
        return Err(format!("prefix /{prefix} is out of range"));
    }
    if prefix >= 31 {
        return Ok(vec![addr]);
    }
    let mask = crate::util::prefix_mask(prefix);
    let network = ip_to_u32(addr) & mask;
    let broadcast = network | !mask;
    let mut out = Vec::new();
    let mut current = network + 1;
    while current < broadcast {
        out.push(u32_to_ip(current));
        current += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subnets() {
        let hosts = parse_subnet("192.168.1.0/30").unwrap();
        assert_eq!(
            hosts,
            vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)]
        );
        assert_eq!(
            parse_subnet("10.0.0.7").unwrap(),
            vec![Ipv4Addr::new(10, 0, 0, 7)]
        );
        assert_eq!(
            parse_subnet("10.0.0.1-10.0.0.3").unwrap(),
            vec![
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3)
            ]
        );
        assert!(parse_subnet("nonsense").is_err());
        assert!(parse_subnet("10.0.0.0/33").is_err());
    }

    #[test]
    fn builds_a_config() {
        let args = Cli::try_parse_from([
            "netmap",
            "scan",
            "--hosts",
            "192.168.1.5,192.168.1.6",
            "--ports",
            "22,80",
            "--mdns",
            "off",
            "--timeout",
            "250",
        ])
        .unwrap();
        let Some(Command::Scan(args)) = args.command else {
            panic!("expected scan")
        };
        let cfg = args.to_config().unwrap();
        assert_eq!(cfg.ports, vec![22, 80]);
        assert_eq!(cfg.targets.len(), 2);
        assert_eq!(cfg.mdns, MdnsMode::Off);
        assert_eq!(cfg.timeout, Duration::from_millis(250));
    }

    #[test]
    fn parses_wol_args() {
        let cli = Cli::try_parse_from([
            "netmap", "wol", "AA:BB:CC:DD:EE:FF", "--ip", "10.0.0.5", "--repeat", "5",
        ])
        .unwrap();
        let Some(Command::Wol(args)) = cli.command else {
            panic!("expected wol")
        };
        assert_eq!(args.mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(args.ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(args.port, 9);
        assert_eq!(args.repeat, 5);
        assert!(!args.json);

        // --ip alone is enough: the MAC comes from the ARP cache.
        let cli = Cli::try_parse_from(["netmap", "wol", "--ip", "10.0.0.5"]).unwrap();
        let Some(Command::Wol(args)) = cli.command else {
            panic!("expected wol")
        };
        assert!(args.mac.is_none());
    }

    #[test]
    fn rejects_bad_mdns_mode() {
        let args = Cli::try_parse_from(["netmap", "scan", "--mdns", "bogus"]).unwrap();
        let Some(Command::Scan(args)) = args.command else {
            panic!("expected scan")
        };
        assert!(args.to_config().is_err());
    }
}
