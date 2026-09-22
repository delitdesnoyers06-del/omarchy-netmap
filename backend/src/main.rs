//! netmap CLI entry point.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use tokio::sync::mpsc;

use netmap::cli::{Cli, Command};
use netmap::model::Event;
use netmap::{diff, interfaces, mdns, oui, ports, scan, util, wol};
use netmap::emit::{Emitter, OutputFormat};


#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        None => run_scan(scan::ScanConfig::default(), OutputFormat::Human, false, 0).await,
        Some(Command::Scan(args)) => {
            let quiet = args.quiet;
            let watch = args.watch;
            let format = if args.jsonl {
                OutputFormat::JsonLines
            } else if args.json {
                OutputFormat::Json
            } else {
                OutputFormat::Human
            };
            match args.to_config() {
                Ok(config) => run_scan(config, format, quiet, watch).await,
                Err(message) => {
                    eprintln!("netmap: {message}");
                    ExitCode::from(2)
                }
            }
        }
        Some(Command::Ifaces) => {
            print_interfaces();
            ExitCode::SUCCESS
        }
        Some(Command::Ports { spec }) => {
            let spec = spec.unwrap_or_else(|| "top".to_string());
            match ports::parse_spec(&spec) {
                Ok(list) => {
                    for port in list {
                        let name = ports::name_of(port);
                        let probe = ports::lookup(port)
                            .map(|info| format!("{:?}", info.probe).to_lowercase())
                            .unwrap_or_else(|| "-".to_string());
                        println!("{port:>5}  {name:<24} {probe}");
                    }
                    ExitCode::SUCCESS
                }
                Err(message) => {
                    eprintln!("netmap: {message}");
                    ExitCode::from(2)
                }
            }
        }
        Some(Command::Wol(args)) => wake(&args).await,
        Some(Command::Version) => {
            let info = serde_json::json!({
                "tool": scan::TOOL,
                "version": scan::VERSION,
                "curated_ports": ports::curated().len(),
                "mdns": {
                    "native": true,
                    "avahi": util::find_on_path("avahi-browse").is_some(),
                    "seed_types": mdns::SEED_TYPES.len(),
                },
                "oui_prefixes": oui::table_size(),
                "interfaces": interfaces::local_interfaces().len(),
            });
            println!("{}", serde_json::to_string_pretty(&info).unwrap_or_default());
            ExitCode::SUCCESS
        }
    }
}

async fn run_scan(
    config: scan::ScanConfig,
    format: OutputFormat,
    quiet: bool,
    watch_seconds: u64,
) -> ExitCode {
    let (tx, rx) = mpsc::unbounded_channel();
    let emitter = Emitter::new(format, quiet);
    let writer = tokio::spawn(emitter.run(rx));

    // Watch mode: scan, diff against the previous round, repeat. The diff is
    // what makes continuous monitoring useful - a consumer is told what changed
    // instead of having to compare two maps itself.
    let mut round: u32 = 0;
    let mut previous: Option<diff::Snapshot> = None;
    loop {
        let mut round_config = config.clone();
        round_config.round = round;
        let (summary, snapshot) = scan::run(round_config, tx.clone()).await;
        if let Some(previous) = &previous {
            let changes = diff::diff(previous, &snapshot);
            if !changes.is_empty() {
                let _ = tx.send(Event::Diff(changes));
            }
        }
        previous = Some(snapshot);
        round += 1;
        if watch_seconds == 0 {
            break;
        }
        if format == OutputFormat::Human {
            eprintln!(
                "  . round {round} done ({} hosts, {} open ports) - next scan in {watch_seconds}s, ctrl-c to stop",
                summary.hosts, summary.open_ports
            );
        }
        tokio::time::sleep(Duration::from_secs(watch_seconds)).await;
    }
    drop(tx);
    let _ = writer.await;
    ExitCode::SUCCESS
}

/// netmap wol: send a magic packet, resolving the MAC from the ARP cache when
/// it was not given.
async fn wake(args: &netmap::cli::WolArgs) -> ExitCode {
    let ip = match args.ip.as_deref() {
        Some(raw) => match raw.parse::<Ipv4Addr>() {
            Ok(ip) => Some(ip),
            Err(_) => {
                eprintln!("netmap: bad --ip {raw:?}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    let mac = match args.mac.clone().or_else(|| {
        ip.and_then(|ip| {
            interfaces::arp_table()
                .into_iter()
                .find(|(address, _, _)| *address == ip)
                .map(|(_, mac, _)| mac)
        })
    }) {
        Some(mac) => mac,
        None => {
            eprintln!(
                "netmap: no MAC given and none for that address in the ARP cache;                  try netmap ifaces to see what the kernel knows"
            );
            return ExitCode::from(2);
        }
    };

    let mut extras: Vec<SocketAddr> = Vec::new();
    for spec in &args.broadcasts {
        let parsed = spec
            .parse::<SocketAddr>()
            .or_else(|_| spec.parse::<Ipv4Addr>().map(|ip| SocketAddr::from((ip, args.port))))
            .or_else(|_| {
                spec.parse::<std::net::IpAddr>()
                    .map(|ip| SocketAddr::new(ip, args.port))
            });
        match parsed {
            Ok(addr) => extras.push(addr),
            Err(_) => {
                eprintln!("netmap: bad --broadcast {spec:?}");
                return ExitCode::from(2);
            }
        }
    }

    match wol::wake(&mac, ip, &extras, args.port, args.repeat).await {
        Ok(outcome) => {
            if args.json {
                println!("{}", serde_json::to_string(&outcome).unwrap_or_default());
            } else {
                println!(
                    "sent {} magic packet(s) for {} to {}",
                    outcome.sent,
                    outcome.mac,
                    outcome.targets.join(", ")
                );
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("netmap: {message}");
            ExitCode::from(1)
        }
    }
}

fn print_interfaces() {
    let route = interfaces::default_route();
    println!("interfaces:");
    for iface in interfaces::local_interfaces() {
        let is_default = route
            .as_ref()
            .map(|(_, name)| *name == iface.name)
            .unwrap_or(false);
        println!(
            "  {:<12} {:<16} /{:<3} mac {:<18} {}",
            iface.name,
            iface.ip.to_string(),
            iface.prefix,
            iface.mac.clone().unwrap_or_else(|| "-".to_string()),
            if is_default { "(default route)" } else { "" }
        );
    }
    match route {
        Some((gateway, name)) => println!("gateway: {gateway} via {name}"),
        None => println!("gateway: none"),
    }
    let arp = interfaces::arp_table();
    println!("arp cache: {} complete entries", arp.len());
    for (ip, mac, iface) in arp {
        let vendor = oui::lookup(&mac).unwrap_or("");
        println!("  {ip:<16} {mac:<18} {iface:<12} {vendor}");
    }
}
