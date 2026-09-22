//! The scan driver: decide what to probe, probe it in parallel, and keep the
//! shared map consistent while events stream out.
//!
//! The parallelism model is a sliding window over (host, port) pairs held in a
//! JoinSet: memory stays flat whether the job is 253x150 or 253x65535, and the
//! in-flight count is exactly the configured concurrency. Two adaptive tricks
//! keep a fast LAN fast:
//!   * the connect timeout drops to ~6x the fastest observed RTT, so a 1ms LAN
//!     stops waiting 400ms per filtered port;
//!   * a host that times out on N consecutive ports without ever answering is
//!     dropped for the rest of the run instead of costing one timeout per port.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinSet;
use tokio::time::timeout as with_timeout;

use crate::classify;
use crate::interfaces;
use crate::mdns::{self, MdnsMode};
use crate::model::{
    Event, HostRecord, IfaceInfo, MapState, MdnsRecord, Meta, PortRecord, Summary,
};
use crate::netbios;
use crate::oui;
use crate::ports::{self, Probe};
use crate::probe;
use crate::util::u32_to_ip;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const TOOL: &str = "netmap";

/// Hard cap on NetBIOS name queries, so a /16 or a dead LAN cannot stretch the
/// post-scan pass beyond a second or two.
const NETBIOS_LIMIT: usize = 64;
const NETBIOS_CONCURRENCY: usize = 48;

#[derive(Clone, Debug)]
pub struct ScanConfig {
    /// Explicit targets. Empty means "derive them from the local interfaces".
    pub targets: Vec<Ipv4Addr>,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout: Duration,
    /// Consecutive timeouts on one host before the rest of its ports are skipped.
    pub host_failures: u32,
    /// Speak to the services that are open, to identify them.
    pub deep_probe: bool,
    pub netbios: bool,
    pub mdns: MdnsMode,
    pub mdns_duration: Duration,
    pub max_hosts: usize,
    /// Round counter for watch mode; 0 for a one-shot scan.
    pub round: u32,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            ports: ports::curated(),
            concurrency: 1024,
            timeout: Duration::from_millis(400),
            host_failures: 8,
            deep_probe: true,
            netbios: true,
            mdns: MdnsMode::Auto,
            mdns_duration: Duration::from_millis(2500),
            max_hosts: 1024,
            round: 0,
        }
    }
}

impl ScanConfig {
    /// A probe does a round trip and then reads; it gets more room than a bare
    /// connect, but never so much that one stubborn service stalls a slot.
    pub fn probe_timeout(&self) -> Duration {
        self.timeout.max(Duration::from_millis(700)).min(Duration::from_millis(2500))
    }
}

/// Shared scanner state. Everything is behind Arc so probe tasks stay cheap.
struct Ctx {
    map: Mutex<MapState>,
    tx: UnboundedSender<Event>,
    cfg: ScanConfig,
    started: Instant,
    done: AtomicU64,
    open: AtomicU64,
    total: u64,
    timeout_us: AtomicU64,
    rtt_min_us: AtomicU64,
    successes: AtomicU32,
    skip: Vec<AtomicBool>,
    failures: Vec<AtomicU32>,
    finished: AtomicBool,
    skipped: AtomicU64,
}

impl Ctx {
    fn send(&self, event: Event) {
        let _ = self.tx.send(event);
    }

    fn status(&self, message: impl Into<String>) {
        self.send(Event::Status {
            message: message.into(),
        });
    }

    /// Mutate one host record; emits the fresh snapshot when the closure says
    /// something changed, which is what makes the stream an upsert sequence.
    fn mutate<F: FnOnce(&mut HostRecord) -> bool>(&self, ip: Ipv4Addr, f: F) {
        let snapshot = {
            let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
            let mut changed = false;
            map.update(ip, false, |host| changed = f(host));
            if changed {
                map.get(ip).cloned()
            } else {
                None
            }
        };
        if let Some(host) = snapshot {
            self.send(Event::Host(Box::new(host)));
        }
    }

    fn host_name(&self, ip: Ipv4Addr) -> Option<String> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.get(ip).and_then(|h| h.names.first().cloned())
    }

    fn self_ips(&self) -> Vec<Ipv4Addr> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.self_ips()
    }

    fn counters(&self) -> (usize, usize) {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        (map.alive_count(), map.open_port_count())
    }

    fn current_timeout(&self) -> Duration {
        Duration::from_micros(self.timeout_us.load(Ordering::Relaxed))
    }

    /// Lower the connect timeout once a few hosts have answered, so the rest
    /// of the run does not wait the full configured value for silence.
    fn tune_timeout(&self, rtt: Duration) {
        let micros = rtt.as_micros().max(1) as u64;
        let mut best = self.rtt_min_us.load(Ordering::Relaxed);
        while micros < best && self
            .rtt_min_us
            .compare_exchange(best, micros, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            best = self.rtt_min_us.load(Ordering::Relaxed);
        }
        let successes = self.successes.fetch_add(1, Ordering::Relaxed) + 1;
        if successes < 3 {
            return;
        }
        let target = (best.saturating_mul(6)).clamp(120_000, self.cfg.timeout.as_micros() as u64);
        let current = self.timeout_us.load(Ordering::Relaxed);
        if target < current {
            let _ = self
                .timeout_us
                .compare_exchange(current, target, Ordering::Relaxed, Ordering::Relaxed);
        }
    }

    /// A host answered (or refused): it is not a candidate for the skip list.
    fn note_response(&self, index: usize) {
        if let Some(counter) = self.failures.get(index) {
            counter.store(0, Ordering::Relaxed);
        }
    }

    /// Count a timeout and decide whether to drop the host for this run.
    fn note_timeout(&self, index: usize, ip: Ipv4Addr) {
        let Some(counter) = self.failures.get(index) else {
            return;
        };
        let failures = counter.fetch_add(1, Ordering::Relaxed) + 1;
        if failures < self.cfg.host_failures {
            return;
        }
        let alive = {
            let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
            map.get(ip).map(|h| h.alive || h.open_ports > 0).unwrap_or(false)
        };
        if alive {
            return;
        }
        if let Some(flag) = self.skip.get(index) {
            if !flag.swap(true, Ordering::Relaxed) {
                // Counted, not announced: a /24 has hundreds of these and the
                // per-host line drowns out the interesting ones.
                self.skipped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Probe one port on one host. This is the whole inner loop.
async fn probe_one(ctx: Arc<Ctx>, index: usize, ip: Ipv4Addr, port: u16) {
    if ctx
        .skip
        .get(index)
        .map(|flag| flag.load(Ordering::Relaxed))
        .unwrap_or(false)
    {
        ctx.done.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let started = Instant::now();
    match with_timeout(ctx.current_timeout(), TcpStream::connect((ip, port))).await {
        Ok(Ok(stream)) => {
            let elapsed = started.elapsed();
            let rtt_ms = round_ms(elapsed);
            ctx.tune_timeout(elapsed);
            ctx.note_response(index);
            ctx.open.fetch_add(1, Ordering::Relaxed);
            drop(stream);

            let service = ports::name_of(port);
            ctx.mutate(ip, |host| {
                let changed = host.alive != true || !host.ports.iter().any(|p| p.port == port);
                host.alive = true;
                if host.rtt_ms.map_or(true, |value| rtt_ms < value) {
                    host.rtt_ms = Some(rtt_ms);
                }
                host.add_source("tcp");
                host.set_port(PortRecord {
                    port,
                    service: service.clone(),
                    proto: service.clone(),
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
                    rtt_ms: Some(rtt_ms),
                });
                changed
            });
            ctx.status(format!("open {ip}:{port} {service}"));

            if ctx.cfg.deep_probe {
                if let Some(info) = ports::lookup(port) {
                    if info.probe != Probe::None {
                        let sni = ctx.host_name(ip);
                        let outcome = probe::identify(
                            ip,
                            port,
                            info,
                            ctx.cfg.probe_timeout(),
                            sni.as_deref(),
                        )
                        .await;
                        let record = outcome.into_record(port, info.name, Some(rtt_ms));
                        ctx.mutate(ip, |host| host.set_port(record));
                    }
                }
            }
        }
        Ok(Err(_)) => {
            // Connection refused: the host is up and the port is closed. This
            // is host discovery for free, and the port is not worth retrying.
            ctx.note_response(index);
            ctx.mutate(ip, |host| {
                let flipped = !host.alive;
                host.alive = true;
                host.add_source("tcp-refused");
                flipped
            });
        }
        Err(_) => {
            ctx.note_timeout(index, ip);
        }
    }
    ctx.done.fetch_add(1, Ordering::Relaxed);
}

/// A port record for something we connected to but did not identify.
fn plain_record(
    port: u16,
    service: &str,
    proto: &str,
    title: Option<&str>,
    rtt_ms: f64,
) -> PortRecord {
    PortRecord {
        port,
        service: service.to_string(),
        proto: proto.to_string(),
        state: "open".to_string(),
        tls: false,
        banner: None,
        product: None,
        version: None,
        title: title.map(|value| value.to_string()),
        server: None,
        url: None,
        status: None,
        note: Some("mDNS advertised".to_string()),
        rtt_ms: Some(rtt_ms),
    }
}

fn round_ms(duration: Duration) -> f64 {
    let ms = duration.as_secs_f64() * 1000.0;
    (ms * 100.0).round() / 100.0
}

/// Derive scan targets when none were given: every usable address on the
/// primary interface, plus anything the ARP cache already knows about.
pub fn default_targets(iface: &interfaces::LocalIface, max_hosts: usize) -> (Vec<Ipv4Addr>, bool) {
    let (mut hosts, truncated) = iface.hosts(max_hosts);
    for (ip, _, _) in interfaces::arp_table() {
        if !hosts.contains(&ip) && ip != iface.ip {
            hosts.push(ip);
        }
    }
    hosts.sort_by_key(|ip| u32::from(*ip));
    hosts.dedup();
    (hosts, truncated)
}

/// Run a full scan. Events go to the caller's channel; the summary and a
/// snapshot of the map come back so a watch loop can diff one round against
/// the next.
pub async fn run(
    cfg: ScanConfig,
    tx: UnboundedSender<Event>,
) -> (Summary, crate::diff::Snapshot) {
    let started = Instant::now();
    let interfaces_list = interfaces::local_interfaces();
    let route = interfaces::default_route();
    let primary = match route.as_ref().and_then(|(_, name)| {
        interfaces_list.iter().find(|i| &i.name == name).cloned()
    }) {
        Some(found) => Some(found),
        None => interfaces::primary_interface(),
    };

    // Targets: explicit, or the primary subnet plus ARP neighbours. The ARP
    // cache is context for a subnet scan; when the caller named the hosts, the
    // map should contain those hosts and nothing else but real discoveries.
    let explicit_targets = !cfg.targets.is_empty();
    let (targets, truncated) = if !cfg.targets.is_empty() {
        let mut list = cfg.targets.clone();
        list.sort_by_key(|ip| u32::from(*ip));
        list.dedup();
        let truncated = list.len() > cfg.max_hosts;
        list.truncate(cfg.max_hosts);
        (list, truncated)
    } else {
        match &primary {
            Some(iface) => default_targets(iface, cfg.max_hosts),
            None => (Vec::new(), false),
        }
    };

    let iface_infos: Vec<IfaceInfo> = interfaces_list
        .iter()
        .map(|iface| IfaceInfo {
            name: iface.name.clone(),
            ip: iface.ip.to_string(),
            prefix: iface.prefix,
            network: format!("{}/{}", iface.network(), iface.prefix),
            mac: iface.mac.clone(),
            is_default: primary.as_ref().map(|p| p.name == iface.name).unwrap_or(false),
        })
        .collect();

    let gateway = route.as_ref().map(|(ip, _)| *ip);
    let self_ips: Vec<Ipv4Addr> = interfaces_list.iter().map(|i| i.ip).collect();
    let hostname = crate::util::hostname();

    let total = (targets.len() as u64) * (cfg.ports.len() as u64);
    let ctx = Arc::new(Ctx {
        map: Mutex::new(MapState::new(gateway, self_ips.clone())),
        tx,
        started,
        done: AtomicU64::new(0),
        open: AtomicU64::new(0),
        total,
        timeout_us: AtomicU64::new(cfg.timeout.as_micros().max(1) as u64),
        rtt_min_us: AtomicU64::new(u64::MAX),
        successes: AtomicU32::new(0),
        skip: (0..targets.len()).map(|_| AtomicBool::new(false)).collect(),
        failures: (0..targets.len()).map(|_| AtomicU32::new(0)).collect(),
        finished: AtomicBool::new(false),
        skipped: AtomicU64::new(0),
        cfg: cfg.clone(),
    });

    ctx.send(Event::Meta(Meta {
        version: VERSION.to_string(),
        tool: TOOL.to_string(),
        hostname: hostname.clone(),
        started_ms: crate::util::now_ms(),
        round: cfg.round,
        interfaces: iface_infos,
        targets: targets.len(),
        ports: cfg.ports.len(),
        concurrency: cfg.concurrency,
        timeout_ms: cfg.timeout.as_millis() as u64,
        mdns: cfg.mdns.as_str().to_string(),
        gateway: gateway.map(|ip| ip.to_string()),
        truncated,
    }));

    if let Some(iface) = &primary {
        ctx.status(format!(
            "interface {} {}/{} gateway {}",
            iface.name,
            iface.ip,
            iface.prefix,
            gateway
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
    } else {
        ctx.status("no non-loopback IPv4 interface found");
    }

    // --- seed: self, gateway, ARP neighbours -------------------------------
    for iface in &interfaces_list {
        let mut names = Vec::new();
        if let Some(name) = hostname.clone() {
            names.push(name);
        }
        ctx.mutate(iface.ip, |host| {
            host.alive = true;
            host.is_self = true;
            host.add_source("self");
            if host.iface.is_none() {
                host.iface = Some(iface.name.clone());
            }
            if host.mac.is_none() {
                host.mac = iface.mac.clone();
            }
            let mut changed = false;
            for name in &names {
                changed |= host.add_name(name);
            }
            changed
        });
    }
    if let Some(gw) = gateway {
        ctx.mutate(gw, |host| {
            host.is_gateway = true;
            host.add_source("route");
            host.alive = true;
            if host.iface.is_none() {
                host.iface = Some(route.as_ref().map(|(_, n)| n.clone()).unwrap_or_default());
            }
            true
        });
    }
    let neighbours = if explicit_targets {
        Vec::new()
    } else {
        interfaces::arp_table()
    };
    for (ip, mac, iface_name) in neighbours {
        ctx.mutate(ip, |host| {
            let mut changed = host.add_source("arp");
            if host.mac.as_deref() != Some(mac.as_str()) {
                host.mac = Some(mac.clone());
                host.vendor = oui::lookup(&mac).map(|v| v.to_string());
                changed = true;
            }
            if host.iface.is_none() && !iface_name.is_empty() {
                host.iface = Some(iface_name.clone());
                changed = true;
            }
            // A complete ARP entry means the kernel talked to it recently.
            if !host.alive {
                host.alive = true;
                changed = true;
            }
            changed
        });
    }
    if !explicit_targets {
        ctx.status(format!(
            "{} neighbours known from the ARP cache",
            interfaces::arp_table().len()
        ));
    }

    // --- mDNS runs alongside the port scan ---------------------------------
    let mdns_handle = if cfg.mdns == MdnsMode::Off {
        None
    } else {
        let ctx_mdns = ctx.clone();
        let sink: mdns::RecordSink = Arc::new(move |record: MdnsRecord| {
            // Every record is kept for the services list and the stream.
            {
                let mut map = ctx_mdns.map.lock().unwrap_or_else(|e| e.into_inner());
                let mut all = map.mdns_records().to_vec();
                all.push(record.clone());
                map.set_mdns(all);
            }
            ctx_mdns.send(Event::Mdns(record.clone()));

            // Route it to a host: its own IPv4 address, or this machine when it
            // only resolved to loopback (avahi reports local services that way,
            // and a second 127.0.0.1 node on the map would be noise).
            let targets: Vec<Ipv4Addr> = match record
                .ip
                .as_deref()
                .and_then(|value| value.parse::<Ipv4Addr>().ok())
            {
                Some(ip) if !ip.is_loopback() => vec![ip],
                Some(_) => ctx_mdns.self_ips(),
                None => Vec::new(),
            };
            for ip in targets {
                ctx_mdns.mutate(ip, |host| {
                    let mut changed = host.add_source("mdns");
                    changed |= host.add_name(&record.host);
                    changed |= host.add_name(&record.name);
                    // The advertised port is deliberately NOT added to the port
                    // list here: only a TCP connect may claim that. Advertised
                    // ports are verified separately once mDNS has settled.
                    changed |= host.add_mdns(record.clone());
                    if !host.alive {
                        host.alive = true;
                        changed = true;
                    }
                    changed
                });
            }
        });
        ctx.status(format!(
            "mDNS: browsing {} seed types plus the meta query for {}ms",
            mdns::SEED_TYPES.len(),
            cfg.mdns_duration.as_millis()
        ));
        Some(tokio::spawn(mdns::discover(
            cfg.mdns,
            cfg.mdns_duration,
            sink,
        )))
    };

    // --- progress ticker ---------------------------------------------------
    let ticker = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(300)).await;
                if ctx.finished.load(Ordering::Relaxed) {
                    break;
                }
                let (alive, open_ports) = ctx.counters();
                ctx.send(Event::Progress {
                    phase: "ports".to_string(),
                    done: ctx.done.load(Ordering::Relaxed),
                    total: ctx.total,
                    alive,
                    open_ports,
                    elapsed_ms: ctx.started.elapsed().as_millis() as u64,
                });
            }
        })
    };

    // --- the port scan -----------------------------------------------------
    ctx.status(format!(
        "scanning {} hosts x {} ports ({} concurrent, {}ms timeout)",
        targets.len(),
        cfg.ports.len(),
        cfg.concurrency,
        cfg.timeout.as_millis()
    ));

    let host_count = targets.len();
    let port_count = cfg.ports.len();
    let mut window: JoinSet<()> = JoinSet::new();
    let mut cursor = 0u64;
    while cursor < total || !window.is_empty() {
        while window.len() < cfg.concurrency && cursor < total {
            let host_index = (cursor / port_count as u64) as usize;
            let port = cfg.ports[(cursor % port_count as u64) as usize];
            cursor += 1;
            if host_index >= host_count {
                continue;
            }
            let ctx = ctx.clone();
            let ip = targets[host_index];
            window.spawn(probe_one(ctx, host_index, ip, port));
        }
        if window.join_next().await.is_none() {
            break;
        }
    }

    let skipped = ctx.skipped.load(Ordering::Relaxed);
    if skipped > 0 {
        ctx.status(format!(
            "{skipped} hosts never answered and were dropped early; their remaining ports were not probed"
        ));
    }

    // --- NetBIOS names for whoever is still anonymous ----------------------
    if cfg.netbios {
        let candidates: Vec<Ipv4Addr> = {
            let map = ctx.map.lock().unwrap_or_else(|e| e.into_inner());
            map.hosts
                .values()
                .filter(|host| host.alive && host.names.is_empty() && !host.is_self)
                .map(|host| u32_to_ip(host.ip_num))
                .take(NETBIOS_LIMIT)
                .collect()
        };
        if !candidates.is_empty() {
            ctx.status(format!(
                "asking {} hosts for their NetBIOS name",
                candidates.len()
            ));
            let mut names: JoinSet<(Ipv4Addr, Option<String>)> = JoinSet::new();
            let mut index = 0usize;
            while index < candidates.len() || !names.is_empty() {
                while names.len() < NETBIOS_CONCURRENCY && index < candidates.len() {
                    let ip = candidates[index];
                    index += 1;
                    names.spawn(async move {
                        (ip, netbios::query_name(ip, Duration::from_millis(500)).await)
                    });
                }
                if let Some(Ok((ip, Some(name)))) = names.join_next().await {
                    ctx.mutate(ip, |host| {
                        let mut changed = host.add_name(&name);
                        changed |= host.add_source("netbios");
                        changed
                    });
                }
            }
        }
    }

    // --- wait for mDNS, then settle ----------------------------------------
    if let Some(handle) = mdns_handle {
        match handle.await {
            Ok(mode) => ctx.status(format!("mDNS finished ({mode})")),
            Err(_) => ctx.status("mDNS task failed"),
        }
    }

    // --- verify the ports that mDNS advertised -----------------------------
    // An advertisement is a claim; a TCP connect is evidence. Types ending in
    // ._udp.local. are ignored because they say nothing about a TCP port.
    let advertised: Vec<(Ipv4Addr, u16, String, String)> = {
        let map = ctx.map.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<(Ipv4Addr, u16, String, String)> = Vec::new();
        for record in map.mdns_records() {
            if record.port == 0 || !record.service_type.ends_with("._tcp.local.") {
                continue;
            }
            let Some(ip) = record
                .ip
                .as_deref()
                .and_then(|value| value.parse::<Ipv4Addr>().ok())
            else {
                continue;
            };
            if ip.is_loopback() || out.iter().any(|(a, b, _, _)| *a == ip && *b == record.port) {
                continue;
            }
            let already_open = map
                .get(ip)
                .map(|host| host.ports.iter().any(|p| p.port == record.port))
                .unwrap_or(false);
            if already_open {
                continue;
            }
            let service = record
                .service_type
                .trim_end_matches("._tcp.local.")
                .trim_start_matches('_')
                .to_string();
            out.push((ip, record.port, service, record.name.clone()));
        }
        out.truncate(96);
        out
    };

    if !advertised.is_empty() {
        ctx.status(format!(
            "verifying {} mDNS-advertised TCP ports",
            advertised.len()
        ));
        let mut verified: JoinSet<Option<(Ipv4Addr, PortRecord)>> = JoinSet::new();
        let mut index = 0usize;
        while index < advertised.len() || !verified.is_empty() {
            while verified.len() < 24 && index < advertised.len() {
                let (ip, port, service, title) = advertised[index].clone();
                index += 1;
                let timeout = cfg.timeout;
                let deep = cfg.deep_probe;
                verified.spawn(async move {
                    let started = Instant::now();
                    let opened = with_timeout(timeout, TcpStream::connect((ip, port)))
                        .await
                        .map(|result| result.is_ok())
                        .unwrap_or(false);
                    if !opened {
                        return None;
                    }
                    let rtt = round_ms(started.elapsed());
                    let record = match ports::lookup(port) {
                        Some(info) if deep => probe::identify(
                            ip,
                            port,
                            info,
                            Duration::from_millis(1200),
                            None,
                        )
                        .await
                        .into_record(port, info.name, Some(rtt)),
                        Some(info) => plain_record(port, info.name, info.name, None, rtt),
                        None => plain_record(port, &service, &service, Some(&title), rtt),
                    };
                    Some((ip, record))
                });
            }
            if let Some(Ok(Some((ip, record)))) = verified.join_next().await {
                ctx.open.fetch_add(1, Ordering::Relaxed);
                ctx.mutate(ip, |host| {
                    host.alive = true;
                    host.set_port(record)
                });
            }
        }
    }

    ctx.finished.store(true, Ordering::Relaxed);
    ticker.abort();

    // Final classification pass: the class depends on everything gathered, so
    // it is computed once at the end and emitted as the settled snapshot.
    let snapshot = {
        let map = ctx.map.lock().unwrap_or_else(|e| e.into_inner());
        map.ordered()
    };
    for host in &snapshot {
        let class = classify::classify(host);
        let ip = u32_to_ip(host.ip_num);
        ctx.mutate(ip, move |record| {
            if record.class.as_ref() == Some(&class) {
                return false;
            }
            record.class = Some(class);
            true
        });
    }

    let (alive, open_ports) = ctx.counters();
    let (hosts_total, services, classes) = {
        let map = ctx.map.lock().unwrap_or_else(|e| e.into_inner());
        let mut classes = std::collections::BTreeMap::new();
        for host in map.hosts.values() {
            if let Some(class) = &host.class {
                *classes.entry(class.label.clone()).or_insert(0usize) += 1;
            }
        }
        (
            map.len(),
            map.mdns_records().len(),
            classes,
        )
    };
    let elapsed = started.elapsed();
    let summary = Summary {
        elapsed_ms: elapsed.as_millis() as u64,
        hosts: hosts_total,
        alive,
        open_ports,
        services,
        classes,
    };
    let finished_snapshot = {
        let map = ctx.map.lock().unwrap_or_else(|e| e.into_inner());
        crate::diff::snapshot(&map)
    };

    ctx.send(Event::Done(summary.clone()));
    ctx.status(format!(
        "done in {}: {} hosts ({} alive), {} open ports, {} services",
        crate::util::fmt_ms(summary.elapsed_ms),
        summary.hosts,
        summary.alive,
        summary.open_ports,
        summary.services
    ));
    (summary, finished_snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_sane() {
        let cfg = ScanConfig::default();
        assert!(cfg.ports.len() > 100);
        assert!(cfg.concurrency >= 128);
        assert!(cfg.probe_timeout() >= cfg.timeout);
        assert_eq!(cfg.mdns, MdnsMode::Auto);
    }

    #[test]
    fn probe_timeout_is_bounded() {
        let mut cfg = ScanConfig::default();
        cfg.timeout = Duration::from_millis(50);
        assert_eq!(cfg.probe_timeout(), Duration::from_millis(700));
        cfg.timeout = Duration::from_secs(10);
        assert_eq!(cfg.probe_timeout(), Duration::from_millis(2500));
    }

    #[test]
    fn rounds_rtt_to_two_decimals() {
        assert_eq!(round_ms(Duration::from_micros(1234)), 1.23);
        assert_eq!(round_ms(Duration::from_millis(10)), 10.0);
    }

    #[test]
    fn default_targets_include_arp_neighbours() {
        let iface = interfaces::LocalIface {
            name: "test0".into(),
            ip: Ipv4Addr::new(192, 168, 1, 42),
            prefix: 24,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mac: None,
            is_link_local: false,
        };
        let (targets, truncated) = default_targets(&iface, 4096);
        assert!(!truncated);
        assert!(targets.len() >= 253);
        assert!(targets.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!targets.contains(&Ipv4Addr::new(192, 168, 1, 42)));
    }
}
