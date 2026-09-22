//! Device classification: turn port and mDNS evidence into a label and an icon.
//!
//! Every rule records why it fired, and the winning rule is the most specific
//! one that matched, so the panel can show a confidence and the user can see
//! the evidence instead of trusting a black box.

use crate::model::{DeviceClass, HostRecord};

// Nerd Font (Material Design Icons) glyphs. Verified present in
// JetBrainsMono Nerd Font, which is what omarchy ships and themes.
pub const GLYPH_ROUTER: &str = "\u{F1087}"; // md-router_network
pub const GLYPH_AP: &str = "\u{F0003}"; // md-access_point
pub const GLYPH_LAPTOP: &str = "\u{F0322}"; // md-laptop
pub const GLYPH_DESKTOP: &str = "\u{F01C5}"; // md-desktop_tower
pub const GLYPH_PHONE: &str = "\u{F011C}"; // md-cellphone
pub const GLYPH_TABLET: &str = "\u{F04F6}"; // md-tablet
pub const GLYPH_PRINTER: &str = "\u{F042A}"; // md-printer
pub const GLYPH_CAMERA: &str = "\u{F07AE}"; // md-cctv
pub const GLYPH_TV: &str = "\u{F0502}"; // md-television
pub const GLYPH_SPEAKER: &str = "\u{F04C3}"; // md-speaker
pub const GLYPH_NAS: &str = "\u{F08F3}"; // md-nas
pub const GLYPH_SERVER: &str = "\u{F048B}"; // md-server
pub const GLYPH_IOT: &str = "\u{F061A}"; // md-chip
pub const GLYPH_APPLE: &str = "\u{F0035}"; // md-apple
pub const GLYPH_WINDOWS: &str = "\u{F05B3}"; // md-microsoft_windows
pub const GLYPH_LINUX: &str = "\u{F033D}"; // md-linux
pub const GLYPH_PI: &str = "\u{F043F}"; // md-raspberry_pi
pub const GLYPH_CAST: &str = "\u{F0118}"; // md-cast
pub const GLYPH_WEB: &str = "\u{F01E7}"; // md-earth
pub const GLYPH_IP: &str = "\u{F0A5F}"; // md-ip
pub const GLYPH_UNKNOWN: &str = "\u{F02FC}"; // md-information

fn has_port(host: &HostRecord, port: u16) -> bool {
    host.ports.iter().any(|p| p.port == port)
}

fn has_proto(host: &HostRecord, proto: &str) -> bool {
    host.ports.iter().any(|p| p.proto == proto)
}

fn has_any_port(host: &HostRecord, ports: &[u16]) -> bool {
    host.ports.iter().any(|p| ports.contains(&p.port))
}

/// True when any mDNS service type contains the needle, e.g. "_airplay".
fn has_mdns(host: &HostRecord, needle: &str) -> bool {
    host.services
        .iter()
        .any(|s| s.service_type.to_ascii_lowercase().contains(needle))
}

/// True when any mDNS TXT record has this key (manufacturer=, model=, ...).
fn txt_value<'a>(host: &'a HostRecord, key: &str) -> Option<&'a str> {
    host.services
        .iter()
        .find_map(|s| s.txt.get(key).map(|v| v.as_str()))
}

fn vendor_is(host: &HostRecord, needle: &str) -> bool {
    host.vendor
        .as_deref()
        .map(|v| v.to_ascii_lowercase().contains(&needle.to_ascii_lowercase()))
        .unwrap_or(false)
}

fn class(
    key: &str,
    label: &str,
    glyph: &str,
    confidence: f32,
    evidence: Vec<String>,
) -> DeviceClass {
    DeviceClass {
        key: key.to_string(),
        label: label.to_string(),
        glyph: glyph.to_string(),
        confidence,
        evidence,
    }
}

fn ev(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// Name hints, matched against every alias the scan learned (mDNS, NetBIOS).
fn class_from_name(host: &HostRecord) -> Option<DeviceClass> {
    let names: Vec<String> = host
        .names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    if names.is_empty() {
        return None;
    }
    if let Some(name) = &names.first() {
        // Evidence quotes the alias that matched, so the panel can show why.
        let hints: &[(&[&str], &str, &str, f32)] = &[
            (
                &["truenas", "freenas", "synology", "diskstation", "qnap", "openmediavault", "unraid", "nas"],
                "nas",
                "NAS / file server",
                0.8,
            ),
            (&["raspberry", "rpi"], "pi", "Raspberry Pi", 0.75),
            (&["iphone", "ipad", "ipod"], "mobile", "iPhone / iPad", 0.8),
            (&["android", "oneplus", "redmi", "pocophone"], "android", "Android device", 0.7),
            (&["printer", "brother", "canon", "epson", "kyocera"], "printer", "Printer", 0.7),
            (&["camera", "ipcam", "dahua", "hikvision", "reolink", "doorbell"], "camera", "IP camera", 0.7),
            (&["apple-tv", "appletv", "bravia", "webostv", "roku", "firetv", "chromecast"], "tv", "TV / streaming", 0.65),
            (&["livebox", "fritz", "openwrt", "router", "gateway", "bbox"], "network", "Router / access point", 0.6),
        ];
        for (needles, key, label, confidence) in hints {
            if needles.iter().any(|needle| name.contains(needle)) {
                let glyph = match *key {
                    "nas" => GLYPH_NAS,
                    "pi" => GLYPH_PI,
                    "mobile" | "android" => GLYPH_PHONE,
                    "printer" => GLYPH_PRINTER,
                    "camera" => GLYPH_CAMERA,
                    "tv" => GLYPH_TV,
                    _ => GLYPH_ROUTER,
                };
                return Some(class(
                    key,
                    label,
                    glyph,
                    *confidence,
                    vec![format!("hostname {name}")],
                ));
            }
        }
    }
    None
}

/// Classify a host from the strongest available evidence.
///
/// Order matters: the first rule that matches wins, so put the things that can
/// only be one kind of device (a Chromecast, an iPhone, a printer) before the
/// things that are true of whole families (an open SSH port).
pub fn classify(host: &HostRecord) -> DeviceClass {
    if host.is_self {
        return class(
            "self",
            "This machine",
            GLYPH_LAPTOP,
            1.0,
            ev(&["local interface address"]),
        );
    }
    if host.is_gateway {
        return class(
            "gateway",
            "Router / Gateway",
            GLYPH_ROUTER,
            0.95,
            ev(&["default route"]),
        );
    }

    // --- mDNS-identified devices -------------------------------------------
    if has_mdns(host, "_googlecast") {
        return class(
            "chromecast",
            "Chromecast / Google TV",
            GLYPH_CAST,
            0.95,
            ev(&["mDNS _googlecast._tcp"]),
        );
    }
    if has_mdns(host, "_airplay") || has_mdns(host, "_raop") {
        let mut evidence = ev(&["mDNS _airplay._tcp"]);
        if let Some(model) = txt_value(host, "model") {
            evidence.push(format!("model {model}"));
        }
        return class("apple-tv", "Apple TV / AirPlay", GLYPH_TV, 0.9, evidence);
    }
    if has_mdns(host, "_spotify-connect") || has_mdns(host, "_sonos") {
        return class(
            "speaker",
            "Speaker",
            GLYPH_SPEAKER,
            0.85,
            ev(&["mDNS audio service"]),
        );
    }
    if has_mdns(host, "_hap") {
        return class(
            "homekit",
            "HomeKit accessory",
            GLYPH_IOT,
            0.85,
            ev(&["mDNS _hap._tcp"]),
        );
    }
    if has_mdns(host, "_home-assistant") || has_port(host, 8123) {
        return class(
            "home-assistant",
            "Home Assistant",
            GLYPH_SERVER,
            0.9,
            ev(&["port 8123", "mDNS _home-assistant"]),
        );
    }
    if has_mdns(host, "_printer")
        || has_mdns(host, "_ipp")
        || has_mdns(host, "_pdl-datastream")
        || has_any_port(host, &[631, 515, 9100])
    {
        let mut evidence = ev(&["printing service"]);
        if let Some(make) = txt_value(host, "usb_MDL").or_else(|| txt_value(host, "ty")) {
            evidence.push(format!("model {make}"));
        }
        return class("printer", "Printer", GLYPH_PRINTER, 0.9, evidence);
    }
    if has_mdns(host, "_sleep-proxy") || has_mdns(host, "_airport") {
        return class(
            "ap",
            "Access point",
            GLYPH_AP,
            0.8,
            ev(&["mDNS _sleep-proxy"]),
        );
    }
    if has_mdns(host, "_kdeconnect") {
        return class(
            "kdeconnect",
            "KDE Connect peer",
            GLYPH_DESKTOP,
            0.55,
            ev(&["mDNS _kdeconnect._udp"]),
        );
    }
    if has_mdns(host, "_adb-tls-connect") || has_mdns(host, "_adb") {
        return class(
            "android",
            "Android device",
            GLYPH_PHONE,
            0.8,
            ev(&["mDNS _adb-tls-connect._tcp"]),
        );
    }
    if has_mdns(host, "_apple-mobdev2") {
        return class(
            "mobile",
            "iPhone / iPad",
            GLYPH_PHONE,
            0.8,
            ev(&["mDNS _apple-mobdev2._tcp"]),
        );
    }
    if has_mdns(host, "_workstation") && (has_port(host, 445) || has_port(host, 3389)) {
        return class(
            "windows",
            "Windows PC",
            GLYPH_WINDOWS,
            0.85,
            ev(&["mDNS _workstation", "SMB/RDP"]),
        );
    }
    // --- hostname hints ----------------------------------------------------
    //
    // Weaker than mDNS or port evidence, stronger than the vendor table: a
    // "truenas.local" that answers on SMB is a NAS, not a Windows PC.
    if let Some(named) = class_from_name(host) {
        return named;
    }
    if has_mdns(host, "_smb") || has_mdns(host, "_device-info") {
        let mut evidence = ev(&["mDNS _smb._tcp"]);
        if has_port(host, 548) {
            evidence.push("AFP 548".into());
        }
        return class("nas", "NAS / file server", GLYPH_NAS, 0.75, evidence);
    }

    // --- port-signature devices --------------------------------------------
    if has_port(host, 62078) {
        return class(
            "mobile",
            "iPhone / iPad",
            GLYPH_PHONE,
            0.9,
            ev(&["port 62078 (iOS sync)"]),
        );
    }
    if has_proto(host, "rtsp") || (has_port(host, 554) && has_any_port(host, &[8000, 8080, 8554])) {
        return class(
            "camera",
            "IP camera / NVR",
            GLYPH_CAMERA,
            0.85,
            ev(&["RTSP 554"]),
        );
    }
    if has_port(host, 37777) {
        return class(
            "camera",
            "IP camera / NVR",
            GLYPH_CAMERA,
            0.7,
            ev(&["port 37777 (Dahua)"]),
        );
    }
    if has_port(host, 9100) || has_port(host, 631) {
        return class(
            "printer",
            "Printer",
            GLYPH_PRINTER,
            0.8,
            ev(&["port 9100/631"]),
        );
    }
    if has_port(host, 548) && has_any_port(host, &[445, 5000, 5001, 2049]) {
        return class("nas", "NAS / file server", GLYPH_NAS, 0.8, ev(&["AFP + SMB"]));
    }
    if has_any_port(host, &[5000, 5001, 7000, 3689, 32400, 8008, 8009])
        && (vendor_is(host, "apple") || has_port(host, 3689) || has_port(host, 62078))
    {
        return class(
            "apple",
            "Apple device",
            GLYPH_APPLE,
            0.6,
            ev(&["AirPlay/DAAP ports"]),
        );
    }
    if has_port(host, 8009) || has_port(host, 8008) {
        return class(
            "chromecast",
            "Chromecast / Google TV",
            GLYPH_CAST,
            0.7,
            ev(&["Google Cast 8008/8009"]),
        );
    }
    if has_port(host, 8060) {
        return class("tv", "Streaming device", GLYPH_TV, 0.7, ev(&["Roku ECP 8060"]));
    }
    if has_port(host, 3389) || has_port(host, 445) || has_port(host, 139) {
        let mut evidence = ev(&["SMB/RDP"]);
        if has_port(host, 22) {
            evidence.push("ssh open too".into());
            return class("windows", "Windows PC", GLYPH_WINDOWS, 0.65, evidence);
        }
        return class("windows", "Windows PC", GLYPH_WINDOWS, 0.75, evidence);
    }
    if has_any_port(host, &[1883, 8883]) {
        return class(
            "mqtt",
            "MQTT broker",
            GLYPH_SERVER,
            0.75,
            ev(&["MQTT 1883/8883"]),
        );
    }

    // --- vendor hints ------------------------------------------------------
    if vendor_is(host, "raspberry") {
        return class(
            "pi",
            "Raspberry Pi",
            GLYPH_PI,
            0.85,
            ev(&["OUI Raspberry Pi"]),
        );
    }
    if vendor_is(host, "espressif")
        || vendor_is(host, "shelly")
        || vendor_is(host, "tuya")
        || vendor_is(host, "philips hue")
    {
        return class(
            "iot",
            "IoT device",
            GLYPH_IOT,
            0.8,
            ev(&["OUI ESP/embedded radio"]),
        );
    }
    if vendor_is(host, "sonos") {
        return class(
            "speaker",
            "Speaker",
            GLYPH_SPEAKER,
            0.8,
            ev(&["OUI Sonos"]),
        );
    }
    if vendor_is(host, "roku") {
        return class("tv", "Streaming device", GLYPH_TV, 0.7, ev(&["OUI Roku"]));
    }
    if vendor_is(host, "samsung") && has_any_port(host, &[8001, 8002, 9197, 55000]) {
        return class("tv", "Smart TV", GLYPH_TV, 0.7, ev(&["OUI Samsung + TV ports"]));
    }
    if vendor_is(host, "lg ") || vendor_is(host, "lg electronics") {
        if has_any_port(host, &[3000, 3001, 9197, 9998]) {
            return class("tv", "Smart TV", GLYPH_TV, 0.7, ev(&["OUI LG + TV ports"]));
        }
    }
    if vendor_is(host, "apple") {
        return class(
            "apple",
            "Apple device",
            GLYPH_APPLE,
            0.6,
            ev(&["OUI Apple"]),
        );
    }
    if vendor_is(host, "amazon") {
        return class(
            "echo",
            "Amazon device",
            GLYPH_SPEAKER,
            0.6,
            ev(&["OUI Amazon"]),
        );
    }
    if vendor_is(host, "google") {
        return class(
            "chromecast",
            "Google device",
            GLYPH_CAST,
            0.6,
            ev(&["OUI Google"]),
        );
    }
    if vendor_is(host, "ubiquiti")
        || vendor_is(host, "mikrotik")
        || vendor_is(host, "tp-link")
        || vendor_is(host, "netgear")
        || vendor_is(host, "d-link")
        || vendor_is(host, "cisco")
        || vendor_is(host, "asus")
    {
        return class(
            "network",
            "Network device",
            GLYPH_ROUTER,
            0.7,
            ev(&["OUI network vendor"]),
        );
    }
    if vendor_is(host, "synology") || vendor_is(host, "qnap") {
        return class("nas", "NAS / file server", GLYPH_NAS, 0.8, ev(&["OUI NAS vendor"]));
    }
    if vendor_is(host, "hp")
        || vendor_is(host, "brother")
        || vendor_is(host, "epson")
        || vendor_is(host, "canon")
        || vendor_is(host, "kyocera")
    {
        return class(
            "printer",
            "Printer",
            GLYPH_PRINTER,
            0.75,
            ev(&["OUI printer vendor"]),
        );
    }
    if vendor_is(host, "vmware")
        || vendor_is(host, "virtualbox")
        || vendor_is(host, "qemu")
        || vendor_is(host, "hyper-v")
    {
        return class(
            "vm",
            "Virtual machine",
            GLYPH_SERVER,
            0.8,
            ev(&["OUI hypervisor"]),
        );
    }

    // --- protocol families -------------------------------------------------
    if has_proto(host, "ssh") && host.ports.len() >= 2 {
        let mut evidence = ev(&["ssh + more services"]);
        if has_port(host, 80) || has_port(host, 443) {
            evidence.push("web server".into());
        }
        if has_port(host, 3306) || has_port(host, 5432) {
            evidence.push("database".into());
        }
        if has_port(host, 2375) || has_port(host, 6443) || has_port(host, 10250) {
            evidence.push("container host".into());
        }
        return class("linux", "Linux server", GLYPH_LINUX, 0.6, evidence);
    }
    if has_port(host, 22) {
        return class(
            "server",
            "SSH host",
            GLYPH_SERVER,
            0.5,
            ev(&["port 22 (ssh)"]),
        );
    }
    if has_any_port(host, &[80, 443, 8080, 8443, 8000, 8888]) {
        return class("web", "Web device", GLYPH_WEB, 0.55, ev(&["HTTP/HTTPS open"]));
    }
    if !host.ports.is_empty() {
        return class("host", "Host", GLYPH_IP, 0.4, ev(&["open ports"]));
    }
    if !host.services.is_empty() {
        return class("mdns", "mDNS device", GLYPH_IP, 0.4, ev(&["mDNS only"]));
    }
    if host.alive {
        return class("host", "Host", GLYPH_IP, 0.3, ev(&["answered a probe"]));
    }
    class("unknown", "Unknown", GLYPH_UNKNOWN, 0.1, ev(&["no response"]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MdnsRecord, PortRecord};
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

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

    fn mdns(ty: &str, name: &str) -> MdnsRecord {
        MdnsRecord {
            name: name.into(),
            service_type: ty.into(),
            port: 0,
            host: "x.local".into(),
            ip: None,
            txt: BTreeMap::new(),
            source: "mdns".into(),
        }
    }

    /// The glyph codepoints were verified against the font itself (its cmap
    /// plus post-table names). They are easy to get wrong by one row, and a
    /// wrong codepoint renders a completely different icon, so pin them.
    #[test]
    fn glyphs_are_the_verified_codepoints() {
        let pairs = [
            (GLYPH_ROUTER, 0xF1087, "md-router_network"),
            (GLYPH_AP, 0xF0003, "md-access_point"),
            (GLYPH_LAPTOP, 0xF0322, "md-laptop"),
            (GLYPH_DESKTOP, 0xF01C5, "md-desktop_tower"),
            (GLYPH_PHONE, 0xF011C, "md-cellphone"),
            (GLYPH_PRINTER, 0xF042A, "md-printer"),
            (GLYPH_CAMERA, 0xF07AE, "md-cctv"),
            (GLYPH_TV, 0xF0502, "md-television"),
            (GLYPH_SPEAKER, 0xF04C3, "md-speaker"),
            (GLYPH_NAS, 0xF08F3, "md-nas"),
            (GLYPH_SERVER, 0xF048B, "md-server"),
            (GLYPH_IOT, 0xF061A, "md-chip"),
            (GLYPH_APPLE, 0xF0035, "md-apple"),
            (GLYPH_WINDOWS, 0xF05B3, "md-microsoft_windows"),
            (GLYPH_LINUX, 0xF033D, "md-linux"),
            (GLYPH_PI, 0xF043F, "md-raspberry_pi"),
            (GLYPH_CAST, 0xF0118, "md-cast"),
            (GLYPH_WEB, 0xF01E7, "md-earth"),
            (GLYPH_IP, 0xF0A5F, "md-ip"),
            (GLYPH_UNKNOWN, 0xF02FC, "md-information"),
        ];
        for (glyph, codepoint, name) in pairs {
            let actual: Vec<u32> = glyph.chars().map(|c| c as u32).collect();
            assert_eq!(actual, vec![codepoint], "{name} must be U+{codepoint:05X}");
        }
    }

    #[test]
    fn gateway_wins_over_ports() {
        let mut host = HostRecord::new(Ipv4Addr::new(192, 168, 1, 1));
        host.is_gateway = true;
        host.set_port(port(80, "http"));
        assert_eq!(classify(&host).key, "gateway");
    }

    #[test]
    fn airplay_beats_vendor() {
        let mut host = HostRecord::new(Ipv4Addr::new(192, 168, 1, 20));
        host.vendor = Some("Apple".into());
        host.add_mdns(mdns("_airplay._tcp.local.", "Living Room"));
        let c = classify(&host);
        assert_eq!(c.key, "apple-tv");
        assert!(c.evidence.iter().any(|e| e.contains("airplay")));
    }

    #[test]
    fn rtsp_is_a_camera() {
        let mut host = HostRecord::new(Ipv4Addr::new(192, 168, 1, 30));
        host.set_port(port(554, "rtsp"));
        host.set_port(port(8000, "http"));
        assert_eq!(classify(&host).key, "camera");
    }

    #[test]
    fn windows_from_smb() {
        let mut host = HostRecord::new(Ipv4Addr::new(192, 168, 1, 40));
        host.set_port(port(445, "microsoft-ds"));
        host.set_port(port(139, "netbios-ssn"));
        assert_eq!(classify(&host).key, "windows");
    }

    #[test]
    fn linux_server_from_ssh_and_web() {
        let mut host = HostRecord::new(Ipv4Addr::new(192, 168, 1, 50));
        host.set_port(port(22, "ssh"));
        host.set_port(port(80, "http"));
        assert_eq!(classify(&host).key, "linux");
    }

    #[test]
    fn ssh_only_is_a_server() {
        let mut host = HostRecord::new(Ipv4Addr::new(192, 168, 1, 51));
        host.set_port(port(22, "ssh"));
        assert_eq!(classify(&host).key, "server");
    }

    #[test]
    fn hostname_hints_classify_better_than_ports() {
        // The real case: a TrueNAS that answers on SMB used to come out as a
        // Windows PC because 445 was the strongest evidence available.
        let mut nas = HostRecord::new(Ipv4Addr::new(192, 168, 1, 12));
        nas.add_name("truenas.local");
        nas.set_port(port(22, "ssh"));
        nas.set_port(port(445, "microsoft-ds"));
        let classified = classify(&nas);
        assert_eq!(classified.key, "nas");
        assert!(classified.evidence.iter().any(|e| e.contains("truenas.local")));

        let mut phone = HostRecord::new(Ipv4Addr::new(10, 0, 0, 30));
        phone.add_name("Android_0123456789abcdef");
        assert_eq!(classify(&phone).key, "android");

        let mut pi = HostRecord::new(Ipv4Addr::new(10, 0, 0, 31));
        pi.add_name("raspberrypi");
        assert_eq!(classify(&pi).key, "pi");

        // mDNS evidence still wins over a name hint.
        let mut airplay = HostRecord::new(Ipv4Addr::new(10, 0, 0, 32));
        airplay.add_name("nas.local");
        airplay.add_mdns(mdns("_airplay._tcp.local.", "Salon"));
        assert_eq!(classify(&airplay).key, "apple-tv");
    }

    #[test]
    fn espressif_is_iot() {
        let mut host = HostRecord::new(Ipv4Addr::new(192, 168, 1, 60));
        host.vendor = Some("Espressif (IoT)".into());
        assert_eq!(classify(&host).key, "iot");
    }

    #[test]
    fn silence_is_unknown() {
        let host = HostRecord::new(Ipv4Addr::new(192, 168, 1, 99));
        assert_eq!(classify(&host).key, "unknown");
    }
}
