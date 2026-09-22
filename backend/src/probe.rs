//! Service identification: what is actually listening on an open port.
//!
//! Unprivileged and passive-ish: read what the service says first, or send the
//! smallest request that makes it identify itself. TLS uses rustls with
//! certificate verification disabled on purpose - nothing is trusted or
//! exchanged here, we only ask which protocol is on the wire.

use std::net::Ipv4Addr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::TlsConnector;

use crate::model::PortRecord;
use crate::ports::{PortInfo, Probe};

/// What a probe learned. Every field is optional because services are rude.
#[derive(Clone, Debug, Default)]
pub struct RawProbe {
    pub proto: String,
    pub tls: bool,
    pub banner: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub url: Option<String>,
    pub status: Option<u16>,
    /// Short note shown next to the service, e.g. "TLS handshake ok".
    pub note: Option<String>,
}

impl RawProbe {
    fn unnamed(service: &str) -> Self {
        Self {
            proto: service.to_string(),
            ..Default::default()
        }
    }

    pub fn into_record(self, port: u16, service: &str, rtt_ms: Option<f64>) -> PortRecord {
        PortRecord {
            port,
            service: service.to_string(),
            proto: if self.proto.is_empty() {
                service.to_string()
            } else {
                self.proto
            },
            state: "open".to_string(),
            tls: self.tls,
            banner: self.banner,
            product: self.product,
            version: self.version,
            title: self.title,
            server: self.server,
            url: self.url,
            status: self.status,
            note: self.note,
            rtt_ms,
        }
    }
}

// ---------------------------------------------------------------- TLS setup

/// Certificate verifier that accepts anything. Deliberate: LAN services are
/// very often self-signed, and rejecting them would hide the service instead of
/// identifying it. No application data is ever sent over these connections.
#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_connector() -> TlsConnector {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let built = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth();
        Arc::new(built)
    });
    TlsConnector::from(config.clone())
}

/// Server name for the handshake: a known hostname when we have one (so SNI is
/// sent and virtual hosts answer), otherwise the literal IP.
fn server_name(ip: Ipv4Addr, sni: Option<&str>) -> ServerName<'static> {
    if let Some(name) = sni {
        if let Ok(parsed) = ServerName::try_from(name.to_string()) {
            return parsed;
        }
    }
    // An IPv4 literal always parses as ServerName::IpAddress, so this cannot
    // fail; the fallback only exists to keep the return type total.
    ServerName::try_from(ip.to_string())
        .unwrap_or_else(|_| ServerName::try_from("localhost").expect("static name parses"))
}

// ------------------------------------------------------------- io helpers

async fn connect(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<TcpStream> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    let _ = stream.set_nodelay(true);
    Some(stream)
}

/// Read whatever arrives until the peer goes quiet. A single read() often
/// returns only part of an HTTP head, so a short idle window is what decides
/// that the service has said all it is going to say.
async fn read_text<S: AsyncRead + Unpin>(stream: &mut S, max: usize, idle: Duration) -> String {
    let mut collected: Vec<u8> = Vec::new();
    let mut buffer = vec![0u8; 2048];
    loop {
        match tokio::time::timeout(idle, stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
            Ok(Ok(read)) => {
                collected.extend_from_slice(&buffer[..read]);
                if collected.len() >= max {
                    break;
                }
            }
        }
    }
    collected.truncate(max);
    String::from_utf8_lossy(&collected).to_string()
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) {
    let _ = stream.write_all(bytes).await;
    let _ = stream.flush().await;
}

// ------------------------------------------------------------- HTTP parsing

#[derive(Clone, Debug, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Parse an HTTP/1.x response head plus whatever body came with it. None when
/// the bytes are not HTTP at all, which is the signal to try the other
/// transport (plaintext vs TLS).
pub fn parse_http_response(raw: &str) -> Option<HttpResponse> {
    let (head, body) = match raw.find("\r\n\r\n") {
        Some(index) => (&raw[..index], &raw[index + 4..]),
        None => match raw.find("\n\n") {
            Some(index) => (&raw[..index], &raw[index + 2..]),
            None => (raw, ""),
        },
    };
    let mut lines = head.split(['\r', '\n']).filter(|line| !line.is_empty());
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next()?;
    if !version.to_ascii_uppercase().starts_with("HTTP/") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    // Keep the whole reason phrase: splitting on whitespace would turn
    // "Not Found" into "Not".
    let reason = status_line
        .splitn(3, ' ')
        .nth(2)
        .unwrap_or("")
        .trim()
        .to_string();
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Some(HttpResponse {
        status,
        reason,
        headers,
        body: body.to_string(),
    })
}

/// First title element in an HTML body, whitespace collapsed.
pub fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let open = lower[start..].find('>')? + start + 1;
    let end = lower[open..].find("</title")? + open;
    let title = body[open..end].split_whitespace().collect::<Vec<_>>().join(" ");
    let title = title.trim().to_string();
    if title.is_empty() {
        return None;
    }
    Some(title.chars().take(120).collect())
}

/// First x.y.z-looking version in a blob of text.
pub fn extract_version(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if !chars[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        let mut dots = 0;
        while index < chars.len()
            && (chars[index].is_ascii_alphanumeric() || chars[index] == '.' || chars[index] == '_')
        {
            if chars[index] == '.' {
                dots += 1;
            }
            index += 1;
        }
        let mut end = index;
        while end > start && !chars[end - 1].is_ascii_alphanumeric() {
            end -= 1;
        }
        if dots >= 1 && end > start + 2 {
            return Some(chars[start..end].iter().collect());
        }
    }
    None
}

/// Trim a banner to something a panel row can show.
fn clean_banner(text: &str) -> Option<String> {
    let first = text.lines().find(|line| !line.trim().is_empty())?;
    let printable: String = first
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let cleaned = printable.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        return None;
    }
    Some(cleaned.chars().take(160).collect())
}

/// Name the software behind a text banner, per service family.
pub fn parse_banner(service: &str, text: &str) -> (String, Option<String>, Option<String>) {
    let trimmed = text.trim_start();

    if let Some(rest) = trimmed.strip_prefix("SSH-") {
        let software = rest.split_whitespace().next().unwrap_or("");
        let software = software.split('-').nth(1).unwrap_or(software);
        let product = software.split('_').next().unwrap_or(software);
        return (
            "ssh".to_string(),
            Some(product.to_string()).filter(|p| !p.is_empty()),
            extract_version(software),
        );
    }
    if trimmed.starts_with("+PONG") || trimmed.starts_with("-NOAUTH") {
        return ("redis".to_string(), Some("Redis".to_string()), None);
    }
    if let Some(rest) = trimmed.strip_prefix("VERSION ") {
        let version = rest.split_whitespace().next().map(|v| v.to_string());
        return ("memcached".to_string(), Some("memcached".to_string()), version);
    }
    if trimmed.starts_with("RFB ") {
        return ("vnc".to_string(), Some("VNC".to_string()), extract_version(trimmed));
    }
    if trimmed.starts_with("RTSP/") {
        let server = trimmed
            .lines()
            .find_map(|line| line.strip_prefix("Server:").map(|v| v.trim().to_string()));
        let product = server.as_deref().and_then(|value| {
            value
                .split_once('/')
                .map(|(name, _)| name.trim().to_string())
                .filter(|name| !name.is_empty())
        });
        let version = server.as_deref().and_then(|value| {
            value
                .split_once('/')
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .map(|v| v.to_string())
                .filter(|v| !v.is_empty())
        });
        return ("rtsp".to_string(), product, version);
    }
    if let Some(rest) = trimmed.strip_prefix("220 ") {
        let lower = rest.to_ascii_lowercase();
        if lower.contains("smtp") || service == "smtp" || service == "submission" {
            let product = rest.split_whitespace().last().map(|p| p.to_string());
            return ("smtp".to_string(), product, extract_version(rest));
        }
        // "(vsFTPd 3.0.5)" and "ProFTPD 1.3.8 Server (...)" are the two shapes
        // in the wild for the FTP greeting.
        let trimmed_rest = rest.trim_start();
        let product = if let Some(inner) = trimmed_rest.strip_prefix('(') {
            inner
                .split(')')
                .next()
                .and_then(|value| value.split_whitespace().next())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        } else {
            trimmed_rest
                .split_whitespace()
                .find(|chunk| {
                    chunk
                        .chars()
                        .next()
                        .map(|c| c.is_ascii_alphanumeric())
                        .unwrap_or(false)
                        && !chunk.contains('.')
                })
                .map(|chunk| chunk.trim_matches(|c| c == '(' || c == ')').to_string())
        };
        return ("ftp".to_string(), product, extract_version(rest));
    }
    if trimmed.starts_with("+OK") {
        let lower = trimmed.to_ascii_lowercase();
        let product = if lower.contains("dovecot") {
            Some("Dovecot".to_string())
        } else {
            None
        };
        return ("pop3".to_string(), product, extract_version(trimmed));
    }
    if trimmed.starts_with("* OK") || trimmed.starts_with("* PREAUTH") {
        let lower = trimmed.to_ascii_lowercase();
        let product = if lower.contains("dovecot") {
            Some("Dovecot".to_string())
        } else if lower.contains("gmail") {
            Some("Gmail".to_string())
        } else {
            None
        };
        return ("imap".to_string(), product, extract_version(trimmed));
    }
    if trimmed.starts_with("AMQP") {
        return ("amqp".to_string(), Some("RabbitMQ".to_string()), None);
    }
    // MySQL and MariaDB speak first with a binary handshake that carries the
    // version string as plain text near the front.
    let head: String = trimmed.chars().take(120).collect();
    if let Some(version) = extract_version(&head) {
        let lower = head.to_ascii_lowercase();
        if lower.contains("mysql") || lower.contains("mariadb") || service == "mysql" {
            let product = if lower.contains("mariadb") { "MariaDB" } else { "MySQL" };
            return ("mysql".to_string(), Some(product.to_string()), Some(version));
        }
    }
    (service.to_string(), None, extract_version(trimmed))
}

// ------------------------------------------------------------------ probes

async fn banner_probe(
    ip: Ipv4Addr,
    port: u16,
    info: &PortInfo,
    timeout: Duration,
    payload: Option<&[u8]>,
) -> RawProbe {
    let started = std::time::Instant::now();
    let Some(mut stream) = connect(ip, port, timeout).await else {
        return RawProbe::unnamed(info.name);
    };
    if let Some(bytes) = payload {
        send(&mut stream, bytes).await;
    }
    let text = read_text(&mut stream, 4096, timeout.min(Duration::from_millis(700))).await;
    if text.is_empty() {
        return RawProbe::unnamed(info.name);
    }
    let (proto, product, version) = parse_banner(info.name, &text);
    RawProbe {
        proto,
        tls: false,
        banner: clean_banner(&text),
        product,
        version,
        note: Some(format!("answered in {}ms", started.elapsed().as_millis())),
        ..Default::default()
    }
}

fn http_request(host_header: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.0\r\nHost: {host_header}\r\nUser-Agent: netmap/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
}

async fn http_over<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host_header: &str,
    tls: bool,
    port: u16,
) -> Option<RawProbe> {
    send(stream, http_request(host_header, "/").as_bytes()).await;
    let text = read_text(stream, 16384, Duration::from_millis(700)).await;
    let response = parse_http_response(&text)?;
    if !(100..600).contains(&response.status) {
        return None;
    }
    let server_header = response.header("server").map(|s| s.to_string());
    let product = server_header
        .as_deref()
        .and_then(|value| value.split('/').next().map(|p| p.trim().to_string()))
        .filter(|p| !p.is_empty());
    let version = server_header
        .as_deref()
        .and_then(|value| {
            value
                .split_once('/')
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .map(|v| v.to_string())
        })
        .filter(|v| !v.is_empty())
        .or_else(|| {
            let head: String = response.body.chars().take(512).collect();
            extract_version(&head)
        });
    let title = extract_title(&response.body);
    let scheme = if tls { "https" } else { "http" };
    let default_port = if tls { 443 } else { 80 };
    let url = if port == default_port {
        format!("{scheme}://{host_header}/")
    } else {
        format!("{scheme}://{host_header}:{port}/")
    };
    let note = match response.header("location") {
        Some(location) if location.starts_with("https://") && !tls => {
            Some("redirects to https".to_string())
        }
        Some(location) if location.starts_with("http://") && tls => {
            Some("redirects to http".to_string())
        }
        _ => None,
    };
    Some(RawProbe {
        proto: if tls { "https".into() } else { "http".into() },
        tls,
        banner: Some(
            format!("HTTP {} {}", response.status, response.reason)
                .trim()
                .to_string(),
        ),
        product,
        version,
        title,
        server: server_header,
        url: Some(url),
        status: Some(response.status),
        note,
    })
}

/// HTTP(S) probe that is forgiving about which transport the service actually
/// speaks: an "https" port serving plain HTTP (or the reverse) is still
/// identified, which is exactly the possible-protocol answer we want.
async fn http_probe(
    ip: Ipv4Addr,
    port: u16,
    info: &PortInfo,
    timeout: Duration,
    sni: Option<&str>,
    prefer_tls: bool,
) -> RawProbe {
    let host_header = sni.map(|s| s.to_string()).unwrap_or_else(|| ip.to_string());
    let order = if prefer_tls { [true, false] } else { [false, true] };
    let mut opened = false;
    for tls in order {
        if tls {
            let Some(stream) = connect(ip, port, timeout).await else {
                continue;
            };
            let name = server_name(ip, sni);
            let Ok(Ok(mut tls_stream)) =
                tokio::time::timeout(timeout, tls_connector().connect(name, stream)).await
            else {
                continue;
            };
            opened = true;
            if let Some(mut outcome) = http_over(&mut tls_stream, &host_header, true, port).await {
                outcome
                    .note
                    .get_or_insert_with(|| "TLS handshake ok".to_string());
                return outcome;
            }
            // TLS completed but no HTTP: knowing the port speaks TLS at all is
            // still the answer to "which protocol is this".
            let text = read_text(&mut tls_stream, 1024, Duration::from_millis(400)).await;
            return RawProbe {
                proto: "tls".to_string(),
                tls: true,
                banner: clean_banner(&text),
                product: Some(info.name.to_string()),
                note: Some("TLS handshake ok, no HTTP response".to_string()),
                ..Default::default()
            };
        }
        let Some(mut stream) = connect(ip, port, timeout).await else {
            continue;
        };
        opened = true;
        if let Some(mut outcome) = http_over(&mut stream, &host_header, false, port).await {
            outcome.note.get_or_insert_with(|| "plain HTTP".to_string());
            return outcome;
        }
    }
    // The port is open and is expected to be a web port, but nothing we sent
    // produced an HTTP response. Still offer the URL - and say so in the note -
    // instead of leaving the user with a port number and no action.
    if opened {
        let scheme = if prefer_tls { "https" } else { "http" };
        let default_port = if prefer_tls { 443 } else { 80 };
        let url = if port == default_port {
            format!("{scheme}://{host_header}/")
        } else {
            format!("{scheme}://{host_header}:{port}/")
        };
        return RawProbe {
            proto: info.name.to_string(),
            tls: prefer_tls,
            url: Some(url),
            note: Some("open, but no HTTP response".to_string()),
            ..Default::default()
        };
    }
    RawProbe::unnamed(info.name)
}

async fn tls_banner_probe(
    ip: Ipv4Addr,
    port: u16,
    info: &PortInfo,
    timeout: Duration,
    sni: Option<&str>,
) -> RawProbe {
    let Some(stream) = connect(ip, port, timeout).await else {
        return RawProbe::unnamed(info.name);
    };
    let name = server_name(ip, sni);
    let Ok(Ok(mut tls_stream)) =
        tokio::time::timeout(timeout, tls_connector().connect(name, stream)).await
    else {
        // TLS refused: the port may still be plaintext after all.
        return banner_probe(ip, port, info, timeout, None).await;
    };
    let text = read_text(&mut tls_stream, 4096, Duration::from_millis(600)).await;
    let (proto, product, version) = parse_banner(info.name, &text);
    RawProbe {
        proto,
        tls: true,
        banner: clean_banner(&text),
        product,
        version,
        note: Some("TLS handshake ok".to_string()),
        ..Default::default()
    }
}

/// Identify whatever is listening on an open port.
pub async fn identify(
    ip: Ipv4Addr,
    port: u16,
    info: &PortInfo,
    timeout: Duration,
    sni: Option<&str>,
) -> RawProbe {
    match info.probe {
        Probe::None => RawProbe::unnamed(info.name),
        Probe::Banner => banner_probe(ip, port, info, timeout, None).await,
        Probe::Redis => banner_probe(ip, port, info, timeout, Some(b"PING\r\n")).await,
        Probe::Memcached => banner_probe(ip, port, info, timeout, Some(b"version\r\n")).await,
        Probe::Rtsp => {
            let payload = format!(
                "OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: netmap/0.1\r\n\r\n"
            );
            let mut outcome =
                banner_probe(ip, port, info, timeout, Some(payload.as_bytes())).await;
            // A media player needs a URL. The camera-specific path usually needs
            // credentials, so offer the RTSP root and let the player ask.
            outcome.url = Some(format!("rtsp://{ip}:{port}/"));
            outcome
        }
        Probe::Http => http_probe(ip, port, info, timeout, sni, false).await,
        Probe::Https => http_probe(ip, port, info, timeout, sni, true).await,
        Probe::Tls => tls_banner_probe(ip, port, info, timeout, sni).await,
    }
}

/// True when a URL needs a media player rather than a browser.
pub fn is_media_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("rtsp://")
        || lower.starts_with("rtsps://")
        || lower.starts_with("rtmp://")
        || lower.starts_with("mms://")
}

/// Probe a service that is already known to be open, for the CLI's one-shot
/// identification path and for tests.
pub async fn identify_by_port(
    ip: Ipv4Addr,
    port: u16,
    timeout: Duration,
) -> Option<PortRecord> {
    let info = crate::ports::lookup(port)?;
    Some(identify(ip, port, info, timeout, None).await.into_record(port, info.name, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_whole_reason_phrase() {
        let response = parse_http_response("HTTP/1.1 404 Not Found\r\n\r\n").expect("parsed");
        assert_eq!(response.reason, "Not Found");
        assert_eq!(response.status, 404);
    }

    #[test]
    fn parses_a_plain_http_response() {
        let raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><head><title> Router   Admin </title></head></html>";
        let response = parse_http_response(raw).expect("valid http");
        assert_eq!(response.status, 200);
        assert_eq!(response.reason, "OK");
        assert_eq!(response.header("server"), Some("nginx/1.24.0 (Ubuntu)"));
        assert_eq!(extract_title(&response.body).as_deref(), Some("Router Admin"));
    }

    #[test]
    fn rejects_non_http_bytes() {
        assert!(parse_http_response("SSH-2.0-OpenSSH_9.6\r\n").is_none());
        assert!(parse_http_response("").is_none());
        assert!(parse_http_response("HTTP/1.1 bogus\r\n\r\n").is_none());
    }

    #[test]
    fn unnamed_probe_has_no_url() {
        let probe = RawProbe::unnamed("http");
        assert_eq!(probe.proto, "http");
        assert!(probe.url.is_none(), "no evidence means no URL to offer");
    }

    #[test]
    fn reads_ssh_banners() {
        let (proto, product, version) = parse_banner("ssh", "SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n");
        assert_eq!(proto, "ssh");
        assert_eq!(product.as_deref(), Some("OpenSSH"));
        assert_eq!(version.as_deref(), Some("9.6p1"));
    }

    #[test]
    fn reads_ftp_smtp_and_pop3() {
        let (proto, product, _) = parse_banner("ftp", "220 (vsFTPd 3.0.5)\r\n");
        assert_eq!(proto, "ftp");
        assert_eq!(product.as_deref(), Some("vsFTPd"));
        let (proto, product, _) = parse_banner("smtp", "220 mail.example.com ESMTP Postfix\r\n");
        assert_eq!(proto, "smtp");
        assert_eq!(product.as_deref(), Some("Postfix"));
        let (proto, product, _) = parse_banner("pop3", "+OK Dovecot ready.\r\n");
        assert_eq!(proto, "pop3");
        assert_eq!(product.as_deref(), Some("Dovecot"));
    }

    #[test]
    fn reads_redis_and_vnc() {
        assert_eq!(parse_banner("redis", "+PONG\r\n").0, "redis");
        let (proto, _, version) = parse_banner("vnc", "RFB 003.008\n");
        assert_eq!(proto, "vnc");
        assert_eq!(version.as_deref(), Some("003.008"));
    }

    #[test]
    fn extracts_versions() {
        assert_eq!(extract_version("nginx/1.24.0").as_deref(), Some("1.24.0"));
        assert_eq!(extract_version("no version here").as_deref(), None);
        assert_eq!(extract_version("ariaDB-1:10.11.6").as_deref(), Some("10.11.6"));
    }

    #[test]
    fn handles_multibyte_without_panicking() {
        let body = format!("<title>{}</title>", "café".repeat(200));
        assert!(extract_title(&body).is_some());
    }
}
