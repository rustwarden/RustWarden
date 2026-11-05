//! Prometheus text metrics on a localhost-only HTTP endpoint, off by default (Settings > Integrations).
//! The listener binds 127.0.0.1 only and answers `GET /metrics` alone. It also refuses any Host header other
//! than localhost, so a web page cannot read it through DNS rebinding.

use crate::applog;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const LOG: &str = "metrics.log";
/// Top apps reported, to keep the number of label values small.
const TOP_APPS: usize = 10;

/// What one scrape reports, over the last 24 hours unless noted. The backend builds it, so Demo mode serves canned numbers.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub wan_down: f64,
    pub wan_up: f64,
    pub blocked: u64,
    /// Alerts raised per kind key, all time.
    pub alerts: Vec<(String, u64)>,
    /// Busiest apps first: name, bytes down, bytes up.
    pub apps: Vec<(String, f64, f64)>,
}

/// Exposition-format text for `s`. Label values are escaped as the format requires.
pub fn render(s: &Snapshot) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# HELP rustywire_traffic_bytes Bytes moved to and from internet addresses in the last 24 hours.");
    let _ = writeln!(out, "# TYPE rustywire_traffic_bytes gauge");
    let _ = writeln!(out, "rustywire_traffic_bytes{{direction=\"down\"}} {}", s.wan_down);
    let _ = writeln!(out, "rustywire_traffic_bytes{{direction=\"up\"}} {}", s.wan_up);
    let _ = writeln!(out, "# HELP rustywire_blocked_connections Connection attempts blocked in the last 24 hours.");
    let _ = writeln!(out, "# TYPE rustywire_blocked_connections gauge");
    let _ = writeln!(out, "rustywire_blocked_connections {}", s.blocked);
    let _ = writeln!(out, "# HELP rustywire_alerts_total Alerts raised, by kind.");
    let _ = writeln!(out, "# TYPE rustywire_alerts_total counter");
    for (kind, n) in &s.alerts {
        let _ = writeln!(out, "rustywire_alerts_total{{kind=\"{}\"}} {n}", label(kind));
    }
    let _ = writeln!(out, "# HELP rustywire_app_traffic_bytes Bytes per app in the last 24 hours, for the busiest {TOP_APPS} apps.");
    let _ = writeln!(out, "# TYPE rustywire_app_traffic_bytes gauge");
    for (app, down, up) in s.apps.iter().take(TOP_APPS) {
        let app = label(app);
        let _ = writeln!(out, "rustywire_app_traffic_bytes{{app=\"{app}\",direction=\"down\"}} {down}");
        let _ = writeln!(out, "rustywire_app_traffic_bytes{{app=\"{app}\",direction=\"up\"}} {up}");
    }
    out
}

fn label(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// A running endpoint. Dropping it asks the thread to stop; the thread notices within a fraction of a second.
pub struct Endpoint {
    port: u16,
    stop: Arc<AtomicBool>,
}

impl Endpoint {
    /// Starts on 127.0.0.1:`port` without blocking. A port still held by a stopping endpoint is retried for a few
    /// seconds, and a bind that never succeeds is logged to metrics.log.
    pub fn start(port: u16, snapshot: Arc<dyn Fn() -> Result<Snapshot, String> + Send + Sync>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let spawned = std::thread::Builder::new().name("metrics".into()).spawn(move || {
            let Some(listener) = bind_retrying(port, &flag) else { return };
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => handle(stream, port, &*snapshot),
                    Err(_) => std::thread::sleep(Duration::from_millis(200)),
                }
            }
        });
        if let Err(e) = spawned {
            applog::line(LOG, &format!("Metrics thread not started: {e}"));
        }
        Self { port, stop }
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn bind_retrying(port: u16, stop: &AtomicBool) -> Option<TcpListener> {
    for _ in 0..50 {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => {
                // Accept without blocking, so a stop request is seen even when no client connects.
                listener.set_nonblocking(true).ok()?;
                return Some(listener);
            }
            Err(_) if !stop.load(Ordering::Relaxed) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return None,
        }
    }
    applog::line(LOG, &format!("Metrics endpoint not started: port {port} stayed in use."));
    None
}

/// Answers one request. `port` is the port this endpoint serves, for the Host check.
fn handle(mut stream: TcpStream, port: u16, snapshot: &dyn Fn() -> Result<Snapshot, String>) {
    // Accepted sockets may inherit non-blocking mode from the listener.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    // Headers end at a blank line; a request may arrive in pieces, so read until that line, a cap, or a close.
    let mut request_bytes = Vec::new();
    let mut chunk = [0u8; 1024];
    while !request_bytes.windows(4).any(|w| w == b"\r\n\r\n") && request_bytes.len() < 8192 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Err(_) => break,
            Ok(n) => request_bytes.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&request_bytes);
    let mut lines = text.lines();
    let mut request = lines.next().unwrap_or_default().split_whitespace();
    let (method, target) = (request.next().unwrap_or_default(), request.next().unwrap_or_default());
    let host = lines.take_while(|l| !l.is_empty()).find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim().eq_ignore_ascii_case("host").then(|| value.trim().to_owned())
    });
    let host_ok = host.is_some_and(|h| {
        let (name, host_port) = h.rsplit_once(':').map_or((h.as_str(), None), |(n, p)| (n, Some(p)));
        matches!(name, "127.0.0.1" | "localhost") && host_port.is_none_or(|p| p == port.to_string())
    });
    let path = target.split('?').next().unwrap_or_default();
    let (status, body) = if !host_ok {
        ("403 Forbidden", "Only localhost requests are served.\n".to_owned())
    } else if method != "GET" {
        ("405 Method Not Allowed", "Use GET.\n".to_owned())
    } else if path != "/metrics" {
        ("404 Not Found", "Try /metrics.\n".to_owned())
    } else {
        match snapshot() {
            Ok(s) => ("200 OK", render(&s)),
            Err(e) => ("500 Internal Server Error", format!("{e}\n")),
        }
    };
    let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = stream.write_all(response.as_bytes());
    // Lingering close: closing right after the write can reset a reply the client has not read yet (seen on Windows
    // loopback), so wait briefly for the client to close first.
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut rest = [0u8; 256];
    while matches!(stream.read(&mut rest), Ok(n) if n > 0) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Snapshot {
        Snapshot { wan_down: 10.0, wan_up: 2.0, blocked: 3, alerts: vec![("arp".into(), 4)], apps: vec![("Chrome".into(), 8.0, 1.0)] }
    }

    /// Sends `request` to a one-shot server thread running `handle`, and returns what the client read back.
    /// A reset before the reply is read is retried: it showed up in about one run in ten on Windows loopback even
    /// though the server had written the whole reply, and its cause was never traced.
    fn exchange(request: &str) -> String {
        for _ in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                handle(stream, port, &|| Ok(sample()));
            });
            let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
            client.write_all(request.replace("PORT", &port.to_string()).as_bytes()).unwrap();
            let mut reply = String::new();
            let read = client.read_to_string(&mut reply);
            drop(client);
            server.join().unwrap();
            match read {
                Ok(_) => return reply,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(e) => panic!("{e}"),
            }
        }
        panic!("the connection was reset three times in a row");
    }

    #[test]
    fn render_lists_each_metric_and_escapes_labels() {
        let text = render(&Snapshot { apps: vec![("a\"b\\c".into(), 1.0, 2.0)], ..sample() });
        assert!(text.contains("rustywire_traffic_bytes{direction=\"down\"} 10\n"));
        assert!(text.contains("rustywire_blocked_connections 3\n"));
        assert!(text.contains("rustywire_alerts_total{kind=\"arp\"} 4\n"));
        assert!(text.contains("rustywire_app_traffic_bytes{app=\"a\\\"b\\\\c\",direction=\"up\"} 2\n"));
    }

    #[test]
    fn metrics_answers_loopback_requests() {
        let reply = exchange("GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:PORT\r\n\r\n");
        assert!(reply.starts_with("HTTP/1.1 200 OK"));
        assert!(reply.contains("rustywire_blocked_connections 3"));
    }

    #[test]
    fn other_hosts_and_paths_are_refused() {
        assert!(exchange("GET /metrics HTTP/1.1\r\nHost: evil.example\r\n\r\n").starts_with("HTTP/1.1 403"));
        assert!(exchange("GET /metrics HTTP/1.1\r\nHost: localhost.evil.example:PORT\r\n\r\n").starts_with("HTTP/1.1 403"));
        assert!(exchange("GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n").starts_with("HTTP/1.1 404"));
        assert!(exchange("POST /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").starts_with("HTTP/1.1 405"));
    }
}
