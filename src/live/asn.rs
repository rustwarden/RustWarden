//! "AS15169 · Google LLC" for remote addresses, from a free service chosen in Settings:
//! Team Cymru's DNS interface (via `nslookup`) or any JSON web API (via `curl.exe`).
//! Lookups run on one background thread; the UI only reads the cache.

use super::net::{Locality, classify};
use super::store::Shared;
use crate::settings::{NetInfoSource, Settings};
use std::collections::HashMap;
use std::net::IpAddr;
use std::os::windows::process::CommandExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Resolver {
    shared: Arc<Shared>,
    /// "" while a lookup is queued or when the service had no answer (kept until settings change).
    cache: Mutex<HashMap<IpAddr, String>>,
    queue: Mutex<Sender<IpAddr>>,
    /// Host name to address, rebuilt when `Shared::hostnames` grows, so names in the UI resolve too.
    names: Mutex<(usize, HashMap<String, IpAddr>)>,
    /// Lookups queued but not finished; past `MAX_PENDING` new addresses wait for a later call.
    pending: AtomicUsize,
}

const MAX_PENDING: usize = 500;

impl Resolver {
    pub fn new(shared: Arc<Shared>) -> (Arc<Self>, Receiver<IpAddr>) {
        let (tx, rx) = channel();
        (Arc::new(Self { shared, cache: Mutex::default(), queue: Mutex::new(tx), names: Mutex::default(), pending: AtomicUsize::new(0) }), rx)
    }

    /// Cached answer for an address or a host name seen earlier; queues a lookup on a miss.
    pub fn get(&self, host: &str) -> String {
        if self.shared.settings().net_info == NetInfoSource::Off {
            return String::new();
        }
        let Some(ip) = host.parse().ok().or_else(|| self.ip_of(host)) else { return String::new() };
        if classify(ip) != Locality::Wan {
            return String::new();
        }
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = cache.get(&ip) {
            return v.clone();
        }
        if self.pending.load(Ordering::Relaxed) >= MAX_PENDING {
            return String::new();
        }
        cache.insert(ip, String::new());
        self.pending.fetch_add(1, Ordering::Relaxed);
        let _ = self.queue.lock().unwrap_or_else(|e| e.into_inner()).send(ip);
        String::new()
    }

    pub fn clear(&self) {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn ip_of(&self, name: &str) -> Option<IpAddr> {
        let st = self.shared.state();
        let mut names = self.names.lock().unwrap_or_else(|e| e.into_inner());
        if names.0 != st.hostnames.len() {
            *names = (st.hostnames.len(), st.hostnames.iter().map(|(ip, n)| (n.clone(), *ip)).collect());
        }
        names.1.get(name).copied()
    }

    pub fn run(self: Arc<Self>, rx: Receiver<IpAddr>) {
        while !self.shared.stopping() {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(ip) => {
                    let found = lookup(ip, &self.shared.settings());
                    self.pending.fetch_sub(1, Ordering::Relaxed);
                    self.cache.lock().unwrap_or_else(|e| e.into_inner()).insert(ip, found);
                    self.shared.repaint();
                    std::thread::sleep(Duration::from_millis(200)); // shortcut: fixed ~5/s, add a setting if a service rate-limits
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}

/// Blocking lookup; "" when the service is off, unreachable or doesn't know the address.
pub fn lookup(ip: IpAddr, s: &Settings) -> String {
    if classify(ip) != Locality::Wan {
        return String::new();
    }
    match s.net_info {
        NetInfoSource::Off => None,
        NetInfoSource::TeamCymru => cymru(ip),
        NetInfoSource::Http => http(ip, &s.net_info_url),
    }
    .unwrap_or_default()
}

pub(super) fn run(program: &str, args: &[&str]) -> Option<String> {
    run_in(program, args, None)
}

/// A curl download of `url` with `args` before it. The address goes in on stdin (`-K -`), not the command line,
/// because it may carry a key and the command line shows in the process list.
pub(super) fn curl_url(args: &[&str], url: &str) -> Option<String> {
    let args: Vec<&str> = args.iter().copied().chain(["-K", "-"]).collect();
    run_in("curl.exe", &args, Some(&format!("{}url = {}\n", crate::sys::curl::PROTO, crate::sys::curl::quote(url))))
}

fn run_in(program: &str, args: &[&str], input: Option<&str>) -> Option<String> {
    use std::io::Write;
    let mut cmd = crate::sys::tool(program);
    let stdin = if input.is_some() { std::process::Stdio::piped() } else { std::process::Stdio::null() };
    cmd.args(args).stdin(stdin).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).creation_flags(crate::sys::NO_WINDOW);
    let mut child = crate::sys::etw::spawn_own(&mut cmd).ok()?;
    if let Some(input) = input {
        // Dropped at the end of the block, so curl sees the end of its config.
        child.stdin.take()?.write_all(input.as_bytes()).ok()?;
    }
    // A hung nslookup must not stall the lookup thread for good.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while child.try_wait().ok()?.is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn cymru_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let nibbles: Vec<String> = a.octets().iter().rev().flat_map(|b| [format!("{:x}", b & 15), format!("{:x}", b >> 4)]).collect();
            format!("{}.origin6.asn.cymru.com", nibbles.join("."))
        }
    }
}

/// The first quoted string of an `nslookup -type=TXT` answer.
fn txt(out: &str) -> Option<&str> {
    let rest = &out[out.find('"')? + 1..];
    Some(&rest[..rest.find('"')?])
}

fn cymru(ip: IpAddr) -> Option<String> {
    let out = run("nslookup", &["-type=TXT", &cymru_name(ip)])?;
    // "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"; announced by several ASes: "15169 36040 | ..."
    let asn = txt(&out)?.split('|').next()?.split_whitespace().next()?.to_owned();
    let org = run("nslookup", &["-type=TXT", &format!("AS{asn}.asn.cymru.com")]).and_then(|o| txt(&o).and_then(|t| t.rsplit('|').next()).map(|s| s.trim().to_owned()));
    format_info(Some(&asn), org.as_deref())
}

/// Registration details for an address from the free RDAP service rdap.org, as text lines.
pub fn whois(ip: &str) -> String {
    let Ok(ip) = ip.parse::<IpAddr>() else { return "Not an IP address.".into() };
    let Some(body) = run("curl.exe", &["-sL", "--max-time", "10", &format!("https://rdap.org/ip/{ip}")]) else { return "The whois service couldn't be reached.".into() };
    let lines: Vec<String> = [("Network", "name"), ("Handle", "handle"), ("From", "startAddress"), ("To", "endAddress"), ("Type", "type"), ("Country", "country")]
        .iter()
        .filter_map(|(label, key)| json_val(&body, key).map(|v| format!("{label}: {v}")))
        .collect();
    if lines.is_empty() {
        "The whois service had no answer for this address.".into()
    } else {
        lines.join(
            "
",
        )
    }
}

fn http(ip: IpAddr, template: &str) -> Option<String> {
    let url = template.replace("{ip}", &ip.to_string());
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return None; // curl would also open file:// and the like
    }
    from_json(&curl_url(&["-s", "--max-time", "5"], &url)?)
}

/// Value of the first `"key": value` in `text`, without parsing the document.
/// shortcut: first match wins and nesting is ignored, so switch to a JSON parser if a service needs it.
pub(super) fn json_val(text: &str, key: &str) -> Option<String> {
    let k = format!("\"{key}\"");
    let rest = text[text.find(&k)? + k.len()..].trim_start().strip_prefix(':')?.trim_start();
    match rest.strip_prefix('"') {
        Some(s) => Some(s[..s.find('"')?].to_owned()),
        None => Some(rest.split([',', '}', ' ', '\n']).next()?.to_owned()),
    }
}

fn from_json(text: &str) -> Option<String> {
    let org = ["org", "as_name", "as", "isp"].iter().find_map(|k| json_val(text, k));
    format_info(json_val(text, "asn").as_deref(), org.as_deref())
}

/// "AS15169 · Google LLC". The name may carry its own "AS15169 " prefix (ipinfo, ip-api).
fn format_info(asn: Option<&str>, org: Option<&str>) -> Option<String> {
    let org = org.map(str::trim).unwrap_or_default();
    let (from_org, name) = match org.strip_prefix("AS").filter(|r| r.starts_with(|c: char| c.is_ascii_digit())) {
        Some(r) => r.split_once(' ').unwrap_or((r, "")),
        None => ("", org),
    };
    let asn = asn.map(|a| a.trim_start_matches("AS")).filter(|a| !a.is_empty()).unwrap_or(from_org);
    if asn.is_empty() || !asn.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let name = name.trim();
    Some(if name.is_empty() { format!("AS{asn}") } else { format!("AS{asn} · {name}") })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cymru_names_are_reversed() {
        assert_eq!(cymru_name("8.8.4.0".parse().unwrap()), "0.4.8.8.origin.asn.cymru.com");
        let v6 = cymru_name("2001:db8::1".parse().unwrap());
        assert!(v6.starts_with("1.0.0.0.") && v6.ends_with("8.b.d.0.1.0.0.2.origin6.asn.cymru.com"), "{v6}");
    }

    #[test]
    fn nslookup_txt_and_cymru_fields() {
        let out = "Non-authoritative answer:\r\nx.origin.asn.cymru.com\ttext =\r\n\r\n\t\"15169 | 8.8.8.0/24 | US | arin | 2023-12-28\"\r\n";
        assert_eq!(txt(out).unwrap().split('|').next().unwrap().trim(), "15169");
        assert_eq!(txt("no quotes"), None);
    }

    #[test]
    fn json_shapes() {
        assert_eq!(from_json(r#"{"ip":"8.8.8.8","org": "AS15169 Google LLC"}"#).unwrap(), "AS15169 · Google LLC");
        assert_eq!(from_json(r#"{"as":"AS15169 Google LLC","isp":"Google"}"#).unwrap(), "AS15169 · Google LLC");
        assert_eq!(from_json(r#"{"connection":{"asn":15169,"org":"Google LLC"}}"#).unwrap(), "AS15169 · Google LLC");
        assert_eq!(from_json(r#"{"asn":"AS15169","as_name":"Google LLC"}"#).unwrap(), "AS15169 · Google LLC");
        assert_eq!(from_json(r#"{"error":"nope"}"#), None);
    }
}
