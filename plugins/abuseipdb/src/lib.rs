//! AbuseIPDB: how often an address has been reported for abuse (scans, brute force, spam). Look up any address on
//! the AbuseIPDB tab, or let the plugin check the public addresses in RustWarden's alerts as they happen (needs the
//! "alerts.read" permission). Only the address you ask about is sent, with your API key.

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Event, Kind, Manifest, Reply, TabDef, UiTree};
use serde_json::Value;
use std::net::IpAddr;

struct AbuseIpDb;

const KEEP: usize = 20;
/// An address looked up this recently isn't asked about again.
const FRESH_SECS: i64 = 86_400;
const DEFAULT_ALERT_SCORE: f64 = 50.0;

/// One answer: address, score (0-100), reports, country, provider, when it was looked up.
#[derive(Debug, PartialEq)]
struct Verdict {
    ip: String,
    score: u32,
    reports: u64,
    country: String,
    isp: String,
    at: i64,
}

impl Verdict {
    fn parse(json: &str, at: i64) -> Option<Self> {
        let v: Value = serde_json::from_str(json).ok()?;
        let d = &v["data"];
        Some(Self {
            ip: d["ipAddress"].as_str()?.to_owned(),
            score: u32::try_from(d["abuseConfidenceScore"].as_u64()?).ok()?,
            reports: d["totalReports"].as_u64().unwrap_or(0),
            country: d["countryCode"].as_str().unwrap_or("").to_owned(),
            isp: d["isp"].as_str().unwrap_or("").replace(['|', '\n'], " "),
            at,
        })
    }

    fn line(&self) -> String {
        format!("{}|{}|{}|{}|{}|{}", self.ip, self.score, self.reports, self.country, self.isp, self.at)
    }

    fn from_line(line: &str) -> Option<Self> {
        let mut f = line.splitn(6, '|');
        Some(Self { ip: f.next()?.to_owned(), score: f.next()?.parse().ok()?, reports: f.next()?.parse().ok()?, country: f.next()?.to_owned(), isp: f.next()?.to_owned(), at: f.next()?.parse().ok()? })
    }

    fn summary(&self) -> String {
        let rating = match self.score {
            0..=9 => "no sign of abuse",
            10..=49 => "some reports",
            50..=79 => "often reported",
            _ => "very likely abusive",
        };
        let country = if self.country.is_empty() { String::new() } else { format!(", {}", self.country) };
        let isp = if self.isp.is_empty() { String::new() } else { format!(", {}", self.isp) };
        format!("{}: {}% abuse confidence ({rating}), {} report(s){country}{isp}", self.ip, self.score, self.reports)
    }
}

/// A key is a plain token: letters and digits only.
fn key_ok(key: &str) -> bool {
    !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn recent() -> Vec<Verdict> {
    guest::config_get("recent").lines().filter_map(Verdict::from_line).collect()
}

fn remember(v: Verdict) {
    let mut list = recent();
    list.retain(|o| o.ip != v.ip);
    list.insert(0, v);
    list.truncate(KEEP);
    guest::config_set("recent", &list.iter().map(Verdict::line).collect::<Vec<_>>().join("\n"));
}

fn demo_verdict(ip: &str) -> Verdict {
    let score = ip.bytes().fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(u32::from(b))) % 100;
    Verdict { ip: ip.to_owned(), score, reports: u64::from(score) * 3, country: "NL".into(), isp: "Demo Hosting".into(), at: guest::now() }
}

fn lookup(ip: &str) -> Result<Verdict, String> {
    let ip: IpAddr = ip.trim().parse().map_err(|_| "That isn't an IP address.".to_owned())?;
    if guest::is_demo() {
        return Ok(demo_verdict(&ip.to_string()));
    }
    let key = guest::secret_get("key");
    if !key_ok(&key) {
        return Err("Enter your AbuseIPDB API key in this plugin's settings first.".to_owned());
    }
    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90");
    match guest::http_raw(&url, &[format!("Key: {key}"), "Accept: application/json".to_owned()], None, false)? {
        (200, body) => Verdict::parse(&body, guest::now()).ok_or_else(|| "AbuseIPDB's answer couldn't be read.".to_owned()),
        (401 | 403, _) => Err("AbuseIPDB refused the API key.".to_owned()),
        (429, _) => Err("AbuseIPDB's daily limit for this key is used up.".to_owned()),
        (status, _) => Err(format!("AbuseIPDB answered HTTP {status}.")),
    }
}

/// Public addresses written in an alert's text, in order.
fn public_addresses(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for token in text.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':')) {
        if let Ok(ip) = token.trim_matches(['.', ':']).parse::<IpAddr>()
            && is_public(ip)
            && !out.contains(&ip)
        {
            out.push(ip);
        }
    }
    out
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let shared = a.octets()[0] == 100 && (64..128).contains(&a.octets()[1]);
            !(a.is_private() || a.is_loopback() || a.is_link_local() || a.is_multicast() || a.is_unspecified() || a.is_broadcast() || shared)
        }
        IpAddr::V6(a) => !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80),
    }
}

fn threshold() -> f64 {
    guest::config_get("alert_score").parse().unwrap_or(DEFAULT_ALERT_SCORE)
}

fn on_alert(title: &str, text: &str) {
    if guest::config_get("auto") != "1" {
        return;
    }
    let now = guest::now();
    for ip in public_addresses(&format!("{title} {text}")).into_iter().take(3) {
        let name = ip.to_string();
        if recent().iter().any(|v| v.ip == name && now - v.at < FRESH_SECS) {
            continue;
        }
        match lookup(&name) {
            Ok(v) => {
                if f64::from(v.score) >= threshold() {
                    guest::notify_in_app(&format!("AbuseIPDB: {}", v.summary()));
                }
                remember(v);
            }
            Err(e) => {
                guest::log(&format!("alert lookup failed: {e}"));
                break;
            }
        }
    }
}

fn tab() -> UiTree {
    let mut rows = vec![
        UiTree::Info("AbuseIPDB scores how often an address has been reported for abuse. Look one up here, or switch on automatic checks in this plugin's settings to see the score of the addresses in your alerts.".into()),
        UiTree::Label("Address".into()),
        UiTree::Row(vec![UiTree::TextField { id: "ip".into(), value: guest::config_get("ip") }, UiTree::Button { id: "lookup".into(), text: "Look up".into() }]),
    ];
    let result = guest::config_get("result");
    if !result.is_empty() {
        rows.push(UiTree::Label(result));
    }
    let list = recent();
    if !list.is_empty() {
        rows.push(UiTree::Separator);
        rows.push(UiTree::Heading("Recent lookups".into()));
        rows.extend(list.iter().map(|v| UiTree::Label(v.summary())));
    }
    UiTree::Column(rows)
}

fn settings() -> UiTree {
    let key = guest::secret_get("key");
    let mut rows = vec![
        UiTree::Link { text: "Get a free API key (1,000 lookups a day)".into(), url: "https://www.abuseipdb.com/account/api".into() },
        UiTree::Label("API key".into()),
        UiTree::Password { id: "key".into(), value: key.clone() },
    ];
    if !key.is_empty() && !key_ok(&key) {
        rows.push(UiTree::Label("⚠ A key is letters and digits only; this one will not be used.".into()));
    }
    rows.push(UiTree::Switch { id: "auto".into(), text: "Check the addresses in alerts automatically".into(), on: guest::config_get("auto") == "1" });
    rows.push(UiTree::Weak("Needs the \"alerts.read\" permission. Each new address in an alert is looked up once a day and shown in the app when its score reaches the level below.".into()));
    rows.push(UiTree::Label("Notify from a score of".into()));
    rows.push(UiTree::Number { id: "alert_score".into(), value: threshold(), min: 1.0, max: 100.0 });
    UiTree::Column(rows)
}

impl Guest for AbuseIpDb {
    fn manifest() -> Manifest {
        Manifest {
            id: "abuseipdb".into(),
            name: "AbuseIPDB".into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            tabs: vec![TabDef { id: "abuseipdb".into(), title: "AbuseIPDB".into() }],
            settings_page: true,
            http_hosts: vec!["api.abuseipdb.com".into()],
            permissions: vec!["alerts.read".into()],
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderTab { .. } => Reply::Ui(tab()),
            Call::RenderSettings => Reply::Ui(settings()),
            Call::Event(Event::Text { id, value }) if id == "ip" => {
                guest::config_set("ip", value.trim());
                Reply::Done
            }
            Call::Event(Event::Text { id, value }) if id == "key" => {
                guest::secret_set("key", value.trim());
                Reply::Done
            }
            Call::Event(Event::Bool { id, on }) if id == "auto" => {
                guest::config_set("auto", if on { "1" } else { "0" });
                Reply::Done
            }
            Call::Event(Event::Number { id, value }) if id == "alert_score" => {
                guest::config_set("alert_score", &value.clamp(1.0, 100.0).round().to_string());
                Reply::Done
            }
            Call::Event(Event::Click { id }) if id == "lookup" => {
                let text = match lookup(&guest::config_get("ip")) {
                    Ok(v) => {
                        let summary = v.summary();
                        remember(v);
                        summary
                    }
                    Err(e) => format!("⚠ {e}"),
                };
                guest::config_set("result", &text);
                Reply::Done
            }
            Call::Alert { title, text, .. } => {
                on_alert(&title, &text);
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(AbuseIpDb);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_check_answer() {
        let json = r#"{"data":{"ipAddress":"118.25.6.39","isPublic":true,"abuseConfidenceScore":100,"countryCode":"CN","isp":"Tencent | Cloud","totalReports":1920}}"#;
        let v = Verdict::parse(json, 5).unwrap();
        assert_eq!((v.score, v.reports, v.country.as_str()), (100, 1920, "CN"));
        assert!(v.summary().contains("very likely abusive"));
        assert_eq!(Verdict::from_line(&v.line()).unwrap(), v, "survives being stored");
        assert!(Verdict::parse("{}", 0).is_none());
    }

    #[test]
    fn only_public_addresses_are_picked_out_of_an_alert() {
        let found = public_addresses("Port scan from 203.0.113.7 tried ports on 192.168.1.5 and 10.0.0.2; also 8.8.8.8, 203.0.113.7.");
        assert_eq!(found, ["203.0.113.7".parse::<IpAddr>().unwrap(), "8.8.8.8".parse().unwrap()]);
        assert!(public_addresses("127.0.0.1 fe80::1 100.64.0.1 169.254.1.1 fd00::1 version 1.2.3").is_empty());
    }

    #[test]
    fn keys_are_plain_tokens() {
        assert!(key_ok("abc123") && !key_ok("") && !key_ok("a\"b") && !key_ok("a b"));
    }
}
