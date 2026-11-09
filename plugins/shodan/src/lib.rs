//! Shodan InternetDB: what the internet at large can see of an address, from Shodan's free, key-less InternetDB
//! (open ports, known vulnerabilities, host names, tags). Look up any address, or check this PC's public one.
//! Only the address you ask about leaves the PC.

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Event, Kind, Manifest, Reply, TabDef, UiTree};
use serde_json::Value;
use std::net::IpAddr;

struct Shodan;

const DEMO_ADDRESS: &str = "203.0.113.7";

/// What Shodan knows, as lines for the page. `None` for an address it has no record of.
fn describe(json: &str) -> Option<Vec<String>> {
    let v: Value = serde_json::from_str(json).ok()?;
    let list = |key: &str| -> Vec<String> { v[key].as_array().map(|a| a.iter().map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_owned)).collect()).unwrap_or_default() };
    let mut out = Vec::new();
    for (label, key) in [("Open ports", "ports"), ("Known vulnerabilities", "vulns"), ("Host names", "hostnames"), ("Tags", "tags"), ("Software", "cpes")] {
        let items = list(key);
        if !items.is_empty() {
            out.push(format!("{label}: {}", items.join(", ")));
        }
    }
    if out.is_empty() {
        out.push("Shodan has seen this address, but lists no open ports or issues.".to_owned());
    }
    Some(out)
}

fn demo_reply(ip: &str) -> String {
    if ip == DEMO_ADDRESS {
        r#"{"ip":"203.0.113.7","ports":[22,80,443],"vulns":["CVE-2021-41773"],"hostnames":["router.demo.example"],"tags":["self-signed"],"cpes":["cpe:/a:apache:http_server:2.4.49"]}"#.to_owned()
    } else {
        r#"{"ip":"x","ports":[443],"vulns":[],"hostnames":[],"tags":["cdn"],"cpes":[]}"#.to_owned()
    }
}

/// The result lines for one address, or why it couldn't be looked up.
fn lookup(ip: &str) -> Result<Vec<String>, String> {
    let ip: IpAddr = ip.trim().parse().map_err(|_| "That isn't an IP address.".to_owned())?;
    let body = if guest::is_demo() {
        demo_reply(&ip.to_string())
    } else {
        match guest::http_raw(&format!("https://internetdb.shodan.io/{ip}"), &[], None, false)? {
            (404, _) => return Ok(vec!["Shodan has no record of this address: no open ports or known issues seen.".to_owned()]),
            (200, body) => body,
            (status, _) => return Err(format!("Shodan answered HTTP {status}.")),
        }
    };
    describe(&body).ok_or_else(|| "Shodan's answer couldn't be read.".to_owned())
}

fn public_ip() -> Result<String, String> {
    if guest::is_demo() {
        return Ok(DEMO_ADDRESS.to_owned());
    }
    let ip = guest::http_request("https://api.ipify.org", &[], None)?.trim().to_owned();
    ip.parse::<IpAddr>().map(|_| ip).map_err(|_| "Couldn't find out this PC's public address.".to_owned())
}

fn run(ip: &str) {
    guest::config_set("ip", ip);
    let text = match lookup(ip) {
        Ok(lines) => lines.join("\n"),
        Err(e) => format!("⚠ {e}"),
    };
    guest::config_set("result", &text);
    guest::config_set("when", &guest::now().to_string());
}

fn page() -> UiTree {
    let mut rows = vec![
        UiTree::Info(
            "Shodan InternetDB lists what the internet can see of an address: open ports, known vulnerabilities and host names. It is free and needs no key. Only the address you look up is sent."
                .into(),
        ),
        UiTree::Label("Address".into()),
        UiTree::Row(vec![
            UiTree::TextField { id: "ip".into(), value: guest::config_get("ip") },
            UiTree::Button { id: "lookup".into(), text: "Look up".into() },
            UiTree::Button { id: "me".into(), text: "Check my public address".into() },
        ]),
    ];
    let result = guest::config_get("result");
    if !result.is_empty() {
        rows.push(UiTree::Separator);
        rows.push(UiTree::Heading(guest::config_get("ip")));
        rows.extend(result.lines().map(|l| UiTree::Label(l.to_owned())));
    }
    UiTree::Column(rows)
}

impl Guest for Shodan {
    fn manifest() -> Manifest {
        Manifest {
            id: "shodan".into(),
            name: "Shodan InternetDB".into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            tabs: vec![TabDef { id: "shodan".into(), title: "Shodan".into() }],
            http_hosts: vec!["internetdb.shodan.io".into(), "api.ipify.org".into()],
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderTab { .. } => Reply::Ui(page()),
            Call::Event(Event::Text { id, value }) if id == "ip" => {
                guest::config_set("ip", value.trim());
                Reply::Done
            }
            Call::Event(Event::Click { id }) if id == "lookup" => {
                run(&guest::config_get("ip"));
                Reply::Done
            }
            Call::Event(Event::Click { id }) if id == "me" => {
                match public_ip() {
                    Ok(ip) => run(&ip),
                    Err(e) => guest::config_set("result", &format!("⚠ {e}")),
                }
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Shodan);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_what_shodan_found() {
        let lines = describe(&demo_reply(DEMO_ADDRESS)).unwrap();
        assert_eq!(lines[0], "Open ports: 22, 80, 443");
        assert!(lines.iter().any(|l| l == "Known vulnerabilities: CVE-2021-41773"));
        assert!(lines.iter().any(|l| l.starts_with("Host names: router.demo.example")));
    }

    #[test]
    fn an_empty_record_and_junk_are_told_apart() {
        assert!(describe(r#"{"ip":"1.2.3.4","ports":[],"vulns":[]}"#).unwrap()[0].contains("no open ports"));
        assert!(describe("not json").is_none());
    }

    #[test]
    fn only_ip_addresses_are_looked_up() {
        assert!(lookup("example.com/../x").unwrap_err().contains("isn't an IP"));
        assert!(lookup("").is_err());
    }
}
