//! OPNsense router: what the router sees (leases, firewall log, gateways) can come into RustWarden, and
//! RustWarden's blocks can go back to it as a RustWarden-owned alias. Nothing is contacted until an address and
//! key are entered, and every option stays off until the API key has been probed to show what it is allowed
//! to do (read only, or read and write).

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Event, Kind, Manifest, Reply, TabDef, UiTree};
use serde::{Deserialize, Serialize};

/// Name of the throw-away alias the write check creates and deletes at once.
const PROBE_ALIAS: &str = "RustWarden_probe";

/// What the API key is allowed to do, as found by the probe.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Caps {
    /// OPNsense version, when it said.
    version: String,
    leases: bool,
    arp: bool,
    log: bool,
    gateway: bool,
    traffic: bool,
    /// None: write access has not been checked (it is only checked when asked for).
    write: Option<bool>,
    /// Set when the write check left its test alias behind.
    warning: String,
}

impl Caps {
    fn any_read(&self) -> bool {
        self.leases || self.arp || self.log || self.gateway || self.traffic
    }
}

/// The settings the page edits.
#[derive(Clone, Debug, Default, PartialEq)]
struct Cfg {
    url: String,
    key: String,
    secret: String,
    /// Accept the router's own (self-signed) certificate. Off unless the user turns it on.
    allow_self_signed: bool,
    pull_devices: bool,
    pull_log: bool,
    pull_gateway: bool,
    push_blocks: bool,
    /// What the last probe found, valid only for the address and key it was run with (`caps_for`).
    caps: Option<Caps>,
    caps_for: String,
}

fn valid_url(u: &str) -> bool {
    u.starts_with("http://") || u.starts_with("https://")
}

fn clean(s: &str) -> String {
    // Control characters would become extra headers in the request.
    s.trim().chars().filter(|c| !c.is_control()).collect()
}

impl Cfg {
    fn load() -> Self {
        let flag = |k: &str| guest::config_get(k) == "1";
        Self {
            url: guest::config_get("url").trim().trim_end_matches('/').to_owned(),
            key: clean(&guest::secret_get("key")),
            secret: clean(&guest::secret_get("secret")),
            allow_self_signed: flag("allow_self_signed"),
            pull_devices: flag("pull_devices"),
            pull_log: flag("pull_log"),
            pull_gateway: flag("pull_gateway"),
            push_blocks: flag("push_blocks"),
            caps: serde_json::from_str(&guest::config_get("caps")).ok(),
            caps_for: guest::secret_get("caps_for"),
        }
    }

    /// Stores the options and the probe result (the address, key and secret are stored as they are typed).
    fn save(&self) {
        let flag = |on: bool| if on { "1" } else { "0" };
        guest::config_set("allow_self_signed", flag(self.allow_self_signed));
        guest::config_set("pull_devices", flag(self.pull_devices));
        guest::config_set("pull_log", flag(self.pull_log));
        guest::config_set("pull_gateway", flag(self.pull_gateway));
        guest::config_set("push_blocks", flag(self.push_blocks));
        guest::config_set("caps", &self.caps.as_ref().map(|c| serde_json::to_string(c).unwrap_or_default()).unwrap_or_default());
        guest::secret_set("caps_for", &self.caps_for);
    }

    fn ready(&self) -> bool {
        !self.key.is_empty() && !self.secret.is_empty() && valid_url(&self.url)
    }

    /// Why this can't be used yet, if it can't.
    fn problem(&self) -> Option<&'static str> {
        if self.url.is_empty() {
            Some("Enter the address of the OPNsense web interface.")
        } else if !valid_url(&self.url) {
            Some("The address must start with http:// or https://")
        } else if self.key.is_empty() {
            Some("Enter the API key.")
        } else if self.secret.is_empty() {
            Some("Enter the API secret.")
        } else {
            None
        }
    }

    /// Identifies the address and credentials a probe result belongs to.
    fn fingerprint(&self) -> String {
        format!("{}\0{}\0{}", self.url, self.key, self.secret)
    }

    /// The probe result, only while it still matches the saved address and key.
    fn caps(&self) -> Option<&Caps> {
        self.caps.as_ref().filter(|_| self.caps_for == self.fingerprint())
    }

    fn can_pull_devices(&self) -> bool {
        self.caps().is_some_and(|c| c.leases || c.arp)
    }
    fn can_pull_log(&self) -> bool {
        self.caps().is_some_and(|c| c.log)
    }
    fn can_pull_gateway(&self) -> bool {
        self.caps().is_some_and(|c| c.gateway || c.traffic)
    }
    fn can_push(&self) -> bool {
        self.caps().is_some_and(|c| c.write == Some(true))
    }

    /// Switches off every option the key hasn't been shown to allow (also after the address or key changes).
    fn gate(&mut self) {
        self.pull_devices &= self.can_pull_devices();
        self.pull_log &= self.can_pull_log();
        self.pull_gateway &= self.can_pull_gateway();
        self.push_blocks &= self.can_push();
    }
}

// ---- talking to the router ----

/// (HTTP status, body), or why the router couldn't be reached.
type Reply2 = Result<(u16, String), String>;

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() { out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char) } else { out.push('=') }
        }
    }
    out
}

/// The pieces of a probe, so tests can stand in for the router.
trait Transport {
    fn get(&self, path: &str) -> Reply2;
    fn post(&self, path: &str, body: &str) -> Reply2;
}

struct Router<'a>(&'a Cfg);

impl Router<'_> {
    fn request(&self, path: &str, body: Option<&str>) -> Reply2 {
        let mut headers = vec![format!("Authorization: Basic {}", base64(format!("{}:{}", self.0.key, self.0.secret).as_bytes()))];
        if body.is_some() {
            headers.push("Content-Type: application/json".to_owned());
        }
        guest::http_raw(&format!("{}{path}", self.0.url), &headers, body, self.0.allow_self_signed).map_err(|e| {
            if e.contains("certificate") {
                "The router's certificate isn't trusted. If it is self-signed, turn on \"Allow self-signed certificate\".".to_owned()
            } else {
                format!("Can't reach OPNsense: {e}")
            }
        })
    }
}

impl Transport for Router<'_> {
    fn get(&self, path: &str) -> Reply2 {
        self.request(path, None)
    }
    fn post(&self, path: &str, body: &str) -> Reply2 {
        self.request(path, Some(body))
    }
}

/// Finds out what the key may do. `write` also tries to create (and remove) the test alias; that is
/// only done when the user asks. `keep` carries over an earlier write result when it isn't re-checked.
fn probe_with(t: &dyn Transport, write: bool, keep: Option<bool>) -> Result<Caps, String> {
    let (code, _) = t.get("/api/core/system/status")?;
    match code {
        401 => return Err("OPNsense rejected the API key or secret.".into()),
        0 => return Err("OPNsense didn't answer with HTTP.".into()),
        404 => return Err("That address doesn't look like OPNsense's web interface (no API there).".into()),
        _ => {}
    }
    let ok = |path: &str| matches!(t.get(path), Ok((200, _)));
    let mut caps = Caps {
        leases: ok("/api/dhcpv4/leases/searchLease") || ok("/api/kea/leases4/search"),
        arp: ok("/api/diagnostics/interface/getArp"),
        log: ok("/api/diagnostics/firewall/log?limit=1"),
        gateway: ok("/api/routes/gateway/status"),
        traffic: ok("/api/diagnostics/traffic/interface"),
        write: keep,
        ..Default::default()
    };
    if let Ok((200, body)) = t.get("/api/core/firmware/status") {
        caps.version = json_str(&body, "product_version");
    }
    if !caps.any_read() && code == 403 {
        return Err("This key can't read anything useful. Give its user the Diagnostics, DHCP and Firewall log privileges.".into());
    }
    if write {
        let (w, warning) = write_check(t);
        caps.write = w;
        caps.warning = warning;
    }
    Ok(caps)
}

fn json_str(body: &str, key: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body).ok().and_then(|v| v.get(key)?.as_str().map(str::to_owned)).unwrap_or_default()
}

/// What creating the test alias said.
#[derive(Debug, PartialEq)]
enum Added {
    Uuid(String),
    Denied,
    /// The alias is already there (a leftover), or the router refused it for another reason.
    Failed(String),
}

fn parse_add(code: u16, body: &str) -> Added {
    if code == 401 || code == 403 {
        return Added::Denied;
    }
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    match (v.get("result").and_then(|r| r.as_str()), v.get("uuid").and_then(|u| u.as_str())) {
        (Some("saved"), Some(u)) if !u.is_empty() => Added::Uuid(u.to_owned()),
        _ => Added::Failed(format!("HTTP {code}")),
    }
}

/// Creates `RustWarden_probe` and deletes it again without applying anything. Returns whether writing
/// is allowed (None when it couldn't be told) and a warning if the test alias was left behind.
fn write_check(t: &dyn Transport) -> (Option<bool>, String) {
    let body = format!("{{\"alias\":{{\"enabled\":\"1\",\"name\":\"{PROBE_ALIAS}\",\"type\":\"host\",\"content\":\"\",\"description\":\"RustWarden write-access check (safe to delete)\"}}}}");
    let mut added = t.post("/api/firewall/alias/addItem", &body).map_or_else(Added::Failed, |(c, b)| parse_add(c, &b));
    if matches!(added, Added::Failed(_)) {
        // A leftover from an earlier check: remove it and try once more.
        if let Ok((200, b)) = t.get(&format!("/api/firewall/alias/getAliasUUID/{PROBE_ALIAS}")) {
            let old = json_str(&b, "uuid");
            if !old.is_empty() {
                let _ = t.post(&format!("/api/firewall/alias/delItem/{old}"), "{}");
                added = t.post("/api/firewall/alias/addItem", &body).map_or_else(Added::Failed, |(c, b)| parse_add(c, &b));
            }
        }
    }
    match added {
        Added::Denied => (Some(false), String::new()),
        Added::Failed(_) => (None, String::new()),
        Added::Uuid(u) => match t.post(&format!("/api/firewall/alias/delItem/{u}"), "{}") {
            Ok((200, b)) if json_str(&b, "result") == "deleted" => (Some(true), String::new()),
            _ => (Some(true), format!("The write check created an alias called {PROBE_ALIAS} and couldn't remove it. Delete it in Firewall > Aliases.")),
        },
    }
}

/// A made-up router for Demo mode: reads everything; a key containing "readonly" can't write.
fn demo_probe(cfg: &Cfg, write: bool, keep: Option<bool>) -> Caps {
    Caps {
        version: "25.1 (demo)".into(),
        leases: true,
        arp: true,
        log: true,
        gateway: true,
        traffic: true,
        write: if write { Some(!cfg.key.to_lowercase().contains("readonly")) } else { keep },
        warning: String::new(),
    }
}

// ---- what the options do ----

/// The alias RustWarden keeps on the router: the addresses RustWarden has blocked. A firewall rule that blocks this
/// alias (made by hand on the router) is what turns the list into a block there.
const BLOCK_ALIAS: &str = "RustWarden_blocked";
const ALIAS_NOTE: &str = "Addresses blocked by RustWarden. Managed by RustWarden: edits here are overwritten.";
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS p_opnsense__devices (
    mac TEXT PRIMARY KEY, checked INTEGER NOT NULL, found INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL DEFAULT '', area TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '');";
/// Gateway and log rows kept for the tab.
const LOG_ROWS: usize = 25;

fn field(v: &serde_json::Value, keys: &[&str]) -> String {
    keys.iter().find_map(|k| v.get(*k).and_then(|x| x.as_str().map(str::to_owned).or_else(|| x.as_f64().map(|n| n.to_string())))).unwrap_or_default()
}

/// MAC addresses compare without regard to case or separators.
fn norm_mac(mac: &str) -> String {
    mac.chars().filter(char::is_ascii_hexdigit).collect::<String>().to_lowercase()
}

/// (MAC, host name) of the DHCP leases (ISC, or Kea's `rows`) and of an ARP table (a plain array), whichever `body` is.
fn names_in(body: &str) -> Vec<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let rows = v.get("rows").and_then(|r| r.as_array()).or_else(|| v.as_array()).cloned().unwrap_or_default();
    rows.iter()
        .filter_map(|r| {
            let mac = norm_mac(&field(r, &["mac", "hwaddr"]));
            let name = field(r, &["hostname", "client-hostname"]);
            (mac.len() == 12 && !name.trim().is_empty()).then(|| (mac, name.trim().to_owned()))
        })
        .collect()
}

#[derive(Debug, PartialEq)]
struct Gateway {
    name: String,
    status: String,
    delay: String,
    loss: String,
}

fn gateways_in(body: &str) -> Vec<Gateway> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    v.get("items")
        .and_then(|i| i.as_array())
        .map(|items| items.iter().map(|g| Gateway { name: field(g, &["name"]), status: field(g, &["status_translated", "status"]), delay: field(g, &["delay"]), loss: field(g, &["loss"]) }).collect())
        .unwrap_or_default()
}

/// The newest lines of the router's firewall log: "time|action|interface|source|destination|protocol".
fn log_lines(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let rows = v.as_array().or_else(|| v.get("rows").and_then(|r| r.as_array())).cloned().unwrap_or_default();
    rows.iter()
        .take(LOG_ROWS)
        .map(|r| {
            let end = |addr: &str, port: &str| {
                let (a, p) = (field(r, &[addr]), field(r, &[port]));
                if p.is_empty() { a } else { format!("{a}:{p}") }
            };
            let clean = |s: String| s.replace('|', "/").replace('\n', " ");
            [
                field(r, &["__timestamp__", "timestamp"]),
                field(r, &["action"]),
                field(r, &["interface_name", "interface", "intf"]),
                end("src", "srcport"),
                end("dst", "dstport"),
                field(r, &["protoname", "proto"]),
            ]
            .map(clean)
            .join("|")
        })
        .collect()
}

/// The addresses that go into the alias: valid, once each, sorted. Anything else never reaches the router.
fn alias_addresses(blocked: &[String]) -> Vec<String> {
    let mut ips: Vec<String> = blocked.iter().filter_map(|s| s.trim().parse::<std::net::IpAddr>().ok()).map(|ip| ip.to_string()).collect();
    ips.sort();
    ips.dedup();
    ips
}

/// Creates or updates `RustWarden_blocked` and has the router load it. Returns how many addresses it now holds.
fn push_with(t: &dyn Transport, ips: &[String]) -> Result<usize, String> {
    let body = serde_json::json!({"alias": {"enabled": "1", "name": BLOCK_ALIAS, "type": "host", "content": ips.join("\n"), "description": ALIAS_NOTE}}).to_string();
    let uuid = match t.get(&format!("/api/firewall/alias/getAliasUUID/{BLOCK_ALIAS}")) {
        Ok((200, b)) => json_str(&b, "uuid"),
        _ => String::new(),
    };
    let path = if uuid.is_empty() { "/api/firewall/alias/addItem".to_owned() } else { format!("/api/firewall/alias/setItem/{uuid}") };
    let (code, reply) = t.post(&path, &body)?;
    if code == 401 || code == 403 {
        return Err("The router refused to change the alias: the key can't write.".into());
    }
    if json_str(&reply, "result") != "saved" {
        return Err(format!("The router didn't save the alias (HTTP {code})."));
    }
    // Only the alias is loaded; no firewall rule is touched.
    match t.post("/api/firewall/alias/reconfigure", "{}")? {
        (200, b) if json_str(&b, "status") == "ok" => Ok(ips.len()),
        (code, _) => Err(format!("The alias was saved, but the router didn't load it (HTTP {code}).")),
    }
}

fn fnv(s: &str) -> String {
    format!("{:08x}", s.bytes().fold(0x811c_9dc5u32, |h, b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193)))
}

/// Single-quoted SQL text.
fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Names the scanned devices from the router's leases and ARP table. Returns how many were named.
fn pull_devices(t: &dyn Transport, cfg: &Cfg) -> Result<usize, String> {
    let scanned = guest::devices()?;
    if scanned.is_empty() {
        return Ok(0);
    }
    let mut known = std::collections::HashMap::new();
    for path in ["/api/dhcpv4/leases/searchLease", "/api/kea/leases4/search", "/api/diagnostics/interface/getArp"] {
        if let Ok((200, body)) = t.get(path) {
            for (mac, name) in names_in(&body) {
                known.entry(mac).or_insert(name);
            }
        }
    }
    let now = guest::now();
    let mut named = 0;
    for d in scanned {
        let Some(name) = known.get(&norm_mac(&d.mac)) else { continue };
        let sql = format!("INSERT OR REPLACE INTO p_opnsense__devices (mac, checked, found, name, area, kind, model, url) VALUES ({}, {now}, 1, {}, '', '', '', {})", q(&d.mac), q(name), q(&cfg.url));
        guest::db_exec(&sql)?;
        named += 1;
    }
    Ok(named)
}

fn set_status(text: &str) {
    guest::config_set("status", text);
}

/// One round of the enabled options. Blocks the plugin's own worker, never the window.
fn refresh() {
    let cfg = Cfg::load();
    if !cfg.ready() || !cfg.caps().is_some_and(Caps::any_read) {
        return;
    }
    let demo = guest::is_demo();
    let router = Router(&cfg);
    let mut problems: Vec<String> = Vec::new();
    if cfg.pull_devices && !demo {
        match pull_devices(&router, &cfg) {
            Ok(n) => guest::config_set("named", &n.to_string()),
            Err(e) => problems.push(format!("Devices: {e}")),
        }
    }
    if cfg.pull_gateway {
        let rows = if demo {
            "WAN_GW|Online|4.8 ms|0.0 %\nWAN6_GW|Online|5.1 ms|0.0 %".to_owned()
        } else {
            match router.get("/api/routes/gateway/status") {
                Ok((200, b)) => gateways_in(&b).iter().map(|g| format!("{}|{}|{}|{}", g.name, g.status, g.delay, g.loss)).collect::<Vec<_>>().join("\n"),
                Ok((c, _)) => {
                    problems.push(format!("Gateways: HTTP {c}"));
                    guest::config_get("gw")
                }
                Err(e) => {
                    problems.push(format!("Gateways: {e}"));
                    guest::config_get("gw")
                }
            }
        };
        guest::config_set("gw", &rows);
    }
    if cfg.pull_log {
        let rows = if demo {
            "2026-11-09T09:14:02|block|WAN|203.0.113.7:51514|198.51.100.2:23|tcp\n2026-11-09T09:13:40|block|WAN|203.0.113.50:40022|198.51.100.2:3389|tcp".to_owned()
        } else {
            match router.get(&format!("/api/diagnostics/firewall/log?limit={LOG_ROWS}")) {
                Ok((200, b)) => log_lines(&b).join("\n"),
                Ok((c, _)) => {
                    problems.push(format!("Firewall log: HTTP {c}"));
                    guest::config_get("fwlog")
                }
                Err(e) => {
                    problems.push(format!("Firewall log: {e}"));
                    guest::config_get("fwlog")
                }
            }
        };
        guest::config_set("fwlog", &rows);
    }
    if cfg.push_blocks && cfg.can_push() {
        match guest::blocked_addresses() {
            Ok(list) => {
                let ips = alias_addresses(&list);
                let hash = fnv(&format!("{}\n{}", cfg.url, ips.join(",")));
                // The router is only asked when the list (or the router) changed.
                if guest::config_get("pushed") != hash {
                    let sent = if demo { Ok(ips.len()) } else { push_with(&router, &ips) };
                    match sent {
                        Ok(n) => {
                            guest::config_set("pushed", &hash);
                            guest::config_set("pushed_n", &n.to_string());
                        }
                        Err(e) => problems.push(format!("Blocked addresses: {e}")),
                    }
                }
            }
            Err(e) => problems.push(format!("Blocked addresses: {e}")),
        }
    }
    guest::config_set("updated", &guest::now().to_string());
    set_status(&problems.join(" "));
}

fn table(headers: &[&str], lines: &str, columns: usize) -> UiTree {
    let mut children: Vec<UiTree> = headers.iter().map(|h| UiTree::Heading((*h).to_owned())).collect();
    for line in lines.lines() {
        let mut cells: Vec<&str> = line.split('|').collect();
        cells.resize(columns, "");
        children.extend(cells.into_iter().take(columns).map(|c| UiTree::Label(c.to_owned())));
    }
    UiTree::Grid { columns, children }
}

fn tab() -> UiTree {
    let cfg = Cfg::load();
    let mut rows = vec![UiTree::Info("What the OPNsense router reports. Choose what to bring in under Settings > Plugins > OPNsense.".into())];
    let on = cfg.pull_gateway || cfg.pull_log || cfg.push_blocks || cfg.pull_devices;
    if !cfg.ready() || !on {
        rows.push(UiTree::Weak("Add the router's address and API key, test the connection and switch an option on in the plugin's settings.".into()));
        return UiTree::Column(rows);
    }
    rows.push(UiTree::Button { id: "refresh".into(), text: "Refresh now".into() });
    let status = guest::config_get("status");
    if !status.is_empty() {
        rows.push(UiTree::Label(format!("⚠ {status}")));
    }
    let updated: i64 = guest::config_get("updated").parse().unwrap_or(0);
    rows.push(UiTree::Weak(if updated == 0 {
        "Not fetched yet; the router is asked once a minute.".to_owned()
    } else {
        format!("Updated {} s ago. The router is asked once a minute.", (guest::now() - updated).max(0))
    }));
    if cfg.pull_gateway {
        rows.push(UiTree::Heading("Gateways".into()));
        rows.push(table(&["Name", "Status", "Delay", "Loss"], &guest::config_get("gw"), 4));
    }
    if cfg.pull_log {
        rows.push(UiTree::Heading("Router firewall log".into()));
        rows.push(table(&["Time", "Action", "Interface", "From", "To", "Protocol"], &guest::config_get("fwlog"), 6));
    }
    if cfg.pull_devices {
        rows.push(UiTree::Label(format!("Named {} scanned device(s) from the router's leases and ARP table (shown on the Scanner tab).", guest::config_get("named").parse::<usize>().unwrap_or(0))));
    }
    if cfg.push_blocks {
        let n = guest::config_get("pushed_n");
        rows.push(UiTree::Label(if n.is_empty() {
            format!("Not sent yet. The alias {BLOCK_ALIAS} is created on the first send.")
        } else {
            format!("Sent {n} blocked address(es) to the alias {BLOCK_ALIAS}.")
        }));
    }
    UiTree::Column(rows)
}

// ---- the page ----

fn badge(on: bool, label: &str) -> UiTree {
    UiTree::Label(format!("{} {label}", if on { "✓" } else { "✕" }))
}

/// A switch that can't be turned on until `allowed`; `reason` says why when it can't.
fn gated(id: &str, on: bool, allowed: bool, label: &str, reason: &str, rows: &mut Vec<UiTree>) {
    let switch = UiTree::Switch { id: id.into(), text: label.into(), on: on && allowed };
    if allowed {
        rows.push(switch);
    } else {
        rows.push(UiTree::Disabled(Box::new(switch)));
        if !reason.is_empty() {
            rows.push(UiTree::Weak(reason.into()));
        }
    }
}

fn page() -> UiTree {
    let cfg = Cfg::load();
    let name_url = guest::config_get("url");
    let mut rows = vec![UiTree::Label("Address of the web interface".into()), UiTree::TextField { id: "url".into(), value: name_url.clone() }];
    if !name_url.trim().is_empty() && !valid_url(name_url.trim()) {
        rows.push(UiTree::Label("⚠ The address must start with http:// or https://".into()));
    }
    rows.push(UiTree::Label("API key (System > Access > Users > API keys)".into()));
    rows.push(UiTree::Password { id: "key".into(), value: guest::secret_get("key") });
    rows.push(UiTree::Label("API secret".into()));
    rows.push(UiTree::Password { id: "secret".into(), value: guest::secret_get("secret") });
    rows.push(UiTree::Switch { id: "allow_self_signed".into(), text: "Allow self-signed certificate".into(), on: cfg.allow_self_signed });
    rows.push(UiTree::Weak("OPNsense uses its own certificate by default. Only turn this on for a router on your own network.".into()));
    rows.push(UiTree::Separator);

    let test = UiTree::Button { id: "test".into(), text: "Test connection".into() };
    let write = UiTree::Button { id: "check_write".into(), text: "Check write access".into() };
    rows.push(UiTree::Row(vec![if cfg.ready() { test } else { UiTree::Disabled(Box::new(test)) }, if cfg.ready() && cfg.caps().is_some() { write } else { UiTree::Disabled(Box::new(write)) }]));
    rows.push(UiTree::Weak(format!("Test connection signs in and finds out which parts of OPNsense this key can read. Check write access creates and removes an alias called {PROBE_ALIAS} on the router, to see whether this key can change it; nothing is applied.")));
    let msg = guest::config_get("msg");
    if !msg.is_empty() {
        rows.push(UiTree::Label(format!("⚠ {msg}")));
    }
    match cfg.caps() {
        None => rows.push(UiTree::Weak("Test the connection to unlock the options below.".into())),
        Some(c) => {
            if !c.version.is_empty() {
                rows.push(UiTree::Label(format!("OPNsense {}", c.version)));
            }
            rows.push(UiTree::Row(vec![badge(c.leases, "DHCP leases"), badge(c.arp, "ARP table"), badge(c.log, "Firewall log"), badge(c.gateway, "Gateways"), badge(c.traffic, "Traffic")]));
            rows.push(match c.write {
                Some(true) => UiTree::Label("✓ This key can change firewall aliases (read and write).".into()),
                Some(false) => UiTree::Label("Read only: this key can't change aliases, so pushing blocks stays off.".into()),
                None => UiTree::Weak("Write access hasn't been checked.".into()),
            });
            if !c.warning.is_empty() {
                rows.push(UiTree::Label(format!("⚠ {}", c.warning)));
            }
        }
    }
    rows.push(UiTree::Separator);
    rows.push(UiTree::Heading("Bring in from OPNsense".into()));
    let (dev, log, gw, push) = (cfg.can_pull_devices(), cfg.can_pull_log(), cfg.can_pull_gateway(), cfg.can_push());
    let none = cfg.caps().is_none();
    let why = |ok: bool, denied: &str| {
        if none {
            "Test the connection first.".to_owned()
        } else if ok {
            String::new()
        } else {
            denied.to_owned()
        }
    };
    gated("pull_devices", cfg.pull_devices, dev, "Device names and addresses (DHCP leases, ARP)", &why(dev, "This key can't read leases or the ARP table."), &mut rows);
    gated("pull_log", cfg.pull_log, log, "Router firewall log", &why(log, "This key can't read the firewall log."), &mut rows);
    gated("pull_gateway", cfg.pull_gateway, gw, "Gateway status and traffic", &why(gw, "This key can't read gateways or traffic."), &mut rows);
    rows.push(UiTree::Heading("Send to OPNsense".into()));
    let denied = if cfg.caps().is_some_and(|c| c.write.is_none()) { "Press Check write access first." } else { "This key is read only." };
    gated("push_blocks", cfg.push_blocks, push, "Blocked addresses (a RustWarden alias on the router)", &why(push, denied), &mut rows);
    rows.push(UiTree::Weak("Everything RustWarden creates on the router is named RustWarden, so it can be found and removed.".into()));
    if let Some(p) = cfg.problem() {
        rows.push(UiTree::Label(p.into()));
    }
    UiTree::Column(rows)
}

/// Runs a probe now (this blocks the plugin's own worker, never the window) and keeps what it found.
fn run_probe(write: bool) {
    let mut cfg = Cfg::load();
    if !cfg.ready() {
        return;
    }
    let keep = cfg.caps().and_then(|c| c.write);
    let result = if guest::is_demo() { Ok(demo_probe(&cfg, write, keep)) } else { probe_with(&Router(&cfg), write, keep) };
    match result {
        Ok(caps) => {
            cfg.caps = Some(caps);
            cfg.caps_for = cfg.fingerprint();
            cfg.gate();
            cfg.save();
            guest::config_set("msg", "");
        }
        Err(e) => {
            cfg.caps = None;
            cfg.gate();
            cfg.save();
            guest::config_set("msg", &e);
        }
    }
}

fn event(e: Event) {
    match e {
        Event::Text { id, value } if id == "url" => guest::config_set("url", value.trim()),
        Event::Text { id, value } if id == "key" || id == "secret" => guest::secret_set(&id, &clean(&value)),
        Event::Bool { id, on } if matches!(id.as_str(), "allow_self_signed" | "pull_devices" | "pull_log" | "pull_gateway" | "push_blocks") => {
            let mut cfg = Cfg::load();
            match id.as_str() {
                "allow_self_signed" => cfg.allow_self_signed = on,
                "pull_devices" => cfg.pull_devices = on,
                "pull_log" => cfg.pull_log = on,
                "pull_gateway" => cfg.pull_gateway = on,
                _ => cfg.push_blocks = on,
            }
            cfg.gate();
            cfg.save();
            return;
        }
        Event::Click { id } if id == "test" => return run_probe(false),
        Event::Click { id } if id == "check_write" => return run_probe(true),
        _ => return,
    }
    // Editing the address or key drops what the last probe found, and with it every option that needed it.
    let mut cfg = Cfg::load();
    cfg.gate();
    cfg.save();
}

struct Opnsense;

impl Guest for Opnsense {
    fn manifest() -> Manifest {
        Manifest {
            id: "opnsense".into(),
            name: "OPNsense".into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            tabs: vec![TabDef { id: "opnsense".into(), title: "OPNsense".into() }],
            settings_page: true,
            // The router is wherever the user put it, and its own certificate is usually self-signed.
            http_hosts: vec!["*".into()],
            allow_insecure_tls: true,
            // Names for scanned devices, and the blocked addresses to send to the router's alias.
            permissions: vec!["devices.annotate".into(), "firewall.blocks.read".into()],
            tick_secs: 60,
            schema: SCHEMA.into(),
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderSettings => Reply::Ui(page()),
            Call::RenderTab { .. } => Reply::Ui(tab()),
            Call::Tick => {
                refresh();
                Reply::Done
            }
            Call::Event(Event::Click { id }) if id == "refresh" => {
                refresh();
                Reply::Done
            }
            Call::Event(e) => {
                event(e);
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Opnsense);

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn probed(write: Option<bool>) -> Cfg {
        let mut i = Cfg { url: "https://fw".into(), key: "k".into(), secret: "s".into(), ..Default::default() };
        i.caps = Some(Caps { leases: true, log: true, write, ..Default::default() });
        i.caps_for = i.fingerprint();
        i
    }

    #[test]
    fn options_stay_off_until_probed() {
        let mut i = Cfg { pull_devices: true, pull_log: true, pull_gateway: true, push_blocks: true, ..Default::default() };
        i.gate();
        assert!(!i.pull_devices && !i.pull_log && !i.pull_gateway && !i.push_blocks);
    }

    #[test]
    fn a_read_only_key_cannot_push() {
        let mut i = probed(Some(false));
        (i.pull_devices, i.pull_log, i.pull_gateway, i.push_blocks) = (true, true, true, true);
        i.gate();
        assert!(i.pull_devices && i.pull_log);
        assert!(!i.pull_gateway, "gateway was denied");
        assert!(!i.push_blocks);
        assert!(!probed(None).can_push(), "unchecked write access is not write access");
        assert!(probed(Some(true)).can_push());
    }

    #[test]
    fn changing_the_key_discards_the_probe() {
        let mut i = probed(Some(true));
        i.push_blocks = true;
        i.secret = "other".into();
        assert!(i.caps().is_none());
        i.gate();
        assert!(!i.push_blocks);
    }

    #[test]
    fn using_it_needs_an_address_key_and_secret() {
        let mut i = Cfg::default();
        assert_eq!(i.problem(), Some("Enter the address of the OPNsense web interface."));
        i.url = "192.168.1.1".into();
        assert!(i.problem().unwrap().contains("http"));
        i.url = "https://192.168.1.1".into();
        assert_eq!(i.problem(), Some("Enter the API key."));
        i.key = "k".into();
        assert_eq!(i.problem(), Some("Enter the API secret."));
        i.secret = "s".into();
        assert_eq!(i.problem(), None);
        assert!(i.ready());
    }

    #[test]
    fn base64_matches_the_rfc_examples() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"key:secret"), "a2V5OnNlY3JldA==");
    }

    /// Answers by path prefix; records every POST.
    struct Fake {
        reads: Vec<(&'static str, u16)>,
        /// What `getAliasUUID` says.
        alias: &'static str,
        add: (u16, &'static str),
        del: (u16, &'static str),
        posts: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(add: (u16, &'static str)) -> Self {
            Self { reads: vec![], alias: "{}", add, del: (200, "{\"result\":\"deleted\"}"), posts: RefCell::new(vec![]) }
        }
    }

    impl Transport for Fake {
        fn get(&self, path: &str) -> Reply2 {
            if path == "/api/core/system/status" {
                return Ok((200, "{}".into()));
            }
            if path == "/api/core/firmware/status" {
                return Ok((200, "{\"product_version\":\"25.1.3\"}".into()));
            }
            if path.contains("getAliasUUID") {
                return Ok((200, self.alias.into()));
            }
            let code = self.reads.iter().find(|(p, _)| path.starts_with(p)).map_or(403, |(_, c)| *c);
            Ok((code, "{}".into()))
        }
        fn post(&self, path: &str, _body: &str) -> Reply2 {
            self.posts.borrow_mut().push(path.to_owned());
            Ok(if path.contains("addItem") || path.contains("setItem") {
                (self.add.0, self.add.1.into())
            } else if path.contains("reconfigure") {
                (200, "{\"status\":\"ok\"}".into())
            } else {
                (self.del.0, self.del.1.into())
            })
        }
    }

    const SAVED: &str = "{\"result\":\"saved\",\"uuid\":\"abc-1\"}";

    #[test]
    fn reads_are_judged_per_endpoint() {
        let mut f = Fake::new((403, ""));
        f.reads = vec![("/api/dhcpv4/leases", 200), ("/api/diagnostics/firewall", 200)];
        let c = probe_with(&f, false, None).unwrap();
        assert!(c.leases && c.log);
        assert!(!c.arp && !c.gateway && !c.traffic);
        assert_eq!(c.version, "25.1.3");
        assert_eq!(c.write, None, "write access is only tested when asked");
        assert!(f.posts.borrow().is_empty(), "a read check posts nothing");
    }

    #[test]
    fn a_read_check_keeps_the_earlier_write_result() {
        let f = Fake::new((403, ""));
        assert_eq!(probe_with(&f, false, Some(true)).unwrap().write, Some(true));
    }

    #[test]
    fn a_writable_key_creates_then_removes_the_test_alias() {
        let f = Fake::new((200, SAVED));
        let c = probe_with(&f, true, None).unwrap();
        assert_eq!(c.write, Some(true));
        assert!(c.warning.is_empty());
        let posts = f.posts.borrow();
        assert_eq!(posts.as_slice(), ["/api/firewall/alias/addItem", "/api/firewall/alias/delItem/abc-1"]);
        assert!(!posts.iter().any(|p| p.contains("reconfigure")), "nothing is applied on the router");
    }

    #[test]
    fn a_read_only_key_is_told_apart() {
        let f = Fake::new((403, "{\"status\":403}"));
        assert_eq!(probe_with(&f, true, None).unwrap().write, Some(false));
    }

    #[test]
    fn a_leftover_alias_is_reported() {
        let mut f = Fake::new((200, SAVED));
        f.del = (200, "{\"result\":\"failed\"}");
        let c = probe_with(&f, true, None).unwrap();
        assert_eq!(c.write, Some(true));
        assert!(c.warning.contains(PROBE_ALIAS));
    }

    #[test]
    fn bad_keys_are_rejected_up_front() {
        struct Denied;
        impl Transport for Denied {
            fn get(&self, _: &str) -> Reply2 {
                Ok((401, String::new()))
            }
            fn post(&self, _: &str, _: &str) -> Reply2 {
                unreachable!("no write is attempted with a bad key")
            }
        }
        assert!(probe_with(&Denied, true, None).unwrap_err().contains("rejected"));
    }

    #[test]
    fn add_replies_are_classified() {
        assert_eq!(parse_add(200, SAVED), Added::Uuid("abc-1".into()));
        assert_eq!(parse_add(403, ""), Added::Denied);
        assert!(matches!(parse_add(200, "{\"result\":\"failed\",\"validations\":{}}"), Added::Failed(_)));
        assert!(matches!(parse_add(200, "not json"), Added::Failed(_)));
    }

    #[test]
    fn names_come_from_leases_and_the_arp_table_by_mac() {
        let leases = r#"{"rows":[{"address":"192.168.1.20","mac":"AA:BB:CC:00:11:22","hostname":"laptop"},{"address":"192.168.1.21","hwaddr":"aa:bb:cc:00:11:33","hostname":""}]}"#;
        assert_eq!(names_in(leases), [("aabbcc001122".to_owned(), "laptop".to_owned())]);
        let arp = r#"[{"ip":"192.168.1.30","mac":"aa:bb:cc:00:11:44","hostname":"printer","manufacturer":"HP"},{"ip":"1.2.3.4","mac":"bad","hostname":"x"}]"#;
        assert_eq!(names_in(arp), [("aabbcc001144".to_owned(), "printer".to_owned())]);
        assert!(names_in("not json").is_empty());
        assert_eq!(norm_mac("AA-BB-CC-00-11-22"), "aabbcc001122");
    }

    #[test]
    fn gateways_and_log_lines_are_read_for_the_tab() {
        let gw = r#"{"items":[{"name":"WAN_GW","status":"none","status_translated":"Online","delay":"4.8 ms","loss":"0.0 %"}],"status":"ok"}"#;
        assert_eq!(gateways_in(gw), [Gateway { name: "WAN_GW".into(), status: "Online".into(), delay: "4.8 ms".into(), loss: "0.0 %".into() }]);
        let log = r#"[{"__timestamp__":"2026-11-09T09:14:02","action":"block","interface_name":"wan","src":"203.0.113.7","srcport":"51514","dst":"198.51.100.2","dstport":"23","protoname":"tcp"}]"#;
        assert_eq!(log_lines(log), ["2026-11-09T09:14:02|block|wan|203.0.113.7:51514|198.51.100.2:23|tcp"]);
        assert!(log_lines("{}").is_empty() && gateways_in("[]").is_empty());
    }

    #[test]
    fn only_valid_addresses_reach_the_alias() {
        let list = ["203.0.113.50".to_owned(), " 198.51.100.23 ".to_owned(), "203.0.113.50".to_owned(), "evil\"; drop".to_owned(), "2001:db8::1".to_owned(), "".to_owned()];
        assert_eq!(alias_addresses(&list), ["198.51.100.23", "2001:db8::1", "203.0.113.50"]);
    }

    #[test]
    fn the_alias_is_created_then_updated_and_loaded_without_touching_rules() {
        let f = Fake::new((200, SAVED));
        assert_eq!(push_with(&f, &["203.0.113.50".into()]), Ok(1));
        assert_eq!(f.posts.borrow().as_slice(), ["/api/firewall/alias/addItem", "/api/firewall/alias/reconfigure"]);
        let mut f = Fake::new((200, "{\"result\":\"saved\"}"));
        f.alias = "{\"uuid\":\"u-9\"}";
        assert_eq!(push_with(&f, &[]), Ok(0));
        assert_eq!(f.posts.borrow().as_slice(), ["/api/firewall/alias/setItem/u-9", "/api/firewall/alias/reconfigure"]);
        assert!(!f.posts.borrow().iter().any(|p| p.contains("firewall/filter")), "no rule is created");
        assert!(push_with(&Fake::new((403, "")), &[]).unwrap_err().contains("can't write"));
        assert!(push_with(&Fake::new((200, "{\"result\":\"failed\"}")), &[]).is_err());
    }

    #[test]
    fn the_demo_probe_follows_the_key() {
        let mut i = Cfg { key: "ReadOnly-key".into(), ..Default::default() };
        assert_eq!(demo_probe(&i, true, None).write, Some(false));
        i.key = "full".into();
        assert_eq!(demo_probe(&i, true, None).write, Some(true));
        assert_eq!(demo_probe(&i, false, Some(false)).write, Some(false));
    }
}
