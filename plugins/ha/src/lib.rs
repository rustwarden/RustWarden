//! Home Assistant: names and types for scanned devices, matched by MAC address only.
//! Each network device is looked up once (then hourly while unmatched, daily once matched), so
//! Home Assistant is never polled; devices Home Assistant knows but the network scan hasn't
//! seen are never stored. RustWarden shows what this plugin stores in `p_ha__devices` on the Scanner tab.

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Event, Kind, Manifest, Reply, UiTree};
use serde_json::Value;
use std::collections::HashMap;

const LOGO: &[u8] = include_bytes!("../assets/home-assistant.png");
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS p_ha__devices (
    mac TEXT PRIMARY KEY, checked INTEGER NOT NULL, found INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL DEFAULT '', area TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '');";
const RECHECK_MISSING: i64 = 3600;
const RECHECK_FOUND: i64 = 24 * 3600;

struct Ha;

/// What Home Assistant knows about one network device.
#[derive(Debug, Default, PartialEq)]
struct Note {
    name: String,
    area: String,
    model: String,
    kind: String,
    device_id: String,
}

/// Base address without a trailing slash.
fn url() -> String {
    guest::config_get("url").trim().trim_end_matches('/').to_owned()
}

/// Control characters would become extra headers in the request.
fn token() -> String {
    guest::secret_get("token").trim().chars().filter(|c| !c.is_control()).collect()
}

fn valid_url(u: &str) -> bool {
    u.starts_with("http://") || u.starts_with("https://")
}

fn ready() -> bool {
    !token().is_empty() && valid_url(&url())
}

fn flag(key: &str) -> bool {
    guest::config_get(key) != "0"
}

fn num(key: &str) -> i64 {
    guest::config_get(key).parse().unwrap_or(0)
}

/// The Jinja template for one MAC; it renders "name<TAB>area<TAB>model<TAB>entity,entity<TAB>device id" or nothing.
fn template(mac: &str) -> String {
    let mac: String = mac.to_lowercase().chars().filter(|c| c.is_ascii_hexdigit() || *c == ':').collect();
    format!(
        "{{%- set ns = namespace(r='') -%}}\
         {{%- for d in states | map(attribute='entity_id') | map('device_id') | select('string') | unique -%}}\
         {{%- if not ns.r -%}}{{%- for c in device_attr(d, 'connections') -%}}\
         {{%- if c[0] == 'mac' and c[1] | lower == '{mac}' -%}}\
         {{%- set ns.r = [device_attr(d, 'name_by_user') or device_attr(d, 'name') or '', area_name(d) or '', device_attr(d, 'model') or '', device_entities(d) | join(','), d] | join('\\t') -%}}\
         {{%- endif -%}}{{%- endfor -%}}{{%- endif -%}}{{%- endfor -%}}{{{{ ns.r }}}}"
    )
}

fn headers() -> Vec<String> {
    vec![format!("Authorization: Bearer {}", token()), "Content-Type: application/json".to_owned()]
}

/// A request error in words: the host reports a status as "HTTP 401".
fn explain(e: &str) -> String {
    match e {
        "HTTP 401" | "HTTP 403" => "Home Assistant rejected the access token.".to_owned(),
        s if s.starts_with("HTTP ") => format!("Home Assistant answered {s}."),
        s => format!("Can't reach Home Assistant: {s}"),
    }
}

fn test() -> Result<(), String> {
    guest::http_request(&format!("{}/api/", url()), &headers(), None).map(|_| ()).map_err(|e| explain(&e))
}

/// `Ok(None)`: Home Assistant answered and has no such device.
fn lookup(mac: &str) -> Result<Option<Note>, String> {
    let body = serde_json::json!({ "template": template(mac) }).to_string();
    guest::http_request(&format!("{}/api/template", url()), &headers(), Some(&body)).map(|t| parse(&t)).map_err(|e| explain(&e))
}

fn parse(text: &str) -> Option<Note> {
    let mut f = text.trim_matches(['\r', '\n', ' ']).splitn(5, '\t'); // not trim(): an empty name leaves leading tabs
    let (name, area, model, entities) = (f.next()?.trim(), f.next()?.trim(), f.next()?.trim(), f.next()?);
    let device_id = f.next().unwrap_or("").trim();
    let has = |domain: &str| entities.split(',').any(|e| e.split('.').next() == Some(domain));
    let kind = ["camera", "lock", "light", "media_player", "switch", "sensor", "binary_sensor"].into_iter().find(|d| has(d)).map_or("other", |d| match d {
        "media_player" => "media",
        "binary_sensor" => "sensor",
        d => d,
    });
    let name = if name.is_empty() { model } else { name };
    (!name.is_empty()).then(|| Note { name: name.into(), area: area.into(), model: model.into(), kind: kind.into(), device_id: device_id.into() })
}

/// Single-quoted SQL text.
fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn store(mac: &str, note: Option<&Note>, now: i64) {
    let n = note.map(|n| Note { name: n.name.clone(), area: n.area.clone(), model: n.model.clone(), kind: n.kind.clone(), device_id: n.device_id.clone() }).unwrap_or_default();
    let link = if note.is_some() && !n.device_id.is_empty() { format!("{}/config/devices/device/{}", url(), n.device_id) } else { String::new() };
    let sql = format!(
        "INSERT OR REPLACE INTO p_ha__devices (mac, checked, found, name, area, kind, model, url) VALUES ({}, {now}, {}, {}, {}, {}, {}, {})",
        q(mac),
        i32::from(note.is_some()),
        q(&n.name),
        q(&n.area),
        q(&n.kind),
        q(&n.model),
        q(&link)
    );
    if let Err(e) = guest::db_exec(&sql) {
        guest::log(&format!("couldn't store a lookup: {e}"));
    }
}

/// (checked, found) for every device looked up so far, by MAC.
fn known() -> HashMap<String, (i64, bool)> {
    let Ok(json) = guest::db_query("SELECT mac, checked, found FROM p_ha__devices") else { return HashMap::new() };
    let rows: Vec<Vec<Value>> = serde_json::from_str(&json).unwrap_or_default();
    rows.iter().filter_map(|r| Some((r.first()?.as_str()?.to_owned(), (r.get(1)?.as_i64()?, r.get(2)?.as_i64()? == 1)))).collect()
}

/// The scanned device that is due a lookup: never checked first, then the longest overdue.
fn next_due(devices: &[String], known: &HashMap<String, (i64, bool)>, now: i64) -> Option<String> {
    devices
        .iter()
        // "ip:..." rows are devices seen only by address (another subnet): they have no MAC to match.
        .filter(|m| !m.starts_with("ip:"))
        .filter_map(|m| match known.get(m) {
            None => Some((i64::MIN, m)),
            Some((checked, found)) => (*checked < now - if *found { RECHECK_FOUND } else { RECHECK_MISSING }).then_some((*checked, m)),
        })
        .min_by_key(|(c, _)| *c)
        .map(|(_, m)| m.clone())
}

fn set_status(msg: &str) {
    let before = guest::config_get("status");
    guest::config_set("status", msg);
    // A toast when trouble starts, not on every failed retry.
    if before.is_empty() && !msg.is_empty() {
        guest::notify_in_app(msg);
    }
}

fn tick() {
    if !ready() {
        set_status("");
        return;
    }
    let now = guest::now();
    // Kept with the secrets, so only a different Home Assistant (not a restart) makes every device due again.
    let key = format!("{}\0{}", url(), token());
    if guest::secret_get("cfg") != key || guest::config_get("sync") == "1" {
        guest::secret_set("cfg", &key);
        guest::config_set("sync", "0");
        guest::config_set("retry_at", "0");
        guest::config_set("fails", "0");
        let _ = guest::db_exec("UPDATE p_ha__devices SET checked = 0");
    }
    if now < num("retry_at") {
        return;
    }
    let Ok(devices) = guest::devices() else { return };
    let macs: Vec<String> = devices.into_iter().map(|d| d.mac).collect();
    let Some(mac) = next_due(&macs, &known(), now) else { return };
    match lookup(&mac) {
        Ok(note) => {
            guest::config_set("fails", "0");
            set_status("");
            store(&mac, note.as_ref(), now);
        }
        Err(e) => {
            // Nothing is recorded, so the device is tried again after the pause, which grows from a minute to an hour.
            let fails = num("fails") + 1;
            let pause = (60i64 << (fails - 1).min(6)).min(3600);
            guest::config_set("fails", &fails.to_string());
            guest::config_set("retry_at", &(now + pause).to_string());
            set_status(&format!("{e} Trying again in {} min.", pause / 60));
        }
    }
}

fn settings() -> UiTree {
    let u = guest::config_get("url");
    let mut rows = vec![UiTree::Label("Address".into()), UiTree::TextField { id: "url".into(), value: u.clone() }];
    if !u.trim().is_empty() && !valid_url(u.trim()) {
        rows.push(UiTree::Label("⚠ The address must start with http:// or https://".into()));
    } else if u.trim().is_empty() {
        rows.push(UiTree::Weak("For example http://homeassistant.local:8123".into()));
    }
    rows.push(UiTree::Label("Long-lived access token (Home Assistant profile > Security)".into()));
    rows.push(UiTree::Password { id: "token".into(), value: guest::secret_get("token") });
    rows.push(UiTree::Switch { id: "prefer_name".into(), text: "Prefer HA entity name".into(), on: flag("prefer_name") });
    rows.push(UiTree::Weak("Shows the Home Assistant name (with its area) instead of the network name on the Scanner tab.".into()));
    rows.push(UiTree::Switch { id: "show_type".into(), text: "Show device type".into(), on: flag("show_type") });
    rows.push(UiTree::Weak("Shows an icon for light, plug, sensor and so on beside matched devices.".into()));
    rows.push(UiTree::Row(vec![UiTree::Button { id: "test".into(), text: "Test connection".into() }, UiTree::Button { id: "sync".into(), text: "Sync now".into() }]));
    rows.push(UiTree::Weak("Sync now looks every scanned device up again.".into()));
    for key in ["test_msg", "status"] {
        let m = guest::config_get(key);
        if !m.is_empty() {
            rows.push(UiTree::Label(m));
        }
    }
    UiTree::Column(rows)
}

fn event(e: Event) {
    match e {
        Event::Text { id, value } if id == "url" => guest::config_set("url", value.trim()),
        Event::Text { id, value } if id == "token" => guest::secret_set("token", &value.trim().chars().filter(|c| !c.is_control()).collect::<String>()),
        Event::Bool { id, on } if id == "prefer_name" || id == "show_type" => guest::config_set(&id, if on { "1" } else { "0" }),
        Event::Click { id } if id == "test" => {
            guest::config_set("test_msg", &if ready() { test().map_or_else(|e| e, |()| "Connected.".to_owned()) } else { "Enter an address and a token first.".to_owned() });
        }
        Event::Click { id } if id == "sync" => guest::config_set("sync", "1"),
        _ => {}
    }
}

impl Guest for Ha {
    fn manifest() -> Manifest {
        Manifest {
            id: "ha".into(),
            name: "Home Assistant".into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            icon: LOGO.to_vec(),
            settings_page: true,
            // Home Assistant runs wherever the user put it.
            http_hosts: vec!["*".into()],
            permissions: vec!["devices.annotate".into()],
            tick_secs: 1,
            schema: SCHEMA.into(),
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderSettings => Reply::Ui(settings()),
            Call::Event(e) => {
                event(e);
                Reply::Done
            }
            Call::Tick => {
                tick();
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Ha);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_match_and_picks_the_type() {
        let i = parse("Sonos Arc\tLiving Room\tArc\tmedia_player.arc,sensor.arc_battery\n").unwrap();
        assert_eq!((i.name.as_str(), i.area.as_str(), i.kind.as_str()), ("Sonos Arc", "Living Room", "media"));
        assert_eq!(parse("Plug\t\tP110\tswitch.plug,sensor.plug_power\tabc123").unwrap().device_id, "abc123");
        assert_eq!(parse("Plug\t\tP110\tswitch.plug,sensor.plug_power").unwrap().kind, "switch");
        assert_eq!(parse("Temp\tBackyard\t\tbinary_sensor.x").unwrap().kind, "sensor");
        assert_eq!(parse("\t\tModelX\t").unwrap().name, "ModelX");
    }

    #[test]
    fn no_match_is_none() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("  \n"), None);
    }

    #[test]
    fn template_embeds_only_a_clean_lowercase_mac() {
        let t = template("AA:BB:cc:01:02:03' }}");
        assert!(t.contains("== 'aa:bb:cc:01:02:03'"));
        // The tab escape survives JSON encoding.
        assert!(serde_json::json!({ "template": t }).to_string().contains("\\\\t"));
    }

    #[test]
    fn lookups_are_due_on_schedule() {
        let known: HashMap<String, (i64, bool)> = HashMap::from([("AA".into(), (1000, true)), ("BB".into(), (1000, false))]);
        let all = vec!["AA".to_owned(), "BB".to_owned(), "CC".to_owned(), "ip:10.0.0.9".to_owned()];
        // Never checked comes first, and an address-only row is never looked up.
        assert_eq!(next_due(&all, &known, 1000).as_deref(), Some("CC"));
        let checked: HashMap<String, (i64, bool)> = HashMap::from([("AA".into(), (1000, true)), ("BB".into(), (1000, false)), ("CC".into(), (1000, false))]);
        assert_eq!(next_due(&all, &checked, 1000), None);
        // An unmatched device comes round hourly, a matched one daily.
        assert_eq!(next_due(&all, &checked, 1000 + 3601).as_deref(), Some("BB"));
        assert_eq!(next_due(&["AA".to_owned()], &checked, 1000 + 3601), None);
        assert_eq!(next_due(&["AA".to_owned()], &checked, 1000 + 24 * 3600 + 1).as_deref(), Some("AA"));
    }

    #[test]
    fn sql_text_is_quoted() {
        assert_eq!(q("it's"), "'it''s'");
    }

    #[test]
    fn http_errors_are_explained() {
        assert!(explain("HTTP 401").contains("rejected"));
        assert!(explain("HTTP 500").contains("HTTP 500"));
        assert!(explain("could not resolve").starts_with("Can't reach"));
    }
}
