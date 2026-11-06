//! One-time move of the old typed integration settings into plugins: which plugins were in use, and their
//! keys, tokens, webhook addresses and hosts. Runs at start-up against the raw settings file (the old fields
//! are gone from `Settings`, so saving would otherwise lose them) and does nothing once a plugin has its state.

use crate::plugins::wasm::manager;
use crate::settings::{PluginState, Settings, secret};
use std::collections::BTreeMap;

/// Plugin id and (old settings key, the plugin's secret field it becomes).
const NOTIFICATIONS: &[(&str, &[(&str, &str)])] = &[
    ("discord", &[("discord_webhook", "webhook")]),
    ("slack", &[("slack_webhook", "webhook")]),
    ("pushbullet", &[("pushbullet_token", "token")]),
    ("ntfy", &[("ntfy_url", "url")]),
    ("gotify", &[("gotify_url", "url"), ("gotify_token", "token")]),
    ("webhook", &[("generic_webhook", "url")]),
];

/// The old text values for these keys: decrypted, trimmed, and only the non-empty ones.
fn old_values(raw: &toml::Table, map: &[(&str, &str)]) -> BTreeMap<String, String> {
    map.iter().filter_map(|(old, new)| raw.get(*old).and_then(|v| v.as_str()).map(|v| ((*new).to_owned(), secret::open(v).trim().to_owned()))).filter(|(_, v)| !v.is_empty()).collect()
}

/// Turns on, and gives their old values to, the plugins the old settings file used. Never overwrites a plugin
/// that already has a state or saved settings. True when `s` changed.
pub fn run(s: &mut Settings, raw: &toml::Table) -> bool {
    let mut changed = false;
    for (id, map) in NOTIFICATIONS {
        let secrets = old_values(raw, map);
        if secrets.is_empty() || s.plugins.contains_key(*id) {
            continue;
        }
        manager::seed(id, BTreeMap::new(), secrets);
        s.plugins.insert((*id).to_owned(), PluginState { enabled: true, ..PluginState::default() });
        changed = true;
    }
    if !s.plugins.contains_key("ping")
        && let Some((config, show_tab)) = raw.get("ping").and_then(|v| v.as_table()).and_then(ping_config)
    {
        manager::seed("ping", config, BTreeMap::new());
        s.plugins.insert("ping".to_owned(), PluginState { enabled: show_tab, ..PluginState::default() });
        changed = true;
    }
    if !s.plugins.contains_key("virustotal")
        && let Some((config, secrets, enabled)) = virustotal_config(raw)
    {
        manager::seed("virustotal", config, secrets);
        s.plugins.insert("virustotal".to_owned(), PluginState { enabled, ..PluginState::default() });
        changed = true;
    }
    if !s.plugins.contains_key("opnsense")
        && let Some((config, secrets, enabled)) = opnsense_config(raw)
    {
        manager::seed("opnsense", config, secrets);
        s.plugins.insert("opnsense".to_owned(), PluginState { enabled, ..PluginState::default() });
        changed = true;
    }
    if !s.plugins.contains_key("speedtest")
        && let Some((config, show_tab)) = raw.get("speedtest").and_then(|v| v.as_table()).and_then(speedtest_config)
    {
        manager::seed("speedtest", config, BTreeMap::new());
        s.plugins.insert("speedtest".to_owned(), PluginState { enabled: show_tab, ..PluginState::default() });
        changed = true;
    }
    if !s.plugins.contains_key("thinkbroadband")
        && let Some((config, enabled)) = raw.get("thinkbroadband").and_then(|v| v.as_table()).and_then(thinkbroadband_config)
    {
        manager::seed("thinkbroadband", config, BTreeMap::new());
        s.plugins.insert("thinkbroadband".to_owned(), PluginState { enabled, ..PluginState::default() });
        changed = true;
    }
    if !s.plugins.contains_key("ha")
        && let Some((config, secrets, enabled)) = ha_config(raw)
    {
        manager::seed("ha", config, secrets);
        s.plugins.insert("ha".to_owned(), PluginState { enabled, ..PluginState::default() });
        changed = true;
    }
    changed
}

/// The old `[[integrations]]` list as the Home Assistant plugin's settings: the first one that was in use (switched on,
/// with a token and an address), else the first. The plugin handles one Home Assistant; the others are dropped.
type Strings = BTreeMap<String, String>;

/// The old `[thinkbroadband]` table as the plugin's saved settings: the chosen graphs, the download interval, the
/// alert level and the chart choices. The plugin is on when it was switched on and had graphs.
fn thinkbroadband_config(t: &toml::Table) -> Option<(Strings, bool)> {
    let clean = |s: &str| s.chars().filter(|c| !c.is_control()).collect::<String>();
    let monitors: Vec<String> = t
        .get("monitors")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|m| {
            let m = m.as_table()?;
            Some(format!("{}\t{}", m.get("id")?.as_integer()?, clean(m.get("name").and_then(|n| n.as_str()).unwrap_or(""))))
        })
        .collect();
    if monitors.is_empty() {
        return None;
    }
    let mut config = BTreeMap::from([("monitors".to_owned(), monitors.join("\n"))]);
    for k in ["interval_mins", "layout", "range"] {
        if let Some(n) = t.get(k).and_then(|v| v.as_integer()) {
            config.insert(k.to_owned(), n.to_string());
        }
    }
    if let Some(p) = t.get("alert_pct").and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64))) {
        config.insert("alert_pct".to_owned(), p.to_string());
    }
    Some((config, t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true)))
}

/// The old `[speedtest]` table as the speedtest plugin's saved settings, and whether its tab was switched on.
/// `None` when it holds nothing worth keeping.
fn speedtest_config(t: &toml::Table) -> Option<(Strings, bool)> {
    let show_tab = t.get("show_tab").and_then(|v| v.as_bool()).unwrap_or(false);
    let int = |k: &str| t.get(k).and_then(|v| v.as_integer()).filter(|n| *n > 0);
    let config: Strings = [("interval_mins", int("interval_mins")), ("server_id", int("server_id")), ("range", t.get("range").and_then(|v| v.as_integer()).filter(|n| *n >= 0))]
        .into_iter()
        .filter_map(|(k, v)| Some((k.to_owned(), v?.to_string())))
        .collect();
    (show_tab || !config.is_empty()).then_some((config, show_tab))
}

/// The old `[opnsense]` table. The probe result is kept only while it still matches the address and key it
/// was made for (the old fingerprint is checked); otherwise every option goes back off until it is probed again.
fn opnsense_config(raw: &toml::Table) -> Option<(Strings, Strings, bool)> {
    use sha2::{Digest, Sha256};
    let t = raw.get("opnsense")?.as_table()?;
    let plain = |k: &str| t.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_owned();
    let clean = |s: String| s.chars().filter(|c| !c.is_control()).collect::<String>();
    let url = plain("url").trim_end_matches('/').to_owned();
    let key = clean(secret::open(&plain("key")).trim().to_owned());
    let secret_value = clean(secret::open(&plain("secret")).trim().to_owned());
    if url.is_empty() && key.is_empty() && secret_value.is_empty() {
        return None;
    }
    let fingerprint: String = {
        let mut h = Sha256::new();
        for part in [&url, &key, &secret_value] {
            h.update(part.as_bytes());
            h.update([0]);
        }
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    };
    let probe_valid = t.get("caps_for").and_then(|v| v.as_str()) == Some(fingerprint.as_str());
    let caps = t.get("caps").filter(|_| probe_valid);
    let flag = |k: &str| if probe_valid && t.get(k).and_then(|v| v.as_bool()).unwrap_or(false) { "1" } else { "0" };
    let mut config = BTreeMap::from([
        ("url".to_owned(), url.clone()),
        ("allow_self_signed".to_owned(), if t.get("allow_self_signed").and_then(|v| v.as_bool()).unwrap_or(false) { "1" } else { "0" }.to_owned()),
        ("pull_devices".to_owned(), flag("pull_devices").to_owned()),
        ("pull_log".to_owned(), flag("pull_log").to_owned()),
        ("pull_gateway".to_owned(), flag("pull_gateway").to_owned()),
        ("push_blocks".to_owned(), flag("push_blocks").to_owned()),
    ]);
    let mut secrets = BTreeMap::from([("key".to_owned(), key.clone()), ("secret".to_owned(), secret_value.clone())]);
    if let Some(c) = caps.and_then(|c| serde_json::to_string(c).ok()) {
        config.insert("caps".to_owned(), c);
        // The plugin's own fingerprint scheme: the address, key and secret joined.
        secrets.insert("caps_for".to_owned(), format!("{url}\0{key}\0{secret_value}"));
    }
    let enabled = t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true) && !key.is_empty() && !secret_value.is_empty() && url.starts_with("http");
    Some((config, secrets, enabled))
}

/// The old VirusTotal key and auto-scan switch. The plugin is on when a key was saved (that is what turned the
/// column on before); `None` when the file never had either.
fn virustotal_config(raw: &toml::Table) -> Option<(Strings, Strings, bool)> {
    let key = raw.get("virustotal_key").and_then(|v| v.as_str()).map(|v| secret::open(v).trim().to_owned()).unwrap_or_default();
    let auto = raw.get("virustotal_auto").and_then(|v| v.as_bool()).unwrap_or(false);
    let added = raw.get("virustotal_added").and_then(|v| v.as_bool()).unwrap_or(false);
    if key.is_empty() && !added {
        return None;
    }
    let config = BTreeMap::from([("auto".to_owned(), if auto { "1" } else { "0" }.to_owned())]);
    let secrets = if key.is_empty() { BTreeMap::new() } else { BTreeMap::from([("key".to_owned(), key.clone())]) };
    Some((config, secrets, !key.is_empty()))
}

fn ha_config(raw: &toml::Table) -> Option<(Strings, Strings, bool)> {
    let list = raw.get("integrations")?.as_array()?;
    let tables: Vec<&toml::Table> = list.iter().filter_map(|v| v.as_table()).collect();
    let text = |t: &toml::Table, k: &str| t.get(k).and_then(|v| v.as_str()).map(|v| secret::open(v).trim().to_owned()).unwrap_or_default();
    let token = |t: &toml::Table| text(t, "token").chars().filter(|c| !c.is_control()).collect::<String>();
    let url = |t: &toml::Table| text(t, "url").trim_end_matches('/').to_owned();
    let enabled = |t: &toml::Table| t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    let in_use = |t: &toml::Table| enabled(t) && !token(t).is_empty() && !url(t).is_empty();
    let it = *tables.iter().find(|t| in_use(t)).or(tables.first())?;
    if url(it).is_empty() && token(it).is_empty() {
        return None;
    }
    let flag = |k: &str| if it.get(k).and_then(|v| v.as_bool()).unwrap_or(true) { "1" } else { "0" };
    let config = BTreeMap::from([("url".to_owned(), url(it)), ("prefer_name".to_owned(), flag("prefer_name").to_owned()), ("show_type".to_owned(), flag("show_type").to_owned())]);
    let secrets = BTreeMap::from([("token".to_owned(), token(it))]);
    Some((config, secrets, in_use(it)))
}

/// The old `[ping]` table as the ping plugin's saved settings, and whether its tab was switched on.
/// `None` when it holds nothing worth keeping (no hosts and the tab off).
fn ping_config(p: &toml::Table) -> Option<(BTreeMap<String, String>, bool)> {
    let show_tab = p.get("show_tab").and_then(|v| v.as_bool()).unwrap_or(false);
    let clean = |s: &str| s.chars().filter(|c| !c.is_control()).collect::<String>().trim().to_owned();
    let hosts: Vec<String> = p
        .get("hosts")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|h| {
            let h = h.as_table()?;
            let (id, address) = (h.get("id")?.as_integer()?, clean(h.get("address")?.as_str()?));
            (!address.is_empty()).then(|| format!("{id}\t{address}\t{}", clean(h.get("name").and_then(|n| n.as_str()).unwrap_or(""))))
        })
        .collect();
    if hosts.is_empty() && !show_tab {
        return None;
    }
    let mut config = BTreeMap::new();
    config.insert("hosts".to_owned(), hosts.join("\n"));
    for k in ["next_id", "layout", "range"] {
        if let Some(n) = p.get(k).and_then(|v| v.as_integer()) {
            config.insert(k.to_owned(), n.to_string());
        }
    }
    Some((config, show_tab))
}

/// The tables the plugins took over, moved under their new names the first time the database opens. Each step
/// copies the old rows and then drops the old table, so a database that has been moved is left alone.
pub fn migrate_tables(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let has = |name: &str| conn.query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [name], |_| Ok(())).is_ok();
    if has("ping_samples") {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS p_ping__samples (
                host INTEGER NOT NULL, ts INTEGER NOT NULL, min REAL NOT NULL, avg REAL NOT NULL, max REAL NOT NULL, loss REAL NOT NULL,
                PRIMARY KEY (host, ts)) WITHOUT ROWID;
             INSERT OR IGNORE INTO p_ping__samples SELECT host, ts, min, avg, max, loss FROM ping_samples;
             DROP TABLE ping_samples;",
        )?;
    }
    if has("tbb_samples") {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS p_thinkbroadband__samples (
                monitor INTEGER NOT NULL, ts INTEGER NOT NULL, min REAL NOT NULL, avg REAL NOT NULL, max REAL NOT NULL, loss REAL NOT NULL,
                PRIMARY KEY (monitor, ts)) WITHOUT ROWID;
             INSERT OR IGNORE INTO p_thinkbroadband__samples SELECT monitor, ts, min, avg, max, loss FROM tbb_samples;
             DROP TABLE tbb_samples;",
        )?;
    }
    if has("speedtest_results") {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS p_speedtest__results (
                ts INTEGER PRIMARY KEY, ping REAL NOT NULL, jitter REAL NOT NULL, down REAL NOT NULL, up REAL NOT NULL,
                loss REAL NOT NULL, server TEXT NOT NULL, isp TEXT NOT NULL, url TEXT NOT NULL,
                server_ip TEXT NOT NULL DEFAULT '', client_ip TEXT NOT NULL DEFAULT '');
             INSERT OR IGNORE INTO p_speedtest__results (ts, ping, jitter, down, up, loss, server, isp, url, server_ip, client_ip)
                SELECT ts, ping, jitter, down, up, loss, server, isp, url, server_ip, client_ip FROM speedtest_results;
             DROP TABLE speedtest_results;",
        )?;
    }
    // Home Assistant's lookups are a cache: the plugin asks again, one device a second.
    if has("ha_devices") {
        conn.execute_batch("DROP TABLE ha_devices;")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> toml::Table {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn old_values_are_found_trimmed_and_empty_ones_skipped() {
        let raw = table("gotify_url = ' https://g.example '\ngotify_token = ''\nntfy_url = 'https://ntfy.sh/x'");
        let g = old_values(&raw, &[("gotify_url", "url"), ("gotify_token", "token")]);
        assert_eq!(g, BTreeMap::from([("url".to_owned(), "https://g.example".to_owned())]));
        assert!(old_values(&raw, &[("discord_webhook", "webhook")]).is_empty());
    }

    #[test]
    fn nothing_is_enabled_when_no_service_was_configured() {
        let mut s = Settings::default();
        assert!(!run(&mut s, &table("bits = true\nntfy_url = ''")));
        assert!(s.plugins.is_empty());
    }

    #[test]
    fn the_old_ping_table_becomes_the_plugins_settings() {
        let raw = table(
            "[ping]\nshow_tab = true\nnext_id = 3\nlayout = 2\nrange = 1\n[[ping.hosts]]\nid = 1\nname = 'Cloud flare'\naddress = '1.1.1.1'\n[[ping.hosts]]\nid = 3\nname = ''\naddress = ' 8.8.8.8 '\n[[ping.hosts]]\nid = 4\nname = 'no address'\naddress = ''\n",
        );
        let (config, show) = ping_config(raw["ping"].as_table().unwrap()).unwrap();
        assert!(show);
        assert_eq!(config["hosts"], "1\t1.1.1.1\tCloud flare\n3\t8.8.8.8\t");
        assert_eq!((config["next_id"].as_str(), config["layout"].as_str(), config["range"].as_str()), ("3", "2", "1"));
        // A default table with nothing in it is not worth a plugin state.
        assert!(ping_config(table("[ping]\nshow_tab = false\nhosts = []")["ping"].as_table().unwrap()).is_none());
    }

    #[test]
    fn the_old_opnsense_table_keeps_a_probe_only_while_it_still_matches() {
        use sha2::{Digest, Sha256};
        let fp: String = {
            let mut h = Sha256::new();
            for part in ["https://fw", "k1", "s1"] {
                h.update(part.as_bytes());
                h.update([0]);
            }
            h.finalize().iter().map(|b| format!("{b:02x}")).collect()
        };
        let text = |caps_for: &str| {
            format!(
                "[opnsense]\nenabled = true\nurl = 'https://fw/'\nkey = 'k1'\nsecret = 's1'\nallow_self_signed = true\npull_devices = true\npush_blocks = true\ncaps_for = '{caps_for}'\n[opnsense.caps]\nleases = true\nwrite = true\nversion = '25.1'\n"
            )
        };
        let (config, secrets, on) = opnsense_config(&table(&text(&fp))).unwrap();
        assert!(on);
        assert_eq!((config["url"].as_str(), config["allow_self_signed"].as_str(), config["pull_devices"].as_str(), config["push_blocks"].as_str()), ("https://fw", "1", "1", "1"));
        assert!(config["caps"].contains("\"leases\":true"));
        assert_eq!((secrets["key"].as_str(), secrets["caps_for"].as_str()), ("k1", "https://fw\0k1\0s1"));
        // A probe made for another address or key is dropped, and the options it unlocked go off.
        let (config, secrets, _) = opnsense_config(&table(&text("not-the-fingerprint"))).unwrap();
        assert_eq!((config["pull_devices"].as_str(), config["push_blocks"].as_str()), ("0", "0"));
        assert!(!config.contains_key("caps") && !secrets.contains_key("caps_for"));
        assert!(opnsense_config(&table("[opnsense]\nurl = ''")).is_none());
        assert!(opnsense_config(&table("bits = true")).is_none());
    }

    #[test]
    fn the_old_thinkbroadband_table_becomes_the_plugins_settings() {
        let raw = table(
            "[thinkbroadband]\nenabled = true\nshow_tab = true\ninterval_mins = 15\nalert_pct = 2.5\nlayout = 2\nrange = 0\n[[thinkbroadband.monitors]]\nid = 7\nname = 'Home line'\n[[thinkbroadband.monitors]]\nid = 9\nname = 'Office'\n",
        );
        let (config, on) = thinkbroadband_config(raw["thinkbroadband"].as_table().unwrap()).unwrap();
        assert!(on);
        assert_eq!(config["monitors"], "7\tHome line\n9\tOffice");
        assert_eq!((config["interval_mins"].as_str(), config["alert_pct"].as_str(), config["layout"].as_str(), config["range"].as_str()), ("15", "2.5", "2", "0"));
        // No graphs chosen: never usable, nothing to keep.
        assert!(thinkbroadband_config(table("[thinkbroadband]\nenabled = true")["thinkbroadband"].as_table().unwrap()).is_none());
    }

    #[test]
    fn old_thinkbroadband_samples_move_into_the_plugin_table() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE tbb_samples (monitor INTEGER NOT NULL, ts INTEGER NOT NULL, min REAL NOT NULL, avg REAL NOT NULL, max REAL NOT NULL, loss REAL NOT NULL, PRIMARY KEY (monitor, ts)) WITHOUT ROWID;
             INSERT INTO tbb_samples VALUES (7, 100, 1, 2, 3, 0), (7, 200, 1, 2, 3, 4);",
        )
        .unwrap();
        migrate_tables(&conn).unwrap();
        let n: i64 = conn.query_row("SELECT count(*) FROM p_thinkbroadband__samples WHERE monitor = 7", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2);
        assert!(conn.query_row("SELECT 1 FROM sqlite_master WHERE name = 'tbb_samples'", [], |_| Ok(())).is_err());
    }

    #[test]
    fn the_old_speedtest_table_becomes_the_plugins_settings() {
        let (config, on) = speedtest_config(&table("[speedtest]\nshow_tab = true\ninterval_mins = 60\nserver_id = 1234\nrange = 2\n")["speedtest"].as_table().unwrap().clone()).unwrap();
        assert!(on);
        assert_eq!((config["interval_mins"].as_str(), config["server_id"].as_str(), config["range"].as_str()), ("60", "1234", "2"));
        // Defaults only (0 minutes, closest server, first range): the tab was off, so nothing to keep.
        assert!(speedtest_config(&table("[speedtest]\nshow_tab = false\ninterval_mins = 0\nserver_id = 0")["speedtest"].as_table().unwrap().clone()).is_none());
        // Off, but with a schedule: kept, off.
        assert!(!speedtest_config(&table("[speedtest]\nshow_tab = false\ninterval_mins = 30")["speedtest"].as_table().unwrap().clone()).unwrap().1);
    }

    #[test]
    fn old_speedtest_rows_move_into_the_plugin_table() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE speedtest_results (ts INTEGER PRIMARY KEY, ping REAL NOT NULL, jitter REAL NOT NULL, down REAL NOT NULL, up REAL NOT NULL, loss REAL NOT NULL, server TEXT NOT NULL, isp TEXT NOT NULL, url TEXT NOT NULL, server_ip TEXT NOT NULL DEFAULT '', client_ip TEXT NOT NULL DEFAULT '');
             INSERT INTO speedtest_results VALUES (100, 10, 1, 900, 90, 0, 'S', 'I', '', '1.2.3.4', '5.6.7.8');",
        )
        .unwrap();
        migrate_tables(&conn).unwrap();
        let row: (i64, f64, String) = conn.query_row("SELECT ts, down, server_ip FROM p_speedtest__results", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!(row, (100, 900.0, "1.2.3.4".to_owned()));
        assert!(conn.query_row("SELECT 1 FROM sqlite_master WHERE name = 'speedtest_results'", [], |_| Ok(())).is_err());
    }

    #[test]
    fn the_old_virustotal_key_becomes_the_plugins_secret() {
        let (config, secrets, on) = virustotal_config(&table("virustotal_key = ' abc123 '\nvirustotal_auto = true")).unwrap();
        assert!(on);
        assert_eq!((config["auto"].as_str(), secrets["key"].as_str()), ("1", "abc123"));
        // Added from the menu but never given a key: kept, off. Never touched: nothing.
        let (_, secrets, on) = virustotal_config(&table("virustotal_added = true")).unwrap();
        assert!(!on && secrets.is_empty());
        assert!(virustotal_config(&table("virustotal_key = ''")).is_none());
    }

    #[test]
    fn the_first_home_assistant_in_use_becomes_the_plugin() {
        let raw = table(
            "[[integrations]]\nenabled = false\nurl = 'http://old:8123'\ntoken = 't0'\n[[integrations]]\nenabled = true\nurl = 'http://ha.local:8123/'\ntoken = ' t1 '\nprefer_name = false\nshow_type = true\n",
        );
        let (config, secrets, on) = ha_config(&raw).unwrap();
        assert!(on);
        assert_eq!((config["url"].as_str(), config["prefer_name"].as_str(), config["show_type"].as_str()), ("http://ha.local:8123", "0", "1"));
        assert_eq!(secrets["token"], "t1");
        // One that was never filled in isn't worth a plugin state.
        assert!(ha_config(&table("[[integrations]]\nenabled = true\nurl = ''\ntoken = ''")).is_none());
        // Switched off but filled in: kept, off.
        let (_, _, on) = ha_config(&table("[[integrations]]\nenabled = false\nurl = 'http://x'\ntoken = 't'")).unwrap();
        assert!(!on);
        assert!(ha_config(&table("bits = true")).is_none());
    }

    #[test]
    fn old_ping_rows_move_into_the_plugin_table_once() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE ping_samples (host INTEGER NOT NULL, ts INTEGER NOT NULL, min REAL NOT NULL, avg REAL NOT NULL, max REAL NOT NULL, loss REAL NOT NULL, PRIMARY KEY (host, ts)) WITHOUT ROWID;
             INSERT INTO ping_samples VALUES (1, 100, 1, 2, 3, 0), (1, 200, 1, 2, 3, 50);",
        )
        .unwrap();
        migrate_tables(&conn).unwrap();
        let count = |t: &str| conn.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get::<_, i64>(0));
        assert_eq!(count("p_ping__samples").unwrap(), 2);
        assert!(count("ping_samples").is_err(), "the old table is gone");
        migrate_tables(&conn).unwrap();
        assert_eq!(count("p_ping__samples").unwrap(), 2, "a second run changes nothing");
    }

    #[test]
    fn a_plugin_that_already_has_a_state_is_left_alone() {
        let mut s = Settings::default();
        s.plugins.insert("discord".into(), PluginState::default());
        assert!(!run(&mut s, &table("discord_webhook = 'https://discord.com/api/webhooks/1/x'")));
        assert!(!s.plugins["discord"].enabled);
    }
}
