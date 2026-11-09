//! The first-party plugins, built into the exe by build.rs (plugin crates in `plugins/`). They load from
//! memory, so there is nothing to extract or keep up to date: a new RustWarden brings new plugins.
//! An id here is reserved; a file in the plugin folder cannot use it.

use super::loader::Plugin;
use super::manager::{Found, Source};

macro_rules! bundle {
    ($($id:literal),* $(,)?) => {
        /// (plugin id, wasm bytes). Empty bytes mean build.rs could not build that plugin.
        const ALL: &[(&str, &[u8])] = &[$(($id, include_bytes!(concat!(env!("OUT_DIR"), "/plugins/", $id, ".wasm")))),*];
    };
}

// Keep in step with PLUGINS in build.rs.
bundle!(
    "discord",
    "slack",
    "pushbullet",
    "ntfy",
    "gotify",
    "webhook",
    "ping",
    "ha",
    "virustotal",
    "opnsense",
    "speedtest",
    "thinkbroadband",
    "prometheus",
    "upnp",
    "cloudflare",
    "shodan",
    "abuseipdb"
);

/// Every built-in plugin that loads, in list order. One that fails to load is skipped (and logged), never fatal.
pub fn found() -> Vec<Found> {
    ALL.iter()
        .filter(|(_, bytes)| !bytes.is_empty())
        .filter_map(|(id, bytes)| match Plugin::load(bytes) {
            Ok(p) if p.manifest.id == *id => Some(Found { source: Source::Bundled(bytes), hash: p.hash.clone(), manifest: p.manifest.clone() }),
            Ok(p) => {
                crate::applog::line("plugins.log", &format!("built-in plugin {id} reports the id {}; skipped", p.manifest.id));
                None
            }
            Err(e) => {
                crate::applog::line("plugins.log", &format!("built-in plugin {id} failed to load: {e}"));
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(id: &str) -> Option<crate::plugins::wasm::loader::Plugin> {
        let bytes = ALL.iter().find(|(i, _)| *i == id).map(|(_, b)| *b).filter(|b| !b.is_empty())?;
        Some(Plugin::load(bytes).unwrap())
    }

    #[test]
    fn the_prometheus_plugin_keeps_its_port() {
        use plugin_sdk::{Call, Event, Reply};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("prometheus") else { return };
        assert_eq!(p.manifest.permissions, ["metrics.serve".to_owned()]);
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::from(["metrics.serve".to_owned()]), false).unwrap();
        assert!(matches!(p.call(&Call::Event(Event::Number { id: "port".into(), value: 80.0 })).unwrap(), Reply::Done));
        assert_eq!(p.host().config.get("port").map(String::as_str), Some("1024"), "a privileged port is raised to 1024");
    }

    /// Demo mode forwards against a made-up router: the mapping is listed with a public address and can be removed.
    #[test]
    fn the_upnp_plugin_forwards_and_removes_in_demo() {
        use plugin_sdk::{Call, Event, Reply};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("upnp") else { return };
        assert_eq!(p.manifest.permissions, ["upnp".to_owned()]);
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::from(["upnp".to_owned()]), true).unwrap();
        let click = |p: &mut crate::plugins::wasm::loader::Plugin, id: &str| p.call(&Call::Event(Event::Click { id: id.into() })).unwrap();
        click(&mut p, "forward");
        let maps = p.host().config.get("maps").cloned().unwrap_or_default();
        assert_eq!(maps.lines().count(), 1, "{maps}");
        let Reply::Ui(tree) = p.call(&Call::RenderTab { tab: "upnp".into() }).unwrap() else { panic!("no page") };
        assert!(format!("{tree:?}").contains("Copy address"));
        click(&mut p, "rm:0");
        assert_eq!(p.host().config.get("maps").map(String::as_str), Some(""));
    }

    /// Demo mode answers for a made-up address, so the page shows a result without asking Shodan.
    #[test]
    fn the_shodan_plugin_looks_up_the_demo_address() {
        use plugin_sdk::{Call, Event};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("shodan") else { return };
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::new(), true).unwrap();
        p.call(&Call::Event(Event::Click { id: "me".into() })).unwrap();
        let result = p.host().config.get("result").cloned().unwrap_or_default();
        assert!(result.contains("Open ports: 22, 80, 443") && result.contains("CVE-2021-41773"), "{result}");
    }

    /// With "alerts.read" and automatic checks on, an alert's public address is scored (Demo mode makes the score up) and remembered.
    #[test]
    fn the_abuseipdb_plugin_scores_addresses_in_alerts() {
        use plugin_sdk::{Call, Event};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("abuseipdb") else { return };
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::from(["alerts.read".to_owned()]), true).unwrap();
        p.call(&Call::Event(Event::Bool { id: "auto".into(), on: true })).unwrap();
        p.call(&Call::Alert { important: true, title: "Port scan".into(), text: "from 203.0.113.7 tried 14 ports on 192.168.1.5".into() }).unwrap();
        let recent = p.host().config.get("recent").cloned().unwrap_or_default();
        assert!(recent.starts_with("203.0.113.7|") && recent.lines().count() == 1, "{recent}");
    }

    /// Demo mode starts and stops a pretend tunnel without running anything.
    #[test]
    fn the_cloudflare_plugin_pretends_in_demo() {
        use plugin_sdk::{Call, Event, Reply};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("cloudflare") else { return };
        assert_eq!(p.manifest.permissions, ["helper.exe".to_owned()]);
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::from(["helper.exe".to_owned()]), true).unwrap();
        p.host().config.insert("mode".into(), "token".into());
        p.host().secrets.insert("token".into(), "eyJhIjoiYWJjZGVmZ2hpamtsbW5vcCJ9".into());
        let page = |p: &mut crate::plugins::wasm::loader::Plugin| match p.call(&Call::RenderTab { tab: "tunnel".into() }).unwrap() {
            Reply::Ui(tree) => format!("{tree:?}"),
            other => panic!("{other:?}"),
        };
        assert!(page(&mut p).contains("Stopped"));
        p.call(&Call::Event(Event::Click { id: "start".into() })).unwrap();
        assert!(page(&mut p).contains("Running"));
        p.call(&Call::Event(Event::Click { id: "stop".into() })).unwrap();
        assert!(page(&mut p).contains("Stopped"));
    }

    /// The ping plugin the way the manager runs it: its schema, then a tick, then the page and the chart's own query.
    #[test]
    fn the_ping_plugin_stores_rounds_and_serves_its_chart() {
        use plugin_sdk::{Call, HostCall, HostReply, Reply, UiTree};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("ping") else { return };
        let granted = BTreeSet::from(["ping".to_owned()]);
        p.bind(Connection::open_in_memory().unwrap(), granted.clone(), true).unwrap();
        let schema = p.manifest.schema.clone();
        assert!(matches!(p.host().handle(HostCall::DbExec { sql: schema }), HostReply::Ok(_)));
        p.host().config.insert(
            "hosts".into(),
            "1	127.0.0.1	Loopback
2	10.0.0.9	"
                .into(),
        );
        // Demo mode makes up a week of minutes for each host.
        p.call(&Call::Tick).unwrap();
        let count = |p: &mut crate::plugins::wasm::loader::Plugin| match p.host().handle(HostCall::DbQuery { sql: "SELECT count(*) FROM p_ping__samples WHERE host = 1".into() }) {
            HostReply::Ok(j) => j.trim_matches(|c| c == '[' || c == ']').parse::<i64>().unwrap(),
            HostReply::Err(e) => panic!("{e}"),
        };
        assert!(count(&mut p) > 9_000, "a week of minutes");
        // A second tick only adds the minutes since.
        let before = count(&mut p);
        p.call(&Call::Tick).unwrap();
        assert!(count(&mut p) - before <= 2);
        let Reply::Ui(UiTree::LatencyChart(chart)) = p.call(&Call::RenderTab { tab: "ping".into() }).unwrap() else { panic!("no chart") };
        assert_eq!(chart.lines.iter().map(|l| (l.id, l.name.as_str())).collect::<Vec<_>>(), [(1, "Loopback"), (2, "10.0.0.9")]);
        assert!(chart.sql.contains("p_ping__samples"));

        // Live mode really pings, here only the loopback address.
        let mut live = load("ping").unwrap();
        live.bind(Connection::open_in_memory().unwrap(), granted, false).unwrap();
        let schema = live.manifest.schema.clone();
        live.host().handle(HostCall::DbExec { sql: schema });
        live.host().config.insert("hosts".into(), "1	127.0.0.1	Loopback".into());
        live.call(&Call::Tick).unwrap();
        assert_eq!(count(&mut live), 1);
        assert!(live.host().config.get("last_ok").is_some_and(|t| t.parse::<i64>().unwrap() > 0));
        // Without the permission the round fails and nothing is stored.
        let mut denied = load("ping").unwrap();
        denied.bind(Connection::open_in_memory().unwrap(), BTreeSet::new(), false).unwrap();
        let schema = denied.manifest.schema.clone();
        denied.host().handle(HostCall::DbExec { sql: schema });
        denied.host().config.insert("hosts".into(), "1	127.0.0.1	Loopback".into());
        denied.call(&Call::Tick).unwrap();
        assert_eq!(count(&mut denied), 0);
    }

    /// Home Assistant as the manager runs it, without a server: the page, the settings and the "not set up yet" tick.
    #[test]
    fn the_home_assistant_plugin_keeps_its_settings_and_waits_for_a_token() {
        use plugin_sdk::{Call, Event, HostCall, HostReply, Reply, UiTree};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("ha") else { return };
        assert_eq!(&p.manifest.icon[1..4], b"PNG", "the logo is the plugin's icon");
        assert_eq!(p.manifest.permissions, ["devices.annotate"]);
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::from(["devices.annotate".to_owned()]), true).unwrap();
        let schema = p.manifest.schema.clone();
        assert!(matches!(p.host().handle(HostCall::DbExec { sql: schema }), HostReply::Ok(_)));
        // No address or token: a tick does nothing and does not fail.
        p.call(&Call::Tick).unwrap();
        for (id, value) in [
            ("url", " http://ha.local:8123/ "),
            (
                "token", " abc
 ",
            ),
        ] {
            p.call(&Call::Event(Event::Text { id: id.into(), value: value.into() })).unwrap();
        }
        assert_eq!(p.host().config.get("url").map(String::as_str), Some("http://ha.local:8123/"));
        assert_eq!(p.host().secrets.get("token").map(String::as_str), Some("abc"), "the token is a secret, with control characters gone");
        p.call(&Call::Event(Event::Bool { id: "prefer_name".into(), on: false })).unwrap();
        assert_eq!(p.host().config.get("prefer_name").map(String::as_str), Some("0"));
        let Reply::Ui(UiTree::Column(page)) = p.call(&Call::RenderSettings).unwrap() else { panic!("no page") };
        assert!(page.iter().any(|w| matches!(w, UiTree::Switch { id, on: false, .. } if id == "prefer_name")));
        assert!(page.iter().any(|w| matches!(w, UiTree::Password { id, .. } if id == "token")));
        // Demo mode has no scanned devices, so a configured tick finds nothing due and makes no request.
        p.call(&Call::Tick).unwrap();
        // Without the permission the device list is refused and the tick does nothing.
        let mut denied = load("ha").unwrap();
        denied.bind(Connection::open_in_memory().unwrap(), BTreeSet::new(), true).unwrap();
        denied.host().config.insert("url".into(), "http://ha.local:8123".into());
        denied.host().secrets.insert("token".into(), "t".into());
        denied.call(&Call::Tick).unwrap();
    }

    #[test]
    fn the_virustotal_plugin_keeps_the_key_as_a_secret() {
        use plugin_sdk::{Call, Event, Reply, UiTree};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("virustotal") else { return };
        assert_eq!((p.manifest.permissions.as_slice(), p.manifest.http_hosts.as_slice()), (["programs.hash".to_owned()].as_slice(), ["www.virustotal.com".to_owned()].as_slice()));
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::from(["programs.hash".to_owned()]), false).unwrap();
        p.call(&Call::Event(Event::Text { id: "key".into(), value: " abc123 ".into() })).unwrap();
        p.call(&Call::Event(Event::Bool { id: "auto".into(), on: true })).unwrap();
        assert_eq!(p.host().secrets.get("key").map(String::as_str), Some("abc123"));
        assert!(!p.host().config.contains_key("key"), "the key is never in the plain settings");
        assert_eq!(p.host().config.get("auto").map(String::as_str), Some("1"));
        let Reply::Ui(UiTree::Column(page)) = p.call(&Call::RenderSettings).unwrap() else { panic!("no page") };
        assert!(page.iter().any(|w| matches!(w, UiTree::Switch { id, on: true, .. } if id == "auto")));
    }

    #[test]
    fn the_ping_toolbar_opens_add_and_manage_windows() {
        use plugin_sdk::{CHART_DIALOG_CLOSE, Call, Event, Reply, UiTree};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("ping") else { return };
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::from(["ping".to_owned()]), true).unwrap();
        let chart = |p: &mut crate::plugins::wasm::loader::Plugin| match p.call(&Call::RenderTab { tab: "ping".into() }).unwrap() {
            Reply::Ui(UiTree::LatencyChart(c)) => c,
            other => panic!("no chart: {other:?}"),
        };
        let c = chart(&mut p);
        assert!(c.dialog.is_none() && c.tools.len() == 2);
        let click = |p: &mut crate::plugins::wasm::loader::Plugin, id: &str| p.call(&Call::Event(Event::Click { id: id.into() })).unwrap();
        click(&mut p, "add_host");
        let c = chart(&mut p);
        assert_eq!((c.dialog_title.as_str(), c.dialog.is_some()), ("Add host", true));
        p.call(&Call::Event(Event::Text { id: "new_addr".into(), value: " 1.1.1.1 ".into() })).unwrap();
        p.call(&Call::Event(Event::Text { id: "new_name".into(), value: "Cloudflare".into() })).unwrap();
        click(&mut p, "add");
        let c = chart(&mut p);
        assert!(c.dialog.is_none(), "adding closes the window");
        assert_eq!(c.lines.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), ["Cloudflare"]);
        click(&mut p, "manage_hosts");
        assert_eq!(chart(&mut p).dialog_title, "Manage hosts");
        click(&mut p, CHART_DIALOG_CLOSE);
        assert!(chart(&mut p).dialog.is_none(), "the window's X closes it");
        // Cancel with a half-typed address adds nothing.
        click(&mut p, "add_host");
        p.call(&Call::Event(Event::Text { id: "new_addr".into(), value: "8.8.8.8".into() })).unwrap();
        click(&mut p, "cancel");
        assert_eq!(chart(&mut p).lines.len(), 1);
    }

    #[test]
    fn the_opnsense_plugin_gates_its_options_on_a_probe() {
        use plugin_sdk::{Call, Event, HostCall, HostReply, Reply, UiTree};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("opnsense") else { return };
        assert!(p.manifest.allow_insecure_tls, "the router's own certificate is its normal case");
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::new(), true).unwrap();
        let on = |p: &mut crate::plugins::wasm::loader::Plugin, id: &str| match p.call(&Call::RenderSettings).unwrap() {
            Reply::Ui(UiTree::Column(rows)) => rows.iter().any(|w| matches!(w, UiTree::Switch { id: i, on: true, .. } if i == id)),
            other => panic!("no page: {other:?}"),
        };
        let text = |p: &mut crate::plugins::wasm::loader::Plugin, id: &str, v: &str| p.call(&Call::Event(Event::Text { id: id.into(), value: v.into() })).unwrap();
        let click = |p: &mut crate::plugins::wasm::loader::Plugin, id: &str| p.call(&Call::Event(Event::Click { id: id.into() })).unwrap();
        let flip = |p: &mut crate::plugins::wasm::loader::Plugin, id: &str| p.call(&Call::Event(Event::Bool { id: id.into(), on: true })).unwrap();
        // Nothing is probed yet, so a switch can't be turned on.
        flip(&mut p, "pull_devices");
        assert!(!on(&mut p, "pull_devices"));
        text(&mut p, "url", " https://192.168.1.1/ ");
        text(&mut p, "key", "mykey");
        text(&mut p, "secret", "mysecret");
        click(&mut p, "test");
        assert!(p.host().config.get("caps").is_some_and(|c| c.contains("25.1 (demo)")));
        flip(&mut p, "pull_devices");
        flip(&mut p, "push_blocks");
        assert!(on(&mut p, "pull_devices"), "a probed key unlocks reading");
        assert!(!on(&mut p, "push_blocks"), "write access has not been checked");
        click(&mut p, "check_write");
        flip(&mut p, "push_blocks");
        assert!(on(&mut p, "push_blocks"));
        // Editing the key drops the probe and everything it unlocked.
        text(&mut p, "key", "otherkey");
        assert!(!on(&mut p, "pull_devices") && !on(&mut p, "push_blocks"));
        assert_eq!(p.host().secrets.get("key").map(String::as_str), Some("otherkey"));
        // A plugin that did not declare allow_insecure_tls can't ask for it.
        let mut hello = Plugin::load(include_bytes!(concat!(env!("OUT_DIR"), "/plugins/ntfy.wasm"))).unwrap();
        hello.bind(Connection::open_in_memory().unwrap(), BTreeSet::new(), false).unwrap();
        hello.host().http_hosts = vec!["*".into()];
        let r = hello.host().handle(HostCall::HttpRaw { url: "https://192.168.1.1/".into(), headers: vec![], body: None, insecure: true, ca_pem: None, connect_to: None });
        assert!(matches!(r, HostReply::Err(e) if e.contains("allow_insecure_tls")));
    }

    #[test]
    fn the_speedtest_plugin_runs_a_demo_test_and_keeps_the_result() {
        use plugin_sdk::{Call, Event, HostCall, HostReply, Reply, SPEED_RANGE, SPEED_RUN, UiTree};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("speedtest") else { return };
        assert_eq!((p.manifest.permissions.as_slice(), p.manifest.http_hosts.as_slice()), (["helper.exe".to_owned()].as_slice(), ["install.speedtest.net".to_owned()].as_slice()));
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::from(["helper.exe".to_owned()]), true).unwrap();
        let schema = p.manifest.schema.clone();
        assert!(matches!(p.host().handle(HostCall::DbExec { sql: schema }), HostReply::Ok(_)));
        let count = |p: &mut crate::plugins::wasm::loader::Plugin| match p.host().handle(HostCall::DbQuery { sql: "SELECT count(*) FROM p_speedtest__results".into() }) {
            HostReply::Ok(j) => j.trim_matches(|c| c == '[' || c == ']').parse::<i64>().unwrap(),
            HostReply::Err(e) => panic!("{e}"),
        };
        let page = |p: &mut crate::plugins::wasm::loader::Plugin| match p.call(&Call::RenderTab { tab: "speedtest".into() }).unwrap() {
            Reply::Ui(UiTree::Speedtest(s)) => s,
            other => panic!("no page: {other:?}"),
        };
        // The first tick works out the schedule and, in Demo mode, makes up a week of history; the program counts as downloaded.
        p.call(&Call::Tick).unwrap();
        assert_eq!(count(&mut p), 21);
        let s = page(&mut p);
        assert!(s.cli_ready && !s.running && s.sql.contains("p_speedtest__results"));
        // Running a test shows live readings, then stores one more result.
        p.call(&Call::Event(Event::Click { id: SPEED_RUN.into() })).unwrap();
        assert!(page(&mut p).running);
        assert_eq!(p.host().tick_ms, Some(100), "the plugin asks for a fast tick while the dial moves");
        let mut saw_live = false;
        for _ in 0..200 {
            p.call(&Call::Tick).unwrap();
            let s = page(&mut p);
            saw_live |= !s.live.is_empty();
            if !s.running {
                break;
            }
        }
        assert!(saw_live && !page(&mut p).running);
        assert_eq!(count(&mut p), 22);
        assert_eq!(p.host().tick_ms, None, "back to the manifest's rhythm");
        assert!(page(&mut p).last_ok > 0);
        // The chosen history range is remembered.
        p.call(&Call::Event(Event::Index { id: SPEED_RANGE.into(), index: 2 })).unwrap();
        assert_eq!(page(&mut p).range, 2);
        // A helper call without the permission is refused by the host.
        let mut denied = load("speedtest").unwrap();
        denied.bind(Connection::open_in_memory().unwrap(), BTreeSet::new(), false).unwrap();
        assert!(matches!(denied.host().handle(HostCall::HelperReady { exe: "speedtest.exe".into(), exe_sha256: String::new() }), HostReply::Err(e) if e.contains("not granted")));
    }

    #[test]
    fn the_thinkbroadband_plugin_charts_demo_data_and_keeps_its_choices() {
        use plugin_sdk::{CHART_LAYOUT, Call, Event, HostCall, HostReply, Reply, UiTree};
        use rusqlite::Connection;
        use std::collections::BTreeSet;
        let Some(mut p) = load("thinkbroadband") else { return };
        assert_eq!(p.manifest.permissions, ["browser.session", "alerts.write"]);
        assert_eq!(p.manifest.http_hosts, ["www.thinkbroadband.com"]);
        assert!(p.manifest.icon.len() > 100, "the site's logo is the plugin's icon");
        let perms = BTreeSet::from(["browser.session".to_owned(), "alerts.write".to_owned()]);
        p.bind(Connection::open_in_memory().unwrap(), perms.clone(), true).unwrap();
        let schema = p.manifest.schema.clone();
        assert!(matches!(p.host().handle(HostCall::DbExec { sql: schema }), HostReply::Ok(_)));
        let chart = |p: &mut crate::plugins::wasm::loader::Plugin| match p.call(&Call::RenderTab { tab: "broadband".into() }).unwrap() {
            Reply::Ui(UiTree::LatencyChart(c)) => c,
            other => panic!("no chart: {other:?}"),
        };
        // Demo mode shows a made-up graph without saving one into the settings, and fills a week of rounds.
        p.call(&Call::Tick).unwrap();
        let c = chart(&mut p);
        assert_eq!(c.lines.iter().map(|l| (l.id, l.name.as_str())).collect::<Vec<_>>(), [(1, "Home line")]);
        assert!(c.sql.contains("p_thinkbroadband__samples") && !c.wants_missing && !c.paused);
        assert!(p.host().config.get("monitors").is_none_or(String::is_empty), "demo data never reaches the saved settings");
        let rows = match p.host().handle(HostCall::DbQuery { sql: "SELECT count(*) FROM p_thinkbroadband__samples".into() }) {
            HostReply::Ok(j) => j.trim_matches(|c| c == '[' || c == ']').parse::<i64>().unwrap(),
            HostReply::Err(e) => panic!("{e}"),
        };
        assert!(rows > 6000, "a week of 100-second rounds");
        p.call(&Call::Event(Event::Index { id: CHART_LAYOUT.into(), index: 2 })).unwrap();
        assert_eq!(chart(&mut p).layout, 2);
        // Choosing graphs: only ones the import found can be ticked, and each choice is kept.
        p.host().config.insert("found".into(), "7\tHome line\n9\tOffice".into());
        p.call(&Call::Event(Event::Bool { id: "mon:9".into(), on: true })).unwrap();
        p.call(&Call::Event(Event::Bool { id: "mon:99".into(), on: true })).unwrap();
        assert_eq!(p.host().config.get("monitors").map(String::as_str), Some("9\tOffice"));
        p.call(&Call::Event(Event::Number { id: "interval_mins".into(), value: 99999.0 })).unwrap();
        assert_eq!(p.host().config.get("interval_mins").map(String::as_str), Some("1440"));
        // The browser and the alert path are guarded by the host.
        let mut live = load("thinkbroadband").unwrap();
        live.bind(Connection::open_in_memory().unwrap(), perms, false).unwrap();
        let mut fetch = |u: &str| live.host().handle(HostCall::BrowserFetch { urls: vec![u.into()] });
        assert!(matches!(fetch("https://evil.example/steal"), HostReply::Err(e) if e.contains("not on the plugin's site")));
        assert!(matches!(fetch("https://www.thinkbroadband.com.evil.example/"), HostReply::Err(_)));
        assert!(matches!(live.host().handle(HostCall::RaiseAlert { kind: "anything-else".into(), who: "x".into(), text: "y".into() }), HostReply::Err(_)));
        let mut denied = load("thinkbroadband").unwrap();
        denied.bind(Connection::open_in_memory().unwrap(), BTreeSet::new(), false).unwrap();
        assert!(matches!(denied.host().handle(HostCall::BrowserSignIn), HostReply::Err(e) if e.contains("not granted")));
        assert!(matches!(denied.host().handle(HostCall::RaiseAlert { kind: "packet-loss".into(), who: "x".into(), text: "y".into() }), HostReply::Err(e) if e.contains("not granted")));
    }

    #[test]
    fn every_built_in_plugin_loads_with_its_own_id() {
        // Empty only when the wasm target isn't installed; then this build ships without them.
        if ALL.iter().all(|(_, b)| b.is_empty()) {
            eprintln!("skipped: the plugins were not built");
            return;
        }
        let ids: Vec<String> = found().into_iter().map(|f| f.manifest.id).collect();
        assert_eq!(ids, ALL.iter().map(|(id, _)| (*id).to_owned()).collect::<Vec<_>>());
    }
}
