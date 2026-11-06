//! Ping Monitor: pings the hosts you add every 30 seconds and charts latency and loss on its tab,
//! with the same charts as Broadband Quality. History is only what this plugin has stored itself.

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, CHART_DIALOG_CLOSE, CHART_LAYOUT, CHART_RANGE, CHART_REFRESH, Call, ChartLine, Event, Kind, LatencyChart, Manifest, Reply, TabDef, UiTree};

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS p_ping__samples (
    host INTEGER NOT NULL, ts INTEGER NOT NULL, min REAL NOT NULL, avg REAL NOT NULL, max REAL NOT NULL, loss REAL NOT NULL,
    PRIMARY KEY (host, ts)) WITHOUT ROWID;";
const CHART_SQL: &str = "SELECT ts, min, avg, max, loss FROM p_ping__samples WHERE host = ?1 AND ts >= ?2 ORDER BY ts";
const PINGS: u32 = 3;
const KEEP_SECS: i64 = 30 * 86_400;
/// Demo mode keeps a week of made-up rounds, one a minute.
const DEMO_SPAN: i64 = 7 * 86_400;

struct Ping;

struct Host {
    id: u32,
    address: String,
    name: String,
}

impl Host {
    fn label(&self) -> &str {
        if self.name.is_empty() { &self.address } else { &self.name }
    }
}

/// One line per host: `id<TAB>address<TAB>name`.
fn hosts() -> Vec<Host> {
    guest::config_get("hosts")
        .lines()
        .filter_map(|l| {
            let mut p = l.splitn(3, '\t');
            Some(Host { id: p.next()?.parse().ok()?, address: p.next()?.to_owned(), name: p.next().unwrap_or("").to_owned() })
        })
        .collect()
}

fn save_hosts(hosts: &[Host]) {
    guest::config_set("hosts", &hosts.iter().map(|h| format!("{}\t{}\t{}", h.id, h.address, h.name)).collect::<Vec<_>>().join("\n"));
}

/// Single-line text without control characters (a tab would split the saved line).
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect::<String>().trim().to_owned()
}

fn num(key: &str) -> usize {
    guest::config_get(key).parse().unwrap_or(0)
}

/// The first value of a one-cell query result such as `[[123]]`.
fn scalar(json: &str) -> Option<i64> {
    json.trim().trim_start_matches('[').trim_end_matches(']').parse().ok()
}

fn insert_rows(rows: &[(u32, i64, f32, f32, f32, f32)]) {
    for chunk in rows.chunks(2000) {
        let body: String = chunk
            .iter()
            .map(|(h, ts, min, avg, max, loss)| format!("INSERT OR REPLACE INTO p_ping__samples (host, ts, min, avg, max, loss) VALUES ({h}, {ts}, {min}, {avg}, {max}, {loss});"))
            .collect();
        if let Err(e) = guest::db_exec(&format!("BEGIN; {body} COMMIT;")) {
            guest::log(&format!("couldn't store ping results: {e}"));
            let _ = guest::db_exec("ROLLBACK;");
            return;
        }
    }
}

/// One made-up round: a steady latency with a gentle wave, a spike now and then and the odd lost echo.
fn demo_row(id: u32, ts: i64) -> (u32, i64, f32, f32, f32, f32) {
    let k = ts / 60;
    let base = 0.6 + (id % 5) as f32 * 0.9;
    let x = ts as f32 / 900.0 + id as f32 * 1.7;
    let mut avg = base * (1.0 + x.sin() * 0.25 + (x * 2.3).sin() * 0.1);
    if k % 37 == 0 {
        avg *= 3.0;
    }
    (id, ts, avg * 0.8, avg, avg * 1.5, if k % 53 == 0 { 33.3 } else { 0.0 })
}

/// One round for every host now, stored; True when it worked.
fn round() {
    let hosts = hosts();
    if hosts.is_empty() {
        return;
    }
    let now = guest::now();
    if guest::is_demo() {
        let mut rows = Vec::new();
        for h in &hosts {
            let last = guest::db_query(&format!("SELECT max(ts) FROM p_ping__samples WHERE host = {}", h.id)).ok().and_then(|j| scalar(&j));
            let from = last.map_or(now - DEMO_SPAN, |l| l + 60).max(now - DEMO_SPAN).div_euclid(60) * 60;
            rows.extend((from..=now).step_by(60).filter(|ts| *ts > last.unwrap_or(0)).map(|ts| demo_row(h.id, ts)));
        }
        insert_rows(&rows);
    } else {
        let addrs: Vec<String> = hosts.iter().map(|h| h.address.clone()).collect();
        match guest::ping_round(&addrs, PINGS) {
            Ok(results) => insert_rows(&hosts.iter().zip(results).map(|(h, r)| (h.id, now, r.min, r.avg, r.max, r.loss)).collect::<Vec<_>>()),
            Err(e) => {
                guest::log(&format!("ping failed: {e}"));
                return;
            }
        }
    }
    let _ = guest::db_exec(&format!("DELETE FROM p_ping__samples WHERE ts < {}", now - KEEP_SECS));
    guest::config_set("last_ok", &now.to_string());
}

fn chart() -> UiTree {
    let (dialog_title, dialog) = match guest::config_get("dialog").as_str() {
        "add" => ("Add host", Some(Box::new(add_form()))),
        "manage" => ("Manage hosts", Some(Box::new(manage_form()))),
        _ => ("", None),
    };
    UiTree::LatencyChart(Box::new(LatencyChart {
        lines: hosts().iter().map(|h| ChartLine { id: h.id, name: h.label().to_owned() }).collect(),
        sql: CHART_SQL.into(),
        layout: num("layout").min(2),
        range: if guest::config_get("range").is_empty() { 1 } else { num("range").min(2) },
        last_ok: guest::config_get("last_ok").parse().unwrap_or(0),
        refresh_hint: "Ping the hosts now".into(),
        text_not_live: "Ping data is collected in Live mode.".into(),
        text_no_lines: "No hosts yet. Press Add host to start pinging one.".into(),
        text_no_data_day: "No pings were recorded on this day.".into(),
        text_no_data: "No pings yet; the first result appears within a few seconds.".into(),
        tools: vec![UiTree::Button { id: "add_host".into(), text: "+ Add host".into() }, UiTree::Button { id: "manage_hosts".into(), text: "Manage hosts".into() }],
        dialog_title: dialog_title.into(),
        dialog,
        ..LatencyChart::default()
    }))
}

/// The address and label fields with Add and Cancel (shared by the Add host window and the settings page).
fn add_form() -> UiTree {
    UiTree::Column(vec![
        UiTree::Label("Host name or IP address".into()),
        UiTree::TextField { id: "new_addr".into(), value: guest::config_get("new_addr") },
        UiTree::Label("Label (optional)".into()),
        UiTree::TextField { id: "new_name".into(), value: guest::config_get("new_name") },
        UiTree::Row(vec![UiTree::Button { id: "add".into(), text: "Add".into() }, UiTree::Button { id: "cancel".into(), text: "Cancel".into() }]),
    ])
}

fn host_rows() -> Vec<UiTree> {
    hosts()
        .into_iter()
        .map(|h| {
            UiTree::Row(vec![
                UiTree::TextField { id: format!("addr:{}", h.id), value: h.address.clone() },
                UiTree::TextField { id: format!("name:{}", h.id), value: h.name.clone() },
                UiTree::Button { id: format!("del:{}", h.id), text: "Remove".into() },
            ])
        })
        .collect()
}

fn manage_form() -> UiTree {
    let mut rows = host_rows();
    if rows.is_empty() {
        rows.push(UiTree::Label("No hosts yet.".into()));
    }
    rows.push(UiTree::Button { id: "add_host".into(), text: "Add host".into() });
    UiTree::Column(rows)
}

fn settings() -> UiTree {
    let mut rows = vec![UiTree::Weak("Pinged every 30 seconds with three echoes each. Charts are on the Ping Monitor tab under Network.".into())];
    rows.extend(host_rows());
    rows.push(UiTree::Separator);
    rows.push(UiTree::Label("Add a host (name or IP address, then an optional label)".into()));
    rows.push(UiTree::Row(vec![
        UiTree::TextField { id: "new_addr".into(), value: guest::config_get("new_addr") },
        UiTree::TextField { id: "new_name".into(), value: guest::config_get("new_name") },
        UiTree::Button { id: "add".into(), text: "Add".into() },
    ]));
    UiTree::Column(rows)
}

fn event(e: Event) {
    match e {
        Event::Text { id, value } => {
            let value = clean(&value);
            if let Some(n) = id.strip_prefix("addr:").and_then(|n| n.parse::<u32>().ok()) {
                let mut hs = hosts();
                if let Some(h) = hs.iter_mut().find(|h| h.id == n) {
                    h.address = value;
                }
                save_hosts(&hs);
            } else if let Some(n) = id.strip_prefix("name:").and_then(|n| n.parse::<u32>().ok()) {
                let mut hs = hosts();
                if let Some(h) = hs.iter_mut().find(|h| h.id == n) {
                    h.name = value;
                }
                save_hosts(&hs);
            } else if id == "new_addr" || id == "new_name" {
                guest::config_set(&id, &value);
            }
        }
        Event::Click { id } if id == "add_host" => guest::config_set("dialog", "add"),
        Event::Click { id } if id == "manage_hosts" => guest::config_set("dialog", "manage"),
        Event::Click { id } if id == "cancel" || id == CHART_DIALOG_CLOSE => guest::config_set("dialog", ""),
        Event::Click { id } if id == "add" => {
            let address = clean(&guest::config_get("new_addr"));
            if !address.is_empty() {
                let mut hs = hosts();
                let next = (num("next_id") as u32).max(hs.iter().map(|h| h.id).max().unwrap_or(0)) + 1;
                hs.push(Host { id: next, address, name: clean(&guest::config_get("new_name")) });
                save_hosts(&hs);
                guest::config_set("next_id", &next.to_string());
                guest::config_set("new_addr", "");
                guest::config_set("new_name", "");
                guest::config_set("dialog", "");
            }
        }
        Event::Click { id } if id.starts_with("del:") => {
            if let Ok(n) = id["del:".len()..].parse::<u32>() {
                let hs: Vec<Host> = hosts().into_iter().filter(|h| h.id != n).collect();
                save_hosts(&hs);
                let _ = guest::db_exec(&format!("DELETE FROM p_ping__samples WHERE host = {n}"));
            }
        }
        Event::Click { id } if id == CHART_REFRESH => round(),
        Event::Index { id, index } if id == CHART_LAYOUT => guest::config_set("layout", &index.min(2).to_string()),
        Event::Index { id, index } if id == CHART_RANGE => guest::config_set("range", &index.min(2).to_string()),
        _ => {}
    }
}

impl Guest for Ping {
    fn manifest() -> Manifest {
        Manifest {
            id: "ping".into(),
            name: "Ping Monitor".into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            tabs: vec![TabDef { id: "ping".into(), title: "Ping Monitor".into() }],
            settings_page: true,
            permissions: vec!["ping".into()],
            tick_secs: 30,
            schema: SCHEMA.into(),
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderTab { .. } => Reply::Ui(chart()),
            Call::RenderSettings => Reply::Ui(settings()),
            Call::Event(e) => {
                event(e);
                Reply::Done
            }
            Call::Tick => {
                round();
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Ping);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_one_cell_result_is_read() {
        assert_eq!(scalar("[[123]]"), Some(123));
        assert_eq!(scalar("[[null]]"), None);
        assert_eq!(scalar("[]"), None);
    }

    #[test]
    fn demo_rows_are_sane_and_stable() {
        for id in 1..6 {
            for k in 0..200 {
                let (h, ts, min, avg, max, loss) = demo_row(id, 1_000_000 + k * 60);
                assert_eq!((h, ts), (id, 1_000_000 + k * 60));
                assert!(min > 0.0 && min <= avg && avg <= max && (0.0..=100.0).contains(&loss));
            }
        }
        assert_eq!(demo_row(2, 12_000), demo_row(2, 12_000));
        assert_ne!(demo_row(1, 12_000), demo_row(2, 12_000));
    }

    #[test]
    fn text_is_made_single_line() {
        assert_eq!(clean(" a\tb\nc "), "abc");
    }
}
