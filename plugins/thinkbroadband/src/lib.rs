//! thinkbroadband Broadband Quality Monitor: signs in with the account, downloads each chosen monitor's daily
//! XML, keeps the samples and draws them on its own tab. Packet loss raises an alert, delivered like any other.
//! The site sits behind a Cloudflare browser check, so RustWarden reaches it through a real browser engine
//! (the `browser.session` permission); the sign-in is kept by that browser and this plugin never sees the password.

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, CHART_LAYOUT, CHART_RANGE, CHART_REFRESH, CHART_SIGNIN, Call, ChartLine, Event, Kind, LatencyChart, Manifest, Reply, TabDef, UiTree};
use std::cell::RefCell;

const LOGO: &[u8] = include_bytes!("../assets/thinkbroadband.png");
const HOST: &str = "https://www.thinkbroadband.com";
const BASE: &str = "/my-profile/broadband-quality-monitor";
/// What the browser reports when the saved sign-in no longer works.
const NEED_LOGIN: &str = "Sign in to thinkbroadband again.";
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS p_thinkbroadband__samples (
    monitor INTEGER NOT NULL, ts INTEGER NOT NULL, min REAL NOT NULL, avg REAL NOT NULL, max REAL NOT NULL, loss REAL NOT NULL,
    PRIMARY KEY (monitor, ts)) WITHOUT ROWID;";
const CHART_SQL: &str = "SELECT ts, min, avg, max, loss FROM p_thinkbroadband__samples WHERE monitor = ?1 AND ts >= ?2 ORDER BY ts";
/// How long downloaded samples are kept.
const KEEP_SECS: i64 = 365 * 86_400;
/// A monitor with nothing stored yet is filled with this many days; afterwards the days since its newest sample are
/// fetched again (at least two, at most this many), so a long break leaves no hole.
const FIRST_DAYS: i64 = 7;
/// Demo mode makes up a week of rounds, one every 100 seconds, for one monitor.
const DEMO_ID: u32 = 1;

struct Tbb;

/// One poll result: latency in milliseconds, packet loss in percent.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Sample {
    ts: i64,
    min: f32,
    avg: f32,
    max: f32,
    loss: f32,
}

#[derive(Clone, Debug, PartialEq)]
struct Monitor {
    id: u32,
    name: String,
}

#[derive(Default)]
struct St {
    demo: Option<bool>,
    needs_login: bool,
    refreshing: bool,
    /// When the next download is due; `None` until the first tick works it out.
    next_at: Option<i64>,
}

thread_local! {
    static ST: RefCell<St> = RefCell::new(St::default());
}

fn with<T>(f: impl FnOnce(&mut St) -> T) -> T {
    ST.with(|s| f(&mut s.borrow_mut()))
}

fn is_demo() -> bool {
    with(|s| *s.demo.get_or_insert_with(guest::is_demo))
}

fn num(key: &str) -> i64 {
    guest::config_get(key).parse().unwrap_or(0)
}

fn interval_mins() -> i64 {
    let v = guest::config_get("interval_mins");
    if v.is_empty() { 10 } else { v.parse().unwrap_or(10).clamp(1, 1440) }
}

fn alert_pct() -> f32 {
    let v = guest::config_get("alert_pct");
    if v.is_empty() { 1.0 } else { v.parse().unwrap_or(1.0f32).clamp(0.0, 100.0) }
}

/// One line per monitor: `id<TAB>name`.
fn parse_monitors(text: &str) -> Vec<Monitor> {
    text.lines()
        .filter_map(|l| {
            let (id, name) = l.split_once('\t')?;
            Some(Monitor { id: id.parse().ok()?, name: name.to_owned() })
        })
        .collect()
}

fn format_monitors(list: &[Monitor]) -> String {
    list.iter().map(|m| format!("{}\t{}", m.id, m.name)).collect::<Vec<_>>().join("\n")
}

/// The chosen graphs; in Demo mode, a made-up one when none was chosen (never saved, so it can't leak into Live mode).
fn monitors() -> Vec<Monitor> {
    let list = parse_monitors(&guest::config_get("monitors"));
    if list.is_empty() && is_demo() { vec![Monitor { id: DEMO_ID, name: "Home line".into() }] } else { list }
}

fn scalar(json: &str) -> Option<i64> {
    json.trim().trim_start_matches('[').trim_end_matches(']').parse().ok()
}

fn latest(id: u32) -> Option<i64> {
    guest::db_query(&format!("SELECT max(ts) FROM p_thinkbroadband__samples WHERE monitor = {id}")).ok().and_then(|j| scalar(&j))
}

// ---- reading the site ----

/// The value of ` name="..."` inside one tag.
fn attr<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let start = text.find(&key)? + key.len();
    Some(&text[start..start + text[start..].find('"')?])
}

fn day_url(id: u32, day: &str) -> String {
    format!("{HOST}{BASE}/download-xml/{id}/{day}")
}

/// The site backslash-escapes quotes in names (`Orbi\'s`); drop those backslashes.
fn unescape(name: &str) -> String {
    let mut out = String::new();
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        out.push(if c == '\\' { chars.next().unwrap_or(c) } else { c });
    }
    out
}

/// `<graph name=..>` then one `<record timestamp sent-polls lost-polls min/ave/max-latency-ns/>` per poll round.
fn parse_xml(text: &str) -> (String, Vec<Sample>) {
    let name = text.split("<graph").nth(1).and_then(|t| attr(t.split('>').next()?, "name")).unwrap_or("").to_owned();
    let name = unescape(&name);
    let samples = text
        .split("<record")
        .skip(1)
        .filter_map(|r| {
            let r = r.split("/>").next()?;
            let num = |k| attr(r, k)?.parse::<f64>().ok();
            let sent = num("sent-polls")?;
            let ms = |k| Some((num(k)? / 1e6) as f32);
            Some(Sample {
                ts: parse_iso(attr(r, "timestamp")?)?,
                min: ms("min-latency-ns")?,
                avg: ms("ave-latency-ns")?,
                max: ms("max-latency-ns")?,
                loss: if sent > 0.0 { (num("lost-polls").unwrap_or(0.0) / sent * 100.0) as f32 } else { 0.0 },
            })
        })
        .collect();
    (name, samples)
}

/// Days since 1970-01-01 of a civil date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// "2026-10-28T00:01:40Z" to unix seconds.
fn parse_iso(s: &str) -> Option<i64> {
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let days = days_from_civil(n(0..4)?, n(5..7)? as u32, n(8..10)? as u32);
    Some(days * 86_400 + n(11..13)? * 3600 + n(14..16)? * 60 + n(17..19)?)
}

/// UTC `YYYY-MM-DD` of a unix time.
fn date(ts: i64) -> String {
    let (y, m, d) = civil_from_days(ts.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// The monitors on the account, named from today's XML. `Err(NEED_LOGIN)` when signed out.
fn list_monitors() -> Result<Vec<Monitor>, String> {
    let page = guest::browser_fetch(&[format!("{HOST}{BASE}")])?.into_iter().next().map(|p| p.1).unwrap_or_default();
    let mut ids: Vec<u32> = Vec::new();
    for part in page.split("broadband-quality-monitor/view/").skip(1) {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(id) = digits.parse()
            && !ids.contains(&id)
        {
            ids.push(id);
        }
    }
    let today = date(guest::now());
    let xml = guest::browser_fetch(&ids.iter().map(|id| day_url(*id, &today)).collect::<Vec<_>>())?;
    Ok(ids
        .into_iter()
        .zip(xml)
        .map(|(id, (_, body))| {
            let name = parse_xml(&body).0;
            Monitor { id, name: if name.is_empty() { format!("Monitor {id}") } else { name } }
        })
        .collect())
}

/// Downloads UTC days (`YYYY-MM-DD`) of monitors in one browser run: the result of each request, in order.
/// Each day stands alone, so a day that isn't published yet (just after midnight) doesn't lose the others.
fn fetch_days(requests: &[(u32, String)]) -> Result<Vec<Result<Vec<Sample>, String>>, String> {
    // A few days at a time, parsed as they come: a week of every monitor in one reply would not fit the plugin's memory.
    let mut out = Vec::new();
    for chunk in requests.chunks(6) {
        let answers = guest::browser_fetch(&chunk.iter().map(|(id, day)| day_url(*id, day)).collect::<Vec<_>>())?;
        out.extend(answers.into_iter().zip(chunk).map(|((code, body), (id, day))| {
            if code == 200 && body.trim_start().starts_with("<?xml") { Ok(parse_xml(&body).1) } else { Err(format!("thinkbroadband answered HTTP {code} for monitor {id} on {day}.")) }
        }));
    }
    Ok(out)
}

// ---- storing ----

fn store(id: u32, samples: &[Sample]) -> Result<(), String> {
    for chunk in samples.chunks(2000) {
        let body: String = chunk
            .iter()
            .map(|s| format!("INSERT OR REPLACE INTO p_thinkbroadband__samples (monitor, ts, min, avg, max, loss) VALUES ({id}, {}, {}, {}, {}, {});", s.ts, s.min, s.avg, s.max, s.loss))
            .collect();
        if let Err(e) = guest::db_exec(&format!("BEGIN; {body} COMMIT;")) {
            let _ = guest::db_exec("ROLLBACK;");
            return Err(e);
        }
    }
    Ok(())
}

// ---- polling ----

/// One alert per monitor and download, for the worst new sample: its text, or `None` when none reached `pct`.
fn loss_alert(pct: f32, fresh: &[Sample]) -> Option<String> {
    let min = pct.max(f32::EPSILON);
    let worst = fresh.iter().filter(|s| s.loss >= min).max_by(|a, b| a.loss.total_cmp(&b.loss))?;
    let n = fresh.iter().filter(|s| s.loss >= min).count();
    Some(format!("lost up to {:.0}% of packets ({n} intervals of 100 seconds)", worst.loss))
}

/// How old a sample may be and still raise an alert. A download after a gap (RustWarden was closed, the sign-in had lapsed)
/// brings in samples from hours ago: they are stored for the graph, but an alert about them would be old news.
const ALERT_MAX_AGE_SECS: i64 = 15 * 60;

/// The samples worth an alert: newer than the last one seen, and recent.
fn news(all: Vec<Sample>, last: i64, now: i64) -> Vec<Sample> {
    all.into_iter().filter(|s| s.ts > last && s.ts >= now - ALERT_MAX_AGE_SECS).collect()
}

fn poll() -> Result<(), String> {
    let now = guest::now();
    let list = monitors();
    // One browser run for every monitor and day.
    let mut requests = Vec::new();
    for m in &list {
        let days = latest(m.id).map_or(FIRST_DAYS, |ts| ((now - ts) / 86_400 + 2).clamp(2, FIRST_DAYS));
        requests.extend((0..days).rev().map(|back| (m.id, date(now - back * 86_400))));
    }
    let mut answers = fetch_days(&requests)?.into_iter();
    for m in &list {
        let mut all = Vec::new();
        let mut failed = None;
        for _ in requests.iter().filter(|r| r.0 == m.id) {
            match answers.next() {
                Some(Ok(s)) => all.extend(s),
                Some(Err(e)) => failed = Some(e),
                None => {}
            }
        }
        // A missing day is fine as long as another one answered.
        if all.is_empty()
            && let Some(e) = failed
        {
            return Err(e);
        }
        store(m.id, &all).map_err(|e| format!("Can't store the samples: {e}"))?;
        let _ = guest::db_exec(&format!("DELETE FROM p_thinkbroadband__samples WHERE ts < {}", guest::now() - KEEP_SECS));
        let key = format!("alert_{}", m.id);
        let last = guest::config_get(&key).parse::<i64>().ok();
        let Some(newest) = all.iter().map(|s| s.ts).max() else { continue };
        // The first download is history, not news.
        if let Some(last) = last {
            let fresh = news(all, last, guest::now());
            if let Some(text) = loss_alert(alert_pct(), &fresh) {
                guest::raise_alert("packet-loss", &m.name, &text);
            }
        }
        guest::config_set(&key, &newest.max(last.unwrap_or(0)).to_string());
    }
    Ok(())
}

/// Downloads now, and keeps what happened for the pages.
fn poll_now() {
    let now = guest::now();
    with(|s| {
        s.refreshing = true;
        s.next_at = Some(now + interval_mins() * 60);
    });
    guest::config_set("attempt", &now.to_string());
    match poll() {
        Ok(()) => {
            guest::config_set("synced", &guest::now().to_string());
            guest::config_set("status", "");
            with(|s| s.needs_login = false);
        }
        Err(e) if e == NEED_LOGIN => {
            let first = !with(|s| s.needs_login);
            with(|s| s.needs_login = true);
            guest::config_set("status", "ThinkBroadband Quality Monitor needs you to sign in again.");
            if first {
                guest::notify_in_app("ThinkBroadband Quality Monitor needs you to sign in again (Network > ThinkBroadband Quality Monitor).");
            }
        }
        Err(e) => guest::config_set("status", &format!("{e} Trying again in {} minutes.", interval_mins())),
    }
    with(|s| s.refreshing = false);
}

/// "Sync now": forget a sign-in failure and download straight away.
fn sync_now() {
    with(|s| s.needs_login = false);
    poll_now();
}

fn sign_in_then_sync() {
    if guest::browser_sign_in().is_ok() {
        sync_now();
    }
}

/// A day with nothing stored is fetched from thinkbroadband for these monitors.
fn backfill(ids: &[u32], from: i64, to: i64) {
    with(|s| s.refreshing = true);
    // thinkbroadband's days are UTC, so a local day can touch two of them.
    let days: std::collections::BTreeSet<String> = [from, to - 1].iter().map(|t| date(*t)).collect();
    let requests: Vec<(u32, String)> = ids.iter().flat_map(|id| days.iter().map(move |d| (*id, d.clone()))).collect();
    if let Ok(answers) = fetch_days(&requests) {
        for id in ids {
            let all: Vec<Sample> = requests.iter().zip(&answers).filter(|(r, _)| r.0 == *id).filter_map(|(_, a)| a.as_ref().ok()).flatten().copied().collect();
            let _ = store(*id, &all);
        }
    }
    with(|s| s.refreshing = false);
}

// ---- demo ----

/// A made-up round: a steady latency with a slow wave, a spike now and then and the odd lost poll.
fn demo_sample(ts: i64) -> Sample {
    let k = ts / 100;
    let x = ts as f32 / 3600.0;
    let avg = 14.0 + (x * 0.9).sin() * 1.5 + if k % 41 == 0 { 9.0 } else { 0.0 };
    Sample { ts, min: avg * 0.6, avg, max: avg * 1.6 + if k % 41 == 0 { 12.0 } else { 0.0 }, loss: if k % 67 == 0 { 4.0 } else { 0.0 } }
}

fn demo_fill(now: i64) {
    let from = latest(DEMO_ID).map_or(now - 7 * 86_400, |l| l + 100).max(now - 7 * 86_400).div_euclid(100) * 100;
    let rows: Vec<Sample> = (from..=now).step_by(100).filter(|ts| latest(DEMO_ID).is_none_or(|l| *ts > l)).map(demo_sample).collect();
    let _ = store(DEMO_ID, &rows);
}

fn tick() {
    if monitors().is_empty() {
        return;
    }
    let now = guest::now();
    if is_demo() {
        demo_fill(now);
        return;
    }
    if with(|s| s.needs_login) {
        return;
    }
    let every = interval_mins() * 60;
    let due = match with(|s| s.next_at) {
        Some(at) => at,
        None => {
            // First pass after launch: keep to the last attempt's schedule so restarts don't re-download.
            let stored = monitors().iter().all(|m| latest(m.id).is_some());
            let at = if stored { num("attempt") + every } else { 0 };
            with(|s| s.next_at = Some(at));
            at
        }
    };
    if now >= due {
        poll_now();
    }
}

// ---- the pages ----

fn chart() -> UiTree {
    let (needs_login, refreshing) = with(|s| (s.needs_login, s.refreshing));
    let demo = is_demo();
    UiTree::LatencyChart(Box::new(LatencyChart {
        lines: monitors().iter().map(|m| ChartLine { id: m.id, name: unescape(&m.name) }).collect(),
        sql: CHART_SQL.into(),
        layout: num("layout").clamp(0, 2) as usize,
        range: if guest::config_get("range").is_empty() { 1 } else { num("range").clamp(0, 2) as usize },
        last_ok: if demo { guest::now() } else { num("synced") },
        refresh_hint: "Download the latest samples now".into(),
        text_not_live: "ThinkBroadband Quality Monitor data is downloaded in Live mode.".into(),
        text_no_lines: "No graphs chosen. Import them in Settings > Plugins > ThinkBroadband Quality Monitor > Settings.".into(),
        text_no_data_day: "ThinkBroadband has no data for this day.".into(),
        text_no_data: "No samples yet. Press Refresh to download them.".into(),
        refreshing,
        paused: needs_login,
        signin_text: if needs_login { "Your ThinkBroadband session has expired. Sign in again to keep these graphs up to date.".into() } else { String::new() },
        signin_button: if needs_login { "Sign in".into() } else { String::new() },
        wants_missing: !demo,
        ..LatencyChart::default()
    }))
}

fn settings() -> UiTree {
    let chosen = parse_monitors(&guest::config_get("monitors"));
    let mut rows = vec![
        UiTree::Label("Signing in opens a browser window (thinkbroadband checks visitors with Cloudflare), so RustWarden never sees your password.".into()),
        UiTree::Link {
            text: "Data from the Broadband Quality Monitor by thinkbroadband.com, downloaded from your own account.".into(),
            url: "https://www.thinkbroadband.com/broadband/monitoring/quality".into(),
        },
    ];
    let (needs_login, refreshing) = with(|s| (s.needs_login, s.refreshing));
    let _ = (needs_login, refreshing);
    rows.push(UiTree::Button { id: "import".into(), text: "Sign in and import graphs".into() });
    for key in ["msg", "info"] {
        let m = guest::config_get(key);
        if !m.is_empty() {
            rows.push(UiTree::Label(m));
        }
    }
    // Graphs found on the account, plus any already chosen that the last import didn't list.
    let mut list = parse_monitors(&guest::config_get("found"));
    for m in &chosen {
        if !list.iter().any(|l| l.id == m.id) {
            list.push(m.clone());
        }
    }
    rows.push(UiTree::Label(if list.is_empty() { "Import to choose which reliability graphs to include.".into() } else { "Graphs to include:".into() }));
    for m in &list {
        rows.push(UiTree::Switch { id: format!("mon:{}", m.id), text: format!("{} ({})", m.name, m.id), on: chosen.iter().any(|c| c.id == m.id) });
    }
    if chosen.is_empty() {
        rows.push(UiTree::Label("Tick at least one graph; the ThinkBroadband Quality Monitor tab appears once one is chosen.".into()));
    }
    rows.push(UiTree::Row(vec![UiTree::Label("Alert at packet loss of (%)".into()), UiTree::Number { id: "alert_pct".into(), value: f64::from(alert_pct()), min: 0.0, max: 100.0 }]));
    rows.push(UiTree::Row(vec![UiTree::Label("Download every (minutes)".into()), UiTree::Number { id: "interval_mins".into(), value: interval_mins() as f64, min: 1.0, max: 1440.0 }]));
    rows.push(UiTree::Separator);
    if guest::config_get("confirm_reset") == "1" {
        rows.push(UiTree::Label("Sign out, forget the graphs and delete the downloaded samples?".into()));
        rows.push(UiTree::Row(vec![UiTree::Button { id: "reset_yes".into(), text: "Yes, reset".into() }, UiTree::Button { id: "reset_no".into(), text: "Cancel".into() }]));
    } else {
        rows.push(UiTree::Row(vec![UiTree::Button { id: "sync".into(), text: "Sync now".into() }, UiTree::Button { id: "reset".into(), text: "Sign out and reset data".into() }]));
    }
    let status = guest::config_get("status");
    if !status.is_empty() {
        rows.push(UiTree::Label(status));
    }
    UiTree::Column(rows)
}

/// Opens the sign-in window if the saved session is gone, then lists the graphs on the account.
fn import() {
    let result = match list_monitors() {
        Ok(l) => Ok((l, true)),
        Err(e) if e == NEED_LOGIN => guest::browser_sign_in().and_then(|()| list_monitors()).map(|l| (l, false)),
        Err(e) => Err(e),
    };
    match result {
        Ok((list, was_signed_in)) => {
            let how = if was_signed_in { "You're already signed in, nothing to do." } else { "Signed in." };
            guest::config_set("info", &format!("{how} Found {} graph(s); tick the ones to include.", list.len()));
            guest::config_set("found", &format_monitors(&list));
            guest::config_set("msg", "");
            with(|s| s.needs_login = false);
        }
        Err(e) => {
            guest::config_set("msg", &e);
            guest::config_set("info", "");
        }
    }
}

fn reset() {
    guest::config_set("confirm_reset", "0");
    guest::config_set("monitors", "");
    guest::config_set("found", "");
    with(|s| s.needs_login = false);
    let result = guest::browser_sign_out().and_then(|()| guest::db_exec("DELETE FROM p_thinkbroadband__samples"));
    match result {
        Ok(()) => guest::config_set("info", "Signed out and data deleted. Import again to reconnect."),
        Err(e) => guest::config_set("msg", &format!("Reset incomplete: {e}")),
    }
}

fn event(e: Event) {
    match e {
        Event::Click { id } if id == CHART_REFRESH || id == "sync" => sync_now(),
        Event::Click { id } if id == CHART_SIGNIN => sign_in_then_sync(),
        Event::Click { id } if id == "import" => import(),
        Event::Click { id } if id == "reset" => guest::config_set("confirm_reset", "1"),
        Event::Click { id } if id == "reset_no" => guest::config_set("confirm_reset", "0"),
        Event::Click { id } if id == "reset_yes" => reset(),
        Event::Index { id, index } if id == CHART_LAYOUT => guest::config_set("layout", &index.min(2).to_string()),
        Event::Index { id, index } if id == CHART_RANGE => guest::config_set("range", &index.min(2).to_string()),
        Event::ChartMissing { ids, from, to } => backfill(&ids, from, to),
        Event::Bool { id, on } if id.starts_with("mon:") => {
            let Ok(n) = id["mon:".len()..].parse::<u32>() else { return };
            let mut chosen = parse_monitors(&guest::config_get("monitors"));
            chosen.retain(|m| m.id != n);
            if on && let Some(m) = parse_monitors(&guest::config_get("found")).into_iter().find(|m| m.id == n) {
                chosen.push(m);
            }
            guest::config_set("monitors", &format_monitors(&chosen));
            // A new set of graphs is downloaded at the next tick.
            with(|s| s.next_at = Some(0));
        }
        Event::Number { id, value } if id == "alert_pct" => guest::config_set("alert_pct", &format!("{}", value.clamp(0.0, 100.0))),
        Event::Number { id, value } if id == "interval_mins" => guest::config_set("interval_mins", &(value.clamp(1.0, 1440.0) as i64).to_string()),
        _ => {}
    }
}

impl Guest for Tbb {
    fn manifest() -> Manifest {
        Manifest {
            id: "thinkbroadband".into(),
            name: "ThinkBroadband Quality Monitor".into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            icon: LOGO.to_vec(),
            tabs: vec![TabDef { id: "broadband".into(), title: "ThinkBroadband Quality Monitor".into() }],
            settings_page: true,
            http_hosts: vec!["www.thinkbroadband.com".into()],
            permissions: vec!["browser.session".into(), "alerts.write".into()],
            tick_secs: 5,
            schema: SCHEMA.into(),
            hidden: true,
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
                tick();
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Tbb);

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<cqm generated="2026-10-29T00:06:50Z">
  <graph name="LorenteNET" period-start="2026-10-28T00:00:00Z">
    <record timestamp="2026-10-28T00:00:00Z" sent-polls="100" lost-polls="0" rejected-polls="0" min-latency-ns="8261000" ave-latency-ns="14030000" max-latency-ns="20280000" score="1"/>
    <record timestamp="2026-10-28T00:01:40Z" sent-polls="100" lost-polls="4" rejected-polls="0" min-latency-ns="10200000" ave-latency-ns="13740000" max-latency-ns="26660000" score="1"/>
    <record timestamp="2026-10-28T00:03:20Z" sent-polls="100" min-latency-ns="1000000" ave-latency-ns="2000000" max-latency-ns="3000000"/>
  </graph></cqm>"#;

    #[test]
    fn parses_records() {
        let (name, s) = parse_xml(XML);
        assert_eq!(name, "LorenteNET");
        assert_eq!(s.len(), 3); // the last has no lost-polls: none lost
        assert_eq!(s[2].loss, 0.0);
        assert_eq!(s[0].ts, 1_793_145_600); // 2026-10-28T00:00:00Z
        assert_eq!(s[1].ts - s[0].ts, 100);
        assert!((s[0].min - 8.261).abs() < 1e-3 && (s[1].max - 26.66).abs() < 1e-3);
        assert_eq!((s[0].loss, s[1].loss), (0.0, 4.0));
        assert_eq!(date(s[0].ts), "2026-10-28");
        assert_eq!(unescape(r"Orbi\'s at 52A"), "Orbi's at 52A");
    }

    #[test]
    fn civil_dates_round_trip() {
        for (y, m, d) in [(1970, 1, 1), (2000, 2, 29), (2026, 10, 28), (2024, 12, 31), (1999, 3, 1)] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(parse_iso("2026-10-28T00:01:40Z"), Some(1_793_145_700));
        assert_eq!(parse_iso("garbage"), None);
    }

    #[test]
    fn one_alert_names_the_worst_new_sample() {
        let s = |loss| Sample { loss, ..Default::default() };
        assert_eq!(loss_alert(1.0, &[s(0.0), s(4.0), s(2.0)]).as_deref(), Some("lost up to 4% of packets (2 intervals of 100 seconds)"));
        assert_eq!(loss_alert(5.0, &[s(4.0)]), None);
        // Samples brought in after a gap are stored but never alerted on: only new ones from the last 15 minutes count.
        let at = |ts, loss| Sample { ts, loss, ..Default::default() };
        let now = 100_000;
        let all = vec![at(now - 11_000, 84.0), at(now - 500, 40.0), at(now - 2_000, 30.0), at(now - 100, 10.0)];
        let fresh = news(all, now - 1_000, now);
        assert_eq!(fresh.iter().map(|s| s.loss).collect::<Vec<_>>(), [40.0, 10.0], "old and already-seen samples are left out");
        assert_eq!(loss_alert(5.0, &fresh).as_deref(), Some("lost up to 40% of packets (2 intervals of 100 seconds)"));
        assert!(news(vec![at(now - 11_000, 84.0)], 0, now).is_empty());
        // At a level of 0 only real loss counts, never a clean sample.
        assert_eq!(loss_alert(0.0, &[s(0.0)]), None);
        assert!(loss_alert(0.0, &[s(0.5)]).is_some());
    }

    #[test]
    fn monitors_round_trip_through_their_saved_lines() {
        let list = vec![Monitor { id: 7, name: "Home line".into() }, Monitor { id: 12, name: "Office".into() }];
        assert_eq!(parse_monitors(&format_monitors(&list)), list);
        assert!(parse_monitors("no tab here\nx\tnot a number").is_empty());
    }

    #[test]
    fn demo_rounds_are_sane() {
        for k in 0..400 {
            let s = demo_sample(1_000_000 + k * 100);
            assert!(s.min > 0.0 && s.min <= s.avg && s.avg <= s.max && (0.0..=100.0).contains(&s.loss));
        }
    }
}
