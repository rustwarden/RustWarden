//! Speedtest tab (Network > Speedtest). Speedtest.net has no public API, so this drives Ookla's own
//! `speedtest.exe` CLI: RustWarden downloads it when the user asks (the `helper.exe` permission), runs it on
//! request or on a schedule, and this plugin stores each result and shows the figures on its tab.
//! Nothing is contacted until the user downloads the CLI or runs a test.

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Event, Kind, Manifest, Reply, SPEED_INSTALL, SPEED_RANGE, SPEED_RUN, SpeedLive, SpeedPage, SpeedPhase, TabDef, UiTree};
use serde_json::Value;
use std::cell::RefCell;

const URL: &str = "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-win64.zip";
const ZIP_SHA256: &str = "13e3d888b845d301a556419e31f14ab9bff57e3f06089ef2fd3bdc9ba6841efa";
const EXE: &str = "speedtest.exe";
/// `speedtest.exe` inside that zip; lets an elevated run take over a copy downloaded without elevation.
const EXE_SHA256: &str = "c73c4ac2a7cdc48829fe0f9d7ec91ca41c8b434490d4eb3205aad69c7aa3b921";
/// A test normally takes about 30 s; anything longer than this is stuck.
const TEST_TIMEOUT_SECS: u32 = 180;
const KEEP_SECS: i64 = 365 * 86_400;
/// How long a demo speed test takes, and how often its dial moves.
const DEMO_TEST_SECS: f32 = 9.0;
const DEMO_STEP_MS: u32 = 100;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS p_speedtest__results (
    ts INTEGER PRIMARY KEY, ping REAL NOT NULL, jitter REAL NOT NULL, down REAL NOT NULL, up REAL NOT NULL,
    loss REAL NOT NULL, server TEXT NOT NULL, isp TEXT NOT NULL, url TEXT NOT NULL,
    server_ip TEXT NOT NULL DEFAULT '', client_ip TEXT NOT NULL DEFAULT '');";
const PAGE_SQL: &str = "SELECT ts, ping, jitter, down, up, loss, server, isp, url, server_ip, client_ip FROM p_speedtest__results WHERE ts >= ?1 ORDER BY ts";

struct Speedtest;

/// One finished test.
#[derive(Clone, Debug, Default, PartialEq)]
struct SpeedResult {
    ts: i64,
    ping_ms: f32,
    jitter_ms: f32,
    down_mbps: f32,
    up_mbps: f32,
    /// Packet loss in percent; negative when the server didn't report it.
    loss: f32,
    server: String,
    isp: String,
    url: String,
    server_ip: String,
    client_ip: String,
}

/// What the plugin remembers between calls (the module stays loaded, so this lives as long as the plugin runs).
#[derive(Default)]
struct St {
    demo: Option<bool>,
    cli_ready: bool,
    installing: bool,
    running: bool,
    live: Vec<SpeedLive>,
    error: String,
    /// When the next scheduled test is due; 0 until the first tick works it out ("no test at startup").
    next_at: i64,
    started_at: i64,
    demo_frac: f32,
    /// What the running CLI has printed so far.
    seen: Seen,
}

thread_local! {
    static ST: RefCell<St> = RefCell::new(St::default());
}

fn with<T>(f: impl FnOnce(&mut St) -> T) -> T {
    ST.with(|s| f(&mut s.borrow_mut()))
}

fn num(key: &str) -> i64 {
    guest::config_get(key).parse().unwrap_or(0)
}

fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn is_demo() -> bool {
    with(|s| *s.demo.get_or_insert_with(guest::is_demo))
}

// ---- reading the CLI's output ----

/// A live `ping`, `download` or `upload` line of the CLI's jsonl output; None for any other line.
fn progress_of(line: &str) -> Option<SpeedLive> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    let phase = match v["type"].as_str()? {
        "ping" => SpeedPhase::Ping,
        "download" => SpeedPhase::Download,
        "upload" => SpeedPhase::Upload,
        _ => return None,
    };
    let body = &v[v["type"].as_str()?];
    let mbps = if phase == SpeedPhase::Ping { 0.0 } else { body["bandwidth"].as_f64().unwrap_or(0.0) as f32 * 8.0 / 1e6 };
    Some(SpeedLive { phase, mbps, progress: body["progress"].as_f64().unwrap_or(0.0).clamp(0.0, 1.0) as f32 })
}

/// What the CLI has printed that matters: its result line, or the message of its error line.
#[derive(Default)]
struct Seen {
    result: Option<SpeedResult>,
    error: Option<String>,
}

impl Seen {
    fn feed(&mut self, line: &str, now: i64) {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { return };
        if v["type"] == "result" {
            self.result = Some(result_of(&v, now));
        } else if v["level"] == "error" {
            self.error = v["message"].as_str().map(str::to_owned);
        }
    }
}

fn result_of(v: &Value, now: i64) -> SpeedResult {
    let f = |x: &Value| x.as_f64().unwrap_or(0.0) as f32;
    // The CLI reports bandwidth in bytes per second.
    let mbps = |x: &Value| f(x) * 8.0 / 1e6;
    let s = |x: &Value| x.as_str().unwrap_or_default().to_owned();
    let server = [s(&v["server"]["name"]), s(&v["server"]["location"])].into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join(", ");
    SpeedResult {
        ts: now,
        ping_ms: f(&v["ping"]["latency"]),
        jitter_ms: f(&v["ping"]["jitter"]),
        down_mbps: mbps(&v["download"]["bandwidth"]),
        up_mbps: mbps(&v["upload"]["bandwidth"]),
        loss: v["packetLoss"].as_f64().map_or(-1.0, |x| x as f32),
        server,
        isp: s(&v["isp"]),
        url: s(&v["result"]["url"]),
        server_ip: s(&v["server"]["ip"]),
        client_ip: s(&v["interface"]["externalIp"]),
    }
}

// ---- storing ----

fn store(r: &SpeedResult) -> Result<(), String> {
    guest::db_exec(&format!(
        "INSERT OR REPLACE INTO p_speedtest__results (ts, ping, jitter, down, up, loss, server, isp, url, server_ip, client_ip) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});DELETE FROM p_speedtest__results WHERE ts < {};",
        r.ts,
        r.ping_ms,
        r.jitter_ms,
        r.down_mbps,
        r.up_mbps,
        r.loss,
        q(&r.server),
        q(&r.isp),
        q(&r.url),
        q(&r.server_ip),
        q(&r.client_ip),
        r.ts - KEEP_SECS
    ))?;
    guest::config_set("last_ok", &r.ts.to_string());
    Ok(())
}

// ---- demo ----

/// One made-up result; `k` varies the figures from test to test.
fn demo_result(ts: i64, k: f32) -> SpeedResult {
    SpeedResult {
        ts,
        ping_ms: 11.0 + (k * 1.7).sin().abs() * 6.0,
        jitter_ms: 0.8 + (k * 2.3).cos().abs(),
        down_mbps: 880.0 + (k * 0.9).sin() * 40.0,
        up_mbps: 92.0 + (k * 1.3).cos() * 6.0,
        loss: 0.0,
        server: "Demo Net, London".into(),
        isp: "Demo ISP".into(),
        url: String::new(),
        server_ip: "203.0.113.9".into(),
        client_ip: "198.51.100.7".into(),
    }
}

/// The readings a demo test would have produced `frac` (0 to 1) of the way through: a ping, then a download
/// that ramps up to about 880 Mbps, then an upload that ramps up to about 92.
fn demo_live(frac: f32) -> Vec<SpeedLive> {
    let mut out = Vec::new();
    let mut at = 0.0f32;
    while at <= frac {
        let (phase, top, p) = match at {
            a if a < 0.1 => (SpeedPhase::Ping, 0.0, a / 0.1),
            a if a < 0.55 => (SpeedPhase::Download, 880.0, (a - 0.1) / 0.45),
            a => (SpeedPhase::Upload, 92.0, (a - 0.55) / 0.45),
        };
        let wobble = 1.0 + ((at * 90.0).sin() * 0.05);
        out.push(SpeedLive { phase, mbps: top * (1.0 - (-6.0 * p).exp()) * wobble, progress: p.min(1.0) });
        at += 0.01;
    }
    out
}

/// A week of made-up tests, a few a day, the first time Demo mode starts the plugin.
fn demo_history(now: i64) {
    let empty = guest::db_query("SELECT count(*) FROM p_speedtest__results").ok().is_some_and(|j| j.contains("[[0]]"));
    if empty {
        for i in 0..21 {
            let _ = store(&demo_result(now - (21 - i) * 8 * 3600, i as f32));
        }
    }
}

// ---- running a test ----

fn start_test() {
    if with(|s| s.running || s.installing) {
        return;
    }
    if !with(|s| s.cli_ready) {
        with(|s| s.error = "Download speedtest-cli first.".into());
        return;
    }
    let now = guest::now();
    with(|s| {
        s.running = true;
        s.live.clear();
        s.started_at = now;
        s.seen = Seen::default();
        s.demo_frac = 0.0;
    });
    if is_demo() {
        guest::set_tick(DEMO_STEP_MS);
        return;
    }
    // jsonl prints a line per reading while the test runs; json would only print the result at the end.
    let mut args: Vec<String> = ["--accept-license", "--accept-gdpr", "-f", "jsonl"].iter().map(|a| (*a).to_owned()).collect();
    let server = num("server_id");
    if server > 0 {
        args.push("-s".into());
        args.push(server.to_string());
    }
    if let Err(e) = guest::helper_start(EXE, &args, TEST_TIMEOUT_SECS) {
        with(|s| {
            s.running = false;
            s.error = e;
        });
    }
}

/// A test finished (or could not): keep its result, or say why not.
fn finish(outcome: Result<String, String>) {
    guest::set_tick(0);
    let (seen, started) = with(|s| {
        s.running = false;
        s.live.clear();
        (std::mem::take(&mut s.seen), s.started_at)
    });
    let _ = started;
    let message = match outcome {
        Err(e) => e,
        Ok(stderr) => match seen.result {
            Some(r) => match store(&r) {
                Ok(()) => String::new(),
                Err(e) => format!("The result couldn't be stored: {e}"),
            },
            None => seen.error.unwrap_or_else(|| format!("speedtest.exe gave no result ({})", stderr.trim().chars().take(120).collect::<String>())),
        },
    };
    with(|s| s.error = message);
}

fn tick() {
    let now = guest::now();
    let demo = is_demo();
    if demo {
        with(|s| s.cli_ready = true);
        demo_history(now);
    } else {
        let ready = guest::helper_ready(EXE, EXE_SHA256);
        with(|s| s.cli_ready = ready);
    }
    // The demo test is made up here, a step at a time.
    if demo && with(|s| s.running) {
        let frac = with(|s| {
            s.demo_frac += DEMO_STEP_MS as f32 / 1000.0 / DEMO_TEST_SECS;
            s.demo_frac
        });
        if frac >= 1.0 {
            let k = guest::db_query("SELECT count(*) FROM p_speedtest__results").ok().and_then(|j| j.trim_matches(|c| c == '[' || c == ']').parse::<f32>().ok()).unwrap_or(0.0);
            let _ = store(&demo_result(now, k));
            with(|s| {
                s.running = false;
                s.live.clear();
                s.error.clear();
            });
            guest::set_tick(0);
        } else {
            with(|s| s.live = demo_live(frac));
        }
        return;
    }
    let every = num("interval_mins").clamp(0, 24 * 60) * 60;
    let (next_at, running) = with(|s| (s.next_at, s.running || s.installing));
    if next_at == 0 {
        // No test at startup.
        with(|s| s.next_at = now + every.max(1));
        return;
    }
    if every > 0 && now >= next_at && !running {
        with(|s| s.next_at = now + every.max(60));
        start_test();
    }
}

// ---- the pages ----

fn page() -> UiTree {
    let (live, running, installing, cli_ready, error) = with(|s| (s.live.clone(), s.running, s.installing, s.cli_ready, s.error.clone()));
    UiTree::Speedtest(Box::new(SpeedPage {
        sql: PAGE_SQL.into(),
        range: num("range").clamp(0, 2) as usize,
        live,
        running,
        installing,
        cli_ready,
        last_ok: num("last_ok"),
        error,
        install_title: "Download speedtest-cli".into(),
        install_text: vec![
            "speedtest-cli is a third-party program by Ookla, not part of RustWarden. It will be downloaded from install.speedtest.net and saved in RustWarden's own folder.".into(),
            "Using it means you accept Ookla's End User License Agreement and Privacy Policy (speedtest.net/about). Each test connects to Ookla's servers and sends them your IP address and the test results.".into(),
            "RustWarden passes the CLI's license and GDPR acceptance flags on your behalf, so only continue if you agree.".into(),
        ],
    }))
}

fn settings() -> UiTree {
    UiTree::Column(vec![
        UiTree::Weak("Runs Ookla's speedtest-cli; nothing is downloaded until you press the button on the Speedtest tab (Network).".into()),
        UiTree::Link { text: "Speedtest® by Ookla® (Ookla, LLC). Used under Ookla's End User License Agreement.".into(), url: "https://www.speedtest.net/about/eula".into() },
        UiTree::Label("Automatic speed tests: minutes between tests (0 = only when I press Run test)".into()),
        UiTree::Number { id: "interval_mins".into(), value: num("interval_mins") as f64, min: 0.0, max: 1440.0 },
        UiTree::Label("Server ID (0 = let Speedtest pick the closest)".into()),
        UiTree::Number { id: "server_id".into(), value: num("server_id") as f64, min: 0.0, max: 99_999_999.0 },
    ])
}

fn event(e: Event) {
    match e {
        Event::Click { id } if id == SPEED_RUN => start_test(),
        Event::Click { id } if id == SPEED_INSTALL => {
            with(|s| {
                s.installing = true;
                s.error.clear();
            });
            let result = guest::helper_install(URL, ZIP_SHA256, EXE);
            let ready = guest::helper_ready(EXE, EXE_SHA256);
            with(|s| {
                s.installing = false;
                s.cli_ready = ready;
                s.error = result.err().unwrap_or_default();
            });
        }
        Event::Index { id, index } if id == SPEED_RANGE => guest::config_set("range", &index.min(2).to_string()),
        Event::Number { id, value } if id == "interval_mins" || id == "server_id" => {
            let max = if id == "interval_mins" { 1440.0 } else { 99_999_999.0 };
            guest::config_set(&id, &(value.clamp(0.0, max) as i64).to_string());
            if id == "interval_mins" {
                // The new schedule starts counting now.
                with(|s| s.next_at = 0);
            }
        }
        _ => {}
    }
}

impl Guest for Speedtest {
    fn manifest() -> Manifest {
        Manifest {
            id: "speedtest".into(),
            name: "Speedtest".into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            tabs: vec![TabDef { id: "speedtest".into(), title: "Speedtest".into() }],
            settings_page: true,
            http_hosts: vec!["install.speedtest.net".into()],
            permissions: vec!["helper.exe".into()],
            tick_secs: 1,
            schema: SCHEMA.into(),
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderTab { .. } => Reply::Ui(page()),
            Call::RenderSettings => Reply::Ui(settings()),
            Call::Event(e) => {
                event(e);
                Reply::Done
            }
            Call::Tick => {
                tick();
                Reply::Done
            }
            Call::HelperLine { line } => {
                let now = with(|s| s.started_at);
                if let Some(p) = progress_of(&line) {
                    with(|s| s.live.push(p));
                }
                with(|s| s.seen.feed(&line, now));
                Reply::Done
            }
            Call::HelperDone { ok, message } => {
                finish(if ok { Ok(message) } else { Err(message) });
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Speedtest);

#[cfg(test)]
mod tests {
    use super::*;

    const RESULT: &str = r#"{"type":"result","timestamp":"2026-10-31T10:00:00Z","ping":{"jitter":0.7,"latency":10.5,"low":9.0,"high":12.0},"download":{"bandwidth":12500000,"bytes":1,"elapsed":1},"upload":{"bandwidth":2500000,"bytes":1,"elapsed":1},"packetLoss":0,"isp":"Example ISP","server":{"id":1234,"name":"Example Net","location":"London"},"result":{"id":"abc","url":"https://www.speedtest.net/result/c/abc"}}"#;

    fn parse(output: &str, now: i64) -> Result<SpeedResult, String> {
        let mut seen = Seen::default();
        for l in output.lines() {
            seen.feed(l, now);
        }
        seen.result.ok_or_else(|| seen.error.unwrap_or_else(|| format!("speedtest.exe gave no result ({})", output.trim().chars().take(120).collect::<String>())))
    }

    #[test]
    fn reads_a_result_and_converts_bytes_to_megabits() {
        let r = parse(RESULT, 42).unwrap();
        assert_eq!((r.ts, r.down_mbps, r.up_mbps), (42, 100.0, 20.0));
        assert_eq!((r.ping_ms, r.jitter_ms, r.loss), (10.5, 0.7, 0.0));
        assert_eq!((r.server.as_str(), r.isp.as_str()), ("Example Net, London", "Example ISP"));
        assert!(r.url.ends_with("/abc"));
    }

    #[test]
    fn skips_progress_lines_and_reports_errors() {
        assert!(parse(&format!("{{\"type\":\"testStart\"}}\n{RESULT}\n"), 1).is_ok());
        let e = parse(r#"{"type":"log","level":"error","message":"Configuration - Could not retrieve or read configuration"}"#, 1).unwrap_err();
        assert!(e.starts_with("Configuration"));
        assert!(parse("garbage", 1).unwrap_err().contains("no result"));
    }

    #[test]
    fn live_lines_become_progress() {
        let down = r#"{"type":"download","timestamp":"t","download":{"bandwidth":12500000,"bytes":1,"elapsed":900,"progress":0.5}}"#;
        assert_eq!(progress_of(down), Some(SpeedLive { phase: SpeedPhase::Download, mbps: 100.0, progress: 0.5 }));
        assert_eq!(progress_of(r#"{"type":"ping","ping":{"jitter":1,"latency":9,"progress":1}}"#).map(|p| (p.phase, p.progress)), Some((SpeedPhase::Ping, 1.0)));
        assert_eq!(progress_of(RESULT), None);
        assert_eq!(progress_of("garbage"), None);
    }

    #[test]
    fn reads_the_addresses_for_the_route_map() {
        let json = RESULT.replace("\"id\":1234,", "\"id\":1234,\"ip\":\"203.0.113.9\",").replace("\"isp\"", "\"interface\":{\"externalIp\":\"198.51.100.7\"},\"isp\"");
        let r = parse(&json, 1).unwrap();
        assert_eq!((r.server_ip.as_str(), r.client_ip.as_str()), ("203.0.113.9", "198.51.100.7"));
    }

    #[test]
    fn missing_packet_loss_is_negative() {
        assert!(parse(&RESULT.replace("\"packetLoss\":0,", ""), 1).unwrap().loss < 0.0);
    }

    #[test]
    fn demo_readings_ramp_up_through_the_three_phases() {
        let live = demo_live(1.0);
        assert_eq!(live.first().map(|p| p.phase), Some(SpeedPhase::Ping));
        assert!(live.iter().any(|p| p.phase == SpeedPhase::Download && p.mbps > 700.0));
        assert!(live.last().is_some_and(|p| p.phase == SpeedPhase::Upload && p.mbps > 60.0));
        assert!(demo_live(0.0).len() == 1);
    }

    #[test]
    fn sql_text_is_quoted() {
        assert_eq!(q("a'b"), "'a''b'");
    }
}
