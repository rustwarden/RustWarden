//! Ookla's `speedtest.exe`: downloading it, running it and reading its JSON. Ookla's licence doesn't
//! allow shipping the CLI inside another program, so it is fetched from Ookla only when the user asks.

use super::{Phase, Progress, SpeedResult};
use std::io::{BufRead, Read};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const URL: &str = "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-win64.zip";
const ZIP_SHA256: &str = "13e3d888b845d301a556419e31f14ab9bff57e3f06089ef2fd3bdc9ba6841efa";
/// `speedtest.exe` inside that zip; lets an elevated run take over a copy downloaded without elevation.
const EXE_SHA256: &str = "c73c4ac2a7cdc48829fe0f9d7ec91ca41c8b434490d4eb3205aad69c7aa3b921";
/// A test normally takes about 30 s; anything longer than this is stuck.
const TEST_TIMEOUT: Duration = Duration::from_secs(180);

fn user_dir() -> PathBuf {
    crate::settings::data_dir().join("speedtest")
}

/// Elevated runs use an admin-only folder: any program could swap the exe in the data folder, or plant a DLL beside it.
pub fn dir() -> PathBuf {
    if crate::sys::is_elevated() { crate::settings::admin_dir().join("speedtest") } else { user_dir() }
}

/// Elevated: moves a genuine copy from the data folder to the admin-only one, so nobody has to download it again.
pub fn adopt_user_copy() {
    if crate::sys::is_elevated() && adopt(&user_dir().join("speedtest.exe"), &dir(), EXE_SHA256) {
        let _ = std::fs::remove_dir_all(user_dir());
    }
}

/// Hashes the copy, not the original, because the original can still change after it is checked.
fn adopt(from: &Path, to_dir: &Path, wanted: &str) -> bool {
    let to = to_dir.join("speedtest.exe");
    if to.exists() || !from.is_file() || std::fs::create_dir_all(to_dir).is_err() || std::fs::copy(from, &to).is_err() {
        return false;
    }
    let genuine = crate::sys::apps::hash_file(&to.to_string_lossy()).eq_ignore_ascii_case(wanted);
    if !genuine {
        let _ = std::fs::remove_file(&to);
    }
    genuine
}

pub fn exe() -> PathBuf {
    dir().join("speedtest.exe")
}

/// Downloads and unpacks the CLI. Blocks, so callers run it on a worker.
pub fn install() -> Result<(), String> {
    let dir = dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("Can't create {}: {e}", dir.display()))?;
    let mut curl = crate::sys::tool("curl.exe");
    curl.args(["-fsSL", "--max-time", "300", "-o", "speedtest.zip", URL]).current_dir(&dir);
    run_tool(&mut curl, "Can't download speedtest-cli")?;
    let zip = dir.join("speedtest.zip");
    if !crate::sys::apps::hash_file(&zip.to_string_lossy()).eq_ignore_ascii_case(ZIP_SHA256) {
        let _ = std::fs::remove_file(&zip);
        return Err("The speedtest-cli download did not match the expected checksum, so it was thrown away.".into());
    }
    // tar.exe ships with Windows 10+ and reads zip files, so no archive crate is needed.
    let mut tar = crate::sys::tool("tar.exe");
    tar.args(["-xf", "speedtest.zip", "speedtest.exe"]).current_dir(&dir);
    let unpacked = run_tool(&mut tar, "Can't unpack speedtest-cli");
    let _ = std::fs::remove_file(dir.join("speedtest.zip"));
    unpacked?;
    if exe().is_file() { Ok(()) } else { Err("The download didn't contain speedtest.exe".into()) }
}

fn run_tool(cmd: &mut Command, what: &str) -> Result<(), String> {
    cmd.stdout(Stdio::null()).stderr(Stdio::piped()).creation_flags(crate::sys::NO_WINDOW);
    let child = crate::sys::etw::spawn_own(cmd).map_err(|e| format!("{what}: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("{what}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(format!("{what}: {}", err.lines().next().unwrap_or("it failed").trim()))
}

/// Runs one test against `server` (0 = closest). Blocks for about 30 s; `on_progress` gets each live reading.
pub fn run(server: u32, now: i64, on_progress: impl Fn(Progress) + Send + 'static) -> Result<SpeedResult, String> {
    let mut cmd = Command::new(exe());
    // jsonl prints a line per reading while the test runs; json would only print the result at the end.
    cmd.args(["--accept-license", "--accept-gdpr", "-f", "jsonl"]);
    if server != 0 {
        cmd.arg("-s").arg(server.to_string());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null()).creation_flags(crate::sys::NO_WINDOW);
    let mut child = crate::sys::etw::spawn_own(&mut cmd).map_err(|e| format!("Can't run speedtest.exe: {e}"))?;
    let (stdout, mut stderr) = (child.stdout.take(), child.stderr.take());
    let out = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(o) = stdout {
            for line in std::io::BufReader::new(o).lines().map_while(Result::ok) {
                if let Some(p) = progress_of(&line) {
                    on_progress(p);
                }
                s.push_str(&line);
                s.push('\n');
            }
        }
        if let Some(e) = &mut stderr {
            let _ = e.read_to_string(&mut s);
        }
        s
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() > TEST_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("The speed test timed out".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => return Err(format!("Can't wait for speedtest.exe: {e}")),
        }
    }
    parse(&out.join().unwrap_or_default(), now)
}

/// A live `ping`, `download` or `upload` line of the CLI's jsonl output; None for any other line.
pub fn progress_of(line: &str) -> Option<Progress> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let phase = match v["type"].as_str()? {
        "ping" => Phase::Ping,
        "download" => Phase::Download,
        "upload" => Phase::Upload,
        _ => return None,
    };
    let body = &v[v["type"].as_str()?];
    let mbps = if phase == Phase::Ping { 0.0 } else { body["bandwidth"].as_f64().unwrap_or(0.0) as f32 * 8.0 / 1e6 };
    Some(Progress { phase, mbps, progress: body["progress"].as_f64().unwrap_or(0.0).clamp(0.0, 1.0) as f32 })
}

/// Reads the CLI's jsonl output: the `result` line, or the message of its error line.
pub fn parse(output: &str, now: i64) -> Result<SpeedResult, String> {
    let mut error = None;
    for v in output.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok()) {
        if v["type"] == "result" {
            return Ok(result_of(&v, now));
        }
        if v["level"] == "error" {
            error = v["message"].as_str().map(str::to_owned);
        }
    }
    Err(error.unwrap_or_else(|| format!("speedtest.exe gave no result ({})", output.trim().chars().take(120).collect::<String>())))
}

fn result_of(v: &serde_json::Value, now: i64) -> SpeedResult {
    let f = |x: &serde_json::Value| x.as_f64().unwrap_or(0.0) as f32;
    // The CLI reports bandwidth in bytes per second.
    let mbps = |x: &serde_json::Value| f(x) * 8.0 / 1e6;
    let s = |x: &serde_json::Value| x.as_str().unwrap_or_default().to_owned();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adopts_only_a_genuine_copy() {
        let root = std::env::temp_dir().join(format!("rustywire-speedtest-test-{}", std::process::id()));
        let (from, to) = (root.join("from.exe"), root.join("to"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&from, b"program").unwrap();
        let real = crate::sys::apps::hash_file(&from.to_string_lossy());
        assert!(!adopt(&from, &to, &"0".repeat(64)));
        assert!(!to.join("speedtest.exe").exists(), "a wrong copy must not stay");
        assert!(adopt(&from, &to, &real));
        assert!(to.join("speedtest.exe").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    const RESULT: &str = r#"{"type":"result","timestamp":"2026-10-31T10:00:00Z","ping":{"jitter":0.7,"latency":10.5,"low":9.0,"high":12.0},"download":{"bandwidth":12500000,"bytes":1,"elapsed":1},"upload":{"bandwidth":2500000,"bytes":1,"elapsed":1},"packetLoss":0,"isp":"Example ISP","server":{"id":1234,"name":"Example Net","location":"London"},"result":{"id":"abc","url":"https://www.speedtest.net/result/c/abc"}}"#;

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
        assert_eq!(progress_of(down), Some(Progress { phase: Phase::Download, mbps: 100.0, progress: 0.5 }));
        assert_eq!(progress_of(r#"{"type":"ping","ping":{"jitter":1,"latency":9,"progress":1}}"#).map(|p| (p.phase, p.progress)), Some((Phase::Ping, 1.0)));
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
}
