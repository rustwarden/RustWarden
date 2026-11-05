//! Runs a test when the user asks, or on the interval if one is set, and stores the result.

use super::{Progress, SpeedStatus, cli};
use crate::live::store::Shared;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

/// Set by the Run test button.
pub static RUN_NOW: AtomicBool = AtomicBool::new(false);
pub static RUNNING: AtomicBool = AtomicBool::new(false);
pub static INSTALLING: AtomicBool = AtomicBool::new(false);
/// `speedtest.exe` is present; kept here so the UI never touches the disk.
pub static CLI_READY: AtomicBool = AtomicBool::new(false);
pub static LAST_OK: AtomicI64 = AtomicI64::new(0);
static ERROR: Mutex<String> = Mutex::new(String::new());
/// Readings of the test in progress, for the gauge and the live graph.
static LIVE: Mutex<Vec<Progress>> = Mutex::new(Vec::new());

const KEEP_SECS: i64 = 365 * 86_400;

pub fn set_error(e: &str) {
    *ERROR.lock().unwrap_or_else(|p| p.into_inner()) = e.to_owned();
}

pub fn status() -> SpeedStatus {
    SpeedStatus {
        live: LIVE.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        cli_ready: CLI_READY.load(Ordering::Relaxed),
        installing: INSTALLING.load(Ordering::Relaxed),
        running: RUNNING.load(Ordering::Relaxed),
        last_ok: LAST_OK.load(Ordering::Relaxed),
        error: ERROR.lock().unwrap_or_else(|p| p.into_inner()).clone(),
    }
}

/// Downloads the CLI (blocks; the caller is a worker).
pub fn install() -> Result<(), String> {
    INSTALLING.store(true, Ordering::Relaxed);
    let r = cli::install();
    CLI_READY.store(cli::exe().is_file(), Ordering::Relaxed);
    INSTALLING.store(false, Ordering::Relaxed);
    set_error(r.as_ref().err().map_or("", |e| e.as_str()));
    r
}

pub fn run(shared: Arc<Shared>) {
    cli::adopt_user_copy();
    let mut next_at = 0;
    while shared.sleep(0.5) {
        CLI_READY.store(cli::exe().is_file(), Ordering::Relaxed);
        let s = shared.settings();
        let now = crate::clock::now_unix();
        let every = i64::from(s.speedtest.interval_mins) * 60;
        if next_at == 0 {
            next_at = now + every; // no test at startup
        }
        let asked = RUN_NOW.swap(false, Ordering::Relaxed);
        let due = every > 0 && now >= next_at;
        if !s.speedtest.show_tab || !(asked || due) {
            continue;
        }
        next_at = now + every.max(60);
        if !CLI_READY.load(Ordering::Relaxed) {
            set_error("Download speedtest-cli first.");
            shared.repaint();
            continue;
        }
        RUNNING.store(true, Ordering::Relaxed);
        LIVE.lock().unwrap_or_else(|p| p.into_inner()).clear();
        shared.repaint();
        let on_progress = {
            let shared = shared.clone();
            move |p| {
                LIVE.lock().unwrap_or_else(|e| e.into_inner()).push(p);
                shared.repaint();
            }
        };
        let result = cli::run(s.speedtest.server_id, crate::clock::now_unix(), on_progress);
        LIVE.lock().unwrap_or_else(|p| p.into_inner()).clear();
        match result {
            Ok(r) => match shared.open_db().and_then(|db| db.speedtest_put(&r).and_then(|_| db.speedtest_prune(now - KEEP_SECS))) {
                Ok(_) => {
                    LAST_OK.store(r.ts, Ordering::Relaxed);
                    set_error("");
                }
                Err(e) => set_error(&format!("The result couldn't be stored: {e}")),
            },
            Err(e) => set_error(&e),
        }
        RUNNING.store(false, Ordering::Relaxed);
        shared.repaint();
    }
}
