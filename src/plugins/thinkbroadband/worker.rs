//! Downloads the chosen monitors every few minutes and raises packet-loss alerts for new samples.

use super::browser::NEED_LOGIN;
use super::{Integration, Sample, active, client};
use crate::data::StatusNote;
use crate::live::alerts::AlertKind;
use crate::live::db::Db;
use crate::live::store::Shared;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

/// Set by the "Sync now" button: download again straight away.
pub static SYNC_NOW: AtomicBool = AtomicBool::new(false);

/// How long downloaded samples are kept.
const KEEP_SECS: i64 = 365 * 86_400;

/// Set when the saved sign-in no longer works; the app then asks the user to sign in, and polling waits.
pub static NEEDS_LOGIN: AtomicBool = AtomicBool::new(false);

/// True while a download is running (the Refresh button shows it).
pub static REFRESHING: AtomicBool = AtomicBool::new(false);

/// Unix time of the last download that worked; shown on the tab.
pub static LAST_OK: AtomicI64 = AtomicI64::new(0);

const NOTE: &str = "thinkbroadband";
/// A monitor with nothing stored yet is filled with this many days; afterwards the days since its
/// newest sample are fetched again (at least two, at most this many), so a long break leaves no hole.
const FIRST_DAYS: i64 = 7;

/// Settings kept in the database: when the last download was tried, and when one last worked.
const ATTEMPT: &str = "tbb_attempt";
const SYNCED: &str = "tbb_synced";

fn kv_time(db: &Db, key: &str) -> i64 {
    db.kv_get(key).and_then(|v| v.parse().ok()).unwrap_or(0)
}

pub fn run(shared: Arc<Shared>) {
    let (mut seen_cfg, mut next_at) = (None, 0);
    while shared.sleep(0.5) {
        let s = shared.settings();
        let Some(cfg) = active(&s) else {
            shared.set_note(NOTE, None);
            continue;
        };
        let cfg_key = Some(cfg.monitors.iter().map(|m| m.id).collect::<Vec<_>>());
        let now = crate::clock::now_unix();
        if seen_cfg.is_none() {
            let Ok(db) = shared.open_db() else { continue };
            // First pass after launch: keep to the last attempt's schedule so restarts don't re-download.
            LAST_OK.store(kv_time(&db, SYNCED), Ordering::Relaxed);
            let stored = cfg.monitors.iter().all(|m| db.tbb_latest(m.id).is_some());
            next_at = if stored { kv_time(&db, ATTEMPT) + i64::from(cfg.interval_mins) * 60 } else { 0 };
            seen_cfg = cfg_key.clone();
        }
        if SYNC_NOW.swap(false, Ordering::Relaxed) || seen_cfg != cfg_key {
            NEEDS_LOGIN.store(false, Ordering::Relaxed);
            seen_cfg = cfg_key;
            next_at = 0;
        }
        if now < next_at || NEEDS_LOGIN.load(Ordering::Relaxed) {
            continue;
        }
        next_at = now + i64::from(cfg.interval_mins) * 60;
        let Ok(db) = shared.open_db() else { continue };
        let _ = db.kv_set(ATTEMPT, &now.to_string());
        REFRESHING.store(true, Ordering::Relaxed);
        shared.repaint();
        let result = poll(&shared, &db, cfg, now);
        REFRESHING.store(false, Ordering::Relaxed);
        match result {
            Ok(()) => {
                let done = crate::clock::now_unix();
                LAST_OK.store(done, Ordering::Relaxed);
                let _ = db.kv_set(SYNCED, &done.to_string());
                shared.set_note(NOTE, None);
            }
            Err(e) if e == NEED_LOGIN => {
                NEEDS_LOGIN.store(true, Ordering::Relaxed);
                shared.set_note(NOTE, Some(StatusNote::warn("thinkbroadband needs you to sign in again.".to_owned())));
            }
            Err(e) => shared.set_note(NOTE, Some(StatusNote::warn(format!("{e} Trying again in {} minutes.", cfg.interval_mins)))),
        }
        shared.repaint();
    }
}

fn poll(shared: &Shared, db: &Db, cfg: &Integration, now: i64) -> Result<(), String> {
    // One browser run for every monitor and day.
    let mut requests = Vec::new();
    for m in &cfg.monitors {
        let days = db.tbb_latest(m.id).map_or(FIRST_DAYS, |ts| ((now - ts) / 86_400 + 2).clamp(2, FIRST_DAYS));
        requests.extend((0..days).rev().map(|back| (m.id, client::date(now - back * 86_400))));
    }
    let mut answers = client::fetch_days(&requests)?.into_iter();
    for m in &cfg.monitors {
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
        db.tbb_put(m.id, &all).map_err(|e| format!("Can't store the samples: {e}"))?;
        let _ = db.tbb_prune(crate::clock::now_unix() - KEEP_SECS);
        let key = format!("tbb_alert_{}", m.id);
        let last = db.kv_get(&key).and_then(|v| v.parse::<i64>().ok());
        let Some(newest) = all.iter().map(|s| s.ts).max() else { continue };
        // The first download is history, not news.
        if let Some(last) = last {
            let fresh: Vec<Sample> = all.into_iter().filter(|s| s.ts > last).collect();
            report(shared, db, cfg, &m.name, &fresh);
        }
        let _ = db.kv_set(&key, &newest.max(last.unwrap_or(0)).to_string());
    }
    Ok(())
}

/// One alert per monitor and download, for the worst new sample.
fn report(shared: &Shared, db: &Db, cfg: &Integration, name: &str, fresh: &[Sample]) {
    let worst = |min: f32| fresh.iter().filter(|s| s.loss >= min.max(f32::EPSILON)).max_by(|a, b| a.loss.total_cmp(&b.loss));
    if let Some(w) = worst(cfg.alert_pct) {
        let n = fresh.iter().filter(|s| s.loss >= cfg.alert_pct.max(f32::EPSILON)).count();
        shared.alert(db, AlertKind::ThinkBroadband, name, &format!("lost up to {:.0}% of packets ({n} intervals of 100 seconds)", w.loss), "", "");
    }
}
