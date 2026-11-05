//! VirusTotal reputation of the programs on the Firewall tab, by SHA-256. Only the hash is sent: a
//! program VirusTotal has never seen stays "Not found" until the user confirms uploading that one file
//! (up to 32 MB, see [`Scanner::upload`]); it is then looked up again every minute, that program
//! only, until its report exists or `MAX_POLLS` minutes pass. Lookups run one at a time on a background thread, paced for the
//! free API's 4 requests a minute, through `curl.exe` with the key passed on stdin so it never
//! shows in the process list.

use super::asn::json_val;
use super::db::Db;
use super::store::Shared;
use super::store::lock;
use crate::data::{StatusNote, Vt};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const API: &str = "https://www.virustotal.com/api/v3/files";
/// The plain upload endpoint's limit; bigger files need a separate upload URL.
/// shortcut: larger files are skipped, add the upload_url call if they matter.
const MAX_UPLOAD: u64 = 32 * 1024 * 1024;
const POLL: Duration = Duration::from_secs(60);
const RETRY_FAILED: Duration = Duration::from_secs(3600);
/// Looks at an uploaded file this many times, a minute further apart each time, then stops asking.
const MAX_POLLS: u32 = 8;
/// This many failures in a row (usually the quota running out) pause all lookups for `HOLD`.
const HOLD_AFTER: u64 = 3;
const HOLD: Duration = Duration::from_secs(6 * 3600);

#[derive(Default)]
pub struct Scanner {
    /// Results by file hash. `Pending` and `Failed` live here only; the rest is also in the kv table.
    cache: Mutex<HashMap<String, Vt>>,
    queue: Mutex<VecDeque<String>>,
    /// Files the user confirmed uploading, one by one. Nothing else ever fills it.
    uploads: Mutex<VecDeque<String>>,
    /// Uploaded files whose report isn't there yet, with when to look next and how often it was looked at.
    waiting: Mutex<HashMap<String, (Instant, u32)>>,
    /// When set and in the future, no lookups run. shortcut: not saved, a restart ends the hold.
    hold_until: Mutex<Option<Instant>>,
}

impl Scanner {
    fn on_hold(&self) -> bool {
        lock(&self.hold_until).is_some_and(|t| t > Instant::now())
    }

    pub fn get(&self, db: &Db, hash: &str) -> Vt {
        if hash.is_empty() {
            return Vt::None;
        }
        let v = self.cached(db, hash);
        if matches!(v, Vt::Pending | Vt::Failed) && self.on_hold() { Vt::OnHold } else { v }
    }

    fn cached(&self, db: &Db, hash: &str) -> Vt {
        lock(&self.cache)
            .entry(hash.to_owned())
            .or_insert_with(|| {
                // Uploaded before RustWarden last closed: shown as "Analysing…", not polled again.
                db.kv_get(&format!("vt:{hash}")).map_or(Vt::None, |v| parse_stored(&v))
            })
            .clone()
    }

    /// Queues a lookup. A hash that already has a final answer is never looked up again.
    pub fn scan(&self, hash: &str) {
        let mut cache = lock(&self.cache);
        if hash.is_empty() || matches!(cache.get(hash), Some(Vt::Pending | Vt::Analysing | Vt::Result { .. } | Vt::NotFound | Vt::Skipped)) {
            return;
        }
        cache.insert(hash.to_owned(), Vt::Pending);
        // Front: a banner is waiting on it.
        lock(&self.queue).push_front(hash.to_owned());
    }

    /// Queues sending the file with this hash to VirusTotal. Call it only after the user confirmed that file.
    pub fn upload(&self, hash: &str) {
        let mut cache = lock(&self.cache);
        if hash.is_empty() || matches!(cache.get(hash), Some(Vt::Pending | Vt::Analysing | Vt::Result { .. } | Vt::Skipped)) {
            return;
        }
        cache.insert(hash.to_owned(), Vt::Pending);
        lock(&self.uploads).push_back(hash.to_owned());
    }

    /// A new key deserves a retry of lookups that failed with the old one.
    pub fn forget_failures(&self) {
        *lock(&self.hold_until) = None;
        lock(&self.cache).retain(|_, v| *v != Vt::Failed);
    }

    /// The next uploaded file whose minute is up; it is looked at again a minute later.
    fn due(&self) -> Option<String> {
        let now = Instant::now();
        let mut waiting = lock(&self.waiting);
        let hash = waiting.iter().find(|(_, (at, _))| *at <= now).map(|(h, _)| h.clone())?;
        let polls = waiting[&hash].1 + 1;
        if polls > MAX_POLLS {
            // Still unreported after all that: it stays "analysing" but costs no more lookups.
            waiting.remove(&hash);
            return None;
        }
        waiting.insert(hash.clone(), (now + POLL * polls, polls));
        Some(hash)
    }

    pub fn run(&self, shared: Arc<Shared>) {
        let Ok(db) = shared.open_db() else {
            shared.set_note("vt", Some(StatusNote::warn("VirusTotal lookups are off: the database couldn't be opened.")));
            return;
        };
        let mut last_retry = Instant::now();
        let mut failures = 0u64;
        while !shared.stopping() {
            // A network blip must not leave a program marked Failed until restart.
            if last_retry.elapsed() > RETRY_FAILED {
                self.forget_failures();
                last_retry = Instant::now();
            }
            let s = shared.settings();
            let key = s.virustotal_key.trim().to_owned();
            if key.is_empty() || self.on_hold() {
                nap(&shared, 5);
                continue;
            }
            if s.virustotal_auto {
                for a in db.apps().unwrap_or_default().iter().filter(|a| a.missing_since.is_none() && self.get(&db, &a.hash) == Vt::None) {
                    self.scan(&a.hash);
                }
            }
            let upload = lock(&self.uploads).pop_front();
            let queued = upload.clone().or_else(|| lock(&self.queue).pop_front());
            let Some((hash, polling)) = queued.map(|h| (h, false)).or_else(|| self.due().map(|h| (h, true))) else {
                nap(&shared, 5);
                continue;
            };
            let result = if upload.is_some() { upload_unknown(&db, &key, &hash) } else { after_lookup(lookup(&key, &hash), polling) };
            if result != Vt::Analysing {
                lock(&self.waiting).remove(&hash);
            } else if !polling {
                lock(&self.waiting).insert(hash.clone(), (Instant::now() + POLL, 0));
            }
            if let Some(v) = stored(&result) {
                let _ = db.kv_set(&format!("vt:{hash}"), &v);
            }
            // Failures are mostly the quota running out (429): back off instead of burning more lookups.
            failures = if result == Vt::Failed { failures + 1 } else { 0 };
            lock(&self.cache).insert(hash, result);
            if failures >= HOLD_AFTER {
                *lock(&self.hold_until) = Some(Instant::now() + HOLD);
                failures = 0;
            }
            shared.repaint();
            nap(&shared, 16 + 60 * failures.min(30));
        }
    }
}

/// What a lookup result means for the program. A hash VirusTotal has never seen stays `NotFound`: uploading the
/// file is the user's decision, never ours. While polling an uploaded file, "not there yet" means still analysing.
fn after_lookup(found: Vt, polling: bool) -> Vt {
    match (found, polling) {
        (Vt::NotFound | Vt::Failed, true) => Vt::Analysing,
        (r, _) => r,
    }
}

fn nap(shared: &Shared, secs: u64) {
    for _ in 0..secs * 4 {
        if shared.stopping() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn stored(v: &Vt) -> Option<String> {
    match v {
        Vt::Analysing => Some("up".into()),
        Vt::Skipped => Some("big".into()),
        Vt::NotFound => Some("nf".into()),
        Vt::Result { bad, total } => Some(format!("{bad}/{total}")),
        _ => None,
    }
}

fn parse_stored(v: &str) -> Vt {
    match v.split_once('/') {
        Some((b, t)) => b.parse().ok().zip(t.parse().ok()).map_or(Vt::None, |(bad, total)| Vt::Result { bad, total }),
        None if v == "up" => Vt::Analysing,
        None if v == "big" => Vt::Skipped,
        None if v == "nf" => Vt::NotFound,
        None => Vt::None,
    }
}

/// Runs `curl.exe` with `extra` appended to a config of the key header; returns the body followed by "\n<http status>".
fn curl(key: &str, extra: &str, dir: Option<&Path>, max_secs: &str) -> Option<String> {
    // The key goes into a curl config file, so anything but a plain token is refused.
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let config = format!("silent\nmax-time = {max_secs}\nwrite-out = \"\\n%{{http_code}}\"\nheader = \"x-apikey: {key}\"\n{extra}");
    Some(String::from_utf8_lossy(&crate::sys::curl::run(&config, dir).ok()?.stdout).into_owned())
}

fn lookup(key: &str, hash: &str) -> Vt {
    curl(key, &format!("url = \"{API}/{hash}\"\n"), None, "20").map_or(Vt::Failed, |b| parse_response(&b))
}

/// Sends the program with this hash to VirusTotal. `Analysing` once accepted.
fn upload_unknown(db: &Db, key: &str, hash: &str) -> Vt {
    let apps = db.apps().unwrap_or_default();
    let Some(path) = apps.iter().find(|a| a.hash == hash).map(|a| Path::new(&a.path)) else { return Vt::Failed };
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else { return Vt::Failed };
    // The file is named relative to its folder so the path needs no escaping in curl's config.
    if name.contains(['"', '\\', '\n']) {
        return Vt::Failed;
    }
    match std::fs::metadata(path) {
        Ok(m) if m.len() > MAX_UPLOAD => return Vt::Skipped,
        Ok(_) => {}
        Err(_) => return Vt::Failed,
    }
    crate::applog::line("rustywire.log", &format!("VirusTotal upload, confirmed by the user: {} ({hash})", path.display()));
    let body = curl(key, &format!("url = \"{API}\"\nform = \"file=@\\\"{name}\\\"\"\n"), Some(dir), "300");
    if body.is_some_and(|b| b.trim_end().ends_with("200")) { Vt::Analysing } else { Vt::Failed }
}

/// `body` ends with "\n<http status>" (curl's `-w`).
fn parse_response(body: &str) -> Vt {
    let (json, code) = body.rsplit_once('\n').unwrap_or(("", body));
    match code.trim() {
        "404" => Vt::NotFound,
        "200" => {
            let stats = json.find("\"last_analysis_stats\"").map_or("", |i| &json[i..]);
            let n = |k| json_val(stats, k).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
            let bad = n("malicious");
            let total = bad + n("suspicious") + n("harmless") + n("undetected");
            // The file is known but has no engine results yet.
            if total == 0 { Vt::Analysing } else { Vt::Result { bad, total } }
        }
        _ => Vt::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses() {
        let ok = "{\"data\":{\"attributes\":{\"last_analysis_stats\": {\"harmless\": 0, \"suspicious\": 1,\n \"malicious\": 2, \"undetected\": 67}}}}\n200";
        assert_eq!(parse_response(ok), Vt::Result { bad: 2, total: 70 });
        assert_eq!(parse_response("{}\n404"), Vt::NotFound);
        assert_eq!(parse_response("{}\n401"), Vt::Failed);
        assert_eq!(parse_response("{}\n200"), Vt::Analysing);
    }

    #[test]
    fn a_hash_virustotal_has_not_seen_is_never_uploaded_by_itself() {
        assert_eq!(after_lookup(Vt::NotFound, false), Vt::NotFound);
        assert_eq!(after_lookup(Vt::NotFound, true), Vt::Analysing);
        assert_eq!(after_lookup(Vt::Failed, false), Vt::Failed);
        let s = Scanner::default();
        s.scan("aa");
        assert!(lock(&s.uploads).is_empty());
    }

    #[test]
    fn upload_queues_only_when_asked_and_only_once() {
        let s = Scanner::default();
        s.upload("bb");
        s.upload("bb");
        s.upload("");
        assert_eq!(lock(&s.uploads).len(), 1);
        assert_eq!(lock(&s.cache)["bb"], Vt::Pending);
    }

    #[test]
    fn a_hash_with_a_final_answer_is_not_looked_up_or_sent_again() {
        let s = Scanner::default();
        for v in [Vt::Result { bad: 0, total: 70 }, Vt::NotFound, Vt::Skipped] {
            lock(&s.cache).insert("cc".into(), v.clone());
            s.scan("cc");
            assert_eq!(lock(&s.cache)["cc"], v);
            assert!(lock(&s.queue).is_empty());
        }
        for v in [Vt::Result { bad: 0, total: 70 }, Vt::Skipped] {
            lock(&s.cache).insert("dd".into(), v.clone());
            s.upload("dd");
            assert!(lock(&s.uploads).is_empty());
        }
        // A "Not found" hash is still uploaded, but only when the user confirms it.
        lock(&s.cache).insert("ee".into(), Vt::NotFound);
        s.upload("ee");
        assert_eq!(lock(&s.uploads).len(), 1);
    }

    #[test]
    fn stored_round_trip() {
        for v in [Vt::Analysing, Vt::Skipped, Vt::NotFound, Vt::Result { bad: 3, total: 72 }] {
            assert_eq!(parse_stored(&stored(&v).unwrap()), v);
        }
        assert_eq!(stored(&Vt::Failed), None);
    }
}
