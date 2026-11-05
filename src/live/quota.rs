//! Data quotas. A thread works out each quota's usage for the current period from the traffic
//! database (so the counters survive restarts by construction), raises alerts at the warning
//! percentage and at 100%, and blocks or unblocks the app through the firewall layer.
//!
//! The only state of its own is a `Track` per quota in the `kv` table: which period it last saw,
//! which level it already alerted, and whether the block on the app is ours to lift.

use super::db::Db;
use super::firewall::{FwController, is_lan};
use super::qos::Qos;
use super::store::Shared;
use crate::clock::{self, PeriodKind};
use crate::data::{Direction, QuotaLevel, QuotaStatus, StatusNote, Verdict};
use crate::settings::{PlanPeriod, Quota, QuotaAction};
use crate::util::fmt_bytes;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const KV_KEY: &str = "quota_state";

pub fn period_kind(p: PlanPeriod) -> PeriodKind {
    match p {
        PlanPeriod::Day => PeriodKind::Day,
        PlanPeriod::Week => PeriodKind::Week,
        PlanPeriod::Month => PeriodKind::Month,
    }
}

fn period_word(p: PlanPeriod) -> &'static str {
    match p {
        PlanPeriod::Day => "daily",
        PlanPeriod::Week => "weekly",
        PlanPeriod::Month => "monthly",
    }
}

/// How much of `limit` is used: warning from `warn_pct` percent, over at 100%.
pub fn level(used: f64, limit: f64, warn_pct: u32) -> QuotaLevel {
    if limit.is_nan() || limit <= 0.0 {
        QuotaLevel::Ok
    } else if used >= limit {
        QuotaLevel::Over
    } else if used >= limit * f64::from(warn_pct) / 100.0 {
        QuotaLevel::Warn
    } else {
        QuotaLevel::Ok
    }
}

/// What one quota remembers between runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Track {
    /// Start of the period the counters belong to.
    pub start: i64,
    /// Highest level already alerted in that period.
    pub alerted: QuotaLevel,
    /// We blocked `app`, so lifting the block is our job.
    pub blocked: bool,
    /// The app that block is on.
    pub app: String,
    /// We capped `app`'s upload rate, so lifting the cap is our job.
    pub throttled: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Decision {
    /// A level that was just crossed and should be announced.
    pub alert: Option<QuotaLevel>,
    pub block: bool,
    pub release: bool,
    pub throttle: bool,
    pub unthrottle: bool,
}

/// A track whose quota is gone, switched off or aimed at another app can't keep its block.
pub fn orphaned(t: &Track, q: Option<&Quota>) -> bool {
    q.is_none_or(|q| !q.enabled || q.app != t.app)
}

/// Moves `t` to the current period and says what to do about `used` bytes. The caller sets
/// `t.blocked` once a block or release has actually happened.
pub fn step(t: &mut Track, q: &Quota, start: i64, used: f64) -> Decision {
    // A new period, or the clock was moved into another one: counting starts again. The block flag
    // stays until the release really happened.
    if t.start != start {
        *t = Track { start, alerted: QuotaLevel::Ok, blocked: t.blocked, app: t.app.clone(), throttled: t.throttled };
    }
    let lvl = level(used, q.limit_bytes(), q.warn_pct);
    let mut d = Decision::default();
    // Over with action None stays quiet; the bar is all it gets.
    if lvl > t.alerted && (lvl == QuotaLevel::Warn || q.action != QuotaAction::None) {
        d.alert = Some(lvl);
    }
    // Usage that fell (a raised limit) re-arms the alert for the next crossing.
    t.alerted = lvl;
    let want_block = lvl == QuotaLevel::Over && q.action.blocks();
    d.block = want_block && !t.blocked;
    d.release = !want_block && t.blocked;
    // Slowing down comes before blocking: from the warning level for ThrottleBlock, at 100% for Throttle.
    let want_throttle = match q.action {
        QuotaAction::Throttle => lvl == QuotaLevel::Over,
        QuotaAction::ThrottleBlock => lvl >= QuotaLevel::Warn,
        _ => false,
    };
    d.throttle = want_throttle && !t.throttled;
    d.unthrottle = !want_throttle && t.throttled;
    d
}

pub fn tracks_to_text(m: &BTreeMap<u32, Track>) -> String {
    // The app comes before the throttle flag so lines saved before it existed still read.
    m.iter().map(|(id, t)| format!("{id}\t{}\t{}\t{}\t{}\t{}", t.start, t.alerted as u8, u8::from(t.blocked), t.app, u8::from(t.throttled))).collect::<Vec<_>>().join("\n")
}

pub fn tracks_from_text(text: &str) -> BTreeMap<u32, Track> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.splitn(6, '\t');
            let id = f.next()?.parse().ok()?;
            let start = f.next()?.parse().ok()?;
            let alerted = match f.next()? {
                "1" => QuotaLevel::Warn,
                "2" => QuotaLevel::Over,
                _ => QuotaLevel::Ok,
            };
            let blocked = f.next()? == "1";
            let app = f.next().unwrap_or("").to_owned();
            Some((id, Track { start, alerted, blocked, app, throttled: f.next() == Some("1") }))
        })
        .collect()
}

/// `None` when the database can't be read: a quota must not look unused (and release its block) because of that.
fn used_by(db: &Db, q: &Quota, start: i64, now: i64) -> Option<(f64, String)> {
    if q.app.is_empty() {
        return Some((db.quota_used(None, start, now + 1).ok()?, "All traffic".into()));
    }
    let own_name = |fallback: &str| {
        if q.app_name.is_empty() { fallback.to_owned() } else { q.app_name.clone() }
    };
    match db.app_by_key(&q.app).ok()? {
        Some(rec) => Some((db.quota_used(Some(rec.id), start, now + 1).ok()?, own_name(&rec.name))),
        None => Some((0.0, own_name(&q.app))),
    }
}

/// Whether the user's own outbound block already covers this app (so it is not ours to lift later).
fn user_blocked(shared: &Shared, key: &str) -> bool {
    shared.state().fw.rules.iter().any(|r| r.block && r.outbound && super::firewall::row_key(&r.program, &r.service) == key && !is_lan(&r.name))
}

struct Worker {
    shared: Arc<Shared>,
    fw: Arc<FwController>,
    db: Db,
    tracks: BTreeMap<u32, Track>,
    saved: String,
    /// Quotas whose block failed this period, so a missing admin right isn't retried every few seconds.
    failed: BTreeSet<u32>,
    /// The same for quotas whose bandwidth limit couldn't be set.
    slow_failed: BTreeSet<u32>,
    qos: Arc<Qos>,
}

impl Worker {
    fn alert(&self, app: &str, text: &str, target: &str) {
        self.shared.alert(&self.db, super::alerts::AlertKind::Quota, app, text, target, "");
    }

    fn release(&self, app: &str) -> bool {
        self.fw.set_verdict(app, Direction::Out, Verdict::Allowed).is_ok()
    }

    /// The program path a bandwidth limit needs; the quota only knows the app's key.
    fn path_of(&self, app: &str) -> Option<String> {
        self.db.app_by_key(app).ok().flatten().map(|r| r.path).filter(|p| !p.is_empty())
    }

    /// Caps the app's upload rate. `Ok(false)` when the user's own limit is already on it (not ours to lift).
    fn throttle(&self, q: &Quota) -> Result<bool, String> {
        let path = self.path_of(&q.app).ok_or("the program's path isn't known")?;
        if self.qos.find(&path).is_some() {
            return Ok(false);
        }
        self.qos.save(crate::qos::QosLimit::upload(0, true, path, q.throttle_kbps)).map(|()| true)
    }

    /// Lifts a cap we set; true when it is gone (or already was).
    fn unthrottle(&self, app: &str) -> bool {
        match self.path_of(app).and_then(|p| self.qos.find(&p)) {
            Some(limit) => self.qos.remove(limit.id).is_ok(),
            None => true,
        }
    }

    fn set_throttled(&mut self, id: u32, on: bool) {
        if let Some(t) = self.tracks.get_mut(&id) {
            t.throttled = on;
        }
    }

    fn set_blocked(&mut self, id: u32, on: bool) {
        if let Some(t) = self.tracks.get_mut(&id) {
            t.blocked = on;
        }
    }

    fn tick(&mut self) {
        let s = self.shared.settings();
        let now = clock::now_unix();
        let ids: BTreeSet<u32> = s.quotas.iter().map(|q| q.id).collect();
        let orphans: Vec<u32> = self.tracks.iter().filter(|(id, t)| orphaned(t, s.quotas.iter().find(|q| q.id == **id))).map(|(id, _)| *id).collect();
        for id in orphans {
            let (app, blocked, throttled) = {
                let t = &self.tracks[&id];
                (t.app.clone(), t.blocked, t.throttled)
            };
            if (!blocked || self.release(&app)) && (!throttled || self.unthrottle(&app)) {
                self.tracks.remove(&id);
            }
        }
        self.failed.retain(|id| ids.contains(id));
        let mut statuses = Vec::new();
        for q in s.quotas.iter().filter(|q| q.enabled) {
            let start = clock::period_start(now, period_kind(q.period));
            let Some((used, name)) = used_by(&self.db, q, start, now) else { continue };
            let t = self.tracks.entry(q.id).or_insert_with(|| Track { start, app: q.app.clone(), ..Track::default() });
            let d = step(t, q, start, used);
            let lvl = t.alerted;
            if lvl != QuotaLevel::Over {
                self.failed.remove(&q.id);
            }
            if lvl == QuotaLevel::Ok {
                self.slow_failed.remove(&q.id);
            }
            let limit = q.limit_bytes();
            let amount = format!("{} of {}", fmt_bytes(used), fmt_bytes(limit));
            let word = period_word(q.period);
            if d.release && self.release(&q.app) {
                self.set_blocked(q.id, false);
                self.alert(&name, &format!("was unblocked: its {word} quota is no longer reached"), "");
            }
            if d.unthrottle && self.unthrottle(&q.app) {
                self.set_throttled(q.id, false);
                self.alert(&name, &format!("is no longer slowed: its {word} quota is not reached"), "");
            }
            let mut throttle_note = String::new();
            if d.throttle && !self.slow_failed.contains(&q.id) {
                match self.throttle(q) {
                    Ok(true) => {
                        self.set_throttled(q.id, true);
                        throttle_note = format!("upload limited to {} until the period resets", crate::qos::fmt_rate(q.throttle_kbps));
                    }
                    Ok(false) => throttle_note = "already has a bandwidth limit".into(),
                    Err(e) => {
                        self.slow_failed.insert(q.id);
                        throttle_note = format!("couldn't limit upload: {e}");
                    }
                }
            }
            let mut block_note = String::new();
            if d.block && !self.failed.contains(&q.id) {
                if user_blocked(&self.shared, &q.app) {
                    block_note = "already blocked".into();
                } else {
                    match self.fw.set_verdict(&q.app, Direction::Out, Verdict::Blocked) {
                        Ok(()) => {
                            self.set_blocked(q.id, true);
                            block_note = "blocked until the period resets".into();
                        }
                        Err(e) => {
                            self.failed.insert(q.id);
                            block_note = format!("couldn't block: {e}");
                        }
                    }
                }
            }
            let notes = [throttle_note, block_note].into_iter().filter(|n| !n.is_empty()).collect::<Vec<_>>().join("; ");
            match d.alert {
                Some(QuotaLevel::Warn) => {
                    let target = if notes.is_empty() { amount } else { format!("{amount} ({notes})") };
                    self.alert(&name, &format!("has used {}% of its {word} quota:", q.warn_pct), &target);
                }
                Some(QuotaLevel::Over) => {
                    let target = if notes.is_empty() { amount } else { format!("{amount} ({notes})") };
                    self.alert(&name, &format!("has reached its {word} quota:"), &target);
                }
                _ => {}
            }
            let (blocked, throttled) = self.tracks.get(&q.id).map_or((false, false), |t| (t.blocked, t.throttled));
            statuses.push(QuotaStatus { quota: q.clone(), name, used, limit, level: lvl, blocked, throttled });
        }
        self.shared.state().quotas = statuses;
        let text = tracks_to_text(&self.tracks);
        if text != self.saved {
            let _ = self.db.kv_set(KV_KEY, &text);
            self.saved = text;
        }
        self.shared.repaint();
    }
}

pub fn run(shared: Arc<Shared>, fw: Arc<FwController>, qos: Arc<Qos>) {
    let Ok(db) = shared.open_db() else {
        shared.set_note("quota", Some(StatusNote::warn("Data quotas are off: the database couldn't be opened.")));
        return;
    };
    let saved = db.kv_get(KV_KEY).unwrap_or_default();
    let mut w = Worker { shared: shared.clone(), fw, db, tracks: tracks_from_text(&saved), saved, failed: BTreeSet::new(), slow_failed: BTreeSet::new(), qos };
    while shared.sleep(5.0) {
        w.tick();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: f64 = 1024.0 * 1024.0;

    fn quota(action: QuotaAction) -> Quota {
        // 100 MB, warn at 80%.
        Quota { id: 1, app: "app".into(), limit: 100.0, gb: false, warn_pct: 80, action, ..Quota::default() }
    }

    fn track(start: i64) -> Track {
        Track { start, app: "app".into(), ..Track::default() }
    }

    #[test]
    fn levels_follow_the_warning_percentage() {
        assert_eq!(level(79.0, 100.0, 80), QuotaLevel::Ok);
        assert_eq!(level(80.0, 100.0, 80), QuotaLevel::Warn);
        assert_eq!(level(99.9, 100.0, 80), QuotaLevel::Warn);
        assert_eq!(level(100.0, 100.0, 80), QuotaLevel::Over);
        assert_eq!(level(50.0, 100.0, 50), QuotaLevel::Warn);
        assert_eq!(level(5.0, 0.0, 80), QuotaLevel::Ok);
        assert_eq!(level(5.0, f64::NAN, 80), QuotaLevel::Ok);
    }

    #[test]
    fn warns_once_then_alerts_over_once() {
        let q = quota(QuotaAction::AlertOnly);
        let mut t = track(1000);
        assert_eq!(step(&mut t, &q, 1000, 10.0 * MB), Decision::default());
        assert_eq!(step(&mut t, &q, 1000, 85.0 * MB).alert, Some(QuotaLevel::Warn));
        assert_eq!(step(&mut t, &q, 1000, 90.0 * MB).alert, None);
        assert_eq!(step(&mut t, &q, 1000, 100.0 * MB).alert, Some(QuotaLevel::Over));
        assert_eq!(step(&mut t, &q, 1000, 120.0 * MB), Decision::default());
    }

    #[test]
    fn jumping_straight_over_alerts_once() {
        let mut t = track(1000);
        let d = step(&mut t, &quota(QuotaAction::AlertOnly), 1000, 150.0 * MB);
        assert_eq!(d.alert, Some(QuotaLevel::Over));
        assert!(!d.block);
    }

    #[test]
    fn action_none_only_warns() {
        let q = quota(QuotaAction::None);
        let mut t = track(1000);
        assert_eq!(step(&mut t, &q, 1000, 85.0 * MB).alert, Some(QuotaLevel::Warn));
        assert_eq!(step(&mut t, &q, 1000, 101.0 * MB), Decision::default());
    }

    #[test]
    fn block_is_asked_for_until_it_happens() {
        let q = quota(QuotaAction::Block);
        let mut t = track(1000);
        assert!(step(&mut t, &q, 1000, 101.0 * MB).block);
        // The caller could not block (not elevated): it is asked again, but not alerted again.
        let again = step(&mut t, &q, 1000, 102.0 * MB);
        assert!(again.block);
        assert_eq!(again.alert, None);
        t.blocked = true;
        assert_eq!(step(&mut t, &q, 1000, 103.0 * MB), Decision::default());
    }

    #[test]
    fn rollover_releases_the_block_and_rearms_alerts() {
        let q = quota(QuotaAction::Block);
        let mut t = track(1000);
        step(&mut t, &q, 1000, 101.0 * MB);
        t.blocked = true;
        let d = step(&mut t, &q, 2000, 1.0 * MB);
        assert!(d.release);
        assert!(!d.block);
        assert_eq!(t.start, 2000);
        assert_eq!(t.alerted, QuotaLevel::Ok);
        // The release failed: the flag stays so it is retried.
        assert!(t.blocked);
        assert!(step(&mut t, &q, 2000, 1.0 * MB).release);
        t.blocked = false;
        // The new period alerts again.
        assert_eq!(step(&mut t, &q, 2000, 85.0 * MB).alert, Some(QuotaLevel::Warn));
    }

    #[test]
    fn clock_moved_back_starts_a_fresh_period() {
        let q = quota(QuotaAction::Block);
        let mut t = track(5000);
        t.alerted = QuotaLevel::Over;
        t.blocked = true;
        let d = step(&mut t, &q, 1000, 0.0);
        assert!(d.release);
        assert_eq!((t.start, t.alerted), (1000, QuotaLevel::Ok));
    }

    #[test]
    fn raising_the_limit_lifts_the_block() {
        let mut q = quota(QuotaAction::Block);
        let mut t = track(1000);
        step(&mut t, &q, 1000, 101.0 * MB);
        t.blocked = true;
        q.limit = 200.0;
        let d = step(&mut t, &q, 1000, 101.0 * MB);
        assert!(d.release);
        assert_eq!(t.alerted, QuotaLevel::Ok);
        t.blocked = false;
        // Using up the new limit alerts again.
        assert_eq!(step(&mut t, &q, 1000, 201.0 * MB).alert, Some(QuotaLevel::Over));
    }

    #[test]
    fn deleted_disabled_or_retargeted_quotas_orphan_their_track() {
        let t = track(1000);
        let q = quota(QuotaAction::Block);
        assert!(!orphaned(&t, Some(&q)));
        assert!(orphaned(&t, None));
        assert!(orphaned(&t, Some(&Quota { enabled: false, ..q.clone() })));
        assert!(orphaned(&t, Some(&Quota { app: "other".into(), ..q })));
    }

    #[test]
    fn tracks_round_trip_through_text() {
        let mut m = BTreeMap::new();
        m.insert(1, Track { start: 1_760_000_000, alerted: QuotaLevel::Over, blocked: true, app: r"c:\program files\x\y.exe".into(), throttled: true });
        m.insert(7, Track { start: 5, alerted: QuotaLevel::Warn, blocked: false, app: String::new(), throttled: false });
        assert_eq!(tracks_from_text(&tracks_to_text(&m)), m);
        assert!(tracks_from_text("garbage\n\n1\tx").is_empty());
        // A line saved before the throttle flag existed still reads.
        let old = tracks_from_text("3\t10\t2\t1\tc:\\a.exe");
        assert_eq!(old[&3], Track { start: 10, alerted: QuotaLevel::Over, blocked: true, app: "c:\\a.exe".into(), throttled: false });
    }

    #[test]
    fn throttle_comes_first_and_block_follows() {
        let q = quota(QuotaAction::ThrottleBlock);
        let mut t = track(1000);
        let warn = step(&mut t, &q, 1000, 85.0 * MB);
        assert!(warn.throttle && !warn.block);
        t.throttled = true;
        let over = step(&mut t, &q, 1000, 101.0 * MB);
        assert!(over.block && !over.throttle, "already slowed, now blocked");
        t.blocked = true;
        // A raised limit lifts both.
        let ok = step(&mut t, &q, 1000, 10.0 * MB);
        assert!(ok.release && ok.unthrottle);
    }

    #[test]
    fn throttle_only_waits_for_the_limit() {
        let q = quota(QuotaAction::Throttle);
        let mut t = track(1000);
        assert!(!step(&mut t, &q, 1000, 85.0 * MB).throttle);
        let over = step(&mut t, &q, 1000, 100.0 * MB);
        assert!(over.throttle && !over.block);
        t.throttled = true;
        // New period: usage restarts, the cap comes off.
        assert!(step(&mut t, &q, 2000, 1.0 * MB).unthrottle);
        // Other actions never throttle.
        let mut t = track(1000);
        assert!(!step(&mut t, &quota(QuotaAction::Block), 1000, 150.0 * MB).throttle);
    }

    #[test]
    fn usage_counts_internet_traffic_of_the_period_only() {
        use crate::live::db::{KIND_LAN, KIND_WAN, TrafficDelta};
        let mut db = Db::memory();
        let now = clock::now_unix();
        let start = clock::period_start(now, PeriodKind::Month);
        let d = |app_id, kind, down, up| TrafficDelta { app_id, remote: "x".into(), proto: String::new(), kind, down, up };
        db.add_traffic(now, &[d(1, KIND_WAN, 1000, 200), d(1, KIND_LAN, 500, 50), d(2, KIND_WAN, 70, 0)]).unwrap();
        // Last period's traffic is not counted.
        db.add_traffic(start - 86_400, &[d(1, KIND_WAN, 9999, 0)]).unwrap();
        assert_eq!(db.quota_used(Some(1), start, now + 1).unwrap(), 1200.0);
        assert_eq!(db.quota_used(None, start, now + 1).unwrap(), 1270.0);
        assert_eq!(db.quota_used(Some(3), start, now + 1).unwrap(), 0.0);
    }
}
