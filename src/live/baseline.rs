//! Behaviour baselines. For each program: which countries and networks it usually talks to, how
//! much it moves in a day and which hours it is active in. Built from the stored traffic history
//! and kept locally. A worker raises an anomaly alert when a program steps outside that, and
//! "mark as normal" on the alert teaches the baseline. The rules are pure, so the tests use
//! synthetic histories and need no OS.

use super::alerts::AlertKind;
use super::asn;
use super::db::{AppRecord, BASE_ALERTED, BASE_LEARNED, BASE_NORMAL, BaselineItem, Db};
use super::geo::Geo;
use super::store::Shared;
use crate::clock;
use crate::data::StatusNote;
use crate::settings::{NetInfoSource, Settings};
use crate::util::fmt_bytes;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

const DAY: i64 = 86_400;
const MB: f64 = 1024.0 * 1024.0;
/// A day never counts as a spike below this, whatever the history says.
const VOLUME_FLOOR: f64 = 50.0 * MB;
/// The smallest deviation the volume rule uses, so a flat history doesn't alert on noise.
const SPREAD_FLOOR: f64 = MB;
/// An hour with less traffic than this is not activity.
const BUSY_HOUR: f64 = MB;
/// How often the worker looks, in seconds.
const TICK_SECS: f64 = 60.0;
const DIM_COUNTRY: &str = "country";
const DIM_ASN: &str = "asn";
const DIM_HOUR: &str = "hour";
const DIM_VOLUME: &str = "volume";
const KV_CURSOR: &str = "baseline_cursor";
const KV_ASN_CURSOR: &str = "baseline_asn_cursor";
/// How many known values an alert names as "usual".
const USUAL_SHOWN: usize = 4;

pub fn median(values: &[f64]) -> f64 {
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    match v.len() {
        0 => 0.0,
        n if n % 2 == 1 => v[n / 2],
        n => (v[n / 2 - 1] + v[n / 2]) / 2.0,
    }
}

/// Median absolute deviation, scaled like a standard deviation for normal data. One huge day
/// barely moves it, unlike the mean and standard deviation.
pub fn mad(values: &[f64]) -> f64 {
    let m = median(values);
    let dev: Vec<f64> = values.iter().map(|v| (v - m).abs()).collect();
    median(&dev) * 1.4826
}

/// The most a day may move before it counts as a spike: the median plus five robust deviations.
pub fn volume_limit(daily: &[f64]) -> f64 {
    let m = median(daily);
    let spread = mad(daily).max(m / 10.0).max(SPREAD_FLOOR);
    (m + 5.0 * spread).max(VOLUME_FLOOR)
}

/// An hour is unusual when the program was active in it on fewer than a tenth of the `days` seen
/// (and on at least one day).
pub fn unusual_hour(days_active: u32, days: u32) -> bool {
    f64::from(days_active) < (f64::from(days) / 10.0).max(1.0)
}

/// A program that first appeared less than `learn_days` ago only learns and never alerts.
pub fn learning(first_seen: i64, now: i64, learn_days: u32) -> bool {
    now - first_seen < i64::from(learn_days) * DAY
}

/// Whether an alert for the same thing was raised within the throttle window.
pub fn throttled(alerted: i64, now: i64, hours: u32) -> bool {
    alerted > 0 && now - alerted < i64::from(hours) * 3600
}

/// Local day number and hour of the day for a unix time.
pub fn local_day_hour(ts: i64) -> (i64, u32) {
    let local = clock::to_local(ts);
    (local.div_euclid(DAY), (local.rem_euclid(DAY) / 3600) as u32)
}

/// For each hour of the day, on how many distinct days the program was active in it.
/// `active` holds one (local day, local hour) pair per busy bucket.
pub fn active_days_by_hour(active: &[(i64, u32)]) -> [u32; 24] {
    let distinct: BTreeSet<(i64, u32)> = active.iter().copied().collect();
    let mut out = [0u32; 24];
    for (_, hour) in distinct {
        if let Some(n) = out.get_mut(hour as usize) {
            *n += 1;
        }
    }
    out
}

/// The alert text for a country the baseline didn't know, with the usual ones named.
pub fn country_why(usual: &[String]) -> String {
    format!("contacted a country it has not used before; usual: {}.", list(usual))
}

/// The AS number at the front of a net-info answer such as "AS15169 · Google LLC".
pub fn network_of(info: &str) -> Option<&str> {
    info.split(" · ").next().filter(|n| !n.is_empty())
}

pub fn network_why(usual: &[String]) -> String {
    format!("contacted a network it has not used before; usual: {}.", list(usual))
}

pub fn volume_why(today: f64, median: f64, limit: f64) -> String {
    format!("moved {} today; usual about {} a day (limit {}).", fmt_bytes(today), fmt_bytes(median), fmt_bytes(limit))
}

pub fn hour_why(hour: u32, days_active: u32, days: u32) -> String {
    format!("was active at {hour:02}:00, an hour it was active in on only {days_active} of the last {days} days.")
}

fn list(values: &[String]) -> String {
    if values.is_empty() {
        return "none yet".into();
    }
    let mut s = values.iter().take(USUAL_SHOWN).cloned().collect::<Vec<_>>().join(", ");
    if values.len() > USUAL_SHOWN {
        s.push_str(&format!(" and {} more", values.len() - USUAL_SHOWN));
    }
    s
}

struct Worker {
    shared: Arc<Shared>,
    db: Db,
    geo: Geo,
    asn: Arc<asn::Resolver>,
}

impl Worker {
    fn tick(&mut self, s: &Settings) {
        let now = clock::now_unix();
        if !self.shared.state().etw {
            self.shared.set_note("baseline", Some(StatusNote::warn("Behaviour baseline is paused: per-program traffic isn't being measured (run as administrator).")));
            return;
        }
        self.shared.set_note("baseline", None);
        let Ok(apps) = self.db.apps() else { return };
        self.learn_countries(now, s, &apps);
        if s.baseline_networks && s.net_info != NetInfoSource::Off {
            self.learn_networks(now, s, &apps);
        }
        let _ = self.db.prune_baseline(now, s.baseline_days);
        for app in apps.iter().filter(|a| !learning(a.first_seen, now, s.baseline_learn_days)) {
            self.check_volume(app, now, s);
            self.check_hours(app, now, s);
        }
    }

    /// Countries every program has contacted since the last scan, learned or checked against the baseline.
    fn learn_countries(&mut self, now: i64, s: &Settings, apps: &[AppRecord]) {
        let from = self.db.kv_get(KV_CURSOR).and_then(|v| v.parse().ok()).unwrap_or(0);
        let Ok(groups) = self.db.wan_remotes_since(from) else {
            return;
        };
        for (app_id, remote, _) in groups {
            let (Ok(ip), Some(app)) = (remote.parse::<IpAddr>(), apps.iter().find(|a| a.id == app_id)) else {
                continue;
            };
            let code = self.geo.place(ip).code();
            if code.is_empty() || code == "LOCAL" {
                continue;
            }
            self.observe(app, DIM_COUNTRY, &code, &format!("{remote} ({code})"), country_why, now, s);
        }
        let newest = self.db.newest_bucket().unwrap_or(from);
        let _ = self.db.kv_set(KV_CURSOR, &newest.to_string());
    }

    /// Networks (AS numbers) from the net-info lookup. The lookup answers later, so addresses it
    /// hasn't resolved yet hold the cursor back until a later scan.
    /// shortcut: an address the lookup never answers holds the cursor back, so this scan grows until that traffic expires; skip such addresses after a few tries.
    fn learn_networks(&mut self, now: i64, s: &Settings, apps: &[AppRecord]) {
        let from = self.db.kv_get(KV_ASN_CURSOR).and_then(|v| v.parse().ok()).unwrap_or(0);
        let Ok(groups) = self.db.wan_remotes_since(from) else {
            return;
        };
        let mut next = self.db.newest_bucket().unwrap_or(from);
        for (app_id, remote, first) in groups {
            let Some(app) = apps.iter().find(|a| a.id == app_id) else {
                continue;
            };
            let info = self.asn.get(&remote);
            let Some(network) = network_of(&info) else {
                next = next.min(first);
                continue;
            };
            self.observe(app, DIM_ASN, network, &format!("{remote} ({info})"), network_why, now, s);
        }
        let _ = self.db.kv_set(KV_ASN_CURSOR, &next.to_string());
    }

    /// Records that `app` used `val` in `dim`. A value the baseline doesn't know raises an alert,
    /// unless the program is still learning or the same alert was raised within the throttle window.
    #[allow(clippy::too_many_arguments)]
    fn observe(&mut self, app: &AppRecord, dim: &str, val: &str, target: &str, why: fn(&[String]) -> String, now: i64, s: &Settings) {
        let items = self.db.baseline_items(app.id, dim).unwrap_or_default();
        let usual: Vec<String> = items.iter().filter(|i| i.state != BASE_ALERTED).map(|i| i.val.clone()).collect();
        let existing = items.iter().find(|i| i.val == val).cloned();
        let mut item = existing.clone().unwrap_or_else(|| new_item(dim, val, now));
        item.last_seen = now;
        let known = existing.as_ref().is_some_and(|i| i.state != BASE_ALERTED);
        let quiet = known || learning(app.first_seen, now, s.baseline_learn_days) || existing.as_ref().is_some_and(|i| throttled(i.alerted, now, s.baseline_throttle_hours));
        if quiet {
            self.save(app, &item);
            return;
        }
        let text = why(&usual);
        let country = if dim == DIM_COUNTRY { val } else { "" };
        item.alert_id = self.alert(app, AlertKind::AnomalyContact, &text, target, country);
        item.state = BASE_ALERTED;
        item.alerted = now;
        self.save(app, &item);
    }

    /// Raises a volume spike once a day: today's bytes so far against the median and spread of the last `baseline_days` full days.
    fn check_volume(&mut self, app: &AppRecord, now: i64, s: &Settings) {
        let (today, _) = local_day_hour(now);
        let Ok(buckets) = self.db.wan_buckets(app.id, now - (i64::from(s.baseline_days) + 1) * DAY, now + 1) else {
            return;
        };
        let mut days: BTreeMap<i64, f64> = BTreeMap::new();
        for (ts, bytes) in buckets {
            *days.entry(local_day_hour(ts).0).or_default() += bytes;
        }
        let history: Vec<f64> = (today - i64::from(s.baseline_days)..today).map(|d| days.get(&d).copied().unwrap_or(0.0)).collect();
        let used = days.get(&today).copied().unwrap_or(0.0);
        let limit = volume_limit(&history);
        if used <= limit {
            return;
        }
        let items = self.db.baseline_items(app.id, DIM_VOLUME).unwrap_or_default();
        let key = today.to_string();
        if items.iter().any(|i| i.val == key) {
            // One alert a day; a day the user marked normal stays quiet.
            return;
        }
        let mut item = new_item(DIM_VOLUME, &key, now);
        let text = volume_why(used, median(&history), limit);
        item.alert_id = self.alert(app, AlertKind::AnomalyVolume, &text, "", "");
        item.state = BASE_ALERTED;
        item.alerted = now;
        self.save(app, &item);
    }

    /// Raises an alert when the program is busy now at an hour it has almost never been active in.
    fn check_hours(&mut self, app: &AppRecord, now: i64, s: &Settings) {
        let (today, hour) = local_day_hour(now);
        let Ok(buckets) = self.db.wan_buckets(app.id, now - i64::from(s.baseline_days) * DAY, now + 1) else {
            return;
        };
        let mut current = 0.0;
        let mut active = Vec::new();
        for (ts, bytes) in buckets.iter().filter(|(_, b)| *b > 0.0) {
            let (day, h) = local_day_hour(*ts);
            if day == today {
                if h == hour {
                    current += bytes;
                }
                continue;
            }
            active.push((day, h));
        }
        if current < BUSY_HOUR {
            return;
        }
        let days = (i64::from(s.baseline_days)).min((now - app.first_seen) / DAY).max(1) as u32;
        let days_active = active_days_by_hour(&active)[hour as usize];
        if !unusual_hour(days_active, days) {
            return;
        }
        let items = self.db.baseline_items(app.id, DIM_HOUR).unwrap_or_default();
        let mut item = items.iter().find(|i| i.val == hour.to_string()).cloned().unwrap_or_else(|| new_item(DIM_HOUR, &hour.to_string(), now));
        if item.state == BASE_NORMAL || throttled(item.alerted, now, s.baseline_throttle_hours) {
            return;
        }
        let text = hour_why(hour, days_active, days);
        item.alert_id = self.alert(app, AlertKind::AnomalyHour, &text, "", "");
        item.state = BASE_ALERTED;
        item.alerted = now;
        item.last_seen = now;
        self.save(app, &item);
    }

    fn alert(&self, app: &AppRecord, kind: AlertKind, text: &str, target: &str, country: &str) -> Option<i64> {
        self.shared.alert_as(&self.db, kind, &app.name, text, target, country, false)
    }

    fn save(&self, app: &AppRecord, item: &BaselineItem) {
        let _ = self.db.save_baseline_item(app.id, item);
    }
}

fn new_item(dim: &str, val: &str, now: i64) -> BaselineItem {
    BaselineItem { dim: dim.into(), val: val.into(), first_seen: now, last_seen: now, state: BASE_LEARNED, alerted: 0, alert_id: None }
}

pub fn run(shared: Arc<Shared>, asn: Arc<asn::Resolver>) {
    let Ok(db) = shared.open_db() else {
        shared.set_note("baseline", Some(StatusNote::warn("Behaviour baseline is off: the database couldn't be opened.")));
        return;
    };
    let geo = Geo::open(shared.settings().geo_path().as_deref());
    let mut w = Worker { shared: shared.clone(), db, geo, asn };
    while shared.sleep(TICK_SECS) {
        let s = shared.settings();
        if s.baseline {
            w.tick(&s);
        } else {
            shared.set_note("baseline", None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_and_mad_ignore_one_huge_day() {
        assert_eq!(median(&[]), 0.0);
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), 2.5);
        // One 2 GB day moves the median very little, while the mean would jump.
        let mut days = vec![100.0 * MB; 13];
        days.push(2048.0 * MB);
        assert_eq!(median(&days), 100.0 * MB);
        assert!(mad(&days) < 1.0 * MB);
    }

    #[test]
    fn volume_limit_flags_only_real_spikes() {
        // Around 100 MB a day with some noise.
        let noisy: Vec<f64> = (0..14).map(|i| (95.0 + f64::from(i % 5) * 2.0) * MB).collect();
        let limit = volume_limit(&noisy);
        assert!(110.0 * MB <= limit, "a normal day must stay under {limit}");
        assert!(2048.0 * MB > limit, "2 GB is a spike");
    }

    #[test]
    fn flat_history_uses_the_floors() {
        // No spread at all: the floor keeps a 10 MB day from alerting, a 60 MB day is still under the 50 MB floor only when the median is small.
        let flat = [10.0 * MB; 14];
        assert_eq!(volume_limit(&flat), VOLUME_FLOOR);
        assert!(volume_limit(&flat) > 10.0 * MB);
        assert_eq!(volume_limit(&[]), VOLUME_FLOOR);
    }

    #[test]
    fn hours_outside_the_usual_span_are_unusual() {
        // Active 08:00 to 23:00 on all 14 days, never at 03:00.
        let mut active = Vec::new();
        for day in 0..14 {
            for h in 8..23 {
                active.push((day, h));
            }
        }
        let counts = active_days_by_hour(&active);
        assert!(unusual_hour(counts[3], 14));
        assert!(!unusual_hour(counts[10], 14));
        // One past 03:00 day out of 14 is still under the 10% line.
        let once = active_days_by_hour(&[(0, 3)]);
        assert!(unusual_hour(once[3], 14));
        // The same day repeated at one hour counts once.
        assert_eq!(active_days_by_hour(&[(0, 3), (0, 3), (1, 3)])[3], 2);
    }

    #[test]
    fn learning_and_throttle_windows() {
        let day = DAY;
        let now = 100 * day;
        assert!(learning(now - 3 * day, now, 7));
        assert!(!learning(now - 7 * day, now, 7));
        assert!(throttled(now - 3600, now, 24));
        assert!(!throttled(now - 25 * 3600, now, 24));
        assert!(!throttled(0, now, 24), "never alerted is not throttled");
    }

    #[test]
    fn network_comes_from_the_answer_front() {
        assert_eq!(network_of("AS15169 · Google LLC"), Some("AS15169"));
        assert_eq!(network_of(""), None);
    }

    #[test]
    fn alert_text_says_why() {
        assert!(country_why(&["US".into(), "NL".into()]).contains("usual: US, NL."));
        assert!(country_why(&[]).contains("usual: none yet."));
        let many: Vec<String> = ["A", "B", "C", "D", "E", "F"].iter().map(|s| s.to_string()).collect();
        assert!(country_why(&many).ends_with("usual: A, B, C, D and 2 more."));
        assert!(hour_why(3, 0, 14).starts_with("was active at 03:00"));
        assert!(volume_why(1800.0 * MB, 120.0 * MB, 200.0 * MB).contains("moved 1.8 GB today"));
    }

    /// Synthetic history: `days` days, each active 08:00-22:00 and moving 100 MB spread over those hours,
    /// all for app 1 to one address. Returns the database and the time just after the history.
    fn seeded(days: i64) -> (Db, i64) {
        let mut db = Db::memory();
        let now = clock::now_unix();
        let start = now - days * DAY;
        for d in 0..days {
            for h in 8..22 {
                let ts = start + d * DAY + h * 3600;
                let down = (100.0 * MB / 14.0) as u64;
                let row = crate::live::db::TrafficDelta { app_id: 1, remote: "203.0.113.7".into(), proto: "TCP".into(), kind: crate::live::db::KIND_WAN, down, up: 0 };
                db.add_traffic(ts, &[row]).unwrap();
            }
        }
        (db, now)
    }

    #[test]
    fn synthetic_history_reads_back_per_hour() {
        let (db, now) = seeded(14);
        let buckets = db.wan_buckets(1, now - 14 * DAY, now + 1).unwrap();
        let active: Vec<(i64, u32)> = buckets.iter().map(|(ts, _)| local_day_hour(*ts)).collect();
        let counts = active_days_by_hour(&active);
        // Seeded busy for 14 hours a day. A daylight-saving change inside the window shifts those hours
        // by one, so most busy hours reach every day and the rest reach most of them.
        assert!(counts.iter().filter(|&&c| c >= 13).count() >= 10, "{counts:?}");
        assert!(counts.iter().filter(|&&c| c == 0).count() >= 8, "{counts:?}");
        assert!(buckets.iter().map(|(_, b)| b).sum::<f64>() > 90.0 * MB);
    }

    #[test]
    fn baseline_items_round_trip_and_mark_normal() {
        let db = Db::memory();
        let now = 1_000_000;
        let item = BaselineItem { dim: DIM_COUNTRY.into(), val: "DE".into(), first_seen: now, last_seen: now, state: BASE_ALERTED, alerted: now, alert_id: Some(42) };
        db.save_baseline_item(1, &item).unwrap();
        assert_eq!(db.baseline_items(1, DIM_COUNTRY).unwrap(), vec![item.clone()]);
        assert!(db.baseline_items(2, DIM_COUNTRY).unwrap().is_empty());
        assert!(db.mark_normal(42, now + 10).unwrap());
        assert!(!db.mark_normal(7, now).unwrap());
        let got = &db.baseline_items(1, DIM_COUNTRY).unwrap()[0];
        assert_eq!((got.state, got.last_seen), (BASE_NORMAL, now + 10));
    }

    #[test]
    fn prune_forgets_old_items_but_keeps_normal_ones() {
        let db = Db::memory();
        let now = 100 * DAY;
        let old = |val: &str, state| BaselineItem { dim: DIM_ASN.into(), val: val.into(), first_seen: 0, last_seen: now - 20 * DAY, state, alerted: 0, alert_id: None };
        db.save_baseline_item(1, &old("AS1", BASE_LEARNED)).unwrap();
        db.save_baseline_item(1, &old("AS2", BASE_NORMAL)).unwrap();
        db.prune_baseline(now, 14).unwrap();
        let left: Vec<String> = db.baseline_items(1, DIM_ASN).unwrap().into_iter().map(|i| i.val).collect();
        assert_eq!(left, vec!["AS2".to_string()]);
    }

    #[test]
    fn new_remote_is_listed_from_the_cursor_only() {
        let (db, now) = seeded(3);
        let all = db.wan_remotes_since(0).unwrap();
        assert_eq!(all.len(), 1);
        let newest = db.newest_bucket().unwrap();
        assert!(newest <= now);
        // Nothing new after the newest bucket.
        assert!(db.wan_remotes_since(newest + 1).unwrap().is_empty());
    }
}
