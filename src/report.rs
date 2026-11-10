//! The weekly summary: what happened over the last seven days. It is shown from the Alerts tab, and sent through
//! External Notifications on the weekday and hour chosen in Settings (off by default, and it sends nothing
//! unless a notification service is set up there).

use crate::clock;
use crate::data::StatusNote;
use crate::live::alerts::AlertKind;
use crate::live::bucket::Scale;
use crate::live::db::Db;
use crate::live::geo::{Geo, Place};
use crate::live::store::Shared;
use crate::settings::Settings;
use crate::util::fmt_bytes;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

const TICK_SECS: f64 = 60.0;
const KV_LAST: &str = "report_last";
const WEEK: i64 = 7 * 86_400;
/// Items listed per line; the rest are only counted.
const LISTED: usize = 5;
/// Discord rejects messages over 2000 characters, the smallest limit among the services.
const MAX_CHARS: usize = 1800;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Report {
    /// Unix seconds the seven days end at.
    pub until: i64,
    /// Busiest apps first: name, bytes down plus up.
    pub top_apps: Vec<(String, f64)>,
    /// `None` when the history does not reach back before the week, so everything would look new.
    pub new_hosts: Option<Vec<String>>,
    pub new_countries: Option<Vec<String>>,
    /// Alerts per kind label, most first.
    pub alerts: Vec<(String, u64)>,
    pub blocked: u64,
    pub quota_events: u64,
    /// Pinged hosts and thinkbroadband monitors: label, average ms, average loss in percent.
    pub ping: Vec<(String, f32, f32)>,
    pub broadband: Vec<(String, f32, f32)>,
    /// Bytes down plus up per day, oldest first, each day starting at the unix time given.
    pub daily: Vec<(i64, f64)>,
}

impl Report {
    /// Plain text, short enough for every notification service.
    pub fn to_text(&self) -> String {
        let mut out = format!("RustWarden weekly summary, 7 days to {}\n", clock::fmt_date(self.until));
        let apps: Vec<String> = self.top_apps.iter().take(LISTED).map(|(n, b)| format!("{n} {}", fmt_bytes(*b))).collect();
        out += &format!("Top apps: {}\n", if apps.is_empty() { "none".into() } else { apps.join(", ") });
        out += &new_line("New hosts", &self.new_hosts);
        out += &new_line("New countries", &self.new_countries);
        let total: u64 = self.alerts.iter().map(|(_, n)| n).sum();
        let kinds: Vec<String> = self.alerts.iter().take(LISTED).map(|(k, n)| format!("{k} {n}")).collect();
        out += &format!("Alerts: {total}{}\n", if kinds.is_empty() { String::new() } else { format!(" ({})", kinds.join(", ")) });
        out += &format!("Blocked connections: {}\nQuota events: {}\n", self.blocked, self.quota_events);
        for (title, rows) in [("Ping", &self.ping), ("Broadband", &self.broadband)] {
            for (name, avg, loss) in rows {
                out += &format!("{title} {name}: avg {avg:.0} ms, loss {loss:.1}%\n");
            }
        }
        if out.chars().count() > MAX_CHARS {
            out = out.chars().take(MAX_CHARS - 1).collect::<String>() + "…";
        }
        out
    }
}

pub(crate) fn new_line(title: &str, items: &Option<Vec<String>>) -> String {
    match items {
        None => format!("{title}: not enough history yet\n"),
        Some(v) if v.is_empty() => format!("{title}: none\n"),
        Some(v) => format!("{title}: {} ({}{})\n", v.len(), v.iter().take(LISTED).cloned().collect::<Vec<_>>().join(", "), if v.len() > LISTED { ", …" } else { "" }),
    }
}

/// Mean of the finite averages and losses, or `None` without samples.
/// The hosts the ping plugin keeps in its settings (`id<TAB>address<TAB>name` per line) as (id, label).
fn ping_hosts(config: &std::collections::BTreeMap<String, String>) -> Vec<(u32, String)> {
    config
        .get("hosts")
        .map(|h| h.as_str())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut p = l.splitn(3, '\t');
            let (id, address, name) = (p.next()?.parse().ok()?, p.next()?, p.next().unwrap_or(""));
            Some((id, if name.is_empty() { address } else { name }.to_owned()))
        })
        .collect()
}

/// The graphs the thinkbroadband plugin keeps in its settings (`id<TAB>name` per line) as (id, name).
fn tbb_monitors(config: &std::collections::BTreeMap<String, String>) -> Vec<(u32, String)> {
    config.get("monitors").map(|m| m.as_str()).unwrap_or_default().lines().filter_map(|l| l.split_once('\t').and_then(|(id, name)| Some((id.parse().ok()?, name.to_owned())))).collect()
}

/// The thinkbroadband plugin's stored samples for one graph since `since`; empty when the plugin never ran.
fn tbb_samples(db: &crate::live::db::Db, monitor: u32, since: i64) -> Vec<crate::plugins::core::latency::Sample> {
    use crate::plugins::core::latency::Sample;
    let read = || -> rusqlite::Result<Vec<Sample>> {
        let mut stmt = db.conn.prepare("SELECT ts, min, avg, max, loss FROM p_thinkbroadband__samples WHERE monitor = ?1 AND ts >= ?2 ORDER BY ts")?;
        stmt.query_map(rusqlite::params![monitor, since], |r| Ok(Sample { ts: r.get(0)?, min: r.get(1)?, avg: r.get(2)?, max: r.get(3)?, loss: r.get(4)? }))?.collect()
    };
    read().unwrap_or_default()
}

/// The ping plugin's stored rounds for one host since `since`; empty when the plugin never ran.
fn ping_samples(db: &crate::live::db::Db, host: u32, since: i64) -> Vec<crate::plugins::core::latency::Sample> {
    use crate::plugins::core::latency::Sample;
    let read = || -> rusqlite::Result<Vec<Sample>> {
        let mut stmt = db.conn.prepare("SELECT ts, min, avg, max, loss FROM p_ping__samples WHERE host = ?1 AND ts >= ?2 ORDER BY ts")?;
        stmt.query_map(rusqlite::params![host, since], |r| Ok(Sample { ts: r.get(0)?, min: r.get(1)?, avg: r.get(2)?, max: r.get(3)?, loss: r.get(4)? }))?.collect()
    };
    read().unwrap_or_default()
}

fn mean(samples: &[crate::plugins::core::latency::Sample]) -> Option<(f32, f32)> {
    let good: Vec<_> = samples.iter().filter(|s| s.avg.is_finite() && s.loss.is_finite()).collect();
    if good.is_empty() {
        return None;
    }
    let n = good.len() as f32;
    Some((good.iter().map(|s| s.avg).sum::<f32>() / n, good.iter().map(|s| s.loss).sum::<f32>() / n))
}

fn country_of(geo: &Geo, ip: &str) -> Option<String> {
    match geo.place(ip.parse::<IpAddr>().ok()?) {
        place @ Place::Country(_) => Some(place.label().to_owned()),
        _ => None,
    }
}

/// Builds the report for the seven days up to `now`. Reads the database and the geo database, so callers run it off the UI thread.
pub fn build(db: &Db, geo: &Geo, _s: &Settings, now: i64) -> rusqlite::Result<Report> {
    let (t0, t1) = (now - WEEK, now + 1);
    let names: HashMap<String, String> = db.apps()?.into_iter().map(|a| (a.id.to_string(), a.name)).collect();
    // usage_by_app is already busiest first.
    let top_apps = db.usage_by_app(Scale::S600, t0, t1)?.into_iter().map(|u| (names.get(&u.key).cloned().unwrap_or(u.key), u.down + u.up)).collect();

    let (mut new_hosts, mut new_countries) = (None, None);
    if db.history_start()?.is_some_and(|start| start < t0) {
        let before: HashSet<String> = db.wan_remotes_between(i64::MIN, t0)?.into_iter().collect();
        let week = db.wan_remotes_between(t0, t1)?;
        let host_names: HashMap<String, String> = db.hostnames()?.into_iter().collect();
        let mut hosts: Vec<String> = week.iter().filter(|r| !before.contains(*r)).map(|r| host_names.get(r).cloned().unwrap_or_else(|| r.clone())).collect();
        hosts.sort();
        new_hosts = Some(hosts);
        let known: HashSet<String> = before.iter().filter_map(|r| country_of(geo, r)).collect();
        let mut countries: Vec<String> = week.iter().filter(|r| !before.contains(*r)).filter_map(|r| country_of(geo, r)).filter(|c| !known.contains(c)).collect::<HashSet<_>>().into_iter().collect();
        countries.sort();
        new_countries = Some(countries);
    }

    let mut counts = db.alert_counts_between(t0, t1)?;
    let quota_events = counts.iter().find(|(k, _)| k == AlertKind::Quota.key()).map_or(0, |(_, n)| *n);
    counts.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let alerts = counts.into_iter().map(|(k, n)| (AlertKind::label_for_key(&k).to_owned(), n)).collect();
    let blocked = db.blocked_by_remote(t0, t1)?.iter().map(|(_, n)| u64::from(*n)).sum();

    let mut ping = Vec::new();
    for (id, label) in ping_hosts(&crate::plugins::wasm::manager::saved_config("ping")) {
        if let Some((avg, loss)) = mean(&ping_samples(db, id, t0)) {
            ping.push((label, avg, loss));
        }
    }
    let mut broadband = Vec::new();
    for (id, name) in tbb_monitors(&crate::plugins::wasm::manager::saved_config("thinkbroadband")) {
        if let Some((avg, loss)) = mean(&tbb_samples(db, id, t0)) {
            broadband.push((name, avg, loss));
        }
    }
    let mut daily = Vec::new();
    for day in 0..7 {
        let d0 = t0 + day * 86_400;
        let t = db.totals(Scale::S600, d0, d0 + 86_400)?;
        daily.push((d0, t.down + t.up));
    }
    Ok(Report { until: now, top_apps, new_hosts, new_countries, alerts, blocked, quota_events, ping, broadband, daily })
}

/// Unix time of the latest slot (`weekday` 0 = Monday, local `hour`) at or before `now`.
pub fn last_slot(now: i64, weekday: u8, hour: u8) -> i64 {
    let local = clock::to_local(now);
    let today = local.div_euclid(86_400);
    // 1970-01-01 was a Thursday, weekday 3 counting from Monday.
    let back = (today + 3 - i64::from(weekday)).rem_euclid(7);
    let mut slot_local = (today - back) * 86_400 + i64::from(hour) * 3600;
    if slot_local > local {
        slot_local -= WEEK;
    }
    now - (local - slot_local)
}

/// A report is due once a slot has passed since the last one was sent. A clock set back leaves it not due until time catches up.
pub fn due(now: i64, last_sent: i64, weekday: u8, hour: u8) -> bool {
    last_sent < last_slot(now, weekday, hour)
}

/// Sends the report on schedule. Turning it on does not send at once: the first report goes at the next slot.
pub fn run(shared: Arc<Shared>) {
    let Ok(db) = shared.open_db() else {
        shared.set_note("report", Some(StatusNote::warn("The weekly report is off: the database couldn't be opened.")));
        return;
    };
    let geo = Geo::open(shared.settings().geo_path().as_deref());
    while shared.sleep(TICK_SECS) {
        let s = shared.settings();
        if !s.report {
            shared.set_note("report", None);
            // Keep the schedule armed from now, so switching it back on later doesn't send for a slot passed while it was off.
            let _ = db.kv_set(KV_LAST, &clock::now_unix().to_string());
            continue;
        }
        let now = clock::now_unix();
        let Some(last) = db.kv_get(KV_LAST).and_then(|v| v.parse::<i64>().ok()) else {
            let _ = db.kv_set(KV_LAST, &now.to_string());
            continue;
        };
        if !due(now, last, s.report_weekday, s.report_hour) {
            continue;
        }
        match build(&db, &geo, &s, now) {
            Ok(report) => {
                crate::plugins::wasm::manager::broadcast_alert(false, "RustWarden weekly summary", &report.to_text());
                let _ = db.kv_set(KV_LAST, &now.to_string());
                shared.set_note("report", None);
            }
            Err(e) => shared.set_note("report", Some(StatusNote::warn(format!("The weekly report couldn't be built ({e}); it will be tried again.")))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::db::{AppRecord, KIND_WAN, TrafficDelta};

    fn sample() -> Report {
        Report {
            until: 1_800_000_000,
            top_apps: vec![("Chrome".into(), 4.0e9), ("Spotify".into(), 1.0e9)],
            new_hosts: Some(vec!["a.example".into(), "b.example".into()]),
            new_countries: Some(vec![]),
            alerts: vec![("New device".into(), 3), ("Data quotas".into(), 1)],
            blocked: 12,
            quota_events: 1,
            ping: vec![("1.1.1.1".into(), 12.4, 0.25)],
            broadband: vec![],
            daily: vec![],
        }
    }

    #[test]
    fn text_lists_every_section() {
        let text = sample().to_text();
        assert!(text.contains(&format!("Top apps: Chrome {}, Spotify {}", fmt_bytes(4.0e9), fmt_bytes(1.0e9))), "{text}");
        assert!(text.contains("New hosts: 2 (a.example, b.example)"));
        assert!(text.contains("New countries: none"));
        assert!(text.contains("Alerts: 4 (New device 3, Data quotas 1)"));
        assert!(text.contains("Blocked connections: 12\nQuota events: 1\n"));
        assert!(text.contains("Ping 1.1.1.1: avg 12 ms, loss 0.2%"));
    }

    #[test]
    fn text_says_when_history_is_too_short_and_stays_under_the_limit() {
        let mut r = Report { new_hosts: None, new_countries: None, ..sample() };
        assert!(r.to_text().contains("New hosts: not enough history yet"));
        r.top_apps = (0..500).map(|i| (format!("app-with-a-long-name-{i}"), 1.0)).collect();
        r.ping = (0..200).map(|i| (format!("host-{i}"), 1.0, 0.0)).collect();
        assert!(r.to_text().chars().count() <= MAX_CHARS);
    }

    #[test]
    fn slots_land_on_the_chosen_weekday_and_hour() {
        // Mid-January and mid-July 2026, away from any clock change.
        for now in [1_768_392_000_i64, 1_784_116_800] {
            for weekday in 0..7u8 {
                let slot = last_slot(now, weekday, 12);
                assert!(slot <= now && now - slot < WEEK, "slot {slot} for now {now}");
                let local = clock::to_local(slot);
                assert_eq!(local.rem_euclid(86_400) / 3600, 12);
                assert_eq!((local.div_euclid(86_400) + 3).rem_euclid(7), i64::from(weekday));
            }
        }
    }

    #[test]
    fn a_report_is_due_once_per_slot() {
        // Seven minutes past the hour, so `now` is never on a slot boundary in any time zone.
        let now = 1_768_392_000 + 420;
        let slot = last_slot(now, 2, 12);
        assert!(due(now, slot - 1, 2, 12));
        assert!(!due(now, slot, 2, 12));
        // Sent a minute ago, or the clock was set back: not due.
        assert!(!due(now, now - 60, 2, 12));
        assert!(!due(now, now + 86_400, 2, 12));
    }

    #[test]
    fn build_finds_new_hosts_only_with_older_history() {
        let mut db = Db::memory();
        let app = db.insert_app(&AppRecord { key: "c:\\a.exe".into(), path: "C:\\a.exe".into(), name: "a".into(), first_seen: 1, ..Default::default() }).unwrap();
        let delta = |remote: &str, down| TrafficDelta { app_id: app, remote: remote.into(), proto: "Other".into(), kind: KIND_WAN, down, up: 0 };
        let now = 100 * 86_400;
        let geo = Geo::open(None);
        let s = Settings::default();

        db.add_traffic(now - 2 * 86_400, &[delta("8.8.8.8", 100)]).unwrap();
        assert_eq!(build(&db, &geo, &s, now).unwrap().new_hosts, None);

        db.add_traffic(now - 20 * 86_400, &[delta("1.1.1.1", 5)]).unwrap();
        db.add_traffic(now - 86_400, &[delta("1.1.1.1", 50)]).unwrap();
        db.set_hostname("8.8.8.8", "dns.google", 0).unwrap();
        let r = build(&db, &geo, &s, now).unwrap();
        assert_eq!(r.new_hosts, Some(vec!["dns.google".to_string()]));
        assert_eq!(r.top_apps, vec![("a".to_string(), 150.0)]);
        assert_eq!(r.daily.len(), 7);
        assert_eq!(r.daily.iter().map(|d| d.1).sum::<f64>(), 150.0);
    }
}
