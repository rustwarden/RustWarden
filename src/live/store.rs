//! State shared between the collector threads and the UI-facing `LiveBackend`.
//!
//! Slow-changing history lives in SQLite (each thread opens its own connection; WAL lets
//! them run together). Fast, small state — the hardware ring, current rates, notes — lives
//! here behind short-held mutexes, so the UI thread never waits on a collector.

use super::alerts::AlertKind;
use super::db::{Db, NewAlert};
use crate::data::{Alert, AppIcon, ConnectAsk, Country, HardwareSample, NoteLevel, QuotaStatus, ScanState, StatusNote, Threat};
use crate::settings::AlertLevel;
use crate::settings::Settings;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock};

pub const HW_WINDOW: usize = 300;

/// How an alert is delivered on top of its kind's settings.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Urgency {
    /// As the kind's settings and the alert rules say.
    Normal,
    /// Important whatever the kind's level (e.g. a gateway MAC change).
    Important,
    /// Kept, not pushed: recorded in the Alerts log (already read) and the event log, but no desktop
    /// popup, no unread badge and nothing sent to notification plugins.
    Quiet,
}

impl From<bool> for Urgency {
    fn from(important: bool) -> Self {
        if important { Self::Important } else { Self::Normal }
    }
}

#[derive(Clone, Debug, Default)]
pub struct HwNow {
    pub cpu_pct: f32,
    pub memory_used: f64,
    pub memory_total: f64,
    pub disk_read: f64,
    pub disk_write: f64,
    pub gpu_pct: f32,
    pub gpu_memory: f64,
    pub gpu_available: bool,
}

/// What the traffic collector knows right now (rates are per second).
#[derive(Clone, Debug, Default)]
pub struct TrafficNow {
    pub down_rate: f64,
    pub up_rate: f64,
    /// Rate per app id.
    pub app_rates: HashMap<i64, (f64, f64)>,
    /// Remote addresses with an open connection, per app id.
    pub app_hosts: HashMap<i64, Vec<IpAddr>>,
    /// Apps with network activity in the last minute, by app id.
    pub active_apps: Vec<i64>,
    /// File name of the process that started each app, by app id.
    pub app_parents: HashMap<i64, String>,
    /// Process ids of each service row (svchost.exe split by service), by the row's key.
    pub service_pids: HashMap<String, Vec<u32>>,
}

#[derive(Clone, Debug, Default)]
pub struct NetworkInfo {
    /// Stable key: adapter name plus gateway.
    pub key: String,
    pub label: String,
}

/// Windows Firewall as last read by the firewall collector.
#[derive(Clone, Debug, Default)]
pub struct FwSnapshot {
    pub readable: bool,
    pub error: Option<String>,
    pub windows_firewall_on: bool,
    /// RustWarden's own rules (group "RustWarden"): (program path lower-cased, outbound?, enabled).
    pub rules: Vec<FwRuleInfo>,
    pub block_all_active: bool,
    pub ask_active: bool,
    /// Addresses blocked as malicious (from the "RustWarden threat out" rules).
    pub threat_blocked: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FwRuleInfo {
    pub name: String,
    pub program: String,
    /// Service the rule is limited to, lower-cased; empty for the whole program.
    pub service: String,
    pub outbound: bool,
    pub block: bool,
    pub enabled: bool,
}

#[derive(Default)]
pub struct State {
    /// Programs flagged as peer-to-peer by the traffic collector.
    pub p2p: Vec<crate::data::P2pApp>,
    pub hw: VecDeque<HardwareSample>,
    pub hw_now: HwNow,
    pub hw_secs: i64,
    pub traffic: TrafficNow,
    pub fw: FwSnapshot,
    pub fw_enabled: bool,
    pub networks: Vec<NetworkInfo>,
    pub scan: ScanState,
    pub hostnames: HashMap<IpAddr, String>,
    pub snooze_until: i64,
    /// Desktop notifications waiting for the UI to show them as popups.
    pub popups: Vec<Alert>,
    /// The UI shows `popups` (even from the tray); when false, alerts fall back to a tray balloon.
    pub popups_ok: bool,
    /// Prompt prompts waiting for the UI to take them.
    pub asks: Vec<ConnectAsk>,
    /// Set when an app's rules were removed, so Prompt may ask about it again.
    pub ask_reset: bool,
    /// Addresses on the loaded malicious-IP lists, and the (app key, address) pairs already reported this run.
    pub threat_ips: HashMap<IpAddr, String>,
    pub threat_seen: HashSet<(String, IpAddr)>,
    /// (app key, address) hits the threat thread has yet to act on.
    pub threat_hits: Vec<(String, IpAddr)>,
    /// Addresses the user unblocked: warned about again, but never auto-blocked.
    pub threat_manual: HashSet<IpAddr>,
    /// Whitelisted addresses, and "program · Signed" for each address that ever hit.
    pub threat_allow: Vec<String>,
    pub threat_meta: HashMap<String, String>,
    pub threats: Vec<Threat>,
    /// Names on the loaded malicious-domain lists, and the (program, name) pairs already reported this run.
    pub dns_domains: HashSet<String>,
    pub dns_seen: HashSet<(String, String)>,
    /// The ETW session is running, so per-app traffic is being measured.
    pub etw: bool,
    /// Data-quota usage as last worked out by the quota thread.
    pub quotas: Vec<QuotaStatus>,
}

/// Country of a stored alert: "" none, "LOCAL" the local network, else an ISO code.
pub fn country_of(code: &str) -> Option<Country> {
    match code {
        "" => None,
        "LOCAL" => Some(Country::Local),
        code => crate::countries::parse_a2(code).map(Country::from_a2),
    }
}

pub struct Shared {
    pub settings: RwLock<Settings>,
    pub ctx: Mutex<Option<egui::Context>>,
    pub stop: AtomicBool,
    pub scan_cancel: AtomicBool,
    pub elevated: bool,
    pub db_path: PathBuf,
    pub state: Mutex<State>,
    notes: Mutex<BTreeMap<&'static str, StatusNote>>,
    /// When an alert rule that limits repeats last let an alert through.
    rule_seen: Mutex<HashMap<(u32, String), i64>>,
}

/// A mutex's data even if a panicking thread poisoned it: one dead collector must not take the rest down.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    pub fn new(settings: Settings, db_path: PathBuf, elevated: bool) -> Self {
        Self {
            settings: RwLock::new(settings),
            ctx: Mutex::new(None),
            stop: AtomicBool::new(false),
            scan_cancel: AtomicBool::new(false),
            elevated,
            db_path,
            // Popups are always the UI's own: a hidden window still runs `logic`, which shows what is queued here (a tray balloon is only a fallback).
            state: Mutex::new(State { popups_ok: true, ..State::default() }),
            notes: Mutex::new(BTreeMap::new()),
            rule_seen: Mutex::new(HashMap::new()),
        }
    }

    pub fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Opens this thread's own connection to the database.
    pub fn open_db(&self) -> rusqlite::Result<Db> {
        Db::open(&self.db_path)
    }

    pub fn repaint(&self) {
        if let Some(ctx) = lock(&self.ctx).as_ref() {
            ctx.request_repaint();
        }
    }

    /// Sets or clears one collector's status line.
    pub fn set_note(&self, source: &'static str, note: Option<StatusNote>) {
        let mut notes = lock(&self.notes);
        match note {
            Some(n) => notes.insert(source, n),
            None => notes.remove(source),
        };
    }

    pub fn notes(&self) -> Vec<StatusNote> {
        let mut v: Vec<StatusNote> = lock(&self.notes).values().cloned().collect();
        v.sort_by_key(|n| n.level != NoteLevel::Warn);
        v
    }

    /// Sleeps up to `secs`, waking early when the app is shutting down. Returns false to stop.
    pub fn sleep(&self, secs: f64) -> bool {
        let end = std::time::Instant::now() + std::time::Duration::from_secs_f64(secs);
        while std::time::Instant::now() < end {
            if self.stopping() {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        !self.stopping()
    }

    /// Sample alert for the Settings test button: the kind's own event log, external-service and
    /// level options apply, the banner always shows, and monitor switches and snooze are
    /// ignored. Never stored, so it doesn't reach Alerts.
    pub fn test_alert(&self, key: &str, s: &Settings) {
        let Some(kind) = AlertKind::ALL.into_iter().find(|k| k.key() == key) else { return };
        let (app, text, target) = kind.sample();
        let title = kind.title();
        let opts = kind.opts(s);
        let important = opts.level == AlertLevel::Important;
        let line = format!("{app} {text} {target}").replace("  ", " ");
        let line = line.trim();
        if s.event_log && opts.event_log {
            crate::sys::eventlog::write(important, &format!("{title}: {line}"));
        }
        if opts.api {
            crate::plugins::wasm::manager::broadcast_alert(important, title, line);
        }
        let mut st = self.state();
        if st.popups_ok {
            st.popups.push(Alert {
                id: 0,
                icon: AppIcon::Generic,
                app: app.into(),
                text: text.into(),
                target: target.into(),
                country: None,
                kind: title.into(),
                time: String::new(),
                day: String::new(),
                ts: crate::clock::now_unix(),
                unread: true,
                important,
                anomaly: super::alerts::can_mark_normal(kind.key()),
            });
        } else {
            drop(st);
            crate::sys::notify::balloon(title, line);
        }
        self.repaint();
    }

    /// Records an alert unless its monitor is switched off. During a snooze alerts are still
    /// recorded but arrive already read, so they don't badge the tab.
    pub fn alert(&self, db: &Db, kind: AlertKind, app: &str, text: &str, target: &str, country: &str) {
        self.alert_as(db, kind, app, text, target, country, Urgency::Normal);
    }

    /// `alert`, delivered as `urgency` says on top of the kind's settings.
    /// Returns the stored alert's id, or `None` when it was switched off or couldn't be stored.
    #[allow(clippy::too_many_arguments)]
    pub fn alert_as(&self, db: &Db, kind: AlertKind, app: &str, text: &str, target: &str, country: &str, urgency: Urgency) -> Option<i64> {
        let settings = self.settings();
        if !kind.enabled(&settings.alerts) {
            return None;
        }
        let now = crate::clock::now_unix();
        let snoozed = self.state().snooze_until > now;
        let mut opts = kind.opts(&settings);
        // Alert rules (Alerts > Rules) change how this one is delivered; it is recorded either way.
        let (minute, weekday) = crate::alertrules::when(now);
        let info = crate::alertrules::AlertInfo { kind: kind.key(), app, text, target, minute, weekday };
        let effect = crate::alertrules::decide(&settings.alert_rules, &info, &mut lock(&self.rule_seen), now);
        if effect.mute {
            (opts.desktop, opts.event_log, opts.api) = (false, false, false);
        }
        opts.api &= !effect.local_only;
        if effect.escalate {
            opts.desktop = true;
            opts.level = AlertLevel::Important;
        }
        // Quiet wins over an escalate rule: it is for findings that must be kept but not pushed at anyone.
        if urgency == Urgency::Quiet {
            (opts.desktop, opts.api, opts.level) = (false, false, AlertLevel::Logs);
        }
        let important = (urgency == Urgency::Important || opts.level == AlertLevel::Important) && !effect.mute;
        if settings.event_log && opts.event_log {
            crate::sys::eventlog::write(important, &format!("{}: {} {} {}", kind.title(), app, text, target).replace("  ", " "));
        }
        if opts.api && (!snoozed || settings.api_in_snooze) {
            crate::plugins::wasm::manager::broadcast_alert(important, kind.title(), &format!("{app} {text} {target}").replace("  ", " "));
        }
        let alert = NewAlert { ts: now, kind: kind.key().into(), important, app: app.into(), text: text.into(), target: target.into(), country: country.into(), unread: important && !snoozed };
        let id = match db.insert_alert(&alert) {
            Ok(id) => id,
            Err(e) => {
                self.set_note("alerts-db", Some(StatusNote::warn(format!("Can't store alerts: {e}"))));
                return None;
            }
        };
        self.repaint();
        if opts.desktop && !snoozed {
            let mut st = self.state();
            if st.popups_ok {
                st.popups.push(Alert {
                    id: id as u64,
                    icon: AppIcon::Generic,
                    app: app.into(),
                    text: text.into(),
                    target: target.into(),
                    country: country_of(country),
                    kind: kind.title().into(),
                    time: String::new(),
                    day: String::new(),
                    ts: now,
                    unread: true,
                    important,
                    anomaly: super::alerts::can_mark_normal(kind.key()),
                });
            } else {
                drop(st);
                crate::sys::notify::balloon(kind.title(), &format!("{app} {text} {target}").trim().replace("  ", " "));
            }
            self.repaint();
        }
        Some(id)
    }
}

/// The live backend's shared state, so a plugin can raise an alert. Set once at start; Demo mode has none.
static ALERT_SINK: std::sync::OnceLock<std::sync::Arc<Shared>> = std::sync::OnceLock::new();

pub fn install_alert_sink(shared: std::sync::Arc<Shared>) {
    let _ = ALERT_SINK.set(shared);
}

/// The addresses blocked by the malicious-address list or by hand, for plugins with "firewall.blocks.read".
pub fn blocked_addresses() -> Vec<String> {
    ALERT_SINK.get().map(|s| s.state().fw.threat_blocked.clone()).unwrap_or_default()
}

/// A packet-loss alert from the thinkbroadband plugin, with the user's settings for that alert kind applied.
pub fn raise_plugin_alert(who: &str, text: &str) {
    let Some(shared) = ALERT_SINK.get() else { return };
    if let Ok(db) = shared.open_db() {
        shared.alert(&db, super::alerts::AlertKind::ThinkBroadband, who, text, "", "");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alertrules::{AlertRule, RuleAction};

    fn shared(rules: Vec<AlertRule>) -> Shared {
        let mut settings = Settings::default();
        (settings.alert_rules, settings.event_log) = (rules, false);
        let s = Shared::new(settings, std::path::PathBuf::new(), false);
        s.state().popups_ok = true;
        s
    }

    #[test]
    fn a_mute_rule_records_the_alert_but_shows_nothing() {
        let s = shared(vec![AlertRule { action: RuleAction::Mute, kinds: vec!["remote_session".into()], ..AlertRule::default() }]);
        let db = Db::memory();
        // Remote Desktop alerts are Important and pop up by default; the rule silences them. Another kind is untouched.
        s.alert(&db, AlertKind::RemoteSession, "demouser", "started a Remote Desktop session", "", "");
        assert!(s.state().popups.is_empty());
        s.alert(&db, AlertKind::NewDevice, "Phone", "joined", "", "");
        assert_eq!(s.state().popups.len(), 1);
        let stored = db.alerts(10).unwrap();
        assert_eq!(stored.len(), 2, "muted alerts are still logged");
        assert!(stored.iter().all(|a| !a.new.important));
    }

    #[test]
    fn an_escalate_rule_makes_an_alert_important_with_a_popup() {
        let s = shared(vec![AlertRule { action: RuleAction::Escalate, kinds: vec!["arp".into()], ..AlertRule::default() }]);
        let db = Db::memory();
        // ARP alerts are quiet logs by default.
        s.alert(&db, AlertKind::Arp, "ARP table", "changed", "", "");
        assert_eq!(s.state().popups.len(), 1);
        assert!(s.state().popups[0].important);
        assert!(db.alerts(10).unwrap()[0].new.important);
    }

    #[test]
    fn a_quiet_alert_is_logged_read_without_a_popup_even_when_escalated() {
        let s = shared(vec![AlertRule { action: RuleAction::Escalate, kinds: vec!["remote_session".into()], ..AlertRule::default() }]);
        let db = Db::memory();
        // Remote Desktop pops up by default and the rule escalates it; quiet still wins.
        let id = s.alert_as(&db, AlertKind::RemoteSession, "demouser", "started a session", "", "", Urgency::Quiet);
        assert!(id.is_some(), "a quiet alert is still stored");
        assert!(s.state().popups.is_empty());
        let stored = &db.alerts(10).unwrap()[0];
        assert!(!stored.new.important && !stored.new.unread);
    }
}
