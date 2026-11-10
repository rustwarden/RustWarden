//! Alert rules: what happens to an alert after it is raised. A rule is a set of conditions (alert kind,
//! app, words in the text, a time window, days of the week) and one action. The first enabled rule that
//! matches wins. This is the pure part; `live::store` applies it to real alerts and Demo mode to its samples.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Most rules kept.
pub const MAX_RULES: usize = 64;
/// Every weekday bit set (bit 0 is Monday).
pub const ALL_DAYS: u8 = 0x7f;
pub const DAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Keep the alert in the log, but no popup, event-log entry or push, and it arrives read.
    #[default]
    Mute,
    /// Make it Important and show the desktop popup, whatever the alert's own settings say.
    Escalate,
    /// Don't send it to Notification Plugins (Discord, ntfy and the rest); everything else stays.
    KeepLocal,
    /// Notify at most once per `limit_min` minutes for the same alert kind and app; the rest are muted.
    Limit,
}

impl RuleAction {
    pub const ALL: [RuleAction; 4] = [Self::Mute, Self::Escalate, Self::KeepLocal, Self::Limit];

    pub fn label(self) -> &'static str {
        match self {
            Self::Mute => "Mute",
            Self::Escalate => "Escalate",
            Self::KeepLocal => "Keep on this PC",
            Self::Limit => "Limit repeats",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Self::Mute => "Still recorded in the Alerts log, but no popup, event log entry or push message.",
            Self::Escalate => "Becomes Important and shows a desktop popup, whatever the alert's own settings say.",
            Self::KeepLocal => "Not sent to Notification Plugins (Discord, ntfy and the rest); popups and the log stay as they are.",
            Self::Limit => "Notifies at most once in the time you set for the same alert kind and app; repeats inside it are muted.",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertRule {
    /// Stable identity; the repeat limiter is keyed by it.
    pub id: u32,
    pub enabled: bool,
    pub action: RuleAction,
    /// Alert kinds (see `AlertKind::key`) the rule covers; empty means any.
    pub kinds: Vec<String>,
    /// Part of the app name; empty means any app. Not case sensitive.
    pub app: String,
    /// Words that must appear in the alert's text or target; empty means no condition. Not case sensitive.
    pub contains: String,
    /// Time window in minutes since midnight. Equal values mean all day; `from` after `to` runs past midnight.
    pub from: u16,
    pub to: u16,
    /// Weekdays the rule covers, bit 0 is Monday.
    pub days: u8,
    /// Minutes for `RuleAction::Limit`.
    pub limit_min: u32,
}

impl Default for AlertRule {
    fn default() -> Self {
        Self { id: 0, enabled: true, action: RuleAction::Mute, kinds: Vec::new(), app: String::new(), contains: String::new(), from: 0, to: 0, days: ALL_DAYS, limit_min: 60 }
    }
}

/// One alert as the rules see it. `minute` is local minutes since midnight, `weekday` 0 = Monday.
pub struct AlertInfo<'a> {
    pub kind: &'a str,
    pub app: &'a str,
    pub text: &'a str,
    pub target: &'a str,
    pub minute: u16,
    pub weekday: u8,
}

/// What the matching rule changes about the alert.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Effect {
    pub mute: bool,
    pub escalate: bool,
    pub local_only: bool,
}

fn contains_nocase(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(&needle.to_lowercase())
}

/// Whether `minute` is inside the window; equal ends mean all day.
pub fn in_window(from: u16, to: u16, minute: u16) -> bool {
    match from.cmp(&to) {
        std::cmp::Ordering::Equal => true,
        std::cmp::Ordering::Less => (from..to).contains(&minute),
        std::cmp::Ordering::Greater => minute >= from || minute < to,
    }
}

/// Local (minutes since midnight, weekday with Monday 0) for a unix time.
pub fn when(ts: i64) -> (u16, u8) {
    let local = crate::clock::to_local(ts);
    // 1970-01-01 was a Thursday, which is 3 with Monday as 0.
    ((local.rem_euclid(86_400) / 60) as u16, (local.div_euclid(86_400) + 3).rem_euclid(7) as u8)
}

impl AlertRule {
    pub fn matches(&self, a: &AlertInfo) -> bool {
        (self.kinds.is_empty() || self.kinds.iter().any(|k| k == a.kind))
            && (self.app.trim().is_empty() || contains_nocase(a.app, self.app.trim()))
            && (self.contains.trim().is_empty() || contains_nocase(a.text, self.contains.trim()) || contains_nocase(a.target, self.contains.trim()))
            && in_window(self.from, self.to, a.minute)
            && self.days & (1 << a.weekday.min(6)) != 0
    }

    /// The rule in a sentence, for the list. `kind_title` turns a kind key into its name.
    pub fn summary(&self, kind_title: impl Fn(&str) -> String) -> String {
        let what = match self.action {
            RuleAction::Mute => "Mute".to_owned(),
            RuleAction::Escalate => "Escalate".to_owned(),
            RuleAction::KeepLocal => "Keep on this PC".to_owned(),
            RuleAction::Limit => format!("Notify at most once per {} min", self.limit_min),
        };
        let kinds = match self.kinds.as_slice() {
            [] => "any alert".to_owned(),
            [one] => kind_title(one),
            [one, rest @ ..] => format!("{} and {} more", kind_title(one), rest.len()),
        };
        let mut s = format!("{what}: {kinds}");
        if !self.app.trim().is_empty() {
            s.push_str(&format!(" from {}", self.app.trim()));
        }
        if !self.contains.trim().is_empty() {
            s.push_str(&format!(" mentioning \"{}\"", self.contains.trim()));
        }
        if self.from != self.to {
            s.push_str(&format!(", {}-{}", fmt_minute(self.from), fmt_minute(self.to)));
        }
        if self.days & ALL_DAYS != ALL_DAYS {
            let days: Vec<&str> = (0..7).filter(|d| self.days & (1 << d) != 0).map(|d| DAY_NAMES[d]).collect();
            s.push_str(&format!(", {}", if days.is_empty() { "never".to_owned() } else { days.join(" ") }));
        }
        s
    }
}

pub fn fmt_minute(m: u16) -> String {
    format!("{:02}:{:02}", m / 60, m % 60)
}

/// "22:30" to minutes since midnight.
pub fn parse_minute(s: &str) -> Option<u16> {
    let (h, m) = s.trim().split_once(':')?;
    let (h, m): (u16, u16) = (h.trim().parse().ok()?, m.trim().parse().ok()?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

/// The effect of the first enabled rule that matches `info`. `last` remembers when a `Limit` rule last let an
/// alert through, by (rule id, kind and app).
pub fn decide(rules: &[AlertRule], info: &AlertInfo, last: &mut HashMap<(u32, String), i64>, now: i64) -> Effect {
    let Some(rule) = rules.iter().find(|r| r.enabled && r.matches(info)) else { return Effect::default() };
    match rule.action {
        RuleAction::Mute => Effect { mute: true, ..Effect::default() },
        RuleAction::Escalate => Effect { escalate: true, ..Effect::default() },
        RuleAction::KeepLocal => Effect { local_only: true, ..Effect::default() },
        RuleAction::Limit => {
            let key = (rule.id, format!("{}|{}", info.kind, info.app.to_lowercase()));
            let window = i64::from(rule.limit_min) * 60;
            if last.get(&key).is_some_and(|t| now - t < window) {
                Effect { mute: true, ..Effect::default() }
            } else {
                last.insert(key, now);
                Effect::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info<'a>(kind: &'a str, app: &'a str, minute: u16, weekday: u8) -> AlertInfo<'a> {
        AlertInfo { kind, app, text: "connected to the network", target: "203.0.113.7:443", minute, weekday }
    }

    #[test]
    fn windows_wrap_past_midnight() {
        assert!(in_window(0, 0, 700));
        assert!(in_window(22 * 60, 7 * 60, 23 * 60));
        assert!(in_window(22 * 60, 7 * 60, 3 * 60));
        assert!(!in_window(22 * 60, 7 * 60, 12 * 60));
        assert!(in_window(9 * 60, 17 * 60, 9 * 60) && !in_window(9 * 60, 17 * 60, 17 * 60));
    }

    #[test]
    fn conditions_all_have_to_hold() {
        let rule = AlertRule { kinds: vec!["first_activity".into()], app: "Chrome".into(), contains: ":443".into(), from: 22 * 60, to: 7 * 60, days: 0b0011111, ..AlertRule::default() };
        assert!(rule.matches(&info("first_activity", "chrome.exe", 23 * 60, 2)));
        assert!(!rule.matches(&info("arp", "chrome.exe", 23 * 60, 2)), "other kind");
        assert!(!rule.matches(&info("first_activity", "firefox.exe", 23 * 60, 2)), "other app");
        assert!(!rule.matches(&info("first_activity", "chrome.exe", 12 * 60, 2)), "outside the window");
        assert!(!rule.matches(&info("first_activity", "chrome.exe", 23 * 60, 6)), "Sunday is not covered");
        assert!(AlertRule::default().matches(&info("anything", "", 0, 0)), "an empty rule covers everything");
    }

    #[test]
    fn first_enabled_match_wins() {
        let off = AlertRule { id: 1, enabled: false, action: RuleAction::Mute, ..AlertRule::default() };
        let esc = AlertRule { id: 2, action: RuleAction::Escalate, kinds: vec!["threat".into()], ..AlertRule::default() };
        let mute = AlertRule { id: 3, action: RuleAction::Mute, ..AlertRule::default() };
        let rules = [off, esc, mute];
        let mut last = HashMap::new();
        assert!(decide(&rules, &info("threat", "a", 0, 0), &mut last, 0).escalate);
        assert!(decide(&rules, &info("arp", "a", 0, 0), &mut last, 0).mute);
        assert_eq!(decide(&[], &info("arp", "a", 0, 0), &mut last, 0), Effect::default());
        let local = [AlertRule { action: RuleAction::KeepLocal, ..AlertRule::default() }];
        assert!(decide(&local, &info("arp", "a", 0, 0), &mut last, 0).local_only);
    }

    #[test]
    fn limit_lets_one_through_per_window_and_app() {
        let rules = [AlertRule { id: 9, action: RuleAction::Limit, limit_min: 10, ..AlertRule::default() }];
        let mut last = HashMap::new();
        let at = |app: &str, now, last: &mut HashMap<_, _>| decide(&rules, &info("first_activity", app, 0, 0), last, now).mute;
        assert!(!at("a.exe", 1000, &mut last));
        assert!(at("A.exe", 1100, &mut last), "same app inside the window");
        assert!(!at("b.exe", 1100, &mut last), "another app has its own window");
        assert!(!at("a.exe", 1000 + 600, &mut last), "window over");
    }

    #[test]
    fn times_and_weekdays_come_from_the_clock() {
        // 2026-11-02 12:34 UTC is a Monday; the local offset moves the clock but not by a full day here.
        let (m, d) = when(1_793_622_840);
        assert!(m < 1440 && d < 7);
        assert_eq!(parse_minute("07:05"), Some(425));
        assert_eq!(parse_minute("24:00"), None);
        assert_eq!(parse_minute("7"), None);
        assert_eq!(fmt_minute(425), "07:05");
    }

    #[test]
    fn summaries_read_as_sentences() {
        let rule = AlertRule { action: RuleAction::Mute, kinds: vec!["first_activity".into()], app: "steam".into(), from: 22 * 60, to: 7 * 60, days: 0b1100000, ..AlertRule::default() };
        assert_eq!(rule.summary(|_| "New connection".into()), "Mute: New connection from steam, 22:00-07:00, Sat Sun");
        assert_eq!(AlertRule { action: RuleAction::Limit, limit_min: 30, ..AlertRule::default() }.summary(|k| k.into()), "Notify at most once per 30 min: any alert");
    }
}
