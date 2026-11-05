//! Export and import of the firewall rules as a plain JSON file, so they survive a reinstall, a rename of the app (its
//! rules are named after it) or a move to another PC. Only the user's choices are written: which programs are blocked in
//! which direction, the destination rules, and the app's settings (as TOML text; secrets stay DPAPI-encrypted, so they
//! only open for the same Windows user). Importing applies what differs from now, the same as clicking the chips.

use crate::data::{Direction, FirewallApp, Verdict};
use crate::destrules::DestRule;
use serde::{Deserialize, Serialize};

const FORMAT: &str = "rustwarden-rules";
const VERSION: u32 = 1;

/// One program's blocks. A direction not listed is allowed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRule {
    /// Row key: the lower-cased executable path, plus the service for a service row.
    pub key: String,
    /// For reading the file; the key is what is matched.
    pub name: String,
    pub blocked_in: bool,
    pub blocked_out: bool,
    pub blocked_local: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesFile {
    format: String,
    version: u32,
    #[serde(default)]
    pub apps: Vec<AppRule>,
    /// Destination rules in the settings store's one-line form (see `DestRule::encode`).
    #[serde(default)]
    pub dest: Vec<String>,
    /// The settings, as `Settings::to_export` text. Files from before settings were exported don't have it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<String>,
}

/// What importing would do now.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub verdicts: Vec<(String, Direction, Verdict)>,
    /// Programs in the file that the firewall doesn't list right now; their blocks are still tried.
    pub unlisted: usize,
    pub dest: Vec<DestRule>,
    /// The file carries settings, which replace the current ones.
    pub settings: bool,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.verdicts.is_empty() && self.dest.is_empty() && !self.settings
    }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.verdicts.is_empty() {
            parts.push(format!("{} program rule change(s)", self.verdicts.len()));
        }
        if !self.dest.is_empty() {
            parts.push(format!("{} destination rule(s)", self.dest.len()));
        }
        if self.settings {
            parts.push("your settings change".into());
        }
        if parts.is_empty() { "Nothing to change: this PC already has these rules.".into() } else { parts.join(" and ") }
    }
}

const DIRECTIONS: [Direction; 3] = [Direction::In, Direction::Out, Direction::Local];

impl RulesFile {
    /// The rules as they are now. System rows (locked) are Windows' own and are left out.
    pub fn collect(apps: &[FirewallApp], dest: &[DestRule], settings: &crate::settings::Settings) -> Self {
        let blocked = |v: Verdict| v == Verdict::Blocked;
        let apps = apps
            .iter()
            .filter(|a| !a.locked && [a.inbound, a.outbound, a.local].into_iter().any(blocked))
            .map(|a| AppRule { key: a.key.clone(), name: a.name.clone(), blocked_in: blocked(a.inbound), blocked_out: blocked(a.outbound), blocked_local: blocked(a.local) })
            .collect();
        RulesFile { format: FORMAT.into(), version: VERSION, apps, dest: dest.iter().map(DestRule::encode).collect(), settings: Some(settings.to_export()) }
    }

    pub fn to_text(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let file: RulesFile = serde_json::from_str(text).map_err(|e| format!("This isn't a rules file: {e}"))?;
        if file.format != FORMAT {
            return Err("This isn't a RustWarden rules file.".into());
        }
        if file.version > VERSION {
            return Err("This file was made by a newer version of RustWarden. Update the app to import it.".into());
        }
        Ok(file)
    }

    /// What to change to make the firewall match the file. `current` is each listed program's (key, [in, out, local])
    /// and `dest` the destination rules already saved. Blocks the file doesn't have are lifted only on programs it lists.
    pub fn plan(&self, current: &[(String, [Verdict; 3])], dest: &[DestRule]) -> Plan {
        let mut plan = Plan { settings: self.settings.is_some(), ..Plan::default() };
        for rule in &self.apps {
            let wanted = [rule.blocked_in, rule.blocked_out, rule.blocked_local];
            let now = current.iter().find(|(k, _)| *k == rule.key).map(|(_, v)| *v);
            if now.is_none() {
                plan.unlisted += 1;
            }
            for (i, direction) in DIRECTIONS.into_iter().enumerate() {
                let have = now.map_or(Verdict::Allowed, |v| v[i]);
                let want = if wanted[i] { Verdict::Blocked } else { Verdict::Allowed };
                if have != want {
                    plan.verdicts.push((rule.key.clone(), direction, want));
                }
            }
        }
        let same = |a: &DestRule, b: &DestRule| DestRule { id: 0, ..a.clone() } == DestRule { id: 0, ..b.clone() };
        for rule in self.dest.iter().filter_map(|line| DestRule::decode(line)) {
            if !dest.iter().any(|have| same(have, &rule)) && !plan.dest.iter().any(|queued| same(queued, &rule)) {
                plan.dest.push(DestRule { id: 0, ..rule });
            }
        }
        plan
    }
}

/// The current state of each listed program, for [`RulesFile::plan`].
pub fn current_of(apps: &[FirewallApp]) -> Vec<(String, [Verdict; 3])> {
    apps.iter().map(|a| (a.key.clone(), [a.inbound, a.outbound, a.local])).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destrules::{Mode, Target};

    fn rule(key: &str, i: bool, o: bool, l: bool) -> AppRule {
        AppRule { key: key.into(), name: key.into(), blocked_in: i, blocked_out: o, blocked_local: l }
    }

    fn file(apps: Vec<AppRule>, dest: Vec<String>) -> RulesFile {
        RulesFile { format: FORMAT.into(), version: VERSION, apps, dest, settings: None }
    }

    #[test]
    fn old_files_without_settings_or_lists_still_load() {
        let f = RulesFile::parse(r#"{"format":"rustwarden-rules","version":1}"#).unwrap();
        assert!(f.settings.is_none() && f.apps.is_empty());
        assert!(!f.plan(&[], &[]).settings);
        let f = RulesFile { settings: Some(String::new()), ..f };
        assert!(f.plan(&[], &[]).settings);
    }

    #[test]
    fn a_file_survives_writing_and_reading() {
        let f = file(vec![rule(r"c:\a.exe", true, false, true)], vec![]);
        assert_eq!(RulesFile::parse(&f.to_text()).unwrap(), f);
    }

    #[test]
    fn foreign_and_newer_files_are_refused() {
        assert!(RulesFile::parse("not json").is_err());
        assert!(RulesFile::parse(r#"{"format":"other","version":1,"apps":[],"dest":[]}"#).unwrap_err().contains("isn't a RustWarden"));
        assert!(RulesFile::parse(r#"{"format":"rustwarden-rules","version":99,"apps":[],"dest":[]}"#).unwrap_err().contains("newer"));
    }

    #[test]
    fn only_differences_are_planned() {
        let f = file(vec![rule("a", true, true, false), rule("b", false, false, false), rule("gone", false, true, false)], vec![]);
        let current = vec![("a".to_owned(), [Verdict::Blocked, Verdict::Allowed, Verdict::Allowed]), ("b".to_owned(), [Verdict::Blocked, Verdict::Allowed, Verdict::Allowed])];
        let plan = f.plan(&current, &[]);
        assert_eq!(plan.verdicts, vec![("a".to_owned(), Direction::Out, Verdict::Blocked), ("b".to_owned(), Direction::In, Verdict::Allowed), ("gone".to_owned(), Direction::Out, Verdict::Blocked)]);
        assert_eq!(plan.unlisted, 1);
    }

    #[test]
    fn matching_state_plans_nothing() {
        let f = file(vec![rule("a", true, false, false)], vec![]);
        let current = vec![("a".to_owned(), [Verdict::Blocked, Verdict::Allowed, Verdict::Allowed])];
        let plan = f.plan(&current, &[]);
        assert!(plan.is_empty());
        assert!(plan.summary().starts_with("Nothing to change"));
    }

    #[test]
    fn destination_rules_are_added_once_and_get_fresh_ids() {
        let block = DestRule { id: 7, enabled: true, mode: Mode::Block, target: Target::Domain("example.com".into()), program: String::new() };
        let f = file(vec![], vec![block.encode(), block.encode()]);
        let plan = f.plan(&[], &[]);
        assert_eq!(plan.dest.len(), 1);
        assert_eq!(plan.dest[0].id, 0);
        // already saved here under another id: nothing to add
        let have = DestRule { id: 3, ..block };
        assert!(f.plan(&[], &[have]).dest.is_empty());
    }
}
