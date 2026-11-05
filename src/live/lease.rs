//! Keeps RustWarden's own downloads working: just before it starts a helper (`curl`, PowerShell, the
//! speedtest CLI) the helper gets a temporary way online, even if the firewall would block it. Block rules
//! beat allow rules, so a block rule for that exact program is switched off for the lease and switched
//! back on when it ends; if the firewall blocks everything by default, a tagged allow rule is added too.
//! Leases are saved, so a crash can't leave a rule off: they're ended when they expire, at exit and at
//! "Restore firewall defaults". Only the helper's own rules are ever touched, and only while elevated.

use super::db::Db;
use super::firewall::FwController;
use super::store::{Shared, lock};
use crate::sys::firewall::{self, Rule, RuleSpec};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

const KEY: &str = "helper_leases";
/// Group of the allow rules made here; not `firewall::GROUP`, so the Firewall tab and its change check ignore them.
pub const GROUP: &str = "RustWarden helper lease";
/// How long a lease lasts. Starting the helper again renews it once half is gone.
const SECS: i64 = 600;
const IDLE_RECHECK: i64 = 60;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Lease {
    exe: String,
    expires: i64,
    /// Names of the block rules switched off for this lease.
    suspended: Vec<String>,
}

fn encode(leases: &[Lease]) -> String {
    leases.iter().map(|l| format!("{}\t{}\t{}", l.exe, l.expires, l.suspended.join("\t"))).collect::<Vec<_>>().join("\n")
}

fn decode(text: &str) -> Vec<Lease> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            let (exe, expires) = (f.next()?.to_owned(), f.next()?.parse().ok()?);
            Some(Lease { exe, expires, suspended: f.filter(|n| !n.is_empty()).map(str::to_owned).collect() })
        })
        .collect()
}

/// The helper's full path, if `program` is one RustWarden launches; a bare name means the Windows copy.
fn helper_path(program: &Path, system_root: &str) -> Option<String> {
    let stem = program.file_stem()?.to_str()?.to_ascii_lowercase();
    if program.is_absolute() {
        return matches!(stem.as_str(), "curl" | "nslookup" | "powershell" | "speedtest").then(|| program.to_string_lossy().into_owned());
    }
    match stem.as_str() {
        "curl" | "nslookup" => Some(format!(r"{system_root}\System32\{stem}.exe")),
        "powershell" => Some(format!(r"{system_root}\System32\WindowsPowerShell\v1.0\powershell.exe")),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Plan {
    suspend: Vec<String>,
    add_allow: bool,
}

/// What `exe` needs to get online: its own enabled block rules off, and an allow rule if everything else is blocked by default.
fn plan(exe: &str, blocks: &[Rule], allows: &[Rule], default_blocked: bool) -> Plan {
    let same = |r: &&Rule| r.program.eq_ignore_ascii_case(exe);
    let allowed = allows.iter().any(|r| same(&r));
    Plan { suspend: blocks.iter().filter(same).map(|r| r.name.clone()).collect(), add_allow: default_blocked && !allowed }
}

fn rule_name(exe: &str) -> String {
    format!("{GROUP}: {exe}")
}

/// When each helper is next looked at: spawning it again before then does nothing.
static NEXT_CHECK: Mutex<Option<HashMap<String, i64>>> = Mutex::new(None);

fn due(exe: &str, now: i64) -> bool {
    lock(&NEXT_CHECK).as_ref().and_then(|m| m.get(exe)).is_none_or(|t| now >= *t)
}

fn check_again_at(exe: &str, at: i64) {
    lock(&NEXT_CHECK).get_or_insert_with(HashMap::new).insert(exe.to_owned(), at);
}

/// Hooks the lease into every helper start. Live mode only.
pub fn install(shared: Arc<Shared>, fw: Arc<FwController>) {
    crate::sys::etw::set_spawn_hook(Some(Arc::new(move |program| before_spawn(&shared, &fw, program))));
}

pub fn uninstall() {
    crate::sys::etw::set_spawn_hook(None);
}

fn before_spawn(shared: &Shared, fw: &FwController, program: &Path) {
    if !shared.elevated || !shared.settings().allow_helper_tools {
        return;
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let Some(exe) = helper_path(program, &root) else { return };
    if !due(&exe, crate::clock::now_unix()) {
        return;
    }
    let _g = fw.lock_op();
    let now = crate::clock::now_unix();
    if !due(&exe, now) {
        return;
    }
    let Ok(db) = shared.open_db() else { return };
    let mut leases = decode(&db.kv_get(KEY).unwrap_or_default());
    let (blocks, allows) = (firewall::enabled_outbound_blocks().unwrap_or_default(), firewall::enabled_outbound_allows().unwrap_or_default());
    let p = plan(&exe, &blocks, &allows, firewall::default_outbound_blocked().is_ok_and(|b| b.contains(&true)));
    let existing = leases.iter().position(|l| l.exe.eq_ignore_ascii_case(&exe));
    if existing.is_none() && p.suspend.is_empty() && !p.add_allow {
        check_again_at(&exe, now + IDLE_RECHECK);
        return;
    }
    let i = existing.unwrap_or_else(|| {
        leases.push(Lease { exe: exe.clone(), expires: 0, suspended: Vec::new() });
        leases.len() - 1
    });
    leases[i].expires = now + SECS;
    for name in &p.suspend {
        if !leases[i].suspended.contains(name) {
            leases[i].suspended.push(name.clone());
        }
    }
    // Saved before anything is switched off, so a crash always leaves a way back.
    if db.kv_set(KEY, &encode(&leases)).is_err() {
        return;
    }
    for name in &p.suspend {
        let _ = firewall::set_rule_enabled(name, false);
    }
    if p.add_allow {
        let spec = RuleSpec {
            name: rule_name(&exe),
            description: "Created by RustWarden so one of its own downloads can run. Removed automatically.".into(),
            grouping: GROUP.into(),
            program: Some(exe.clone()),
            outbound: true,
            block: false,
            enabled: true,
            protocol: None,
            local_ports: None,
            remote_ports: None,
            remote_addrs: None,
            service: None,
        };
        let _ = firewall::add_rule(&spec);
    }
    check_again_at(&exe, now + SECS / 2);
    // Switched-off rules may be ones RustWarden tracks; this is its own change, not an outside edit.
    fw.refresh(true);
}

/// Ends leases that ran out. Nothing is read from Windows unless one did.
pub fn sweep(shared: &Shared, fw: &FwController) {
    if !shared.elevated {
        return;
    }
    let Ok(db) = shared.open_db() else { return };
    let text = db.kv_get(KEY).unwrap_or_default();
    if decode(&text).iter().all(|l| l.expires > crate::clock::now_unix()) {
        return;
    }
    let _g = fw.lock_op();
    end(&db, false);
    fw.refresh(true);
}

/// Ends every lease now: at exit, and for "Restore firewall defaults". The caller holds the firewall lock where it has one.
pub fn end_all(shared: &Shared, fw: &FwController) {
    if !shared.elevated {
        return;
    }
    if let Ok(db) = shared.open_db() {
        let _g = fw.lock_op();
        end(&db, true);
    }
}

/// Switches the suspended rules back on and removes the allow rules, for expired leases (or all).
pub fn end(db: &Db, all: bool) {
    let now = crate::clock::now_unix();
    let (done, keep): (Vec<_>, Vec<_>) = decode(&db.kv_get(KEY).unwrap_or_default()).into_iter().partition(|l| all || l.expires <= now);
    for lease in &done {
        for name in &lease.suspended {
            let _ = firewall::set_rule_enabled(name, true);
        }
        let _ = firewall::remove_rule(&rule_name(&lease.exe));
        lock(&NEXT_CHECK).get_or_insert_with(HashMap::new).remove(&lease.exe);
    }
    if !done.is_empty() {
        let _ = db.kv_set(KEY, &encode(&keep));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, program: &str, block: bool) -> Rule {
        Rule { name: name.into(), grouping: String::new(), program: program.into(), service: String::new(), outbound: true, block, enabled: true }
    }

    #[test]
    fn leases_round_trip() {
        let v = vec![
            Lease { exe: r"C:\Windows\System32\curl.exe".into(), expires: 99, suspended: vec!["Block curl".into(), "RustWarden x".into()] },
            Lease { exe: r"C:\a\speedtest.exe".into(), expires: 5, suspended: vec![] },
        ];
        assert_eq!(decode(&encode(&v)), v);
        assert!(decode("junk\nexe\tnot-a-number").is_empty());
    }

    #[test]
    fn only_our_helpers_are_recognised() {
        let root = r"C:\Windows";
        assert_eq!(helper_path(Path::new("curl.exe"), root).as_deref(), Some(r"C:\Windows\System32\curl.exe"));
        assert_eq!(helper_path(Path::new("powershell"), root).as_deref(), Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"));
        assert_eq!(helper_path(Path::new(r"C:\Data\speedtest\speedtest.exe"), root).as_deref(), Some(r"C:\Data\speedtest\speedtest.exe"));
        assert_eq!(helper_path(Path::new("speedtest.exe"), root), None, "a bare speedtest name could be anything");
        assert_eq!(helper_path(Path::new("tar.exe"), root), None);
        assert_eq!(helper_path(Path::new(r"C:\x\chrome.exe"), root), None);
    }

    #[test]
    fn plan_switches_off_only_the_helpers_own_block_rules() {
        let exe = r"C:\Windows\System32\curl.exe";
        let blocks = [rule("Block curl", &exe.to_uppercase(), true), rule("Block chrome", r"C:\chrome.exe", true)];
        assert_eq!(plan(exe, &blocks, &[], false), Plan { suspend: vec!["Block curl".into()], add_allow: false });
        assert_eq!(plan(exe, &[], &[], true), Plan { suspend: vec![], add_allow: true }, "blocked by default and not allowed: add an allow rule");
        assert_eq!(plan(exe, &[], &[rule("Allow curl", exe, false)], true), Plan { suspend: vec![], add_allow: false });
        assert_eq!(plan(exe, &[], &[], false), Plan { suspend: vec![], add_allow: false });
    }
}
