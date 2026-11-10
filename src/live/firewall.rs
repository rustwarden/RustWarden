//! RustWarden's firewall on top of Windows Firewall.
//!
//! Safety rules, all enforced here and not in the UI:
//! * Only rules in the group [`GROUP`] whose name starts with [`NAME_PREFIX`] are ever changed
//!   or deleted ([`is_ours`]). Rules from Windows or other programs are never touched.
//! * Windows Firewall is turned on only through [`FwController::enable_windows_firewall`],
//!   which the UI calls after a confirmation dialog. Profile default actions change only for
//!   Block All, which also writes a marker file so a crash can be undone on the next start.
//! * Critical programs and RustWarden itself can't be blocked ([`super::apps::critical_reason`]).
//! * Every change is followed by a re-read, so the UI shows what Windows really holds.

use super::alerts::AlertKind;
use super::apps::{critical_reason, ensure_service_record, key_for_path, service_key, service_of_key};
use super::store::{FwRuleInfo, FwSnapshot, Shared};
use crate::data::{Answer, Direction, FirewallMode, StatusNote, Verdict};
use crate::sys::firewall::{self, Rule, RuleSpec};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub const GROUP: &str = "RustWarden";
pub const NAME_PREFIX: &str = "RustWarden ";
/// Settings key holding the app keys the user removed from the Firewall tab, one per line.
pub const REMOVED_KEY: &str = "protect_removed";

/// Apps removed from the Firewall list, with when. Lines are "key<TAB>time"; an old bare key counts as time 0.
pub fn removed_apps(db: &super::db::Db) -> std::collections::HashMap<String, i64> {
    db.kv_get(REMOVED_KEY)
        .unwrap_or_default()
        .lines()
        .map(|l| match l.split_once('\t') {
            Some((k, t)) => (k.to_owned(), t.parse().unwrap_or(0)),
            None => (l.to_owned(), 0),
        })
        .collect()
}
/// Settings key remembering the chosen mode at the last run: "1" Prompt, "2" Block All, else Manual Blocking.
const ASK_KEY: &str = "fw_ask";
/// Unix time "Block Windows components" last ran, for the automatic repeat.
const WINEXTRAS_KEY: &str = "winextras_last";
/// Rules that feature created, one "group<TAB>name" per line, and the paused groups ("0,2").
const WINEXTRAS_RULES_KEY: &str = "winextras_rules";
const WINEXTRAS_PAUSED_KEY: &str = "winextras_paused";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtrasAct {
    Unblock,
    Pause,
    Resume,
}

fn extras_rules(db: &super::db::Db) -> Vec<(usize, String)> {
    db.kv_get(WINEXTRAS_RULES_KEY).unwrap_or_default().lines().filter_map(|l| l.split_once('\t')).filter_map(|(g, n)| Some((g.parse().ok()?, n.to_owned()))).collect()
}

fn extras_paused(db: &super::db::Db) -> Vec<usize> {
    db.kv_get(WINEXTRAS_PAUSED_KEY).unwrap_or_default().split(',').filter_map(|g| g.parse().ok()).collect()
}

/// Names of the rules in paused groups; the on/off switch and its restore at start must leave them off.
fn paused_extras(db: &super::db::Db) -> Vec<String> {
    let paused = extras_paused(db);
    extras_rules(db).into_iter().filter(|(g, _)| paused.contains(g)).map(|(_, n)| n).collect()
}

/// Settings keys: profile names (one per line) and the active one.
const PROFILES_KEY: &str = "fw_profiles";
const ACTIVE_PROFILE_KEY: &str = "fw_profile";
pub const DEFAULT_PROFILE: &str = "Default";
/// Where inactive profiles' rules wait, switched off. Not [`GROUP`], so nothing of ours touches them.
const STASH_GROUP: &str = "RustWarden saved profiles";

/// Per profile ("fw_since@name", unix time): programs not seen since then, and without a rule,
/// are left off the Firewall tab and unknown to Prompt, so a new profile starts afresh.
/// They come back as soon as they use the network again.
fn since_key(profile: &str) -> String {
    format!("fw_since@{profile}")
}

/// The active profile's start time (0 for profiles that never started afresh).
pub fn profile_since(db: &super::db::Db) -> i64 {
    let active = db.kv_get(ACTIVE_PROFILE_KEY).unwrap_or_else(|| DEFAULT_PROFILE.into());
    db.kv_get(&since_key(&active)).and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// Appended to a parked rule's name; says which profile it belongs to.
fn stash_suffix(profile: &str) -> String {
    format!(" @[{profile}]")
}

pub fn valid_profile_name(name: &str, existing: &[String]) -> Result<(), String> {
    if name.is_empty() {
        Err("Enter a name.".into())
    } else if name.chars().count() > 40 || name.chars().any(|c| c.is_control() || "@[]".contains(c)) || name != name.trim() {
        Err("Use up to 40 characters, without @ [ ] or line breaks.".into())
    } else if existing.iter().any(|p| p.eq_ignore_ascii_case(name)) {
        Err("A ruleset with that name already exists.".into())
    } else {
        Ok(())
    }
}

/// Name prefix the other firewall gives its per-program rules; imported ones keep it when not renamed.
const IMPORT_PREFIX: &str = "{GlassWire.";

/// A rule may be modified or deleted only if it carries our group and our name prefix (or a
/// imported-firewall name the user imported into our group).
pub fn is_ours(grouping: &str, name: &str) -> bool {
    grouping == GROUP && (name.starts_with(NAME_PREFIX) || name.starts_with(IMPORT_PREFIX))
}

/// The key of the program or service row a rule belongs to: a rule limited to one service belongs to that service's row.
pub fn row_key(program: &str, service: &str) -> String {
    let program = key_for_path(program);
    if service.is_empty() { program } else { service_key(&program, &service.to_lowercase()) }
}

pub fn rule_key(r: &Rule) -> String {
    row_key(&r.program, &r.service)
}

/// A block rule of ours for this program (or one of its services) and direction, whatever it is named.
fn find_block<'a>(rules: &'a [Rule], direction: Direction, path: &str, service: &str) -> Option<&'a Rule> {
    let key = key_for_path(path);
    rules.iter().find(|r| {
        is_ours(&r.grouping, &r.name)
            && r.block
            && is_lan(&r.name) == (direction == Direction::Local)
            && (direction == Direction::Local || r.outbound == (direction == Direction::Out))
            && key_for_path(&r.program) == key
            && r.service.eq_ignore_ascii_case(service)
    })
}

/// Remote addresses the local-network rule covers: private, link-local and multicast ranges. Not the "LocalSubnet"
/// keyword: a VPN's on-link default routes make Windows treat every internet address as local.
const LAN_ADDRS: &str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,224.0.0.0/4,fe80::/10,fc00::/7,ff00::/8";
const LAN_TAG: &str = "block lan";
/// Every remote port but 53: DNS servers are usually on the LAN (the router), and blocking them would cut off the internet too.
const LAN_PORTS: &str = "1-52,54-65535";

/// The local-network block: ports need a protocol, so TCP and UDP each get a rule.
fn lan_specs(path: &str, service: &str, enabled: bool) -> Vec<RuleSpec> {
    [(6, "tcp"), (17, "udp")]
        .into_iter()
        .map(|(proto, tag)| RuleSpec {
            interfaces: None,
            name: tagged_name(&format!("{LAN_TAG} {tag}"), path, service),
            protocol: Some(proto),
            remote_ports: Some(LAN_PORTS.into()),
            ..block_spec(Direction::Local, path, service, enabled)
        })
        .collect()
}

/// Whether a rule of ours is the per-program local-network block (an outbound block limited to [`LAN_ADDRS`]).
pub fn is_lan(name: &str) -> bool {
    name.strip_prefix(NAME_PREFIX).is_some_and(|n| n.starts_with(LAN_TAG))
}

fn fnv(s: &str) -> u32 {
    s.bytes().fold(0x811c_9dc5u32, |h, b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193))
}

/// "RustWarden block out: chrome.exe [3fa9c1d2]". The hash of the full path keeps two programs
/// with the same file name apart. A service's rule reads "RustWarden block out: svchost.exe (wuauserv) [..]".
pub fn rule_name(direction: Direction, path: &str, service: &str) -> String {
    tagged_name(
        match direction {
            Direction::In => "block in",
            Direction::Out => "block out",
            Direction::Local => LAN_TAG,
        },
        path,
        service,
    )
}

fn tagged_name(what: &str, path: &str, service: &str) -> String {
    let file: String = super::apps::file_name(path).chars().filter(|c| !c.is_control()).collect();
    if service.is_empty() {
        return format!("{NAME_PREFIX}{what}: {file} [{:08x}]", fnv(&path.to_lowercase()));
    }
    format!("{NAME_PREFIX}{what}: {file} ({service}) [{:08x}]", fnv(&service_key(&path.to_lowercase(), &service.to_lowercase())))
}

/// What Prompt creates when a program is allowed (or is critical and so always allowed).
fn allow_spec(path: &str, service: &str) -> RuleSpec {
    RuleSpec {
        interfaces: None,
        name: tagged_name("allow out", path, service),
        description: "Created by RustWarden for Prompt. Use \"Restore firewall defaults\" in RustWarden to remove all such rules.".into(),
        grouping: GROUP.into(),
        program: Some(path.to_owned()),
        outbound: true,
        block: false,
        enabled: true,
        protocol: None,
        local_ports: None,
        remote_ports: None,
        remote_addrs: None,
        service: (!service.is_empty()).then(|| service.to_owned()),
    }
}

fn block_spec(direction: Direction, path: &str, service: &str, enabled: bool) -> RuleSpec {
    RuleSpec {
        interfaces: None,
        name: rule_name(direction, path, service),
        description: "Created by RustWarden. Use \"Restore firewall defaults\" in RustWarden to remove all such rules.".into(),
        grouping: GROUP.into(),
        program: Some(path.to_owned()),
        outbound: direction != Direction::In,
        block: true,
        enabled,
        protocol: None,
        local_ports: None,
        remote_ports: None,
        remote_addrs: (direction == Direction::Local).then(|| LAN_ADDRS.to_owned()),
        service: (!service.is_empty()).then(|| service.to_owned()),
    }
}

/// Per-address rules from the malicious-IP list; hidden from the Firewall tab, which lists programs.
const THREAT_PREFIX: &str = "RustWarden threat ";
/// Per-destination rules (domain, ASN, country); also hidden from the Firewall tab and the profile switch. See `super::dest`.
pub const DEST_PREFIX: &str = "RustWarden dest ";

/// Per-program blocks of the peer-to-peer guard (no VPN, so no peer-to-peer); also hidden from the Firewall tab. See `super::p2p`.
pub const P2P_PREFIX: &str = "RustWarden p2p ";

/// Rules of the VPN kill switch and the DNS-over-HTTPS block; hidden from the Firewall tab like the other aux rules. See `super::guard`.
pub const GUARD_PREFIX: &str = "RustWarden guard ";

/// The ping allow rules Prompt creates; hidden from the Firewall tab like the other aux rules.
const ICMP_PREFIX: &str = "RustWarden icmp ";
/// Stands in for a program path in the prompt about pings, which Windows doesn't attribute to a program.
pub const ICMP_PATH: &str = "icmp:ping";

/// Allows outbound ICMP (IPv4) and ICMPv6 for every program.
fn icmp_specs() -> Vec<RuleSpec> {
    [(1, "v4"), (58, "v6")]
        .into_iter()
        .map(|(proto, v)| RuleSpec {
            interfaces: None,
            name: format!("{ICMP_PREFIX}allow out {v}"),
            description: "Created by RustWarden for Prompt: lets ping work. Use \"Restore firewall defaults\" in RustWarden to remove all such rules.".into(),
            grouping: GROUP.into(),
            program: None,
            outbound: true,
            block: false,
            enabled: true,
            protocol: Some(proto),
            local_ports: None,
            remote_ports: None,
            remote_addrs: None,
            service: None,
        })
        .collect()
}

/// The rule that lets the driver engine's re-sent packets through. Windows gives such a packet no owning program ("System"),
/// so with Prompt or Block All on (outbound blocked by default) the firewall would drop everything the engine handles.
const ENGINE_RULE: &str = "RustWarden engine allow out: System";

fn engine_spec() -> RuleSpec {
    RuleSpec {
        interfaces: None,
        name: ENGINE_RULE.into(),
        description:
            "Created by RustWarden while bandwidth limits are active, so the packets its driver sends on are not blocked. Use \"Restore firewall defaults\" in RustWarden to remove all such rules."
                .into(),
        grouping: GROUP.into(),
        program: Some("System".into()),
        outbound: true,
        block: false,
        enabled: true,
        protocol: None,
        local_ports: None,
        remote_ports: None,
        remote_addrs: None,
        service: None,
    }
}

/// Adds or removes [`ENGINE_RULE`]; a rule that is already as wanted is left alone.
pub fn allow_engine_traffic(on: bool) -> Result<(), String> {
    let present = firewall::rules_in_group(GROUP)?.0.iter().any(|r| r.name == ENGINE_RULE);
    match (on, present) {
        (true, false) => firewall::add_rule(&engine_spec()),
        (false, true) => firewall::remove_rule(ENGINE_RULE),
        _ => Ok(()),
    }
}

/// Rules that belong to no program row, profile or on/off toggle.
fn is_aux(name: &str) -> bool {
    name.starts_with(THREAT_PREFIX) || name.starts_with(DEST_PREFIX) || name.starts_with(P2P_PREFIX) || name.starts_with(GUARD_PREFIX) || name.starts_with(ICMP_PREFIX) || name == ENGINE_RULE
}
const BLOCK_ALL_PREFIX: &str = "RustWarden block-all exception";

/// What Block All keeps open: RustWarden itself and DHCP renewals (so leases survive the undo).
fn block_all_exceptions(own_exe: &str) -> Vec<RuleSpec> {
    let base = |name: &str, desc: &str| RuleSpec {
        interfaces: None,
        name: format!("{BLOCK_ALL_PREFIX}: {name}"),
        description: format!("Created by RustWarden while Block All is on. {desc}"),
        grouping: GROUP.into(),
        program: None,
        outbound: true,
        block: false,
        enabled: true,
        protocol: None,
        local_ports: None,
        remote_ports: None,
        remote_addrs: None,
        service: None,
    };
    let rules = vec![
        RuleSpec { program: Some(own_exe.to_owned()), ..base("RustWarden", "Keeps RustWarden itself connected.") },
        RuleSpec { protocol: Some(17), local_ports: Some("68".into()), remote_ports: Some("67".into()), ..base("DHCP", "Lets the network lease be renewed.") },
    ];
    // curl and PowerShell get no standing exception: a rule on the program lets any caller out. `lease` opens them for the few
    // minutes after RustWarden itself starts one.
    rules
}

/// Block All exception rules of ours that the current version no longer makes.
fn stale_exceptions(rules: &[Rule], wanted: &[RuleSpec]) -> Vec<String> {
    rules.iter().filter(|r| is_ours(&r.grouping, &r.name) && r.name.starts_with(BLOCK_ALL_PREFIX) && !wanted.iter().any(|w| w.name == r.name)).map(|r| r.name.clone()).collect()
}

/// Where the safety markers live. Elevated runs act on what these files say (undo Block All, switch rules back on), so they
/// sit where only administrators can write: the user's own folder could be planted with a marker that opens the firewall.
fn state_dir() -> PathBuf {
    if crate::sys::is_elevated() { crate::settings::admin_dir() } else { crate::settings::data_dir() }
}

/// Versions up to 1.21.3 kept the safety files in the user's folder. A Block All still in force from then is carried over,
/// but only when Windows Firewall itself holds one of its exceptions (a program running as the user can't make those);
/// otherwise the old files are just deleted, so a planted one is never acted on.
pub fn migrate_legacy_state(elevated: bool) {
    const FILES: [&str; 5] = ["blockall.marker", "ask.marker", "closed.marker", "audit.prev", "blockall.suspended"];
    let (old, new) = (crate::settings::data_dir(), state_dir());
    if !elevated || old == new || !FILES.iter().any(|f| old.join(f).exists()) {
        return;
    }
    // Firewall unreadable: leave everything where it is and try at the next start.
    let Ok((rules, _)) = firewall::rules_in_group(GROUP) else { return };
    let real = rules.iter().any(|r| is_ours(&r.grouping, &r.name) && r.name.starts_with(BLOCK_ALL_PREFIX));
    let _ = std::fs::create_dir_all(&new);
    for f in FILES {
        if real && !new.join(f).exists() {
            let _ = std::fs::copy(old.join(f), new.join(f));
        }
        let _ = std::fs::remove_file(old.join(f));
    }
}

fn marker_path() -> PathBuf {
    state_dir().join("blockall.marker")
}

/// Present while Block All's machinery is running for Prompt rather than plain Block All.
fn ask_marker_path() -> PathBuf {
    state_dir().join("ask.marker")
}

fn ask_marker_exists() -> bool {
    ask_marker_path().exists()
}

/// Unix time RustWarden exited while keeping Prompt's block in force ("Keep blocking when RustWarden is closed").
fn closed_path() -> PathBuf {
    state_dir().join("closed.marker")
}

/// When RustWarden last exited with the block kept; read once, so the programs stopped since are offered once.
pub fn take_closed_since() -> Option<i64> {
    let text = std::fs::read_to_string(closed_path()).ok()?;
    let _ = std::fs::remove_file(closed_path());
    text.trim().parse().ok()
}

/// Whether the previous run left Prompt blocking on purpose, so this start carries on instead of undoing it.
pub fn kept_block(keep_setting: bool, elevated: bool) -> bool {
    keep_setting && elevated && block_all_marker_exists() && ask_marker_exists()
}

/// Whether the "Filtering Platform Connection" failure audit was on before we enabled it: "on" or "off".
fn audit_prev_path() -> PathBuf {
    state_dir().join("audit.prev")
}

/// Turns on the failure audit that makes Windows log blocked connections (event 5157), remembering how it was.
fn enable_audit() -> Result<(), String> {
    let prev = audit_prev_path();
    if !prev.exists() {
        let was = crate::sys::audit::failure_audit_on().unwrap_or(true);
        std::fs::write(&prev, if was { "on" } else { "off" }).map_err(|e| e.to_string())?;
    }
    crate::sys::audit::set_failure_audit(true)
}

/// Puts the audit back to how it was before [`enable_audit`].
fn restore_audit() {
    let prev = audit_prev_path();
    let Ok(text) = std::fs::read_to_string(&prev) else { return };
    if text.trim() == "off" && crate::sys::audit::set_failure_audit(false).is_err() {
        return; // not elevated: try again at the next undo
    }
    let _ = std::fs::remove_file(prev);
}

/// Allow rules Block All switched off, one name per line, so a crash can switch them back on.
fn suspended_path() -> PathBuf {
    state_dir().join("blockall.suspended")
}

/// Allow rules naming a program would let it past Block All's default-deny: ours from Prompt,
/// or ones other firewalls leave behind. Windows' own rules stay on.
fn rules_to_suspend(rules: &[Rule], system_root: &str) -> Vec<String> {
    // Windows' own tools that fetch and run things stay off the exception list too: a third-party allow rule for one of them is a hole.
    const TOOLS: [&str; 8] = ["curl.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "wscript.exe"];
    let tool = |program: &str| TOOLS.iter().any(|t| program.to_lowercase().ends_with(&format!("\\{t}")));
    rules
        .iter()
        .filter(|r| {
            r.program.contains(":\\") && (!r.program.to_lowercase().starts_with(system_root) || tool(&r.program)) && !r.name.starts_with(BLOCK_ALL_PREFIX) && !r.name.starts_with(super::lease::GROUP)
        })
        .map(|r| r.name.clone())
        .collect()
}

fn resume_suspended() {
    let path = suspended_path();
    if let Ok(text) = std::fs::read_to_string(&path) {
        for name in text.lines() {
            let _ = firewall::restore_rule(name, true); // a rule deleted meanwhile is fine
        }
    }
    let _ = std::fs::remove_file(path);
}

/// Previous default-outbound-blocked flags, written before Block All changes anything.
fn marker_text(prev: [bool; 3]) -> String {
    prev.iter().map(|b| if *b { "1" } else { "0" }).collect::<Vec<_>>().join(" ")
}

fn parse_marker(text: &str) -> Option<[bool; 3]> {
    let v: Vec<bool> = text.split_whitespace().map(|t| t == "1").collect();
    <[bool; 3]>::try_from(v).ok()
}

/// Undoes a Block All left behind by a crash. Returns true if one was found and undone,
/// `Err` if one was found but couldn't be undone (not elevated).
pub fn recover_block_all() -> Result<bool, String> {
    let _ = std::fs::remove_file(closed_path());
    restore_audit();
    let path = marker_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        let _ = std::fs::remove_file(ask_marker_path());
        return Ok(false);
    };
    let prev = parse_marker(&text).unwrap_or([false; 3]);
    firewall::set_default_outbound_blocked(prev).map_err(|e| format!("Block All is still active from an earlier session and couldn't be undone: {e}"))?;
    remove_exceptions();
    resume_suspended();
    let _ = std::fs::remove_file(ask_marker_path());
    let _ = std::fs::remove_file(path);
    Ok(true)
}

pub fn block_all_marker_exists() -> bool {
    marker_path().exists()
}

fn remove_exceptions() {
    if let Ok((rules, _)) = firewall::rules_in_group(GROUP) {
        for r in rules.iter().filter(|r| is_ours(&r.grouping, &r.name) && r.name.starts_with(BLOCK_ALL_PREFIX)) {
            let _ = firewall::remove_rule(&r.name);
        }
    }
}

/// Rules made under the old name (RustyWire) take the RustWarden name and groups, so the app keeps owning them.
/// Returns how many it renamed, or the first error after trying them all. The Block All exception for RustWarden
/// itself is remade for `own_exe`, since it named the old exe.
pub fn adopt_legacy_rules(own_exe: &str) -> Result<usize, String> {
    const OLD: &str = "RustyWire";
    let mut found = Vec::new();
    for group in [OLD, "RustyWire saved profiles", "RustyWire helper lease"] {
        found.extend(firewall::rules_in_group(group)?.0);
    }
    found.extend(firewall::rules_named("RustyWire ")?);
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found.dedup_by(|a, b| a.name == b.name);
    let (mut renamed, mut error) = (0, None);
    for r in found {
        let name = r.name.replace(OLD, "RustWarden");
        let group = r.grouping.strip_prefix(OLD).map_or(r.grouping.clone(), |rest| format!("RustWarden{rest}"));
        match firewall::adopt_rule(&r.name, &name, &group) {
            Ok(()) => renamed += 1,
            Err(e) => error = Some(e),
        }
        if name == format!("{BLOCK_ALL_PREFIX}: RustWarden") && !r.program.eq_ignore_ascii_case(own_exe) {
            let _ = firewall::remove_rule(&name);
            let _ = firewall::add_rule(&block_all_exceptions(own_exe)[0]);
        }
    }
    error.map_or(Ok(renamed), Err)
}

/// What [`remove_all_owned`] did. `failed` holds one message per rule that could not be changed.
#[derive(Debug, Default)]
pub struct Removal {
    pub removed: usize,
    pub handed_back: usize,
    pub failed: Vec<String>,
}

/// The rules of ours in [`GROUP`] to delete, and the imported rules to hand back untouched.
fn plan_removals(rules: &[Rule]) -> (Vec<String>, Vec<String>) {
    let (imported, ours): (Vec<&Rule>, Vec<&Rule>) = rules.iter().filter(|r| is_ours(&r.grouping, &r.name)).partition(|r| r.name.starts_with(IMPORT_PREFIX));
    (ours.iter().map(|r| r.name.clone()).collect(), imported.iter().map(|r| r.name.clone()).collect())
}

/// Undoes Block All and deletes every rule RustWarden owns, parked profile rules included. Used by
/// "Restore firewall defaults" and by the `--remove-all-rules` rescue, so both behave the same.
/// A rule that can't be changed is recorded and the rest still go; `log` gets one line per change.
pub fn remove_all_owned(log: &mut dyn FnMut(&str)) -> Result<Removal, String> {
    let mut out = Removal::default();
    if recover_block_all()? {
        log("Undid a Block All left over from an earlier session.");
    }
    let (delete, hand_back) = plan_removals(&firewall::rules_in_group(GROUP)?.0);
    for name in hand_back {
        match firewall::adopt_rule(&name, &name, "") {
            Ok(()) => {
                out.handed_back += 1;
                log(&format!("Handed back to the other firewall: {name}"));
            }
            Err(e) => {
                log(&format!("Could not hand back {name}: {e}"));
                out.failed.push(format!("{name}: {e}"));
            }
        }
    }
    // Parked rules of saved profiles are ours too; the profiles themselves have nothing left to restore.
    let parked = firewall::rules_in_group(STASH_GROUP)?.0.into_iter().chain(firewall::rules_in_group(super::lease::GROUP)?.0).map(|r| r.name);
    for name in delete.into_iter().chain(parked) {
        match firewall::remove_rule(&name) {
            Ok(()) => {
                out.removed += 1;
                log(&format!("Removed: {name}"));
            }
            Err(e) => {
                log(&format!("Could not remove {name}: {e}"));
                out.failed.push(format!("{name}: {e}"));
            }
        }
    }
    Ok(out)
}

fn info_of(r: &Rule) -> FwRuleInfo {
    FwRuleInfo { name: r.name.clone(), program: r.program.to_lowercase(), service: r.service.to_lowercase(), outbound: r.outbound, block: r.block, enabled: r.enabled }
}

/// Settings key holding our rules as last seen ([`manifest_text`]), so a change made while RustWarden was closed
/// is noticed at the next start.
const MANIFEST_KEY: &str = "fw_manifest";

/// Rules that went, changed or appeared between two reads.
#[derive(Debug, Default, PartialEq, Eq)]
struct Drift {
    missing: Vec<String>,
    altered: Vec<String>,
    added: Vec<String>,
}

impl Drift {
    fn is_empty(&self) -> bool {
        self.missing.is_empty() && self.altered.is_empty() && self.added.is_empty()
    }

    /// "1 missing (a); 2 altered (b, c)", with at most `names` rule names per kind.
    fn describe(&self, names: usize) -> String {
        [("missing", &self.missing), ("altered", &self.altered), ("added", &self.added)]
            .iter()
            .filter(|(_, rules)| !rules.is_empty())
            .map(|(what, rules)| format!("{} {what} ({}{})", rules.len(), rules.iter().take(names).map(String::as_str).collect::<Vec<_>>().join(", "), if rules.len() > names { ", …" } else { "" }))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// What differs between `before` and `now`, by rule name. Block All's exceptions come and go with Block All, so they don't count.
fn drift(before: &[FwRuleInfo], now: &[FwRuleInfo]) -> Drift {
    let tracked = |r: &&FwRuleInfo| !r.name.starts_with(BLOCK_ALL_PREFIX);
    let mut d = Drift::default();
    for b in before.iter().filter(tracked) {
        match now.iter().find(|n| n.name == b.name) {
            None => d.missing.push(b.name.clone()),
            Some(n) if n != b => d.altered.push(b.name.clone()),
            Some(_) => {}
        }
    }
    d.added = now.iter().filter(tracked).filter(|n| !before.iter().any(|b| b.name == n.name)).map(|n| n.name.clone()).collect();
    d
}

/// One tab-separated line per rule: name, program, service, then direction, action and enabled as 1 or 0.
fn manifest_text(rules: &[FwRuleInfo]) -> String {
    rules.iter().map(|r| format!("{}\t{}\t{}\t{}{}{}", r.name, r.program, r.service, u8::from(r.outbound), u8::from(r.block), u8::from(r.enabled))).collect::<Vec<_>>().join("\n")
}

/// The rules in [`manifest_text`]; a line that doesn't fit is skipped.
fn parse_manifest(text: &str) -> Vec<FwRuleInfo> {
    text.lines()
        .filter_map(|l| {
            let fields: Vec<&str> = l.split('\t').collect();
            let [name, program, service, flags] = fields[..] else { return None };
            let flags: Vec<bool> = flags.chars().map(|c| c == '1').collect();
            let [outbound, block, enabled] = flags[..] else { return None };
            Some(FwRuleInfo { name: name.into(), program: program.into(), service: service.into(), outbound, block, enabled })
        })
        .collect()
}

pub struct FwController {
    shared: Arc<Shared>,
    /// Serialises writes so two UI actions can't interleave their re-reads.
    op: Mutex<()>,
    /// What we believe our rules look like; a difference after a re-read means someone else changed them.
    expected: Mutex<Option<Vec<FwRuleInfo>>>,
    own_exe: String,
}

fn sorted(mut v: Vec<FwRuleInfo>) -> Vec<FwRuleInfo> {
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

impl FwController {
    pub fn new(shared: Arc<Shared>) -> Self {
        let own_exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let enabled = shared.open_db().ok().and_then(|db| db.kv_get("fw_enabled")).map(|v| v == "1").unwrap_or(false);
        shared.state().fw_enabled = enabled;
        // Our rules as the last run left them: the first read of this run is compared against them. None on a first run.
        let last_run = shared.open_db().ok().and_then(|db| db.kv_get(MANIFEST_KEY)).map(|t| parse_manifest(&t));
        Self { shared, op: Mutex::new(()), expected: Mutex::new(last_run), own_exe }
    }

    pub(super) fn lock_op(&self) -> std::sync::MutexGuard<'_, ()> {
        self.op.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn need_admin(&self) -> Result<(), String> {
        if self.shared.elevated { Ok(()) } else { Err("Changing firewall rules needs administrator rights. Use \"Restart as administrator\".".into()) }
    }

    /// Re-reads Windows Firewall into the shared state. `from_us` marks the result as the new baseline.
    pub fn refresh(&self, from_us: bool) {
        let snapshot = match (firewall::profile_state(), firewall::rules_in_group(GROUP)) {
            (Ok(p), Ok((rules, _))) => {
                let ours: Vec<FwRuleInfo> = rules.iter().filter(|r| is_ours(&r.grouping, &r.name) && !is_aux(&r.name)).map(info_of).collect();
                // A block rule for a program with no app record (blocked before it ever sent traffic) would be invisible on the Firewall tab.
                let blocked: Vec<_> = rules.iter().filter(|r| is_ours(&r.grouping, &r.name) && r.block && !r.program.is_empty() && !is_aux(&r.name)).collect();
                // No connection (and schema run) every 5 s when there is nothing to record.
                if !blocked.is_empty()
                    && let Ok(db) = self.shared.open_db()
                {
                    let now = crate::clock::now_unix();
                    for r in blocked {
                        if r.service.is_empty() {
                            super::apps::ensure_record(&db, &r.program, now);
                        } else {
                            ensure_service_record(&db, &r.program, &r.service, now);
                        }
                    }
                }
                let out_prefix = format!("{THREAT_PREFIX}out ");
                let mut threat_blocked: Vec<String> = rules.iter().filter(|r| r.grouping == GROUP).filter_map(|r| r.name.strip_prefix(&out_prefix).map(str::to_owned)).collect();
                threat_blocked.sort();
                let active = block_all_marker_exists();
                let ask = active && ask_marker_exists();
                FwSnapshot { readable: true, error: None, windows_firewall_on: p.active_profiles_on(), rules: ours, block_all_active: active && !ask, ask_active: ask, threat_blocked }
            }
            (Err(e), _) | (_, Err(e)) => FwSnapshot { readable: false, error: Some(e), ..FwSnapshot::default() },
        };
        if snapshot.readable {
            let now = sorted(snapshot.rules.clone());
            let mut expected = self.expected.lock().unwrap_or_else(|e| e.into_inner());
            let drifted = expected.as_ref().filter(|_| !from_us).map(|before| drift(before, &now));
            if let Some(d) = drifted
                && !d.is_empty()
                && let Ok(db) = self.shared.open_db()
            {
                crate::applog::line("rustwarden.log", &format!("RustWarden firewall rules were changed outside RustWarden: {}", d.describe(usize::MAX)));
                self.shared.alert(&db, AlertKind::FirewallRules, "Windows Firewall", "RustWarden rules were changed outside RustWarden:", &d.describe(5), "");
            }
            // Saved after the report, so a change is reported once and not again at every start.
            if expected.as_ref() != Some(&now)
                && let Ok(db) = self.shared.open_db()
            {
                let _ = db.kv_set(MANIFEST_KEY, &manifest_text(&now));
            }
            *expected = Some(now);
        }
        let error = snapshot.error.clone();
        self.shared.state().fw = snapshot;
        self.shared.set_note("firewall", error.map(|e| StatusNote::warn(format!("Firewall unavailable: {e}"))));
        self.shared.repaint();
    }

    pub fn set_verdict(&self, key: &str, direction: Direction, verdict: Verdict) -> Result<(), String> {
        self.need_admin()?;
        let _g = self.lock_op();
        let db = self.shared.open_db().map_err(|e| e.to_string())?;
        // The path comes from the app table, or from an existing rule for programs we only know by rule.
        let path = db
            .app_by_key(key)
            .ok()
            .flatten()
            .map(|a| a.path)
            .filter(|p| !p.is_empty())
            .or_else(|| self.shared.state().fw.rules.iter().find(|r| row_key(&r.program, &r.service) == key).map(|r| r.program.clone()))
            .ok_or("This program has no executable path, so it can't be blocked")?;
        self.apply_verdict(key, &path, direction, verdict)
    }

    /// Blocks the program at `path` in both directions (its rules are RustWarden's own, so they show on the Firewall tab
    /// and go with "Restore firewall defaults").
    pub fn block_path(&self, path: &str) -> Result<String, String> {
        self.need_admin()?;
        let _g = self.lock_op();
        let key = super::apps::key_for_path(path);
        for direction in [Direction::Out, Direction::In] {
            self.apply_verdict(&key, path, direction, Verdict::Blocked)?;
        }
        Ok(format!("Blocked {}", super::apps::file_name(path)))
    }

    /// Adds or removes the block rule for `path`, or for one service inside it when `key` is a service row.
    /// The caller holds the op lock.
    fn apply_verdict(&self, key: &str, path: &str, direction: Direction, verdict: Verdict) -> Result<(), String> {
        if let Some(reason) = critical_reason(key, path, &self.own_exe, &super::apps::system_root()) {
            return Err(reason.into());
        }
        let service = service_of_key(key);
        if !service.is_empty() && verdict == Verdict::Blocked {
            if service.contains('+') {
                return Err("This process hosts several services, so Windows Firewall can't block just one of them".into());
            }
            if !firewall::service_has_sid(service)? {
                return Err("This service has no identity of its own, so Windows Firewall can't tell its traffic apart".into());
            }
        }
        let path = path.to_owned();
        let (rules, _) = firewall::rules_in_group(GROUP)?;
        let existing = find_block(&rules, direction, &path, service);
        match (verdict, existing) {
            (Verdict::Blocked, None) => {
                let enabled = self.shared.state().fw_enabled;
                let specs = if direction == Direction::Local { lan_specs(&path, service, enabled) } else { vec![block_spec(direction, &path, service, enabled)] };
                for spec in &specs {
                    firewall::add_rule(spec)?;
                }
            }
            (Verdict::Allowed, Some(r)) => {
                let row = if service.is_empty() { key_for_path(&path) } else { service_key(&key_for_path(&path), &service.to_lowercase()) };
                let names: Vec<&str> = if direction == Direction::Local {
                    rules.iter().filter(|r| is_ours(&r.grouping, &r.name) && r.block && is_lan(&r.name) && rule_key(r) == row).map(|r| r.name.as_str()).collect()
                } else {
                    vec![r.name.as_str()]
                };
                for name in names {
                    firewall::remove_rule(name)?;
                }
            }
            _ => {}
        }
        // Under Block All / Prompt everything is denied by default, so lifting the block isn't enough: the program needs an allow rule.
        if verdict == Verdict::Allowed && direction == Direction::Out && block_all_marker_exists() {
            self.add_allow(&path, service)?;
        }
        self.refresh(true);
        Ok(())
    }

    /// Creates the allow rule for a program (or one of its services) that doesn't have one yet.
    fn add_allow(&self, path: &str, service: &str) -> Result<(), String> {
        let (rules, _) = firewall::rules_in_group(GROUP)?;
        let spec = allow_spec(path, service);
        let row = if service.is_empty() { key_for_path(path) } else { service_key(&key_for_path(path), &service.to_lowercase()) };
        if !rules.iter().any(|r| r.name == spec.name || (is_ours(&r.grouping, &r.name) && !r.block && r.outbound && rule_key(r) == row)) {
            firewall::add_rule(&spec)?;
        }
        Ok(())
    }

    /// Creates allow rules for the programs that don't have one yet.
    fn add_allows(&self, paths: &[String]) -> Result<(), String> {
        for path in paths {
            self.add_allow(path, "")?;
        }
        Ok(())
    }

    /// Blocks (or lifts the block on) one remote address in both directions, for any program.
    pub fn block_ip(&self, ip: std::net::IpAddr, on: bool) -> Result<(), String> {
        self.need_admin()?;
        if on && super::threat::is_protected(ip, &super::threat::protected_addrs(&super::threat::home_assistant_urls())) {
            return Err(format!("{ip} is on your own network, or is a gateway, DNS server or Home Assistant host, so it can't be blocked."));
        }
        let _g = self.lock_op();
        for outbound in [true, false] {
            let name = format!("{THREAT_PREFIX}{} {ip}", if outbound { "out" } else { "in" });
            let _ = firewall::remove_rule(&name); // absent is fine; also avoids duplicates
            if on {
                let added = firewall::add_rule(&RuleSpec {
                    interfaces: None,
                    name,
                    description: "Created by RustWarden: address is on a malicious-IP list. Use \"Restore firewall defaults\" in RustWarden to remove all such rules.".into(),
                    grouping: GROUP.into(),
                    program: None,
                    outbound,
                    block: true,
                    enabled: true,
                    protocol: None,
                    local_ports: None,
                    remote_ports: None,
                    remote_addrs: Some(ip.to_string()),
                    service: None,
                });
                if let Err(e) = added {
                    // Don't leave only one direction blocked.
                    let _ = firewall::remove_rule(&format!("{THREAT_PREFIX}out {ip}"));
                    let _ = firewall::remove_rule(&format!("{THREAT_PREFIX}in {ip}"));
                    self.refresh(true);
                    return Err(e);
                }
            }
        }
        self.refresh(true);
        Ok(())
    }

    /// Makes the destination rules in Windows Firewall exactly `want`: removes the rules named in
    /// `remove` and adds `add`. Every name must start with [`DEST_PREFIX`]; anything else is refused.
    pub fn apply_dest(&self, remove: &[String], add: &[RuleSpec]) -> Result<(), String> {
        self.apply_owned(DEST_PREFIX, remove, add)
    }

    /// Like [`Self::apply_dest`] for the peer-to-peer guard's rules ([`P2P_PREFIX`]).
    pub fn apply_p2p(&self, remove: &[String], add: &[RuleSpec]) -> Result<(), String> {
        self.apply_owned(P2P_PREFIX, remove, add)
    }

    /// Like [`Self::apply_dest`] for the VPN kill switch and DNS-over-HTTPS block ([`GUARD_PREFIX`]).
    pub fn apply_guard(&self, remove: &[String], add: &[RuleSpec]) -> Result<(), String> {
        self.apply_owned(GUARD_PREFIX, remove, add)
    }

    /// Removes the kill switch's block (the DNS-over-HTTPS block is a standing policy and stays).
    fn drop_kill_switch(&self) {
        if !self.shared.elevated {
            return;
        }
        for r in firewall::rules_named(super::guard::KILL_PREFIX).unwrap_or_default() {
            let _ = firewall::remove_rule(&r.name);
        }
    }

    fn apply_owned(&self, prefix: &str, remove: &[String], add: &[RuleSpec]) -> Result<(), String> {
        self.need_admin()?;
        if remove.iter().chain(add.iter().map(|s| &s.name)).any(|n| !n.starts_with(prefix)) {
            return Err("Refused to change a rule that is not one of ours of this kind.".into());
        }
        let _g = self.lock_op();
        for name in remove {
            let _ = firewall::remove_rule(name); // already gone is fine
        }
        let mut result = Ok(());
        for spec in add {
            if let Err(e) = firewall::add_rule(spec) {
                result = Err(e);
                break;
            }
        }
        self.refresh(true);
        result
    }

    /// Applies the user's answer to a Prompt prompt.
    pub fn answer(&self, path: &str, answer: Answer) -> Result<(), String> {
        self.need_admin()?;
        let _g = self.lock_op();
        if path == ICMP_PATH {
            // Pings are stopped already by Prompt's default; "Block" has nothing to add.
            if matches!(answer, Answer::Allow { .. }) {
                let (rules, _) = firewall::rules_in_group(GROUP)?;
                for spec in icmp_specs().iter().filter(|s| !rules.iter().any(|r| r.name == s.name)) {
                    firewall::add_rule(spec)?;
                }
                self.refresh(true);
            }
            return Ok(());
        }
        match answer {
            Answer::Allow { local } => {
                self.add_allows(&[path.to_owned()])?;
                if local {
                    self.refresh(true);
                } else {
                    // Prompt denies by default, so local access stays denied unless the box was ticked.
                    self.apply_verdict(&key_for_path(path), path, Direction::Local, Verdict::Blocked)?;
                }
            }
            Answer::Block(direction) => {
                let key = key_for_path(path);
                for d in direction.map_or(vec![Direction::In, Direction::Out], |d| vec![d]) {
                    self.apply_verdict(&key, path, d, Verdict::Blocked)?;
                }
            }
        }
        Ok(())
    }

    /// Whether the ping allow rules exist.
    pub fn icmp_allowed(&self) -> bool {
        firewall::rules_in_group(GROUP).is_ok_and(|(rules, _)| icmp_specs().iter().all(|s| rules.iter().any(|r| r.name == s.name)))
    }

    /// Whether a program Prompt just stopped should be put to the user. Critical programs
    /// are allowed here instead (they can't be blocked), and a program that already has an
    /// outbound rule was decided earlier.
    pub fn needs_prompt(&self, path: &str) -> bool {
        let key = key_for_path(path);
        if critical_reason(&key, path, &self.own_exe, &super::apps::system_root()).is_some() {
            if let Err(e) = self.answer(path, Answer::Allow { local: true }) {
                self.shared.set_note("ask", Some(StatusNote::warn(format!("Prompt couldn't allow a Windows program: {e}"))));
            }
            return false;
        }
        !self.shared.state().fw.rules.iter().any(|r| r.program == key && r.outbound && !is_lan(&r.name))
    }

    pub fn remove_app(&self, key: &str) -> Result<(), String> {
        self.need_admin()?;
        // `key` is the lower-cased path, which is enough for the critical-program check.
        if let Some(reason) = critical_reason(key, key, &self.own_exe, &super::apps::system_root()) {
            return Err(reason.into());
        }
        let _g = self.lock_op();
        let (rules, _) = firewall::rules_in_group(GROUP)?;
        for r in rules.iter().filter(|r| is_ours(&r.grouping, &r.name) && !r.name.starts_with(BLOCK_ALL_PREFIX) && !is_aux(&r.name) && rule_key(r) == key) {
            firewall::remove_rule(&r.name)?;
        }
        if let Ok(db) = self.shared.open_db() {
            let mut removed = removed_apps(&db);
            removed.insert(key.to_owned(), crate::clock::now_unix());
            let text: Vec<String> = removed.iter().map(|(k, t)| format!("{k}\t{t}")).collect();
            let _ = db.kv_set(REMOVED_KEY, &text.join("\n"));
        }
        // Refresh first: a block event handled against the old rule list would find the removed allow
        // rule still there and wrongly treat the app as already decided.
        self.refresh(true);
        self.shared.state().ask_reset = true;
        Ok(())
    }

    pub fn set_enabled(&self, on: bool) -> Result<(), String> {
        self.need_admin()?;
        let _g = self.lock_op();
        let (rules, _) = firewall::rules_in_group(GROUP)?;
        let paused = self.shared.open_db().map(|db| paused_extras(&db)).unwrap_or_default();
        // Address blocks from the malicious-IP list belong to no profile and no toggle.
        for r in rules.iter().filter(|r| is_ours(&r.grouping, &r.name) && r.block && !is_aux(&r.name) && !paused.contains(&r.name)) {
            firewall::set_rule_enabled(&r.name, on)?;
        }
        if let Ok(db) = self.shared.open_db() {
            let _ = db.kv_set("fw_enabled", if on { "1" } else { "0" });
        }
        self.shared.state().fw_enabled = on;
        self.refresh(true);
        Ok(())
    }

    pub fn set_mode(&self, mode: FirewallMode) -> Result<(), String> {
        self.need_admin()?;
        let _g = self.lock_op();
        // Moving between Block All and Prompt starts from the saved defaults.
        self.end_block_all()?;
        match mode {
            FirewallMode::ClickToBlock => {}
            FirewallMode::BlockAll => self.begin_block_all(false)?,
            FirewallMode::AskToConnect => self.begin_block_all(true)?,
        }
        if let Ok(db) = self.shared.open_db() {
            let _ = db.kv_set(
                ASK_KEY,
                match mode {
                    FirewallMode::ClickToBlock => "0",
                    FirewallMode::AskToConnect => "1",
                    FirewallMode::BlockAll => "2",
                },
            );
        }
        self.refresh(true);
        Ok(())
    }

    /// Puts the firewall back as it was at the last run: the on/off switch for block rules, and Ask To
    /// Connect or Block All. Exiting ends both modes (nothing would answer the prompts), but the choice is remembered.
    pub fn resume(&self) {
        let Ok(db) = self.shared.open_db() else { return };
        if self.shared.elevated {
            let on = self.shared.state().fw_enabled;
            let paused = paused_extras(&db);
            let stale = self.shared.state().fw.rules.iter().any(|r| r.block && r.enabled != on && !paused.contains(&r.name));
            if stale && let Err(e) = self.set_enabled(on) {
                self.shared.set_note("ask", Some(StatusNote::warn(format!("The firewall switch couldn't be restored: {e}"))));
            }
        }
        let mode = match db.kv_get(ASK_KEY).as_deref() {
            Some("1") => FirewallMode::AskToConnect,
            Some("2") => FirewallMode::BlockAll,
            _ => return,
        };
        // Left in force by the last exit: carry on rather than open the firewall for a moment.
        if mode == FirewallMode::AskToConnect && kept_block(self.shared.settings().keep_blocking_closed, self.shared.elevated) {
            // The rules may have been deleted while we were away (crash, Windows Firewall console): rebuild them, or give up the block rather than leave no internet.
            if let Err(e) = self.heal_kept_block() {
                let _ = self.end_block_all();
                self.shared.set_note("ask", Some(StatusNote::warn(format!("The kept block was broken and has been lifted: {e}"))));
            }
            return;
        }
        if let Err(e) = self.set_mode(mode) {
            self.shared.set_note("ask", Some(StatusNote::warn(format!("{} couldn't be turned back on: {e}", mode.label()))));
        }
    }

    /// Block All, or with `ask` Prompt: the same default-deny, but every program RustWarden
    /// has already seen keeps its internet access and new ones are put to the user.
    fn begin_block_all(&self, ask: bool) -> Result<(), String> {
        let state = firewall::profile_state()?;
        if !state.active_profiles_on() {
            return Err("Windows Firewall is off, so Block All would do nothing. Turn it on first.".into());
        }
        let previous = firewall::default_outbound_blocked()?;
        std::fs::create_dir_all(state_dir()).map_err(|e| e.to_string())?;
        // The marker comes first: if anything below fails or we crash, the next start can undo it.
        std::fs::write(marker_path(), marker_text(previous)).map_err(|e| format!("Can't write the Block All safety marker: {e}"))?;
        let result = (|| {
            for spec in block_all_exceptions(&self.own_exe) {
                firewall::add_rule(&spec)?;
            }
            if ask {
                std::fs::write(ask_marker_path(), "ask").map_err(|e| e.to_string())?;
                if self.shared.settings().keep_blocking_closed
                    && let Err(e) = enable_audit()
                {
                    self.shared.set_note("ask", Some(StatusNote::warn(format!("Blocked connections can't be logged while RustWarden is closed: {e}"))));
                }
                // Allowed before the default flips, so nothing already in use loses its connection.
                self.add_allows(&self.known_programs())?;
            } else {
                let names = rules_to_suspend(&firewall::enabled_outbound_allows()?, &super::apps::system_root());
                // Written before switching off, so a crash midway still gets every rule back.
                std::fs::write(suspended_path(), names.join("\n")).map_err(|e| e.to_string())?;
                for name in &names {
                    firewall::set_rule_enabled(name, false)?;
                }
            }
            firewall::set_default_outbound_blocked([true; 3])
        })();
        if let Err(e) = result {
            let _ = self.end_block_all();
            return Err(format!("Block All could not be turned on and was undone: {e}"));
        }
        Ok(())
    }

    /// Re-creates any exception or allow rule that went missing under a block that stayed in force.
    fn heal_kept_block(&self) -> Result<(), String> {
        let _g = self.lock_op();
        let (rules, _) = firewall::rules_in_group(GROUP)?;
        let wanted = block_all_exceptions(&self.own_exe);
        // A block kept by an older version still has the curl / nslookup / PowerShell exceptions it made then.
        for name in stale_exceptions(&rules, &wanted) {
            let _ = firewall::remove_rule(&name);
        }
        for spec in wanted {
            if !rules.iter().any(|r| r.name == spec.name) {
                firewall::add_rule(&spec)?;
            }
        }
        self.add_allows(&self.known_programs())?;
        self.refresh(true);
        Ok(())
    }

    /// Paths of installed programs RustWarden has seen on the network.
    fn known_programs(&self) -> Vec<String> {
        let Ok(db) = self.shared.open_db() else { return Vec::new() };
        let apps = db.apps().unwrap_or_default();
        // Programs the user removed from the list are new again, so Prompt asks about them.
        let removed = removed_apps(&db);
        let since = profile_since(&db);
        // A program we block outbound is never given an allow rule behind the user's back.
        let rules = firewall::rules_in_group(GROUP).map(|(r, _)| r).unwrap_or_default();
        apps.into_iter()
            .filter(|a| {
                !a.path.is_empty()
                    && a.service.is_empty()
                    && a.missing_since.is_none()
                    && a.last_seen >= since
                    && !removed.contains_key(&a.key)
                    && find_block(&rules, Direction::Out, &a.path, &a.service).is_none()
            })
            .map(|a| a.path)
            .collect()
    }

    /// Repeats [`Self::block_windows_extras`] when the setting is on and the interval has passed, so
    /// apps Windows Update reinstalled under a new version folder are covered again.
    fn reapply_windows_extras(&self) {
        let s = self.shared.settings();
        if !s.block_windows_auto || !self.shared.elevated {
            return;
        }
        let Ok(db) = self.shared.open_db() else { return };
        let now = crate::clock::now_unix();
        let last: i64 = db.kv_get(WINEXTRAS_KEY).and_then(|v| v.parse().ok()).unwrap_or(0);
        // The first run is the user's own click, so a missing stamp means "not yet asked for".
        if last == 0 || now - last < i64::from(s.block_windows_hours) * 3600 {
            return;
        }
        let note = match self.block_windows_extras() {
            Ok(_) => None,
            Err(e) => Some(StatusNote::warn(format!("Re-blocking Windows components failed: {e}"))),
        };
        self.shared.set_note("winextras", note);
    }

    /// Blocks both directions for the Windows programs in [`super::windows_extras`] that exist here.
    /// Programs already blocked are left as they are; our own allow rule for one is removed.
    pub fn block_windows_extras(&self) -> Result<usize, String> {
        self.need_admin()?;
        let _g = self.lock_op();
        let (rules, _) = firewall::rules_in_group(GROUP)?;
        let (root, enabled) = (super::apps::system_root(), self.shared.state().fw_enabled);
        let mut done = 0;
        let db = self.shared.open_db().ok();
        let paused = db.as_ref().map(extras_paused).unwrap_or_default();
        let mut made = db.as_ref().map(extras_rules).unwrap_or_default();
        for (group, path) in super::windows_extras::resolve(&self.own_exe) {
            if paused.contains(&group) || critical_reason(&key_for_path(&path), &path, &self.own_exe, &root).is_some() {
                continue;
            }
            let key = key_for_path(&path);
            for r in rules.iter().filter(|r| is_ours(&r.grouping, &r.name) && !r.block && key_for_path(&r.program) == key) {
                firewall::remove_rule(&r.name)?;
            }
            let mut added = false;
            for d in [Direction::Out, Direction::In] {
                if find_block(&rules, d, &path, "").is_none() {
                    let spec = block_spec(d, &path, "", enabled);
                    firewall::add_rule(&spec)?;
                    // Only rules made here are recorded, so Unblock never removes a block the user set themselves.
                    made.push((group, spec.name));
                    added = true;
                }
            }
            done += usize::from(added);
        }
        if let Some(db) = &db {
            let _ = db.kv_set(WINEXTRAS_KEY, &crate::clock::now_unix().to_string());
            made.sort();
            made.dedup();
            let _ = db.kv_set(WINEXTRAS_RULES_KEY, &made.iter().map(|(g, n)| format!("{g}\t{n}")).collect::<Vec<_>>().join("\n"));
        }
        self.refresh(true);
        Ok(done)
    }

    /// Per group of [`super::windows_extras::GROUPS`]: (has rules made by that feature, is paused).
    /// Reads through the reader connection: the Settings dialog polls this, and opening a database each time stalls the UI.
    pub fn windows_extras_state_in(db: Option<&super::db::Db>) -> Vec<(bool, bool)> {
        let n = super::windows_extras::GROUPS.len();
        let Some(db) = db else { return vec![(false, false); n] };
        let (made, paused) = (extras_rules(db), extras_paused(db));
        (0..n).map(|g| (made.iter().any(|(m, _)| *m == g), paused.contains(&g))).collect()
    }

    /// Unblocks, pauses (rules switched off, kept) or resumes the rules that "Block Windows components"
    /// made for one group of [`super::windows_extras::GROUPS`]. Returns how many rules it touched.
    pub fn windows_extras_act(&self, group: usize, act: ExtrasAct) -> Result<usize, String> {
        self.need_admin()?;
        let _g = self.lock_op();
        let db = self.shared.open_db().map_err(|e| e.to_string())?;
        let (mut made, mut paused) = (extras_rules(&db), extras_paused(&db));
        let enabled = self.shared.state().fw_enabled;
        // The list is in the user's database: only rules with our own name are acted on.
        let names: Vec<String> = made.iter().filter(|(g, n)| *g == group && n.starts_with(NAME_PREFIX)).map(|(_, n)| n.clone()).collect();
        for name in &names {
            // A rule deleted by hand meanwhile is fine.
            let _ = match act {
                ExtrasAct::Unblock => firewall::remove_rule(name),
                ExtrasAct::Pause => firewall::set_rule_enabled(name, false),
                ExtrasAct::Resume => firewall::set_rule_enabled(name, enabled),
            };
        }
        paused.retain(|g| *g != group);
        if act == ExtrasAct::Pause {
            paused.push(group);
        }
        if act == ExtrasAct::Unblock {
            made.retain(|(g, _)| *g != group);
        }
        let _ = db.kv_set(WINEXTRAS_RULES_KEY, &made.iter().map(|(g, n)| format!("{g}\t{n}")).collect::<Vec<_>>().join("\n"));
        let _ = db.kv_set(WINEXTRAS_PAUSED_KEY, &paused.iter().map(usize::to_string).collect::<Vec<_>>().join(","));
        self.refresh(true);
        Ok(names.len())
    }

    /// Restores the saved defaults and removes the exceptions. Safe to call when Block All is off.
    pub fn end_block_all(&self) -> Result<(), String> {
        if !block_all_marker_exists() {
            return Ok(());
        }
        recover_block_all().map(|_| ())
    }

    /// Deletes RustWarden's own rules (after ending Block All) and nothing else.
    pub fn restore_defaults(&self) -> Result<(), String> {
        self.need_admin()?;
        let _g = self.lock_op();
        if let Ok(db) = self.shared.open_db() {
            super::lease::end(&db, true);
        }
        let removal = remove_all_owned(&mut |_| {})?;
        // Forget removed apps and Prompt decisions so the Firewall tab starts clean.
        if let Ok(db) = self.shared.open_db() {
            let _ = db.kv_set(REMOVED_KEY, "");
            let _ = db.kv_set(ASK_KEY, "0");
        }
        self.shared.state().ask_reset = true;
        self.refresh(true);
        match removal.failed.first() {
            Some(first) => Err(first.clone()),
            None => Ok(()),
        }
    }

    /// Brings the other firewall's per-program rules under RustWarden's control by
    /// moving them into our group, so they show on the Firewall tab. With `rename` they also get
    /// RustWarden's naming (the other firewall then no longer recognises them); without it the names stay,
    /// so they keep working if that firewall returns. Returns how many.
    /// Rules for no particular program, and ones that would duplicate a RustWarden rule, stay as they are.
    pub fn import_rules(&self, rename: bool) -> Result<usize, String> {
        self.need_admin()?;
        let _g = self.lock_op();
        let mut taken: Vec<String> = firewall::rules_in_group(GROUP)?.0.into_iter().map(|r| r.name).collect();
        let mut done = 0;
        for r in firewall::rules_named(IMPORT_PREFIX)?.into_iter().filter(|r| !r.program.is_empty() && !(r.grouping == GROUP && !rename)) {
            let name = if rename { tagged_name(&format!("{} {}", if r.block { "block" } else { "allow" }, if r.outbound { "out" } else { "in" }), &r.program, &r.service) } else { r.name.clone() };
            if rename && taken.contains(&name) {
                continue;
            }
            firewall::adopt_rule(&r.name, &name, GROUP)?;
            taken.push(name);
            done += 1;
        }
        self.refresh(true);
        Ok(done)
    }

    /// Profile names (the active one always included) and the active one.
    pub fn profiles(&self) -> (Vec<String>, String) {
        Self::profiles_in(self.shared.open_db().ok().as_ref())
    }

    /// [`Self::profiles`] read from an already open `db`.
    pub fn profiles_in(db: Option<&super::db::Db>) -> (Vec<String>, String) {
        let get = |k: &str| db.and_then(|d| d.kv_get(k));
        let active = get(ACTIVE_PROFILE_KEY).unwrap_or_else(|| DEFAULT_PROFILE.into());
        let mut list: Vec<String> = get(PROFILES_KEY).unwrap_or_default().lines().map(str::to_owned).collect();
        if !list.contains(&active) {
            list.insert(0, active.clone());
        }
        (list, active)
    }

    /// Parks the active profile's rules and brings in `name`'s (or an empty new one). Rules are only
    /// ever switched off and moved to [`STASH_GROUP`], never deleted, so every profile stays intact
    /// in Windows Firewall. Block All / Prompt end first, as the rule set under them changes.
    pub fn switch_profile(&self, name: &str, create: bool) -> Result<(), String> {
        self.need_admin()?;
        let _g = self.lock_op();
        let (mut list, active) = self.profiles();
        if create {
            valid_profile_name(name, &list)?;
        } else if !list.iter().any(|p| p == name) {
            return Err("That ruleset no longer exists.".into());
        }
        self.end_block_all()?;
        if let Ok(db) = self.shared.open_db() {
            let _ = db.kv_set(ASK_KEY, "0");
        }
        if name != active {
            if let Err(e) = self.stash(&active) {
                // Put back what was already parked so the Firewall tab still shows the active profile.
                let _ = self.unstash(&active);
                return Err(format!("Couldn't switch ruleset, nothing was deleted: {e}"));
            }
            if create {
                list.push(name.to_owned());
            }
            if let Ok(db) = self.shared.open_db() {
                let _ = db.kv_set(PROFILES_KEY, &list.join("\n"));
                let _ = db.kv_set(ACTIVE_PROFILE_KEY, name);
                if create {
                    let _ = db.kv_set(&since_key(name), &crate::clock::now_unix().to_string());
                }
            }
        }
        // Past this point `name` is the active profile; a failure here is finished by switching to it again.
        let result = self.unstash(name).map_err(|e| format!("Some of {name}'s rules are still switched off ({e}). Switch to it again to finish."));
        self.shared.state().ask_reset = true;
        self.refresh(true);
        result
    }

    /// Deletes an inactive profile with its parked rules. The only profile, and the active one, stay.
    pub fn delete_profile(&self, name: &str) -> Result<(), String> {
        self.need_admin()?;
        let _g = self.lock_op();
        let (mut list, active) = self.profiles();
        if !list.iter().any(|p| p == name) {
            return Err("That ruleset no longer exists.".into());
        }
        if list.len() < 2 {
            return Err("The only ruleset can't be deleted.".into());
        }
        if name == active {
            return Err("The active ruleset can't be deleted. Switch to another ruleset first.".into());
        }
        // Rules first: if one can't be removed the profile stays listed and this can be retried.
        let suffix = stash_suffix(name);
        for r in firewall::rules_in_group(STASH_GROUP)?.0.iter().filter(|r| r.name.ends_with(&suffix)) {
            firewall::remove_rule(&r.name)?;
        }
        list.retain(|p| p != name);
        if let Ok(db) = self.shared.open_db() {
            let _ = db.kv_set(
                PROFILES_KEY,
                &list.join(
                    "
",
                ),
            );
            let _ = db.kv_set(&since_key(name), "");
        }
        Ok(())
    }

    /// Switches off and moves the active rules into the stash, tagged with `profile`.
    fn stash(&self, profile: &str) -> Result<(), String> {
        let (rules, _) = firewall::rules_in_group(GROUP)?;
        for r in rules.iter().filter(|r| is_ours(&r.grouping, &r.name) && !r.name.starts_with(BLOCK_ALL_PREFIX) && !is_aux(&r.name)) {
            // Moved first, switched off second: a failure in between leaves the rule enforcing, and `unstash` can find it.
            let parked = format!("{}{}", r.name, stash_suffix(profile));
            firewall::adopt_rule(&r.name, &parked, STASH_GROUP)?;
            firewall::set_rule_enabled(&parked, false)?;
        }
        Ok(())
    }

    /// Moves `profile`'s parked rules back under their own names and switches them on again
    /// (block rules only while the RustWarden firewall toggle is on).
    fn unstash(&self, profile: &str) -> Result<(), String> {
        let suffix = stash_suffix(profile);
        let on = self.shared.state().fw_enabled;
        for r in firewall::rules_in_group(STASH_GROUP)?.0.iter().filter(|r| r.name.ends_with(&suffix)) {
            let name = &r.name[..r.name.len() - suffix.len()];
            firewall::adopt_rule(&r.name, name, GROUP)?;
            firewall::set_rule_enabled(name, !r.block || on)?;
        }
        Ok(())
    }

    pub fn enable_windows_firewall(&self) -> Result<(), String> {
        self.need_admin()?;
        let _g = self.lock_op();
        firewall::enable_windows_firewall()?;
        self.refresh(true);
        Ok(())
    }

    /// Removes block rules of apps that have been idle or uninstalled longer than the settings allow.
    pub fn cleanup(&self) {
        let settings = self.shared.settings();
        if !settings.firewall_cleanup || !self.shared.elevated {
            return;
        }
        let Ok(db) = self.shared.open_db() else { return };
        let _g = self.lock_op();
        let now = crate::clock::now_unix();
        let Ok((rules, _)) = firewall::rules_in_group(GROUP) else { return };
        let apps = db.apps().unwrap_or_default();
        for r in rules.iter().filter(|r| is_ours(&r.grouping, &r.name) && r.block) {
            let Some(app) = apps.iter().find(|a| a.key == key_for_path(&r.program)) else { continue };
            // Blocked traffic is never seen, so "idle" can't tell a blocked app from an unused one; only uninstalled apps are cleaned.
            if should_clean(app.missing_since, now, settings.cleanup_uninstalled_days) {
                let _ = firewall::remove_rule(&r.name);
            }
        }
        self.refresh(true);
    }

    /// Undoes Block All / Prompt, unless `keep` (the app is really exiting) and the setting asks for the block to stay.
    pub fn shutdown(&self, keep: bool) {
        let _g = self.lock_op();
        if keep && kept_block(self.shared.settings().keep_blocking_closed, self.shared.elevated) {
            if let Err(e) = enable_audit() {
                eprintln!("RustWarden: {e}");
            }
            let _ = std::fs::create_dir_all(state_dir()).and_then(|()| std::fs::write(closed_path(), crate::clock::now_unix().to_string()));
            return;
        }
        if let Err(e) = self.end_block_all() {
            eprintln!("RustWarden: {e}");
        }
        // Nothing would lift the kill switch's block once RustWarden is gone, which could leave the PC without internet.
        self.drop_kill_switch();
    }
}

/// Whether a rule's app is old enough to clean up: uninstalled for `uninstalled_days`.
pub fn should_clean(missing_since: Option<i64>, now: i64, uninstalled_days: u32) -> bool {
    missing_since.is_some_and(|since| now - since >= i64::from(uninstalled_days) * 86_400)
}

/// Runs the periodic re-read, which also catches rules changed from outside.
pub fn run(shared: Arc<Shared>, fw: Arc<FwController>) {
    fw.refresh(true);
    fw.resume();
    let mut tick = 0u64;
    while shared.sleep(5.0) {
        // Not while a change is half-applied, or it would be reported as an outside edit.
        {
            let _g = fw.lock_op();
            fw.refresh(false);
        }
        super::lease::sweep(&shared, &fw);
        tick += 1;
        if tick.is_multiple_of(720) {
            fw.cleanup();
        }
        // Hourly (and once soon after start) check whether the repeat is due.
        if tick == 2 || tick.is_multiple_of(720) {
            fw.reapply_windows_extras();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_engine_rule_allows_system_out_and_stays_off_the_program_list() {
        let s = engine_spec();
        assert!(is_ours(&s.grouping, &s.name) && is_aux(&s.name));
        assert!(!s.block && s.outbound && s.program.as_deref() == Some("System"));
    }

    #[test]
    fn ping_rules_are_ours_allow_icmp_and_stay_off_the_program_list() {
        let specs = icmp_specs();
        assert_eq!(specs.iter().map(|s| s.protocol).collect::<Vec<_>>(), [Some(1), Some(58)]);
        for s in &specs {
            assert!(is_ours(&s.grouping, &s.name) && is_aux(&s.name));
            assert!(!s.block && s.outbound && s.program.is_none() && s.local_ports.is_none());
        }
    }

    use super::*;

    fn named(group: &str, name: &str) -> Rule {
        Rule { name: name.into(), grouping: group.into(), program: String::new(), service: String::new(), outbound: true, block: true, enabled: true }
    }

    fn info(name: &str, enabled: bool) -> FwRuleInfo {
        FwRuleInfo { name: name.into(), program: r"c:\x\a.exe".into(), service: String::new(), outbound: true, block: true, enabled }
    }

    #[test]
    fn drift_finds_missing_altered_and_added_rules() {
        let before = [info("RustWarden a", true), info("RustWarden b", true), info("RustWarden c", true)];
        assert_eq!(drift(&before, &before), Drift::default());
        let now = [info("RustWarden a", true), info("RustWarden b", false), info("RustWarden d", true)];
        let d = drift(&before, &now);
        assert_eq!(d, Drift { missing: vec!["RustWarden c".into()], altered: vec!["RustWarden b".into()], added: vec!["RustWarden d".into()] });
        assert_eq!(d.describe(5), "1 missing (RustWarden c); 1 altered (RustWarden b); 1 added (RustWarden d)");
    }

    #[test]
    fn drift_ignores_block_all_exceptions_and_caps_the_names_shown() {
        let exception = info(&format!("{BLOCK_ALL_PREFIX}: DHCP"), true);
        assert!(drift(std::slice::from_ref(&exception), &[]).is_empty());
        assert!(drift(&[], &[exception]).is_empty());
        let many: Vec<FwRuleInfo> = (0..7).map(|i| info(&format!("RustWarden r{i}"), true)).collect();
        assert_eq!(drift(&many, &[]).describe(2), "7 missing (RustWarden r0, RustWarden r1, …)");
    }

    #[test]
    fn manifest_round_trips_and_skips_bad_lines() {
        let rules = [info("RustWarden a", true), FwRuleInfo { service: "wuauserv".into(), outbound: false, block: false, ..info("RustWarden b", false) }];
        assert_eq!(parse_manifest(&manifest_text(&rules)), rules);
        assert!(parse_manifest("").is_empty());
        let text = format!("{}\nnot a rule\na\tb\tc\t12\n", manifest_text(&rules[..1]));
        assert_eq!(parse_manifest(&text), rules[..1]);
    }

    #[test]
    fn rescue_deletes_only_ours_and_hands_imported_back() {
        let rules = [
            named("RustWarden", "RustWarden block out: chrome.exe [00000001]"),
            named("RustWarden", &format!("{IMPORT_PREFIX}in.app_1.profile_1.mode_2}}")),
            named("RustWarden", "Allow everything"),
            named("Core Networking", "RustWarden block out: x"),
            named("", "Windows Defender Firewall: something"),
        ];
        let (delete, hand_back) = plan_removals(&rules);
        assert_eq!(delete, vec!["RustWarden block out: chrome.exe [00000001]"]);
        assert_eq!(hand_back, vec![format!("{IMPORT_PREFIX}in.app_1.profile_1.mode_2}}")]);
    }

    #[test]
    fn only_our_group_and_prefix_count_as_ours() {
        assert!(is_ours("RustWarden", "RustWarden block out: chrome.exe [00000001]"));
        // Right name, wrong group (someone else's rule named like ours).
        assert!(!is_ours("Core Networking", "RustWarden block out: x"));
        // Right group, wrong name (a rule dropped into our group by someone else).
        assert!(!is_ours("RustWarden", "Allow everything"));
        assert!(!is_ours("", "RustWarden block out: x"));
        assert!(!is_ours("rustwarden", "RustWarden block out: x"));
        // Imported rules count only once they sit in our group.
        assert!(is_ours("RustWarden", &format!("{IMPORT_PREFIX}in.app_1.profile_1.mode_2}}")));
        assert!(!is_ours("Other", &format!("{IMPORT_PREFIX}in.app_1.profile_1.mode_2}}")));
    }

    #[test]
    fn rule_names_are_stable_and_distinguish_paths() {
        let a = rule_name(Direction::Out, r"C:\Apps\one\tool.exe", "");
        let b = rule_name(Direction::Out, r"C:\Apps\two\tool.exe", "");
        assert!(a.starts_with("RustWarden block out: tool.exe ["));
        assert_ne!(a, b);
        assert_eq!(a, rule_name(Direction::Out, r"c:\apps\ONE\tool.exe", ""));
        assert!(rule_name(Direction::In, r"C:\x\y.exe", "").contains("block in:"));
        assert!(is_ours(GROUP, &a));
    }

    #[test]
    fn block_specs_are_scoped_to_one_program_and_direction() {
        let s = block_spec(Direction::Out, r"C:\x\y.exe", "", true);
        assert!(s.block && s.outbound && s.grouping == GROUP);
        assert_eq!(s.program.as_deref(), Some(r"C:\x\y.exe"));
        assert!(s.service.is_none());
        let inbound = block_spec(Direction::In, r"C:\x\y.exe", "", false);
        assert!(!inbound.outbound && !inbound.enabled);
    }

    #[test]
    fn lan_block_is_its_own_outbound_rule() {
        let s = block_spec(Direction::Local, r"C:\x\y.exe", "", true);
        assert!(s.block && s.outbound && s.remote_addrs.as_deref() == Some(LAN_ADDRS));
        assert!(is_lan(&s.name) && is_ours(&s.grouping, &s.name));
        assert!(!is_lan(&rule_name(Direction::Out, r"C:\x\y.exe", "")));
        let both = lan_specs(r"C:\x\y.exe", "", true);
        assert!(both.len() == 2 && both.iter().all(|s| is_lan(&s.name) && s.remote_ports.as_deref() == Some(LAN_PORTS)));
        assert_ne!(both[0].name, both[1].name);
    }

    #[test]
    fn allow_rules_are_ours_outbound_and_distinct_from_block_rules() {
        let s = allow_spec(r"C:\x\y.exe", "");
        assert!(!s.block && s.outbound && s.enabled && is_ours(&s.grouping, &s.name));
        assert_eq!(s.program.as_deref(), Some(r"C:\x\y.exe"));
        assert_ne!(s.name, rule_name(Direction::Out, r"C:\x\y.exe", ""));
        assert_eq!(s.name, allow_spec(r"c:\X\y.exe", "").name);
    }

    const SVCHOST: &str = r"C:\Windows\System32\svchost.exe";

    fn rule(program: &str, service: &str, block: bool) -> Rule {
        Rule { name: format!("RustWarden block out: {service}"), grouping: GROUP.into(), program: program.into(), service: service.into(), outbound: true, block, enabled: true }
    }

    #[test]
    fn a_service_rule_is_a_separate_row_with_its_own_name() {
        let s = block_spec(Direction::Out, SVCHOST, "wuauserv", true);
        assert_eq!(s.service.as_deref(), Some("wuauserv"));
        assert_eq!(s.program.as_deref(), Some(SVCHOST));
        assert!(s.name.starts_with("RustWarden block out: svchost.exe (wuauserv) ["));
        assert_ne!(s.name, rule_name(Direction::Out, SVCHOST, ""));
        assert_ne!(s.name, block_spec(Direction::Out, SVCHOST, "bits", true).name);
        assert_eq!(rule_key(&rule(SVCHOST, "WuAuServ", true)), service_key(&key_for_path(SVCHOST), "wuauserv"));
        assert_eq!(rule_key(&rule(SVCHOST, "", true)), key_for_path(SVCHOST));
    }

    #[test]
    fn a_program_block_does_not_match_a_service_block_and_back() {
        let program_wide = vec![rule(SVCHOST, "", true)];
        let one_service = vec![rule(SVCHOST, "wuauserv", true)];
        assert!(find_block(&program_wide, Direction::Out, SVCHOST, "wuauserv").is_none());
        assert!(find_block(&one_service, Direction::Out, SVCHOST, "").is_none());
        assert!(find_block(&one_service, Direction::Out, SVCHOST, "WUAUSERV").is_some());
    }

    #[test]
    fn a_service_block_is_found_on_its_own_row_only() {
        let rules = vec![rule(SVCHOST, "wuauserv", true)];
        assert!(find_block(&rules, Direction::Out, SVCHOST, "wuauserv").is_some());
        assert!(find_block(&rules, Direction::Out, SVCHOST, "bits").is_none());
        assert!(find_block(&rules, Direction::In, SVCHOST, "wuauserv").is_none());
    }

    #[test]
    fn service_allow_is_limited_to_its_service() {
        let s = allow_spec(SVCHOST, "bits");
        assert_eq!(s.service.as_deref(), Some("bits"));
        assert!(s.name.contains("(bits)") && s.name != allow_spec(SVCHOST, "").name);
    }

    #[test]
    fn block_all_suspends_program_allows_but_not_windows_or_its_own() {
        let rule = |name: &str, program: &str| Rule { name: name.into(), grouping: String::new(), program: program.into(), service: String::new(), outbound: true, block: false, enabled: true };
        let rules = [
            rule(&format!("{IMPORT_PREFIX}out.app_1}}"), r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            rule("RustWarden allow out: x", r"c:\x\y.exe"),
            rule("Core Networking", "System"),
            rule("Store", ""),
            rule("Backup", r"C:\WINDOWS\SystemApps\x.exe"),
            rule("Their curl", r"C:\Windows\System32\curl.exe"),
            rule(&format!("{BLOCK_ALL_PREFIX}: RustWarden"), r"C:\RustWarden.exe"),
        ];
        assert_eq!(rules_to_suspend(&rules, r"c:\windows"), [format!("{IMPORT_PREFIX}out.app_1}}").as_str(), "RustWarden allow out: x", "Their curl"]);
    }

    #[test]
    fn exceptions_an_older_version_made_are_stale() {
        let wanted = block_all_exceptions(r"C:\RustWarden.exe");
        let mut rules: Vec<Rule> = wanted.iter().map(|w| named(GROUP, &w.name)).collect();
        for old in ["curl", "nslookup", "PowerShell"] {
            rules.push(named(GROUP, &format!("{BLOCK_ALL_PREFIX}: {old}")));
        }
        rules.push(named("Other firewall", &format!("{BLOCK_ALL_PREFIX}: PowerShell")));
        rules.push(named(GROUP, "RustWarden allow out: x"));
        assert_eq!(stale_exceptions(&rules, &wanted), [format!("{BLOCK_ALL_PREFIX}: curl"), format!("{BLOCK_ALL_PREFIX}: nslookup"), format!("{BLOCK_ALL_PREFIX}: PowerShell")]);
    }

    #[test]
    fn block_all_exceptions_are_ours_and_allow() {
        let ex = block_all_exceptions(r"C:\RustWarden.exe");
        assert!(ex.iter().all(|r| !r.block && r.grouping == GROUP && is_ours(&r.grouping, &r.name) && r.name.starts_with(BLOCK_ALL_PREFIX)));
        assert_eq!(ex[0].program.as_deref(), Some(r"C:\RustWarden.exe"));
        // No standing way out for the Windows tools any program can run.
        for tool in ["curl.exe", "nslookup.exe", "powershell.exe"] {
            assert!(!ex.iter().any(|r| r.program.as_deref().is_some_and(|p| p.to_lowercase().ends_with(tool))));
        }
    }

    #[test]
    fn profile_names_are_checked() {
        let have = vec![DEFAULT_PROFILE.to_owned()];
        assert!(valid_profile_name("Work", &have).is_ok());
        assert!(valid_profile_name("default", &have).is_err());
        assert!(valid_profile_name("", &have).is_err());
        assert!(valid_profile_name("a@b", &have).is_err());
        assert!(valid_profile_name(" x", &have).is_err());
        assert_eq!(stash_suffix("Work"), " @[Work]");
    }

    #[test]
    fn marker_round_trip() {
        assert_eq!(parse_marker(&marker_text([true, false, true])), Some([true, false, true]));
        assert_eq!(parse_marker("garbage"), None);
        assert_eq!(parse_marker("1 0"), None);
    }

    #[test]
    fn cleanup_thresholds() {
        let day = 86_400;
        assert!(should_clean(Some(0), 8 * day, 7));
        assert!(!should_clean(Some(0), 6 * day, 7));
        assert!(!should_clean(None, 31 * day, 7));
    }
}
