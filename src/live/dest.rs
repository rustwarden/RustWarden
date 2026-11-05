//! Destination rules in Live mode: compiles each rule (domain, ASN or country, for one program or all)
//! into address ranges and keeps matching RustWarden-owned Windows Firewall rules in step.
//!
//! Windows Firewall knows only addresses, so this is best effort: a domain is the set of addresses
//! the PC has resolved for it (from the DNS log, remembered for two weeks), and a program may fail
//! its first connection to a server it has not looked up yet. Rules are named `RustWarden dest <id> …`
//! and carry a hash of their address list, so a change in the list replaces exactly the rules it touches.

use super::apps::{critical_reason, key_for_path, system_root};
use super::firewall::{DEST_PREFIX, FwController, GROUP};
use super::geo::{self, Geo};
use super::store::{Shared, lock};
use crate::destrules::{self, DestRule, DestRuleView, MAX_RULES_PER_DEST, Mode, RangeSet, Target};
use crate::sys::firewall::{self, RuleSpec};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

const RULES_KEY: &str = "dest_rules";
/// How long an address stays in a domain's set after the last lookup that returned it.
const SEEN_TTL: i64 = 14 * 86_400;
/// How many recent DNS answers are searched for the domains.
const DNS_WINDOW: usize = 20_000;

fn seen_key(id: u32) -> String {
    format!("dest_seen_{id}")
}

pub fn load(db: &super::db::Db) -> Vec<DestRule> {
    destrules::decode_all(&db.kv_get(RULES_KEY).unwrap_or_default())
}

fn store(db: &super::db::Db, rules: &[DestRule]) -> Result<(), String> {
    db.kv_set(RULES_KEY, &destrules::encode_all(rules)).map_err(|e| format!("Can't save the rule: {e}"))
}

/// The id of the destination rule a firewall rule name belongs to.
fn id_of(name: &str) -> Option<u32> {
    name.strip_prefix(DEST_PREFIX)?.split_whitespace().next()?.parse().ok()
}

pub struct Dest {
    shared: Arc<Shared>,
    fw: Arc<FwController>,
    geo: Mutex<Geo>,
    /// Country and ASN ranges by target, with the modification time of the database they came from.
    cache: Mutex<HashMap<Target, (Option<SystemTime>, RangeSet)>>,
    status: Mutex<HashMap<u32, (String, bool)>>,
    /// Gateways and DNS servers (never blocked), and when they were read.
    protected: Mutex<Option<(Instant, RangeSet)>>,
    /// Serialises reconciles from the worker and from saves.
    busy: Mutex<()>,
    /// Some destination rule exists in Windows Firewall, so an empty rule list still has cleaning to do.
    applied: AtomicBool,
    own_exe: String,
}

impl Dest {
    pub fn new(shared: Arc<Shared>, fw: Arc<FwController>) -> Self {
        let geo = Geo::open(shared.settings().geo_path().as_deref());
        let own_exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        Self { shared, fw, geo: Mutex::new(geo), cache: Mutex::default(), status: Mutex::default(), protected: Mutex::new(None), busy: Mutex::new(()), applied: AtomicBool::new(true), own_exe }
    }

    /// The rules and their state. Takes the UI's own database connection: opening one per call would stall it.
    pub fn views(&self, db: &super::db::Db) -> Vec<DestRuleView> {
        let status = lock(&self.status);
        load(db)
            .into_iter()
            .map(|rule| {
                let (status, problem) = status.get(&rule.id).cloned().unwrap_or_else(|| ("Starting…".into(), false));
                DestRuleView { rule, status, problem }
            })
            .collect()
    }

    /// Adds the rule (id 0) or replaces the one with its id, then applies it.
    pub fn save_rule(&self, mut rule: DestRule) -> Result<(), String> {
        if !self.shared.elevated {
            return Err("Changing firewall rules needs administrator rights. Use \"Restart as administrator\".".into());
        }
        if let Some(problem) = rule.problem() {
            return Err(problem.into());
        }
        let program = rule.program.trim().to_owned();
        if !program.is_empty() {
            let key = key_for_path(&program);
            if let Some(reason) = critical_reason(&key, &program, &self.own_exe, &system_root()) {
                return Err(format!("{reason}, so it can't have a destination rule."));
            }
        }
        rule.program = program;
        let db = self.shared.open_db().map_err(|e| format!("Can't open the database: {e}"))?;
        let mut rules = load(&db);
        if rule.id == 0 {
            rule.id = rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
            rules.push(rule);
        } else if let Some(slot) = rules.iter_mut().find(|r| r.id == rule.id) {
            *slot = rule;
        } else {
            return Err("That rule no longer exists.".into());
        }
        store(&db, &rules)?;
        drop(db);
        self.reconcile();
        Ok(())
    }

    pub fn remove_rule(&self, id: u32) -> Result<(), String> {
        let db = self.shared.open_db().map_err(|e| format!("Can't open the database: {e}"))?;
        let mut rules = load(&db);
        rules.retain(|r| r.id != id);
        store(&db, &rules)?;
        let _ = db.kv_set(&seen_key(id), "");
        drop(db);
        self.reconcile();
        Ok(())
    }

    /// The addresses `rule` names. `Err` says what it is waiting for; its firewall rules are then left as they are.
    fn target_ranges(&self, db: &super::db::Db, rule: &DestRule) -> Result<RangeSet, String> {
        let mut set = RangeSet::new();
        match &rule.target {
            Target::Domain(domain) => {
                let now = crate::clock::now_unix();
                let fresh: Vec<IpAddr> = db
                    .dns_recent(DNS_WINDOW)
                    .map_err(|e| format!("Can't read the DNS log: {e}"))?
                    .into_iter()
                    .filter(|e| e.status == 0 && destrules::domain_matches(domain, &e.name))
                    .flat_map(|e| e.ips)
                    .filter_map(|ip| ip.parse().ok())
                    .collect();
                let old = destrules::seen_from_text(&db.kv_get(&seen_key(rule.id)).unwrap_or_default());
                let merged = destrules::merge_seen(old.clone(), &fresh, now, SEEN_TTL);
                // Only rewritten when an address is new, so a busy log doesn't write every few seconds.
                if merged.len() != old.len() || merged.iter().map(|m| m.0).ne(old.iter().map(|o| o.0)) {
                    let _ = db.kv_set(&seen_key(rule.id), &destrules::seen_to_text(&merged));
                }
                for (ip, _) in merged {
                    set.add_ip(ip);
                }
                if set.is_empty() {
                    return Err(format!("Waiting for a lookup of {domain}"));
                }
            }
            Target::Country(code) => {
                let mtime = {
                    let mut g = lock(&self.geo);
                    if g.appeared() {
                        *g = Geo::open(self.shared.settings().geo_path().as_deref());
                    }
                    if !g.available() {
                        return Err("Needs the country database (Settings, Map)".into());
                    }
                    std::fs::metadata(&g.path).and_then(|m| m.modified()).ok()
                };
                if let Some(hit) = self.cached(&rule.target, mtime) {
                    return Ok(hit);
                }
                for (ip, prefix) in lock(&self.geo).country_networks(*code) {
                    set.add_net(ip, prefix);
                }
                set.tidy();
                lock(&self.cache).insert(rule.target.clone(), (mtime, set.clone()));
                if set.is_empty() {
                    return Err(format!("The country database has no addresses for {}", rule.target.text()));
                }
            }
            Target::Asn(n) => {
                let path = geo::asn_db_path();
                let Ok(meta) = std::fs::metadata(&path) else { return Err("Needs the ASN database (download it in this window)".into()) };
                let mtime = meta.modified().ok();
                if let Some(hit) = self.cached(&rule.target, mtime) {
                    return Ok(hit);
                }
                for (ip, prefix) in geo::asn_networks(&path, *n)? {
                    set.add_net(ip, prefix);
                }
                set.tidy();
                lock(&self.cache).insert(rule.target.clone(), (mtime, set.clone()));
                if set.is_empty() {
                    return Err(format!("The ASN database has no addresses for AS{n}"));
                }
            }
        }
        set.tidy();
        Ok(set)
    }

    fn cached(&self, target: &Target, mtime: Option<SystemTime>) -> Option<RangeSet> {
        lock(&self.cache).get(target).filter(|(t, _)| *t == mtime).map(|(_, s)| s.clone())
    }

    /// Never blocked: this PC's network, its gateways and its DNS servers.
    fn keep_open(&self) -> RangeSet {
        let mut cached = lock(&self.protected);
        if let Some((at, set)) = cached.as_ref()
            && at.elapsed() < Duration::from_secs(60)
        {
            return set.clone();
        }
        let mut set = destrules::local_ranges();
        for ip in super::threat::protected_addrs(&self.shared.settings().integrations) {
            set.add_ip(ip);
        }
        set.tidy();
        *cached = Some((Instant::now(), set.clone()));
        set
    }

    /// Compares what the rules should be with what Windows Firewall holds and changes the difference.
    pub fn reconcile(&self) {
        let _busy = lock(&self.busy);
        let Ok(db) = self.shared.open_db() else { return };
        let rules = load(&db);
        if rules.is_empty() && !self.applied.load(Ordering::Relaxed) {
            return;
        }
        if !self.shared.elevated {
            *lock(&self.status) = rules.iter().map(|r| (r.id, ("Needs administrator rights".to_owned(), true))).collect();
            return;
        }
        let existing: Vec<String> = match firewall::rules_named(DEST_PREFIX) {
            Ok(list) => list.into_iter().filter(|r| r.grouping == GROUP).map(|r| r.name).collect(),
            Err(e) => {
                *lock(&self.status) = rules.iter().map(|r| (r.id, (e.clone(), true))).collect();
                return;
            }
        };
        let keep_open = self.keep_open();
        let mut status: HashMap<u32, (String, bool)> = HashMap::new();
        let mut hold: BTreeSet<u32> = BTreeSet::new();
        let mut want: Vec<RuleSpec> = Vec::new();
        for rule in &rules {
            if !rule.enabled {
                status.insert(rule.id, ("Off".into(), false));
                continue;
            }
            let target = match self.target_ranges(&db, rule) {
                Ok(t) => t,
                Err(wait) => {
                    hold.insert(rule.id);
                    status.insert(rule.id, (wait, false));
                    continue;
                }
            };
            let blocked = destrules::blocked_set(rule.mode, &target, &keep_open);
            let chunks = blocked.chunks();
            if chunks.len() * 2 > MAX_RULES_PER_DEST {
                status.insert(rule.id, (format!("Too many addresses ({}) for one rule; nothing is enforced", target.len()), true));
                continue;
            }
            status.insert(
                rule.id,
                (
                    match rule.mode {
                        Mode::Block => format!("Blocking {} address ranges", target.len()),
                        Mode::OnlyAllow => format!("Allowing only {} address ranges; the rest is blocked", target.len()),
                    },
                    false,
                ),
            );
            for (n, chunk) in chunks.iter().enumerate() {
                for outbound in [true, false] {
                    want.push(spec(rule, outbound, n, chunk));
                }
            }
        }
        let wanted: BTreeSet<&str> = want.iter().map(|s| s.name.as_str()).collect();
        let remove: Vec<String> = existing.iter().filter(|n| !wanted.contains(n.as_str()) && !id_of(n).is_some_and(|id| hold.contains(&id))).cloned().collect();
        let add: Vec<RuleSpec> = want.iter().filter(|s| !existing.contains(&s.name)).cloned().collect();
        self.applied.store(!existing.is_empty() || !want.is_empty(), Ordering::Relaxed);
        if !remove.is_empty() || !add.is_empty() {
            if let Err(e) = self.fw.apply_dest(&remove, &add) {
                for r in &rules {
                    if r.enabled && !hold.contains(&r.id) {
                        status.insert(r.id, (e.clone(), true));
                    }
                }
            }
            self.applied.store(true, Ordering::Relaxed);
        }
        *lock(&self.status) = status;
        self.shared.repaint();
    }
}

fn spec(rule: &DestRule, outbound: bool, n: usize, chunk: &str) -> RuleSpec {
    let hash = destrules::fingerprint(&format!("{}|{}|{chunk}", rule.program.to_lowercase(), u8::from(rule.mode == Mode::Block)));
    RuleSpec {
        name: format!("{DEST_PREFIX}{} {} {n} {hash:08x}", rule.id, if outbound { "out" } else { "in" }),
        description: format!(
            "Created by RustWarden: destination rule {} ({} {}). Use \"Restore firewall defaults\" in RustWarden to remove all such rules.",
            rule.id,
            rule.mode.label(),
            rule.target.text()
        ),
        grouping: GROUP.into(),
        program: (!rule.program.is_empty()).then(|| rule.program.clone()),
        outbound,
        block: true,
        enabled: true,
        protocol: None,
        local_ports: None,
        remote_ports: None,
        remote_addrs: Some(chunk.to_owned()),
        service: None,
    }
}

/// Re-checks every few seconds, so an address the DNS log has just learned is let through (or blocked) soon.
pub fn run(shared: Arc<Shared>, dest: Arc<Dest>) {
    dest.reconcile();
    while shared.sleep(5.0) {
        dest.reconcile();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: u32, mode: Mode, program: &str) -> DestRule {
        DestRule { id, enabled: true, mode, target: Target::Country(*b"RU"), program: program.into() }
    }

    #[test]
    fn firewall_rules_belong_to_their_destination_rule() {
        let s = spec(&rule(7, Mode::Block, ""), true, 2, "1.2.3.4");
        assert_eq!(id_of(&s.name), Some(7));
        assert!(s.name.starts_with(DEST_PREFIX) && s.block && s.outbound && s.grouping == GROUP);
        assert!(super::super::firewall::is_ours(&s.grouping, &s.name));
        assert_eq!(id_of("RustWarden threat out 1.2.3.4"), None);
        assert_eq!(id_of("RustWarden dest x out 0 00"), None);
    }

    #[test]
    fn name_changes_with_the_address_list_program_and_mode_only() {
        let base = spec(&rule(1, Mode::Block, r"c:\a.exe"), true, 0, "1.2.3.4").name;
        assert_eq!(base, spec(&rule(1, Mode::Block, r"C:\A.exe"), true, 0, "1.2.3.4").name);
        assert_ne!(base, spec(&rule(1, Mode::Block, r"c:\a.exe"), true, 0, "1.2.3.5").name);
        assert_ne!(base, spec(&rule(1, Mode::Block, r"c:\b.exe"), true, 0, "1.2.3.4").name);
        assert_ne!(base, spec(&rule(1, Mode::OnlyAllow, r"c:\a.exe"), true, 0, "1.2.3.4").name);
        assert_ne!(base, spec(&rule(1, Mode::Block, r"c:\a.exe"), false, 0, "1.2.3.4").name);
    }

    #[test]
    fn rules_are_scoped_to_the_program() {
        assert_eq!(spec(&rule(1, Mode::Block, r"c:\a.exe"), true, 0, "1.2.3.4").program.as_deref(), Some(r"c:\a.exe"));
        assert_eq!(spec(&rule(1, Mode::Block, ""), true, 0, "1.2.3.4").program, None);
    }
}
