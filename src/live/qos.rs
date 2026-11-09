//! Bandwidth limits in Live mode: the saved list of limits is kept in step with the Windows QoS policies
//! that enforce them (see `sys::qos`). Policies are named `RustWarden QoS <id> <exe>`, so a limit that was
//! edited or removed, or a policy left over from one, is found by name and replaced or removed.

use super::apps::{critical_reason, key_for_path, system_root};
use super::db::Db;
use super::store::{Shared, lock};
use crate::qos::{self, MAX_LIMITS, QosLimit, QosView};
use crate::sys::qos as os;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const KEY: &str = "qos_limits";
const NEEDS_ADMIN: &str = "Changing bandwidth limits needs administrator rights. Use \"Restart as administrator\".";

pub fn load(db: &Db) -> Vec<QosLimit> {
    qos::decode_all(&db.kv_get(KEY).unwrap_or_default())
}

fn store(db: &Db, limits: &[QosLimit]) -> Result<(), String> {
    db.kv_set(KEY, &qos::encode_all(limits)).map_err(|e| format!("Can't save the limit: {e}"))
}

pub struct Qos {
    shared: Arc<Shared>,
    /// Plain-English state of each limit by id: (text, is a problem).
    status: Mutex<HashMap<u32, (String, bool)>>,
    /// Serialises reconciles from the worker and from saves.
    busy: Mutex<()>,
    /// Some policy may exist in Windows, so an empty list still has cleaning to do.
    applied: AtomicBool,
    own_exe: String,
    /// Enforces the limits through the driver in Driver mode.
    engine: super::engine::Engine,
}

impl Qos {
    pub fn new(shared: Arc<Shared>) -> Self {
        let own_exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        Self { shared, status: Mutex::default(), busy: Mutex::new(()), applied: AtomicBool::new(true), own_exe, engine: Default::default() }
    }

    /// The limits and their state. Takes the UI's own database connection: opening one per call would stall it.
    pub fn views(&self, db: &Db) -> Vec<QosView> {
        let status = lock(&self.status);
        load(db)
            .into_iter()
            .map(|limit| {
                let (text, problem) = status.get(&limit.id).cloned().unwrap_or_else(|| ("Checking…".into(), false));
                QosView { limit, status: text, problem }
            })
            .collect()
    }

    /// The saved limit on `program`, if any.
    pub fn find(&self, program: &str) -> Option<QosLimit> {
        let db = self.shared.open_db().ok()?;
        load(&db).into_iter().find(|l| l.program.eq_ignore_ascii_case(program))
    }

    /// Adds the limit (id 0) or replaces the one with its id, then applies it.
    pub fn save(&self, mut limit: QosLimit) -> Result<(), String> {
        if !self.shared.elevated {
            return Err(NEEDS_ADMIN.into());
        }
        if let Some(problem) = limit.problem() {
            return Err(problem.into());
        }
        limit.program = limit.program.trim().to_owned();
        let key = key_for_path(&limit.program);
        if let Some(reason) = critical_reason(&key, &limit.program, &self.own_exe, &system_root()) {
            return Err(format!("{reason}, so it can't have a bandwidth limit."));
        }
        // Held until the list is stored: `reconcile` also rewrites it (ended simulations), and would overwrite this save.
        let edit = lock(&self.busy);
        let db = self.shared.open_db().map_err(|e| format!("Can't open the database: {e}"))?;
        let mut limits = load(&db);
        if limits.iter().any(|l| l.id != limit.id && l.program.eq_ignore_ascii_case(&limit.program)) {
            return Err("That program already has a limit. Edit or remove it instead.".into());
        }
        let id = if limit.id == 0 {
            if limits.len() >= MAX_LIMITS {
                return Err(format!("At most {MAX_LIMITS} programs can be limited."));
            }
            limit.id = limits.iter().map(|l| l.id).max().unwrap_or(0) + 1;
            limits.push(limit);
            limits.last().map_or(0, |l| l.id)
        } else if let Some(slot) = limits.iter_mut().find(|l| l.id == limit.id) {
            let id = limit.id;
            *slot = limit;
            id
        } else {
            return Err("That limit no longer exists.".into());
        };
        store(&db, &limits)?;
        drop((db, edit));
        self.applied.store(true, Ordering::Relaxed);
        self.reconcile();
        match lock(&self.status).get(&id) {
            Some((text, true)) => Err(text.clone()),
            _ => Ok(()),
        }
    }

    pub fn remove(&self, id: u32) -> Result<(), String> {
        if !self.shared.elevated {
            return Err(NEEDS_ADMIN.into());
        }
        let edit = lock(&self.busy);
        let db = self.shared.open_db().map_err(|e| format!("Can't open the database: {e}"))?;
        let mut limits = load(&db);
        limits.retain(|l| l.id != id);
        store(&db, &limits)?;
        drop((db, edit));
        self.applied.store(true, Ordering::Relaxed);
        self.reconcile();
        Ok(())
    }

    /// Removes every RustWarden policy and forgets the saved limits ("Restore firewall defaults").
    pub fn remove_all(&self) -> Result<(), String> {
        if !self.shared.elevated {
            return Err(NEEDS_ADMIN.into());
        }
        let _g = lock(&self.busy);
        self.engine.stop();
        os::remove_all()?;
        if let Ok(db) = self.shared.open_db() {
            store(&db, &[])?;
        }
        lock(&self.status).clear();
        self.applied.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// Stops the driver engine (before the driver is removed, and at exit).
    pub fn stop_engine(&self) {
        self.engine.stop();
    }

    /// Makes Windows match the saved list: creates or fixes policies, removes those of off or deleted limits.
    pub fn reconcile(&self) {
        let _g = lock(&self.busy);
        let Ok(db) = self.shared.open_db() else { return };
        let mut limits = load(&db);
        // A simulation that has run out is switched off; a limit that was only a simulation is switched off with it.
        let now = crate::clock::now_unix();
        let mut ended = false;
        for l in limits.iter_mut().filter(|l| l.sim_until > 0 && l.sim_until <= now) {
            (l.delay_ms, l.loss_pct, l.sim_until) = (0, 0, 0);
            l.enabled &= l.problem().is_none();
            ended = true;
        }
        if ended {
            let _ = store(&db, &limits);
        }
        drop(db);
        if limits.is_empty() && !self.applied.load(Ordering::Relaxed) {
            return;
        }
        let mut status: HashMap<u32, (String, bool)> = HashMap::new();
        if !self.shared.elevated {
            for l in &limits {
                status.insert(l.id, ("Needs administrator rights to apply.".into(), true));
            }
            *lock(&self.status) = status;
            return;
        }
        let present = match os::list() {
            Ok(p) => p,
            Err(e) => {
                for l in &limits {
                    status.insert(l.id, (format!("Can't read Windows QoS policies: {e}"), true));
                }
                *lock(&self.status) = status;
                return;
            }
        };
        // Driver mode: the engine enforces every limit, in both directions, and no QoS policy is needed. If it can't start,
        // uploads fall back to QoS policies and downloads say why they aren't limited.
        let settings = self.shared.settings();
        let driver_mode = settings.app_mode == crate::settings::AppMode::Driver;
        let usable: Vec<QosLimit> = limits.iter().filter(|l| l.enabled && l.problem().is_none()).cloned().collect();
        // The engine re-sends packets as "System"; with outbound blocked by default those need an allow rule or they are dropped.
        if let Err(e) = super::firewall::allow_engine_traffic(driver_mode && !usable.is_empty()) {
            crate::applog::line("engine.log", &format!("couldn't update the rule that lets the engine's packets through: {e}"));
        }
        let engine_result = if driver_mode { self.engine.apply(&usable, (settings.line_up_mbps, settings.line_down_mbps)) } else { self.engine.apply(&[], (0, 0)) };
        let via_driver = driver_mode && engine_result.is_ok();
        let no_download = match &engine_result {
            Err(e) if driver_mode && super::engine::tripped() => e.clone(),
            Err(e) if driver_mode => format!("Download limits and simulated conditions need the driver: {e}"),
            _ => "Download limits and simulated conditions need Driver mode.".to_owned(),
        };
        let (mut keep, mut gone) = (HashSet::new(), HashSet::new());
        for l in &limits {
            let name = l.policy_name();
            let state = if let Some(problem) = l.problem() {
                (problem.to_owned(), true)
            } else if !l.enabled {
                if present.contains_key(&name) {
                    gone.insert(name.clone());
                    if let Err(e) = os::remove(&name) {
                        status.insert(l.id, (e, true));
                        continue;
                    }
                }
                ("Off".to_owned(), false)
            } else {
                // The Windows policy: an upload throttle (Normal mode, or the fallback) and/or the priority's DSCP mark.
                let throttle = if via_driver || !l.dir.up() { 0 } else { l.bits_per_second() };
                let policy = (throttle, l.priority.dscp());
                let needed = policy != (0, None);
                if needed {
                    keep.insert(name.clone());
                }
                let applied = if !needed || present.get(&name) == Some(&policy) { Ok(()) } else { os::apply(&name, &l.program, throttle, policy.1) };
                match applied {
                    Err(e) => (e, true),
                    Ok(()) if via_driver => (format!("Active (driver): {}", l.rate_text(true)), false),
                    Ok(()) if throttle > 0 => (format!("Active: uploads capped at {}{}", qos::fmt_rate(l.kbps), if l.dir.down() { format!(". {no_download}") } else { String::new() }), l.dir.down()),
                    Ok(()) if policy.1.is_some() => (format!("Active: uploads marked {} priority. Sharing the line needs Driver mode.", l.priority.label()), false),
                    Ok(()) => (no_download.clone(), true),
                }
            };
            status.insert(l.id, state);
        }
        // Policies of deleted limits, or of a program that was swapped for another.
        let failed = remove_orphans(present.keys(), &keep, &gone, os::remove);
        for f in &failed {
            crate::applog::line("engine.log", &format!("couldn't remove the orphaned QoS policy {f}"));
        }
        // Stay "dirty" while an orphan survives, so the next pass retries it.
        if limits.is_empty() && failed.is_empty() {
            self.applied.store(false, Ordering::Relaxed);
        }
        *lock(&self.status) = status;
    }
}

/// Removes the listed policies that no limit wants; returns the names (with the error) that couldn't be removed.
fn remove_orphans<'a>(present: impl Iterator<Item = &'a String>, keep: &HashSet<String>, gone: &HashSet<String>, remove: impl Fn(&str) -> Result<(), String>) -> Vec<String> {
    present.filter(|n| !keep.contains(*n) && !gone.contains(*n)).filter_map(|name| remove(name).err().map(|e| format!("{name}: {e}"))).collect()
}

/// Re-checks once a minute: a policy removed by hand in PowerShell comes back, and the first pass cleans up after a crash.
pub fn run(shared: Arc<Shared>, qos: Arc<Qos>) {
    qos.reconcile();
    while shared.sleep(60.0) {
        qos.reconcile();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_limits_round_trip_through_the_store() {
        let db = Db::memory();
        let l = QosLimit::upload(3, true, r"C:\Apps\game.exe", 2000);
        store(&db, std::slice::from_ref(&l)).unwrap();
        assert_eq!(load(&db), vec![l]);
    }

    #[test]
    fn orphans_are_removed_with_no_limits_and_failures_are_counted() {
        let present: Vec<String> = ["RustWarden QoS 1 a.exe", "RustWarden QoS 2 b.exe"].map(String::from).into();
        let removed = Mutex::new(Vec::new());
        let ok = |n: &str| {
            removed.lock().unwrap().push(n.to_owned());
            Ok(())
        };
        assert_eq!(remove_orphans(present.iter(), &HashSet::new(), &HashSet::new(), ok).len(), 0);
        assert_eq!(*removed.lock().unwrap(), present);
        let keep: HashSet<String> = [present[0].clone()].into();
        assert_eq!(remove_orphans(present.iter(), &keep, &HashSet::new(), |_| Err("denied".into())).len(), 1);
    }

    #[test]
    fn without_administrator_rights_a_limit_is_refused() {
        let shared = Arc::new(Shared::new(Default::default(), std::path::PathBuf::new(), false));
        let q = Qos::new(shared);
        let l = QosLimit::upload(0, true, r"C:\Apps\game.exe", 2000);
        assert!(q.save(l).unwrap_err().contains("administrator"));
        assert!(q.remove(1).is_err() && q.remove_all().is_err());
    }
}
