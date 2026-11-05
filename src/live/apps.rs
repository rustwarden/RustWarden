//! Turns process ids into app records: path, description, publisher,
//! version, signature, hash. Records persist by lower-cased path; a changed hash, version,
//! publisher or signature on a known path raises "App info changed".

use super::alerts::AlertKind;
use super::db::{AppRecord, Db};
use super::store::Shared;
use crate::data::AppIcon;
use crate::sys::apps as sysapps;
use crate::sys::services;
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Debug)]
pub struct Resolved {
    pub id: i64,
    pub key: String,
    pub name: String,
    /// First time this program has been seen with network activity (not during the baseline pass).
    pub is_new: bool,
}

pub const SYSTEM_KEY: &str = "system";

pub fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()).to_lowercase()
}

pub fn key_for_path(path: &str) -> String {
    path.to_lowercase()
}

pub fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Why a program must never be blocked, if it must not. Blocking these can cut off the whole
/// machine (services host, security subsystem) or RustWarden itself.
pub fn critical_reason(key: &str, path: &str, own_exe: &str, system_root: &str) -> Option<&'static str> {
    if key == SYSTEM_KEY || key.strip_prefix(SYSTEM_KEY).is_some_and(|rest| rest.starts_with("|svc:")) {
        return Some("System can't be blocked");
    }
    if !own_exe.is_empty() && path.eq_ignore_ascii_case(own_exe) {
        return Some("RustWarden can't be blocked");
    }
    // A service row is judged by its own service, so the other services in svchost.exe stay blockable.
    let service = service_of_key(key);
    if !service.is_empty() {
        return service.split('+').any(|s| CRITICAL_SERVICES.iter().any(|c| c.eq_ignore_ascii_case(s))).then_some("This Windows service is needed for the network or the system");
    }
    let lower = path.to_lowercase();
    let in_system32 = lower.starts_with(&format!("{system_root}\\system32\\"));
    if in_system32 && matches!(file_name(&lower), "smss.exe" | "csrss.exe" | "wininit.exe" | "services.exe" | "lsass.exe" | "winlogon.exe" | "svchost.exe") {
        return Some("Windows core processes can't be blocked");
    }
    None
}

/// Services whose loss takes the network, name resolution, DHCP or the system's core with it. Their rows
/// can't be blocked, as the Windows core processes can't.
const CRITICAL_SERVICES: &[&str] = &["RpcSs", "RpcEptMapper", "DcomLaunch", "PlugPlay", "Power", "BFE", "mpssvc", "nsi", "Dhcp", "Dnscache", "LanmanWorkstation", "EventLog", "SamSs", "ProfSvc"];

/// Service part of a service row's key ("bits" for "…svchost.exe|svc:bits"); empty for a whole program.
pub fn service_of_key(key: &str) -> &str {
    key.split_once("|svc:").map_or("", |(_, service)| service)
}

/// Well-known VPN client executables whose own traffic is the encrypted copy of what the apps send.
const VPN_CLIENTS: &[&str] = &[
    "openvpn.exe",
    "openvpnserv.exe",
    "openvpnserv2.exe",
    "openvpn-gui.exe",
    "wireguard.exe",
    "nordvpn.exe",
    "nordvpn-service.exe",
    "expressvpn.exe",
    "expressvpnd.exe",
    "protonvpn.exe",
    "protonvpnservice.exe",
    "mullvad-daemon.exe",
    "tailscaled.exe",
    "vpnagent.exe",
    "surfshark.exe",
    "pia-service.exe",
    "windscribe.exe",
    "windscribeservice.exe",
    "pia-client.exe",
    "pia-openvpn.exe",
    "pia-wgservice.exe",
    "pia-wireguard-go.exe",
    "piavpn.exe",
    "warp-svc.exe",
];

/// Whether `path` is a VPN client: in the built-in list or among the user's `extra` executable names.
pub fn is_vpn_client(path: &str, extra: &[String]) -> bool {
    let n = file_name(path).to_lowercase();
    VPN_CLIENTS.contains(&n.as_str()) || extra.iter().any(|e| file_name(e.trim()).eq_ignore_ascii_case(&n))
}

pub fn icon_for(path: &str) -> AppIcon {
    let n = file_name(path).to_lowercase();
    match n.as_str() {
        "chrome.exe" => AppIcon::Chrome,
        "code.exe" => AppIcon::VsCode,
        "claude.exe" => AppIcon::Claude,
        "bitwarden.exe" => AppIcon::Bitwarden,
        "rustdesk.exe" => AppIcon::RemoteDesktop,
        "msiexec.exe" => AppIcon::Installer,
        _ if n.starts_with("googledrive") => AppIcon::Drive,
        _ => AppIcon::Generic,
    }
}

/// Which descriptive fields differ between the stored and the freshly read record.
pub fn describe_change(old: &AppRecord, new: &AppRecord) -> Vec<String> {
    let mut out = Vec::new();
    if !old.hash.is_empty() && !new.hash.is_empty() && old.hash != new.hash {
        out.push("the program file".to_string());
    }
    if old.version != new.version {
        let shown = |v: &str| if v.is_empty() { "unknown".to_string() } else { v.to_string() };
        out.push(format!("version {} -> {}", shown(&old.version), shown(&new.version)));
    }
    if old.publisher != new.publisher {
        out.push("publisher".to_string());
    }
    if old.signed != new.signed {
        out.push("signature".to_string());
    }
    out
}

/// Suffix on an "App info changed" text that tells the popup whether the new binary is signed.
pub fn signature_suffix(signed: Option<bool>) -> &'static str {
    match signed {
        Some(true) => " [Signed]",
        Some(false) => " [Unsigned]",
        None => "",
    }
}

/// Reads everything about the file at `path` that goes into a record.
fn read_record(path: &str, now: i64) -> AppRecord {
    let info = sysapps::version_info(path);
    let root = system_root();
    let in_windows = path.to_lowercase().starts_with(&root);
    let signed = if sysapps::has_valid_embedded_signature(path) {
        Some(true)
    } else if in_windows {
        // Most Windows binaries are signed through catalogs, which this check doesn't consult.
        None
    } else {
        Some(false)
    };
    AppRecord {
        key: key_for_path(path),
        path: path.to_owned(),
        name: if info.description.trim().is_empty() { file_name(path).to_owned() } else { info.description.trim().to_owned() },
        publisher: info.company.trim().to_owned(),
        version: info.version.split_whitespace().next().unwrap_or("").to_owned(),
        hash: sysapps::hash_file(path),
        signed,
        system: in_windows,
        first_seen: now,
        ..AppRecord::default()
    }
}

/// Makes sure the row of one service inside `path` exists, for a service ruled on before it ever sent traffic.
pub fn ensure_service_record(db: &Db, path: &str, service: &str, now: i64) {
    let key = service_key(&key_for_path(path), service);
    if db.app_by_key(&key).ok().flatten().is_none() {
        let host = read_record(path, now);
        let _ = db.insert_app(&AppRecord { key, name: service.to_owned(), service: service.to_owned(), ..host });
    }
}

/// Makes sure `path` has an app record, so a program that was ruled on before it ever sent
/// traffic (Prompt stops it first) still shows on the Firewall tab.
pub fn ensure_record(db: &Db, path: &str, now: i64) {
    if !path.is_empty() && db.app_by_key(&key_for_path(path)).ok().flatten().is_none() {
        let _ = db.insert_app(&read_record(path, now));
    }
}

/// The svchost.exe in the Windows folder: the shared host of Windows services.
pub fn is_svchost(path: &str) -> bool {
    let lower = path.to_lowercase();
    file_name(&lower) == "svchost.exe" && lower.starts_with(&format!("{}\\system32\\", system_root()))
}

/// Key of a service's own row: the host's key plus the service short names, so each service
/// is its own program in the database and on the Firewall tab.
pub fn service_key(host_key: &str, service_part: &str) -> String {
    format!("{host_key}|svc:{service_part}")
}

/// File name of the process that started `pid`, when it can be read.
fn parent_name(pid: u32) -> Option<String> {
    let parent = crate::sys::etw::parent_of(pid)?;
    sysapps::pid_path(parent).map(|p| file_name(&p).to_owned())
}

pub struct Resolver {
    by_pid: HashMap<u32, (String, i64, Instant, String)>,
    ids: HashMap<String, i64>,
    stat: HashMap<String, (u64, SystemTime)>,
    /// When the database started empty, programs seen in the first moments are the baseline.
    baseline_until: Option<Instant>,
    /// Which service each svchost.exe pid runs; read from the Service Control Manager every few seconds.
    services: HashMap<u32, Vec<services::Service>>,
    services_at: Option<Instant>,
    /// Service row key of each svchost.exe pid seen with traffic.
    service_key_of_pid: HashMap<u32, String>,
    /// File name of the process that started each program, taken from the first pid seen for it.
    pub parents: HashMap<i64, String>,
}

impl Resolver {
    pub fn new(db: &Db) -> Self {
        let empty = db.app_count().unwrap_or(1) == 0;
        Self {
            by_pid: HashMap::new(),
            ids: HashMap::new(),
            stat: HashMap::new(),
            baseline_until: empty.then(|| Instant::now() + Duration::from_secs(20)),
            services: HashMap::new(),
            services_at: None,
            service_key_of_pid: HashMap::new(),
            parents: HashMap::new(),
        }
    }

    /// The service key part and label for a svchost.exe pid; `None` when it runs no service we can see.
    fn service_of(&mut self, pid: u32) -> Option<(String, String)> {
        if self.services_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(5)) {
            if let Ok(map) = services::by_pid() {
                self.services = map;
                self.service_key_of_pid.retain(|pid, _| self.services.contains_key(pid));
            }
            self.services_at = Some(Instant::now());
        }
        services::label(self.services.get(&pid)?)
    }

    /// Pids of each service's process, by the service's row key.
    pub fn service_pids(&self) -> HashMap<String, Vec<u32>> {
        let mut out: HashMap<String, Vec<u32>> = HashMap::new();
        for (pid, key) in &self.service_key_of_pid {
            out.entry(key.clone()).or_default().push(*pid);
        }
        out
    }

    /// The row of one kernel-mode service (`part` from `net::kernel_service`) inside "NT Kernel & System".
    pub fn resolve_kernel(&mut self, db: &Db, part: &str, name: &str, now: i64) -> Option<Resolved> {
        let key = service_key(SYSTEM_KEY, part);
        if let Some(id) = self.ids.get(&key) {
            return Some(Resolved { id: *id, key, name: name.to_owned(), is_new: false });
        }
        let id = match db.app_by_key(&key).ok().flatten() {
            Some(rec) => {
                let _ = db.touch_app(rec.id, now);
                rec.id
            }
            None => db.insert_app(&AppRecord { key: key.clone(), name: name.to_owned(), system: true, first_seen: now, ..AppRecord::default() }).ok()?,
        };
        self.ids.insert(key.clone(), id);
        Some(Resolved { id, key, name: name.to_owned(), is_new: false })
    }

    pub fn resolve(&mut self, db: &Db, pid: u32, now: i64) -> Option<Resolved> {
        if pid == 0 {
            return None;
        }
        // The name is kept with the pid: this runs for every network event, and a database read each time falls behind.
        if let Some((key, id, at, name)) = self.by_pid.get(&pid)
            && at.elapsed() < Duration::from_secs(5)
        {
            return Some(Resolved { id: *id, key: key.clone(), name: name.clone(), is_new: false });
        }
        let (mut key, path) = match crate::sys::etw::cached_path(pid).or_else(|| sysapps::pid_path(pid)) {
            Some(p) => (key_for_path(&p), p),
            None if pid == 4 => (SYSTEM_KEY.to_string(), String::new()),
            None => ("unknown".to_string(), String::new()),
        };
        // svchost.exe hosts many services; each one's traffic gets its own row.
        let service = if is_svchost(&path) { self.service_of(pid) } else { None };
        if let Some((svc, _)) = &service {
            key = service_key(&key, svc);
            self.service_key_of_pid.insert(pid, key.clone());
        }
        let (id, name, is_new) = match db.app_by_key(&key).ok().flatten() {
            Some(rec) => {
                let _ = db.touch_app(rec.id, now);
                (rec.id, rec.name, false)
            }
            None => {
                let mut rec = if path.is_empty() {
                    AppRecord { key: key.clone(), name: if key == SYSTEM_KEY { "NT Kernel & System".into() } else { "Unknown process".into() }, system: true, first_seen: now, ..AppRecord::default() }
                } else {
                    read_record(&path, now)
                };
                if let Some((svc, text)) = &service {
                    rec.key = key.clone();
                    rec.name = text.clone();
                    rec.service = svc.clone();
                }
                let id = db.insert_app(&rec).ok()?;
                rec.id = id;
                let baseline = self.baseline_until.is_some_and(|t| Instant::now() < t);
                (id, rec.name, !baseline && !rec.system)
            }
        };
        if !self.parents.contains_key(&id)
            && let Some(parent) = parent_name(pid)
        {
            self.parents.insert(id, parent);
        }
        self.ids.insert(key.clone(), id);
        self.by_pid.insert(pid, (key.clone(), id, Instant::now(), name.clone()));
        Some(Resolved { id, key, name, is_new })
    }

    /// Looks at the executables of recently active apps: raises "App info changed" and notes
    /// programs that were deleted (uninstalled) or came back.
    pub fn recheck(&mut self, db: &Db, shared: &Shared, now: i64) {
        let apps = db.apps().unwrap_or_default();
        for old in apps.into_iter().filter(|a| !a.path.is_empty() && self.ids.contains_key(&a.key)) {
            let meta = std::fs::metadata(&old.path);
            let Ok(meta) = meta else {
                if old.missing_since.is_none() {
                    let _ = db.set_missing(old.id, Some(now));
                }
                continue;
            };
            if old.missing_since.is_some() {
                let _ = db.set_missing(old.id, None);
            }
            let sig = (meta.len(), meta.modified().unwrap_or(SystemTime::UNIX_EPOCH));
            // Unchanged, or the first look at this program (nothing to compare with yet).
            let before = self.stat.insert(old.key.clone(), sig);
            if before.is_none_or(|b| b == sig) {
                continue;
            }
            // Size or modification time moved since we last looked: read the file again.
            let mut fresh = read_record(&old.path, now);
            fresh.id = old.id;
            let changed = describe_change(&old, &fresh);
            if !changed.is_empty() {
                let what = format!("changed: {}{}", changed.join(", "), signature_suffix(fresh.signed));
                shared.alert(db, AlertKind::AppChanged, &fresh.name, &what, &old.path, "");
                let _ = db.update_app_info(&fresh);
            }
        }
    }

    /// Remembers the current stat of every known app so later changes can be noticed. A version that
    /// changed while RustWarden was closed (updates, rebuilds) is refreshed quietly here, because the
    /// live check only sees changes that happen while it runs; the hash is left for that check.
    pub fn prime_stats(&mut self, db: &Db) {
        for a in db.apps().unwrap_or_default().into_iter().filter(|a| !a.path.is_empty()) {
            if let Ok(m) = std::fs::metadata(&a.path) {
                let version = sysapps::version_info(&a.path).version;
                let version = version.split_whitespace().next().unwrap_or("");
                if !version.is_empty() && version != a.version {
                    let _ = db.update_app_info(&AppRecord { version: version.to_owned(), ..a.clone() });
                }
                self.stat.entry(a.key).or_insert((m.len(), m.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_programs_are_refused() {
        let root = r"c:\windows";
        assert_eq!(critical_reason(SYSTEM_KEY, "", "", root), Some("System can't be blocked"));
        assert_eq!(critical_reason(&service_key(SYSTEM_KEY, "smb"), "", "", root), Some("System can't be blocked"));
        assert!(critical_reason("x", r"C:\Windows\System32\svchost.exe", "", root).is_some());
        assert!(critical_reason("x", r"C:\Windows\System32\lsass.exe", "", root).is_some());
        assert_eq!(critical_reason("x", r"D:\apps\RustyWire.exe", r"d:\apps\rustywire.exe", root), Some("RustWarden can't be blocked"));
        // A program called svchost.exe elsewhere is an ordinary program.
        assert!(critical_reason("x", r"C:\Users\me\svchost.exe", "", root).is_none());
        assert!(critical_reason("x", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "", root).is_none());
    }

    #[test]
    fn change_description() {
        let old = AppRecord { hash: "a".into(), version: "1".into(), publisher: "P".into(), signed: Some(true), ..Default::default() };
        let mut new = old.clone();
        assert!(describe_change(&old, &new).is_empty());
        new.hash = "b".into();
        new.version = "2".into();
        new.signed = Some(false);
        assert_eq!(describe_change(&old, &new), vec!["the program file", "version 1 -> 2", "signature"]);
        assert_eq!(signature_suffix(Some(false)), " [Unsigned]");
        // An unreadable file (empty hash) is not a change.
        new.hash.clear();
        assert!(!describe_change(&old, &new).contains(&"the program file".to_string()));
    }

    #[test]
    fn core_services_are_refused_and_other_services_are_not() {
        let host = r"C:\Windows\System32\svchost.exe";
        let root = r"c:\windows";
        let key = |service: &str| service_key(&key_for_path(host), service);
        assert!(critical_reason(&key("dhcp"), host, "", root).is_some());
        assert!(critical_reason(&key("rpcss+bits"), host, "", root).is_some());
        assert!(critical_reason(&key("wuauserv"), host, "", root).is_none());
        // The host as a whole, which is not one service's row, stays refused.
        assert!(critical_reason(&key_for_path(host), host, "", root).is_some());
    }

    #[test]
    fn only_the_windows_svchost_is_split_by_service() {
        let root = system_root();
        assert!(is_svchost(&format!(r"{root}\System32\svchost.exe")));
        assert!(!is_svchost(r"C:\Users\me\svchost.exe"));
        assert!(!is_svchost(&format!(r"{root}\System32\lsass.exe")));
    }

    #[test]
    fn service_rows_have_their_own_keys() {
        let host = key_for_path(r"C:\Windows\System32\svchost.exe");
        assert_eq!(service_key(&host, "wuauserv"), r"c:\windows\system32\svchost.exe|svc:wuauserv");
        assert_ne!(service_key(&host, "bits"), service_key(&host, "wuauserv"));
    }

    #[test]
    fn names_and_icons() {
        assert_eq!(file_name(r"C:\a\b\Chrome.exe"), "Chrome.exe");
        assert_eq!(icon_for(r"C:\x\chrome.exe"), AppIcon::Chrome);
        assert_eq!(icon_for(r"C:\x\GoogleDriveFS.exe"), AppIcon::Drive);
        assert_eq!(icon_for(r"C:\x\other.exe"), AppIcon::Generic);
    }

    #[test]
    fn this_process_has_a_parent_name() {
        // The test runner was started by something (cargo, a shell, Explorer), so a parent name exists.
        assert!(parent_name(std::process::id()).is_some_and(|p| p.to_lowercase().ends_with(".exe")));
    }

    #[test]
    fn resolves_this_process() {
        let db = Db::memory();
        let mut r = Resolver::new(&db);
        let got = r.resolve(&db, std::process::id(), 100).expect("own process resolves");
        assert!(!got.name.is_empty());
        // The database started empty, so this counts as the baseline, not a "first activity".
        assert!(!got.is_new);
        let again = r.resolve(&db, std::process::id(), 101).unwrap();
        assert_eq!(again.id, got.id);
    }
}
