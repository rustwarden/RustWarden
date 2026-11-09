//! Alert monitors. One thread polls the OS on different intervals; each monitor compares a
//! snapshot with the previous one (the pure comparison lives in `alerts.rs`) and raises an
//! alert on a difference. A failing OS call is skipped, never fatal, so one monitor cannot take
//! the others down.

use super::alerts::{
    AccountChange, AlertKind, Debounce, DnsAdapter, PlanLevel, adapter_ignored, diff_accounts, diff_arp, diff_dns, diff_files, diff_sessions, diff_tasks, diff_uses, dns_leaks, per_user_base,
    plan_level, public_ip_change,
};
use super::bucket::Scale;
use super::db::Db;
use super::store::Shared;
use crate::clock::{self, PeriodKind};
use crate::data::StatusNote;
use crate::settings::{PlanDirection, PlanPeriod};
use crate::sys::{accounts, conns, netinfo, session, watch};
use crate::util::fmt_bytes;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

type ArpMap = HashMap<(u32, IpAddr), String>;
type DnsMap = BTreeMap<String, BTreeSet<IpAddr>>;

fn arp_snapshot() -> Option<ArpMap> {
    let list = netinfo::neighbors().ok()?;
    Some(list.into_iter().filter(|n| n.ip.is_ipv4() && n.resolved && netinfo::is_unicast_mac(&n.mac) && !n.ip.is_multicast()).map(|n| ((n.if_index, n.ip), netinfo::fmt_mac(&n.mac))).collect())
}

fn dns_snapshot() -> Option<DnsMap> {
    let ads = netinfo::adapters().ok()?;
    Some(ads.into_iter().filter(|a| a.up && !a.loopback).map(|a| (a.name, a.dns.into_iter().collect())).collect())
}

fn dns_to_text(m: &DnsMap) -> String {
    m.iter().map(|(a, ips)| format!("{a}|{}", ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(","))).collect::<Vec<_>>().join("\n")
}

fn dns_from_text(t: &str) -> DnsMap {
    t.lines()
        .filter_map(|l| {
            let (a, ips) = l.split_once('|')?;
            Some((a.to_owned(), ips.split(',').filter_map(|s| s.parse().ok()).collect()))
        })
        .collect()
}

fn hosts_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(crate::settings::windows_dir()).join(r"System32\drivers\etc")
}

fn hosts_snapshot() -> BTreeMap<String, String> {
    ["hosts", "lmhosts", "lmhosts.sam"].into_iter().map(|n| (n.to_owned(), crate::sys::apps::hash_file(&hosts_dir().join(n).to_string_lossy()))).collect()
}

fn files_to_text(m: &BTreeMap<String, String>) -> String {
    m.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("\n")
}

fn files_from_text(t: &str) -> BTreeMap<String, String> {
    t.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_owned(), v.to_owned())).collect()
}

/// One line per listening port, "name TCP port (who can reach it)". Ports in the dynamic range are
/// skipped: browsers and runtimes open a new one every launch, which would only be noise.
/// shortcut: a malicious listener on a high port goes unseen, when that matters list them too.
fn listener_set() -> Option<BTreeSet<String>> {
    let list = conns::listeners().ok()?;
    Some(
        list.into_iter()
            .filter(|l| l.port < 49152)
            .map(|l| {
                let path = crate::sys::apps::pid_path(l.pid).unwrap_or_default();
                let name = path.rsplit(['\\', '/']).next().filter(|n| !n.is_empty()).unwrap_or("unknown program");
                format!("{name} TCP port {} ({})", l.port, l.scope())
            })
            .collect(),
    )
}

struct Monitors {
    shared: Arc<Shared>,
    db: Db,
    internet: Debounce,
    arp: Option<ArpMap>,
    dns: Option<DnsMap>,
    proxy: Option<String>,
    hosts: Option<BTreeMap<String, String>>,
    sessions: Option<BTreeMap<u32, String>>,
    away_since: Option<i64>,
    locked: Option<bool>,
    /// The leak last reported, so the same one isn't raised every poll.
    dns_leak: String,
}

impl Monitors {
    fn alert(&self, kind: AlertKind, app: &str, text: &str, target: &str) {
        self.shared.alert(&self.db, kind, app, text, target, "");
    }

    fn internet(&mut self) {
        let Some(connected) = netinfo::internet_connected() else { return };
        if let Some(now_connected) = self.internet.feed(connected) {
            let text = if now_connected { "Internet connection restored" } else { "Internet connection lost" };
            self.alert(AlertKind::Internet, "Internet access", text, "");
        }
    }

    fn sessions(&mut self) {
        let Ok(now) = session::remote_sessions() else { return };
        if let Some(old) = &self.sessions {
            let (started, ended) = diff_sessions(old, &now);
            for user in started {
                self.alert(AlertKind::RemoteSession, &user, "started a Remote Desktop session", "");
            }
            for user in ended {
                self.alert(AlertKind::RemoteSession, &user, "ended a Remote Desktop session", "");
            }
        }
        self.sessions = Some(now);
    }

    fn arp(&mut self) {
        let Some(now) = arp_snapshot() else { return };
        if let Some(old) = &self.arp {
            for c in diff_arp(old, &now) {
                self.alert(AlertKind::Arp, "ARP table", "changed the MAC address of", &format!("{} ({} → {})", c.ip, c.old_mac, c.new_mac));
            }
        }
        self.arp = Some(now);
    }

    fn dns(&mut self) {
        let Some(now) = dns_snapshot() else { return };
        // The first reading of a session is compared with the one saved last time.
        let old = self.dns.take().or_else(|| self.db.kv_get("dns_servers").map(|t| dns_from_text(&t)));
        if let Some(old) = &old {
            for c in diff_dns(old, &now) {
                let list = |v: &[IpAddr]| v.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
                let mut parts = Vec::new();
                if !c.added.is_empty() {
                    parts.push(format!("added {}", list(&c.added)));
                }
                if !c.removed.is_empty() {
                    parts.push(format!("removed {}", list(&c.removed)));
                }
                self.alert(AlertKind::DnsServers, &c.adapter, "changed its DNS servers:", &parts.join("; "));
            }
        }
        if old.as_ref() != Some(&now) {
            let _ = self.db.kv_set("dns_servers", &dns_to_text(&now));
        }
        self.dns = Some(now);
    }

    fn proxy(&mut self) {
        let now = netinfo::proxy_snapshot();
        let old = self.proxy.take().or_else(|| self.db.kv_get("proxy"));
        if let Some(old) = old
            && old != now
        {
            self.alert(AlertKind::Proxy, "Proxy settings", "changed to", &now);
        }
        let _ = self.db.kv_set("proxy", &now);
        self.proxy = Some(now);
    }

    fn hosts(&mut self) {
        let now = hosts_snapshot();
        let old = self.hosts.take().or_else(|| self.db.kv_get("hosts_files").map(|t| files_from_text(&t)));
        if let Some(old) = old {
            let changed = diff_files(&old, &now);
            if !changed.is_empty() {
                self.alert(AlertKind::HostsFile, "Hosts file", "changed:", &changed.join(", "));
            }
        }
        let _ = self.db.kv_set("hosts_files", &files_to_text(&now));
        self.hosts = Some(now);
    }

    /// The first reading ever (nothing saved yet) only sets the baseline; later ones alert on changes.
    fn user_accounts(&mut self) {
        let Ok(now) = accounts::local_users() else { return };
        let old = self.db.kv_get("user_accounts").map(|t| t.lines().filter_map(|l| l.rsplit_once('=')).map(|(k, v)| (k.to_owned(), v == "1")).collect::<BTreeMap<_, _>>());
        if let Some(old) = &old {
            for (name, change) in diff_accounts(old, &now) {
                let what = match change {
                    AccountChange::Created => "was created",
                    AccountChange::Activated => "was activated",
                    AccountChange::Deactivated => "was deactivated",
                    AccountChange::Deleted => "was deleted",
                };
                self.alert(AlertKind::UserAccounts, &format!("User account {name}"), what, "");
            }
        }
        if old.as_ref() != Some(&now) {
            let text = now.iter().map(|(k, v)| format!("{k}={}", u8::from(*v))).collect::<Vec<_>>().join("\n");
            let _ = self.db.kv_set("user_accounts", &text);
        }
    }

    fn scheduled_tasks(&mut self) {
        let Ok(now) = accounts::scheduled_tasks() else { return };
        self.watch_set(AlertKind::ScheduledTasks, "scheduled_tasks", "Task Scheduler", "added a task:", now);
    }

    /// Alerts when an app starts using the microphone or camera. The first reading ever only sets the baseline.
    fn mic_camera(&mut self) {
        let now = watch::device_use();
        let old: Option<BTreeMap<String, u64>> =
            self.db.kv_get("mic_camera").map(|t| t.lines().filter_map(|l| l.rsplit_once('=')).filter_map(|(k, v)| Some((k.to_owned(), v.parse().ok()?))).collect());
        if let Some(old) = &old {
            for key in diff_uses(old, &now) {
                let (device, app) = key.split_once('|').unwrap_or(("microphone", &key));
                let name = app.rsplit(['\\', '/']).next().unwrap_or(app);
                self.alert(AlertKind::MicCamera, name, &format!("started using the {device}"), "");
            }
        }
        if old.as_ref() != Some(&now) {
            let text = now.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("\n");
            let _ = self.db.kv_set("mic_camera", &text);
        }
    }

    fn dns_leak(&mut self) {
        let Ok(ads) = netinfo::adapters() else { return };
        let ignore = self.shared.settings().dns_leak_ignore;
        let list: Vec<DnsAdapter> = ads.into_iter().filter(|a| a.up && !a.loopback && !adapter_ignored(&a.name, &ignore)).map(|a| DnsAdapter { name: a.name, tunnel: a.tunnel, dns: a.dns }).collect();
        let now = dns_leaks(&list).join("; ");
        if !now.is_empty() && now != self.dns_leak {
            self.alert(AlertKind::DnsLeak, "VPN", "is up, but these adapters still use DNS servers outside it:", &now);
        }
        self.dns_leak = now;
    }

    /// Opt-in: asks a web service for this PC's public address. The first reading ever only sets the baseline.
    fn public_ip(&mut self) {
        let s = self.shared.settings();
        if !s.public_ip_check || !s.public_ip_url.starts_with("https://") {
            return;
        }
        // The answer is untrusted: only a bare IP address is accepted.
        let Some(Ok(ip)) = super::asn::curl_url(&["-sS", "--max-time", "10"], &s.public_ip_url).map(|b| b.trim().parse::<IpAddr>()) else { return };
        let isp = super::asn::lookup(ip, &s);
        let new = format!("{ip}|{isp}");
        let old = self.db.kv_get("public_ip");
        if let Some(text) = public_ip_change(old.as_deref(), &ip.to_string(), &isp) {
            self.alert(AlertKind::PublicIp, "Public IP address", "changed:", &text);
        }
        if old.as_deref() != Some(&new) {
            let _ = self.db.kv_set("public_ip", &new);
        }
    }

    fn listeners(&mut self) {
        if let Some(now) = listener_set() {
            self.watch_set(AlertKind::NewListener, "listeners", "Listening ports", "a program started listening:", now);
        }
    }

    /// Alerts on each item of `now` that wasn't in the set saved under `key`. The first reading
    /// ever only sets the baseline.
    fn watch_set(&mut self, kind: AlertKind, key: &str, app: &str, text: &str, now: BTreeSet<String>) {
        let old: Option<BTreeSet<String>> = self.db.kv_get(key).map(|t| t.lines().map(str::to_owned).collect());
        if let Some(old) = &old {
            // A per-user service whose base name was already known is a new login instance, not a new service.
            let known: BTreeSet<&str> = old.iter().map(|o| per_user_base(o).unwrap_or(o)).collect();
            for item in diff_tasks(old, &now) {
                match per_user_base(&item) {
                    Some(base) if kind == AlertKind::NewServices && known.contains(base) => self.alert(kind, app, "refreshed a per-user service:", &item),
                    _ => self.alert(kind, app, text, &item),
                }
            }
        }
        if old.as_ref() != Some(&now) {
            let _ = self.db.kv_set(
                key,
                &now.iter().cloned().collect::<Vec<_>>().join(
                    "
",
                ),
            );
        }
    }

    /// Used bytes in the data plan's current period, per the plan's direction and local-traffic setting.
    fn plan_usage(&self, period: PlanPeriod, direction: PlanDirection, exclude_local: bool, now: i64) -> (f64, i64) {
        let start = clock::period_start(
            now,
            match period {
                PlanPeriod::Day => PeriodKind::Day,
                PlanPeriod::Week => PeriodKind::Week,
                PlanPeriod::Month => PeriodKind::Month,
            },
        );
        let t = self.db.totals(Scale::S600, start, now + 1).unwrap_or_default();
        // Only known-local bytes are left out: unelevated runs record unsplit adapter totals, which still count.
        let (down, up) = if exclude_local { (t.down - (t.lan - t.lan_up), t.up - t.lan_up) } else { (t.down, t.up) };
        let used = match direction {
            PlanDirection::Total => down + up,
            PlanDirection::In => down,
            PlanDirection::Out => up,
        };
        (used, start)
    }

    fn data_plan(&mut self) {
        let plan = self.shared.settings().data_plan;
        if !plan.enabled {
            return;
        }
        let now = clock::now_unix();
        let (used, start) = self.plan_usage(plan.period, plan.direction, plan.exclude_local, now);
        let limit = plan.limit_gb * 1024.0 * 1024.0 * 1024.0;
        let Some(level) = plan_level(used, limit) else { return };
        // Alert once per level per period.
        for l in [PlanLevel::Warning, PlanLevel::Over] {
            if l > level {
                continue;
            }
            let key = format!("plan:{start}:{l:?}");
            if self.db.kv_get(&key).is_none() {
                let _ = self.db.kv_set(&key, "1");
                let text = match l {
                    PlanLevel::Warning => "has used 75% of the data plan:",
                    PlanLevel::Over => "has used the whole data plan:",
                };
                self.alert(AlertKind::DataPlan, "Data plan", text, &format!("{} of {}", fmt_bytes(used), fmt_bytes(limit)));
            }
        }
    }

    fn unlock(&mut self) {
        let Some(now) = session::is_locked() else { return };
        if self.locked == Some(true) && !now {
            self.alert(AlertKind::Unlock, "Computer", "was unlocked", "");
        }
        self.locked = Some(now);
    }

    fn away(&mut self) {
        let settings = self.shared.settings();
        let threshold = u64::from(settings.away_after_minutes) * 60;
        let idle = netinfo::idle_seconds();
        let now = clock::now_unix();
        match self.away_since {
            None if idle >= threshold => self.away_since = Some(now - idle as i64),
            Some(since) if idle < 30 => {
                self.away_since = None;
                let t = self.db.totals(Scale::S30, since, now + 1).unwrap_or_default();
                let mins = (now - since) / 60;
                let target = format!("{} downloaded, {} uploaded in {} min", fmt_bytes(t.down), fmt_bytes(t.up), mins);
                self.alert(AlertKind::Away, "While you were away", "RustWarden recorded", &target);
            }
            _ => {}
        }
    }
}

pub fn run(shared: Arc<Shared>) {
    let Ok(db) = shared.open_db() else {
        shared.set_note("monitors", Some(StatusNote::warn("Alert monitors are off: the database couldn't be opened.")));
        return;
    };
    let mut m =
        Monitors { shared: shared.clone(), db, internet: Debounce::default(), arp: None, dns: None, proxy: None, hosts: None, sessions: None, away_since: None, locked: None, dns_leak: String::new() };
    let mut tick = 0u64;
    while shared.sleep(1.0) {
        if tick.is_multiple_of(5) {
            m.internet();
            m.sessions();
            m.unlock();
        }
        if tick % 10 == 3 {
            m.arp();
            m.dns();
            m.proxy();
            m.hosts();
            m.user_accounts();
            m.scheduled_tasks();
            m.mic_camera();
            m.listeners();
            m.dns_leak();
            m.watch_set(AlertKind::RootCerts, "root_certs", "Root certificates", "added a trusted root certificate:", watch::root_certs());
            m.watch_set(AlertKind::StartupEntries, "startup_entries", "Startup entries", "added a startup entry:", watch::startup_entries());
            m.watch_set(AlertKind::NewServices, "new_services", "Services", "added a service or driver:", watch::service_names());
            m.away();
        }
        if tick % 60 == 30 {
            m.data_plan();
        }
        // First reading soon after start, then every ten minutes.
        if tick == 20 || tick % 600 == 300 {
            m.public_ip();
        }
        tick += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_text_round_trip() {
        let mut m = DnsMap::new();
        m.insert("Wi-Fi".into(), ["192.168.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()].into_iter().collect());
        m.insert("Ethernet".into(), BTreeSet::new());
        assert_eq!(dns_from_text(&dns_to_text(&m)), m);
    }

    #[test]
    fn files_text_round_trip() {
        let m: BTreeMap<String, String> = [("hosts".to_string(), "abc".to_string()), ("lmhosts".to_string(), String::new())].into_iter().collect();
        assert_eq!(files_from_text(&files_to_text(&m)), m);
    }

    #[test]
    fn data_plan_usage_respects_direction_and_local() {
        use crate::live::db::{KIND_LAN, KIND_WAN, TrafficDelta};
        let shared = Arc::new(Shared::new(Default::default(), std::path::PathBuf::new(), false));
        let mut db = Db::memory();
        let now = clock::now_unix();
        let d = |kind, down, up| TrafficDelta { app_id: 1, remote: "x".into(), proto: String::new(), kind, down, up };
        db.add_traffic(now, &[d(KIND_WAN, 1000, 200), d(KIND_LAN, 500, 50)]).unwrap();
        let m = Monitors { shared, db, internet: Debounce::default(), arp: None, dns: None, proxy: None, hosts: None, sessions: None, away_since: None, locked: None, dns_leak: String::new() };
        let (total_wan, _) = m.plan_usage(PlanPeriod::Day, PlanDirection::Total, true, now);
        assert_eq!(total_wan, 1200.0);
        let (total_all, _) = m.plan_usage(PlanPeriod::Day, PlanDirection::Total, false, now);
        assert_eq!(total_all, 1750.0);
        assert_eq!(m.plan_usage(PlanPeriod::Day, PlanDirection::Out, true, now).0, 200.0);
        assert_eq!(m.plan_usage(PlanPeriod::Day, PlanDirection::In, true, now).0, 1000.0);
    }
}
