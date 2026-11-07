//! Traffic collector: once a second it turns what the OS reports into history rows.
//!
//! * Elevated: an ETW session gives per-process bytes with remote endpoints, so apps, hosts,
//!   traffic types, countries and the WAN/LAN split are all measured.
//! * Not elevated: only the interface counters are readable, so the graph and totals work but
//!   there is no per-app breakdown. The TCP connection table still shows which apps talk to
//!   which hosts (for "first network activity" and the Firewall tab) without byte counts.

use super::alerts::AlertKind;
use super::apps::Resolver;
use super::db::{Db, KIND_LAN, KIND_UNKNOWN, KIND_WAN, TrafficDelta};
use super::geo::Geo;
use super::net::{Locality, Transport, classify, kernel_service, protocol_label};
use super::store::{Shared, TrafficNow};
use crate::data::{DnsEntry, StatusNote};
use crate::sys::etw::{EtwSession, NetEvent};
use crate::sys::{conns, ifstats, netinfo};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

/// Where a packet's bytes go in the accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    pub remote: IpAddr,
    pub remote_port: u16,
    pub local_port: u16,
    pub kind: u8,
    pub proto: &'static str,
    pub down: bool,
}

/// Decides which end of an ETW data event is remote. Returns `None` for loopback and for
/// traffic between two of our own addresses (loopback is excluded).
pub fn flow_of(ev: &NetEvent, locals: &HashSet<IpAddr>) -> Option<(u32, u32, Flow)> {
    let NetEvent::Data { pid, bytes, udp, send, src, dst } = ev else { return None };
    let (remote, local) = match (locals.contains(&src.0), locals.contains(&dst.0)) {
        (true, true) => return None,
        (true, false) => (*dst, *src),
        (false, true) => (*src, *dst),
        // Neither is one of ours (address just changed): trust the direction.
        (false, false) => {
            if *send {
                (*dst, *src)
            } else {
                (*src, *dst)
            }
        }
    };
    let kind = match classify(remote.0) {
        Locality::Loopback => return None,
        Locality::Local => KIND_LAN,
        Locality::Wan => KIND_WAN,
    };
    let transport = if *udp { Transport::Udp } else { Transport::Tcp };
    Some((*pid, *bytes, Flow { remote: remote.0, remote_port: remote.1, local_port: local.1, kind, proto: protocol_label(transport, remote.0, remote.1, local.1), down: !*send }))
}

/// The encrypted copy a VPN client sends over the physical adapter: its event isn't on a tunnel address
/// (traffic that is, belongs to the apps using the tunnel and is kept).
pub fn is_vpn_outer(ev: &NetEvent, vpn_locals: &HashSet<IpAddr>, app_key: &str, extra: &[String]) -> bool {
    let NetEvent::Data { src, dst, .. } = ev else { return false };
    !vpn_locals.contains(&src.0) && !vpn_locals.contains(&dst.0) && super::apps::is_vpn_client(app_key, extra)
}

/// Per-second accumulator keyed like the database rows.
#[derive(Default)]
pub struct Aggregator {
    rows: HashMap<(i64, IpAddr, &'static str, u8), (u64, u64)>,
}

impl Aggregator {
    pub fn add(&mut self, app_id: i64, flow: &Flow, bytes: u32) {
        let e = self.rows.entry((app_id, flow.remote, flow.proto, flow.kind)).or_default();
        if flow.down {
            e.0 += u64::from(bytes);
        } else {
            e.1 += u64::from(bytes);
        }
    }

    pub fn drain(&mut self) -> Vec<TrafficDelta> {
        self.rows.drain().map(|((app_id, remote, proto, kind), (down, up))| TrafficDelta { app_id, remote: remote.to_string(), proto: proto.to_owned(), kind, down, up }).collect()
    }
}

/// Hostnames from DNS answers. A shared (CDN / anycast) address serves many names, so besides the
/// per-address list each lookup is remembered per (process, address) and traffic is matched to that first.
#[derive(Default)]
struct Names {
    by_ip: HashMap<IpAddr, Vec<String>>,
    by_pid: HashMap<(u32, IpAddr), String>,
}

impl Names {
    /// Records an answer; returns the name to show for the address.
    fn dns(&mut self, pid: u32, ip: IpAddr, name: &str) -> String {
        if pid != 0 {
            if self.by_pid.len() > 50_000 {
                self.by_pid.clear();
            }
            self.by_pid.insert((pid, ip), name.to_owned());
        }
        let v = self.by_ip.entry(ip).or_default();
        v.retain(|n| n != name);
        v.push(name.to_owned());
        if v.len() > 16 {
            v.remove(0);
        }
        shared_label(v)
    }

    /// The name this process looked up for the address, if it did.
    fn for_flow(&self, pid: u32, ip: IpAddr) -> Option<&str> {
        self.by_pid.get(&(pid, ip)).map(String::as_str)
    }
}

/// Latest name, with a count when other names share the address.
fn shared_label(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [only] => only.clone(),
        [.., last] => format!("{last} (+{} shared)", names.len() - 1),
    }
}

struct Collector {
    shared: Arc<Shared>,
    db: Db,
    resolver: Resolver,
    geo: Geo,
    geo_path: Option<String>,
    locals: HashSet<IpAddr>,
    /// Addresses on VPN / tunnel adapters; empty while no VPN is connected.
    vpn_locals: HashSet<IpAddr>,
    names: HashMap<IpAddr, String>,
    dns_names: Names,
    /// What was last stored per (program, address), so the database is only written on a change.
    app_names: HashMap<(i64, IpAddr), String>,
    /// Names learned since the last publish; only these are copied into the shared state.
    new_names: Vec<(IpAddr, String)>,
    /// Recent remote addresses per app with bytes, for the Firewall tab's host column.
    app_remote: HashMap<i64, HashMap<IpAddr, (u64, Instant)>>,
    recent_totals: VecDeque<(f64, f64)>,
    recent_apps: HashMap<i64, VecDeque<(f64, f64)>>,
    last_seen_app: HashMap<i64, Instant>,
    p2p: super::p2p::Detector,
    /// Programs flagged as peer-to-peer: id, (key, name, last time flagged). Kept for a week so the list doesn't flicker.
    p2p_seen: HashMap<i64, (String, String, i64)>,
}

impl Collector {
    fn refresh_locals(&mut self) {
        if let Ok(ads) = netinfo::adapters() {
            self.locals = ads.iter().flat_map(|a| a.addrs.iter().map(|(ip, _)| *ip)).collect();
            self.vpn_locals = ads.iter().filter(|a| a.up && a.tunnel).flat_map(|a| a.addrs.iter().map(|(ip, _)| *ip)).collect();
            let note = (self.shared.settings().hide_vpn_traffic && !self.vpn_locals.is_empty())
                .then(|| StatusNote::vpn("VPN detected: the VPN client's encrypted tunnel traffic is not counted, so your traffic statistics aren't doubled (Settings > Privacy > VPN)"));
            self.shared.set_note("vpn", note);
        }
    }

    fn name_of(&self, ip: IpAddr) -> String {
        self.names.get(&ip).cloned().unwrap_or_else(|| ip.to_string())
    }

    fn first_activity(&mut self, app: &str, remote: IpAddr) {
        let place = self.geo.place(remote);
        self.shared.alert(&self.db, AlertKind::FirstActivity, app, "initiated its first network connection to", &self.name_of(remote), &place.code());
    }

    fn note_remote(&mut self, app_id: i64, remote: IpAddr, bytes: u64) {
        let e = self.app_remote.entry(app_id).or_default().entry(remote).or_insert((0, Instant::now()));
        e.0 += bytes;
        e.1 = Instant::now();
    }

    fn incognito(&self, key: &str) -> bool {
        let s = self.shared.settings();
        s.incognito_apps.iter().any(|p| p.to_lowercase() == key)
    }

    /// Handles one second of ETW events.
    fn consume_events(&mut self, rx: &Receiver<NetEvent>, now: i64) -> Vec<TrafficDelta> {
        let mut agg = Aggregator::default();
        let mut per_app: HashMap<i64, (u64, u64)> = HashMap::new();
        let mut total = (0u64, 0u64);
        // Read once per second, not cloned from the settings for every event.
        let (hidden, hide_vpn, vpn_apps, dns_log, split_kernel, p2p_detect, p2p_ignore) = {
            let s = self.shared.settings();
            (
                s.incognito_apps.iter().map(|p| p.to_lowercase()).collect::<Vec<String>>(),
                s.hide_vpn_traffic && !self.vpn_locals.is_empty(),
                s.vpn_apps,
                s.dns_log,
                s.split_kernel,
                s.p2p_detect,
                s.p2p_ignore.iter().map(|p| p.to_lowercase()).collect::<Vec<String>>(),
            )
        };
        let mut p2p_names: Vec<(i64, String, String)> = Vec::new();
        let mut seen = HashSet::new();
        let mut dns_rows = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            match &ev {
                NetEvent::Dns { pid, name, qtype, status, ips, log } => {
                    for ip in ips {
                        let shown = self.dns_names.dns(*pid, *ip, name);
                        self.names.insert(*ip, shown.clone());
                        self.new_names.push((*ip, shown));
                        let _ = self.db.set_hostname(&ip.to_string(), name, now);
                    }
                    if *log && dns_log {
                        // Not through the resolver: a lookup mustn't use up a program's "first network activity" alert.
                        let path = crate::sys::etw::cached_path(*pid).or_else(|| crate::sys::apps::pid_path(*pid));
                        if path.as_ref().is_some_and(|p| hidden.contains(&p.to_lowercase())) {
                            continue;
                        }
                        let app = path.as_deref().map_or("Unknown", super::apps::file_name).to_owned();
                        dns_rows.push(DnsEntry { ts: now, app, name: name.clone(), qtype: *qtype, ips: ips.iter().map(IpAddr::to_string).collect(), status: *status, listed: false });
                    }
                }
                NetEvent::Data { .. } => {
                    let Some((pid, bytes, flow)) = flow_of(&ev, &self.locals) else { continue };
                    let app = if pid == 4 && split_kernel {
                        let (part, name) = kernel_service(matches!(ev, NetEvent::Data { udp: true, .. }), flow.remote_port, flow.local_port);
                        self.resolver.resolve_kernel(&self.db, part, name, now)
                    } else {
                        self.resolver.resolve(&self.db, pid, now)
                    };
                    let Some(app) = app else { continue };
                    if hidden.contains(&app.key) {
                        continue;
                    }
                    if hide_vpn && is_vpn_outer(&ev, &self.vpn_locals, &app.key, &vpn_apps) {
                        continue;
                    }
                    if app.is_new {
                        self.first_activity(&app.name, flow.remote);
                    }
                    if p2p_detect
                        && flow.kind == KIND_WAN
                        && !self.names.contains_key(&flow.remote)
                        && !p2p_ignore.contains(&app.key)
                        && let Some(need) = super::p2p::need_for(&app.key)
                    {
                        self.p2p.note(app.id, flow.remote, flow.remote_port, now, need);
                        p2p_names.push((app.id, app.key.clone(), app.name.clone()));
                    }
                    if let Some(n) = self.dns_names.for_flow(pid, flow.remote)
                        && self.app_names.get(&(app.id, flow.remote)).map(String::as_str) != Some(n)
                    {
                        let _ = self.db.set_app_hostname(app.id, &flow.remote.to_string(), n, now);
                        self.app_names.insert((app.id, flow.remote), n.to_owned());
                    }
                    seen.insert((app.key.clone(), flow.remote));
                    agg.add(app.id, &flow, bytes);
                    self.note_remote(app.id, flow.remote, u64::from(bytes));
                    self.last_seen_app.insert(app.id, Instant::now());
                    let e = per_app.entry(app.id).or_default();
                    if flow.down {
                        e.0 += u64::from(bytes);
                        total.0 += u64::from(bytes);
                    } else {
                        e.1 += u64::from(bytes);
                        total.1 += u64::from(bytes);
                    }
                }
            }
        }
        self.publish_p2p(p2p_detect, p2p_names, &p2p_ignore, now);
        let _ = self.db.add_dns(&dns_rows);
        super::dns::check(&self.shared, &self.db, &dns_rows);
        super::threat::hits(&self.shared, seen);
        self.publish_rates(total, per_app, true);
        agg.drain()
    }

    /// Flags programs that look peer-to-peer and publishes the list; with detection off it empties the list.
    fn publish_p2p(&mut self, on: bool, names: Vec<(i64, String, String)>, ignore: &[String], now: i64) {
        if !on {
            self.p2p = Default::default();
            self.p2p_seen.clear();
            let mut st = self.shared.state();
            if !st.p2p.is_empty() {
                st.p2p.clear();
            }
            return;
        }
        let names: HashMap<i64, (String, String)> = names.into_iter().map(|(id, key, name)| (id, (key, name))).collect();
        for id in self.p2p.flagged(now) {
            if let Some((key, name)) = names.get(&id) {
                self.p2p_seen.insert(id, (key.clone(), name.clone(), now));
            } else if let Some(e) = self.p2p_seen.get_mut(&id) {
                e.2 = now;
            }
        }
        self.p2p_seen.retain(|_, (key, _, t)| now - *t < 7 * 86_400 && !ignore.contains(key));
        let mut list: Vec<crate::data::P2pApp> = self.p2p_seen.values().map(|(key, name, t)| crate::data::P2pApp { key: key.clone(), name: name.clone(), last_seen: *t }).collect();
        list.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then_with(|| a.name.cmp(&b.name)));
        let mut st = self.shared.state();
        if st.p2p != list {
            st.p2p = list;
        }
    }

    /// Smooths rates over three seconds and publishes them for the UI.
    /// `hosts_from_events` is false without ETW, where `poll_connections` fills the hosts and they must survive.
    fn publish_rates(&mut self, total: (u64, u64), per_app: HashMap<i64, (u64, u64)>, hosts_from_events: bool) {
        let push = |q: &mut VecDeque<(f64, f64)>, v: (f64, f64)| {
            q.push_back(v);
            while q.len() > 3 {
                q.pop_front();
            }
            let n = q.len() as f64;
            (q.iter().map(|x| x.0).sum::<f64>() / n, q.iter().map(|x| x.1).sum::<f64>() / n)
        };
        let (down_rate, up_rate) = push(&mut self.recent_totals, (total.0 as f64, total.1 as f64));
        let ids: Vec<i64> = self.recent_apps.keys().chain(per_app.keys()).copied().collect::<HashSet<_>>().into_iter().collect();
        let mut app_rates = HashMap::new();
        for id in ids {
            let q = self.recent_apps.entry(id).or_default();
            let v = per_app.get(&id).map_or((0.0, 0.0), |(d, u)| (*d as f64, *u as f64));
            let avg = push(q, v);
            if avg != (0.0, 0.0) || q.iter().any(|x| *x != (0.0, 0.0)) {
                app_rates.insert(id, avg);
            }
        }
        self.recent_apps.retain(|id, q| per_app.contains_key(id) || q.iter().any(|x| *x != (0.0, 0.0)));
        self.app_remote.retain(|_, m| {
            m.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(120));
            !m.is_empty()
        });
        let app_hosts = self
            .app_remote
            .iter()
            .map(|(id, m)| {
                let mut v: Vec<(&IpAddr, &(u64, Instant))> = m.iter().collect();
                v.sort_by_key(|(_, (bytes, _))| std::cmp::Reverse(*bytes));
                (*id, v.into_iter().map(|(ip, _)| *ip).collect())
            })
            .collect();
        let active_apps = self.last_seen_app.iter().filter(|(_, t)| t.elapsed() < Duration::from_secs(60)).map(|(id, _)| *id).collect();
        let mut st = self.shared.state();
        let app_hosts = if hosts_from_events { app_hosts } else { std::mem::take(&mut st.traffic.app_hosts) };
        let app_parents = self.resolver.parents.clone();
        let service_pids = self.resolver.service_pids();
        st.traffic = TrafficNow { down_rate, up_rate, app_rates, app_hosts, active_apps, app_parents, service_pids };
        st.hostnames.extend(self.new_names.drain(..));
    }

    /// Unelevated fallback: the TCP table tells who talks to whom, without bytes.
    fn poll_connections(&mut self, now: i64) {
        let Ok(list) = conns::tcp() else { return };
        let mut hosts: HashMap<i64, Vec<IpAddr>> = HashMap::new();
        let mut seen = HashSet::new();
        for c in list.into_iter().filter(|c| c.established) {
            if classify(c.remote) == Locality::Loopback {
                continue;
            }
            let Some(app) = self.resolver.resolve(&self.db, c.pid, now) else { continue };
            if self.incognito(&app.key) {
                continue;
            }
            seen.insert((app.key.clone(), c.remote));
            if app.is_new {
                self.first_activity(&app.name, c.remote);
            }
            self.last_seen_app.insert(app.id, Instant::now());
            hosts.entry(app.id).or_default().push(c.remote);
        }
        super::threat::hits(&self.shared, seen);
        let active_apps = self.last_seen_app.iter().filter(|(_, t)| t.elapsed() < Duration::from_secs(60)).map(|(id, _)| *id).collect();
        let mut st = self.shared.state();
        st.traffic.app_hosts = hosts;
        st.traffic.active_apps = active_apps;
    }
}

pub fn run(shared: Arc<Shared>) {
    let db = match shared.open_db() {
        Ok(db) => db,
        Err(e) => {
            shared.set_note("traffic", Some(StatusNote::warn(format!("Traffic history unavailable: can't open the database ({e})"))));
            return;
        }
    };
    let settings = shared.settings();
    let geo_path = settings.geo_db_path.clone();
    let mut c = Collector {
        resolver: Resolver::new(&db),
        geo: Geo::open(geo_path.as_deref()),
        geo_path,
        locals: HashSet::new(),
        vpn_locals: HashSet::new(),
        names: db.hostnames().unwrap_or_default().into_iter().filter_map(|(ip, n)| Some((ip.parse().ok()?, n))).collect(),
        new_names: Vec::new(),
        dns_names: Names::default(),
        app_names: HashMap::new(),
        app_remote: HashMap::new(),
        recent_totals: VecDeque::new(),
        recent_apps: HashMap::new(),
        last_seen_app: HashMap::new(),
        p2p: Default::default(),
        p2p_seen: HashMap::new(),
        shared: shared.clone(),
        db,
    };
    shared.state().hostnames = c.names.clone();
    c.resolver.prime_stats(&c.db);
    c.refresh_locals();

    let (tx, rx) = mpsc::sync_channel::<NetEvent>(200_000);
    let session = if shared.elevated {
        match EtwSession::start(tx) {
            Ok(s) => {
                shared.state().etw = true;
                Some(s)
            }
            Err(e) => {
                shared.set_note("traffic", Some(StatusNote::warn(format!("Per-app traffic unavailable: {e}. Showing adapter totals only."))));
                None
            }
        }
    } else {
        shared.set_note("traffic", Some(StatusNote::warn("Not running as administrator: per-app traffic, hosts and traffic types are unavailable (adapter totals only)")));
        None
    };
    publish_geo_note(&shared, &c.geo);

    let mut prev = ifstats::read().ok();
    let mut tick = 0u64;
    let mut next = Instant::now() + Duration::from_secs(1);
    while !shared.stopping() {
        let wait = next.saturating_duration_since(Instant::now());
        if !shared.sleep(wait.as_secs_f64()) {
            break;
        }
        next += Duration::from_secs(1);
        tick += 1;
        let now = crate::clock::now_unix();

        let rows = if session.is_some() {
            c.consume_events(&rx, now)
        } else {
            let mut rows = Vec::new();
            let cur = ifstats::read().ok();
            let (mut down, mut up) = (0u64, 0u64);
            if let (Some(p), Some(n)) = (&prev, &cur) {
                let d = ifstats::delta(p, n);
                (down, up) = (d.rx, d.tx);
                if down + up > 0 {
                    rows.push(TrafficDelta { app_id: 0, remote: String::new(), proto: String::new(), kind: KIND_UNKNOWN, down, up });
                }
            }
            prev = cur;
            c.publish_rates((down, up), HashMap::new(), false);
            if tick.is_multiple_of(2) {
                c.poll_connections(now);
            }
            rows
        };
        if let Err(e) = c.db.add_traffic(now, &rows) {
            shared.set_note("traffic-db", Some(StatusNote::warn(format!("Can't save traffic history: {e}"))));
        } else {
            shared.set_note("traffic-db", None);
        }

        if tick.is_multiple_of(10) {
            let dropped = crate::sys::etw::DROPPED.load(std::sync::atomic::Ordering::Relaxed);
            shared.set_note(
                "etw-drop",
                (dropped > 0).then(|| crate::data::StatusNote::warn(format!("{dropped} network events were dropped because the collector fell behind; traffic totals may read low."))),
            );
            c.refresh_locals();
            let want = shared.settings().geo_db_path;
            if want != c.geo_path || c.geo.appeared() {
                c.geo = Geo::open(want.as_deref());
                c.geo_path = want;
                publish_geo_note(&shared, &c.geo);
            }
        }
        if tick.is_multiple_of(60) {
            let s = shared.settings();
            // A monthly data plan or quota sums the coarsest scale from the start of the month, so keep that long.
            let days = if s.data_plan.enabled || s.quotas.iter().any(|q| q.enabled) { s.retention_days.max(31) } else { s.retention_days };
            let _ = c.db.prune(now, days);
            let _ = c.db.prune_dns(now, s.dns_retention_days);
            c.resolver.recheck(&c.db, &shared, now);
        }
        shared.repaint();
    }
    drop(session);
}

fn publish_geo_note(shared: &Shared, geo: &Geo) {
    let note = if geo.available() {
        None
    } else if let Some(e) = &geo.error {
        Some(StatusNote::warn(format!("Countries unavailable: {e}")))
    } else {
        Some(StatusNote::info(format!("Countries show as Unknown: no GeoIP database. Download GeoLite2-Country.mmdb from MaxMind and put it at {}", geo.path.display())))
    };
    shared.set_note("geo", note);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn names_are_attributed_per_process() {
        let mut n = Names::default();
        let shared = ip("104.16.0.1");
        n.dns(10, shared, "a.example.com");
        let shown = n.dns(20, shared, "b.example.com");
        assert_eq!(n.for_flow(10, shared), Some("a.example.com"));
        assert_eq!(n.for_flow(20, shared), Some("b.example.com"));
        assert_eq!(n.for_flow(30, shared), None);
        assert_eq!(shown, "b.example.com (+1 shared)");
    }

    #[test]
    fn server_answers_without_pid_only_feed_the_address() {
        let mut n = Names::default();
        n.dns(0, ip("1.1.1.1"), "x.test");
        assert_eq!(n.for_flow(0, ip("1.1.1.1")), None);
    }

    fn ev(send: bool, udp: bool, src: (&str, u16), dst: (&str, u16)) -> NetEvent {
        NetEvent::Data { pid: 10, bytes: 100, udp, send, src: (ip(src.0), src.1), dst: (ip(dst.0), dst.1) }
    }

    fn locals() -> HashSet<IpAddr> {
        [ip("192.168.1.5")].into_iter().collect()
    }

    #[test]
    fn outbound_and_inbound_pick_the_remote_end() {
        let out = flow_of(&ev(true, false, ("192.168.1.5", 50000), ("93.184.216.34", 443)), &locals()).unwrap();
        assert_eq!((out.2.remote, out.2.remote_port, out.2.local_port, out.2.down, out.2.kind), (ip("93.184.216.34"), 443, 50000, false, KIND_WAN));
        // The same connection's received data may report the endpoints the other way round.
        let inn = flow_of(&ev(false, false, ("93.184.216.34", 443), ("192.168.1.5", 50000)), &locals()).unwrap();
        assert_eq!((inn.2.remote, inn.2.down), (ip("93.184.216.34"), true));
        let inn2 = flow_of(&ev(false, false, ("192.168.1.5", 50000), ("93.184.216.34", 443)), &locals()).unwrap();
        assert_eq!(inn2.2.remote, ip("93.184.216.34"));
        assert_eq!(out.2.proto, "Hypertext Transfer Protocol over TLS (HTTPS)");
    }

    #[test]
    fn loopback_and_self_traffic_are_excluded() {
        assert!(flow_of(&ev(true, false, ("127.0.0.1", 1), ("127.0.0.1", 2)), &locals()).is_none());
        assert!(flow_of(&ev(true, false, ("192.168.1.5", 1), ("127.0.0.1", 2)), &locals()).is_none());
        let mut l = locals();
        l.insert(ip("10.0.0.2"));
        assert!(flow_of(&ev(true, false, ("192.168.1.5", 1), ("10.0.0.2", 2)), &l).is_none());
    }

    #[test]
    fn vpn_client_outer_traffic_is_dropped_but_inner_kept() {
        let vpn: HashSet<IpAddr> = [ip("10.8.0.2")].into_iter().collect();
        let key = r"c:\program files\openvpn\bin\openvpn.exe";
        let outer = ev(true, true, ("192.168.1.5", 50000), ("203.0.113.9", 1194));
        let inner = ev(true, false, ("10.8.0.2", 50000), ("93.184.216.34", 443));
        assert!(is_vpn_outer(&outer, &vpn, key, &[]));
        assert!(!is_vpn_outer(&inner, &vpn, key, &[]));
        // Other apps are never touched, and the user's extra names count.
        assert!(!is_vpn_outer(&outer, &vpn, r"c:\apps\chrome.exe", &[]));
        assert!(is_vpn_outer(&outer, &vpn, r"c:\apps\MyVpn.exe", &["myvpn.exe".to_owned()]));
    }

    #[test]
    fn lan_traffic_is_classified() {
        let f = flow_of(&ev(true, true, ("192.168.1.5", 5353), ("224.0.0.251", 5353)), &locals()).unwrap();
        assert_eq!((f.2.kind, f.2.proto), (KIND_LAN, "Multicast DNS (mDNS)"));
    }

    #[test]
    fn aggregator_sums_by_key() {
        let flow = flow_of(&ev(true, false, ("192.168.1.5", 50000), ("93.184.216.34", 443)), &locals()).unwrap().2;
        let mut down = flow.clone();
        down.down = true;
        let mut agg = Aggregator::default();
        agg.add(1, &flow, 100);
        agg.add(1, &flow, 50);
        agg.add(1, &down, 10);
        agg.add(2, &flow, 1);
        let mut rows = agg.drain();
        rows.sort_by_key(|r| r.app_id);
        assert_eq!((rows[0].app_id, rows[0].up, rows[0].down), (1, 150, 10));
        assert_eq!(rows.len(), 2);
        assert!(agg.drain().is_empty());
    }
}
