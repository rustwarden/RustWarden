//! Live mode: measures this machine.
//!
//! Collector threads (traffic, hardware, monitors, scanner, firewall) write into a [`store::Shared`]
//! and into SQLite; [`LiveBackend`] answers the UI from there. The UI thread only reads, and it
//! never waits on a collector. Each collector is individually fault-tolerant: a panic or error
//! in one becomes a status note and the others keep running.

pub mod alerts;
pub mod apps;
pub mod ask;
pub mod asn;
pub mod baseline;
pub mod beacon;
pub mod bucket;
pub mod capture;
pub mod db;
pub mod dest;
pub mod dns;
pub mod dnsguard;
pub mod dnstunnel;
pub mod domains;
pub mod engine;
pub mod firewall;
pub mod geo;
pub mod guard;
pub mod hardware;
pub mod lease;
pub mod monitors;
pub mod net;
pub mod p2p;
pub mod qos;
pub mod quota;
pub mod scanner;
pub mod sniff;
pub mod store;
pub mod threat;
pub mod traffic;
pub mod vt;
pub mod windows_extras;

use crate::data::*;
use crate::settings::Settings;
use bucket::{Scale, range_buckets, selection_interval};
use db::{AppRecord, Db};
use firewall::FwController;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use store::{Shared, lock};

pub struct LiveBackend {
    shared: Arc<Shared>,
    reader: Mutex<Option<Db>>,
    fw: Arc<FwController>,
    dest: Arc<dest::Dest>,
    qos: Arc<qos::Qos>,
    sniffer: Arc<sniff::Sniffer>,
    domains: Arc<domains::Domains>,
    dnsguard: Arc<dnsguard::Guard>,
    capture: capture::Capture,
    geo: Mutex<geo::Geo>,
    asn: Arc<asn::Resolver>,
    vt: Arc<vt::Scanner>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

/// The history database, also opened by the thinkbroadband / Ping tab.
pub fn db_path() -> std::path::PathBuf {
    crate::settings::data_dir().join("rustwarden.db")
}

impl LiveBackend {
    pub fn new(settings: &Settings) -> Self {
        let _ = std::fs::create_dir_all(crate::settings::data_dir());
        let elevated = crate::sys::is_elevated();
        let shared = Arc::new(Shared::new(settings.clone(), db_path(), elevated));
        let reader = match shared.open_db() {
            Ok(db) => {
                // One-time and a few rows at most; done here so it is over before plugins start.
                dnstunnel::clear_false_reports(&db);
                Some(db)
            }
            Err(e) => {
                shared.set_note("db", Some(StatusNote::warn(format!("History database unavailable: {e}"))));
                None
            }
        };
        let fw = Arc::new(FwController::new(shared.clone()));
        firewall::migrate_legacy_state(elevated);
        // A Block All left behind by a crash is undone before anything else.
        // (unless the last exit left Prompt blocking on purpose, which `resume` carries on)
        if !firewall::kept_block(settings.keep_blocking_closed, elevated)
            && let Err(e) = firewall::recover_block_all()
        {
            shared.set_note("blockall", Some(StatusNote::warn(e)));
        }
        let (asn, asn_rx) = asn::Resolver::new(shared.clone());
        let vt = Arc::new(vt::Scanner::default());
        let dest = Arc::new(dest::Dest::new(shared.clone(), fw.clone()));
        let qos = Arc::new(qos::Qos::new(shared.clone()));
        let domains = Arc::new(domains::Domains::new(shared.clone()));
        let backend = Self {
            dest: dest.clone(),
            qos: qos.clone(),
            vt: vt.clone(),
            asn: asn.clone(),
            geo: Mutex::new(geo::Geo::open(settings.geo_path().as_deref())),
            shared,
            reader: Mutex::new(reader),
            fw,
            sniffer: Arc::new(sniff::Sniffer::default()),
            domains: domains.clone(),
            dnsguard: Arc::default(),
            capture: Default::default(),
            threads: Mutex::new(Vec::new()),
        };
        lease::install(backend.shared.clone(), backend.fw.clone());
        store::install_alert_sink(backend.shared.clone());
        backend.spawn("asn", move |_| asn.run(asn_rx));
        backend.spawn("virustotal", move |shared| vt.run(shared));
        backend.spawn("traffic", traffic::run);
        backend.spawn("hardware", hardware::run);
        backend.spawn("monitors", monitors::run);
        backend.spawn("scanner", scanner::run);
        let (shared, fw) = (backend.shared.clone(), backend.fw.clone());
        backend.spawn("firewall", move |_| firewall::run(shared, fw));
        backend.spawn("dest", move |shared| dest::run(shared, dest));
        backend.spawn("qos", move |shared| qos::run(shared, qos));
        let guard = backend.dnsguard.clone();
        backend.spawn("driver-dns", move |shared| dnsguard::run(shared, guard));
        let domains = backend.domains.clone();
        backend.spawn("driver-domains", move |shared| domains::run(shared, domains));
        let sniffer = backend.sniffer.clone();
        backend.spawn("driver-names", move |shared| sniff::run(shared, sniffer));
        let (shared, fw) = (backend.shared.clone(), backend.fw.clone());
        backend.spawn("p2p", move |_| p2p::run(shared, fw));
        let (shared, fw) = (backend.shared.clone(), backend.fw.clone());
        backend.spawn("guard", move |_| guard::run(shared, fw));
        let (shared, fw) = (backend.shared.clone(), backend.fw.clone());
        backend.spawn("ask", move |_| ask::run(shared, fw));
        let (shared, fw) = (backend.shared.clone(), backend.fw.clone());
        backend.spawn("threat", move |_| threat::run(shared, fw));
        backend.spawn("dns-threat", dns::run);
        let (shared, fw) = (backend.shared.clone(), backend.fw.clone());
        let qos = backend.qos.clone();
        backend.spawn("quota", move |_| quota::run(shared, fw, qos));
        let asn = backend.asn.clone();
        backend.spawn("baseline", move |shared| baseline::run(shared, asn));
        backend.spawn("report", crate::report::run);
        if elevated {
            let (qos, domains, guard, sniffer) = (backend.qos.clone(), backend.domains.clone(), backend.dnsguard.clone(), backend.sniffer.clone());
            backend.spawn("driver-move", move |shared| {
                if !crate::driver::retire_old_folder() {
                    return;
                }
                let result = crate::driver::install();
                qos.reconcile();
                domains.reconcile();
                dnsguard::refresh(&shared, &guard);
                sniff::refresh(&shared, &sniffer);
                if let Err(e) = result {
                    shared
                        .set_note("driver-move", Some(StatusNote::warn(format!("The network driver moved to a safer folder, but reinstalling it failed: {e} Install it again in Settings > Other."))));
                }
            });
        }
        backend
    }

    /// Runs a collector on its own thread; a panic is reported instead of silently ending it.
    fn spawn(&self, name: &'static str, f: impl FnOnce(Arc<Shared>) + Send + 'static) {
        let shared = self.shared.clone();
        let handle = std::thread::Builder::new().name(name.into()).spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(shared.clone())));
            if result.is_err() {
                shared.set_note(name, Some(StatusNote::warn(format!("The {name} collector stopped unexpectedly; the rest keep running"))));
            }
        });
        if let Ok(h) = handle {
            lock(&self.threads).push(h);
        }
    }

    fn with_db<T: Default>(&self, f: impl FnOnce(&Db) -> rusqlite::Result<T>) -> T {
        match lock(&self.reader).as_ref() {
            Some(db) => match f(db) {
                Ok(v) => {
                    self.shared.set_note("db", None);
                    v
                }
                Err(e) => {
                    self.shared.set_note("db", Some(StatusNote::warn(format!("A database read failed ({e}); some lists may be empty."))));
                    T::default()
                }
            },
            None => T::default(),
        }
    }

    fn network_key(&self, label: &str) -> Option<String> {
        self.shared.state().networks.iter().find(|n| n.label == label).map(|n| n.key.clone())
    }

    fn place_of(&self, ip: &str) -> geo::Place {
        let Ok(ip) = ip.parse::<IpAddr>() else { return geo::Place::Unknown };
        let mut g = lock(&self.geo);
        // A database that appeared after startup (downloaded or copied in) is picked up here.
        if g.appeared() {
            *g = geo::Geo::open(g.path.to_str());
        }
        g.place(ip)
    }

    /// Programs the user put on the Incognito list, lower-cased like app keys.
    fn hidden_keys(&self) -> Vec<String> {
        self.shared.settings().incognito_apps.iter().map(|p| p.to_lowercase()).collect()
    }

    fn host_label(&self, ip: &str) -> String {
        ip.parse::<IpAddr>().ok().and_then(|ip| self.shared.state().hostnames.get(&ip).cloned()).unwrap_or_else(|| ip.to_owned())
    }
}

/// Folds `(label, remote, down, up)` rows into one entry per label, biggest first. `key` is the
/// remote that carried the most, so a merged row still opens a detail view.
fn merge_hosts(rows: Vec<(String, String, f64, f64)>) -> Vec<(String, db::UsageEntry)> {
    let mut out: Vec<(String, db::UsageEntry, f64)> = Vec::new();
    for (label, key, down, up) in rows {
        match out.iter_mut().find(|(l, ..)| *l == label) {
            Some((_, e, best)) => {
                e.down += down;
                e.up += up;
                if down + up > *best {
                    *best = down + up;
                    e.key = key;
                }
            }
            None => out.push((label, db::UsageEntry { key, down, up }, down + up)),
        }
    }
    out.sort_by(|a, b| (b.1.down + b.1.up).total_cmp(&(a.1.down + a.1.up)));
    out.into_iter().map(|(l, e, _)| (l, e)).collect()
}

/// Fraction of `part` in `whole`, 0 when `whole` is 0.
fn share(part: f64, whole: f64) -> f32 {
    if whole > 0.0 { (part / whole) as f32 } else { 0.0 }
}

fn row(label: String, e: &db::UsageEntry, left: Glyph, right: Option<Glyph>) -> UsageRow {
    UsageRow { label, key: e.key.clone(), bytes: e.down + e.up, up_share: share(e.up, e.down + e.up), left, right }
}

const MAX_HOSTS: usize = 10;

impl Backend for LiveBackend {
    fn set_repaint(&self, ctx: egui::Context) {
        *lock(&self.shared.ctx) = Some(ctx);
    }

    fn capabilities(&self) -> Capabilities {
        let st = self.shared.state();
        let readable = st.fw.readable;
        let elevated = self.shared.elevated;
        Capabilities {
            live: true,
            elevated,
            per_app_traffic: st.etw,
            firewall_write: elevated && readable,
            firewall_modes: [true, elevated && readable, elevated && readable],
            scanner: true,
            geo_db: lock(&self.geo).available(),
        }
    }

    fn status(&self) -> Vec<StatusNote> {
        let mut notes = self.shared.notes();
        if !self.shared.elevated {
            notes.push(StatusNote::warn("Not running as administrator: firewall rules are read-only"));
        }
        notes
    }

    fn set_traffic_filter(&self, filter: &TrafficFilter) {
        // The AS lookups are cached in memory, so the matching addresses are worked out here.
        // Hosts still being looked up don't match yet; the next reload applies the filter again.
        let q = filter.network.trim().to_lowercase();
        let remotes = (!q.is_empty()).then(|| {
            // "15169" matches AS15169 only, not AS151690.
            let digits = q.strip_prefix("as").unwrap_or(&q);
            let q = if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) { format!("as{digits} ") } else { q.clone() };
            self.with_db(|db| db.remotes()).into_iter().filter(|r| format!("{} ", self.asn.get(r).to_lowercase()).contains(&q)).collect::<Vec<_>>()
        });
        self.with_db(|db| db.set_filter(filter, remotes.as_deref()));
    }

    fn map_data(&self, range: TimeRange) -> MapData {
        let (scale, first, n) = range_buckets(crate::clock::now_unix(), range);
        let entries = self.with_db(|db| db.usage_by_remote(scale, first, first + n as i64 * scale.secs()));
        let geo = lock(&self.geo);
        let city_mode = self.shared.settings().geoip_city && geo.city_db();
        // One point per country, or per place (rounded to ~1 km) when a city database is in use.
        let mut points: HashMap<([u8; 2], i32, i32), MapConnection> = HashMap::new();
        let mut add = |ip: IpAddr, f: &dyn Fn(&mut MapConnection)| {
            let place = geo.place(ip);
            if let (geo::Place::Country(code), Some(pos)) = (place, geo.position(ip, place)) {
                let k = if city_mode { ((pos.1 * 100.0).round() as i32, (pos.0 * 100.0).round() as i32) } else { (0, 0) };
                f(points.entry((code, k.0, k.1)).or_insert_with(|| MapConnection {
                    lon: pos.0,
                    lat: pos.1,
                    count: 0,
                    down: 0.0,
                    up: 0.0,
                    blocked: 0,
                    key: String::from_utf8_lossy(&code).into_owned(),
                    label: if city_mode { geo.city(ip).unwrap_or_default() } else { String::new() },
                }));
            }
        };
        for e in &entries {
            let Ok(ip) = e.key.parse::<IpAddr>() else { continue };
            add(ip, &|c| {
                c.count += 1;
                c.down += e.down;
                c.up += e.up;
            });
        }
        // Attempts the firewall stopped: hosts with no allowed traffic still get a point.
        for (remote, hits) in self.with_db(|db| db.blocked_by_remote(first, first + n as i64 * scale.secs())) {
            let Ok(ip) = remote.parse::<IpAddr>() else { continue };
            add(ip, &|c| c.blocked += hits);
        }
        let home = crate::sys::home_region().and_then(crate::countries::by_a2).map_or((0.0, 20.0), |e| (e.lon, e.lat));
        // HashMap order changes every call; sorting keeps each arc's animation steady across reloads.
        let mut connections: Vec<_> = points.into_values().collect();
        connections.sort_by(|a, b| (&a.key, a.lon.to_bits(), a.lat.to_bits()).cmp(&(&b.key, b.lon.to_bits(), b.lat.to_bits())));
        let mut active: Vec<String> = connections.iter().filter_map(|c| crate::countries::parse_a2(&c.key).and_then(crate::countries::by_a2)).map(|e| e.a3.to_owned()).collect();
        active.sort();
        active.dedup();
        MapData { home, connections, active }
    }

    fn traffic_history(&self, range: TimeRange) -> TrafficHistory {
        let (scale, first, n) = range_buckets(crate::clock::now_unix(), range);
        let rows = self.with_db(|db| db.series(scale, first, first + n as i64 * scale.secs()));
        TrafficHistory { start_minute: crate::clock::minute_of_day(first), step_minutes: scale.secs() as f32 / 60.0, samples: bucket::fill(&rows, first, n, scale) }
    }

    fn totals(&self, range: TimeRange, window: (f32, f32)) -> Totals {
        let (scale, first, n) = range_buckets(crate::clock::now_unix(), range);
        let (t0, t1) = selection_interval(first, n, scale, window);
        let t = self.with_db(|db| db.totals(scale, t0, t1).map(|t| (t.down, t.up, t.wan, t.wan_up, t.lan, t.lan_up)));
        let now = self.shared.state().traffic.clone();
        Totals { down: t.0, up: t.1, down_rate: now.down_rate, up_rate: now.up_rate, wan: t.2, lan: t.4 }
    }

    fn breakdown(&self, range: TimeRange, window: (f32, f32)) -> UsageBreakdown {
        let (scale, first, n) = range_buckets(crate::clock::now_unix(), range);
        let (t0, t1) = selection_interval(first, n, scale, window);
        let (by_app, by_remote, by_proto, apps, top_hosts, app_remote, app_names) = self.with_db(|db| {
            Ok((
                db.usage_by_app(scale, t0, t1)?,
                db.usage_by_remote(scale, t0, t1)?,
                db.usage_by_proto(scale, t0, t1)?,
                db.apps()?,
                db.hosts_by_app(scale, t0, t1)?,
                db.usage_by_app_remote(scale, t0, t1)?,
                db.app_hostnames()?,
            ))
        });
        let app_names: HashMap<(i64, String), String> = app_names.into_iter().map(|(id, ip, n)| ((id, ip), n)).collect();
        let apps_by_id: HashMap<String, &AppRecord> = apps.iter().map(|a| (a.id.to_string(), a)).collect();
        let mut main_host: HashMap<i64, String> = HashMap::new();
        for (id, ip, _) in &top_hosts {
            main_host.entry(*id).or_insert_with(|| ip.clone());
        }

        let hidden = self.hidden_keys();
        let app_rows = by_app
            .iter()
            .filter(|e| apps_by_id.get(&e.key).is_none_or(|a| !hidden.contains(&a.key)))
            .take(8)
            .map(|e| {
                let rec = apps_by_id.get(&e.key);
                let icon = rec.map_or(AppIcon::Generic, |a| apps::icon_for(&a.path));
                let flag = rec.and_then(|a| main_host.get(&a.id)).map(|ip| self.place_of(ip).country());
                row(rec.map_or_else(|| "Unknown".into(), |a| a.name.clone()), e, Glyph::App(icon), flag.map(Glyph::Flag))
            })
            .collect();

        // Named per program where known, so a shared CDN address isn't one arbitrary name for everyone.
        let merged =
            merge_hosts(app_remote.into_iter().map(|(id, remote, down, up)| (app_names.get(&(id, remote.clone())).cloned().unwrap_or_else(|| self.host_label(&remote)), remote, down, up)).collect());
        let mut host_rows: Vec<UsageRow> = merged.iter().take(MAX_HOSTS).map(|(label, e)| row(label.clone(), e, Glyph::Flag(self.place_of(&e.key).country()), Some(Glyph::Window))).collect();
        if merged.len() > MAX_HOSTS {
            let rest = &merged[MAX_HOSTS..];
            let (down, up) = rest.iter().fold((0.0, 0.0), |a, (_, e)| (a.0 + e.down, a.1 + e.up));
            host_rows.push(row(format!("+{} more", rest.len()), &db::UsageEntry { key: String::new(), down, up }, Glyph::More, Some(Glyph::Window)));
        }

        let type_rows = by_proto.iter().take(9).map(|e| row(e.key.clone(), e, Glyph::Window, None)).collect();

        let mut countries: Vec<(geo::Place, f64, f64)> = Vec::new();
        for e in &by_remote {
            let place = self.place_of(&e.key);
            match countries.iter_mut().find(|(p, _, _)| *p == place) {
                Some(c) => {
                    c.1 += e.down;
                    c.2 += e.up;
                }
                None => countries.push((place, e.down, e.up)),
            }
        }
        countries.sort_by(|a, b| (b.1 + b.2).total_cmp(&(a.1 + a.2)));
        let country_rows = countries.iter().take(8).map(|(p, down, up)| row(p.label().to_owned(), &db::UsageEntry { key: p.code(), down: *down, up: *up }, Glyph::Flag(p.country()), None)).collect();

        UsageBreakdown { apps: app_rows, hosts: host_rows, traffic_types: type_rows, countries: country_rows }
    }

    fn usage_detail(&self, range: TimeRange, window: (f32, f32), kind: UsageKind, key: &str) -> Option<UsageDetail> {
        use db::Dim;
        if key.is_empty() && kind != UsageKind::Country {
            return None;
        }
        let (scale, first, n) = range_buckets(crate::clock::now_unix(), range);
        let (t0, t1) = selection_interval(first, n, scale, window);
        let apps = self.with_db(|db| db.apps());
        let by_id: HashMap<String, &AppRecord> = apps.iter().map(|a| (a.id.to_string(), a)).collect();
        let app_row = |e: &db::UsageEntry| {
            let rec = by_id.get(&e.key);
            DetailRow {
                label: rec.map_or_else(|| "Unknown".into(), |a| a.name.clone()),
                left: Glyph::App(rec.map_or(AppIcon::Generic, |a| apps::icon_for(&a.path))),
                right: None,
                extra: String::new(),
                down: e.down,
                up: e.up,
                target: rec.map(|_| (UsageKind::App, e.key.clone())),
            }
        };
        let host_row = |e: &db::UsageEntry| DetailRow {
            label: self.host_label(&e.key),
            left: Glyph::Flag(self.place_of(&e.key).country()),
            right: None,
            extra: String::new(),
            down: e.down,
            up: e.up,
            target: Some((UsageKind::Host, e.key.clone())),
        };
        let detail = match kind {
            UsageKind::App => {
                let rec = by_id.get(key)?;
                let mut facts = vec![("Path".to_owned(), rec.path.clone()), ("Publisher".to_owned(), rec.publisher.clone()), ("Version".to_owned(), rec.version.clone())];
                if !rec.service.is_empty() {
                    facts.push(("Service".to_owned(), rec.service.replace('+', ", ")));
                }
                if let Some(parent) = self.shared.state().traffic.app_parents.get(&rec.id) {
                    facts.push(("Parent process".to_owned(), parent.clone()));
                }
                facts.retain(|(_, v)| !v.is_empty());
                let rows = self.with_db(|db| db.grouped(Dim::Remote, (Dim::App, key), scale, t0, t1)).iter().map(host_row).collect();
                UsageDetail { title: rec.name.clone(), glyph: Glyph::App(apps::icon_for(&rec.path)), facts, heading: "Hosts".into(), rows }
            }
            UsageKind::Host => {
                let place = self.place_of(key);
                let name = self.host_label(key);
                let mut facts = vec![("Region".to_owned(), place.label().to_owned())];
                if name != key {
                    facts.push(("Host".to_owned(), name.clone()));
                }
                facts.push(("IP".to_owned(), key.to_owned()));
                let info = self.asn.get(key);
                if !info.is_empty() {
                    facts.push(("Network".to_owned(), info));
                }
                let rows = self.with_db(|db| db.grouped(Dim::App, (Dim::Remote, key), scale, t0, t1)).iter().map(app_row).collect();
                UsageDetail { title: name, glyph: Glyph::Flag(place.country()), facts, heading: "App".into(), rows }
            }
            UsageKind::TrafficType => {
                let rows = self.with_db(|db| db.grouped(Dim::App, (Dim::Proto, key), scale, t0, t1)).iter().map(app_row).collect();
                UsageDetail { title: key.to_owned(), glyph: Glyph::Window, facts: Vec::new(), heading: "App".into(), rows }
            }
            UsageKind::Country => {
                let (code, city) = key.split_once(':').unwrap_or((key, ""));
                let hosts: Vec<db::UsageEntry> = self
                    .with_db(|db| db.usage_by_remote(scale, t0, t1))
                    .into_iter()
                    .filter(|e| self.place_of(&e.key).code() == code)
                    .filter(|e| city.is_empty() || e.key.parse::<IpAddr>().ok().is_some_and(|ip| lock(&self.geo).city(ip).as_deref() == Some(city)))
                    .collect();
                let place = hosts.first().map(|e| self.place_of(&e.key))?;
                let rows = hosts
                    .iter()
                    .take(50)
                    .map(|e| {
                        let users = self.with_db(|db| db.grouped(Dim::App, (Dim::Remote, &e.key), scale, t0, t1));
                        let mut row = host_row(e);
                        row.right = users.first().map(|u| app_row(u).left);
                        row.extra = if users.len() > 1 { format!("+{}", users.len() - 1) } else { String::new() };
                        row
                    })
                    .collect();
                let where_ = if city.is_empty() { place.label().to_owned() } else { format!("{city}, {}", place.label()) };
                UsageDetail { title: format!("{where_} ({} hosts)", hosts.len()), glyph: Glyph::Flag(place.country()), facts: Vec::new(), heading: "Apps".into(), rows }
            }
        };
        Some(detail.with_all())
    }

    fn firewall_info(&self) -> FirewallInfo {
        let st = self.shared.state();
        let engine = if !st.fw.readable {
            EngineState::Unavailable(st.fw.error.clone().unwrap_or_else(|| "still reading".into()))
        } else if !st.fw.windows_firewall_on {
            EngineState::WindowsFirewallOff
        } else {
            EngineState::Ready
        };
        FirewallInfo {
            enabled: st.fw_enabled,
            mode: if st.fw.ask_active {
                FirewallMode::AskToConnect
            } else if st.fw.block_all_active {
                FirewallMode::BlockAll
            } else {
                FirewallMode::ClickToBlock
            },
            engine,
            block_all_active: st.fw.block_all_active,
            rule_count: st.fw.rules.len(),
            read_only: (!self.shared.elevated).then(|| "run RustWarden as administrator to change firewall rules (use \"Restart as administrator\")".to_owned()),
        }
    }

    fn firewall_apps(&self) -> Vec<FirewallApp> {
        let apps = self.with_db(|db| db.apps());
        let now = crate::clock::now_unix();
        let activity = self.with_db(|db| db.app_activity(Scale::S30, now / 30 * 30 - 39 * 30, now + 1));
        let st = self.shared.state();
        let (traffic, rules) = (st.traffic.clone(), st.fw.rules.clone());
        let hostnames = st.hostnames.clone();
        drop(st);
        let own_exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let root = apps::system_root();
        let blocked = |key: &str, outbound: bool| rules.iter().any(|r| r.block && firewall::row_key(&r.program, &r.service) == key && r.outbound == outbound && !firewall::is_lan(&r.name));
        let local_blocked = |key: &str| rules.iter().any(|r| r.block && firewall::row_key(&r.program, &r.service) == key && firewall::is_lan(&r.name));
        // Prompt denies by default: an app with no rules yet (just removed, or new) is denied until answered.
        let ask = self.shared.state().fw.ask_active;
        let undecided = |key: &str| ask && !rules.iter().any(|r| firewall::row_key(&r.program, &r.service) == key && !r.name.starts_with("RustWarden block-all"));
        let thirty_days = 30 * 86_400;

        let hidden = self.hidden_keys();
        let removed = self.with_db(|db| Ok(firewall::removed_apps(db)));
        let since = self.with_db(|db| Ok(firewall::profile_since(db)));
        let running = crate::sys::apps::running_paths();
        let mut out: Vec<FirewallApp> = Vec::new();
        let vts: Vec<Vt> = self.with_db(|db| Ok(apps.iter().map(|a| self.vt.get(db, &a.hash)).collect()));
        for (i, a) in apps.iter().enumerate().filter(|(_, a)| !hidden.contains(&a.key)) {
            // Any RustWarden rule keeps an app on the list (an allow rule too, or it couldn't be removed).
            let has_rule = rules.iter().any(|r| firewall::row_key(&r.program, &r.service) == a.key && !r.name.starts_with("RustWarden block-all"));
            let active = traffic.active_apps.contains(&a.id);
            // A removed app stays hidden until it is seen again (new or continuing connection) or gets a rule.
            if !has_rule && (removed.get(&a.key).is_some_and(|&at| a.last_seen <= at) || a.last_seen < since) {
                continue;
            }
            let locked = apps::critical_reason(&a.key, &a.path, &own_exe, &root).is_some();
            let is_windows = locked && !a.path.eq_ignore_ascii_case(&own_exe);
            let group = if is_windows {
                AppGroup::Windows
            } else if a.missing_since.is_some() {
                AppGroup::Uninstalled
            } else if active {
                AppGroup::Active
            } else {
                AppGroup::Inactive
            };
            if !matches!(group, AppGroup::Active | AppGroup::Windows) && !has_rule && now - a.last_seen > thirty_days {
                continue;
            }
            if group == AppGroup::Uninstalled && !has_rule {
                continue;
            }
            let hosts = traffic.app_hosts.get(&a.id).cloned().unwrap_or_default();
            let (host, host_country) = hosts.first().map_or((String::new(), Country::Other), |ip| (hostnames.get(ip).cloned().unwrap_or_else(|| ip.to_string()), lock(&self.geo).place(*ip).country()));
            let (down_rate, up_rate) = traffic.app_rates.get(&a.id).copied().unwrap_or_default();
            // 40 half-minute buckets, the last one being the current.
            let mut series: Vec<f32> = (0..40)
                .map(|i| {
                    let t = now / 30 * 30 - 39 * 30 + i * 30;
                    activity.iter().filter(|(id, ts, _)| *id == a.id && *ts == t).map(|(_, _, b)| *b as f32).sum()
                })
                .collect();
            let peak = series.iter().copied().fold(0.0_f32, f32::max);
            if peak > 0.0 {
                series.iter_mut().for_each(|v| *v /= peak);
            }
            // A locked program is always allowed (Prompt never asks about it), so it can't count as undecided.
            let undecided = !locked && undecided(&a.key);
            out.push(FirewallApp {
                key: a.key.clone(),
                usage_key: a.id.to_string(),
                name: a.name.clone(),
                path: a.path.clone(),
                publisher: a.publisher.clone(),
                signed: a.signed,
                group,
                icon: apps::icon_for(&a.path),
                // Only the outgoing chip is held at Blocked until Prompt has an answer; incoming and local show their own
                // rules, so changing them by hand shows at once instead of after outgoing is allowed.
                inbound: verdict_shown(blocked(&a.key, false)),
                outbound: verdict_shown(undecided || blocked(&a.key, true)),
                local: verdict_shown(local_blocked(&a.key)),
                locked,
                version: a.version.clone(),
                host,
                host_country,
                more_hosts: hosts.len().saturating_sub(1) as u32,
                down_rate,
                up_rate,
                activity: series,
                virustotal: vts.get(i).cloned().unwrap_or_default(),
                hash: a.hash.clone(),
                pids: if a.service.is_empty() { running.iter().filter(|(_, p)| *p == a.key).map(|(pid, _)| *pid).collect() } else { traffic.service_pids.get(&a.key).cloned().unwrap_or_default() },
                service: a.service.clone(),
                parent: traffic.app_parents.get(&a.id).cloned().unwrap_or_default(),
            });
        }
        out.sort_by(|a, b| {
            let rank = |g: AppGroup| AppGroup::ALL.iter().position(|x| *x == g).unwrap_or(0);
            rank(a.group).cmp(&rank(b.group)).then((b.down_rate + b.up_rate).total_cmp(&(a.down_rate + a.up_rate))).then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        out
    }

    fn quotas(&self, _settings: &Settings) -> Vec<QuotaStatus> {
        self.shared.state().quotas.clone()
    }

    fn set_verdict(&self, key: &str, direction: Direction, verdict: Verdict) -> Result<(), String> {
        self.fw.set_verdict(key, direction, verdict)
    }

    fn block_program(&self, path: &str) -> Result<String, String> {
        self.fw.block_path(path)
    }

    fn remove_app(&self, key: &str) -> Result<(), String> {
        self.fw.remove_app(key)
    }

    fn set_firewall_enabled(&self, on: bool) -> Result<(), String> {
        self.fw.set_enabled(on)
    }

    fn set_firewall_mode(&self, mode: FirewallMode) -> Result<(), String> {
        self.fw.set_mode(mode)
    }

    fn restore_defaults(&self) -> Result<(), String> {
        let firewall = self.fw.restore_defaults();
        // Bandwidth limits are RustWarden's too.
        let limits = self.qos.remove_all();
        let domains = self.domains.remove_all();
        firewall.and(limits).and(domains)
    }

    fn import_firewall_rules(&self, rename: bool) -> Result<usize, String> {
        self.fw.import_rules(rename)
    }

    fn block_windows_extras(&self) -> Result<usize, String> {
        self.fw.block_windows_extras()
    }

    fn windows_extras_state(&self) -> Vec<(bool, bool)> {
        FwController::windows_extras_state_in(lock(&self.reader).as_ref())
    }

    fn windows_extras_act(&self, group: usize, act: firewall::ExtrasAct) -> Result<usize, String> {
        self.fw.windows_extras_act(group, act)
    }

    fn enable_windows_firewall(&self) -> Result<(), String> {
        self.fw.enable_windows_firewall()
    }

    fn firewall_profiles(&self) -> (Vec<String>, String) {
        // The reader connection: this runs every refresh, and opening a database each time stalls the UI.
        FwController::profiles_in(lock(&self.reader).as_ref())
    }

    fn delete_firewall_profile(&self, name: &str) -> Result<(), String> {
        self.fw.delete_profile(name)
    }

    fn switch_firewall_profile(&self, name: &str, create: bool) -> Result<(), String> {
        self.fw.switch_profile(name, create)
    }

    fn p2p_apps(&self) -> Vec<crate::data::P2pApp> {
        self.shared.state().p2p.clone()
    }

    fn dest_rules(&self) -> Vec<crate::destrules::DestRuleView> {
        self.with_db(|db| Ok(self.dest.views(db)))
    }

    fn save_dest_rule(&self, rule: crate::destrules::DestRule) -> Result<(), String> {
        self.dest.save_rule(rule)
    }

    fn remove_dest_rule(&self, id: u32) -> Result<(), String> {
        self.dest.remove_rule(id)
    }

    fn driver_state(&self) -> crate::driver::DriverState {
        crate::driver::state()
    }

    fn capture_status(&self) -> Option<crate::pcap::CaptureStatus> {
        self.capture.status()
    }

    fn start_capture(&self, conn: &LiveConn) -> Result<String, String> {
        self.capture.start(&self.shared, conn)
    }

    fn stop_capture(&self) {
        self.capture.stop();
    }

    fn domain_blocks(&self) -> crate::domainblock::DomainView {
        self.with_db(|db| Ok(self.domains.view(db)))
    }

    fn save_domain_block(&self, rule: crate::domainblock::DomainRule) -> Result<(), String> {
        self.domains.save(rule)
    }

    fn remove_domain_block(&self, id: u32) -> Result<(), String> {
        self.domains.remove(id)
    }

    fn import_domain_list(&self, url: &str) -> Result<usize, String> {
        self.domains.import(url)
    }

    fn clear_domain_list(&self) -> Result<(), String> {
        self.domains.clear_list()
    }

    fn install_driver(&self) -> Result<(), String> {
        let result = crate::driver::install();
        self.qos.reconcile();
        self.domains.reconcile();
        dnsguard::refresh(&self.shared, &self.dnsguard);
        sniff::refresh(&self.shared, &self.sniffer);
        result
    }

    fn remove_driver(&self) -> Result<(), String> {
        // The engine holds the driver open, which keeps its files locked.
        self.qos.stop_engine();
        self.sniffer.stop();
        self.domains.stop();
        self.dnsguard.stop();
        self.capture.stop();
        let result = crate::driver::remove();
        self.qos.reconcile();
        result
    }

    fn qos_limits(&self) -> Vec<crate::qos::QosView> {
        self.with_db(|db| Ok(self.qos.views(db)))
    }

    fn save_qos_limit(&self, limit: crate::qos::QosLimit) -> Result<(), String> {
        self.qos.save(limit)
    }

    fn remove_qos_limit(&self, id: u32) -> Result<(), String> {
        self.qos.remove(id)
    }

    fn asn_db_ready(&self) -> bool {
        geo::asn_db_path().exists()
    }

    fn download_asn_db(&self) -> Result<(), String> {
        geo::download_dbip(&geo::asn_db_path(), "asn", &Default::default())
    }

    fn dns_log(&self) -> Vec<crate::data::DnsEntry> {
        let mut rows = self.with_db(|db| db.dns_recent(5000));
        let st = self.shared.state();
        if !st.dns_domains.is_empty() {
            for r in &mut rows {
                r.listed = dns::is_listed(&st.dns_domains, &r.name);
            }
        }
        rows
    }

    fn live_connections(&self) -> Vec<LiveConn> {
        let rows = crate::sys::conns::table(self.shared.elevated).unwrap_or_default();
        let hostnames = self.shared.state().hostnames.clone();
        let mut names: HashMap<u32, String> = HashMap::new();
        let mut out: Vec<LiveConn> = rows
            .into_iter()
            .map(|r| {
                let app = names
                    .entry(r.pid)
                    .or_insert_with(|| crate::sys::apps::pid_path(r.pid).and_then(|p| p.rsplit(['\\', '/']).next().map(str::to_owned)).unwrap_or_else(|| format!("PID {}", r.pid)))
                    .clone();
                LiveConn {
                    pid: r.pid,
                    app,
                    state: r.state.label().to_owned(),
                    local: r.local,
                    remote: r.remote,
                    host: hostnames.get(&r.remote.ip()).cloned().unwrap_or_default(),
                    bytes: r.bytes,
                    killable: crate::sys::conns::killable(&r),
                    country: match self.place_of(&r.remote.ip().to_string()) {
                        geo::Place::Unknown => None,
                        p => Some(p.country()),
                    },
                    since: r.started,
                }
            })
            .collect();
        // UDP flows come from the driver's flow events, so they appear only with the driver installed and in use.
        if self.shared.settings().app_mode == crate::settings::AppMode::Driver && crate::driver::ready() {
            for (pid, local, remote) in self.sniffer.udp_flows() {
                let app =
                    names.entry(pid).or_insert_with(|| crate::sys::apps::pid_path(pid).and_then(|p| p.rsplit(['\\', '/']).next().map(str::to_owned)).unwrap_or_else(|| format!("PID {pid}"))).clone();
                let country = match self.place_of(&remote.ip().to_string()) {
                    geo::Place::Unknown => None,
                    p => Some(p.country()),
                };
                out.push(LiveConn { pid, app, state: "UDP".into(), local, remote, host: hostnames.get(&remote.ip()).cloned().unwrap_or_default(), bytes: None, killable: true, country, since: None });
            }
        }
        out.sort_by(|a, b| b.bytes.map_or(0, |(i, o)| i + o).cmp(&a.bytes.map_or(0, |(i, o)| i + o)).then(a.app.to_lowercase().cmp(&b.app.to_lowercase())).then(a.remote.cmp(&b.remote)));
        out
    }

    fn kill_connection(&self, c: &LiveConn) -> Result<String, String> {
        if !self.shared.elevated {
            return Err("Ending a connection needs administrator rights. Use \"Restart as administrator\".".into());
        }
        if c.state == "UDP" {
            return sniff::kill_udp(c.local, c.remote);
        }
        let state = crate::sys::conns::TcpState::Established;
        crate::sys::conns::kill(&crate::sys::conns::ConnRow { pid: c.pid, local: c.local, remote: c.remote, state, bytes: c.bytes, started: c.since })?;
        Ok(format!("Ended the connection from {} to {}.", c.app, c.remote))
    }

    fn block_remote(&self, ip: IpAddr) -> Result<String, String> {
        self.fw.block_ip(ip, true)?;
        Ok(format!("Blocked {ip} in both directions."))
    }

    fn alerts(&self) -> Vec<Alert> {
        let now = crate::clock::now_unix();
        // A baseline or DNS tunnelling alert offers "Mark as normal" only until it has been marked (or its item forgotten).
        let markable = self.with_db(|db| db.markable_alerts());
        self.with_db(|db| db.alerts(500))
            .into_iter()
            .map(|s| {
                let a = s.new;
                let country = store::country_of(&a.country);
                Alert {
                    id: s.id as u64,
                    icon: AppIcon::Generic,
                    app: a.app,
                    text: a.text,
                    target: a.target,
                    country,
                    kind: alerts::AlertKind::label_for_key(&a.kind).to_owned(),
                    time: crate::clock::fmt_time_lower(a.ts),
                    day: crate::clock::day_label(a.ts, now),
                    ts: a.ts,
                    unread: a.unread,
                    important: a.important,
                    anomaly: alerts::can_mark_normal(&a.kind) && markable.contains(&s.id),
                }
            })
            .collect()
    }

    fn mark_read(&self, id: Option<u64>) {
        self.with_db(|db| db.mark_read(id.map(|i| i as i64)));
    }

    fn mark_alert_normal(&self, id: u64) -> bool {
        self.with_db(|db| db.mark_normal(id as i64, crate::clock::now_unix()))
    }

    fn take_popups(&self, visible: bool) -> Vec<Alert> {
        let mut st = self.shared.state();
        st.popups_ok = visible;
        std::mem::take(&mut st.popups)
    }

    fn virustotal(&self, who: &str) -> Vt {
        if vt::key().is_empty() {
            return Vt::None;
        }
        // shortcut: a name can match several programs, the first with a hash wins; pass the hash when it is known.
        let is_hash = who.len() == 64 && who.bytes().all(|b| b.is_ascii_hexdigit());
        self.with_db(|db| {
            let hash = if is_hash { who.to_owned() } else { db.hash_of(who)?.unwrap_or_default() };
            let v = self.vt.get(db, &hash);
            if v == Vt::None {
                self.vt.scan(&hash);
            }
            Ok(v)
        })
    }

    fn scan_virustotal(&self, key: &str) {
        if let Some(a) = self.with_db(|db| db.apps()).iter().find(|a| a.key == key) {
            self.vt.scan(&a.hash);
        }
    }

    fn upload_virustotal(&self, key: &str) {
        if let Some(a) = self.with_db(|db| db.apps()).iter().find(|a| a.key == key) {
            self.vt.upload(&a.hash);
        }
    }

    fn net_info(&self, host: &str) -> String {
        self.asn.get(host)
    }

    fn take_asks(&self) -> Vec<ConnectAsk> {
        std::mem::take(&mut self.shared.state().asks)
    }

    fn answer_ask(&self, path: &str, answer: Answer) -> Result<(), String> {
        self.fw.answer(path, answer)
    }

    fn take_threats(&self) -> Vec<Threat> {
        std::mem::take(&mut self.shared.state().threats)
    }

    fn blocked_ips(&self) -> Vec<(String, String)> {
        let st = self.shared.state();
        st.fw.threat_blocked.iter().map(|ip| (ip.clone(), st.threat_meta.get(ip).cloned().unwrap_or_default())).collect()
    }

    fn threat_whitelist(&self) -> Vec<(String, String)> {
        let st = self.shared.state();
        st.threat_allow.iter().map(|ip| (ip.clone(), st.threat_meta.get(ip).cloned().unwrap_or_default())).collect()
    }

    fn threat_summary(&self, ip: &str) -> String {
        threat::summary(&self.shared, ip)
    }

    fn threat_act(&self, ip: &str, act: ThreatAct) -> Result<(), String> {
        threat::act(&self.shared, &self.fw, ip, act)
    }

    fn snooze_alerts(&self, minutes: u32) {
        self.shared.state().snooze_until = crate::clock::now_unix() + i64::from(minutes) * 60;
    }

    fn test_alert(&self, kind: &str, s: &Settings) {
        self.shared.test_alert(kind, s);
    }

    fn alerts_snoozed(&self) -> bool {
        self.shared.state().snooze_until > crate::clock::now_unix()
    }

    fn networks(&self) -> Vec<String> {
        self.shared.state().networks.iter().map(|n| n.label.clone()).collect()
    }

    fn devices(&self, network: &str) -> Vec<Device> {
        let Some(key) = self.network_key(network) else { return Vec::new() };
        let annotators = crate::plugins::wasm::manager::annotator_ids();
        let notes = self.with_db(|db| db.device_notes(&annotators));
        self.with_db(|db| db.devices(&key))
            .into_iter()
            .map(|d| Device {
                note: notes.get(&d.mac).cloned(),
                name: d.name,
                online: d.online,
                kind: scanner::kind_from_i64(d.kind),
                description: d.vendor,
                system: d.system,
                ip: d.ip,
                mac: d.mac,
                last_seen: d.last_seen,
                first_seen: d.first_seen,
                seen_count: d.seen_count,
                ports: d.ports.split(',').filter_map(|p| p.parse().ok()).collect(),
                trusted: d.trusted,
            })
            .collect()
    }

    fn scan_state(&self) -> ScanState {
        self.shared.state().scan.clone()
    }

    fn start_scan(&self, network: &str) {
        if let Some(key) = self.network_key(network) {
            scanner::start(&self.shared, &key);
        }
    }

    fn stop_scan(&self) {
        self.shared.scan_cancel.store(true, Ordering::Relaxed);
    }

    fn rename_device(&self, network: &str, mac: &str, name: &str) {
        if let Some(key) = self.network_key(network) {
            self.with_db(|db| db.rename_device(&key, mac, name));
        }
    }

    fn set_device_trusted(&self, network: &str, mac: &str, trusted: bool) {
        if let Some(key) = self.network_key(network) {
            self.with_db(|db| db.set_trusted(&key, mac, trusted));
        }
    }

    fn forget_network(&self, network: &str) {
        if let Some(key) = self.network_key(network) {
            self.with_db(|db| db.forget_network(&key));
        }
    }

    fn hardware(&self, seconds: usize) -> HardwareSnapshot {
        let st = self.shared.state();
        let have = st.hw.len().min(seconds);
        let mut samples = vec![HardwareSample::default(); seconds - have];
        samples.extend(st.hw.iter().skip(st.hw.len() - have).copied());
        let h = &st.hw_now;
        HardwareSnapshot {
            samples,
            now_secs: if st.hw_secs > 0 { st.hw_secs } else { crate::clock::to_local(crate::clock::now_unix()) },
            cpu_pct: h.cpu_pct,
            memory_used: h.memory_used,
            memory_total: h.memory_total,
            gpu_available: h.gpu_available,
            disk_read: h.disk_read,
            disk_write: h.disk_write,
            gpu_pct: h.gpu_pct,
            gpu_memory: h.gpu_memory,
        }
    }

    fn speedtest_route(&self, server_ip: &str, client_ip: &str) -> Option<crate::ui::speed::SpeedRoute> {
        let geo = lock(&self.geo);
        let at = |s: &str| {
            let ip = s.parse::<IpAddr>().ok()?;
            geo.position(ip, geo.place(ip))
        };
        let home = at(client_ip).or_else(|| crate::sys::home_region().and_then(crate::countries::by_a2).map(|e| (e.lon, e.lat)))?;
        Some(crate::ui::speed::SpeedRoute { home, server: at(server_ip)? })
    }

    fn hardware_apps(&self, window_secs: i64) -> Vec<String> {
        let t0 = crate::clock::now_unix() - window_secs;
        self.with_db(|db| db.hardware_apps(t0))
    }

    fn hardware_history(&self, window_secs: i64, buckets: usize, app: Option<&str>) -> Vec<Option<HardwareSample>> {
        let now = crate::clock::now_unix();
        let t0 = now - window_secs;
        let rows = self.with_db(|db| db.hardware_series(t0, now + 1, app));
        // Sum per slot, then average, so a slot spanning several rows isn't dominated by one.
        let mut sums = vec![([0.0_f32; 4], 0u32); buckets];
        for (ts, s) in rows {
            // A row stamped `now` lands one past the end; it belongs to the last slot.
            let i = ((((ts - t0) as f64 / window_secs as f64) * buckets as f64) as usize).min(buckets.saturating_sub(1));
            if let Some((a, n)) = sums.get_mut(i) {
                for (x, v) in a.iter_mut().zip([s.cpu, s.memory, s.disk, s.gpu]) {
                    *x += v;
                }
                *n += 1;
            }
        }
        sums.into_iter()
            .map(|(a, n)| {
                (n > 0).then(|| {
                    let n = n as f32;
                    HardwareSample { cpu: a[0] / n, memory: a[1] / n, disk: a[2] / n, gpu: a[3] / n }
                })
            })
            .collect()
    }

    fn apply_settings(&self, settings: &Settings) {
        let old = self.shared.settings();
        let path_changed = old.geo_path() != settings.geo_path();
        if (old.net_info, &old.net_info_url) != (settings.net_info, &settings.net_info_url) {
            self.asn.clear();
        }
        *self.shared.settings.write().unwrap_or_else(|e| e.into_inner()) = settings.clone();
        // Switching between Normal and Driver mode moves the limits between QoS policies and the driver engine.
        if (old.app_mode, old.driver_names, old.dns_enforce, &old.dns_resolver, old.line_up_mbps, old.line_down_mbps)
            != (settings.app_mode, settings.driver_names, settings.dns_enforce, &settings.dns_resolver, settings.line_up_mbps, settings.line_down_mbps)
        {
            let (qos, sniffer, shared, domains, guard) = (self.qos.clone(), self.sniffer.clone(), self.shared.clone(), self.domains.clone(), self.dnsguard.clone());
            std::thread::spawn(move || {
                dnsguard::refresh(&shared, &guard);
                qos.reconcile();
                domains.reconcile();
                sniff::refresh(&shared, &sniffer);
            });
        }
        // Also retry while there is no database: it may have been downloaded or copied in since.
        if path_changed || !lock(&self.geo).available() {
            *lock(&self.geo) = geo::Geo::open(settings.geo_path().as_deref());
        }
    }

    fn clear_history(&self) -> Result<(), String> {
        match lock(&self.reader).as_ref() {
            Some(db) => db.clear_traffic().map_err(|e| e.to_string()),
            None => Err("History database unavailable".into()),
        }
    }

    fn verify_alerts(&self) -> Result<AlertCheck, String> {
        // A connection of its own, so a long walk does not hold up the UI's reader.
        self.shared.open_db().and_then(|db| db.verify_alerts()).map_err(|e| e.to_string())
    }

    fn weekly_report(&self) -> Result<crate::report::Report, String> {
        let db = self.shared.open_db().map_err(|e| e.to_string())?;
        crate::report::build(&db, &lock(&self.geo), &self.shared.settings(), crate::clock::now_unix()).map_err(|e| e.to_string())
    }

    fn metrics_snapshot(&self) -> Result<crate::metrics::Snapshot, String> {
        let db = self.shared.open_db().map_err(|e| e.to_string())?;
        let now = crate::clock::now_unix();
        let (t0, t1) = (now - 86_400, now + 1);
        let totals = db.totals(Scale::S600, t0, t1).map_err(|e| e.to_string())?;
        let blocked = db.blocked_by_remote(t0, t1).map_err(|e| e.to_string())?.iter().map(|(_, n)| u64::from(*n)).sum();
        let alerts = db.alert_counts().map_err(|e| e.to_string())?;
        let names: std::collections::HashMap<String, String> = db.apps().map_err(|e| e.to_string())?.into_iter().map(|a| (a.id.to_string(), a.name)).collect();
        // usage_by_app is already busiest first.
        let apps = db.usage_by_app(Scale::S600, t0, t1).map_err(|e| e.to_string())?.into_iter().map(|u| (names.get(&u.key).cloned().unwrap_or(u.key), u.down, u.up)).collect();
        Ok(crate::metrics::Snapshot { wan_down: totals.wan, wan_up: totals.wan_up, blocked, alerts, apps })
    }

    fn export_history(&self, data: HistoryData, format: HistoryFormat, days: Option<u32>) -> Result<String, String> {
        let since = days.map_or(i64::MIN, |d| crate::clock::now_unix() - i64::from(d) * 86_400);
        let db = self.shared.open_db().map_err(|e| e.to_string())?;
        Ok(match data {
            HistoryData::Traffic => {
                let mut rows = db.history_rows(since).map_err(|e| e.to_string())?;
                for r in &mut rows {
                    r.country = self.place_of(&r.remote).code();
                }
                match format {
                    HistoryFormat::Csv => crate::export::traffic_csv(&rows),
                    HistoryFormat::Json => crate::export::json(&rows),
                }
            }
            HistoryData::Alerts => {
                let rows = db.alerts_since(since).map_err(|e| e.to_string())?;
                match format {
                    HistoryFormat::Csv => crate::export::alerts_csv(&rows),
                    HistoryFormat::Json => crate::export::json(&rows),
                }
            }
        })
    }

    fn shutdown(&self) {
        self.stop_all(false);
    }

    fn exit(&self) {
        self.stop_all(true);
    }
}

impl LiveBackend {
    /// Stops the collectors. `exiting` is the app really closing, as opposed to a restart or a switch to Demo.
    fn stop_all(&self, exiting: bool) {
        if self.shared.stop.swap(true, Ordering::Relaxed) {
            return;
        }
        self.shared.scan_cancel.store(true, Ordering::Relaxed);
        // Block All is undone first, so leaving the app never leaves the machine cut off.
        self.fw.shutdown(exiting);
        self.qos.stop_engine();
        self.sniffer.stop();
        self.domains.stop();
        self.dnsguard.stop();
        self.capture.stop();
        lease::uninstall();
        lease::end_all(&self.shared, &self.fw);
        // A collector stuck in a long upload (VirusTotal allows 5 minutes) must not hold up exit: wait a few seconds, then let go.
        let mut threads: Vec<_> = lock(&self.threads).drain(..).collect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while threads.iter().any(|h| !h.is_finished()) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        for h in threads.drain(..).filter(|h| h.is_finished()) {
            let _ = h.join();
        }
    }
}

impl Drop for LiveBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The chip for a direction: Blocked when something blocks it.
fn verdict_shown(blocked: bool) -> Verdict {
    if blocked { Verdict::Blocked } else { Verdict::Allowed }
}

#[cfg(test)]
mod verdict_tests {
    use super::*;

    #[test]
    fn hosts_with_the_same_label_merge_into_one_row() {
        let r = |l: &str, k: &str, d: f64| (l.to_owned(), k.to_owned(), d, 1.0);
        let m = merge_hosts(vec![r("cf", "1.1.1.1", 5.0), r("other", "9.9.9.9", 3.0), r("cf", "2.2.2.2", 20.0)]);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].0, "cf");
        assert_eq!((m[0].1.down, m[0].1.up), (25.0, 2.0));
        assert_eq!(m[0].1.key, "2.2.2.2");
    }

    #[test]
    fn a_chip_is_blocked_only_when_something_blocks_it() {
        assert_eq!(verdict_shown(true), Verdict::Blocked);
        assert_eq!(verdict_shown(false), Verdict::Allowed);
    }
}
