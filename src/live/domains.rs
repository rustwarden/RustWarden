//! Block by domain in Live mode (Driver mode only). The saved rules, plus an optional imported list, become a
//! `domainblock::Matcher`. A WinDivert handle (not sniff-only) receives outgoing DNS queries and the first
//! packet of outgoing TLS connections: one that names a blocked domain is dropped, everything else goes
//! straight back. Dropped queries time out and dropped client-hellos never connect.
//!
//! Limits: a program using DNS-over-HTTPS and Encrypted Client Hello shows neither name; QUIC isn't read; a TLS hello
//! split over several packets, and DNS over TCP, aren't read either.

use super::db::Db;
use super::store::{Shared, lock};
use crate::domainblock::{self, DomainRule, DomainView, Matcher};
use crate::netpkt;
use crate::sys::windivert::{self as wd, Address, Handle, Lib};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

const KEY: &str = "domain_blocks";
const URL_KEY: &str = "domain_list_url";
const FILTER: &str = "outbound and !loopback and ((tcp.DstPort == 443 and tcp.PayloadLength > 0 and tcp.Payload[0] == 0x16) or udp.DstPort == 53)";
/// Used if this WinDivert build rejects reading the payload in the filter: slower, since every HTTPS packet comes up.
const FILTER_BROAD: &str = "outbound and !loopback and ((tcp.DstPort == 443 and tcp.PayloadLength > 0) or udp.DstPort == 53)";

fn list_path() -> std::path::PathBuf {
    crate::settings::data_dir().join("domain_blocklist.txt")
}

fn load_rules(db: &Db) -> Vec<DomainRule> {
    domainblock::decode_all(&db.kv_get(KEY).unwrap_or_default())
}

fn store_rules(db: &Db, rules: &[DomainRule]) -> Result<(), String> {
    db.kv_set(KEY, &domainblock::encode_all(rules)).map_err(|e| format!("Can't save the rule: {e}"))
}

/// Whether the packet should be dropped: a TLS hello or a DNS query for a blocked name.
fn should_drop(m: &Matcher, packet: &[u8]) -> bool {
    let Some(p) = netpkt::parse(packet) else { return false };
    let payload = &packet[p.payload.min(packet.len())..];
    if p.proto == netpkt::TCP {
        crate::netparse::sni(payload).is_some_and(|host| m.blocks(&host))
    } else {
        p.dport == 53 && crate::netparse::dns(payload).filter(|d| !d.response).is_some_and(|d| m.blocks(&d.question.0))
    }
}

struct Running {
    matcher: Arc<RwLock<Matcher>>,
    handle: Arc<Handle>,
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

pub struct Domains {
    shared: Arc<Shared>,
    busy: Mutex<()>,
    running: Mutex<Option<Running>>,
    /// Domains of the imported list.
    list: Mutex<Vec<String>>,
    blocked: Arc<AtomicU64>,
    status: Mutex<(String, bool)>,
}

impl Domains {
    pub fn new(shared: Arc<Shared>) -> Self {
        let list = std::fs::read_to_string(list_path()).map(|t| domainblock::parse_list(&t)).unwrap_or_default();
        Self { shared, busy: Mutex::new(()), running: Mutex::new(None), list: Mutex::new(list), blocked: Arc::default(), status: Mutex::new(("Checking…".into(), false)) }
    }

    pub fn view(&self, db: &Db) -> DomainView {
        let (status, problem) = lock(&self.status).clone();
        DomainView { rules: load_rules(db), list_count: lock(&self.list).len(), list_url: db.kv_get(URL_KEY).unwrap_or_default(), status, problem }
    }

    /// Adds the rule (id 0) or replaces the one with its id.
    pub fn save(&self, mut rule: DomainRule) -> Result<(), String> {
        rule.pattern = domainblock::normalize(&rule.pattern).map_err(str::to_owned)?;
        let db = self.shared.open_db().map_err(|e| format!("Can't open the database: {e}"))?;
        let mut rules = load_rules(&db);
        if rules.iter().any(|r| r.id != rule.id && r.pattern == rule.pattern) {
            return Err("That domain is already in the list.".into());
        }
        if rule.id == 0 {
            if rules.len() >= domainblock::MAX_RULES {
                return Err(format!("At most {} domains can be added by hand. Use a list for more.", domainblock::MAX_RULES));
            }
            rule.id = rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
            rules.push(rule);
        } else if let Some(slot) = rules.iter_mut().find(|r| r.id == rule.id) {
            *slot = rule;
        } else {
            return Err("That rule no longer exists.".into());
        }
        store_rules(&db, &rules)?;
        drop(db);
        self.reconcile();
        Ok(())
    }

    pub fn remove(&self, id: u32) -> Result<(), String> {
        let db = self.shared.open_db().map_err(|e| format!("Can't open the database: {e}"))?;
        let mut rules = load_rules(&db);
        rules.retain(|r| r.id != id);
        store_rules(&db, &rules)?;
        drop(db);
        self.reconcile();
        Ok(())
    }

    /// Downloads a hosts-style or one-domain-per-line list (this is the only network use, on the user's click).
    pub fn import(&self, url: &str) -> Result<usize, String> {
        let (status, body) = crate::update::get(url.trim(), "text/plain", None)?;
        if status != 200 {
            return Err(if status == 0 { "Could not download the list.".into() } else { format!("The server answered HTTP {status}.") });
        }
        let domains = domainblock::parse_list(&String::from_utf8_lossy(&body));
        if domains.is_empty() {
            return Err("No domains were found in that list.".into());
        }
        std::fs::write(list_path(), domains.join("\n")).map_err(|e| format!("Can't save the list: {e}"))?;
        if let Ok(db) = self.shared.open_db() {
            let _ = db.kv_set(URL_KEY, url.trim());
        }
        let n = domains.len();
        *lock(&self.list) = domains;
        self.reconcile();
        Ok(n)
    }

    pub fn clear_list(&self) -> Result<(), String> {
        let _ = std::fs::remove_file(list_path());
        lock(&self.list).clear();
        if let Ok(db) = self.shared.open_db() {
            let _ = db.kv_set(URL_KEY, "");
        }
        self.reconcile();
        Ok(())
    }

    /// Forgets every rule and the list ("Restore firewall defaults").
    pub fn remove_all(&self) -> Result<(), String> {
        if let Ok(db) = self.shared.open_db() {
            store_rules(&db, &[])?;
        }
        self.clear_list()
    }

    pub fn stop(&self) {
        let mut running = lock(&self.running);
        if let Some(r) = running.take() {
            r.stop.store(true, Ordering::Relaxed);
            r.handle.shutdown();
            let _ = r.thread.join();
        }
    }

    /// Makes the blocker match the saved rules and the settings.
    pub fn reconcile(&self) {
        let _g = lock(&self.busy);
        let rules = self.shared.open_db().map(|db| load_rules(&db)).unwrap_or_default();
        let domains: Vec<String> = rules.into_iter().filter(|r| r.enabled).map(|r| r.pattern).chain(lock(&self.list).iter().cloned()).collect();
        let matcher = Matcher::new(domains);
        let driver = self.shared.settings().app_mode == crate::settings::AppMode::Driver;
        let (text, problem) = if !driver {
            self.stop();
            ("Blocking by domain needs Driver mode.".to_owned(), false)
        } else if matcher.is_empty() {
            self.stop();
            ("Nothing to block yet.".to_owned(), false)
        } else if !self.shared.elevated {
            self.stop();
            ("Needs administrator rights to apply.".to_owned(), true)
        } else {
            match self.apply(matcher.clone()) {
                Ok(()) => (format!("Active: {} domain(s) blocked; {} connection(s) stopped since start.", matcher.len(), self.blocked.load(Ordering::Relaxed)), false),
                Err(e) => (e, true),
            }
        };
        *lock(&self.status) = (text, problem);
    }

    fn apply(&self, matcher: Matcher) -> Result<(), String> {
        let mut running = lock(&self.running);
        if let Some(r) = running.as_ref()
            && r.thread.is_finished()
        {
            drop(running);
            self.stop();
            running = lock(&self.running);
        }
        if let Some(r) = running.as_ref() {
            *r.matcher.write().unwrap_or_else(|e| e.into_inner()) = matcher;
            return Ok(());
        }
        if crate::driver::state() != crate::driver::DriverState::Ready {
            return Err("The driver isn't installed. Install it in Settings.".into());
        }
        let lib = Lib::load(&crate::driver::dir().join("WinDivert.dll"))?;
        let handle = Arc::new(lib.open(FILTER, wd::LAYER_NETWORK, 1, 0).or_else(|_| lib.open(FILTER_BROAD, wd::LAYER_NETWORK, 1, 0))?);
        let (matcher, stop) = (Arc::new(RwLock::new(matcher)), Arc::new(AtomicBool::new(false)));
        let (m2, h2, c2) = (matcher.clone(), handle.clone(), self.blocked.clone());
        let thread = std::thread::Builder::new().name("driver-domains".into()).spawn(move || packet_loop(&h2, &m2, &c2)).map_err(|e| e.to_string())?;
        *running = Some(Running { matcher, handle, stop, thread });
        Ok(())
    }
}

fn packet_loop(h: &Handle, matcher: &RwLock<Matcher>, blocked: &AtomicU64) {
    let (mut buf, mut addr) = (vec![0u8; wd::MAX_PACKET], Address::zeroed());
    while let Ok(len) = h.recv(&mut buf, &mut addr) {
        let packet = &buf[..len];
        if should_drop(&matcher.read().unwrap_or_else(|e| e.into_inner()), packet) {
            blocked.fetch_add(1, Ordering::Relaxed);
        } else {
            let _ = h.send(packet, &addr);
        }
    }
}

/// Re-checks once a minute, so a stopped blocker comes back and the status stays honest.
pub fn run(shared: Arc<Shared>, domains: Arc<Domains>) {
    domains.reconcile();
    while shared.sleep(60.0) {
        domains.reconcile();
    }
    domains.stop();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip_packet(proto: u8, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0, 10, 0, 0, 2, 9, 9, 9, 9];
        p.extend(50000u16.to_be_bytes());
        p.extend(dport.to_be_bytes());
        if proto == netpkt::UDP {
            p.extend([0, 8, 0, 0]);
        } else {
            p.extend([0; 8]);
            p.extend([0x50, 0x18, 0, 0, 0, 0, 0, 0]);
        }
        p.extend(payload);
        p
    }

    #[test]
    fn dns_queries_and_hellos_for_blocked_names_are_dropped_the_rest_pass() {
        let m = Matcher::new(["ads.example.com".to_owned()]);
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["x", "ads", "example", "com"] {
            q.push(l.len() as u8);
            q.extend(l.as_bytes());
        }
        q.extend([0, 0, 1, 0, 1]);
        assert!(should_drop(&m, &ip_packet(netpkt::UDP, 53, &q)));
        let other = Matcher::new(["other.net".to_owned()]);
        assert!(!should_drop(&other, &ip_packet(netpkt::UDP, 53, &q)));
        assert!(!should_drop(&m, &ip_packet(netpkt::TCP, 443, b"not a hello")));
        assert!(!should_drop(&m, &[]));
    }
}
