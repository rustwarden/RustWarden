//! Two standing firewall guards, both made of tagged RustWarden rules that "Restore firewall defaults" removes:
//!
//! * **VPN kill switch.** While a VPN is up, everything that is not the local network or the VPN's own server is blocked
//!   on the real network cards, so traffic can only leave through the tunnel. When the VPN drops, the block stays and the
//!   internet is cut until it is back. A VPN such as PIA only creates its adapter when you press Connect, so the switch
//!   arms itself the first time a VPN adapter is seen up (switching it on while disconnected blocks nothing). The VPN
//!   client's own packets to its server must still get out, so the server addresses are learned from the host routes
//!   VPN clients add (and remembered), and a "Let the VPN connect" button opens everything for two minutes to reach a new one.
//!   An optional setting presses that button once, by itself, when the VPN has been down for a few seconds.
//! * **QUIC fallback.** For the programs named in the settings, blocks UDP port 443 (QUIC, HTTP/3), so a browser falls
//!   back to HTTPS over TCP, where the server name is in the open for domain blocks and the host names to read. A plain
//!   per-program firewall rule does this; no per-packet work is needed.
//! * **DNS-over-HTTPS block.** Blocks port 443 and 853 (HTTPS and DNS-over-TLS) to a list of well-known public resolvers, so
//!   a browser's private DNS falls back to the system resolver, where domain blocks and the DNS log can see it.

use super::firewall::{FwController, GROUP, GUARD_PREFIX};
use super::store::Shared;
use crate::data::StatusNote;
use crate::destrules::{RangeSet, fingerprint, local_ranges};
use crate::sys::firewall::{self, RuleSpec};
use crate::sys::netinfo::{self, Adapter};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

pub const KILL_PREFIX: &str = "RustWarden guard vpn kill ";
const DOH_PREFIX: &str = "RustWarden guard doh ";
const QUIC_PREFIX: &str = "RustWarden guard quic ";
const ARMED_KEY: &str = "killswitch_armed";
const ENDPOINTS_KEY: &str = "killswitch_endpoints";
const MAX_ENDPOINTS: usize = 64;
/// How long "Let the VPN connect" opens the network.
pub const RELEASE_SECS: i64 = 120;

static RELEASE_UNTIL: AtomicI64 = AtomicI64::new(0);

/// Opens the network for a short while so the VPN client can reach a server the switch hasn't learned yet.
pub fn release() {
    RELEASE_UNTIL.store(crate::clock::now_unix() + RELEASE_SECS, Ordering::Relaxed);
}

/// Well-known public DNS-over-HTTPS / DNS-over-TLS resolvers (their service addresses, not the web sites that share a name with them).
const DOH_ADDRS: &[&str] = &[
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "1.1.1.1",
    "1.0.0.1",
    "1.1.1.2",
    "1.0.0.2",
    "1.1.1.3",
    "1.0.0.3",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "104.16.248.249",
    "104.16.249.249",
    "9.9.9.9",
    "9.9.9.10",
    "9.9.9.11",
    "149.112.112.112",
    "149.112.112.10",
    "149.112.112.11",
    "2620:fe::fe",
    "2620:fe::9",
    "208.67.222.222",
    "208.67.220.220",
    "208.67.222.123",
    "208.67.220.123",
    "94.140.14.14",
    "94.140.15.15",
    "94.140.14.140",
    "94.140.14.141",
    "45.90.28.0",
    "45.90.30.0",
    "185.228.168.9",
    "185.228.169.9",
    "185.228.168.10",
    "185.228.169.11",
    "194.242.2.2",
    "194.242.2.3",
    "194.242.2.4",
    "194.242.2.5",
    "76.76.2.0",
    "76.76.10.0",
    "2a10:50c0::ad1:ff",
    "2a10:50c0::ad2:ff",
    "9.9.9.12",
];

/// The rules that block the resolvers.
fn doh_specs() -> Vec<RuleSpec> {
    let addrs = DOH_ADDRS;
    [(6, "tcp"), (17, "udp")]
        .into_iter()
        .map(|(proto, name)| RuleSpec {
            name: format!("{DOH_PREFIX}{name}"),
            description: "Created by RustWarden: blocks encrypted DNS (DoH/DoT, ports 443 and 853) to well-known public resolvers. Plain DNS on port 53 is not touched.".into(),
            grouping: GROUP.into(),
            program: None,
            outbound: true,
            block: true,
            enabled: true,
            protocol: Some(proto),
            local_ports: None,
            remote_ports: Some("443,853".into()),
            remote_addrs: Some(addrs.join(",")),
            service: None,
            interfaces: None,
        })
        .collect()
}

/// Full paths of the known programs whose file name is one of `wanted` (names separated by commas, semicolons or lines).
fn quic_paths(wanted: &str, known: &[String]) -> Vec<String> {
    let names: BTreeSet<String> = wanted.split([',', ';', '\n']).map(|n| n.trim().to_ascii_lowercase()).filter(|n| !n.is_empty()).collect();
    let mut paths: Vec<String> = known.iter().filter(|p| names.contains(super::apps::file_name(&p.to_ascii_lowercase()))).cloned().collect();
    paths.sort();
    paths.dedup();
    paths
}

/// One rule per program: outbound UDP 443 blocked.
fn quic_specs(paths: &[String]) -> Vec<RuleSpec> {
    paths
        .iter()
        .map(|path| RuleSpec {
            name: format!("{QUIC_PREFIX}{:08x} {}", fingerprint(&path.to_ascii_lowercase()), super::apps::file_name(path)),
            description: "Created by RustWarden: blocks QUIC (UDP 443) for this program so it falls back to HTTPS over TCP.".into(),
            grouping: GROUP.into(),
            program: Some(path.clone()),
            outbound: true,
            block: true,
            enabled: true,
            protocol: Some(17),
            local_ports: None,
            remote_ports: Some("443".into()),
            remote_addrs: None,
            service: None,
            interfaces: None,
        })
        .collect()
}

/// Blocks everything outside the local network and `keep_open` on the named adapters.
fn kill_specs(physical: &[String], keep_open: &RangeSet) -> Vec<RuleSpec> {
    let blocked = RangeSet::new().complement(keep_open);
    let tag = fingerprint(&physical.join("|"));
    blocked
        .chunks()
        .into_iter()
        .enumerate()
        .map(|(n, chunk)| RuleSpec {
            name: format!("{KILL_PREFIX}{tag:08x} {n} {:08x}", fingerprint(&chunk)),
            description: "Created by RustWarden's VPN kill switch: blocks the internet on the real network cards so traffic can only leave through the VPN.".into(),
            grouping: GROUP.into(),
            program: None,
            outbound: true,
            block: true,
            enabled: true,
            protocol: None,
            local_ports: None,
            remote_ports: None,
            remote_addrs: Some(chunk),
            service: None,
            interfaces: Some(physical.to_vec()),
        })
        .collect()
}

fn is_vpn(a: &Adapter) -> bool {
    a.up && a.tunnel && !a.loopback && !a.addrs.is_empty()
}

/// The network cards the VPN's packets leave through: real ones, not the tunnel.
fn physical(adapters: &[Adapter]) -> Vec<String> {
    let mut names: Vec<String> = adapters.iter().filter(|a| !a.tunnel && !a.loopback && a.mac != [0; 6]).map(|a| a.name.clone()).collect();
    names.sort();
    names.dedup();
    names
}

/// Addresses that stay open besides the local network: the VPN servers.
fn open_set(endpoints: &BTreeSet<IpAddr>) -> RangeSet {
    let mut keep = local_ranges();
    endpoints.iter().for_each(|ip| keep.add_ip(*ip));
    keep.tidy();
    keep
}

/// How long the VPN may be down before "reconnect automatically" opens the network (gives the VPN client its own retry first).
const AUTO_RELEASE_AFTER_SECS: i64 = 15;

/// Tracks one VPN outage, so the automatic release fires once per outage and the block comes back afterwards.
#[derive(Default)]
struct Outage {
    since: Option<i64>,
    released: bool,
}

impl Outage {
    /// True once, when the VPN has been down for `AUTO_RELEASE_AFTER_SECS`.
    fn due(&mut self, vpn_up: bool, now: i64) -> bool {
        if vpn_up {
            *self = Outage::default();
            return false;
        }
        let since = *self.since.get_or_insert(now);
        if !self.released && now - since >= AUTO_RELEASE_AFTER_SECS {
            self.released = true;
            return true;
        }
        false
    }
}

#[derive(Default)]
struct State {
    armed: bool,
    endpoints: BTreeSet<IpAddr>,
    outage: Outage,
}

fn load(shared: &Shared) -> State {
    let Ok(db) = shared.open_db() else { return State::default() };
    State { armed: db.kv_get(ARMED_KEY).as_deref() == Some("1"), endpoints: db.kv_get(ENDPOINTS_KEY).unwrap_or_default().lines().filter_map(|l| l.parse().ok()).collect(), outage: Outage::default() }
}

fn save(shared: &Shared, st: &State) {
    if let Ok(db) = shared.open_db() {
        let _ = db.kv_set(ARMED_KEY, if st.armed { "1" } else { "0" });
        let _ = db.kv_set(ENDPOINTS_KEY, &st.endpoints.iter().map(IpAddr::to_string).collect::<Vec<_>>().join("\n"));
    }
}

/// What the kill switch does now, as (rules wanted, note for the status line).
fn kill_plan(st: &State, adapters: &[Adapter], released: bool) -> (Vec<RuleSpec>, StatusNote) {
    let vpn = adapters.iter().any(is_vpn);
    if !st.armed {
        return (Vec::new(), StatusNote::info("VPN kill switch: waiting for the first VPN connection. It switches itself on once a VPN is up."));
    }
    if released {
        return (Vec::new(), StatusNote::info("VPN kill switch: open for a short time so the VPN can connect."));
    }
    let rules = kill_specs(&physical(adapters), &open_set(&st.endpoints));
    let note = if vpn {
        StatusNote::info("VPN kill switch: on. Traffic can only leave through the VPN.")
    } else {
        StatusNote::warn("VPN kill switch: the VPN is down, so the internet is blocked until it reconnects.")
    };
    (rules, note)
}

/// Learns the VPN servers from the single-address routes the VPN client added via the real network cards.
fn learn_endpoints(st: &mut State, adapters: &[Adapter]) -> bool {
    let Ok(routes) = netinfo::host_routes() else { return false };
    let real: BTreeSet<u32> = adapters.iter().filter(|a| !a.tunnel && !a.loopback).map(|a| a.if_index).collect();
    let local = local_ranges();
    let before = st.endpoints.len();
    for (ip, index) in routes {
        if real.contains(&index) && !local.contains(ip) && st.endpoints.len() < MAX_ENDPOINTS {
            st.endpoints.insert(ip);
        }
    }
    st.endpoints.len() != before
}

fn reconcile(shared: &Shared, fw: &FwController, st: &mut State, applied: &mut bool) {
    let s = shared.settings();
    let Ok(adapters) = netinfo::adapters() else { return };
    let mut wanted: Vec<RuleSpec> = Vec::new();
    if s.block_doh {
        wanted.extend(doh_specs());
    }
    if !s.quic_fallback.trim().is_empty()
        && s.app_mode == crate::settings::AppMode::Driver
        && crate::driver::ready()
        && let Ok(db) = shared.open_db()
    {
        let known: Vec<String> = db.apps().unwrap_or_default().into_iter().map(|a| a.path).filter(|p| !p.is_empty()).collect();
        wanted.extend(quic_specs(&quic_paths(&s.quic_fallback, &known)));
    }
    if s.vpn_kill_switch {
        let mut dirty = false;
        if adapters.iter().any(is_vpn) {
            dirty |= !std::mem::replace(&mut st.armed, true);
            dirty |= learn_endpoints(st, &adapters);
        }
        if dirty {
            save(shared, st);
        }
        let vpn_up = adapters.iter().any(is_vpn);
        if s.vpn_kill_auto_release && st.armed && st.outage.due(vpn_up, crate::clock::now_unix()) {
            release();
        } else if !s.vpn_kill_auto_release || !st.armed {
            st.outage = Outage::default();
        }
        let (rules, note) = kill_plan(st, &adapters, crate::clock::now_unix() < RELEASE_UNTIL.load(Ordering::Relaxed));
        wanted.extend(rules);
        shared.set_note("killswitch", Some(note));
    } else {
        shared.set_note("killswitch", None);
        if st.armed {
            st.armed = false;
            save(shared, st);
        }
    }
    if wanted.is_empty() && !*applied {
        return;
    }
    if !shared.elevated {
        shared.set_note("guard", (!wanted.is_empty()).then(|| StatusNote::warn("The VPN kill switch and DNS-over-HTTPS block need administrator rights. Use \"Restart as administrator\".")));
        return;
    }
    let existing: Vec<String> = match firewall::rules_named(GUARD_PREFIX) {
        Ok(list) => list.into_iter().filter(|r| r.grouping == GROUP).map(|r| r.name).collect(),
        Err(e) => {
            shared.set_note("guard", Some(StatusNote::warn(format!("Firewall guards: {e}"))));
            return;
        }
    };
    let names: BTreeSet<&str> = wanted.iter().map(|w| w.name.as_str()).collect();
    let remove: Vec<String> = existing.iter().filter(|n| !names.contains(n.as_str())).cloned().collect();
    let add: Vec<RuleSpec> = wanted.iter().filter(|w| !existing.contains(&w.name)).cloned().collect();
    *applied = !existing.is_empty() || !wanted.is_empty();
    if !remove.is_empty() || !add.is_empty() {
        *applied = true;
        if let Err(e) = fw.apply_guard(&remove, &add) {
            shared.set_note("guard", Some(StatusNote::warn(format!("Firewall guards: {e}"))));
            return;
        }
    }
    shared.set_note("guard", None);
    shared.repaint();
}

/// Checks every few seconds, so a VPN that drops is cut off at once and a new network card is covered.
pub fn run(shared: Arc<Shared>, fw: Arc<FwController>) {
    let mut st = load(&shared);
    // Unknown at start: a first pass cleans up rules a previous run left behind.
    let mut applied = true;
    reconcile(&shared, &fw, &mut st, &mut applied);
    while shared.sleep(3.0) {
        reconcile(&shared, &fw, &mut st, &mut applied);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(name: &str, tunnel: bool, up: bool, index: u32) -> Adapter {
        Adapter { name: name.into(), if_index: index, mac: if tunnel { [0; 6] } else { [1, 2, 3, 4, 5, 6] }, addrs: vec![("10.0.0.2".parse().unwrap(), 24)], up, tunnel, ..Adapter::default() }
    }

    #[test]
    fn the_doh_block_names_only_encrypted_dns_ports_and_real_addresses() {
        let specs = doh_specs();
        assert_eq!(specs.len(), 2);
        for s in &specs {
            assert!(s.block && s.outbound && s.name.starts_with(GUARD_PREFIX) && s.remote_ports.as_deref() == Some("443,853"));
            assert!(s.remote_addrs.as_deref().unwrap().split(',').all(|a| a.parse::<IpAddr>().is_ok()));
        }
        assert_eq!(specs.iter().map(|s| s.protocol).collect::<Vec<_>>(), [Some(6), Some(17)]);
    }

    #[test]
    fn it_arms_only_after_a_vpn_was_seen_and_then_blocks_even_when_it_drops() {
        let wifi = adapter("Wi-Fi", false, true, 5);
        let vpn = adapter("PIA", true, true, 9);
        let mut st = State::default();
        let (rules, _) = kill_plan(&st, std::slice::from_ref(&wifi), false);
        assert!(rules.is_empty(), "never connected: nothing is blocked");
        st.armed = true;
        let (rules, note) = kill_plan(&st, &[wifi.clone(), vpn.clone()], false);
        assert!(!rules.is_empty() && rules.iter().all(|r| r.interfaces.as_deref() == Some(&["Wi-Fi".to_owned()][..])), "only the real card is blocked, not the tunnel");
        assert_eq!(note.level, crate::data::NoteLevel::Info);
        let (rules_down, note) = kill_plan(&st, std::slice::from_ref(&wifi), false);
        assert_eq!(rules.len(), rules_down.len(), "the block stays when the VPN goes");
        assert_eq!(note.level, crate::data::NoteLevel::Warn);
        let (open, _) = kill_plan(&st, &[wifi], true);
        assert!(open.is_empty(), "'Let the VPN connect' opens it");
    }

    #[test]
    fn a_dropped_vpn_opens_the_network_once_after_the_grace_period() {
        let mut o = Outage::default();
        assert!(!o.due(true, 100));
        assert!(!o.due(false, 200), "just dropped");
        assert!(!o.due(false, 200 + AUTO_RELEASE_AFTER_SECS - 1));
        assert!(o.due(false, 200 + AUTO_RELEASE_AFTER_SECS));
        assert!(!o.due(false, 200 + 500), "once per outage, so the block comes back");
        assert!(!o.due(true, 800));
        assert!(!o.due(false, 900) && o.due(false, 900 + AUTO_RELEASE_AFTER_SECS), "a new outage gets a new release");
    }

    #[test]
    fn quic_is_blocked_per_program_by_file_name() {
        let known = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe".to_owned(),
            r"C:\Apps\Other\chrome.exe".to_owned(),
            r"C:\Windows
otepad.exe"
                .to_owned(),
        ];
        let paths = quic_paths(" Chrome.exe ; msedge.exe\n", &known);
        assert_eq!(paths.len(), 2, "every copy of chrome.exe, not notepad");
        let specs = quic_specs(&paths);
        assert!(specs.iter().all(|s| s.block && s.outbound && s.protocol == Some(17) && s.remote_ports.as_deref() == Some("443") && s.name.starts_with(GUARD_PREFIX)));
        assert_ne!(specs[0].name, specs[1].name, "two copies get two rules");
        assert!(quic_paths("", &known).is_empty());
    }

    #[test]
    fn the_local_network_and_vpn_servers_stay_open() {
        let blocked = RangeSet::new().complement(&open_set(&BTreeSet::from(["203.0.113.9".parse().unwrap()])));
        for open in ["192.168.1.1", "10.0.0.5", "127.0.0.1", "169.254.1.1", "203.0.113.9"] {
            assert!(!blocked.contains(open.parse().unwrap()), "{open}");
        }
        for shut in ["8.8.8.8", "203.0.113.10", "2001:db8::1"] {
            assert!(blocked.contains(shut.parse().unwrap()), "{shut}");
        }
    }

    #[test]
    fn rule_names_change_with_the_adapters_and_the_addresses() {
        let keep = open_set(&BTreeSet::new());
        let a = kill_specs(&["Wi-Fi".into()], &keep);
        let b = kill_specs(&["Ethernet".into()], &keep);
        assert!(a.iter().all(|r| r.name.starts_with(KILL_PREFIX)));
        assert!(a.iter().zip(&b).all(|(x, y)| x.name != y.name));
    }
}
