//! Peer-to-peer guard. Windows can't tell a torrent from a web page, so this looks for the shape of
//! peer-to-peer traffic: a program talking to many internet addresses that no DNS lookup ever named,
//! on ports other than the web's. Such programs are listed in Settings > Privacy > P2P, and the ones
//! the user picks are kept off the network, both ways, whenever no VPN adapter is up.
//!
//! The block is on the whole program (a firewall rule can't single out its peer traffic) and its rules
//! are named `RustWarden p2p <hash> in|out` in RustWarden's group, so "Restore firewall defaults" removes them.

use super::apps::{critical_reason, system_root};
use super::firewall::{FwController, GROUP, P2P_PREFIX};
use super::store::Shared;
use crate::data::StatusNote;
use crate::destrules::fingerprint;
use crate::sys::firewall::{self, RuleSpec};
use crate::sys::netinfo;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

/// Distinct unnamed internet peers inside [`WINDOW_SECS`] before a program counts as peer-to-peer.
pub const MIN_PEERS: usize = 20;
pub const WINDOW_SECS: i64 = 120;

/// Web, DNS and their usual alternates: traffic there is a server, not a peer.
/// Programs that are peer-to-peer by design: one unnamed peer is enough to flag them.
const CLIENTS: [&str; 16] = [
    "qbittorrent.exe",
    "utorrent.exe",
    "bittorrent.exe",
    "transmission-qt.exe",
    "transmission-daemon.exe",
    "deluge.exe",
    "deluged.exe",
    "vuze.exe",
    "azureus.exe",
    "biglybt.exe",
    "tixati.exe",
    "bitcomet.exe",
    "frostwire.exe",
    "tribler.exe",
    "ktorrent.exe",
    "aria2c.exe",
];

/// Browsers are left alone: with encrypted DNS (DoH) their lookups are invisible, so every site they visit looks like an unnamed peer.
const BROWSERS: [&str; 7] = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "msedgewebview2.exe"];

/// How many unnamed peers flag this program, or `None` when it is never judged.
pub fn need_for(key: &str) -> Option<usize> {
    let name = super::apps::file_name(key).to_lowercase();
    if BROWSERS.contains(&name.as_str()) {
        None
    } else if CLIENTS.contains(&name.as_str()) {
        Some(3)
    } else {
        Some(MIN_PEERS)
    }
}

fn is_peer_port(port: u16) -> bool {
    !matches!(port, 53 | 80 | 443 | 853 | 8080 | 8443)
}

#[derive(Default)]
pub struct Detector {
    /// Per program: how many unnamed peers flag it, and each such internet address it exchanged data with, when last.
    peers: HashMap<i64, (usize, HashMap<IpAddr, i64>)>,
}

impl Detector {
    pub fn note(&mut self, app: i64, remote: IpAddr, port: u16, now: i64, need: usize) {
        if is_peer_port(port) {
            let e = self.peers.entry(app).or_default();
            e.0 = need;
            e.1.insert(remote, now);
        }
    }

    /// The programs over the threshold right now.
    pub fn flagged(&mut self, now: i64) -> Vec<i64> {
        self.peers.retain(|_, (_, m)| {
            m.retain(|_, t| now - *t <= WINDOW_SECS);
            !m.is_empty()
        });
        self.peers.iter().filter(|(_, (need, m))| m.len() >= *need).map(|(id, _)| *id).collect()
    }
}

/// Which of the user's picked programs must be blocked now. Never anything the machine needs, and nothing at all
/// while detection is off or a VPN is up.
pub fn blocked_keys(detect: bool, vpn_up: bool, keys: &[String], own_exe: &str, root: &str) -> BTreeSet<String> {
    if !detect || vpn_up {
        return BTreeSet::new();
    }
    keys.iter().map(|k| k.to_lowercase()).filter(|k| k.contains('\\') && critical_reason(k, k, own_exe, root).is_none()).collect()
}

fn rule_name(key: &str, outbound: bool) -> String {
    format!("{P2P_PREFIX}{:08x} {}", fingerprint(key), if outbound { "out" } else { "in" })
}

fn spec(key: &str, outbound: bool) -> RuleSpec {
    RuleSpec {
        name: rule_name(key, outbound),
        description: format!("Created by RustWarden: peer-to-peer guard blocks {key} while no VPN is connected. Use \"Restore firewall defaults\" in RustWarden to remove all such rules."),
        grouping: GROUP.into(),
        program: Some(key.to_owned()),
        outbound,
        block: true,
        enabled: true,
        protocol: None,
        local_ports: None,
        remote_ports: None,
        remote_addrs: None,
        service: None,
    }
}

/// A VPN adapter is connected. `None` when Windows wouldn't say, so a hiccup doesn't flip the blocks.
fn vpn_up() -> Option<bool> {
    netinfo::adapters().ok().map(|ads| ads.iter().any(|a| a.up && a.tunnel && !a.addrs.is_empty()))
}

/// Makes Windows Firewall hold exactly the blocks the settings and VPN state call for.
fn reconcile(shared: &Shared, fw: &FwController, own_exe: &str, applied: &mut bool) {
    let s = shared.settings();
    let Some(vpn) = vpn_up() else { return };
    let want = blocked_keys(s.p2p_detect, vpn, &s.p2p_block, own_exe, &system_root());
    if want.is_empty() && !*applied {
        shared.set_note("p2p", None);
        return;
    }
    if !shared.elevated {
        shared.set_note("p2p", (!want.is_empty()).then(|| StatusNote::warn("Peer-to-peer guard needs administrator rights to block programs. Use \"Restart as administrator\".")));
        return;
    }
    let existing: Vec<String> = match firewall::rules_named(P2P_PREFIX) {
        Ok(list) => list.into_iter().filter(|r| r.grouping == GROUP).map(|r| r.name).collect(),
        Err(e) => {
            shared.set_note("p2p", Some(StatusNote::warn(format!("Peer-to-peer guard: {e}"))));
            return;
        }
    };
    let specs: Vec<RuleSpec> = want.iter().flat_map(|k| [spec(k, true), spec(k, false)]).collect();
    let wanted: BTreeSet<&str> = specs.iter().map(|s| s.name.as_str()).collect();
    let remove: Vec<String> = existing.iter().filter(|n| !wanted.contains(n.as_str())).cloned().collect();
    let add: Vec<RuleSpec> = specs.iter().filter(|s| !existing.contains(&s.name)).cloned().collect();
    *applied = !existing.is_empty() || !specs.is_empty();
    if !remove.is_empty() || !add.is_empty() {
        *applied = true;
        if let Err(e) = fw.apply_p2p(&remove, &add) {
            shared.set_note("p2p", Some(StatusNote::warn(format!("Peer-to-peer guard: {e}"))));
            return;
        }
    }
    let note = (!want.is_empty()).then(|| StatusNote::info(format!("Peer-to-peer guard: {} program(s) blocked until a VPN connects.", want.len())));
    shared.set_note("p2p", note);
    shared.repaint();
}

/// Checks every few seconds, so a VPN that drops cuts the programs off quickly.
pub fn run(shared: Arc<Shared>, fw: Arc<FwController>) {
    let own_exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    // Unknown at start: a first pass cleans up rules a previous run left behind.
    let mut applied = true;
    reconcile(&shared, &fw, &own_exe, &mut applied);
    while shared.sleep(3.0) {
        reconcile(&shared, &fw, &own_exe, &mut applied);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u32) -> IpAddr {
        IpAddr::from(std::net::Ipv4Addr::from(0x0b00_0000 + n))
    }

    #[test]
    fn many_unnamed_peers_flag_a_program_and_web_ports_do_not() {
        let mut d = Detector::default();
        for n in 0..MIN_PEERS as u32 {
            d.note(1, ip(n), 51413, 100, MIN_PEERS);
            d.note(2, ip(n), 443, 100, MIN_PEERS);
        }
        for n in 0..5 {
            d.note(3, ip(n), 6881, 100, MIN_PEERS);
        }
        assert_eq!(d.flagged(100), vec![1]);
    }

    #[test]
    fn known_clients_need_few_peers_and_browsers_are_never_judged() {
        assert_eq!(need_for(r"c:\program files\qbittorrent\qbittorrent.exe"), Some(3));
        assert_eq!(need_for(r"c:\apps\other.exe"), Some(MIN_PEERS));
        assert_eq!(need_for(r"c:\program files\google\chrome\application\chrome.exe"), None);
        let mut d = Detector::default();
        for n in 0..3 {
            d.note(1, ip(n), 6881, 5, 3);
        }
        assert_eq!(d.flagged(5), vec![1]);
    }

    #[test]
    fn peers_age_out_of_the_window() {
        let mut d = Detector::default();
        for n in 0..MIN_PEERS as u32 {
            d.note(1, ip(n), 6881, 0, MIN_PEERS);
        }
        assert_eq!(d.flagged(WINDOW_SECS), vec![1]);
        assert!(d.flagged(WINDOW_SECS + 1).is_empty());
    }

    #[test]
    fn blocks_only_with_detection_on_and_no_vpn() {
        let keys = vec![r"C:\Torrent\client.exe".to_owned(), "system".to_owned(), r"c:\torrent\client.exe".to_owned()];
        let root = r"c:\windows";
        assert!(blocked_keys(false, false, &keys, "", root).is_empty());
        assert!(blocked_keys(true, true, &keys, "", root).is_empty());
        let on = blocked_keys(true, false, &keys, "", root);
        assert_eq!(on.into_iter().collect::<Vec<_>>(), vec![r"c:\torrent\client.exe".to_owned()]);
    }

    #[test]
    fn never_blocks_ourselves_or_windows() {
        let own = r"c:\apps\rustwarden.exe";
        let keys = vec![own.to_owned(), r"c:\windows\system32\svchost.exe".to_owned()];
        assert!(blocked_keys(true, false, &keys, own, r"c:\windows").is_empty());
    }

    #[test]
    fn rules_are_ours_both_ways_and_stable() {
        let (o, i) = (spec(r"c:\a.exe", true), spec(r"c:\a.exe", false));
        assert!(o.name.starts_with(P2P_PREFIX) && o.name.ends_with(" out") && i.name.ends_with(" in"));
        assert!(o.block && o.outbound && !i.outbound && o.remote_addrs.is_none() && o.grouping == GROUP);
        assert_eq!(o.name, spec(r"c:\a.exe", true).name);
        assert_ne!(o.name, spec(r"c:\b.exe", true).name);
        assert!(super::super::firewall::is_ours(&o.grouping, &o.name));
    }
}
