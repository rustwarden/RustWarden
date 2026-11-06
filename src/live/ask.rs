//! Prompt: turns connections that Windows Firewall stopped into prompts.
//!
//! Only active while the firewall mode is Prompt ([`FwSnapshot::ask_active`]); in every
//! other mode the events are discarded. Windows can't hold a connection while the user decides,
//! so the program's first attempt fails and it works once the user allows it and it retries.

use super::apps::{file_name, icon_for};
use super::firewall::FwController;
use super::store::{Shared, country_of};
use crate::data::{ConnectAsk, StatusNote};
use crate::sys::wfp::{self, Blocked};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

/// Addresses nobody should be asked about: a program that only chats on the local link
/// (multicast discovery, broadcast) is asked about when it makes a real connection.
fn is_noise(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_unspecified() || a.is_multicast() || a.is_broadcast() || a.is_loopback(),
        IpAddr::V6(a) => a.is_unspecified() || a.is_multicast() || a.is_loopback(),
    }
}

/// Notes one blocked attempt in its minute; local-link chatter is skipped.
fn count(pending: &mut HashMap<(i64, String), u32>, remote: IpAddr) {
    if !is_noise(remote) {
        *pending.entry((crate::clock::now_unix() / 60 * 60, remote.to_string())).or_default() += 1;
    }
}

/// A TCP/UDP packet dropped as "System" is what the firewall does to the driver engine's own packets when nothing allows them;
/// the engine watches the count and shuts itself off.
fn note_engine_drop(b: &Blocked) {
    if !wfp::is_icmp(b.proto) && (b.app.is_empty() || b.app.eq_ignore_ascii_case("system")) {
        super::engine::note_system_drop();
    }
}

fn lookups_on(shared: &Shared) -> bool {
    shared.settings().net_info != crate::settings::NetInfoSource::Off
}

pub fn run(shared: Arc<Shared>, fw: Arc<FwController>) {
    if !shared.elevated {
        return;
    }
    let (tx, rx) = sync_channel(256);
    let _subscription = match wfp::Subscription::start(tx) {
        Ok(s) => s,
        Err(e) => {
            shared.set_note("ask", Some(StatusNote::warn(format!("Prompt can't see blocked connections: {e}"))));
            return;
        }
    };
    let geo_path = shared.settings().geo_db_path;
    let geo = super::geo::Geo::open(geo_path.as_deref());
    // NT paths already put to the user (or ignored) since Prompt was switched on.
    let mut seen: HashSet<String> = HashSet::new();
    // Every blocked attempt feeds the map's blocked layer, whatever the firewall mode; written in batches.
    let mut db = shared.open_db().ok();
    let mut pending: HashMap<(i64, String), u32> = HashMap::new();
    let mut flushed = Instant::now();
    let mut caught_up = false;
    while !shared.stopping() {
        let event = rx.recv_timeout(Duration::from_millis(500));
        if matches!(event, Err(RecvTimeoutError::Disconnected)) {
            return;
        }
        if let Ok(b) = &event {
            count(&mut pending, b.remote);
            note_engine_drop(b);
        }
        if flushed.elapsed() >= Duration::from_secs(2) {
            flushed = Instant::now();
            if let (Some(db), false) = (db.as_mut(), pending.is_empty())
                && db.add_blocked(&pending).is_ok()
            {
                pending.clear();
            }
        }
        let (active, reset) = {
            let mut st = shared.state();
            (st.fw.ask_active, std::mem::take(&mut st.ask_reset))
        };
        if reset {
            seen.clear();
        }
        if !active {
            seen.clear();
            while let Ok(b) = rx.try_recv() {
                count(&mut pending, b.remote);
                note_engine_drop(&b);
            }
            continue;
        }
        // What was stopped while RustWarden was closed (Settings > Firewall > keep blocking), asked about once, now that the rules are read.
        if !caught_up {
            caught_up = true;
            if let Some(since) = fw_closed_since() {
                match crate::sys::audit::blocked_since(since) {
                    Ok(list) => list.into_iter().for_each(|b| offer(&shared, &fw, &geo, &mut seen, b)),
                    Err(e) => shared.set_note("ask", Some(StatusNote::warn(format!("Couldn't read what was blocked while RustWarden was closed: {e}")))),
                }
            }
        }
        if let Ok(b) = event {
            offer(&shared, &fw, &geo, &mut seen, b);
        }
    }
}

fn fw_closed_since() -> Option<i64> {
    super::firewall::take_closed_since()
}

/// Puts a stopped program to the user, unless it was already asked about or is already decided.
fn offer(shared: &Arc<Shared>, fw: &FwController, geo: &super::geo::Geo, seen: &mut HashSet<String>, Blocked { app, remote, proto, .. }: Blocked) {
    if is_noise(remote) {
        return;
    }
    // Windows sends a ping from the kernel, so the program behind it can't be named: ask once about pings in general.
    if wfp::is_icmp(proto) && wfp::dos_path(&app).is_none() {
        offer_ping(shared, fw, seen, remote);
        return;
    }
    if seen.contains(&app) {
        return;
    }
    let Some(path) = wfp::dos_path(&app) else { return };
    // Only remember an app once it has been put to the user; one that merely looked decided
    // (rule list not yet refreshed after a removal) must be asked about on its next attempt.
    if !fw.needs_prompt(&path) {
        return;
    }
    // Rules deleted in bulk make every program look new at once; a flood of threads and prompts would swamp the UI.
    // Not remembered in `seen`, so a program skipped here is asked about on its next attempt.
    if IN_FLIGHT.load(Ordering::Relaxed) >= MAX_IN_FLIGHT || shared.state().asks.len() >= MAX_OPEN_ASKS {
        return;
    }
    seen.insert(app);
    let country = country_of(&geo.place(remote).code());
    // Reverse DNS, network info and the file hash can take seconds; on this thread they would let
    // the 256-event queue overflow and drop other programs' attempts.
    let shared = shared.clone();
    IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
    std::thread::spawn(move || {
        prompt(&shared, path, remote, country);
        IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);
    });
}

/// The one prompt for pings (ICMP) from any program. Not a real path: `FwController::answer` recognises it.
fn offer_ping(shared: &Arc<Shared>, fw: &FwController, seen: &mut HashSet<String>, remote: IpAddr) {
    if seen.contains(super::firewall::ICMP_PATH) || shared.state().asks.iter().any(|a| a.path == super::firewall::ICMP_PATH) || fw.icmp_allowed() {
        return;
    }
    seen.insert(super::firewall::ICMP_PATH.to_owned());
    let ask = ConnectAsk {
        app: "Ping (ICMP)".into(),
        publisher: "Windows can't say which program sent it, so this allows ping for every program.".into(),
        version: String::new(),
        icon: crate::data::AppIcon::Generic,
        target: remote.to_string(),
        country: None,
        info: String::new(),
        hash: String::new(),
        local: false,
        update: false,
        path: super::firewall::ICMP_PATH.into(),
    };
    let shown = {
        let mut st = shared.state();
        st.asks.push(ask);
        st.popups_ok
    };
    if !shown {
        crate::sys::notify::balloon("Ping blocked", "A ping was blocked. Open RustWarden to allow or block ping.");
    }
    shared.repaint();
}

static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
const MAX_IN_FLIGHT: usize = 4;
const MAX_OPEN_ASKS: usize = 20;

fn prompt(shared: &Shared, path: String, remote: IpAddr, country: Option<crate::data::Country>) {
    let cached = shared.state().hostnames.get(&remote).cloned();
    let v = crate::sys::apps::version_info(&path);
    let app = if v.description.trim().is_empty() { file_name(&path).to_owned() } else { v.description.trim().to_owned() };
    let mut ask = ConnectAsk {
        app,
        publisher: v.company,
        version: v.version,
        icon: icon_for(&path),
        target: cached.clone().unwrap_or_else(|| remote.to_string()),
        country,
        info: String::new(),
        hash: String::new(),
        local: false,
        update: false,
        path,
    };
    // Shown at once; the lookups below take seconds, so they patch the open prompt afterwards (same path = update).
    let shown = {
        let mut st = shared.state();
        st.asks.push(ask.clone());
        st.popups_ok
    };
    if !shown {
        crate::sys::notify::balloon("First Network Connection", &format!("{} wants to connect. Open RustWarden to allow or block it.", ask.app));
    }
    shared.repaint();
    if cached.is_none()
        && let IpAddr::V4(a) = remote
        && lookups_on(shared)
        && let Some(name) = super::scanner::reverse_dns(a)
    {
        ask.target = name;
    }
    ask.info = super::asn::lookup(remote, &shared.settings());
    if !super::vt::key().is_empty() {
        ask.hash = crate::sys::apps::hash_file(&ask.path);
    }
    ask.update = true;
    shared.state().asks.push(ask);
    shared.repaint();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_link_chatter_is_not_asked_about() {
        assert!(is_noise("224.0.0.251".parse().unwrap()));
        assert!(is_noise("255.255.255.255".parse().unwrap()));
        assert!(is_noise("ff02::fb".parse().unwrap()));
        assert!(!is_noise("128.123.1.1".parse().unwrap()));
        assert!(!is_noise("192.168.1.20".parse().unwrap()));
    }
}
