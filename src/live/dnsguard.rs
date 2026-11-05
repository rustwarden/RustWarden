//! DNS enforcement (Driver mode, off by default): every program's DNS query on port 53 is sent to the
//! resolver the user chose, whatever server it was aimed at, and the answer is made to look as if the
//! original server sent it. That closes DNS leaks (a program, or a VPN's split setup, quietly using the
//! ISP's resolver) instead of only reporting them.
//!
//! Limits: IPv4 and UDP only; encrypted DNS (DoH/DoT) isn't touched; the resolver must be reachable over the
//! same network connection the query would have used.

use super::store::{Shared, lock};
use crate::netpkt;
use crate::sys::windivert::{self as wd, Address, Handle, Lib};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FILTER: &str = "!loopback and udp and (udp.DstPort == 53 or udp.SrcPort == 53)";
/// How long an answer is expected after its query.
const KEEP: Duration = Duration::from_secs(30);

/// The resolver as typed: a plain IPv4 address that isn't unspecified, loopback or multicast.
pub fn parse_resolver(text: &str) -> Result<Ipv4Addr, &'static str> {
    let ip: Ipv4Addr = text.trim().parse().map_err(|_| "Enter an IPv4 address such as 1.1.1.1.")?;
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
        return Err("That address can't be a DNS resolver.");
    }
    Ok(ip)
}

/// Query seen from the app: (local address, local port) -> the server it asked.
type Pending = HashMap<(Ipv4Addr, u16), (Ipv4Addr, Instant)>;

/// What to do with a packet. Pure, so it can be tested without a driver.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    Pass,
    /// Send this outgoing query to the chosen resolver instead.
    Redirect,
    /// Make this answer look as if it came from the server the app asked.
    Restore(Ipv4Addr),
}

fn decide(p: &netpkt::Parsed, outbound: bool, resolver: Ipv4Addr, pending: &mut Pending, now: Instant) -> Action {
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (p.src, p.dst) else { return Action::Pass };
    if outbound && p.dport == 53 && dst != resolver {
        pending.retain(|_, (_, at)| now.duration_since(*at) < KEEP);
        pending.insert((src, p.sport), (dst, now));
        Action::Redirect
    } else if !outbound && p.sport == 53 && src == resolver {
        match pending.get(&(dst, p.dport)) {
            Some((orig, at)) if now.duration_since(*at) < KEEP => Action::Restore(*orig),
            _ => Action::Pass,
        }
    } else {
        Action::Pass
    }
}

struct Running {
    handle: Arc<Handle>,
    thread: std::thread::JoinHandle<()>,
    resolver: Ipv4Addr,
}

#[derive(Default)]
pub struct Guard {
    running: Mutex<Option<Running>>,
    redirected: Arc<AtomicU64>,
}

impl Guard {
    pub fn stop(&self) {
        if let Some(r) = lock(&self.running).take() {
            r.handle.shutdown();
            let _ = r.thread.join();
        }
    }

    /// Starts, retargets or stops the redirect so it matches `resolver` (None = off).
    pub fn apply(&self, resolver: Option<Ipv4Addr>) -> Result<(), String> {
        let current = lock(&self.running).as_ref().map(|r| (r.resolver, r.thread.is_finished()));
        match (resolver, current) {
            (None, _) => self.stop(),
            (Some(want), Some((have, false))) if want == have => {}
            (Some(want), _) => {
                self.stop();
                if crate::driver::state() != crate::driver::DriverState::Ready {
                    return Err("The driver isn't installed. Install it in Settings.".into());
                }
                let lib = Lib::load(&crate::driver::dir().join("WinDivert.dll"))?;
                let handle = Arc::new(lib.open(FILTER, wd::LAYER_NETWORK, 2, 0)?);
                let (h2, count) = (handle.clone(), self.redirected.clone());
                let thread = std::thread::Builder::new().name("driver-dns".into()).spawn(move || packet_loop(&h2, want, &count)).map_err(|e| e.to_string())?;
                *lock(&self.running) = Some(Running { handle, thread, resolver: want });
            }
        }
        Ok(())
    }
}

fn packet_loop(h: &Handle, resolver: Ipv4Addr, count: &AtomicU64) {
    let (mut buf, mut addr) = (vec![0u8; wd::MAX_PACKET], Address::zeroed());
    let mut pending = Pending::new();
    while let Ok(len) = h.recv(&mut buf, &mut addr) {
        let packet = &mut buf[..len];
        let action = netpkt::parse(packet).map_or(Action::Pass, |p| decide(&p, addr.outbound(), resolver, &mut pending, Instant::now()));
        let changed = match action {
            Action::Pass => false,
            Action::Redirect => netpkt::set_dst_v4(packet, resolver),
            Action::Restore(orig) => netpkt::set_src_v4(packet, orig),
        };
        if changed {
            h.fix_checksums(packet, &mut addr);
            count.fetch_add(1, Ordering::Relaxed);
        }
        let _ = h.send(packet, &addr);
    }
}

/// Keeps the redirect in step with the settings (and the driver) once a minute.
pub fn run(shared: Arc<Shared>, guard: Arc<Guard>) {
    loop {
        refresh(&shared, &guard);
        if !shared.sleep(60.0) {
            break;
        }
    }
    guard.stop();
}

pub fn refresh(shared: &Shared, guard: &Guard) {
    let s = shared.settings();
    let wanted = s.app_mode == crate::settings::AppMode::Driver && s.dns_enforce && shared.elevated;
    let note = if !wanted {
        let _ = guard.apply(None);
        None
    } else {
        parse_resolver(&s.dns_resolver).map_err(str::to_owned).and_then(|ip| guard.apply(Some(ip))).err().map(|e| crate::data::StatusNote::warn(format!("DNS enforcement is not active: {e}")))
    };
    shared.set_note("driver-dns", note);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> netpkt::Parsed {
        netpkt::Parsed { src: IpAddr::from(src), dst: IpAddr::from(dst), proto: netpkt::UDP, sport, dport, payload: 28, tcp_flags: 0 }
    }

    #[test]
    fn queries_to_other_servers_are_redirected_and_their_answers_restored() {
        let (r, isp) = (Ipv4Addr::new(1, 1, 1, 1), [192, 168, 1, 1]);
        let (mut pending, now) = (Pending::new(), Instant::now());
        assert_eq!(decide(&pkt([10, 0, 0, 2], 5000, isp, 53), true, r, &mut pending, now), Action::Redirect);
        assert_eq!(decide(&pkt([1, 1, 1, 1], 53, [10, 0, 0, 2], 5000), false, r, &mut pending, now), Action::Restore(Ipv4Addr::from(isp)));
        assert_eq!(decide(&pkt([1, 1, 1, 1], 53, [10, 0, 0, 2], 6000), false, r, &mut pending, now), Action::Pass, "an answer to a query we didn't redirect");
        assert_eq!(decide(&pkt([10, 0, 0, 2], 5001, [1, 1, 1, 1], 53), true, r, &mut pending, now), Action::Pass, "already going to the resolver");
        assert_eq!(decide(&pkt([1, 1, 1, 1], 53, [10, 0, 0, 2], 5000), false, r, &mut pending, now + KEEP + Duration::from_secs(1)), Action::Pass, "too late");
    }

    #[test]
    fn resolver_addresses_are_checked() {
        assert_eq!(parse_resolver(" 1.1.1.1 "), Ok(Ipv4Addr::new(1, 1, 1, 1)));
        for bad in ["", "dns.google", "0.0.0.0", "127.0.0.1", "224.0.0.1", "::1", "1.1.1"] {
            assert!(parse_resolver(bad).is_err(), "{bad}");
        }
    }
}
