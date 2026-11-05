//! Pings every host each round and stores the result.

use super::Host;
use crate::live::store::Shared;
use crate::plugins::core::latency::Sample;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use windows::Win32::NetworkManagement::IpHelper::{ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho};
use windows::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};

/// Set by the Refresh button: ping again straight away.
pub static SYNC_NOW: AtomicBool = AtomicBool::new(false);
pub static REFRESHING: AtomicBool = AtomicBool::new(false);
/// Unix time of the last finished round (0 = none yet).
pub static LAST_OK: AtomicI64 = AtomicI64::new(0);

const EVERY_SECS: i64 = 30;
const PINGS: u32 = 3;
const TIMEOUT_MS: u32 = 2000;
const KEEP_SECS: i64 = 30 * 86_400;
/// Hosts pinged at once; a long list is done in groups so a round never spawns a thread per host.
const AT_ONCE: usize = 16;

pub fn run(shared: Arc<Shared>) {
    let mut next_at = 0;
    while shared.sleep(0.5) {
        let s = shared.settings();
        let hosts = &s.ping.hosts;
        let now = crate::clock::now_unix();
        if !s.ping.show_tab || hosts.is_empty() || (now < next_at && !SYNC_NOW.swap(false, Ordering::Relaxed)) {
            continue;
        }
        next_at = now + EVERY_SECS;
        let Ok(db) = shared.open_db() else { continue };
        REFRESHING.store(true, Ordering::Relaxed);
        shared.repaint();
        let mut results: Vec<(u32, Sample)> = Vec::new();
        for group in hosts.chunks(AT_ONCE) {
            results.extend(std::thread::scope(|sc| {
                let jobs: Vec<_> = group.iter().map(|h| sc.spawn(move || (h.id, round(h, now)))).collect();
                jobs.into_iter().filter_map(|j| j.join().ok()).collect::<Vec<_>>()
            }));
        }
        let mut failed = false;
        for (id, sample) in results {
            failed |= db.ping_put(id, &sample).is_err();
        }
        shared.set_note("ping", failed.then(|| crate::data::StatusNote::warn("Ping results couldn't be stored.")));
        let _ = db.ping_prune(now - KEEP_SECS);
        LAST_OK.store(crate::clock::now_unix(), Ordering::Relaxed);
        REFRESHING.store(false, Ordering::Relaxed);
        shared.repaint();
    }
}

/// `PINGS` echoes to the host: min/avg/max of the answers, and the share that got none.
fn round(h: &Host, ts: i64) -> Sample {
    let rtts: Vec<f32> = (0..PINGS).filter_map(|_| echo(&h.address)).collect();
    let loss = 100.0 * (PINGS as usize - rtts.len()) as f32 / PINGS as f32;
    if rtts.is_empty() {
        return Sample { ts, loss, ..Default::default() };
    }
    Sample { ts, min: rtts.iter().copied().fold(f32::MAX, f32::min), avg: rtts.iter().sum::<f32>() / rtts.len() as f32, max: rtts.iter().copied().fold(0.0, f32::max), loss }
}

/// One ICMP echo; the round trip in ms, or `None` when unresolved or unanswered.
// shortcut: whole-millisecond timing (IcmpSendEcho / Icmp6SendEcho2).
fn echo(address: &str) -> Option<f32> {
    // IPv4 first, as before; an IPv6-only host is pinged over IPv6.
    let addrs: Vec<IpAddr> = (address, 0).to_socket_addrs().ok()?.map(|a| a.ip()).collect();
    let ip = addrs.iter().find(|a| a.is_ipv4()).or(addrs.first())?;
    match ip {
        IpAddr::V4(v4) => ping_v4(*v4),
        IpAddr::V6(v6) => ping_v6(*v6),
    }
}

fn ping_v6(ip: Ipv6Addr) -> Option<f32> {
    let payload = [0u8; 32];
    let sockaddr = |ip: Ipv6Addr| SOCKADDR_IN6 { sin6_family: AF_INET6, sin6_addr: IN6_ADDR { u: IN6_ADDR_0 { Byte: ip.octets() } }, ..Default::default() };
    let (src, dst) = (sockaddr(Ipv6Addr::UNSPECIFIED), sockaddr(ip));
    let mut buf = [0u8; size_of::<ICMPV6_ECHO_REPLY_LH>() + 32 + 8 + 16];
    unsafe {
        let h = Icmp6CreateFile().ok()?;
        let n = Icmp6SendEcho2(h, None, None, None, &src, &dst, payload.as_ptr().cast(), payload.len() as u16, None, buf.as_mut_ptr().cast(), buf.len() as u32, TIMEOUT_MS);
        let _ = IcmpCloseHandle(h);
        let reply = std::ptr::read_unaligned(buf.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>());
        (n > 0 && reply.Status == 0).then_some(reply.RoundTripTime as f32)
    }
}

fn ping_v4(ip: Ipv4Addr) -> Option<f32> {
    let payload = [0u8; 32];
    // Room for the reply, the echoed payload and the 8 bytes ICMP error data.
    let mut buf = [0u8; size_of::<ICMP_ECHO_REPLY>() + 32 + 8 + 16];
    unsafe {
        let h = IcmpCreateFile().ok()?;
        let n = IcmpSendEcho(h, u32::from_ne_bytes(ip.octets()), payload.as_ptr().cast(), payload.len() as u16, None, buf.as_mut_ptr().cast(), buf.len() as u32, TIMEOUT_MS);
        let _ = IcmpCloseHandle(h);
        let reply = std::ptr::read_unaligned(buf.as_ptr().cast::<ICMP_ECHO_REPLY>());
        (n > 0 && reply.Status == 0).then_some(reply.RoundTripTime as f32)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn loopback_answers() {
        assert!(super::echo("127.0.0.1").is_some());
    }
}
