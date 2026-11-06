//! ICMP echo (ping) through the Windows IP helper API, for the ping plugin's `ping` permission.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use windows::Win32::NetworkManagement::IpHelper::{ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho};
use windows::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};

const TIMEOUT_MS: u32 = 2000;
/// Hosts pinged at once; a long list is done in groups so a round never spawns a thread per host.
const AT_ONCE: usize = 16;
/// Most addresses one `round` accepts.
pub const MAX_ADDRS: usize = 64;

/// What `echoes` echoes to one address came to: milliseconds of the answers (all 0 when none came) and the share lost, in percent.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Round {
    pub min: f32,
    pub avg: f32,
    pub max: f32,
    pub loss: f32,
}

/// `count` echoes to each address (at most `MAX_ADDRS` addresses, 1 to 10 echoes), several addresses at once.
pub fn round(addrs: &[String], count: u32) -> Vec<Round> {
    let count = count.clamp(1, 10);
    let mut out = Vec::with_capacity(addrs.len());
    for group in addrs.iter().take(MAX_ADDRS).collect::<Vec<_>>().chunks(AT_ONCE) {
        out.extend(std::thread::scope(|sc| {
            let jobs: Vec<_> = group.iter().map(|a| sc.spawn(move || echoes(a, count))).collect();
            jobs.into_iter().map(|j| j.join().unwrap_or_default()).collect::<Vec<_>>()
        }));
    }
    out
}

/// `count` echoes to the host: min/avg/max of the answers, and the share that got none.
fn echoes(address: &str, count: u32) -> Round {
    let rtts: Vec<f32> = (0..count).filter_map(|_| echo(address)).collect();
    let loss = 100.0 * (count as usize - rtts.len()) as f32 / count as f32;
    if rtts.is_empty() {
        return Round { loss, ..Default::default() };
    }
    Round { min: rtts.iter().copied().fold(f32::MAX, f32::min), avg: rtts.iter().sum::<f32>() / rtts.len() as f32, max: rtts.iter().copied().fold(0.0, f32::max), loss }
}

/// One ICMP echo; the round trip in ms, or `None` when unresolved or unanswered.
// shortcut: whole-millisecond timing (IcmpSendEcho / Icmp6SendEcho2).
pub fn echo(address: &str) -> Option<f32> {
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
    use super::*;

    #[test]
    fn loopback_answers() {
        assert!(echo("127.0.0.1").is_some());
    }

    #[test]
    fn a_round_reports_each_address_and_counts_losses() {
        let r = round(&["127.0.0.1".to_owned(), "not a host name.invalid".to_owned()], 2);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].loss, 0.0);
        assert!(r[0].min <= r[0].avg && r[0].avg <= r[0].max);
        assert_eq!(r[1], Round { loss: 100.0, ..Round::default() });
    }
}
