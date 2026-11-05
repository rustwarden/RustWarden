//! Pure packet helpers for the driver engine: reading the addresses and ports out of a raw IP packet, and
//! the pacing maths that holds a program to a rate. Nothing here talks to Windows, so it is all unit-tested.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

/// What the engine needs from a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parsed {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    /// Offset of the transport payload (after the TCP/UDP header).
    pub payload: usize,
    pub tcp_flags: u8,
}

/// One connection as the local program sees it. The same for both directions of its packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    pub local: IpAddr,
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
}

impl Parsed {
    /// The connection this packet belongs to; `outbound` says whether it is leaving this PC.
    pub fn flow(&self, outbound: bool) -> FlowKey {
        if outbound {
            FlowKey { proto: self.proto, local: self.src, lport: self.sport, remote: self.dst, rport: self.dport }
        } else {
            FlowKey { proto: self.proto, local: self.dst, lport: self.dport, remote: self.src, rport: self.sport }
        }
    }
}

/// Reads an IPv4 or IPv6 packet whose next header is TCP or UDP. Anything else (other protocols, extension
/// headers, fragments, truncated packets) is `None` and is left alone by the engine.
pub fn parse(p: &[u8]) -> Option<Parsed> {
    let (src, dst, proto, l4): (IpAddr, IpAddr, u8, usize) = match p.first()? >> 4 {
        4 => {
            let ihl = usize::from(p[0] & 15) * 4;
            if ihl < 20 || p.len() < ihl {
                return None;
            }
            // A non-first fragment has no transport header.
            if u16::from_be_bytes([p[6], p[7]]) & 0x1fff != 0 {
                return None;
            }
            (IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15])), IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19])), p[9], ihl)
        }
        6 => {
            if p.len() < 40 {
                return None;
            }
            let addr = |at: usize| Ipv6Addr::from(<[u8; 16]>::try_from(&p[at..at + 16]).unwrap_or_default());
            (IpAddr::V6(addr(8)), IpAddr::V6(addr(24)), p[6], 40)
        }
        _ => return None,
    };
    let t = p.get(l4..)?;
    match proto {
        TCP if t.len() >= 20 => {
            let off = usize::from(t[12] >> 4) * 4;
            (off >= 20 && t.len() >= off).then(|| Parsed { src, dst, proto, sport: u16::from_be_bytes([t[0], t[1]]), dport: u16::from_be_bytes([t[2], t[3]]), payload: l4 + off, tcp_flags: t[13] })
        }
        UDP if t.len() >= 8 => Some(Parsed { src, dst, proto, sport: u16::from_be_bytes([t[0], t[1]]), dport: u16::from_be_bytes([t[2], t[3]]), payload: l4 + 8, tcp_flags: 0 }),
        _ => None,
    }
}

/// Points an IPv4 packet at another destination (the caller fixes the checksums). False for anything else.
pub fn set_dst_v4(p: &mut [u8], ip: Ipv4Addr) -> bool {
    set_v4(p, 16, ip)
}

/// Gives an IPv4 packet another source address.
pub fn set_src_v4(p: &mut [u8], ip: Ipv4Addr) -> bool {
    set_v4(p, 12, ip)
}

fn set_v4(p: &mut [u8], at: usize, ip: Ipv4Addr) -> bool {
    if p.first().is_none_or(|b| b >> 4 != 4) {
        return false;
    }
    match p.get_mut(at..at + 4) {
        Some(slot) => {
            slot.copy_from_slice(&ip.octets());
            true
        }
        None => false,
    }
}

/// Holds a stream to a rate by working out when each packet may leave. A packet that would wait longer
/// than `max_delay` is dropped instead, which tells TCP to slow down (the queue never grows without bound).
#[derive(Clone, Debug)]
pub struct Shaper {
    kbps: u32,
    next_free_ns: u64,
    max_delay_ns: u64,
}

impl Shaper {
    pub fn new(kbps: u32, max_delay_ms: u64) -> Self {
        Self { kbps: kbps.max(1), next_free_ns: 0, max_delay_ns: max_delay_ms * 1_000_000 }
    }

    pub fn set_rate(&mut self, kbps: u32) {
        self.kbps = kbps.max(1);
    }

    #[cfg(test)]
    pub fn rate(&self) -> u32 {
        self.kbps
    }

    /// When a packet of `len` bytes seen at `now_ns` may be sent (never before `now_ns`), or `None` to drop it.
    pub fn admit(&mut self, now_ns: u64, len: usize) -> Option<u64> {
        let start = self.next_free_ns.max(now_ns);
        if start - now_ns > self.max_delay_ns {
            return None;
        }
        // bits / (kbps * 1000) seconds, in nanoseconds: bytes * 8 * 1e9 / (kbps * 1e3) = bytes * 8e6 / kbps
        self.next_free_ns = start + (len as u64 * 8_000_000) / u64::from(self.kbps);
        Some(start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, TCP, 0, 0];
        p.extend(src);
        p.extend(dst);
        p.extend(sport.to_be_bytes());
        p.extend(dport.to_be_bytes());
        p.extend([0; 8]);
        p.extend([0x50, 0x18, 0, 0, 0, 0, 0, 0]);
        p.extend(payload);
        p
    }

    #[test]
    fn reads_ipv4_tcp_and_both_directions_share_one_flow() {
        let out = ipv4_tcp([10, 0, 0, 2], [93, 184, 216, 34], 51000, 443, b"hello");
        let back = ipv4_tcp([93, 184, 216, 34], [10, 0, 0, 2], 443, 51000, b"");
        let (a, b) = (parse(&out).unwrap(), parse(&back).unwrap());
        assert_eq!((a.sport, a.dport, a.proto, a.payload, a.tcp_flags), (51000, 443, TCP, 40, 0x18));
        assert_eq!(&out[a.payload..], b"hello");
        assert_eq!(a.flow(true), b.flow(false));
    }

    #[test]
    fn reads_ipv6_udp_and_refuses_what_it_cannot_place() {
        let mut p = vec![0x60, 0, 0, 0, 0, 8, UDP, 64];
        p.extend(Ipv6Addr::LOCALHOST.octets());
        p.extend(Ipv6Addr::LOCALHOST.octets());
        p.extend([0x00, 0x35, 0xd0, 0x00, 0, 8, 0, 0]);
        let parsed = parse(&p).unwrap();
        assert_eq!((parsed.sport, parsed.dport, parsed.payload), (53, 0xd000, 48));
        assert_eq!(parse(&p[..30]), None, "truncated");
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[0x45; 10]), None);
        let mut icmp = ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, b"");
        icmp[9] = 1;
        assert_eq!(parse(&icmp), None, "not TCP or UDP");
        let mut fragment = ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, b"");
        fragment[7] = 8;
        assert_eq!(parse(&fragment), None, "later fragments carry no ports");
    }

    #[test]
    fn addresses_can_be_swapped_in_ipv4_only() {
        let mut p = ipv4_tcp([10, 0, 0, 2], [8, 8, 8, 8], 5000, 53, b"");
        assert!(set_dst_v4(&mut p, Ipv4Addr::new(1, 1, 1, 1)) && set_src_v4(&mut p, Ipv4Addr::new(10, 0, 0, 9)));
        let parsed = parse(&p).unwrap();
        assert_eq!((parsed.src, parsed.dst), (IpAddr::from([10, 0, 0, 9]), IpAddr::from([1, 1, 1, 1])));
        assert!(!set_dst_v4(&mut [0x60; 40], Ipv4Addr::LOCALHOST) && !set_dst_v4(&mut [0x45; 5], Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn shaper_paces_to_the_rate_then_drops_what_would_wait_too_long() {
        // 1000 kbps = 125 000 bytes/s, so 1250 bytes take 10 ms.
        let mut s = Shaper::new(1000, 25);
        assert_eq!(s.admit(0, 1250), Some(0));
        assert_eq!(s.admit(0, 1250), Some(10_000_000));
        assert_eq!(s.admit(0, 1250), Some(20_000_000));
        assert_eq!(s.admit(0, 1250), None, "30 ms wait is over the 25 ms allowance");
        // After an idle gap there is no saved-up credit: the next packet goes at once and the pacing restarts.
        assert_eq!(s.admit(1_000_000_000, 1250), Some(1_000_000_000));
        assert_eq!(s.admit(1_000_000_000, 1250), Some(1_010_000_000));
        assert_eq!(s.rate(), 1000);
    }
}
