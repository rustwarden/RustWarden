//! Packet capture files (Driver mode): the classic .pcap format that Wireshark opens, and the driver filter
//! for one connection. Pure and tested; `live::capture` does the capturing.

use std::io::{self, Write};
use std::net::SocketAddr;

/// A capture stops by itself at either limit, so a forgotten one can't fill the disk.
pub const MAX_BYTES: u64 = 50 * 1024 * 1024;
pub const MAX_SECS: i64 = 300;

/// LINKTYPE_RAW: each record is a bare IPv4 or IPv6 packet, which is what the driver hands over.
const LINKTYPE_RAW: u32 = 101;

/// What the Live Connections tab shows while capturing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureStatus {
    pub path: String,
    pub packets: u64,
    pub bytes: u64,
    /// What is being captured, for the banner.
    pub what: String,
}

pub struct Writer<W: Write> {
    out: W,
}

impl<W: Write> Writer<W> {
    pub fn new(mut out: W) -> io::Result<Self> {
        out.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?;
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&0i32.to_le_bytes())?; // timezone offset
        out.write_all(&0u32.to_le_bytes())?; // timestamp accuracy
        out.write_all(&65_535u32.to_le_bytes())?; // snapshot length
        out.write_all(&LINKTYPE_RAW.to_le_bytes())?;
        Ok(Self { out })
    }

    /// Appends one packet seen at `secs` + `micros` since 1970.
    pub fn packet(&mut self, secs: u32, micros: u32, data: &[u8]) -> io::Result<()> {
        let len = data.len() as u32;
        for v in [secs, micros, len, len] {
            self.out.write_all(&v.to_le_bytes())?;
        }
        self.out.write_all(data)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// The driver filter that matches both directions of one TCP connection.
pub fn tcp_filter(local: SocketAddr, remote: SocketAddr) -> String {
    let (family, a, b) = match (local, remote) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => ("ip", "ip.SrcAddr", "ip.DstAddr"),
        _ => ("ipv6", "ipv6.SrcAddr", "ipv6.DstAddr"),
    };
    let (l, r, lp, rp) = (local.ip(), remote.ip(), local.port(), remote.port());
    format!("{family} and tcp and (({a} == {l} and tcp.SrcPort == {lp} and {b} == {r} and tcp.DstPort == {rp}) or ({a} == {r} and tcp.SrcPort == {rp} and {b} == {l} and tcp.DstPort == {lp}))")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_the_pcap_header_and_records() {
        let mut w = Writer::new(Vec::new()).unwrap();
        w.packet(10, 20, &[1, 2, 3]).unwrap();
        let bytes = w.out;
        assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1], "little-endian magic");
        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 101, "raw IP");
        assert_eq!(bytes.len(), 24 + 16 + 3);
        assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 10);
        assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), 3, "captured length");
        assert_eq!(&bytes[40..], &[1, 2, 3]);
    }

    #[test]
    fn the_filter_names_both_directions_of_one_connection() {
        let f = tcp_filter("10.0.0.2:51000".parse().unwrap(), "93.184.216.34:443".parse().unwrap());
        assert!(f.starts_with("ip and tcp and"));
        assert!(f.contains("ip.SrcAddr == 10.0.0.2 and tcp.SrcPort == 51000 and ip.DstAddr == 93.184.216.34 and tcp.DstPort == 443"));
        assert!(f.contains("ip.SrcAddr == 93.184.216.34 and tcp.SrcPort == 443 and ip.DstAddr == 10.0.0.2 and tcp.DstPort == 51000"));
        let v6 = tcp_filter("[::1]:5000".parse().unwrap(), "[2001:db8::1]:443".parse().unwrap());
        assert!(v6.starts_with("ipv6 and tcp") && v6.contains("ipv6.SrcAddr == 2001:db8::1"));
    }
}
