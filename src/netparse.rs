//! Pure readers for the two things Driver mode learns host names from: the server name in a TLS
//! ClientHello (SNI) and DNS messages. Both take raw payload bytes, never panic on short or hostile
//! input, and return `None` for anything they can't place.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn u16_at(d: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?])))
}

/// A plausible host name: letters, digits, dots, hyphens, underscores; not an IP literal.
fn host_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 253 && name.contains('.') && name.parse::<IpAddr>().is_err() && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// The server name in a TLS ClientHello that starts at `d` (the TCP payload of the first data packet).
pub fn sni(d: &[u8]) -> Option<String> {
    // Record header: handshake (0x16), version, length. Then handshake type 1 (ClientHello), 3-byte length.
    if *d.first()? != 0x16 || *d.get(5)? != 1 {
        return None;
    }
    // Skip: record header 5, handshake header 4, client version 2, random 32.
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + usize::from(*d.get(at)?); // session id
    at += 2 + u16_at(d, at)?; // cipher suites
    at += 1 + usize::from(*d.get(at)?); // compression methods
    let end = at + 2 + u16_at(d, at)?;
    at += 2;
    while at + 4 <= end.min(d.len()) {
        let (kind, len) = (u16_at(d, at)?, u16_at(d, at + 2)?);
        at += 4;
        if kind == 0 {
            // server_name_list: list length 2, then entries of type 1 (0 = host name), length 2, name.
            if *d.get(at + 2)? != 0 {
                return None;
            }
            let n = u16_at(d, at + 3)?;
            let name = std::str::from_utf8(d.get(at + 5..at + 5 + n)?).ok()?.to_ascii_lowercase();
            return host_ok(&name).then_some(name);
        }
        at += len;
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsMessage {
    pub response: bool,
    pub rcode: u8,
    /// The first question: name and record type.
    pub question: (String, u16),
    /// Addresses in A and AAAA answers.
    pub ips: Vec<IpAddr>,
}

/// Reads a (possibly compressed) name at `at`; returns it and the offset after it in the record.
fn name_at(d: &[u8], mut at: usize) -> Option<(String, usize)> {
    let (mut out, mut after, mut hops) = (String::new(), None, 0);
    loop {
        let len = usize::from(*d.get(at)?);
        if len == 0 {
            return Some((out, after.unwrap_or(at + 1)));
        }
        if len & 0xc0 == 0xc0 {
            after.get_or_insert(at + 2);
            at = ((len & 0x3f) << 8) | usize::from(*d.get(at + 1)?);
            hops += 1;
            if hops > 16 {
                return None;
            }
            continue;
        }
        if len > 63 {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(std::str::from_utf8(d.get(at + 1..at + 1 + len)?).ok()?);
        at += 1 + len;
        if out.len() > 253 {
            return None;
        }
    }
}

/// A DNS message over UDP.
pub fn dns(d: &[u8]) -> Option<DnsMessage> {
    if d.len() < 12 {
        return None;
    }
    let flags = u16_at(d, 2)?;
    let (qd, an) = (u16_at(d, 4)?, u16_at(d, 6)?);
    if qd < 1 {
        return None;
    }
    let (name, mut at) = name_at(d, 12)?;
    let qtype = u16::try_from(u16_at(d, at)?).ok()?;
    at += 4;
    let mut ips = Vec::new();
    for _ in 0..an.min(64) {
        let Some((_, next)) = name_at(d, at) else { break };
        let (rtype, rdlen) = (u16_at(d, next)?, u16_at(d, next + 8)?);
        let data = d.get(next + 10..next + 10 + rdlen)?;
        match (rtype, rdlen) {
            (1, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
            (28, 16) => ips.push(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?))),
            _ => {}
        }
        at = next + 10 + rdlen;
    }
    Some(DnsMessage { response: flags & 0x8000 != 0, rcode: (flags & 15) as u8, question: (name.to_ascii_lowercase(), qtype), ips })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(host: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend([0, 0]); // server_name
        let name = host.as_bytes();
        ext.extend(((name.len() + 5) as u16).to_be_bytes());
        ext.extend(((name.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend((name.len() as u16).to_be_bytes());
        ext.extend(name);
        let mut hello = vec![3, 3];
        hello.extend([7u8; 32]);
        hello.push(0); // no session id
        hello.extend([0, 2, 0x13, 0x01]);
        hello.extend([1, 0]);
        hello.extend((ext.len() as u16).to_be_bytes());
        hello.extend(ext);
        let mut hs = vec![1, 0];
        hs.extend((hello.len() as u16).to_be_bytes());
        hs.extend(hello);
        let mut rec = vec![0x16, 3, 1];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    #[test]
    fn finds_the_server_name_and_refuses_junk() {
        assert_eq!(sni(&client_hello("WWW.Example.com")).as_deref(), Some("www.example.com"));
        assert_eq!(sni(&client_hello("1.2.3.4")), None, "an IP literal isn't a name");
        assert_eq!(sni(&client_hello("bad name.com")), None);
        assert_eq!(sni(b"GET / HTTP/1.1\r\n"), None);
        let hello = client_hello("example.org");
        for cut in 0..hello.len() {
            let _ = sni(&hello[..cut]); // never panics on truncation
        }
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend(label.as_bytes());
        }
        m.push(0);
        m.extend(qtype.to_be_bytes());
        m.extend([0, 1]);
        m
    }

    #[test]
    fn reads_queries_and_answers_with_compressed_names() {
        let q = query("Example.com", 1);
        let parsed = dns(&q).unwrap();
        assert_eq!((parsed.response, parsed.question.clone(), parsed.ips.len()), (false, ("example.com".into(), 1), 0));
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 2;
        // Answer 1: A record, name is a pointer to offset 12.
        r.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        // Answer 2: AAAA.
        r.extend([0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        r.extend(Ipv6Addr::LOCALHOST.octets());
        let parsed = dns(&r).unwrap();
        assert!(parsed.response);
        assert_eq!(parsed.rcode, 0);
        assert_eq!(parsed.ips, [IpAddr::from([93, 184, 216, 34]), IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        for cut in 0..r.len() {
            let _ = dns(&r[..cut]);
        }
    }

    #[test]
    fn a_name_pointer_loop_is_refused() {
        let mut m = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0xc0, 0x0c, 0, 1, 0, 1]);
        assert_eq!(dns(&m), None);
    }
}
