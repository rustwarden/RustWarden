//! TLS client fingerprints (JA3 and JA4) from a ClientHello. A program's TLS library decides how its hello looks, so
//! two programs using different libraries have different fingerprints, however they name themselves. Pure code: it
//! reads bytes and never panics on short or hostile input.

use sha2::{Digest, Sha256};

/// What the fingerprints are made of.
#[derive(Debug, Default, PartialEq)]
pub struct Hello {
    /// The version in the ClientHello itself (0x0303 for TLS 1.2 and 1.3).
    pub version: u16,
    pub ciphers: Vec<u16>,
    /// Extension types in the order sent.
    pub extensions: Vec<u16>,
    pub curves: Vec<u16>,
    pub point_formats: Vec<u8>,
    pub sig_algs: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub alpn: Option<String>,
    pub has_sni: bool,
}

/// GREASE values (RFC 8701) are random placeholders a client sprinkles in; they are left out of every fingerprint.
fn grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn u16_at(d: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?])))
}

fn u16_list(d: &[u8]) -> Vec<u16> {
    d.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect()
}

/// Reads the ClientHello that starts at `d` (a TCP payload beginning with the TLS record). `None` when it isn't one, or when
/// the packet holds only part of it (a hello spread over two packets is skipped, not guessed at).
pub fn parse(d: &[u8]) -> Option<Hello> {
    if *d.first()? != 0x16 || *d.get(5)? != 1 {
        return None;
    }
    let mut hello = Hello { version: u16::try_from(u16_at(d, 9)?).ok()?, ..Hello::default() };
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + usize::from(*d.get(at)?);
    let suites = u16_at(d, at)?;
    hello.ciphers = u16_list(d.get(at + 2..at + 2 + suites)?);
    at += 2 + suites;
    at += 1 + usize::from(*d.get(at)?);
    let total = u16_at(d, at)?;
    at += 2;
    let end = at + total;
    if end > d.len() {
        return None;
    }
    while at + 4 <= end {
        let (kind, len) = (u16::try_from(u16_at(d, at)?).ok()?, u16_at(d, at + 2)?);
        let body = d.get(at + 4..at + 4 + len)?;
        at += 4 + len;
        hello.extensions.push(kind);
        match kind {
            0 => hello.has_sni = true,
            10 => hello.curves = u16_list(body.get(2..)?),
            11 => hello.point_formats = body.get(1..)?.to_vec(),
            13 => hello.sig_algs = u16_list(body.get(2..)?),
            16 => {
                let n = usize::from(*body.get(2)?);
                hello.alpn = body.get(3..3 + n).and_then(|p| std::str::from_utf8(p).ok()).map(str::to_owned);
            }
            43 => hello.supported_versions = u16_list(body.get(1..)?),
            _ => {}
        }
    }
    Some(hello)
}

fn join<T: std::fmt::Display>(v: impl IntoIterator<Item = T>, sep: &str) -> String {
    v.into_iter().map(|x| x.to_string()).collect::<Vec<_>>().join(sep)
}

/// The JA3 text: version, ciphers, extensions, curves and point formats, comma-separated, each list dash-separated.
pub fn ja3_text(h: &Hello) -> String {
    let keep = |v: &[u16]| join(v.iter().copied().filter(|x| !grease(*x)), "-");
    format!("{},{},{},{},{}", h.version, keep(&h.ciphers), keep(&h.extensions), keep(&h.curves), join(h.point_formats.iter(), "-"))
}

pub fn ja3(h: &Hello) -> String {
    md5_hex(ja3_text(h).as_bytes())
}

fn sha12(text: &str) -> String {
    Sha256::digest(text.as_bytes()).iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// JA4 (FoxIO) for TLS over TCP: `t13d1516h2_<12 hex of the ciphers>_<12 hex of the extensions and signature algorithms>`.
pub fn ja4(h: &Hello) -> String {
    let ciphers: Vec<u16> = h.ciphers.iter().copied().filter(|x| !grease(*x)).collect();
    let exts: Vec<u16> = h.extensions.iter().copied().filter(|x| !grease(*x)).collect();
    let top = h.supported_versions.iter().copied().filter(|x| !grease(*x)).max().unwrap_or(h.version);
    let version = match top {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };
    let alpn = h.alpn.as_deref().filter(|a| !a.is_empty()).map_or("00".to_owned(), |a| format!("{}{}", a.chars().next().unwrap_or('0'), a.chars().last().unwrap_or('0')));
    let a = format!("t{version}{}{:02}{:02}{alpn}", if h.has_sni { 'd' } else { 'i' }, ciphers.len().min(99), exts.len().min(99));
    let hex = |v: &[u16]| join(v.iter().map(|x| format!("{x:04x}")), ",");
    let mut sorted_ciphers = ciphers;
    sorted_ciphers.sort_unstable();
    // SNI (0) and ALPN (16) are counted above but not hashed.
    let mut sorted_exts: Vec<u16> = exts.into_iter().filter(|x| *x != 0 && *x != 16).collect();
    sorted_exts.sort_unstable();
    let sig = hex(&h.sig_algs.iter().copied().filter(|x| !grease(*x)).collect::<Vec<_>>());
    let c = if sorted_exts.is_empty() { "000000000000".to_owned() } else { sha12(&if sig.is_empty() { hex(&sorted_exts) } else { format!("{}_{sig}", hex(&sorted_exts)) }) };
    format!("{a}_{}_{c}", sha12(&hex(&sorted_ciphers)))
}

/// MD5 (RFC 1321), which JA3 is defined with. Not used for anything that needs to resist an attacker.
pub fn md5_hex(data: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64).map(|i| ((f64::from(i + 1)).sin().abs() * 4_294_967_296.0) as u32).collect();
    let mut state = [0x6745_2301u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend(((data.len() as u64) * 8).to_le_bytes());
    for block in msg.as_chunks::<64>().0 {
        let m: Vec<u32> = block.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let next = b.wrapping_add(a.wrapping_add(f).wrapping_add(k[i]).wrapping_add(m[g]).rotate_left(S[i]));
            (a, d, c, b) = (d, c, b, next);
        }
        state = [state[0].wrapping_add(a), state[1].wrapping_add(b), state[2].wrapping_add(c), state[3].wrapping_add(d)];
    }
    state.iter().flat_map(|w| w.to_le_bytes()).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello with the given ciphers and extensions `(type, body)`.
    fn hello(ciphers: &[u16], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([7u8; 32]);
        body.push(0);
        body.extend(((ciphers.len() * 2) as u16).to_be_bytes());
        ciphers.iter().for_each(|c| body.extend(c.to_be_bytes()));
        body.extend([1, 0]);
        let mut e = Vec::new();
        for (kind, b) in exts {
            e.extend(kind.to_be_bytes());
            e.extend((b.len() as u16).to_be_bytes());
            e.extend(b);
        }
        body.extend((e.len() as u16).to_be_bytes());
        body.extend(e);
        let mut hs = vec![1, 0];
        hs.extend((body.len() as u16).to_be_bytes());
        hs.extend(body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    fn sample() -> Vec<u8> {
        let curves = vec![0, 6, 0x0a, 0x0a, 0, 29, 0, 23];
        let sig = vec![0, 4, 4, 3, 8, 4];
        let alpn = vec![0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'];
        let versions = vec![4, 0x2a, 0x2a, 3, 4];
        hello(&[0x1a1a, 0x1301, 0xc02b], &[(0x0a0a, vec![]), (0, vec![0, 6, 0, 0, 3, b'a', b'.', b'b']), (10, curves), (11, vec![1, 0]), (13, sig), (16, alpn), (43, versions)])
    }

    #[test]
    fn md5_matches_the_rfc_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(md5_hex(b"The quick brown fox jumps over the lazy dog"), "9e107d9d372bb6826bd81d3542a419d6");
        assert_eq!(md5_hex(&[b'a'; 200]).len(), 32, "more than one block");
    }

    #[test]
    fn reads_the_parts_of_a_hello_in_order() {
        let h = parse(&sample()).unwrap();
        assert_eq!((h.version, h.has_sni), (0x0303, true));
        assert_eq!(h.ciphers, [0x1a1a, 0x1301, 0xc02b]);
        assert_eq!(h.extensions, [0x0a0a, 0, 10, 11, 13, 16, 43]);
        assert_eq!((h.curves.clone(), h.point_formats.clone(), h.sig_algs.clone()), (vec![0x0a0a, 29, 23], vec![0], vec![0x0403, 0x0804]));
        assert_eq!(h.alpn.as_deref(), Some("h2"));
        assert_eq!(h.supported_versions, [0x2a2a, 0x0304]);
    }

    #[test]
    fn ja3_drops_grease_and_is_the_md5_of_its_text() {
        let h = parse(&sample()).unwrap();
        assert_eq!(ja3_text(&h), "771,4865-49195,0-10-11-13-16-43,29-23,0");
        assert_eq!(ja3(&h), md5_hex(b"771,4865-49195,0-10-11-13-16-43,29-23,0"));
    }

    #[test]
    fn ja4_follows_the_layout() {
        let h = parse(&sample()).unwrap();
        let fp = ja4(&h);
        // TLS 1.3 (from supported_versions), SNI present, 2 ciphers, 6 extensions without GREASE, ALPN h2.
        assert!(fp.starts_with("t13d0206h2_"), "{fp}");
        let parts: Vec<&str> = fp.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[1..].iter().all(|p| p.len() == 12 && p.bytes().all(|b| b.is_ascii_hexdigit())));
        assert_eq!(parts[1], sha12("1301,c02b"));
        assert_eq!(parts[2], sha12("000a,000b,000d,002b_0403,0804"));
        let no_alpn = Hello { alpn: None, has_sni: false, ..parse(&sample()).unwrap() };
        assert!(ja4(&no_alpn).starts_with("t13i0206"));
        assert_ne!(ja4(&no_alpn), fp);
    }

    #[test]
    fn partial_or_foreign_data_is_refused_and_never_panics() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), None);
        let full = sample();
        assert!(parse(&full[..full.len() - 3]).is_none(), "a hello cut short is skipped");
        for cut in 0..full.len() {
            let _ = parse(&full[..cut]);
        }
    }
}
