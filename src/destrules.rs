//! Destination rules: "this program may reach only *.example.com", "block this program from country XX".
//!
//! Windows Firewall filters by address only, so a rule here is *compiled* into address ranges
//! and enforced as ordinary RustWarden-owned firewall rules (see `live::dest`). This module is the
//! pure part: the rule model, how it is stored, and the range arithmetic. Live and Demo share it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Most ranges in one firewall rule. Windows refuses a rule with too many addresses (it failed at 20 000
/// with "array bounds are invalid"; 15 365 worked), so longer lists are split over several rules.
pub const MAX_RANGES_PER_RULE: usize = 8000;
/// Most characters of address list in one firewall rule, for the same reason.
pub const MAX_CHARS_PER_RULE: usize = 250_000;
/// Most firewall rules one destination rule may need before it is refused.
pub const MAX_RULES_PER_DEST: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// A domain; it matches the name itself and everything below it.
    Domain(String),
    Asn(u32),
    /// Upper-case ISO alpha-2 code.
    Country([u8; 2]),
}

impl Target {
    pub fn kind(&self) -> &'static str {
        match self {
            Target::Domain(_) => "Domain",
            Target::Asn(_) => "ASN",
            Target::Country(_) => "Country",
        }
    }

    /// The target as the user types it.
    pub fn text(&self) -> String {
        match self {
            Target::Domain(d) => d.clone(),
            Target::Asn(n) => format!("AS{n}"),
            Target::Country(c) => String::from_utf8_lossy(c).into_owned(),
        }
    }

    /// Reads what the user typed for the kind `kind` (see [`Target::kind`]).
    pub fn parse(kind: &str, text: &str) -> Result<Target, String> {
        let text = text.trim();
        match kind {
            "Domain" => {
                let d = text.strip_prefix("*.").unwrap_or(text).trim_end_matches('.').to_ascii_lowercase();
                let ok = d.len() <= 253 && d.contains('.') && !d.starts_with(['.', '-']) && d.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.')) && !d.contains("..");
                if ok { Ok(Target::Domain(d)) } else { Err("Enter a domain such as example.com or *.example.com.".into()) }
            }
            "ASN" => {
                let n = text.get(..2).filter(|p| p.eq_ignore_ascii_case("as")).map_or(text, |_| &text[2..]);
                n.trim().parse::<u32>().ok().filter(|n| *n > 0).map(Target::Asn).ok_or_else(|| "Enter an AS number such as AS15169.".into())
            }
            "Country" => crate::countries::parse_name_or_a2(text)
                .filter(|c| crate::countries::by_a2(*c).is_some())
                .map(Target::Country)
                .ok_or_else(|| "Pick a country or enter a two-letter code such as DE.".into()),
            _ => Err("Unknown rule type.".into()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The program can't reach the target.
    Block,
    /// The program can reach only the target (and the local network).
    OnlyAllow,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Block => "Block",
            Mode::OnlyAllow => "Only allow",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestRule {
    /// 0 for a rule not saved yet.
    pub id: u32,
    pub enabled: bool,
    pub mode: Mode,
    pub target: Target,
    /// Program path; empty for any program.
    pub program: String,
}

impl DestRule {
    /// Why this rule can't be saved, if so.
    pub fn problem(&self) -> Option<&'static str> {
        (self.mode == Mode::OnlyAllow && self.program.trim().is_empty()).then_some("\"Only allow\" needs a program; for every program it would cut this PC off from the internet.")
    }

    /// One line for the settings store.
    pub fn encode(&self) -> String {
        let mode = if self.mode == Mode::Block { "block" } else { "only" };
        format!("{}\t{}\t{}\t{}\t{}\t{}", self.id, u8::from(self.enabled), mode, self.target.kind(), self.target.text(), self.program)
    }

    pub fn decode(line: &str) -> Option<DestRule> {
        let mut f = line.splitn(6, '\t');
        let id = f.next()?.parse().ok().filter(|id| *id > 0)?;
        let enabled = f.next()? == "1";
        let mode = match f.next()? {
            "block" => Mode::Block,
            "only" => Mode::OnlyAllow,
            _ => return None,
        };
        let target = Target::parse(f.next()?, f.next()?).ok()?;
        Some(DestRule { id, enabled, mode, target, program: f.next().unwrap_or_default().to_owned() })
    }
}

pub fn encode_all(rules: &[DestRule]) -> String {
    rules.iter().map(DestRule::encode).collect::<Vec<_>>().join("\n")
}

pub fn decode_all(text: &str) -> Vec<DestRule> {
    text.lines().filter_map(DestRule::decode).collect()
}

/// A rule and what is known about it now.
#[derive(Clone, Debug)]
pub struct DestRuleView {
    pub rule: DestRule,
    /// Plain-English state: how many ranges are enforced, or what it is waiting for.
    pub status: String,
    pub problem: bool,
}

/// Whether `name` is `domain` or a name below it.
pub fn domain_matches(domain: &str, name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name == domain || name.strip_suffix(domain).is_some_and(|rest| rest.ends_with('.'))
}

/// Addresses with last-seen times: the new ones are added, and those not seen for `keep_secs` dropped.
/// DNS history is pruned, but a rule must not suddenly forget a server the program used last week.
pub fn merge_seen(old: Vec<(IpAddr, i64)>, new: &[IpAddr], now: i64, keep_secs: i64) -> Vec<(IpAddr, i64)> {
    let mut map: std::collections::BTreeMap<IpAddr, i64> = old.into_iter().collect();
    for ip in new {
        map.insert(*ip, now);
    }
    map.into_iter().filter(|(_, seen)| now - seen <= keep_secs).collect()
}

pub fn seen_to_text(v: &[(IpAddr, i64)]) -> String {
    v.iter().map(|(ip, t)| format!("{ip}\t{t}")).collect::<Vec<_>>().join("\n")
}

pub fn seen_from_text(t: &str) -> Vec<(IpAddr, i64)> {
    t.lines().filter_map(|l| l.split_once('\t')).filter_map(|(ip, t)| Some((ip.parse().ok()?, t.parse().ok()?))).collect()
}

/// A set of address ranges, one list per IP version, kept sorted and merged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeSet {
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
}

const V4_MAX: u128 = u32::MAX as u128;

fn merge(v: &mut Vec<(u128, u128)>) {
    v.sort_unstable();
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(v.len());
    for &(s, e) in v.iter() {
        match out.last_mut() {
            Some(last) if s <= last.1.saturating_add(1) => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    *v = out;
}

/// `a` without `b`; both sorted and merged.
fn subtract(a: &[(u128, u128)], b: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let mut out = Vec::new();
    let mut j = 0;
    for &(mut s, e) in a {
        while j < b.len() && b[j].1 < s {
            j += 1;
        }
        let mut k = j;
        loop {
            if k >= b.len() || b[k].0 > e {
                out.push((s, e));
                break;
            }
            if b[k].0 > s {
                out.push((s, b[k].0 - 1));
            }
            if b[k].1 >= e {
                break;
            }
            s = b[k].1 + 1;
            k += 1;
        }
    }
    out
}

impl RangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Number of ranges after merging.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Adds `ip/prefix` (a whole address for 32 or 128). Call [`RangeSet::tidy`] after the last one.
    pub fn add_net(&mut self, ip: IpAddr, prefix: u8) {
        match ip.to_canonical() {
            IpAddr::V4(a) => {
                let (start, host) = (u128::from(u32::from(a)), 32u32.saturating_sub(u32::from(prefix)));
                let mask = if host >= 32 { V4_MAX } else { (1u128 << host) - 1 };
                self.v4.push((start & !mask & V4_MAX, (start | mask) & V4_MAX));
            }
            IpAddr::V6(a) => {
                let (start, host) = (u128::from(a), 128u32.saturating_sub(u32::from(prefix)));
                let mask = if host >= 128 { u128::MAX } else { (1u128 << host) - 1 };
                self.v6.push((start & !mask, start | mask));
            }
        }
    }

    pub fn add_ip(&mut self, ip: IpAddr) {
        self.add_net(ip, 128);
    }

    /// Sorts and merges what was added.
    pub fn tidy(&mut self) {
        merge(&mut self.v4);
        merge(&mut self.v6);
    }

    #[cfg(test)]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let (list, n) = match ip.to_canonical() {
            IpAddr::V4(a) => (&self.v4, u128::from(u32::from(a))),
            IpAddr::V6(a) => (&self.v6, u128::from(a)),
        };
        list.iter().any(|&(s, e)| s <= n && n <= e)
    }

    /// This set without the addresses in `other`. Both must be tidy.
    pub fn minus(&self, other: &RangeSet) -> RangeSet {
        RangeSet { v4: subtract(&self.v4, &other.v4), v6: subtract(&self.v6, &other.v6) }
    }

    /// Every address that is in neither this set nor `keep_open`. Both must be tidy.
    pub fn complement(&self, keep_open: &RangeSet) -> RangeSet {
        let mut union = self.clone();
        union.v4.extend(&keep_open.v4);
        union.v6.extend(&keep_open.v6);
        union.tidy();
        RangeSet { v4: subtract(&[(0, V4_MAX)], &union.v4), v6: subtract(&[(0, u128::MAX)], &union.v6) }
    }

    /// The ranges as firewall address lists (`a.b.c.d`, `a.b.c.d-e.f.g.h`), each at most
    /// [`MAX_RANGES_PER_RULE`] entries and [`MAX_CHARS_PER_RULE`] characters.
    pub fn chunks(&self) -> Vec<String> {
        let v4 = self.v4.iter().map(|&(s, e)| (Ipv4Addr::from(s as u32).to_string(), Ipv4Addr::from(e as u32).to_string(), s == e));
        let v6 = self.v6.iter().map(|&(s, e)| (Ipv6Addr::from(s).to_string(), Ipv6Addr::from(e).to_string(), s == e));
        let (mut out, mut cur, mut count) = (Vec::new(), String::new(), 0usize);
        for (a, b, single) in v4.chain(v6) {
            let item = if single { a } else { format!("{a}-{b}") };
            if count > 0 && (count >= MAX_RANGES_PER_RULE || cur.len() + item.len() + 1 > MAX_CHARS_PER_RULE) {
                out.push(std::mem::take(&mut cur));
                count = 0;
            }
            if count > 0 {
                cur.push(',');
            }
            cur.push_str(&item);
            count += 1;
        }
        if count > 0 {
            out.push(cur);
        }
        out
    }
}

/// Addresses a destination rule never blocks: this PC, the local network and multicast. A rule can't
/// cut the PC off from its own network or its router, and these can't be placed in a country anyway.
pub fn local_ranges() -> RangeSet {
    let mut s = RangeSet::new();
    for (ip, prefix) in [
        ("0.0.0.0", 8),
        ("10.0.0.0", 8),
        ("100.64.0.0", 10),
        ("127.0.0.0", 8),
        ("169.254.0.0", 16),
        ("172.16.0.0", 12),
        ("192.168.0.0", 16),
        ("224.0.0.0", 4),
        ("255.255.255.255", 32),
        ("::1", 128),
        ("fc00::", 7),
        ("fe80::", 10),
        ("ff00::", 8),
    ] {
        s.add_net(ip.parse().expect("literal address"), prefix);
    }
    s.tidy();
    s
}

/// The addresses a rule must put behind a block: `target` for [`Mode::Block`], everything else for
/// [`Mode::OnlyAllow`]. Anything in `keep_open` is never blocked. `target` must be tidy.
pub fn blocked_set(mode: Mode, target: &RangeSet, keep_open: &RangeSet) -> RangeSet {
    match mode {
        Mode::Block => target.minus(keep_open),
        Mode::OnlyAllow => target.complement(keep_open),
    }
}

/// FNV-1a, so a rule's name changes exactly when its address list does (and stays the same across builds).
pub fn fingerprint(text: &str) -> u32 {
    text.bytes().fold(0x811c_9dc5u32, |h, b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn set(nets: &[(&str, u8)]) -> RangeSet {
        let mut s = RangeSet::new();
        for (a, p) in nets {
            s.add_net(ip(a), *p);
        }
        s.tidy();
        s
    }

    #[test]
    fn domain_targets_parse_and_match() {
        assert_eq!(Target::parse("Domain", " *.Google.com ").unwrap(), Target::Domain("google.com".into()));
        assert!(Target::parse("Domain", "localhost").is_err());
        assert!(Target::parse("Domain", "bad domain.com").is_err());
        assert!(domain_matches("google.com", "google.com"));
        assert!(domain_matches("google.com", "WWW.Google.com."));
        assert!(!domain_matches("google.com", "notgoogle.com"));
        assert!(!domain_matches("google.com", "google.com.evil.net"));
    }

    #[test]
    fn asn_and_country_targets_parse() {
        assert_eq!(Target::parse("ASN", "AS15169").unwrap(), Target::Asn(15169));
        assert_eq!(Target::parse("ASN", "as 13335").unwrap(), Target::Asn(13335));
        assert!(Target::parse("ASN", "AS0").is_err());
        assert!(Target::parse("ASN", "google").is_err());
        assert_eq!(Target::parse("Country", "de").unwrap(), Target::Country(*b"DE"));
        assert!(Target::parse("Country", "ZZZ").is_err());
        assert!(Target::parse("Country", "Q1").is_err());
    }

    #[test]
    fn rules_round_trip_through_text() {
        let rules = vec![
            DestRule { id: 1, enabled: true, mode: Mode::OnlyAllow, target: Target::Domain("google.com".into()), program: r"c:\chrome\chrome.exe".into() },
            DestRule { id: 2, enabled: false, mode: Mode::Block, target: Target::Country(*b"RU"), program: String::new() },
            DestRule { id: 3, enabled: true, mode: Mode::Block, target: Target::Asn(4134), program: r"c:\a b\x.exe".into() },
        ];
        assert_eq!(decode_all(&encode_all(&rules)), rules);
        assert!(DestRule::decode("0\t1\tblock\tCountry\tRU\t").is_none(), "id 0 is not a saved rule");
        assert!(DestRule::decode("garbage").is_none());
    }

    #[test]
    fn only_allow_needs_a_program() {
        let mut r = DestRule { id: 1, enabled: true, mode: Mode::OnlyAllow, target: Target::Country(*b"DE"), program: String::new() };
        assert!(r.problem().is_some());
        r.program = r"c:\x.exe".into();
        assert!(r.problem().is_none());
        r.program.clear();
        r.mode = Mode::Block;
        assert!(r.problem().is_none());
    }

    #[test]
    fn ranges_merge_and_adjacent_networks_join() {
        let s = set(&[("1.0.0.0", 24), ("1.0.1.0", 24), ("1.0.3.0", 24), ("1.0.0.128", 25)]);
        assert_eq!(s.len(), 2);
        assert_eq!(s.chunks(), vec!["1.0.0.0-1.0.1.255,1.0.3.0-1.0.3.255"]);
        assert!(s.contains(ip("1.0.1.77")) && !s.contains(ip("1.0.2.1")));
    }

    #[test]
    fn single_addresses_print_alone_and_mapped_v4_counts_as_v4() {
        let mut s = RangeSet::new();
        s.add_ip(ip("8.8.8.8"));
        s.add_ip(ip("::ffff:8.8.4.4"));
        s.add_ip(ip("2001:db8::1"));
        s.tidy();
        assert_eq!(s.chunks(), vec!["8.8.4.4,8.8.8.8,2001:db8::1"]);
    }

    #[test]
    fn minus_cuts_holes() {
        let a = set(&[("10.0.0.0", 24)]);
        let b = set(&[("10.0.0.64", 26)]);
        assert_eq!(a.minus(&b).chunks(), vec!["10.0.0.0-10.0.0.63,10.0.0.128-10.0.0.255"]);
        assert!(a.minus(&a).is_empty());
        assert_eq!(a.minus(&RangeSet::new()), a);
    }

    #[test]
    fn complement_covers_everything_else() {
        let allowed = set(&[("8.8.8.8", 32)]);
        let keep = local_ranges();
        let blocked = allowed.complement(&keep);
        assert!(!blocked.contains(ip("8.8.8.8")));
        assert!(blocked.contains(ip("8.8.8.9")) && blocked.contains(ip("1.1.1.1")) && blocked.contains(ip("2001:4860::1")));
        assert!(!blocked.contains(ip("192.168.1.1")) && !blocked.contains(ip("127.0.0.1")) && !blocked.contains(ip("fe80::1")) && !blocked.contains(ip("224.0.0.251")));
        assert!(blocked.contains(ip("255.255.255.254")) && blocked.contains(ip("2a00::1")) && !blocked.contains(ip("ffff::1")));
    }

    #[test]
    fn block_mode_never_touches_the_local_network() {
        let target = set(&[("192.168.0.0", 16), ("203.0.113.0", 24)]);
        let blocked = blocked_set(Mode::Block, &target, &local_ranges());
        assert!(blocked.contains(ip("203.0.113.5")) && !blocked.contains(ip("192.168.1.1")));
    }

    #[test]
    fn long_lists_are_split_into_rules_within_the_limits() {
        let mut s = RangeSet::new();
        for i in 0..(MAX_RANGES_PER_RULE as u32 * 2 + 5) {
            s.add_ip(IpAddr::V4(Ipv4Addr::from(i * 2 + 0x0100_0000)));
        }
        s.tidy();
        let chunks = s.chunks();
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.split(',').count() <= MAX_RANGES_PER_RULE && c.len() <= MAX_CHARS_PER_RULE));
        assert_eq!(chunks.iter().map(|c| c.split(',').count()).sum::<usize>(), s.len());
        // Long IPv6 ranges hit the character limit first.
        let mut v6 = RangeSet::new();
        for i in 0..MAX_RANGES_PER_RULE as u128 {
            v6.add_net(IpAddr::V6(Ipv6Addr::from(0x2001_0db8_u128 << 96 | (i << 70))), 60);
        }
        v6.tidy();
        assert!(v6.chunks().iter().all(|c| c.len() <= MAX_CHARS_PER_RULE));
    }

    #[test]
    fn seen_addresses_expire() {
        let old = vec![(ip("1.1.1.1"), 100), (ip("2.2.2.2"), 1000)];
        let now = merge_seen(old, &[ip("3.3.3.3"), ip("2.2.2.2")], 1500, 600);
        assert_eq!(now, vec![(ip("2.2.2.2"), 1500), (ip("3.3.3.3"), 1500)]);
        assert_eq!(seen_from_text(&seen_to_text(&now)), now);
    }

    #[test]
    fn fingerprint_tracks_the_list() {
        assert_eq!(fingerprint("a"), fingerprint("a"));
        assert_ne!(fingerprint("1.1.1.1"), fingerprint("1.1.1.2"));
    }
}
