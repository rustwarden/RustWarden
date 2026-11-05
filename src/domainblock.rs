//! Block by domain (Driver mode): the pure part. A rule names a domain, which covers the name and
//! everything below it ("example.com" blocks "www.example.com" too). `Matcher` answers "is this host
//! blocked?" by looking up each suffix of the name in a set, so a list of tens of thousands stays fast.

use std::collections::HashSet;

/// Most hand-made rules; an imported list is kept apart and has its own, larger, limit.
pub const MAX_RULES: usize = 500;
pub const MAX_LIST: usize = 200_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainRule {
    pub id: u32,
    pub enabled: bool,
    pub pattern: String,
}

/// The lower-case domain a user typed ("*.Example.com", "example.com.", "https://example.com/x" are all fine), or why not.
pub fn normalize(input: &str) -> Result<String, &'static str> {
    let mut s = input.trim().to_ascii_lowercase();
    if let Some(rest) = s.split_once("://").map(|(_, r)| r.to_owned()) {
        s = rest;
    }
    let s = s.split(['/', '?', '#']).next().unwrap_or("").trim_start_matches("*.").trim_matches('.').to_owned();
    if s.is_empty() || s.len() > 253 || !s.contains('.') {
        return Err("Enter a domain such as example.com.");
    }
    if s.split('.').any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-')) || !s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) {
        return Err("That isn't a valid domain name.");
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return Err("Enter a domain name, not an IP address.");
    }
    Ok(s)
}

impl DomainRule {
    pub fn encode(&self) -> String {
        format!("{}\t{}\t{}", self.id, u8::from(self.enabled), self.pattern)
    }

    pub fn decode(line: &str) -> Option<DomainRule> {
        let mut f = line.splitn(3, '\t');
        let id = f.next()?.parse().ok().filter(|id| *id > 0)?;
        let enabled = f.next()? == "1";
        Some(DomainRule { id, enabled, pattern: normalize(f.next()?).ok()? })
    }
}

pub fn encode_all(rules: &[DomainRule]) -> String {
    rules.iter().map(DomainRule::encode).collect::<Vec<_>>().join("\n")
}

pub fn decode_all(text: &str) -> Vec<DomainRule> {
    text.lines().filter_map(DomainRule::decode).collect()
}

/// Domains in a downloaded list: a hosts file ("0.0.0.0 ads.example.com"), or one domain per line.
/// Comments, localhost entries and anything that isn't a domain are skipped.
pub fn parse_list(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            let word = match line.split_whitespace().collect::<Vec<_>>()[..] {
                [domain] => domain,
                [addr, domain, ..] if addr.parse::<std::net::IpAddr>().is_ok() => domain,
                _ => return None,
            };
            normalize(word).ok().filter(|d| d != "localhost.localdomain" && !d.ends_with(".local"))
        })
        .filter(|d| seen.insert(d.clone()))
        .take(MAX_LIST)
        .collect()
}

/// What the Domain blocks card shows.
#[derive(Clone, Debug, Default)]
pub struct DomainView {
    pub rules: Vec<DomainRule>,
    /// Domains in the imported list, and where it came from.
    pub list_count: usize,
    pub list_url: String,
    /// Plain-English state: how many are blocked, or what is wrong.
    pub status: String,
    pub problem: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Matcher {
    set: HashSet<String>,
}

impl Matcher {
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        Self { set: domains.into_iter().collect() }
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether `host` or any parent domain of it is in the set.
    pub fn blocks(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let mut rest = host.as_str();
        loop {
            if self.set.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, parent)) if parent.contains('.') => rest = parent,
                _ => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_tidied_or_refused() {
        assert_eq!(normalize(" *.Example.COM. ").as_deref(), Ok("example.com"));
        assert_eq!(normalize("https://ads.example.com/path?x=1").as_deref(), Ok("ads.example.com"));
        for bad in ["", "localhost", "a..b.com", "-a.com", "bad name.com", "1.2.3.4", "exa$mple.com"] {
            assert!(normalize(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_domain_covers_everything_below_it_but_not_lookalikes() {
        let m = Matcher::new(["example.com".to_owned(), "ads.tracker.net".to_owned()]);
        for blocked in ["example.com", "www.example.com", "A.B.Example.com.", "ads.tracker.net", "x.ads.tracker.net"] {
            assert!(m.blocks(blocked), "{blocked}");
        }
        for allowed in ["notexample.com", "example.com.evil.org", "tracker.net", "net", "com"] {
            assert!(!m.blocks(allowed), "{allowed}");
        }
        assert!(Matcher::default().is_empty() && !Matcher::default().blocks("example.com"));
    }

    #[test]
    fn rules_and_lists_read_back() {
        let rules = vec![DomainRule { id: 1, enabled: true, pattern: "example.com".into() }, DomainRule { id: 2, enabled: false, pattern: "ads.net".into() }];
        assert_eq!(decode_all(&encode_all(&rules)), rules);
        assert!(decode_all("0\t1\texample.com\nx\ty\n3\t1\tnot a domain").is_empty());
        let list = "# header\n127.0.0.1 localhost\n0.0.0.0 ads.example.com\n0.0.0.0 ads.example.com # again\ntracker.net\n\nbad line here too\n::1 ip6-localhost\n";
        assert_eq!(parse_list(list), ["ads.example.com", "tracker.net"]);
    }
}
