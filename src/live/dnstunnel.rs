//! DNS tunnelling detection: tools that smuggle data through DNS ask for lots of long, random-looking names under
//! one domain they control (`kq3x9v...a1.evil.example`). A name counts as suspicious when the part left of the
//! domain is long, or long enough and random-looking; many of them under one domain in a few minutes are reported.
//! "Mark as normal" on the alert stops reports for that domain; the mark is kept with the baseline items.

use super::db::{BASE_ALERTED, BASE_NORMAL, BaselineItem, Db};
use std::collections::HashMap;

/// Names looked up under one domain, within `WINDOW` seconds, before it is reported.
const MIN_NAMES: usize = 20;
const WINDOW: i64 = 300;
/// Part left of the domain: this long is odd by itself, ...
const VERY_LONG: usize = 40;
/// ... this long and random-looking (bits of entropy per character) is odd too.
const LONG: usize = 20;
const RANDOM_BITS: f64 = 3.3;
const QUIET_AFTER_REPORT: i64 = 86_400;
const MAX_DOMAINS: usize = 2000;

/// What a report says.
#[derive(Debug, PartialEq)]
pub struct Tunnel {
    pub domain: String,
    pub names: usize,
    pub example: String,
}

#[derive(Default)]
struct Seen {
    /// When each odd name was looked up, and the name.
    odd: Vec<(i64, String)>,
    reported: i64,
}

#[derive(Default)]
pub struct Tracker {
    domains: HashMap<String, Seen>,
}

/// The domain a name belongs to (its last two labels, three under a short country suffix such as `co.uk`) and what is left of it.
pub fn split(name: &str) -> Option<(String, String)> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = name.split('.').collect();
    let keep = if labels.len() > 2 && labels[labels.len() - 1].len() == 2 && labels[labels.len() - 2].len() <= 3 { 3 } else { 2 };
    (labels.len() > keep).then(|| (labels[labels.len() - keep..].join("."), labels[..labels.len() - keep].join(".")))
}

/// Bits of Shannon entropy per character.
fn entropy(s: &str) -> f64 {
    let mut counts = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let n = s.chars().count() as f64;
    counts.values().map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum()
}

/// Whether the part of a name left of its domain looks like carried data.
fn odd(prefix: &str) -> bool {
    let data: String = prefix.chars().filter(|c| *c != '.').collect();
    data.len() >= VERY_LONG || (data.len() >= LONG && entropy(&data) >= RANDOM_BITS)
}

impl Tracker {
    /// Notes one lookup; returns a report the first time a domain has gathered enough odd names.
    pub fn note(&mut self, name: &str, now: i64) -> Option<Tunnel> {
        let (domain, prefix) = split(name)?;
        if !odd(&prefix) {
            return None;
        }
        if self.domains.len() > MAX_DOMAINS {
            self.domains.clear();
        }
        let seen = self.domains.entry(domain.clone()).or_default();
        seen.odd.retain(|(at, _)| now - at <= WINDOW);
        if !seen.odd.iter().any(|(_, n)| *n == prefix) {
            seen.odd.push((now, prefix.clone()));
        }
        if seen.odd.len() < MIN_NAMES || (seen.reported != 0 && now - seen.reported < QUIET_AFTER_REPORT) {
            return None;
        }
        seen.reported = now;
        Some(Tunnel { names: seen.odd.len(), example: format!("{prefix}.{domain}"), domain })
    }
}

/// Baseline items for tunnelling hold a domain for every program (app id 0), under their own dimension.
const ANY_APP: i64 = 0;
const DIM: &str = "dns_tunnel";

/// Whether the user marked tunnelling-like lookups under `domain` as normal.
pub fn marked_normal(db: &Db, domain: &str) -> bool {
    db.baseline_items(ANY_APP, DIM).is_ok_and(|items| items.iter().any(|i| i.val == domain && i.state == BASE_NORMAL))
}

/// Remembers which alert reported `domain`, so "Mark as normal" on it can find the domain.
pub fn remember(db: &Db, domain: &str, alert_id: i64, now: i64) {
    let item = BaselineItem { dim: DIM.into(), val: domain.into(), first_seen: now, last_seen: now, state: BASE_ALERTED, alerted: now, alert_id: Some(alert_id) };
    let _ = db.save_baseline_item(ANY_APP, &item);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_marked_normal_stays_quiet() {
        let db = Db::memory();
        assert!(!marked_normal(&db, "exfil.example"));
        remember(&db, "exfil.example", 9, 1000);
        assert!(db.markable_alerts().unwrap().contains(&9));
        assert!(!marked_normal(&db, "exfil.example"), "reported, not yet marked");
        assert!(db.mark_normal(9, 1100).unwrap());
        assert!(marked_normal(&db, "exfil.example"));
        assert!(!marked_normal(&db, "other.example"));
    }

    #[test]
    fn names_split_into_domain_and_the_rest() {
        assert_eq!(split("a.b.example.com."), Some(("example.com".into(), "a.b".into())));
        assert_eq!(split("x.example.co.uk"), Some(("example.co.uk".into(), "x".into())));
        assert_eq!(split("example.com"), None);
        assert_eq!(split("com"), None);
    }

    #[test]
    fn only_long_or_random_prefixes_are_odd() {
        assert!(!odd("www") && !odd("mail.eu-west-1") && !odd("static-assets-cdn"));
        assert!(odd("kq3x9v2mz7p1w8d4j6h0c5a"));
        assert!(odd(&"a".repeat(41)));
    }

    #[test]
    fn many_random_names_under_one_domain_are_a_tunnel() {
        let mut t = Tracker::default();
        let name = |i: u32| format!("{}.exfil.example", (0..24).map(|j| char::from(b'a' + ((i * 7 + j * 13 + (i ^ j)) % 26) as u8)).collect::<String>() + &i.to_string());
        let hit = (0..30).filter_map(|i| t.note(&name(i), 1000 + i64::from(i))).next().expect("reported");
        assert_eq!(hit.domain, "exfil.example");
        assert!(hit.names >= MIN_NAMES);
        assert!((30..60).all(|i| t.note(&name(i), 1000 + i64::from(i)).is_none()), "once a day is enough");
    }

    #[test]
    fn ordinary_lookups_and_slow_trickles_are_ignored() {
        let mut t = Tracker::default();
        assert!((0..100).all(|i| t.note(&format!("host{i}.example.com"), 1000).is_none()));
        // Odd names spread over hours never gather in one window.
        let mut t = Tracker::default();
        assert!((0..40).all(|i| t.note(&format!("kq3x9v2mz7p1w8d4j6h0c5a{i}.slow.example"), 1000 + i64::from(i) * 400).is_none()));
    }
}
