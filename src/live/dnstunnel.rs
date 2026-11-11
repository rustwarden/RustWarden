//! DNS tunnelling detection: tools that smuggle data through DNS ask for lots of long, random-looking names under
//! one domain they control (`kq3x9v...a1.evil.example`). A name counts as suspicious when the part left of the
//! domain is long, or long enough and random-looking; many of them under one domain in a few minutes are reported.
//! "Mark as normal" on the alert stops reports for that domain; the mark is kept with the baseline items.
//! Names that start with an IP address written as labels (reverse, ASN and blocklist lookups such as RustWarden's own
//! `4.3.2.1.origin.asn.cymru.com`) name an address rather than carry data, so the address is left out before judging.

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

/// `prefix` without a leading IP address written as DNS labels: four decimal labels (`4.3.2.1`) or 32 hex nibbles.
fn without_address(prefix: &str) -> &str {
    let labels: Vec<&str> = prefix.split('.').collect();
    let nibble = |l: &&str| l.len() == 1 && l.as_bytes()[0].is_ascii_hexdigit();
    let octet = |l: &&str| (1..=3).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_digit()) && l.parse::<u8>().is_ok();
    let skip = if labels.len() >= 32 && labels[..32].iter().all(nibble) {
        32
    } else if labels.len() >= 4 && labels[..4].iter().all(octet) {
        4
    } else {
        return prefix;
    };
    let cut: usize = labels[..skip].iter().map(|l| l.len() + 1).sum();
    prefix.get(cut..).unwrap_or("")
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
        if !odd(without_address(&prefix)) {
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

/// Set once the false reports below have been cleared, so the cleanup runs once per database.
const CLEANED: &str = "cleanup.address_lookups";

/// Reports raised before addresses were left out of names (RustWarden flagging its own ASN lookups), each with the
/// address-shaped start of its example name (`214.109.171.150` of `214.109.171.150.origin.asn.cymru.com`), which
/// plugins that read addresses out of alerts took for a real address.
fn false_reports(db: &Db) -> rusqlite::Result<Vec<(i64, Option<String>)>> {
    Ok(db
        .alerts_of_kind(DIM)?
        .into_iter()
        .filter_map(|(id, target)| {
            let example = target.rsplit_once("e.g. ")?.1.trim_end_matches(')');
            let (_, prefix) = split(example)?;
            let rest = without_address(&prefix);
            let misread = prefix.split('.').take(4).collect::<Vec<_>>().join(".").parse::<std::net::Ipv4Addr>().ok().map(|a| a.to_string());
            (rest.len() < prefix.len() && !odd(rest)).then_some((id, misread))
        })
        .collect())
}

/// One-time cleanup on update: removes the false reports (re-linking the tamper-evident alert chain over the gap) and
/// the AbuseIPDB lookups that were made of the misread addresses in them. Runs before plugins start.
pub fn clear_false_reports(db: &Db) {
    if db.kv_get(CLEANED).is_some() {
        return;
    }
    let found = match false_reports(db) {
        Ok(f) => f,
        Err(e) => return crate::applog::line("rustwarden.log", &format!("couldn't look for false DNS tunnelling alerts: {e}")),
    };
    if !found.is_empty() {
        let ids: Vec<i64> = found.iter().map(|(id, _)| *id).collect();
        match db.remove_alerts(&ids) {
            Ok(true) => {
                let misread: Vec<String> = found.into_iter().filter_map(|(_, ip)| ip).collect();
                crate::plugins::wasm::manager::forget_recent("abuseipdb", &misread);
                crate::applog::line("rustwarden.log", &format!("removed {} false DNS tunnelling alert(s) about RustWarden's own address lookups", ids.len()));
            }
            Ok(false) => crate::applog::line("rustwarden.log", "kept the false DNS tunnelling alerts: the alert log already fails its check, so it is left as it is"),
            Err(e) => return crate::applog::line("rustwarden.log", &format!("couldn't remove the false DNS tunnelling alerts: {e}")),
        }
    }
    let _ = db.kv_set(CLEANED, "1");
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
    fn addresses_written_as_names_are_not_data() {
        assert_eq!(without_address("214.109.171.150.origin.asn"), "origin.asn");
        assert_eq!(without_address("54.188.123.199"), "");
        let v6 = "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.origin6.asn";
        assert_eq!(without_address(v6), "origin6.asn");
        assert_eq!(without_address("kq3x9vz.a1"), "kq3x9vz.a1");
        assert_eq!(without_address("300.1.2.3.x"), "300.1.2.3.x", "not an octet");
        // Data after an address is still judged.
        assert!(odd(without_address("1.2.3.4.kq3x9vzp7m2lw8rt4ya6c1d5")));
        let mut t = Tracker::default();
        let reports = (0..30u8).filter_map(|i| t.note(&format!("{i}.{}.{}.150.origin.asn.cymru.com", 100 + i, 200 - i), 1000)).count();
        assert_eq!(reports, 0, "RustWarden's own ASN lookups");
        let reports = (0..30u8).filter_map(|i| t.note(&format!("{i}.4.3.2.in-addr.arpa"), 1000)).count();
        assert_eq!(reports, 0, "reverse lookups");
    }

    #[test]
    fn false_reports_are_removed_once_and_the_chain_still_checks() {
        use super::super::db::NewAlert;
        let db = Db::memory();
        let add = |kind: &str, target: &str| {
            db.insert_alert(&NewAlert { ts: 1, kind: kind.into(), important: true, app: "RustWarden.exe".into(), text: "t".into(), target: target.into(), country: String::new(), unread: true })
                .unwrap()
        };
        let before = add("new_contact", "1.1.1.1 (AU)");
        let own = add(DIM, "cymru.com (20 names in 5 minutes, e.g. 214.109.171.150.origin.asn.cymru.com)");
        remember(&db, "cymru.com", own, 1);
        let real = add(DIM, "evil.example (20 names in 5 minutes, e.g. kq3x9vzp7m2lw8rt4ya6c1d5.evil.example)");
        let after = add("new_contact", "8.8.8.8 (US)");
        assert_eq!(false_reports(&db).unwrap(), vec![(own, Some("214.109.171.150".into()))]);
        clear_false_reports(&db);
        let mut left: Vec<i64> = db.alerts(10).unwrap().iter().map(|a| a.id).collect();
        left.sort();
        assert_eq!(left, vec![before, real, after]);
        let check = db.verify_alerts().unwrap();
        assert_eq!((check.checked, check.first_bad), (3, None));
        assert!(!db.markable_alerts().unwrap().contains(&own));
        assert_eq!(db.kv_get(CLEANED).as_deref(), Some("1"));
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
