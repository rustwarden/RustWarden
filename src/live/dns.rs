//! Malicious-domain alerts: downloads public domain blocklists and, when a program looks up a
//! listed name (seen through the DNS log), raises an alert. Alert only: a name can't be blocked
//! with a firewall rule, and RustWarden never changes the system DNS settings. Off until the user
//! turns it on, because it downloads. The collectors only call [`check`]; the downloads happen
//! on this thread.

use super::alerts::AlertKind;
use super::db::Db;
use super::store::Shared;
use super::threat::{LOG, fetch, read_cache, save_cache, vet};
use crate::applog;
use crate::data::{DnsEntry, StatusNote};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Most names kept from the lists, so a huge or hostile feed can't use unbounded memory.
const MAX_DOMAINS: usize = 1_000_000;

/// A usable list entry: lowercase, no trailing dot, host-name characters only and at least two labels.
/// Addresses, single-label names and local names are dropped, so a bad list can't flag this machine or the local network.
fn clean(name: &str) -> Option<String> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let ok = n.len() <= 253
        && n.contains('.')
        && !n.starts_with('.')
        && n.parse::<IpAddr>().is_err()
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !n.ends_with(".local")
        && !n.ends_with(".localdomain");
    ok.then_some(n)
}

/// The name on one feed line: hosts-file lines (`0.0.0.0 name`) or one name per line, `#` comments ignored.
fn domain_of(line: &str) -> Option<String> {
    let mut words = line.split('#').next()?.split_whitespace();
    let first = words.next()?;
    clean(if first.parse::<IpAddr>().is_ok() { words.next()? } else { first })
}

fn parse_domains(text: &str) -> HashSet<String> {
    text.lines().filter_map(domain_of).take(MAX_DOMAINS).collect()
}

/// Whether `name` or one of its parent domains is listed (`a.b.evil.com` matches `evil.com`).
pub fn is_listed(list: &HashSet<String>, name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let mut rest = name.as_str();
    loop {
        if list.contains(rest) {
            return true;
        }
        match rest.split_once('.') {
            // Never test a bare top-level label.
            Some((_, parent)) if parent.contains('.') => rest = parent,
            _ => return false,
        }
    }
}

/// The (program, name) pairs in `rows` that are listed and haven't been reported yet this run.
/// shortcut: the reported set is cleared when it passes 10 000 pairs, so a very long run may repeat an alert; keep a dated map if that matters.
fn hits(list: &HashSet<String>, seen: &mut HashSet<(String, String)>, rows: &[DnsEntry]) -> Vec<(String, String)> {
    if list.is_empty() {
        return Vec::new();
    }
    if seen.len() > 10_000 {
        seen.clear();
    }
    rows.iter().filter(|r| is_listed(list, &r.name)).map(|r| (r.app.clone(), r.name.to_ascii_lowercase())).filter(|k| seen.insert(k.clone())).collect()
}

/// Called by the traffic collector with each second's lookups. Takes the shared lock once, as the UI waits on it too.
pub fn check(shared: &Shared, db: &Db, rows: &[DnsEntry]) {
    let found = {
        let mut guard = shared.state();
        let st = &mut *guard;
        hits(&st.dns_domains, &mut st.dns_seen, rows)
    };
    for (app, name) in found {
        shared.alert(db, AlertKind::DnsThreat, &app, "looked up a malicious domain:", &name, "");
    }
}

pub(crate) fn cache_path() -> std::path::PathBuf {
    crate::settings::data_dir().join("dns_threats.txt")
}

/// Every name on the feeds, through the same download rules as the malicious-IP lists, or `None` when no list could be
/// used. A feed that fails keeps the previous names, which is a shortcut: names that good feeds dropped linger until a
/// download with every feed working. shortcut: keep names per feed, so only the failed feed's names are kept.
fn download(feeds: &str, previous: &HashSet<String>) -> Option<HashSet<String>> {
    let feeds = fetch(feeds);
    let total = feeds.len();
    let mut all = HashSet::new();
    let mut failed = 0;
    for (name, body) in feeds {
        match body.and_then(|text| vet(&text, text.lines().filter(|l| domain_of(l).is_some()).count(), MAX_DOMAINS).map(|()| text)) {
            Ok(text) => all.extend(parse_domains(&text)),
            Err(why) => {
                applog::line(LOG, &format!("skipped the list {name}: {why}"));
                failed += 1;
            }
        }
    }
    if failed == total {
        return None;
    }
    if failed > 0 {
        all.extend(previous.iter().cloned());
    }
    Some(all)
}

pub fn run(shared: Arc<Shared>) {
    let mut job: Option<std::thread::JoinHandle<()>> = None;
    let mut last_try = SystemTime::UNIX_EPOCH;
    while !shared.stopping() {
        std::thread::sleep(Duration::from_millis(500));
        let s = shared.settings();
        if !s.dns_block_alerts {
            let mut st = shared.state();
            if !st.dns_domains.is_empty() {
                st.dns_domains.clear();
                st.dns_seen.clear();
            }
            continue;
        }
        let max_age = Duration::from_secs(u64::from(s.dns_block_update_hours) * 3600);
        let age = std::fs::metadata(cache_path()).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
        if shared.state().dns_domains.is_empty() && age.is_some() {
            match read_cache(&cache_path(), |t| !parse_domains(t).is_empty()) {
                Some(text) => shared.state().dns_domains = parse_domains(&text),
                None => {
                    let _ = std::fs::remove_file(cache_path()); // unreadable: fetch afresh
                }
            }
        }
        let stale = age.is_none_or(|a| a > max_age);
        // Retry a failed download hourly, not every half second.
        let retry = last_try.elapsed().is_ok_and(|e| e > Duration::from_secs(3600));
        if stale && retry && job.as_ref().is_none_or(|j| j.is_finished()) {
            last_try = SystemTime::now();
            let (shared, feeds) = (shared.clone(), s.dns_block_feeds.clone());
            job = Some(std::thread::spawn(move || {
                let previous = shared.state().dns_domains.clone();
                let Some(list) = download(&feeds, &previous) else {
                    shared.set_note("dns-threat", Some(StatusNote::warn("Couldn't download the malicious-domain lists; will retry within the hour.")));
                    return;
                };
                shared.set_note("dns-threat", None);
                let mut names: Vec<&str> = list.iter().map(String::as_str).collect();
                names.sort_unstable();
                if let Err(e) = save_cache(&cache_path(), &names.join("\n")) {
                    applog::line(LOG, &format!("couldn't save the malicious-domain cache: {e}"));
                }
                shared.state().dns_domains = list;
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn row(app: &str, name: &str) -> DnsEntry {
        DnsEntry { ts: 0, app: app.into(), name: name.into(), qtype: 1, ips: vec![], status: 0, listed: false }
    }

    #[test]
    fn feeds_accept_hosts_lines_and_plain_names() {
        let text = "# comment\n127.0.0.1 localhost\n0.0.0.0 Evil.Example.\n0.0.0.0 bad.example # trailing\nplain.example\n  \n";
        assert_eq!(parse_domains(text), set(&["evil.example", "bad.example", "plain.example"]));
    }

    #[test]
    fn feeds_drop_addresses_local_and_odd_names() {
        let text = "1.2.3.4\n::1\nlocalhost\nbroadcasthost\nprinter.local\nhost.localdomain\n.leading.example\nbad name.example\nwith/slash.example\nweird$.example\nok-name_1.example\n";
        assert_eq!(parse_domains(text), set(&["ok-name_1.example"]));
        assert!(parse_domains(&format!("{}.example", "a".repeat(260))).is_empty());
    }

    #[test]
    fn parent_domains_match_but_not_siblings_or_suffix_lookalikes() {
        let list = set(&["evil.example"]);
        assert!(is_listed(&list, "evil.example"));
        assert!(is_listed(&list, "A.B.Evil.Example."));
        assert!(!is_listed(&list, "notevil.example"));
        assert!(!is_listed(&list, "example"));
        assert!(!is_listed(&list, "evil.example.org"));
        assert!(!is_listed(&set(&[]), "evil.example"));
    }

    #[test]
    fn each_program_and_name_is_reported_once() {
        let list = set(&["evil.example"]);
        let mut seen = HashSet::new();
        let rows = [row("curl.exe", "evil.example"), row("curl.exe", "EVIL.example"), row("curl.exe", "fine.example"), row("chrome.exe", "x.evil.example")];
        let first = hits(&list, &mut seen, &rows);
        assert_eq!(first, vec![("curl.exe".to_string(), "evil.example".to_string()), ("chrome.exe".to_string(), "x.evil.example".to_string())]);
        assert!(hits(&list, &mut seen, &rows).is_empty());
        assert!(hits(&set(&[]), &mut HashSet::new(), &rows).is_empty());
    }
}
