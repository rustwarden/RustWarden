//! Malicious-IP protection: downloads public blocklists, and when a program reaches a listed
//! address blocks it in Windows Firewall (if auto-block is on) and raises a banner that stays
//! until the user deals with it. The traffic collectors only call [`hit`]; everything slow
//! happens on this thread.

use super::alerts::AlertKind;
use super::firewall::FwController;
use super::net::{Locality, classify};
use super::store::Shared;
use crate::applog;
use crate::data::{StatusNote, Threat, ThreatAct};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Settings keys: whitelisted addresses (one per line) and "address<TAB>program · signature" lines.
const ALLOW_KEY: &str = "threat_allow";
const META_KEY: &str = "threat_meta";
/// Every list download and every list it refused, with why. Shared with the domain lists.
pub(super) const LOG: &str = "lists.log";
/// Most addresses kept from the lists; a longer list is refused rather than cut short.
const MAX_IPS: usize = 200_000;

/// The address on one feed line: the first word, `#`/`;` comments ignored.
fn ip_of(line: &str) -> Option<IpAddr> {
    line.split(['#', ';']).next()?.split_whitespace().next()?.parse().ok()
}

/// Addresses in a blocklist file. Only public addresses are kept, so a bad list can never cut off the local network.
fn parse_feed(text: &str) -> HashSet<IpAddr> {
    text.lines().filter_map(ip_of).filter(|ip| classify(*ip) == Locality::Wan).collect()
}

/// Refuses a downloaded feed that is not a list: binary data, a web page, mostly lines that aren't entries,
/// or more than `max` entries. `entries` is how many lines gave an entry.
pub(super) fn vet(body: &str, entries: usize, max: usize) -> Result<(), String> {
    let lines = body.lines().filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with(['#', ';'])).count();
    if body.contains('\0') {
        Err("it is binary data, not a list".into())
    } else if body.trim_start().starts_with('<') {
        Err("it is a web page, not a list".into())
    } else if entries == 0 || entries * 2 < lines {
        Err(format!("only {entries} of its {lines} lines are entries"))
    } else if entries > max {
        Err(format!("it has {entries} entries, over the limit of {max}"))
    } else {
        Ok(())
    }
}

/// Replaces a list cache without leaving it half-written: the new text goes to a temporary file, and the
/// old copy is kept as `.bak` for [`read_cache`].
pub(super) fn save_cache(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text)?;
    if path.exists() {
        std::fs::rename(path, path.with_extension("bak"))?;
    }
    std::fs::rename(tmp, path)
}

/// The cache as saved, or the copy kept before it when the current one is missing or fails `valid`.
pub(super) fn read_cache(path: &Path, valid: impl Fn(&str) -> bool) -> Option<String> {
    [path.to_path_buf(), path.with_extension("bak")].iter().find_map(|p| std::fs::read_to_string(p).ok().filter(|t| valid(t)))
}

/// Whether a list must not block `ip`: this machine's own network (loopback, LAN, link-local, multicast) and
/// the addresses in `protected` (gateways, DNS servers and Home Assistant hosts).
pub fn is_protected(ip: IpAddr, protected: &HashSet<IpAddr>) -> bool {
    classify(ip) != Locality::Wan || protected.contains(&ip)
}

/// The gateways and DNS servers of this machine, and the Home Assistant hosts given as addresses. No lookups:
/// the Block button calls this on the UI thread.
pub fn protected_addrs(ha_urls: &[String]) -> HashSet<IpAddr> {
    let adapters = crate::sys::netinfo::adapters().unwrap_or_default();
    let mut set: HashSet<IpAddr> = adapters.iter().flat_map(|a| a.gateways.iter().chain(&a.dns)).copied().collect();
    set.extend(ha_urls.iter().filter_map(|u| ha_host(u)?.parse::<IpAddr>().ok()));
    set
}

/// The Home Assistant host names, resolved. Slow (a DNS lookup each), so only the download thread calls it.
fn resolve_hosts(ha_urls: &[String]) -> HashSet<IpAddr> {
    ha_urls.iter().filter_map(|u| (ha_host(u)?, 0).to_socket_addrs().ok()).flatten().map(|a| a.ip()).collect()
}

/// The address of the Home Assistant plugin, while it runs: its host must never be blocked by a list.
pub fn home_assistant_urls() -> Vec<String> {
    crate::plugins::wasm::manager::plugin_config("ha").and_then(|c| c.get("url").cloned()).filter(|u| !u.is_empty()).into_iter().collect()
}

/// The host of an address such as "http://homeassistant.local:8123/" (no port).
fn ha_host(url: &str) -> Option<&str> {
    let authority = url.split("://").last()?.split('/').next()?;
    Some(authority.rsplit_once(':').map_or(authority, |(host, _)| host))
}

/// Addresses from the last good copy whose lists are among `failed`, with only those lists' names.
fn keep_from_failed(previous: &HashMap<IpAddr, String>, failed: &[String]) -> Vec<(IpAddr, String)> {
    previous
        .iter()
        .filter_map(|(ip, names)| {
            let kept: Vec<&str> = names.split(", ").filter(|n| failed.iter().any(|f| f == n)).collect();
            (!kept.is_empty()).then(|| (*ip, kept.join(", ")))
        })
        .collect()
}

/// Adds a list's name to an address, after the names already there.
fn add_name(all: &mut HashMap<IpAddr, String>, ip: IpAddr, name: &str) {
    let e = all.entry(ip).or_default();
    if !e.is_empty() {
        e.push_str(", ");
    }
    e.push_str(name);
}

/// Called by the collectors once a tick with the (app key, remote address) pairs seen; takes the
/// shared lock once, as the UI waits on it too.
pub fn hits(shared: &Shared, seen: impl IntoIterator<Item = (String, IpAddr)>) {
    let mut st = shared.state();
    for hit in seen {
        if st.threat_ips.contains_key(&hit.1) && st.threat_seen.insert(hit.clone()) {
            st.threat_hits.push(hit);
        }
    }
}

pub(crate) fn cache_path() -> std::path::PathBuf {
    crate::settings::data_dir().join("threats.txt")
}

/// Largest list accepted, in bytes; curl fails a bigger download.
const MAX_FEED_BYTES: &str = "20000000";

/// How a feed is named in the log and the cache: host and path only, since the query or user part often holds an API key.
fn feed_name(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    match rest.split_once('/') {
        Some((auth, path)) => format!("{}/{path}", auth.rsplit('@').next().unwrap_or_default()),
        None => rest.rsplit('@').next().unwrap_or_default().to_owned(),
    }
}

/// Downloads each feed with curl: (the feed's `feed_name`, the body or why it was refused). Shared with the
/// domain lists, so both follow the same rules: https only, a 60 s limit and a 20 MB cap.
pub(super) fn fetch(feeds: &str) -> Vec<(String, Result<String, String>)> {
    feeds
        .lines()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(|url| {
            let name = feed_name(url);
            let body = if !url.starts_with("https://") {
                Err("it is not an https address".into())
            } else if !crate::util::valid_url(url, &[]) {
                Err("it is not a valid address".into())
            } else {
                super::asn::curl_url(&["-sfL", "--max-time", "60", "--max-filesize", MAX_FEED_BYTES], url).ok_or_else(|| "the download failed, or it is over 20 MB".into())
            };
            (name, body)
        })
        .collect()
}

/// Every address with the names of the lists carrying it, or `None` when no list could be used. A list that fails
/// or is refused keeps its addresses from the last good copy (`previous`). Addresses this machine depends on are
/// never added: they are logged and left out.
fn download(feeds: &str, previous: &HashMap<IpAddr, String>, ha_urls: &[String]) -> Option<HashMap<IpAddr, String>> {
    let mut protected = protected_addrs(ha_urls);
    protected.extend(resolve_hosts(ha_urls));
    let feeds = fetch(feeds);
    let total = feeds.len();
    let mut all: HashMap<IpAddr, String> = HashMap::new();
    let mut failed = Vec::new();
    for (name, body) in feeds {
        match body.and_then(|text| vet(&text, text.lines().filter(|l| ip_of(l).is_some()).count(), MAX_IPS).map(|()| text)) {
            Ok(text) => {
                let mut left_out: Vec<IpAddr> = Vec::new();
                for ip in parse_feed(&text) {
                    if protected.contains(&ip) {
                        left_out.push(ip);
                    } else {
                        add_name(&mut all, ip, &name);
                    }
                }
                if !left_out.is_empty() {
                    let shown: Vec<String> = left_out.iter().take(5).map(IpAddr::to_string).collect();
                    applog::line(LOG, &format!("{name}: left out {} address(es) this machine depends on, e.g. {}", left_out.len(), shown.join(", ")));
                }
            }
            Err(why) => {
                applog::line(LOG, &format!("skipped the list {name}: {why}"));
                failed.push(name);
            }
        }
    }
    if failed.len() == total {
        return None;
    }
    for (ip, names) in keep_from_failed(previous, &failed) {
        if !protected.contains(&ip) {
            for name in names.split(", ") {
                add_name(&mut all, ip, name);
            }
        }
    }
    Some(all)
}

fn load_cache(text: &str) -> HashMap<IpAddr, String> {
    text.lines()
        .filter_map(|l| {
            let (ip, names) = l.split_once('\t')?;
            Some((ip.parse().ok()?, names.to_owned()))
        })
        .collect()
}

fn kv(shared: &Shared, key: &str) -> String {
    shared.open_db().ok().and_then(|db| db.kv_get(key)).unwrap_or_default()
}

fn kv_set(shared: &Shared, key: &str, value: &str) -> Result<(), String> {
    shared.open_db().map_err(|e| e.to_string())?.kv_set(key, value).map_err(|e| e.to_string())
}

fn sig_word(signed: Option<bool>) -> &'static str {
    match signed {
        Some(true) => "Signed",
        Some(false) => "Unsigned",
        None => "Signature unknown",
    }
}

pub fn run(shared: Arc<Shared>, fw: Arc<FwController>) {
    {
        let mut st = shared.state();
        st.threat_allow = kv(&shared, ALLOW_KEY).lines().map(str::to_owned).collect();
        st.threat_meta = kv(&shared, META_KEY).lines().filter_map(|l| l.split_once('\t')).map(|(a, b)| (a.to_owned(), b.to_owned())).collect();
    }
    let mut job: Option<std::thread::JoinHandle<()>> = None;
    let mut last_try = SystemTime::UNIX_EPOCH;
    while !shared.stopping() {
        std::thread::sleep(Duration::from_millis(500));
        let s = shared.settings();
        if !s.threat_protect {
            let mut st = shared.state();
            st.threat_ips.clear();
            st.threat_hits.clear();
            st.threat_seen.clear();
            continue;
        }
        let max_age = Duration::from_secs(u64::from(s.threat_update_hours) * 3600);
        let age = std::fs::metadata(cache_path()).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
        if shared.state().threat_ips.is_empty() && age.is_some() {
            match read_cache(&cache_path(), |t| !load_cache(t).is_empty()) {
                Some(text) => shared.state().threat_ips = load_cache(&text),
                // An older format without list names, or unreadable: fetch afresh.
                None => {
                    let _ = std::fs::remove_file(cache_path());
                }
            }
        }
        let stale = age.is_none_or(|a| a > max_age);
        // Retry a failed download hourly, not every half second.
        let retry = last_try.elapsed().is_ok_and(|e| e > Duration::from_secs(3600));
        if stale && retry && job.as_ref().is_none_or(|j| j.is_finished()) {
            last_try = SystemTime::now();
            let (shared, feeds, integrations) = (shared.clone(), s.threat_feeds.clone(), home_assistant_urls());
            job = Some(std::thread::spawn(move || {
                let previous = shared.state().threat_ips.clone();
                let Some(ips) = download(&feeds, &previous, &integrations) else {
                    shared.set_note("threat", Some(StatusNote::warn("Couldn't download the malicious-IP lists; will retry within the hour.")));
                    return;
                };
                shared.set_note("threat", None);
                let text: Vec<String> = ips.iter().map(|(ip, names)| format!("{ip}\t{names}")).collect();
                if let Err(e) = save_cache(&cache_path(), &text.join("\n")) {
                    applog::line(LOG, &format!("couldn't save the malicious-IP cache: {e}"));
                }
                shared.state().threat_ips = ips;
            }));
        }
        let hits = std::mem::take(&mut shared.state().threat_hits);
        if hits.is_empty() {
            continue;
        }
        let Ok(db) = shared.open_db() else {
            // Put them back so the next try reports them; they stay in `threat_seen`, so none is queued twice.
            shared.state().threat_hits.extend(hits);
            continue;
        };
        for (key, ip) in hits {
            let (allowed, manual) = {
                let st = shared.state();
                (st.threat_allow.contains(&ip.to_string()), st.threat_manual.contains(&ip))
            };
            if allowed {
                continue;
            }
            let rec = db.app_by_key(&key).ok().flatten();
            let app = rec.as_ref().map_or_else(|| key.clone(), |r| r.name.clone());
            let signed = rec.and_then(|r| r.signed);
            let attempt = if s.threat_block && !manual { Some(fw.block_ip(ip, true)) } else { None };
            let blocked = matches!(attempt, Some(Ok(())));
            let error = attempt.and_then(Result::err);
            let ip_s = ip.to_string();
            let text = format!("connected to a known malicious address{}{}", if blocked { " (blocked)" } else { "" }, super::apps::signature_suffix(signed));
            shared.alert(&db, AlertKind::Threat, &app, &text, &ip_s, "");
            let (shown, lines) = {
                let mut st = shared.state();
                st.threat_meta.insert(ip_s.clone(), format!("{app} · {}", sig_word(signed)));
                let lines: Vec<String> = st.threat_meta.iter().map(|(a, b)| format!("{a}\t{b}")).collect();
                st.threats.push(Threat { ip: ip_s, app: app.clone(), signed, blocked, error });
                (st.popups_ok, lines)
            };
            // Disk write after the state lock is released: the UI and collector wait on it.
            let _ = db.kv_set(META_KEY, &lines.join("\n"));
            if !shown {
                crate::sys::notify::balloon("Malicious IP detected", &format!("{app} reached {ip}, a known malicious address.{}", if blocked { " It was blocked." } else { "" }));
            }
            shared.repaint();
        }
    }
}

/// The banner's and the Settings list's buttons.
pub fn act(shared: &Shared, fw: &FwController, ip: &str, act: ThreatAct) -> Result<(), String> {
    let addr: IpAddr = ip.parse().map_err(|_| "Not an IP address.".to_string())?;
    match act {
        ThreatAct::Block => {
            fw.block_ip(addr, true)?;
            shared.state().threat_manual.remove(&addr);
        }
        // Like removing a program from the Firewall tab: the next connection raises a fresh warning,
        // but this time nothing is blocked until the user says so.
        ThreatAct::Unblock => {
            fw.block_ip(addr, false)?;
            let mut st = shared.state();
            st.threat_manual.insert(addr);
            st.threat_seen.retain(|(_, a)| *a != addr);
        }
        ThreatAct::Whitelist | ThreatAct::Unwhitelist => {
            let add = act == ThreatAct::Whitelist;
            let mut list = shared.state().threat_allow.clone();
            list.retain(|a| a != ip);
            if add {
                list.push(ip.to_owned());
            }
            kv_set(shared, ALLOW_KEY, &list.join("\n"))?;
            let mut st = shared.state();
            st.threat_allow = list;
            st.threat_seen.retain(|(_, a)| *a != addr);
            drop(st);
            // Without a rule there is nothing to lift (not elevated, or auto-block was off).
            if add {
                let _ = fw.block_ip(addr, false);
            }
        }
    }
    Ok(())
}

/// What the info window shows above the whois answer.
pub fn summary(shared: &Shared, ip: &str) -> String {
    let st = shared.state();
    let who = st.threat_meta.get(ip).map_or("Not seen this run or earlier.", String::as_str);
    let lists = ip.parse().ok().and_then(|a: IpAddr| st.threat_ips.get(&a).cloned());
    format!(
        "Program: {who}\nListed on: {}\nWhitelisted: {}",
        lists.as_deref().unwrap_or("not on the lists currently loaded (they may have been updated since)"),
        if st.threat_allow.iter().any(|a| a == ip) { "yes" } else { "no" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_name_drops_keys() {
        assert_eq!(feed_name("https://example.com/list.txt?key=secret#x"), "example.com/list.txt");
        assert_eq!(feed_name("https://user:pass@example.com/a"), "example.com/a");
        assert_eq!(feed_name("https://tok@example.com?k=1"), "example.com");
        assert_eq!(feed_name("https://feeds.example.org/ips/a@b.txt"), "feeds.example.org/ips/a@b.txt");
    }

    #[test]
    fn feeds_keep_only_public_addresses() {
        let f = parse_feed("# Feodo\n1.2.3.4\n5.6.7.8\t3 ; c2\n192.168.1.1\n127.0.0.1\nnot an ip\n\n2606:4700::1111\n");
        let want: HashSet<IpAddr> = ["1.2.3.4", "5.6.7.8", "2606:4700::1111"].iter().map(|s| s.parse().unwrap()).collect();
        assert_eq!(f, want);
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn vet_refuses_things_that_are_not_lists() {
        let good = "# Feodo\n1.2.3.4\n5.6.7.8\n";
        assert!(vet(good, 2, 10).is_ok());
        assert!(vet("<html><body>Blocked</body></html>", 0, 10).is_err());
        assert!(vet("1.2.3.4\n\0\0\0", 1, 10).is_err());
        assert!(vet("# only comments\n", 0, 10).is_err());
        // Mostly lines that aren't addresses.
        assert!(vet("1.2.3.4\nfoo\nbar\nbaz\n", 1, 10).is_err());
        // Over the limit: refused, not cut short.
        assert!(vet(good, 2, 1).is_err());
    }

    #[test]
    fn protected_addresses_are_the_local_network_and_the_given_ones() {
        let protected: HashSet<IpAddr> = [ip("8.8.8.8")].into();
        assert!(is_protected(ip("127.0.0.1"), &protected));
        assert!(is_protected(ip("192.168.1.1"), &protected));
        assert!(is_protected(ip("8.8.8.8"), &protected), "a public DNS server in the adapter settings");
        assert!(!is_protected(ip("1.2.3.4"), &protected));
    }

    #[test]
    fn home_assistant_host_comes_out_of_its_address() {
        assert_eq!(ha_host("http://homeassistant.local:8123/"), Some("homeassistant.local"));
        assert_eq!(ha_host("https://192.168.1.5"), Some("192.168.1.5"));
        assert!(protected_addrs(&["http://203.0.113.7:8123".to_owned()]).contains(&ip("203.0.113.7")));
    }

    #[test]
    fn a_failed_list_keeps_only_its_own_last_good_entries() {
        let previous: HashMap<IpAddr, String> = [(ip("1.1.1.1"), "a.example/x, b.example/y".to_owned()), (ip("2.2.2.2"), "a.example/x".to_owned())].into();
        let mut kept = keep_from_failed(&previous, &["b.example/y".to_owned()]);
        kept.sort();
        assert_eq!(kept, vec![(ip("1.1.1.1"), "b.example/y".to_owned())]);
        assert!(keep_from_failed(&previous, &[]).is_empty());
    }

    #[test]
    fn the_cache_keeps_the_previous_copy_and_falls_back_to_it() {
        let dir = std::env::temp_dir().join(format!("rw-threat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("threats.txt");
        save_cache(&path, "1.2.3.4\ta").unwrap();
        save_cache(&path, "garbage").unwrap();
        assert_eq!(std::fs::read_to_string(path.with_extension("bak")).unwrap(), "1.2.3.4\ta");
        // The current copy fails the check, so the one before it is read.
        assert_eq!(read_cache(&path, |t| !load_cache(t).is_empty()).as_deref(), Some("1.2.3.4\ta"));
        assert_eq!(read_cache(&path, |_| true).as_deref(), Some("garbage"));
        assert_eq!(read_cache(&dir.join("missing.txt"), |_| true), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_keeps_list_names() {
        let c = load_cache("1.2.3.4\ta.example/x, b.example/y\nbad line\n");
        assert_eq!(c.len(), 1);
        assert_eq!(c[&"1.2.3.4".parse::<IpAddr>().unwrap()], "a.example/x, b.example/y");
    }
}
