//! Spots port scans and SYN floods from the stream of incoming connection attempts (SYN packets). Pure: the
//! caller gives it the time, the source address and the local port of each attempt.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

/// One source trying this many different local ports within [`SCAN_WINDOW_MS`] is scanning.
pub const SCAN_PORTS: usize = 12;
pub const SCAN_WINDOW_MS: u64 = 10_000;
/// This many attempts from anywhere within one second is a flood.
pub const FLOOD_PER_SEC: usize = 300;
/// The same finding is not reported again for this long.
const QUIET_MS: u64 = 600_000;
/// Sources tracked at once; beyond this the oldest are forgotten.
const MAX_SOURCES: usize = 5_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    PortScan { src: IpAddr, ports: usize },
    SynFlood { per_second: usize, busiest: IpAddr },
}

#[derive(Default)]
pub struct Detector {
    per_source: HashMap<IpAddr, VecDeque<(u64, u16)>>,
    /// Attempts in the last second, newest last.
    recent: VecDeque<(u64, IpAddr)>,
    reported: HashMap<String, u64>,
}

impl Detector {
    /// Records one incoming connection attempt; returns what it newly proves, if anything.
    pub fn syn(&mut self, now_ms: u64, src: IpAddr, port: u16) -> Option<Finding> {
        if self.per_source.len() >= MAX_SOURCES && !self.per_source.contains_key(&src) {
            let oldest = self.per_source.iter().min_by_key(|(_, v)| v.back().map_or(0, |e| e.0)).map(|(k, _)| *k);
            if let Some(k) = oldest {
                self.per_source.remove(&k);
            }
        }
        let q = self.per_source.entry(src).or_default();
        q.push_back((now_ms, port));
        while q.front().is_some_and(|(t, _)| now_ms.saturating_sub(*t) > SCAN_WINDOW_MS) {
            q.pop_front();
        }
        let ports = q.iter().map(|(_, p)| *p).collect::<HashSet<_>>().len();

        self.recent.push_back((now_ms, src));
        while self.recent.front().is_some_and(|(t, _)| now_ms.saturating_sub(*t) > 1000) {
            self.recent.pop_front();
        }

        if ports >= SCAN_PORTS && self.quiet(&format!("scan {src}"), now_ms) {
            return Some(Finding::PortScan { src, ports });
        }
        if self.recent.len() >= FLOOD_PER_SEC && self.quiet("flood", now_ms) {
            let mut by: HashMap<IpAddr, usize> = HashMap::new();
            for (_, s) in &self.recent {
                *by.entry(*s).or_default() += 1;
            }
            let busiest = by.into_iter().max_by_key(|(_, n)| *n).map_or(src, |(s, _)| s);
            return Some(Finding::SynFlood { per_second: self.recent.len(), busiest });
        }
        None
    }

    /// True the first time `key` is asked about within the quiet period.
    fn quiet(&mut self, key: &str, now_ms: u64) -> bool {
        if self.reported.get(key).is_some_and(|t| now_ms.saturating_sub(*t) < QUIET_MS) {
            return false;
        }
        self.reported.retain(|_, t| now_ms.saturating_sub(*t) < QUIET_MS);
        self.reported.insert(key.to_owned(), now_ms);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, n])
    }

    #[test]
    fn many_ports_from_one_source_is_a_scan_reported_once() {
        let mut d = Detector::default();
        let mut found = Vec::new();
        for (i, port) in (1000..1020u16).enumerate() {
            found.extend(d.syn(i as u64 * 100, ip(7), port));
        }
        assert_eq!(found, [Finding::PortScan { src: ip(7), ports: SCAN_PORTS }]);
        // Another source is its own case, and the first stays quiet.
        assert!(d.syn(5000, ip(8), 22).is_none());
    }

    #[test]
    fn retrying_one_port_or_going_slowly_is_not_a_scan() {
        let mut d = Detector::default();
        for i in 0..100u64 {
            assert!(d.syn(i * 50, ip(1), 443).is_none(), "one port again and again");
        }
        let mut slow = Detector::default();
        for (i, port) in (1..40u16).enumerate() {
            assert!(slow.syn(i as u64 * 2000, ip(2), port).is_none(), "a port every two seconds never reaches the count inside the window");
        }
    }

    #[test]
    fn a_burst_from_many_sources_is_a_flood() {
        let mut d = Detector::default();
        let mut found = None;
        for i in 0..FLOOD_PER_SEC {
            found = found.or(d.syn(i as u64, ip((i % 200) as u8), 80));
        }
        assert!(matches!(found, Some(Finding::SynFlood { per_second, .. }) if per_second == FLOOD_PER_SEC));
        assert!(d.syn(500, ip(1), 80).is_none(), "reported once");
    }
}
