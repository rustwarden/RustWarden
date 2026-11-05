//! ICMP ping monitor: pings the hosts the user adds and draws latency and loss on the Network > Ping tab,
//! with the shared latency charts (`core::latency`, also used by Broadband Quality). History is only
//! what this app has stored itself.

pub mod store;
pub mod ui;
pub mod worker;

use crate::plugins::core::latency::Sample;
use crate::settings::Settings;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub id: u32,
    pub name: String,
    pub address: String,
}

impl Host {
    pub fn label(&self) -> &str {
        if self.name.is_empty() { &self.address } else { &self.name }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Switched on in Settings; hosts are only pinged while it is.
    pub show_tab: bool,
    pub hosts: Vec<Host>,
    pub next_id: u32,
    /// Tab choices kept between runs, as on the Broadband tab.
    pub layout: usize,
    pub range: usize,
}

impl Config {
    pub fn add(&mut self, name: &str, address: &str) {
        self.next_id += 1;
        self.hosts.push(Host { id: self.next_id, name: name.trim().into(), address: address.trim().into() });
    }
}

/// Made-up ping rounds for one host in Demo mode, from `since` to `until`: a steady latency with a gentle wave, a spike now and
/// then and the odd lost echo. Whole multiples of the step, so the same moments are drawn on every refresh.
pub fn demo_samples(id: u32, since: i64, until: i64) -> Vec<Sample> {
    if until <= since {
        return Vec::new();
    }
    let step = ((until - since) / 400).max(60);
    let base = 0.6 + (id % 5) as f32 * 0.9;
    let phase = id as f32 * 1.7;
    (since.div_euclid(step) + 1..=until.div_euclid(step))
        .map(|k| {
            let x = (k * step) as f32 / 900.0 + phase;
            let mut avg = base * (1.0 + x.sin() * 0.25 + (x * 2.3).sin() * 0.1);
            if k % 37 == 0 {
                avg *= 3.0;
            }
            Sample { ts: k * step, min: avg * 0.8, avg, max: avg * 1.5, loss: if k % 53 == 0 { 33.3 } else { 0.0 } }
        })
        .collect()
}

pub fn tab_visible(s: &Settings) -> bool {
    s.ping.show_tab
}

pub fn sanitize(s: &mut Settings) {
    s.ping.layout = s.ping.layout.min(2);
    s.ping.range = s.ping.range.min(2);
    let top = s.ping.hosts.iter().map(|h| h.id).max().unwrap_or(0);
    s.ping.next_id = s.ping.next_id.max(top);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_samples_are_ordered_inside_the_span_and_sane() {
        let (since, until) = (1_000_000, 1_000_000 + 24 * 3600);
        let s = demo_samples(2, since, until);
        assert!(s.len() > 100);
        assert!(s.windows(2).all(|w| w[0].ts < w[1].ts));
        assert!(s.iter().all(|x| x.ts > since && x.ts <= until));
        assert!(s.iter().all(|x| x.min > 0.0 && x.min <= x.avg && x.avg <= x.max && (0.0..=100.0).contains(&x.loss)));
    }

    #[test]
    fn demo_samples_are_stable_and_differ_per_host() {
        let (since, until) = (5_000_000, 5_000_000 + 3 * 3600);
        assert_eq!(demo_samples(1, since, until), demo_samples(1, since, until));
        assert_ne!(demo_samples(1, since, until), demo_samples(2, since, until));
    }

    #[test]
    fn demo_samples_of_an_empty_span_are_empty() {
        assert!(demo_samples(1, 10, 10).is_empty());
        assert!(demo_samples(1, 10, 5).is_empty());
    }
}
