//! Beaconing detection: malware that checks in with its controller does it on a timer, so the contacts come at
//! near-perfectly even intervals. A contact is the start of a burst of traffic between a program and an address (a
//! quiet gap of a few seconds ends a burst). When a program has made many of them and the gaps between them barely
//! vary, that is reported. Pure bookkeeping: the collector feeds it what it saw each second.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// Seconds of silence that end a burst.
const IDLE_GAP: i64 = 3;
/// Contacts needed before the pattern means anything.
const MIN_BURSTS: usize = 12;
/// Contacts kept per program and address.
const KEEP: usize = 24;
/// Check-in rhythms outside this range (seconds) are not beaconing: faster is a stream, slower is too rare to judge.
const MIN_PERIOD: f64 = 15.0;
const MAX_PERIOD: f64 = 3600.0;
/// Largest spread (standard deviation / mean) of the gaps that still counts as "like clockwork".
const MAX_SPREAD: f64 = 0.08;
/// One report per program and address per day.
const QUIET_AFTER_REPORT: i64 = 86_400;
/// Series untouched this long are forgotten.
const FORGET_AFTER: i64 = 2 * 3600;
const MAX_SERIES: usize = 5000;

#[derive(Debug, PartialEq)]
pub struct Beat {
    /// Seconds between contacts, on average.
    pub period: u64,
    pub count: usize,
}

#[derive(Default)]
struct Series {
    last_seen: i64,
    starts: VecDeque<i64>,
    reported: i64,
}

#[derive(Default)]
pub struct Tracker {
    series: HashMap<(String, IpAddr), Series>,
    pruned: i64,
}

impl Tracker {
    /// Notes that `app` exchanged data with `remote` at `now` (unix seconds). Returns a beat the first time the
    /// pattern is clear.
    pub fn observe(&mut self, app: &str, remote: IpAddr, now: i64) -> Option<Beat> {
        if now - self.pruned > 600 {
            self.pruned = now;
            self.series.retain(|_, s| now - s.last_seen < FORGET_AFTER);
            if self.series.len() > MAX_SERIES {
                self.series.clear();
            }
        }
        let s = self.series.entry((app.to_owned(), remote)).or_default();
        let new_burst = s.starts.is_empty() || now - s.last_seen >= IDLE_GAP;
        s.last_seen = now;
        if !new_burst {
            return None;
        }
        if s.starts.len() == KEEP {
            s.starts.pop_front();
        }
        s.starts.push_back(now);
        if s.starts.len() < MIN_BURSTS || now - s.reported < QUIET_AFTER_REPORT && s.reported != 0 {
            return None;
        }
        let beat = regular(&s.starts)?;
        s.reported = now;
        Some(beat)
    }
}

/// "45 seconds", "5 minutes".
pub fn period_text(secs: u64) -> String {
    if secs < 120 { format!("{secs} seconds") } else { format!("{} minutes", (secs + 30) / 60) }
}

/// Whether the gaps between `starts` are even enough to be a timer.
fn regular(starts: &VecDeque<i64>) -> Option<Beat> {
    let gaps: Vec<f64> = starts.iter().zip(starts.iter().skip(1)).map(|(a, b)| (b - a) as f64).collect();
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if !(MIN_PERIOD..=MAX_PERIOD).contains(&mean) {
        return None;
    }
    let variance = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
    // Contacts are noted to the whole second, so one second of jitter is allowed whatever the rhythm.
    let spread = (variance.sqrt() / mean).max(1.0 / mean);
    (spread <= MAX_SPREAD).then_some(Beat { period: mean.round() as u64, count: starts.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "203.0.113.50".parse().unwrap()
    }

    fn feed(t: &mut Tracker, times: impl IntoIterator<Item = i64>) -> Option<Beat> {
        times.into_iter().filter_map(|at| t.observe("app.exe", ip(), at)).next()
    }

    #[test]
    fn a_steady_timer_is_reported_once() {
        let mut t = Tracker::default();
        let beat = feed(&mut t, (0..20).map(|i| 1000 + i * 60)).expect("clockwork");
        assert_eq!(beat.period, 60);
        assert!(feed(&mut t, (20..40).map(|i| 1000 + i * 60)).is_none(), "once a day is enough");
    }

    #[test]
    fn one_second_of_rounding_still_counts() {
        let mut t = Tracker::default();
        let times = (0..20).map(|i| 1000 + i * 60 + (i % 2));
        assert!(feed(&mut t, times).is_some());
    }

    #[test]
    fn irregular_traffic_is_not_a_beacon() {
        let mut t = Tracker::default();
        let mut at = 1000;
        let times: Vec<i64> = (0..30)
            .map(|i| {
                at += 20 + (i * 37) % 90;
                at
            })
            .collect();
        assert!(feed(&mut t, times).is_none());
    }

    #[test]
    fn a_constant_stream_is_one_burst_and_a_very_fast_or_slow_rhythm_is_ignored() {
        let mut t = Tracker::default();
        assert!(feed(&mut t, 1000..1200).is_none(), "no gaps, one burst");
        let mut t = Tracker::default();
        assert!(feed(&mut t, (0..30).map(|i| 1000 + i * 5)).is_none(), "every 5 s is a stream");
        let mut t = Tracker::default();
        assert!(feed(&mut t, (0..30).map(|i| 1000 + i * 7200)).is_none(), "every 2 hours is too rare to judge");
    }

    #[test]
    fn too_few_contacts_say_nothing() {
        let mut t = Tracker::default();
        assert!(feed(&mut t, (0..MIN_BURSTS as i64 - 1).map(|i| 1000 + i * 60)).is_none());
    }
}
