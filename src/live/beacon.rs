//! Beaconing detection: malware that checks in with its controller does it on a timer, so the contacts come at
//! near-perfectly even intervals. A contact is the start of a burst of traffic between a program and an address (a
//! quiet gap of a few seconds ends a burst). Even timing alone is a weak signal (media players and telemetry run on
//! timers too), so a series that is regular is then scored on several signals together: how big the contacts are, the
//! destination's kind, the program, and how rare the destination is. Pure bookkeeping: the collector feeds it what it
//! saw each second.

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
/// One report per program and address per day.
const QUIET_AFTER_REPORT: i64 = 86_400;
/// Series untouched this long are forgotten.
const FORGET_AFTER: i64 = 2 * 3600;
const MAX_SERIES: usize = 5000;

/// Bytes per contact up to which a contact counts as a small check-in, and from which it is media-sized.
const SMALL: f64 = 2048.0;
const MEDIA: f64 = 65_536.0;
/// Bytes per minute received from which the destination is a download or a stream (1 MB).
const BULK_PER_MIN: f64 = 1_048_576.0;
/// Score from which a report is shown at the higher level.
const IMPORTANT: i32 = 85;

pub const DEFAULT_CDN: &str =
    "live-video.net, googlevideo.com, ytimg.com, nflxvideo.net, ttvnw.net, jtvnw.net, akamaized.net, akamaihd.net, cloudfront.net, fastly.net, llnwd.net, scdn.co, dssott.com";

/// The thresholds, from Settings (`beacon_*`).
#[derive(Clone, Debug)]
pub struct Config {
    /// Seconds the contacts must span before the timing counts.
    pub min_window: i64,
    /// Largest spread (standard deviation / mean) of the gaps that still counts as "like clockwork".
    pub max_spread: f64,
    /// Score (0-100) a series needs before it is reported.
    pub threshold: i32,
    /// Domain suffixes of media / CDN / telemetry hosts, which lower the score (comma separated).
    pub cdn_suffixes: String,
}

impl Default for Config {
    fn default() -> Self {
        Self { min_window: 300, max_spread: 0.08, threshold: 60, cdn_suffixes: DEFAULT_CDN.into() }
    }
}

/// The shape of one series whose timing is even: rhythm, and how big the contacts were.
#[derive(Debug, PartialEq)]
pub struct Beat {
    /// Seconds between contacts, on average.
    pub period: u64,
    pub count: usize,
    /// Standard deviation of the gaps, in seconds.
    pub jitter: f64,
    /// Average bytes (both ways) per contact, and how much they vary (standard deviation / mean).
    pub avg_bytes: f64,
    pub size_spread: f64,
    /// Bytes received per minute over the window.
    pub down_per_min: f64,
}

#[derive(Default)]
struct Series {
    last_seen: i64,
    starts: VecDeque<i64>,
    /// (sent, received) per contact, parallel to `starts`.
    sizes: VecDeque<(u64, u64)>,
    reported: i64,
}

#[derive(Default)]
pub struct Tracker {
    series: HashMap<(String, IpAddr), Series>,
    pruned: i64,
}

impl Tracker {
    /// Notes that `app` exchanged `bytes` (sent, received) with `remote` at `now` (unix seconds). Returns the series' shape
    /// while its timing is clear and it has not been reported lately; the caller scores it and calls `reported`.
    pub fn observe(&mut self, app: &str, remote: IpAddr, now: i64, bytes: (u64, u64), cfg: &Config) -> Option<Beat> {
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
            if let Some(last) = s.sizes.back_mut() {
                (last.0, last.1) = (last.0 + bytes.0, last.1 + bytes.1);
            }
            return None;
        }
        if s.starts.len() == KEEP {
            s.starts.pop_front();
            s.sizes.pop_front();
        }
        s.starts.push_back(now);
        s.sizes.push_back(bytes);
        if s.starts.len() < MIN_BURSTS || now - s.reported < QUIET_AFTER_REPORT && s.reported != 0 {
            return None;
        }
        regular(&s.starts, &s.sizes, cfg)
    }

    /// Marks a series as reported, so it is quiet for a day.
    pub fn reported(&mut self, app: &str, remote: IpAddr, now: i64) {
        if let Some(s) = self.series.get_mut(&(app.to_owned(), remote)) {
            s.reported = now;
        }
    }

    /// How many addresses `app` is watched on, and how many programs are watched on `remote`.
    pub fn spread(&self, app: &str, remote: IpAddr) -> (usize, usize) {
        (self.series.keys().filter(|(a, _)| a == app).count(), self.series.keys().filter(|(_, r)| *r == remote).count())
    }
}

/// Whether a program is on the user's ignore list: `list` holds names or parts of a path (comma, semicolon or line
/// separated, not case sensitive); one that is part of the program's path or display name matches. Entries with an `@`
/// are program + domain pairs, handled by [`ignored_pair`].
pub fn ignored(list: &str, key: &str, name: &str) -> bool {
    let (key, name) = (key.to_ascii_lowercase(), name.to_ascii_lowercase());
    list.split([',', ';', '\n']).map(|p| p.trim().to_ascii_lowercase()).any(|p| !p.is_empty() && !p.contains('@') && (key.contains(&p) || name.contains(&p)))
}

/// A program + domain pair on the ignore list: an entry `program@domain` (such as `chrome@live-video.net`) skips that
/// program's contacts with that domain and its subdomains.
pub fn ignored_pair(list: &str, key: &str, name: &str, host: &str) -> bool {
    let (key, name) = (key.to_ascii_lowercase(), name.to_ascii_lowercase());
    list.split([',', ';', '\n']).filter_map(|e| e.split_once('@')).any(|(prog, domain)| {
        let prog = prog.trim().to_ascii_lowercase();
        (prog.is_empty() || key.contains(&prog) || name.contains(&prog)) && suffix_match(host, domain)
    })
}

/// Whether the host ends in one of the comma separated domain `suffixes` (the domain itself or any subdomain of it).
fn suffix_match(host: &str, suffixes: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    suffixes.split([',', ';', '\n']).map(|p| p.trim().trim_start_matches('.').to_ascii_lowercase()).any(|p| !p.is_empty() && (host == p || host.ends_with(&format!(".{p}"))))
}

/// "45 seconds", "5 minutes".
pub fn period_text(secs: u64) -> String {
    if secs < 120 { format!("{secs} seconds") } else { format!("{} minutes", (secs + 30) / 60) }
}

/// What the caller knows about the series' program and destination.
pub struct Context<'a> {
    /// The destination's name, when a lookup named it.
    pub host: Option<&'a str>,
    pub browser: bool,
    /// Whether the program's file carries a valid signature, when known.
    pub signed: Option<bool>,
    /// Addresses this program is watched on, and programs watched on this address (from [`Tracker::spread`]).
    pub destinations: usize,
    pub programs: usize,
}

#[derive(Debug, PartialEq)]
pub struct Verdict {
    pub score: i32,
    /// Why, in words: "small payloads ~400 B", "unsigned program"...
    pub reasons: Vec<String>,
    pub alert: bool,
    /// A strong match, shown at the higher level.
    pub important: bool,
}

/// Weighs the signals together. Even timing is only the start (30); the rest moves the score up or down.
pub fn score(b: &Beat, ctx: &Context, cfg: &Config) -> Verdict {
    let (mut score, mut reasons) = (30, vec![format!("even timing, jitter {:.1} s", b.jitter)]);
    let mut add = |points: i32, why: String| {
        score += points;
        reasons.push(why);
    };
    if b.jitter / b.period.max(1) as f64 <= cfg.max_spread / 3.0 {
        add(10, "very low jitter".into());
    }
    let size = format!("~{} B", b.avg_bytes.round());
    if b.down_per_min >= BULK_PER_MIN || b.avg_bytes >= MEDIA {
        add(-50, format!("heavy downstream data ({size} per contact, {:.1} MB/min)", b.down_per_min / 1_048_576.0));
    } else if b.avg_bytes <= SMALL {
        add(20, format!("small payloads {size}"));
        if b.size_spread <= 0.3 {
            add(10, "uniform sizes".into());
        }
    }
    if ctx.host.is_some_and(|h| suffix_match(h, &cfg.cdn_suffixes) || h.split('.').any(|l| l.starts_with("hls") || l.starts_with("dash"))) {
        add(-30, "known media / CDN destination".into());
    }
    if ctx.browser && ctx.destinations >= 10 {
        add(-10, "browser talking to many destinations".into());
    }
    if ctx.signed == Some(false) {
        add(15, "unsigned program".into());
    }
    if ctx.destinations <= 2 {
        add(10, "program talks to few destinations".into());
    }
    if ctx.programs <= 1 {
        add(10, "rare destination (one program)".into());
    }
    let score = score.clamp(0, 100);
    Verdict { score, alert: score >= cfg.threshold, important: score >= IMPORTANT, reasons }
}

/// Whether the gaps between `starts` are even enough to be a timer, with the shape of the contacts' sizes.
fn regular(starts: &VecDeque<i64>, sizes: &VecDeque<(u64, u64)>, cfg: &Config) -> Option<Beat> {
    let window = starts.back()? - starts.front()?;
    let gaps: Vec<f64> = starts.iter().zip(starts.iter().skip(1)).map(|(a, b)| (b - a) as f64).collect();
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if !(MIN_PERIOD..=MAX_PERIOD).contains(&mean) || window < cfg.min_window {
        return None;
    }
    let jitter = (gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64).sqrt();
    // Contacts are noted to the whole second, so one second of jitter is allowed whatever the rhythm.
    if (jitter / mean).max(1.0 / mean) > cfg.max_spread {
        return None;
    }
    // The newest contact has only just begun, so its size is not known yet.
    let done: Vec<(f64, f64)> = sizes.iter().take(sizes.len() - 1).map(|(u, d)| ((u + d) as f64, *d as f64)).collect();
    let n = done.len().max(1) as f64;
    let avg_bytes = done.iter().map(|d| d.0).sum::<f64>() / n;
    let size_spread = if avg_bytes > 0.0 { (done.iter().map(|d| (d.0 - avg_bytes).powi(2)).sum::<f64>() / n).sqrt() / avg_bytes } else { 0.0 };
    let down_per_min = done.iter().map(|d| d.1).sum::<f64>() / (window.max(1) as f64 / 60.0);
    Some(Beat { period: mean.round() as u64, count: starts.len(), jitter, avg_bytes, size_spread, down_per_min })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "203.0.113.50".parse().unwrap()
    }

    fn cfg() -> Config {
        Config::default()
    }

    /// Feeds one contact per time with `bytes` (sent, received) each; returns the first beat, marking it reported like the caller does.
    fn feed(t: &mut Tracker, times: impl IntoIterator<Item = i64>, bytes: (u64, u64)) -> Option<Beat> {
        let beat = times.into_iter().find_map(|at| t.observe("app.exe", ip(), at, bytes, &cfg()).map(|b| (b, at)));
        beat.map(|(b, at)| {
            t.reported("app.exe", ip(), at);
            b
        })
    }

    fn ctx<'a>(host: Option<&'a str>, browser: bool, signed: Option<bool>, destinations: usize) -> Context<'a> {
        Context { host, browser, signed, destinations, programs: 1 }
    }

    #[test]
    fn a_steady_timer_is_reported_once() {
        let mut t = Tracker::default();
        let beat = feed(&mut t, (0..20).map(|i| 1000 + i * 60), (150, 150)).expect("clockwork");
        assert_eq!(beat.period, 60);
        assert!(feed(&mut t, (20..40).map(|i| 1000 + i * 60), (150, 150)).is_none(), "once a day is enough");
    }

    #[test]
    fn one_second_of_rounding_still_counts() {
        let mut t = Tracker::default();
        assert!(feed(&mut t, (0..20).map(|i| 1000 + i * 60 + (i % 2)), (150, 150)).is_some());
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
        assert!(feed(&mut t, times, (150, 150)).is_none());
    }

    #[test]
    fn a_constant_stream_is_one_burst_and_a_very_fast_or_slow_rhythm_is_ignored() {
        let mut t = Tracker::default();
        assert!(feed(&mut t, 1000..1200, (150, 150)).is_none(), "no gaps, one burst");
        let mut t = Tracker::default();
        assert!(feed(&mut t, (0..30).map(|i| 1000 + i * 5), (150, 150)).is_none(), "every 5 s is a stream");
        let mut t = Tracker::default();
        assert!(feed(&mut t, (0..30).map(|i| 1000 + i * 7200), (150, 150)).is_none(), "every 2 hours is too rare to judge");
    }

    #[test]
    fn too_few_contacts_or_too_short_a_window_say_nothing() {
        let mut t = Tracker::default();
        assert!(feed(&mut t, (0..MIN_BURSTS as i64 - 1).map(|i| 1000 + i * 60), (150, 150)).is_none());
        let mut t = Tracker::default();
        assert!(feed(&mut t, (0..20).map(|i| 1000 + i * 15), (150, 150)).is_none(), "12 contacts 15 s apart span 165 s, under the 300 s window");
    }

    #[test]
    fn ignore_list_takes_programs_and_program_domain_pairs() {
        let (key, name) = (r"c:\users\me\appdata\local\microsoft\onedrive\onedrive.exe", "Microsoft OneDrive");
        assert!(ignored("onedrive", key, name) && ignored(" Dropbox ; OneDrive.exe ", key, name) && ignored("microsoft onedrive", key, name));
        assert!(!ignored("", key, name) && !ignored(" , ;", key, name) && !ignored("dropbox, slack", key, name));
        assert!(!ignored("onedrive@live.com", key, name), "a pair is not a whole-program entry");
        let chrome = r"c:\program files\google\chrome\application\chrome.exe";
        assert!(ignored_pair("chrome@live-video.net", chrome, "Google Chrome", "abc.playback.live-video.net"));
        assert!(!ignored_pair("chrome@live-video.net", chrome, "Google Chrome", "evil-live-video.net"), "a suffix is a whole domain");
        assert!(!ignored_pair("firefox@live-video.net", chrome, "Google Chrome", "a.live-video.net"));
        assert!(ignored_pair("@example.com", chrome, "Google Chrome", "example.com"), "no program: any program");
    }

    /// Runs a series through the tracker and scorer the way the collector does.
    fn verdict(period: i64, gap_jitter: i64, bytes: (u64, u64), c: Context) -> Option<Verdict> {
        let mut t = Tracker::default();
        let times = (0..26).map(|i| 1000 + i * period + (i % 2) * gap_jitter);
        let beat = times.into_iter().find_map(|at| t.observe("app.exe", ip(), at, bytes, &cfg()))?;
        Some(score(&beat, &c, &cfg()))
    }

    #[test]
    fn chrome_polling_a_live_video_cdn_is_not_reported() {
        let v = verdict(30, 0, (800, 400_000), ctx(Some("de488bcb61af.us-east-1.playback.live-video.net"), true, Some(true), 40)).expect("regular");
        assert!(!v.alert, "{v:?}");
    }

    #[test]
    fn an_unsigned_program_with_tiny_uniform_payloads_to_a_rare_host_is_reported() {
        let v = verdict(60, 1, (150, 150), ctx(Some("rare.example"), false, Some(false), 1)).expect("regular");
        assert!(v.alert && v.important, "{v:?}");
        assert!(v.reasons.iter().any(|r| r.contains("unsigned")) && v.reasons.iter().any(|r| r.contains("small payloads ~300 B")), "{:?}", v.reasons);
    }

    #[test]
    fn a_browser_is_not_exempt() {
        let v = verdict(60, 1, (150, 150), ctx(Some("rare.example"), true, Some(true), 3)).expect("regular");
        assert!(v.alert, "{v:?}");
    }

    #[test]
    fn a_cdn_suffix_lowers_the_level_without_hiding_it() {
        let rare = verdict(60, 1, (150, 150), ctx(Some("rare.example"), false, Some(false), 1)).unwrap();
        let cdn = verdict(60, 1, (150, 150), ctx(Some("x.cloudfront.net"), false, Some(false), 1)).unwrap();
        assert!(cdn.alert && !cdn.important && cdn.score < rare.score, "{cdn:?}");
    }

    #[test]
    fn domain_suffixes_match_whole_labels() {
        assert!(suffix_match("a.b.live-video.net", DEFAULT_CDN) && suffix_match("fastly.net", DEFAULT_CDN));
        assert!(!suffix_match("notfastly.net", DEFAULT_CDN) && !suffix_match("fastly.net.evil.com", DEFAULT_CDN));
    }
}
