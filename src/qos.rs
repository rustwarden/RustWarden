//! Bandwidth limits: "this program may send at most 5 Mbps". Windows enforces them as QoS policies
//! (`New-NetQosPolicy`), so no driver is involved. This module is the pure part: the limit model, how
//! it is stored and the policy names. Live (`live::qos`) and Demo share it.
//!
//! A QoS policy only shapes what a program *sends*; Windows has no user-mode way to cap downloads. In Driver
//! mode (see `driver`) the WinDivert-based engine (`live::engine`) enforces limits in both directions.

/// Every policy RustWarden makes starts with this, so they can be found and removed in bulk.
pub const PREFIX: &str = "RustWarden QoS ";
/// Slowest limit accepted (kilobits per second) and the fastest (10 Gbps).
pub const MIN_KBPS: u32 = 8;
pub const MAX_KBPS: u32 = 10_000_000;
/// Most limits kept; each is one Windows policy.
pub const MAX_LIMITS: usize = 64;

/// Which way a limit applies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LimitDir {
    #[default]
    Up,
    Down,
    Both,
}

impl LimitDir {
    pub const ALL: [LimitDir; 3] = [LimitDir::Up, LimitDir::Down, LimitDir::Both];

    pub fn label(self) -> &'static str {
        match self {
            LimitDir::Up => "Upload",
            LimitDir::Down => "Download",
            LimitDir::Both => "Upload & Download",
        }
    }

    pub fn up(self) -> bool {
        self != LimitDir::Down
    }

    pub fn down(self) -> bool {
        self != LimitDir::Up
    }

    fn code(self) -> char {
        match self {
            LimitDir::Up => 'U',
            LimitDir::Down => 'D',
            LimitDir::Both => 'B',
        }
    }

    fn from_code(c: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| c.starts_with(d.code()))
    }
}

/// How much a program matters when the line is busy. High is never held back by the shared line cap and takes its share first;
/// Low gets what is left. Windows QoS also marks the program's uploads (DSCP) so a router that honours it does the same.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Priority {
    High,
    #[default]
    Normal,
    Low,
}

impl Priority {
    pub const ALL: [Priority; 3] = [Priority::High, Priority::Normal, Priority::Low];

    pub fn label(self) -> &'static str {
        match self {
            Priority::High => "High",
            Priority::Normal => "Normal",
            Priority::Low => "Low",
        }
    }

    /// DSCP value for the QoS policy (EF for high, CS1 "scavenger" for low); Normal leaves packets unmarked.
    pub fn dscp(self) -> Option<u8> {
        match self {
            Priority::High => Some(46),
            Priority::Normal => None,
            Priority::Low => Some(8),
        }
    }

    fn code(self) -> char {
        match self {
            Priority::High => 'H',
            Priority::Normal => 'N',
            Priority::Low => 'L',
        }
    }

    fn from_code(c: &str) -> Self {
        Self::ALL.into_iter().find(|p| c.starts_with(p.code())).unwrap_or_default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QosLimit {
    pub id: u32,
    pub enabled: bool,
    /// Full path of the program's executable.
    pub program: String,
    /// Upload cap in kilobits per second (used when `dir` includes upload).
    pub kbps: u32,
    pub dir: LimitDir,
    /// Download cap in kilobits per second (used when `dir` includes download; Driver mode only).
    pub down_kbps: u32,
    /// Network-condition simulation (Driver mode): milliseconds added to every packet, and the share of packets lost.
    pub delay_ms: u32,
    pub loss_pct: u8,
    /// Unix time the simulation ends by itself (0 = not simulating), so a forgotten one can't break a program for long.
    pub sim_until: i64,
    /// Priority class. Anything but Normal may have no rate caps at all (0 up, 0 down).
    pub priority: Priority,
}

/// Longest added delay and largest loss the simulator accepts.
pub const MAX_DELAY_MS: u32 = 5000;
pub const MAX_LOSS_PCT: u8 = 90;
/// How long a simulation lasts.
pub const SIM_SECS: i64 = 30 * 60;

impl QosLimit {
    /// An upload-only limit, which is all that Normal mode makes.
    pub fn upload(id: u32, enabled: bool, program: impl Into<String>, kbps: u32) -> Self {
        Self { id, enabled, program: program.into(), kbps, dir: LimitDir::Up, down_kbps: 0, delay_ms: 0, loss_pct: 0, sim_until: 0, priority: Priority::Normal }
    }

    /// Whether delay or loss is set (and not yet over at `now`).
    pub fn simulating(&self, now: i64) -> bool {
        (self.delay_ms > 0 || self.loss_pct > 0) && self.sim_until > now
    }

    /// A rate of 0 means "no cap" and is only allowed when the limit simulates conditions or sets a priority instead.
    fn rate_ok(&self, kbps: u32) -> bool {
        (MIN_KBPS..=MAX_KBPS).contains(&kbps) || (kbps == 0 && (self.delay_ms > 0 || self.loss_pct > 0 || self.priority != Priority::Normal))
    }

    fn sim_text(&self) -> String {
        match (self.delay_ms, self.loss_pct) {
            (0, 0) => String::new(),
            (d, 0) => format!(" · +{d} ms"),
            (0, l) => format!(" · {l}% loss"),
            (d, l) => format!(" · +{d} ms · {l}% loss"),
        }
    }

    /// The rate(s) as shown in lists; `named` adds "Up"/"Down" (Driver mode, where limits can differ).
    pub fn rate_text(&self, named: bool) -> String {
        let rate = |k: u32| if k == 0 { "no cap".to_owned() } else { fmt_rate(k) };
        let base = match (self.dir, named) {
            (LimitDir::Up, false) => rate(self.kbps),
            (LimitDir::Up, true) => format!("Up {}", rate(self.kbps)),
            (LimitDir::Down, _) => format!("Down {}", rate(self.down_kbps)),
            (LimitDir::Both, _) => format!("Up {} · Down {}", rate(self.kbps), rate(self.down_kbps)),
        };
        let prio = if self.priority == Priority::Normal { String::new() } else { format!("{} priority · ", self.priority.label()) };
        prio + &base + &self.sim_text()
    }

    /// What is wrong with the limit, if anything.
    pub fn problem(&self) -> Option<&'static str> {
        if self.program.trim().is_empty() {
            Some("Pick a program to limit.")
        } else if self.program.chars().any(char::is_control) {
            Some("That program path is not valid.")
        } else if self.delay_ms > MAX_DELAY_MS || self.loss_pct > MAX_LOSS_PCT {
            Some("Delay can be up to 5000 ms and loss up to 90%.")
        } else if (self.dir.up() && !self.rate_ok(self.kbps)) || (self.dir.down() && !self.rate_ok(self.down_kbps)) {
            Some("Enter a limit between 8 Kbps and 10 Gbps.")
        } else {
            None
        }
    }

    pub fn exe_name(&self) -> &str {
        self.program.rsplit(['\\', '/']).next().unwrap_or(&self.program)
    }

    /// The Windows policy that enforces this limit. The id comes first so a renamed program is still found.
    pub fn policy_name(&self) -> String {
        format!("{PREFIX}{} {}", self.id, self.exe_name())
    }

    pub fn bits_per_second(&self) -> u64 {
        u64::from(self.kbps) * 1000
    }

    /// Upload-only limits keep the original four-column line, so Normal mode's saved data doesn't change.
    pub fn encode(&self) -> String {
        let line = format!("{}\t{}\t{}\t{}", self.id, u8::from(self.enabled), self.kbps, self.program);
        if self.dir == LimitDir::Up && self.down_kbps == 0 && self.sim_until == 0 && self.priority == Priority::Normal {
            line
        } else {
            format!("{line}\t{}\t{}\t{}\t{}\t{}\t{}", self.dir.code(), self.down_kbps, self.delay_ms, self.loss_pct, self.sim_until, self.priority.code())
        }
    }

    pub fn decode(line: &str) -> Option<QosLimit> {
        let mut f = line.splitn(4, '\t');
        let id = f.next()?.parse().ok().filter(|id| *id > 0)?;
        let enabled = f.next()? == "1";
        let kbps = f.next()?.parse().ok()?;
        // A program path holds no tabs (see `problem`), so anything after one is the direction and download rate.
        let mut rest = f.next()?.split('\t');
        let program = rest.next()?.to_owned();
        let dir = rest.next().and_then(LimitDir::from_code).unwrap_or_default();
        let mut num = || rest.next().and_then(|v| v.parse().ok());
        let down_kbps = num().unwrap_or(0);
        let (delay_ms, loss_pct, sim_until) = (num().unwrap_or(0), num().unwrap_or(0) as u8, num().unwrap_or(0) as i64);
        let priority = Priority::from_code(rest.next().unwrap_or(""));
        Some(QosLimit { id, enabled, kbps, program, dir, down_kbps, delay_ms, loss_pct, sim_until, priority })
    }
}

pub fn encode_all(limits: &[QosLimit]) -> String {
    limits.iter().map(QosLimit::encode).collect::<Vec<_>>().join("\n")
}

pub fn decode_all(text: &str) -> Vec<QosLimit> {
    text.lines().filter_map(QosLimit::decode).collect()
}

/// A limit and what is known about it now.
#[derive(Clone, Debug)]
pub struct QosView {
    pub limit: QosLimit,
    /// Plain-English state: active, off, or what went wrong.
    pub status: String,
    pub problem: bool,
}

/// "512 Kbps", "5 Mbps", "1.5 Gbps".
pub fn fmt_rate(kbps: u32) -> String {
    let trim = |v: f64| if v.fract() == 0.0 { format!("{v:.0}") } else { format!("{v:.1}") };
    if kbps >= 1_000_000 {
        format!("{} Gbps", trim(f64::from(kbps) / 1_000_000.0))
    } else if kbps >= 1000 {
        format!("{} Mbps", trim(f64::from(kbps) / 1000.0))
    } else {
        format!("{kbps} Kbps")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(id: u32, kbps: u32, program: &str) -> QosLimit {
        QosLimit::upload(id, true, program, kbps)
    }

    #[test]
    fn stores_and_reads_back() {
        let v = vec![limit(1, 5000, r"C:\Apps\a b\game.exe"), QosLimit { enabled: false, ..limit(2, 64, r"C:\x.exe") }];
        assert_eq!(decode_all(&encode_all(&v)), v);
        assert!(decode_all("0\t1\t5\tx\nnope\n3\t1\tabc\tx").is_empty(), "a zero id, junk and a non-number rate are all dropped");
    }

    #[test]
    fn priority_round_trips_allows_no_caps_and_maps_to_dscp() {
        let high = QosLimit { priority: Priority::High, ..limit(6, 0, r"C:\Zoom.exe") };
        let low = QosLimit { priority: Priority::Low, ..limit(7, 500, r"C:\sync.exe") };
        assert_eq!(decode_all(&encode_all(&[high.clone(), low.clone()])), vec![high.clone(), low]);
        assert!(high.problem().is_none(), "a priority needs no rate");
        assert!(limit(6, 0, r"C:\Zoom.exe").problem().is_some(), "a plain limit still does");
        assert_eq!((Priority::High.dscp(), Priority::Normal.dscp(), Priority::Low.dscp()), (Some(46), None, Some(8)));
        assert_eq!(high.rate_text(false), "High priority · no cap");
    }

    #[test]
    fn directions_round_trip_and_old_lines_still_read() {
        let both = QosLimit { dir: LimitDir::Both, down_kbps: 20_000, ..limit(4, 5000, r"C:\a b\x.exe") };
        let down = QosLimit { dir: LimitDir::Down, kbps: 0, down_kbps: 300, ..limit(5, 0, r"C:\y.exe") };
        assert_eq!(decode_all(&encode_all(&[both.clone(), down.clone()])), vec![both.clone(), down.clone()]);
        assert_eq!(limit(1, 5000, r"C:\a.exe").encode(), "1\t1\t5000\tC:\\a.exe", "upload-only keeps the old line");
        assert_eq!(decode_all("7\t1\t64\tC:\\old.exe"), vec![limit(7, 64, r"C:\old.exe")]);
        assert!(both.problem().is_none() && down.problem().is_none(), "an upload rate isn't needed for a download-only limit");
        assert!(QosLimit { down_kbps: 1, ..both.clone() }.problem().is_some(), "the download rate is checked when it applies");
        assert!(QosLimit { dir: LimitDir::Up, down_kbps: 1, ..both }.problem().is_none(), "and ignored when it doesn't");
        assert_eq!(down.rate_text(false), "Down 300 Kbps");
    }

    #[test]
    fn simulated_conditions_need_no_rate_and_end_by_themselves() {
        let sim = QosLimit { delay_ms: 120, loss_pct: 5, sim_until: 1000, ..QosLimit::upload(1, true, r"C:\a.exe", 0) };
        assert!(sim.problem().is_none(), "a rate of 0 is fine while simulating");
        assert_eq!(sim.rate_text(true), "Up no cap · +120 ms · 5% loss");
        assert!(sim.simulating(999) && !sim.simulating(1000));
        assert!(QosLimit::upload(1, true, r"C:\a.exe", 0).problem().is_some(), "nothing to do without a rate or a simulation");
        assert!(QosLimit { delay_ms: 6000, ..sim.clone() }.problem().is_some() && QosLimit { loss_pct: 95, ..sim.clone() }.problem().is_some());
        assert_eq!(decode_all(&encode_all(std::slice::from_ref(&sim))), vec![sim]);
    }

    #[test]
    fn policy_names_carry_the_id_and_exe() {
        let l = limit(12, 100, r"C:\Apps\game.exe");
        assert_eq!(l.policy_name(), "RustWarden QoS 12 game.exe");
        assert!(l.policy_name().starts_with(PREFIX));
    }

    #[test]
    fn limits_are_checked() {
        assert!(limit(1, 5000, r"C:\a.exe").problem().is_none());
        assert!(limit(1, 5000, " ").problem().is_some());
        assert!(limit(1, 7, r"C:\a.exe").problem().is_some());
        assert!(limit(1, MAX_KBPS + 1, r"C:\a.exe").problem().is_some());
        assert!(limit(1, 5000, "C:\\a\n.exe").problem().is_some());
        assert_eq!(limit(1, 2000, r"C:\a.exe").bits_per_second(), 2_000_000);
    }

    #[test]
    fn rates_read_naturally() {
        assert_eq!(fmt_rate(512), "512 Kbps");
        assert_eq!(fmt_rate(5000), "5 Mbps");
        assert_eq!(fmt_rate(1500), "1.5 Mbps");
        assert_eq!(fmt_rate(2_000_000), "2 Gbps");
    }
}
