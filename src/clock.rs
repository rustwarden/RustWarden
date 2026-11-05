//! Wall-clock helpers: unix time, local offset and the short labels the UI shows.

use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

pub fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Seconds to add to UTC to get local time at `ts`, with the DST rule in force at that moment
/// (not today's, which would put history from the other side of a clock change an hour out).
pub fn local_offset_at(ts: i64) -> i64 {
    let ticks = (ts + 11_644_473_600).max(0) as u64 * 10_000_000; // unix seconds to 100 ns since 1601
    let ft = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
    let (mut utc, mut local) = (SYSTEMTIME::default(), SYSTEMTIME::default());
    let ok = unsafe { FileTimeToSystemTime(&ft, &mut utc).is_ok() && SystemTimeToTzSpecificLocalTime(None, &utc, &mut local).is_ok() };
    if !ok {
        return 0;
    }
    let secs = |t: &SYSTEMTIME| days_from_civil(i64::from(t.wYear), u32::from(t.wMonth), u32::from(t.wDay)) * 86_400 + i64::from(t.wHour) * 3600 + i64::from(t.wMinute) * 60 + i64::from(t.wSecond);
    secs(&local) - secs(&utc)
}

/// Local seconds since midnight (a unix-epoch-style count shifted by the offset).
pub fn to_local(ts: i64) -> i64 {
    ts + local_offset_at(ts)
}

pub fn minute_of_day(ts: i64) -> f32 {
    (to_local(ts).rem_euclid(86_400)) as f32 / 60.0
}

/// (year, month 1..=12, day 1..=31) of a day count since 1970-01-01 (Hinnant's algorithm).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// "8:58 pm"
pub fn fmt_time_lower(ts: i64) -> String {
    crate::util::fmt_clock_secs(to_local(ts), false).to_lowercase()
}

/// How long until something `secs` away: "in 45 s", "in 4 min", "in 1 h 5 min"; "now" when it is due.
pub fn in_words(secs: i64) -> String {
    if secs <= 0 {
        return "now".into();
    }
    if secs < 60 {
        return format!("in {secs} s");
    }
    let mins = (secs + 59) / 60;
    match (mins / 60, mins % 60) {
        (0, m) => format!("in {m} min"),
        (h, 0) => format!("in {h} h"),
        (h, m) => format!("in {h} h {m} min"),
    }
}

/// "Today", "Yesterday", or "25 Oct".
pub fn day_label(ts: i64, now: i64) -> String {
    let (a, b) = (to_local(ts).div_euclid(86_400), to_local(now).div_euclid(86_400));
    match b - a {
        0 => "Today".into(),
        1 => "Yesterday".into(),
        _ => {
            let (_, m, d) = civil_from_days(a);
            format!("{d} {}", MONTHS[m as usize - 1])
        }
    }
}

/// "25 Oct 2026"
pub fn fmt_date(ts: i64) -> String {
    let (y, m, d) = civil_from_days(to_local(ts).div_euclid(86_400));
    format!("{d} {} {y}", MONTHS[m as usize - 1])
}

/// "October 2026" for a calendar header.
pub fn month_name(y: i64, m: u32) -> String {
    const LONG: [&str; 12] = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    format!("{} {y}", LONG[m as usize - 1])
}

/// "25 Oct, 2026, 3:47 PM"
pub fn fmt_stamp(ts: i64) -> String {
    let local = to_local(ts);
    let (y, m, d) = civil_from_days(local.div_euclid(86_400));
    format!("{d} {}, {y}, {}", MONTHS[m as usize - 1], crate::util::fmt_clock_secs(local, false))
}

/// "20261025-154705", for file names.
pub fn file_stamp() -> String {
    let local = to_local(now_unix());
    let (y, m, d) = civil_from_days(local.div_euclid(86_400));
    let s = local.rem_euclid(86_400);
    format!("{y}{m:02}{d:02}-{:02}{:02}{:02}", s / 3600, s / 60 % 60, s % 60)
}

/// Day count since 1970-01-01 of a civil date (inverse of [`civil_from_days`]).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Start (unix seconds) of the local calendar day, week (Monday) or month containing `ts`.
pub fn period_start(ts: i64, days_back: PeriodKind) -> i64 {
    let local_day = to_local(ts).div_euclid(86_400);
    let first_day = match days_back {
        PeriodKind::Day => local_day,
        PeriodKind::Week => local_day - (local_day + 3).rem_euclid(7),
        PeriodKind::Month => {
            let (y, m, _) = civil_from_days(local_day);
            days_from_civil(y, m, 1)
        }
    };
    // The offset at local midnight itself, which may differ from the one at `ts` when a clock change fell in between.
    let local_midnight = first_day * 86_400;
    local_midnight - local_offset_at(local_midnight - local_offset_at(ts))
}

#[derive(Clone, Copy)]
pub enum PeriodKind {
    Day,
    Week,
    Month,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn countdown_wording() {
        assert_eq!(in_words(-5), "now");
        assert_eq!(in_words(45), "in 45 s");
        assert_eq!(in_words(60), "in 1 min");
        assert_eq!(in_words(61), "in 2 min");
        assert_eq!(in_words(300), "in 5 min");
        assert_eq!(in_words(3600), "in 1 h");
        assert_eq!(in_words(3900), "in 1 h 5 min");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_751), (2026, 10, 25));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(days_from_civil(2026, 10, 25), 20_751);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
    }

    #[test]
    fn stamps_use_the_twelve_hour_clock() {
        assert_eq!(crate::util::fmt_clock_secs(0, false), "12:00 AM");
        assert_eq!(crate::util::fmt_clock_secs(12 * 3600 + 5 * 60, false), "12:05 PM");
        assert_eq!(crate::util::fmt_clock_secs(20 * 3600 + 58 * 60, false), "8:58 PM");
    }

    #[test]
    fn offset_is_a_whole_number_of_quarter_hours_in_any_season() {
        for ts in [1_767_225_600, 1_782_864_000, 1_792_800_000] {
            assert_eq!(local_offset_at(ts) % 900, 0);
            assert!(local_offset_at(ts).abs() <= 14 * 3600);
        }
    }
}
