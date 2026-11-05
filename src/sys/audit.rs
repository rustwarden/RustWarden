//! Blocked connections while RustWarden is closed. With "Keep blocking when RustWarden is closed" the
//! default-deny stays in force after exit, and Windows records each stopped connection as Security
//! event 5157 once the "Filtering Platform Connection" failure audit is on. The next start reads
//! those events back so every program that tried meanwhile can be asked about.

use super::wfp::Blocked;
use std::net::IpAddr;
use std::os::windows::process::CommandExt;

/// The "Filtering Platform Connection" audit subcategory (a GUID, so it works in every language).
const SUBCATEGORY: &str = "{0CCE9226-69AE-11D9-BED3-505054503030}";

fn auditpol(args: &[&str]) -> Result<String, String> {
    let out = super::tool("auditpol.exe").args(args).creation_flags(super::NO_WINDOW).output().map_err(|e| format!("couldn't run auditpol ({e})"))?;
    if out.status.success() { Ok(String::from_utf8_lossy(&out.stdout).into_owned()) } else { Err(String::from_utf8_lossy(&out.stdout).trim().to_owned()) }
}

/// Whether failures of the subcategory are audited. `None` when the answer can't be read (e.g. a translated
/// Windows), which callers treat as "on" so RustWarden never switches off an audit it may not have enabled.
pub fn failure_audit_on() -> Option<bool> {
    let text = auditpol(&["/get", &format!("/subcategory:{SUBCATEGORY}"), "/r"]).ok()?.to_lowercase();
    if text.contains("failure") {
        Some(true)
    } else if text.contains("no auditing") {
        Some(false)
    } else {
        None
    }
}

pub fn set_failure_audit(on: bool) -> Result<(), String> {
    auditpol(&["/set", &format!("/subcategory:{SUBCATEGORY}"), &format!("/failure:{}", if on { "enable" } else { "disable" })]).map(|_| ())
}

/// `2026-10-29T10:00:00.000Z` for a unix time.
fn iso(ts: i64) -> String {
    let (y, m, d) = crate::clock::civil_from_days(ts.div_euclid(86_400));
    let s = ts.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z", s / 3600, s / 60 % 60, s % 60)
}

/// Outbound connections Windows stopped since `since` (unix time), oldest first. Needs administrator rights.
pub fn blocked_since(since: i64) -> Result<Vec<Blocked>, String> {
    let query = format!("*[System[(EventID=5157) and TimeCreated[@SystemTime>='{}']]]", iso(since - 1));
    let out = super::tool("wevtutil.exe")
        .args(["qe", "Security", &format!("/q:{query}"), "/f:xml", "/rd:false", "/c:5000"])
        .creation_flags(super::NO_WINDOW)
        .output()
        .map_err(|e| format!("couldn't run wevtutil ({e})"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
    }
    Ok(parse_events(&String::from_utf8_lossy(&out.stdout)))
}

/// The text of `<Data Name='name'>…</Data>` in one event.
fn data<'a>(event: &'a str, name: &str) -> Option<&'a str> {
    let at = event.find(&format!("Name='{name}'")).or_else(|| event.find(&format!("Name=\"{name}\"")))?;
    let rest = &event[at..];
    let start = rest.find('>')? + 1;
    let end = rest[start..].find('<')?;
    Some(&rest[start..start + end])
}

fn parse_events(xml: &str) -> Vec<Blocked> {
    xml.split("<Event ")
        .skip(1)
        .filter_map(|e| {
            // %%14593 is "Outbound"; inbound drops aren't what Prompt is about.
            if data(e, "Direction")? != "%%14593" {
                return None;
            }
            let remote: IpAddr = data(e, "DestAddress")?.split('%').next()?.parse().ok()?;
            let proto = data(e, "Protocol").and_then(|p| p.trim().parse().ok()).unwrap_or(0);
            Some(Blocked { app: data(e, "Application")?.to_owned(), remote, proto })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_time() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(1_793_263_445), "2026-10-29T08:44:05.000Z");
    }

    #[test]
    fn reads_outbound_drops_only() {
        let ev = |dir: &str, dest: &str| {
            format!(
                "<Event xmlns='x'><System><EventID>5157</EventID></System><EventData><Data Name='Application'>\\device\\harddiskvolume3\\a\\b.exe</Data><Data Name='Direction'>{dir}</Data><Data Name='DestAddress'>{dest}</Data><Data Name='Protocol'>6</Data></EventData></Event>"
            )
        };
        let xml = format!("{}{}{}", ev("%%14593", "93.184.216.34"), ev("%%14592", "1.2.3.4"), ev("%%14593", "fe80::1%12"));
        let got = parse_events(&xml);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], Blocked { app: r"\device\harddiskvolume3\a\b.exe".into(), remote: "93.184.216.34".parse().unwrap(), proto: 6 });
        assert_eq!(got[1].remote, "fe80::1".parse::<IpAddr>().unwrap());
    }
}
