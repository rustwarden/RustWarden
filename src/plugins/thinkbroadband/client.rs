//! Talks to thinkbroadband through the `browser` helper (WebView2), which keeps the sign-in.
//! Sign-in is the site's plain form (CSRF `_token`, `username`, `password`); the data is the
//! daily XML download of each monitor.

use super::browser::{self, HOST};
use super::{Monitor, Sample};

const BASE: &str = "/my-profile/broadband-quality-monitor";

/// The value of ` name="..."` inside one tag.
fn attr<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let start = text.find(&key)? + key.len();
    Some(&text[start..start + text[start..].find('"')?])
}

fn day_url(id: u32, day: &str) -> String {
    format!("{HOST}{BASE}/download-xml/{id}/{day}")
}

/// The monitors on the account, named from today's XML. `Err(NEED_LOGIN)` when signed out.
pub fn list_monitors() -> Result<Vec<Monitor>, String> {
    let page = browser::fetch(&[format!("{HOST}{BASE}")])?.remove(0).1;
    let mut ids: Vec<u32> = Vec::new();
    for part in page.split("broadband-quality-monitor/view/").skip(1) {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(id) = digits.parse()
            && !ids.contains(&id)
        {
            ids.push(id);
        }
    }
    let today = date(crate::clock::now_unix());
    let xml = browser::fetch(&ids.iter().map(|id| day_url(*id, &today)).collect::<Vec<_>>())?;
    Ok(ids
        .into_iter()
        .zip(xml)
        .map(|(id, (_, body))| {
            let name = parse_xml(&body).0;
            Monitor { id, name: if name.is_empty() { format!("Monitor {id}") } else { name } }
        })
        .collect())
}

/// Downloads UTC days (`YYYY-MM-DD`) of monitors in one browser run: the result of each request, in order.
/// Each day stands alone, so a day that isn't published yet (just after midnight) doesn't lose the others.
pub fn fetch_days(requests: &[(u32, String)]) -> Result<Vec<Result<Vec<Sample>, String>>, String> {
    let answers = browser::fetch(&requests.iter().map(|(id, day)| day_url(*id, day)).collect::<Vec<_>>())?;
    Ok(answers
        .into_iter()
        .zip(requests)
        .map(
            |((code, body), (id, day))| {
                if code == 200 && body.trim_start().starts_with("<?xml") { Ok(parse_xml(&body).1) } else { Err(format!("thinkbroadband answered HTTP {code} for monitor {id} on {day}.")) }
            },
        )
        .collect())
}

/// The site backslash-escapes quotes in names (`Orbi\'s`); drop those backslashes.
pub fn unescape(name: &str) -> String {
    let mut out = String::new();
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        out.push(if c == '\\' { chars.next().unwrap_or(c) } else { c });
    }
    out
}

/// `<graph name=..>` then one `<record timestamp sent-polls lost-polls min/ave/max-latency-ns/>` per poll round.
pub fn parse_xml(text: &str) -> (String, Vec<Sample>) {
    let name = text.split("<graph").nth(1).and_then(|t| attr(t.split('>').next()?, "name")).unwrap_or("").to_owned();
    let name = unescape(&name);
    let samples = text
        .split("<record")
        .skip(1)
        .filter_map(|r| {
            let r = r.split("/>").next()?;
            let num = |k| attr(r, k)?.parse::<f64>().ok();
            let sent = num("sent-polls")?;
            let ms = |k| Some((num(k)? / 1e6) as f32);
            Some(Sample {
                ts: parse_iso(attr(r, "timestamp")?)?,
                min: ms("min-latency-ns")?,
                avg: ms("ave-latency-ns")?,
                max: ms("max-latency-ns")?,
                loss: if sent > 0.0 { (num("lost-polls").unwrap_or(0.0) / sent * 100.0) as f32 } else { 0.0 },
            })
        })
        .collect();
    (name, samples)
}

/// "2026-10-28T00:01:40Z" to unix seconds.
fn parse_iso(s: &str) -> Option<i64> {
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let days = crate::clock::days_from_civil(n(0..4)?, n(5..7)? as u32, n(8..10)? as u32);
    Some(days * 86_400 + n(11..13)? * 3600 + n(14..16)? * 60 + n(17..19)?)
}

/// UTC `YYYY-MM-DD` of a unix time.
pub fn date(ts: i64) -> String {
    let (y, m, d) = crate::clock::civil_from_days(ts.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<cqm generated="2026-10-29T00:06:50Z">
  <graph name="LorenteNET" period-start="2026-10-28T00:00:00Z">
    <record timestamp="2026-10-28T00:00:00Z" sent-polls="100" lost-polls="0" rejected-polls="0" min-latency-ns="8261000" ave-latency-ns="14030000" max-latency-ns="20280000" score="1"/>
    <record timestamp="2026-10-28T00:01:40Z" sent-polls="100" lost-polls="4" rejected-polls="0" min-latency-ns="10200000" ave-latency-ns="13740000" max-latency-ns="26660000" score="1"/>
    <record timestamp="2026-10-28T00:03:20Z" sent-polls="100" min-latency-ns="1000000" ave-latency-ns="2000000" max-latency-ns="3000000"/>
  </graph></cqm>"#;

    #[test]
    fn parses_records() {
        let (name, s) = parse_xml(XML);
        assert_eq!(name, "LorenteNET");
        assert_eq!(s.len(), 3); // the last has no lost-polls: none lost
        assert_eq!(s[2].loss, 0.0);
        assert_eq!(s[0].ts, 1_793_145_600); // 2026-10-28T00:00:00Z
        assert_eq!(s[1].ts - s[0].ts, 100);
        assert!((s[0].min - 8.261).abs() < 1e-3 && (s[1].max - 26.66).abs() < 1e-3);
        assert_eq!((s[0].loss, s[1].loss), (0.0, 4.0));
        assert_eq!(date(s[0].ts), "2026-10-28");
        assert_eq!(unescape(r"Orbi\'s at 52A"), "Orbi's at 52A");
    }
}
