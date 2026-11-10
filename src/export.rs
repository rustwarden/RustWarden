//! CSV and JSON writers for history exports. Pure functions: the caller gathers the rows and writes the file.

use serde::Serialize;

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct TrafficRow {
    /// Unix seconds, the start of the ten-minute bucket.
    pub ts: i64,
    pub app: String,
    pub remote: String,
    pub host: String,
    pub country: String,
    pub down: u64,
    pub up: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct AlertRow {
    pub ts: i64,
    /// The alert kind's stable key, such as `new_device`, not its label.
    pub kind: String,
    pub app: String,
    pub text: String,
    pub target: String,
    pub country: String,
    pub important: bool,
}

/// Quoted so values with commas, quotes or line breaks stay one cell. A value that starts like a spreadsheet formula
/// (device and host names come from the network) gets a `'` in front so Excel shows it as text.
fn cell(s: &str) -> String {
    let guard = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { "'" } else { "" };
    format!("\"{guard}{}\"", s.replace('"', "\"\""))
}

pub fn traffic_csv(rows: &[TrafficRow]) -> String {
    let mut csv = String::from("\u{feff}Time (unix),App,Remote,Host,Country,Downloaded (bytes),Uploaded (bytes)\r\n");
    for r in rows {
        csv += &format!("{},{},{},{},{},{},{}\r\n", r.ts, cell(&r.app), cell(&r.remote), cell(&r.host), cell(&r.country), r.down, r.up);
    }
    csv
}

pub fn alerts_csv(rows: &[AlertRow]) -> String {
    let mut csv = String::from("\u{feff}Time (unix),Kind,App,Text,Target,Country,Important\r\n");
    for r in rows {
        csv += &format!("{},{},{},{},{},{},{}\r\n", r.ts, cell(&r.kind), cell(&r.app), cell(&r.text), cell(&r.target), cell(&r.country), r.important);
    }
    csv
}

pub fn json<T: Serialize>(rows: &[T]) -> String {
    // Plain structs of strings and numbers always serialize.
    serde_json::to_string_pretty(rows).expect("plain structs always serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_keeps_awkward_values_in_one_cell() {
        let rows = [AlertRow { ts: 5, kind: "arp".into(), app: "a, \"b\"".into(), text: "line\nbreak".into(), target: String::new(), country: "US".into(), important: true }];
        let csv = alerts_csv(&rows);
        assert!(csv.starts_with('\u{feff}'));
        assert!(csv.contains("5,\"arp\",\"a, \"\"b\"\"\",\"line\nbreak\",\"\",\"US\",true\r\n"));
    }

    #[test]
    fn a_value_that_looks_like_a_formula_is_made_text() {
        let rows = [TrafficRow { app: "=HYPERLINK(\"http://x\")".into(), host: "-1+1".into(), ..Default::default() }];
        let csv = traffic_csv(&rows);
        assert!(csv.contains("\"'=HYPERLINK(\"\"http://x\"\")\",\"\",\"'-1+1\""), "{csv}");
    }

    #[test]
    fn traffic_csv_has_one_line_per_row_after_the_header() {
        let rows = [TrafficRow { ts: 600, app: "curl".into(), remote: "8.8.8.8".into(), host: "dns.google".into(), country: "US".into(), down: 100, up: 7 }];
        let csv = traffic_csv(&rows);
        assert_eq!(csv.lines().count(), 2);
        assert!(csv.ends_with("600,\"curl\",\"8.8.8.8\",\"dns.google\",\"US\",100,7\r\n"));
    }

    #[test]
    fn json_uses_field_names() {
        let text = json(&[TrafficRow { ts: 1, app: "x".into(), ..Default::default() }]);
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!((back[0]["ts"].as_i64(), back[0]["app"].as_str(), back[0]["down"].as_u64()), (Some(1), Some("x"), Some(0)));
    }
}
