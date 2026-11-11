//! Who makes the third-party files RustWarden downloads, and the small attribution line shown wherever
//! one can be downloaded: databases, blocklists, the driver and helper programs. The sources are data,
//! so every place names them the same way and the tests can check them.

use crate::theme;
use egui::{RichText, Ui};

/// One third-party source: what it is, who publishes it, its licence (when it has a fixed one) and where to read more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub name: &'static str,
    pub by: &'static str,
    pub licence: Option<(&'static str, &'static str)>,
    pub url: &'static str,
}

/// DB-IP's free Lite databases (country, city, ASN). CC BY 4.0 asks for this credit wherever they are used.
pub const DBIP: Source = Source { name: "IP Geolocation by DB-IP", by: "db-ip.com", licence: Some(("CC BY 4.0", "https://creativecommons.org/licenses/by/4.0/")), url: "https://db-ip.com" };

pub const WINDIVERT: Source =
    Source { name: "WinDivert", by: "basil00", licence: Some(("LGPL-3.0 or GPL-2.0", "https://github.com/basil00/WinDivert/blob/master/LICENSE")), url: "https://reqrypt.org/windivert.html" };

/// Ookla's speedtest-cli, run by the Speedtest plugin. Its results are shown with Ookla's credit.
pub const SPEEDTEST: Source =
    Source { name: "Speedtest® by Ookla®", by: "Ookla, LLC", licence: Some(("End User License Agreement", "https://www.speedtest.net/about/eula")), url: "https://www.speedtest.net/apps/cli" };

/// Blocklists with a known publisher, matched on their download address. Anything else is credited to its host.
const FEEDS: &[(&str, Source)] = &[
    ("feodotracker.abuse.ch", Source { name: "Feodo Tracker", by: "abuse.ch", licence: None, url: "https://feodotracker.abuse.ch" }),
    ("urlhaus.abuse.ch", Source { name: "URLhaus", by: "abuse.ch", licence: None, url: "https://urlhaus.abuse.ch" }),
    ("raw.githubusercontent.com/stamparm/ipsum", Source { name: "IPsum", by: "Miroslav Štampar", licence: None, url: "https://github.com/stamparm/ipsum" }),
    (
        "malware-filter.gitlab.io/malware-filter/urlhaus-filter",
        Source { name: "URLhaus Malicious Hosts Blocklist", by: "malware-filter (from abuse.ch URLhaus data)", licence: None, url: "https://gitlab.com/malware-filter/urlhaus-filter" },
    ),
];

/// Who publishes the list at `url`: a known feed, or the address's host (None for a line that isn't an https/http address).
pub fn feed_source(url: &str) -> Option<(String, String)> {
    let url = url.trim();
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    if let Some((_, s)) = FEEDS.iter().find(|(prefix, _)| rest.starts_with(prefix)) {
        return Some((format!("{} by {}", s.name, s.by), s.url.to_owned()));
    }
    let host = rest.split(['/', '?', '#']).next().filter(|h| !h.is_empty())?;
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    Some((host.to_owned(), format!("https://{host}")))
}

/// The sources of the lists in `feeds` (one address per line), each once, in order.
pub fn feed_sources(feeds: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for s in feeds.lines().filter_map(feed_source) {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// A small dim line that wraps to the space it has; `parts` are plain text, or (text, link) when a link is given.
pub fn line(ui: &mut Ui, parts: &[(&str, Option<&str>)]) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 2.0);
        for (text, url) in parts {
            let rt = RichText::new(*text).font(theme::font(12.5));
            match url {
                Some(u) => {
                    if ui.link(rt).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(*u).clicked() {
                        crate::sys::open_url(u);
                    }
                }
                None => {
                    ui.label(rt.color(theme::text_dim()));
                }
            }
        }
    });
}

/// "Source: <name> (<by>), <licence>." with links.
pub fn source(ui: &mut Ui, s: &Source) {
    let by = format!(" ({}), ", s.by);
    match s.licence {
        Some((licence, licence_url)) => line(ui, &[("Source: ", None), (s.name, Some(s.url)), (&by, None), (licence, Some(licence_url)), (".", None)]),
        None => line(ui, &[("Source: ", None), (s.name, Some(s.url)), (&format!(" ({}).", s.by), None)]),
    }
}

/// "Lists from: A, B. Each list is used under its publisher's terms." for the blocklists in `feeds`.
pub fn feeds(ui: &mut Ui, feeds: &str) {
    let sources = feed_sources(feeds);
    if sources.is_empty() {
        return;
    }
    let mut parts: Vec<(&str, Option<&str>)> = vec![("Lists from: ", None)];
    for (i, (name, url)) in sources.iter().enumerate() {
        if i > 0 {
            parts.push((", ", None));
        }
        parts.push((name, Some(url)));
    }
    parts.push((". Each list belongs to its publisher and is used under their terms.", None));
    line(ui, &parts);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_feeds_are_credited_to_their_publisher() {
        let (name, url) = feed_source("https://feodotracker.abuse.ch/downloads/ipblocklist.txt").unwrap();
        assert_eq!((name.as_str(), url.as_str()), ("Feodo Tracker by abuse.ch", "https://feodotracker.abuse.ch"));
        assert_eq!(feed_source("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt").unwrap().0, "IPsum by Miroslav Štampar");
        assert!(feed_source("https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt").unwrap().0.starts_with("URLhaus Malicious Hosts Blocklist"));
    }

    #[test]
    fn other_feeds_are_credited_to_their_host() {
        assert_eq!(feed_source("https://lists.example.org/bad.txt?key=1").unwrap(), ("lists.example.org".into(), "https://lists.example.org".into()));
        assert_eq!(feed_source("https://user:pw@lists.example.org/x").unwrap().0, "lists.example.org", "credentials never show");
        assert_eq!(feed_source("  "), None);
        assert_eq!(feed_source("not a url"), None);
    }

    #[test]
    fn sources_are_listed_once_in_order() {
        let feeds = "https://feodotracker.abuse.ch/a.txt\nhttps://b.example/x\n\nhttps://feodotracker.abuse.ch/b.txt";
        let names: Vec<String> = feed_sources(feeds).into_iter().map(|s| s.0).collect();
        assert_eq!(names, vec!["Feodo Tracker by abuse.ch".to_string(), "b.example".to_string()]);
    }

    #[test]
    fn the_default_lists_all_have_a_named_publisher() {
        let s = crate::settings::Settings::default();
        for line in s.threat_feeds.lines().chain(s.dns_block_feeds.lines()).filter(|l| !l.trim().is_empty()) {
            let (name, _) = feed_source(line).unwrap();
            assert!(name.contains(" by "), "{line} has no named publisher");
        }
    }
}
