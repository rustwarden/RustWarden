//! Two watchers for Driver mode's listener, as plain bookkeeping the listener feeds: a second DHCP server answering on
//! the network, and a program that names itself like a web browser but speaks TLS like a command-line tool.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

// ---- DHCP ----

/// A DHCP reply, reduced to what the watcher needs.
#[derive(Debug, PartialEq)]
pub struct Dhcp {
    /// 2 = OFFER, 5 = ACK, 6 = NAK.
    pub msg_type: u8,
    /// The server's own identifier (option 54), when it sent one.
    pub server: Option<Ipv4Addr>,
}

/// Reads a DHCP/BOOTP reply (the UDP payload of a packet from port 67 to 68). `None` for requests and anything else.
pub fn dhcp_reply(d: &[u8]) -> Option<Dhcp> {
    if d.len() < 241 || d[0] != 2 || d[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let (mut at, mut msg_type, mut server) = (240, 0, None);
    while at < d.len() {
        match d[at] {
            0 => at += 1,
            255 => break,
            code => {
                let len = usize::from(*d.get(at + 1)?);
                let body = d.get(at + 2..at + 2 + len)?;
                match (code, len) {
                    (53, 1) => msg_type = body[0],
                    (54, 4) => server = Some(Ipv4Addr::new(body[0], body[1], body[2], body[3])),
                    _ => {}
                }
                at += 2 + len;
            }
        }
    }
    (msg_type != 0).then_some(Dhcp { msg_type, server })
}

/// How long a server stays "recently seen".
const SERVER_WINDOW: i64 = 900;
/// A second server is reported at most this often.
const REPORT_EVERY: i64 = 3600;

/// Servers that answered DHCP lately. More than one on a network is unusual at home: a rogue one can hand out a wrong
/// gateway or DNS server.
#[derive(Default)]
pub struct DhcpWatch {
    seen: HashMap<Ipv4Addr, i64>,
    reported: i64,
}

impl DhcpWatch {
    /// Notes an OFFER or ACK from `server` at `now`; returns the servers seen (sorted) when there are two or more.
    pub fn note(&mut self, server: Ipv4Addr, now: i64) -> Option<Vec<Ipv4Addr>> {
        self.seen.retain(|_, at| now - *at < SERVER_WINDOW);
        self.seen.insert(server, now);
        if self.seen.len() < 2 || (self.reported != 0 && now - self.reported < REPORT_EVERY) {
            return None;
        }
        self.reported = now;
        let mut all: Vec<Ipv4Addr> = self.seen.keys().copied().collect();
        all.sort();
        Some(all)
    }
}

// ---- TLS fingerprints ----

/// Programs people call a web browser.
const BROWSERS: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe", "browser.exe", "arc.exe"];
/// Command-line tools and runtimes whose TLS hello is not a browser's. (Electron apps share Chrome's, so they are not here.)
const TOOLS: &[&str] = &[
    "curl.exe",
    "wget.exe",
    "python.exe",
    "pythonw.exe",
    "py.exe",
    "powershell.exe",
    "pwsh.exe",
    "node.exe",
    "java.exe",
    "javaw.exe",
    "ruby.exe",
    "perl.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "git-remote-https.exe",
];

pub fn is_browser(program: &str) -> bool {
    BROWSERS.contains(&program.to_ascii_lowercase().as_str())
}

/// A browser-named program whose fingerprint a command-line tool also uses.
#[derive(Debug, PartialEq)]
pub struct Mismatch {
    pub program: String,
    pub print: String,
    pub looks_like: String,
}

const MAX_PRINTS: usize = 5000;

/// Which tools have been seen with which fingerprints, and which browser/tool pairs were already reported.
#[derive(Default)]
pub struct Prints {
    tools: HashMap<String, HashSet<String>>,
    browsers: HashMap<String, HashSet<String>>,
    reported: HashSet<(String, String)>,
}

impl Prints {
    /// Notes that `program` opened a TLS connection with `print`. Returns a mismatch the first time one is clear.
    pub fn note(&mut self, program: &str, print: &str) -> Option<Mismatch> {
        let program = program.to_ascii_lowercase();
        if self.tools.len() + self.browsers.len() > MAX_PRINTS {
            *self = Self::default();
        }
        if TOOLS.contains(&program.as_str()) {
            self.tools.entry(print.to_owned()).or_default().insert(program.clone());
            // A browser that was seen first with this print is judged now that the tool has shown up.
            let browser = self.browsers.get(print)?.iter().find(|b| !self.reported.contains(&((*b).clone(), program.clone())))?.clone();
            return self.flag(&browser, print, &program);
        }
        if !is_browser(&program) {
            return None;
        }
        self.browsers.entry(print.to_owned()).or_default().insert(program.clone());
        let tool = self.tools.get(print)?.iter().next()?.clone();
        self.flag(&program, print, &tool)
    }

    fn flag(&mut self, browser: &str, print: &str, tool: &str) -> Option<Mismatch> {
        self.reported.insert((browser.to_owned(), tool.to_owned())).then(|| Mismatch { program: browser.to_owned(), print: print.to_owned(), looks_like: tool.to_owned() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(msg_type: u8, server: Option<[u8; 4]>) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 2;
        p[236..240].copy_from_slice(&[99, 130, 83, 99]);
        p.extend([53, 1, msg_type]);
        if let Some(s) = server {
            p.extend([54, 4]);
            p.extend(s);
        }
        p.extend([0, 255]);
        p
    }

    #[test]
    fn reads_the_server_of_an_offer_and_refuses_requests() {
        assert_eq!(dhcp_reply(&reply(2, Some([192, 168, 1, 1]))), Some(Dhcp { msg_type: 2, server: Some(Ipv4Addr::new(192, 168, 1, 1)) }));
        assert_eq!(dhcp_reply(&reply(5, None)).unwrap().server, None);
        let mut request = reply(1, None);
        request[0] = 1;
        assert_eq!(dhcp_reply(&request), None);
        let mut no_cookie = reply(2, None);
        no_cookie[236] = 0;
        assert_eq!(dhcp_reply(&no_cookie), None);
        let full = reply(2, Some([10, 0, 0, 1]));
        for cut in 0..full.len() {
            let _ = dhcp_reply(&full[..cut]);
        }
    }

    #[test]
    fn a_second_server_is_reported_once_an_hour() {
        let (a, b) = (Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 77));
        let mut w = DhcpWatch::default();
        assert_eq!(w.note(a, 100), None);
        assert_eq!(w.note(a, 200), None, "the same server again is fine");
        assert_eq!(w.note(b, 300), Some(vec![a, b]));
        assert_eq!(w.note(b, 400), None, "reported already");
        assert_eq!(w.note(b, 300 + REPORT_EVERY + 1), None, "the first server has been quiet past the window");
    }

    #[test]
    fn a_browser_using_a_tools_fingerprint_is_flagged_either_way_round() {
        let mut p = Prints::default();
        assert!(p.note("curl.exe", "t13d").is_none());
        let m = p.note("Chrome.exe", "t13d").expect("same print as curl");
        assert_eq!((m.program.as_str(), m.looks_like.as_str()), ("chrome.exe", "curl.exe"));
        assert!(p.note("chrome.exe", "t13d").is_none(), "once is enough");
        let mut p = Prints::default();
        assert!(p.note("msedge.exe", "abc").is_none());
        assert!(p.note("python.exe", "abc").is_some(), "the tool turning up later still counts");
    }

    #[test]
    fn electron_apps_and_other_prints_are_left_alone() {
        let mut p = Prints::default();
        assert!(p.note("slack.exe", "t13d").is_none());
        assert!(p.note("chrome.exe", "t13d").is_none(), "an app that shares Chrome's library is not a tool");
        assert!(p.note("curl.exe", "other").is_none());
        assert!(p.note("firefox.exe", "t13d").is_none());
        assert!(is_browser("MSEdge.exe") && !is_browser("curl.exe"));
    }
}
