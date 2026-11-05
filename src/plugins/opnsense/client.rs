//! Talks to OPNsense's REST API with `curl.exe`, like the other web lookups. The key and secret
//! go in on stdin as a Basic auth header, so they never show in the process list.

use super::{Caps, Integration};

/// Name of the throw-away alias the write check creates and deletes at once.
pub const PROBE_ALIAS: &str = "RustWarden_probe";

/// (HTTP status, body), or why the router couldn't be reached.
type Reply = Result<(u16, String), String>;

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() { out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char) } else { out.push('=') }
        }
    }
    out
}

/// One request. `body` makes it a JSON POST.
fn request(cfg: &Integration, path: &str, body: Option<&str>) -> Reply {
    let auth = format!("Authorization: Basic {}", base64(format!("{}:{}", cfg.key, cfg.secret).as_bytes()));
    let config = crate::sys::curl::api_config(&format!("{}{path}", cfg.url.trim_end_matches('/')), &auth, body);
    let out = crate::sys::curl::run(&if cfg.allow_self_signed { format!("insecure\n{config}") } else { config }, None)?;
    if !out.status.success() {
        return Err(if out.status.code() == Some(60) {
            "The router's certificate isn't trusted. If it is self-signed, turn on \"Allow self-signed certificate\".".into()
        } else {
            format!("Can't reach OPNsense: {}", String::from_utf8_lossy(&out.stderr).trim())
        });
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", &text));
    Ok((code.trim().parse().unwrap_or(0), body.to_owned()))
}

/// The pieces of a probe, so tests can stand in for the router.
pub trait Transport {
    fn get(&self, path: &str) -> Reply;
    fn post(&self, path: &str, body: &str) -> Reply;
}

struct Curl<'a>(&'a Integration);

impl Transport for Curl<'_> {
    fn get(&self, path: &str) -> Reply {
        request(self.0, path, None)
    }
    fn post(&self, path: &str, body: &str) -> Reply {
        request(self.0, path, Some(body))
    }
}

/// Finds out what the key may do. `write` also tries to create (and remove) the test alias; that is
/// only done when the user asks. `keep` carries over an earlier write result when it isn't re-checked.
pub fn probe(cfg: &Integration, write: bool, keep: Option<bool>) -> Result<Caps, String> {
    probe_with(&Curl(cfg), write, keep)
}

pub fn probe_with(t: &dyn Transport, write: bool, keep: Option<bool>) -> Result<Caps, String> {
    let (code, _) = t.get("/api/core/system/status")?;
    match code {
        401 => return Err("OPNsense rejected the API key or secret.".into()),
        0 => return Err("OPNsense didn't answer with HTTP.".into()),
        404 => return Err("That address doesn't look like OPNsense's web interface (no API there).".into()),
        _ => {}
    }
    let ok = |path: &str| matches!(t.get(path), Ok((200, _)));
    let mut caps = Caps {
        leases: ok("/api/dhcpv4/leases/searchLease") || ok("/api/kea/leases4/search"),
        arp: ok("/api/diagnostics/interface/getArp"),
        log: ok("/api/diagnostics/firewall/log?limit=1"),
        gateway: ok("/api/routes/gateway/status"),
        traffic: ok("/api/diagnostics/traffic/interface"),
        write: keep,
        ..Default::default()
    };
    if let Ok((200, body)) = t.get("/api/core/firmware/status") {
        caps.version = json_str(&body, "product_version");
    }
    if !caps.any_read() && code == 403 {
        return Err("This key can't read anything useful. Give its user the Diagnostics, DHCP and Firewall log privileges.".into());
    }
    if write {
        let (w, warning) = write_check(t);
        caps.write = w;
        caps.warning = warning;
    }
    Ok(caps)
}

fn json_str(body: &str, key: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body).ok().and_then(|v| v.get(key)?.as_str().map(str::to_owned)).unwrap_or_default()
}

/// What creating the test alias said.
#[derive(Debug, PartialEq)]
pub enum Added {
    Uuid(String),
    Denied,
    /// The alias is already there (a leftover), or the router refused it for another reason.
    Failed(String),
}

pub fn parse_add(code: u16, body: &str) -> Added {
    if code == 401 || code == 403 {
        return Added::Denied;
    }
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    match (v.get("result").and_then(|r| r.as_str()), v.get("uuid").and_then(|u| u.as_str())) {
        (Some("saved"), Some(u)) if !u.is_empty() => Added::Uuid(u.to_owned()),
        _ => Added::Failed(format!("HTTP {code}")),
    }
}

/// Creates `RustWarden_probe` and deletes it again without applying anything. Returns whether writing
/// is allowed (None when it couldn't be told) and a warning if the test alias was left behind.
fn write_check(t: &dyn Transport) -> (Option<bool>, String) {
    let body = format!("{{\"alias\":{{\"enabled\":\"1\",\"name\":\"{PROBE_ALIAS}\",\"type\":\"host\",\"content\":\"\",\"description\":\"RustWarden write-access check (safe to delete)\"}}}}");
    let mut added = t.post("/api/firewall/alias/addItem", &body).map_or_else(Added::Failed, |(c, b)| parse_add(c, &b));
    if matches!(added, Added::Failed(_)) {
        // A leftover from an earlier check: remove it and try once more.
        if let Ok((200, b)) = t.get(&format!("/api/firewall/alias/getAliasUUID/{PROBE_ALIAS}")) {
            let old = json_str(&b, "uuid");
            if !old.is_empty() {
                let _ = t.post(&format!("/api/firewall/alias/delItem/{old}"), "{}");
                added = t.post("/api/firewall/alias/addItem", &body).map_or_else(Added::Failed, |(c, b)| parse_add(c, &b));
            }
        }
    }
    match added {
        Added::Denied => (Some(false), String::new()),
        Added::Failed(_) => (None, String::new()),
        Added::Uuid(u) => match t.post(&format!("/api/firewall/alias/delItem/{u}"), "{}") {
            Ok((200, b)) if json_str(&b, "result") == "deleted" => (Some(true), String::new()),
            _ => (Some(true), format!("The write check created an alias called {PROBE_ALIAS} and couldn't remove it. Delete it in Firewall > Aliases.")),
        },
    }
}

/// A made-up router for Demo mode: reads everything; a key containing "readonly" can't write.
pub fn demo_probe(cfg: &Integration, write: bool, keep: Option<bool>) -> Caps {
    Caps {
        version: "25.1 (demo)".into(),
        leases: true,
        arp: true,
        log: true,
        gateway: true,
        traffic: true,
        write: if write { Some(!cfg.key.to_lowercase().contains("readonly")) } else { keep },
        warning: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn base64_matches_the_rfc_examples() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"key:secret"), "a2V5OnNlY3JldA==");
    }

    /// Answers by path prefix; records every POST.
    struct Fake {
        reads: Vec<(&'static str, u16)>,
        add: (u16, &'static str),
        del: (u16, &'static str),
        posts: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(add: (u16, &'static str)) -> Self {
            Self { reads: vec![], add, del: (200, "{\"result\":\"deleted\"}"), posts: RefCell::new(vec![]) }
        }
    }

    impl Transport for Fake {
        fn get(&self, path: &str) -> Reply {
            if path == "/api/core/system/status" {
                return Ok((200, "{}".into()));
            }
            if path == "/api/core/firmware/status" {
                return Ok((200, "{\"product_version\":\"25.1.3\"}".into()));
            }
            let code = self.reads.iter().find(|(p, _)| path.starts_with(p)).map_or(403, |(_, c)| *c);
            Ok((code, "{}".into()))
        }
        fn post(&self, path: &str, _body: &str) -> Reply {
            self.posts.borrow_mut().push(path.to_owned());
            Ok(if path.contains("addItem") { (self.add.0, self.add.1.into()) } else { (self.del.0, self.del.1.into()) })
        }
    }

    const SAVED: &str = "{\"result\":\"saved\",\"uuid\":\"abc-1\"}";

    #[test]
    fn reads_are_judged_per_endpoint() {
        let mut f = Fake::new((403, ""));
        f.reads = vec![("/api/dhcpv4/leases", 200), ("/api/diagnostics/firewall", 200)];
        let c = probe_with(&f, false, None).unwrap();
        assert!(c.leases && c.log);
        assert!(!c.arp && !c.gateway && !c.traffic);
        assert_eq!(c.version, "25.1.3");
        assert_eq!(c.write, None, "write access is only tested when asked");
        assert!(f.posts.borrow().is_empty(), "a read check posts nothing");
    }

    #[test]
    fn a_read_check_keeps_the_earlier_write_result() {
        let f = Fake::new((403, ""));
        assert_eq!(probe_with(&f, false, Some(true)).unwrap().write, Some(true));
    }

    #[test]
    fn a_writable_key_creates_then_removes_the_test_alias() {
        let f = Fake::new((200, SAVED));
        let c = probe_with(&f, true, None).unwrap();
        assert_eq!(c.write, Some(true));
        assert!(c.warning.is_empty());
        let posts = f.posts.borrow();
        assert_eq!(posts.as_slice(), ["/api/firewall/alias/addItem", "/api/firewall/alias/delItem/abc-1"]);
        assert!(!posts.iter().any(|p| p.contains("reconfigure")), "nothing is applied on the router");
    }

    #[test]
    fn a_read_only_key_is_told_apart() {
        let f = Fake::new((403, "{\"status\":403}"));
        assert_eq!(probe_with(&f, true, None).unwrap().write, Some(false));
    }

    #[test]
    fn a_leftover_alias_is_reported() {
        let mut f = Fake::new((200, SAVED));
        f.del = (200, "{\"result\":\"failed\"}");
        let c = probe_with(&f, true, None).unwrap();
        assert_eq!(c.write, Some(true));
        assert!(c.warning.contains(PROBE_ALIAS));
    }

    #[test]
    fn bad_keys_are_rejected_up_front() {
        struct Denied;
        impl Transport for Denied {
            fn get(&self, _: &str) -> Reply {
                Ok((401, String::new()))
            }
            fn post(&self, _: &str, _: &str) -> Reply {
                unreachable!("no write is attempted with a bad key")
            }
        }
        assert!(probe_with(&Denied, true, None).unwrap_err().contains("rejected"));
    }

    #[test]
    fn add_replies_are_classified() {
        assert_eq!(parse_add(200, SAVED), Added::Uuid("abc-1".into()));
        assert_eq!(parse_add(403, ""), Added::Denied);
        assert!(matches!(parse_add(200, "{\"result\":\"failed\",\"validations\":{}}"), Added::Failed(_)));
        assert!(matches!(parse_add(200, "not json"), Added::Failed(_)));
    }

    #[test]
    fn the_demo_probe_follows_the_key() {
        let mut i = Integration { key: "ReadOnly-key".into(), ..Default::default() };
        assert_eq!(demo_probe(&i, true, None).write, Some(false));
        i.key = "full".into();
        assert_eq!(demo_probe(&i, true, None).write, Some(true));
        assert_eq!(demo_probe(&i, false, Some(false)).write, Some(false));
    }
}
