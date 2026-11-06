//! What a plugin may ask of RustWarden. Every call lands in `Host::handle`, which first checks the
//! plugin's permissions; the database and the network are each narrowed to what the plugin declared.

use super::perms;
use plugin_sdk::{HostCall, HostReply};
use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::collections::{BTreeMap, BTreeSet};
use wasmtime::{StoreLimits, StoreLimitsBuilder};

pub struct Host {
    pub id: String,
    pub http_hosts: Vec<String>,
    pub granted: BTreeSet<String>,
    pub db: Option<Connection>,
    /// Demo mode: plugins make up their data.
    pub demo: bool,
    /// The manifest allows `HttpRaw` to accept a self-signed certificate.
    pub allow_insecure: bool,
    /// Sends a call to the plugin from another thread (the helper program's output); set by the manager.
    pub notify: Option<std::sync::Arc<dyn Fn(plugin_sdk::Call) + Send + Sync>>,
    /// The plugin's own tick interval, once it has asked for one.
    pub tick_ms: Option<u32>,
    /// A helper program is running.
    pub helper_busy: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Persisted by the caller; secrets are encrypted when it writes them out.
    pub config: BTreeMap<String, String>,
    pub secrets: BTreeMap<String, String>,
    /// Messages for `notify_in_app`, drained by the caller.
    pub notes: Vec<String>,
    pub limits: StoreLimits,
}

impl Host {
    /// A host that can do nothing yet: no database, no hosts, no permissions.
    pub fn blank() -> Self {
        Self {
            id: String::new(),
            http_hosts: Vec::new(),
            granted: BTreeSet::new(),
            db: None,
            demo: false,
            allow_insecure: false,
            notify: None,
            tick_ms: None,
            helper_busy: Default::default(),
            config: BTreeMap::new(),
            secrets: BTreeMap::new(),
            notes: Vec::new(),
            // shortcut: 64 MB of memory per plugin, raise if a real plugin needs more.
            limits: StoreLimitsBuilder::new().memory_size(64 << 20).instances(1).build(),
        }
    }

    pub fn handle(&mut self, call: HostCall) -> HostReply {
        match self.run(call) {
            Ok(v) => HostReply::Ok(v),
            Err(e) => HostReply::Err(e),
        }
    }

    fn run(&mut self, call: HostCall) -> Result<String, String> {
        perms::require(&self.granted, &call)?;
        match call {
            HostCall::ConfigGet { key } => Ok(self.config.get(&key).cloned().unwrap_or_default()),
            HostCall::ConfigSet { key, value } => {
                self.config.insert(key, value);
                Ok(String::new())
            }
            HostCall::SecretGet { key } => Ok(self.secrets.get(&key).cloned().unwrap_or_default()),
            HostCall::SecretSet { key, value } => {
                self.secrets.insert(key, value);
                Ok(String::new())
            }
            HostCall::DbExec { sql } => {
                let n = self.db()?.execute_batch(&sql).map(|_| 0).map_err(|e| e.to_string())?;
                Ok(n.to_string())
            }
            HostCall::DbQuery { sql } => query(self.db()?, &sql),
            HostCall::HttpRequest { url, headers, body } => {
                if !host_allowed(&url, &self.http_hosts) {
                    return Err("that address is not in the plugin's http_hosts".into());
                }
                http(&url, &headers, body.as_deref())
            }
            HostCall::Now => Ok(crate::clock::now_unix().to_string()),
            HostCall::Log { msg } => {
                // One line, capped, so a plugin can't forge log entries or fill the disk quickly.
                let msg: String = msg.chars().filter(|c| !c.is_control()).take(500).collect();
                crate::applog::line("plugins.log", &format!("{}: {msg}", self.id));
                Ok(String::new())
            }
            HostCall::NotifyInApp { msg } => {
                self.notes.push(msg);
                Ok(String::new())
            }
            HostCall::PingRound { addrs, count } => {
                let results: Vec<serde_json::Value> =
                    crate::sys::icmp::round(&addrs, count).into_iter().map(|r| serde_json::json!({"min": r.min, "avg": r.avg, "max": r.max, "loss": r.loss})).collect();
                Ok(serde_json::Value::from(results).to_string())
            }
            HostCall::HttpRaw { url, headers, body, insecure } => {
                if !host_allowed(&url, &self.http_hosts) {
                    return Err("that address is not in the plugin's http_hosts".into());
                }
                if insecure && !self.allow_insecure {
                    return Err("the plugin did not declare allow_insecure_tls".into());
                }
                let (status, body) = http_raw(&url, &headers, body.as_deref(), insecure)?;
                Ok(serde_json::json!({"status": status, "body": body}).to_string())
            }
            HostCall::HelperReady { exe, exe_sha256 } => Ok(if crate::sys::helper::ready(&self.id, &exe, &exe_sha256) { "1" } else { "0" }.to_owned()),
            HostCall::HelperInstall { url, zip_sha256, exe } => {
                if !url.starts_with("https://") || !host_allowed(&url, &self.http_hosts) {
                    return Err("that address is not an https address in the plugin's http_hosts".into());
                }
                crate::sys::helper::install(&self.id, &url, &zip_sha256, &exe).map(|()| String::new())
            }
            HostCall::HelperStart { exe, args, timeout_secs } => {
                use std::sync::atomic::Ordering;
                let notify = self.notify.clone().ok_or("the plugin can't be called back yet")?;
                if self.helper_busy.swap(true, Ordering::SeqCst) {
                    return Err("a helper program is already running".into());
                }
                let (busy, done_notify, line_notify) = (self.helper_busy.clone(), notify.clone(), notify);
                let timeout = std::time::Duration::from_secs(if timeout_secs == 0 { 0 } else { u64::from(timeout_secs.clamp(1, 600)) });
                let started = crate::sys::helper::start(
                    &self.id,
                    &exe,
                    args,
                    timeout,
                    move |line| line_notify(plugin_sdk::Call::HelperLine { line }),
                    move |end| {
                        busy.store(false, Ordering::SeqCst);
                        done_notify(match end {
                            Ok(message) => plugin_sdk::Call::HelperDone { ok: true, message },
                            Err(message) => plugin_sdk::Call::HelperDone { ok: false, message },
                        });
                    },
                );
                if started.is_err() {
                    self.helper_busy.store(false, Ordering::SeqCst);
                }
                started.map(|()| String::new())
            }
            HostCall::HelperStop => {
                crate::sys::helper::stop(&self.id);
                Ok(String::new())
            }
            HostCall::UpnpDiscover => {
                if self.demo {
                    return Err("UPnP isn't used in Demo mode".into());
                }
                let g = crate::sys::upnp::discover()?;
                Ok(serde_json::json!({"location": g.location, "local_ip": g.local_ip}).to_string())
            }
            HostCall::SetTick { millis } => {
                self.tick_ms = (millis != 0).then(|| millis.clamp(50, 3_600_000));
                Ok(String::new())
            }
            HostCall::RaiseAlert { kind, who, text } => {
                if kind != "packet-loss" {
                    return Err("only the \"packet-loss\" alert kind can be raised".into());
                }
                let who: String = who.chars().filter(|c| !c.is_control()).take(100).collect();
                let text: String = text.chars().filter(|c| !c.is_control()).take(300).collect();
                crate::live::store::raise_plugin_alert(&who, &text);
                Ok(String::new())
            }
            HostCall::BrowserSignIn => {
                self.not_in_demo()?;
                crate::sys::webview::sign_in().map(|()| String::new())
            }
            HostCall::BrowserFetch { urls } => {
                self.not_in_demo()?;
                if urls.len() > 200 || urls.iter().any(|u| !u.starts_with(crate::sys::webview::HOST) || !host_allowed(u, &self.http_hosts)) {
                    return Err("those addresses are not on the plugin's site".into());
                }
                let answers = crate::sys::webview::fetch(&urls)?;
                Ok(serde_json::Value::from(answers.into_iter().map(|(status, body)| serde_json::json!({"status": status, "body": body})).collect::<Vec<_>>()).to_string())
            }
            HostCall::BrowserSignOut => {
                self.not_in_demo()?;
                crate::sys::webview::sign_out().map(|()| String::new()).map_err(|e| e.to_string())
            }
            HostCall::IsDemo => Ok(if self.demo { "1" } else { "0" }.to_owned()),
            HostCall::Devices => Ok(if self.demo { "[]".to_owned() } else { scanned_devices().map_err(|e| e.to_string())? }),
        }
    }

    fn not_in_demo(&self) -> Result<(), String> {
        if self.demo { Err("the browser isn't used in Demo mode".into()) } else { Ok(()) }
    }

    fn db(&self) -> Result<&Connection, String> {
        self.db.as_ref().ok_or_else(|| "the plugin has no database".to_owned())
    }
}

/// The start of every table name a plugin owns: `p_<id>__` with dashes as underscores. The double
/// underscore ends the id (ids never contain one, see `loader::valid_id`), so no plugin's prefix is the start of another's.
pub fn table_prefix(id: &str) -> String {
    format!("p_{}__", id.replace('-', "_"))
}

/// Limits `conn` to the tables named `table_prefix(id)*`: no other table, no PRAGMA, no ATTACH, no temp objects.
pub fn restrict_db(conn: &mut Connection, id: &str) -> rusqlite::Result<()> {
    let prefix = table_prefix(id);
    conn.authorizer(Some(move |ctx: AuthContext<'_>| {
        let ours = |t: &str| t.starts_with(&prefix);
        let ok = match ctx.action {
            AuthAction::Select | AuthAction::Transaction { .. } | AuthAction::Savepoint { .. } | AuthAction::Recursive => true,
            // CREATE TABLE reads the schema table's row ids; its contents (other plugins' table names) stay unreadable.
            AuthAction::Read { table_name, column_name } => ours(table_name) || (table_name.ends_with("sqlite_master") && column_name == "ROWID"),
            AuthAction::Update { table_name, .. } => ours(table_name) || table_name.ends_with("sqlite_master"),
            // SQLite writes its own schema table when a table is made or dropped; reading it stays refused, and
            // a plugin's direct writes to it fail anyway (writable_schema is off and PRAGMA is refused).
            AuthAction::Insert { table_name } | AuthAction::Delete { table_name } => ours(table_name) || table_name.ends_with("sqlite_master"),
            AuthAction::CreateTable { table_name } | AuthAction::DropTable { table_name } | AuthAction::AlterTable { table_name, .. } => ours(table_name),
            AuthAction::CreateIndex { table_name, .. } | AuthAction::DropIndex { table_name, .. } => ours(table_name),
            // Only the plain SQL functions; load_extension and the like are refused.
            AuthAction::Function { function_name } => !function_name.contains("load_extension"),
            _ => false,
        };
        if ok { Authorization::Allow } else { Authorization::Deny }
    }))
}

fn query(conn: &Connection, sql: &str) -> Result<String, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let n = stmt.column_count();
    let rows = stmt
        .query_map([], |r| {
            (0..n)
                .map(|i| {
                    use rusqlite::types::ValueRef::*;
                    Ok(match r.get_ref(i)? {
                        Null => serde_json::Value::Null,
                        Integer(v) => v.into(),
                        Real(v) => v.into(),
                        Text(v) => String::from_utf8_lossy(v).into_owned().into(),
                        Blob(v) => format!("<{} bytes>", v.len()).into(),
                    })
                })
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    Ok(serde_json::Value::from(rows.into_iter().map(serde_json::Value::from).collect::<Vec<_>>()).to_string())
}

/// True when `url` is http(s) and its host is exactly one of `hosts` (no user-info tricks, no port games), or `hosts` has `"*"`
/// (any host; the approval dialog says so).
pub fn host_allowed(url: &str, hosts: &[String]) -> bool {
    let Some(rest) = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")) else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = authority.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(authority, |(h, _)| h);
    !host.is_empty() && hosts.iter().any(|h| h == "*" || h.eq_ignore_ascii_case(host))
}

fn http(url: &str, headers: &[String], body: Option<&str>) -> Result<String, String> {
    let (status, body) = http_raw(url, headers, body, false)?;
    answer(&status.to_string(), &body)
}

/// The curl config for one request. Every value is quoted, so none can add a line to it (a second `url`, say).
fn curl_config(url: &str, headers: &[String], body: Option<&str>, insecure: bool) -> String {
    use crate::sys::curl::quote;
    // The request goes in on stdin so tokens never show in the process list; no `location`, so a redirect can't leave the host.
    let mut cfg = format!(
        "silent
show-error
max-time = 10
max-filesize = 1048576
write-out = \"\n%{{http_code}}\"
url = {}
",
        quote(url)
    );
    if insecure {
        cfg += "insecure
";
    }
    if let Some(b) = body {
        cfg += &format!(
            "data-raw = {}
",
            quote(b)
        );
    }
    for h in headers {
        cfg += &format!(
            "header = {}
",
            quote(h)
        );
    }
    cfg
}

/// One request through curl: (status, body), or why the server couldn't be reached.
fn http_raw(url: &str, headers: &[String], body: Option<&str>, insecure: bool) -> Result<(u16, String), String> {
    let cfg = curl_config(url, headers, body, insecure);
    let out = crate::sys::curl::run(&cfg, None)?;
    if !out.status.success() {
        return Err(if out.status.code() == Some(60) {
            "the server's certificate isn't trusted".to_owned()
        } else {
            format!("can't reach the server: {}", String::from_utf8_lossy(&out.stderr).trim())
        });
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", &text));
    Ok((code.trim().parse().unwrap_or(0), body.to_owned()))
}

/// The body for a 2xx or 3xx answer, else an error naming the status.
fn answer(code: &str, body: &str) -> Result<String, String> {
    match code.parse::<u16>() {
        Ok(c) if c < 400 => Ok(body.to_owned()),
        _ => Err(format!("HTTP {code}")),
    }
}

/// The devices of the network scan as a JSON array, read straight from the database (read-only).
fn scanned_devices() -> rusqlite::Result<String> {
    let conn = Connection::open_with_flags(crate::live::db_path(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt = conn.prepare("SELECT mac, ip, name FROM devices ORDER BY last_seen DESC")?;
    let rows = stmt.query_map([], |r| Ok(serde_json::json!({"mac": r.get::<_, String>(0)?, "ip": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(serde_json::Value::from(rows).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_with_db(id: &str) -> Host {
        let mut h = Host::blank();
        let mut conn = Connection::open_in_memory().unwrap();
        // Another plugin's table, made before the restriction is applied.
        conn.execute_batch("CREATE TABLE p_other__t (x INTEGER); INSERT INTO p_other__t VALUES (1); CREATE TABLE p_mine_b__t (x INTEGER);").unwrap();
        restrict_db(&mut conn, id).unwrap();
        h.id = id.into();
        h.db = Some(conn);
        h
    }

    #[test]
    fn own_tables_work_and_other_tables_are_refused() {
        let mut h = host_with_db("mine");
        let r = h.handle(HostCall::DbExec { sql: "CREATE TABLE p_mine__t (x INTEGER); INSERT INTO p_mine__t VALUES (7)".into() });
        assert!(matches!(r, HostReply::Ok(_)), "{r:?}");
        assert_eq!(h.handle(HostCall::DbQuery { sql: "SELECT x FROM p_mine__t".into() }), HostReply::Ok("[[7]]".into()));
        for sql in [
            "SELECT x FROM p_other__t",
            // "mine-b" is another plugin whose prefix starts like this one's.
            "SELECT x FROM p_mine_b__t",
            "INSERT INTO p_other__t VALUES (2)",
            "DROP TABLE p_other__t",
            "CREATE TABLE evil (x)",
            "ATTACH 'x.db' AS a",
            "PRAGMA journal_mode",
            "SELECT name FROM sqlite_master",
            "DELETE FROM sqlite_master",
            "UPDATE sqlite_master SET name = 'x'",
        ] {
            assert!(matches!(h.handle(HostCall::DbQuery { sql: sql.into() }), HostReply::Err(_)), "{sql}");
            assert!(matches!(h.handle(HostCall::DbExec { sql: sql.into() }), HostReply::Err(_)), "{sql}");
        }
    }

    #[test]
    fn http_is_limited_to_declared_hosts() {
        let hosts = vec!["ntfy.sh".to_owned(), "ha.local".to_owned()];
        assert!(host_allowed("https://ntfy.sh/topic", &hosts));
        assert!(host_allowed("http://HA.local:8123/api?x=1", &hosts));
        assert!(!host_allowed("https://evil.com/", &hosts));
        assert!(!host_allowed("https://ntfy.sh.evil.com/", &hosts));
        assert!(!host_allowed("https://ntfy.sh@evil.com/", &hosts));
        assert!(!host_allowed("https://evil.com/ntfy.sh", &hosts));
        assert!(!host_allowed("file:///c:/x", &hosts));
        assert!(!host_allowed("https://", &hosts));
        // "*" opens every http(s) host but nothing else.
        let any = vec!["*".to_owned()];
        assert!(host_allowed("https://anything.example/x", &any) && host_allowed("http://10.0.0.5:8080/", &any));
        assert!(!host_allowed("file:///c:/x", &any) && !host_allowed("https://u@evil.com/", &any) && !host_allowed("ftp://x/", &any));
        let mut h = Host::blank();
        h.http_hosts = hosts;
        assert!(matches!(h.handle(HostCall::HttpRequest { url: "https://evil.com/".into(), headers: vec![], body: None }), HostReply::Err(_)));
    }

    #[test]
    fn a_value_cannot_break_out_of_the_curl_config() {
        let c = curl_config("https://h/\"\nurl = \"evil", &["Authorization: Bearer a\nb".to_owned()], Some("{\"x\":1}"), false);
        assert_eq!(c.lines().filter(|l| l.starts_with("url")).count(), 1);
        assert!(c.contains(r"Bearer a\nb"), "a newline in a header stays inside its quotes");
        assert!(c.contains("data-raw = \"{\\\"x\\\":1}\""));
        assert!(!c.contains("insecure"), "certificates are checked unless the plugin was allowed not to");
        assert!(curl_config("https://h", &[], None, true).contains("\ninsecure\n"));
    }

    #[test]
    fn http_answers_are_judged_by_status() {
        assert_eq!(answer("200", "ok"), Ok("ok".to_owned()));
        assert_eq!(answer("302", ""), Ok(String::new()));
        assert_eq!(answer("401", "no"), Err("HTTP 401".to_owned()));
        assert_eq!(answer("503", ""), Err("HTTP 503".to_owned()));
        assert_eq!(answer("", ""), Err("HTTP ".to_owned()));
    }

    #[test]
    fn config_and_secrets_round_trip_and_gated_calls_fail() {
        let mut h = Host::blank();
        h.handle(HostCall::ConfigSet { key: "a".into(), value: "1".into() });
        h.handle(HostCall::SecretSet { key: "k".into(), value: "s".into() });
        assert_eq!(h.handle(HostCall::ConfigGet { key: "a".into() }), HostReply::Ok("1".into()));
        assert_eq!(h.handle(HostCall::SecretGet { key: "k".into() }), HostReply::Ok("s".into()));
        assert!(matches!(h.handle(HostCall::PingRound { addrs: vec!["1.1.1.1".into()], count: 1 }), HostReply::Err(e) if e.contains("not granted")));
    }
}
