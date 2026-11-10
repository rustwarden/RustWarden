//! What a plugin may ask of RustWarden. Every call lands in `Host::handle`, which first checks the
//! plugin's permissions; the database and the network are each narrowed to what the plugin declared.

use super::perms;
use plugin_sdk::{HostCall, HostReply};
use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::collections::{BTreeMap, BTreeSet};
use wasmtime::{StoreLimits, StoreLimitsBuilder};

/// Longest one `DbExec` or `DbQuery` may run.
const DB_CALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(2);

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
            HostCall::DbExec { sql } => self.guarded(|db| db.execute_batch(&sql).map(|()| "0".to_owned()).map_err(|e| e.to_string())),
            HostCall::DbQuery { sql } => self.guarded(|db| query(db, &sql)),
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
                self.notes.push(msg.chars().filter(|c| !c.is_control()).take(500).collect());
                Ok(String::new())
            }
            HostCall::PingRound { addrs, count } => {
                let results: Vec<serde_json::Value> =
                    crate::sys::icmp::round(&addrs, count).into_iter().map(|r| serde_json::json!({"min": r.min, "avg": r.avg, "max": r.max, "loss": r.loss})).collect();
                Ok(serde_json::Value::from(results).to_string())
            }
            HostCall::HttpRaw { url, headers, body, insecure, ca_pem, connect_to } => {
                if !host_allowed(&url, &self.http_hosts) {
                    return Err("that address is not in the plugin's http_hosts".into());
                }
                if insecure && !self.allow_insecure {
                    return Err("the plugin did not declare allow_insecure_tls".into());
                }
                if insecure && ca_pem.is_some() {
                    return Err("a request can't both skip the certificate check and pin a CA".into());
                }
                // The connection may go to another address than the URL names, but only one the plugin could have reached anyway.
                let connect = match connect_to.as_deref() {
                    Some(c) => {
                        let ip = connect_address(c).ok_or("connect_to must look like name:port:address:port")?;
                        if !host_allowed(&format!("https://{ip}/"), &self.http_hosts) {
                            return Err("that connect_to address is not in the plugin's http_hosts".into());
                        }
                        Some(c)
                    }
                    None => None,
                };
                let ca = ca_pem.as_deref().map(CaFile::write).transpose()?;
                let (status, body, cookie) = http_raw(&url, &headers, body.as_deref(), insecure, ca.as_ref().map(CaFile::path), connect)?;
                Ok(serde_json::json!({"status": status, "body": body, "cookie": cookie}).to_string())
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
                let list: Vec<_> = crate::sys::upnp::discover()?.into_iter().map(|g| serde_json::json!({"location": g.location, "local_ip": g.local_ip})).collect();
                Ok(serde_json::Value::Array(list).to_string())
            }
            HostCall::WgKeypair => Ok(wg_keypair().to_string()),
            HostCall::BlockedAddresses => {
                let list = if self.demo { vec!["198.51.100.23".to_owned(), "203.0.113.50".to_owned()] } else { crate::live::store::blocked_addresses() };
                Ok(serde_json::Value::from(list).to_string())
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

    /// Runs one database call with a time limit, and rolls back a transaction the call left open: the connection is
    /// the real database's, so a plugin that kept a write lock (or ran for ever) would stop RustWarden's own writes.
    fn guarded(&mut self, f: impl FnOnce(&Connection) -> Result<String, String>) -> Result<String, String> {
        let db = self.db.as_mut().ok_or_else(|| "the plugin has no database".to_owned())?;
        let start = std::time::Instant::now();
        let _ = db.progress_handler(1000, Some(move || start.elapsed() > DB_CALL_LIMIT));
        let result = f(db);
        let _ = db.progress_handler(1000, None::<fn() -> bool>);
        if !db.is_autocommit() {
            let _ = db.execute_batch("ROLLBACK");
            return Err("a transaction must be finished (COMMIT) within the same call, so it was rolled back".into());
        }
        result
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
    let (status, body, _) = http_raw(url, headers, body, false, None, None)?;
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
write-out = \"\\n%header{{set-cookie}}\\n%{{http_code}}\"
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

/// The address of a `name:port:address:port` connect-to value (curl's `--connect-to`), or `None` if it isn't one of those:
/// plain names, digits and an IPv4 address only, so nothing odd reaches the curl config.
fn connect_address(c: &str) -> Option<&str> {
    let parts: Vec<&str> = c.split(':').collect();
    let [name, p1, ip, p2] = parts[..] else { return None };
    let ok_name = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    let ok_ip = ip.split('.').count() == 4 && ip.split('.').all(|o| !o.is_empty() && o.len() <= 3 && o.chars().all(|c| c.is_ascii_digit()));
    (ok_name && ok_ip && p1.chars().all(|c| c.is_ascii_digit()) && p2.chars().all(|c| c.is_ascii_digit())).then_some(ip)
}

/// A CA certificate a plugin pinned, written to a private file for curl and removed again when dropped.
struct CaFile(std::path::PathBuf);

impl CaFile {
    fn write(pem: &str) -> Result<Self, String> {
        let body_ok = pem.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | ' ' | '\r' | '\n'));
        if !pem.trim_start().starts_with("-----BEGIN CERTIFICATE-----") || pem.len() > 16 * 1024 || !body_ok {
            return Err("ca_pem must be a PEM certificate".into());
        }
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        // Elevated, the file goes where only administrators can write: its name is predictable, so in the user's own
        // folder a planted link could aim this write elsewhere.
        let base = if crate::sys::is_elevated() { crate::settings::admin_dir() } else { crate::settings::data_dir() };
        let dir = base.join("plugin-tmp");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("ca-{}-{}.pem", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        std::fs::write(&path, pem).map_err(|e| e.to_string())?;
        Ok(Self(path))
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap_or("")
    }
}

impl Drop for CaFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

/// A WireGuard keypair as `wg genkey` and `wg pubkey` print them (base64), from the operating system's random numbers.
fn wg_keypair() -> serde_json::Value {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    serde_json::json!({"private": b64(&secret.to_bytes()), "public": b64(public.as_bytes())})
}

/// Splits curl's output (the body, then the first `Set-Cookie` header, then the status, one per line) into (status, body, cookie).
fn split_reply(text: &str) -> (u16, String, String) {
    let (rest, code) = text.rsplit_once('\n').unwrap_or(("", text));
    let (body, cookie) = rest.rsplit_once('\n').unwrap_or(("", rest));
    (code.trim().parse().unwrap_or(0), body.to_owned(), cookie.trim().to_owned())
}

/// The curl lines for a pinned CA. Schannel (curl on Windows) also asks for revocation data, which a private CA's certificates
/// don't carry, so the check would fail with "untrusted"; best-effort skips it, while the pinned CA still has to vouch for the
/// server.
fn pinned_ca_config(path: &str) -> String {
    format!("cacert = {}\nssl-revoke-best-effort\n", crate::sys::curl::quote(path))
}

/// One request through curl: (status, body, first Set-Cookie header), or why the server couldn't be reached.
fn http_raw(url: &str, headers: &[String], body: Option<&str>, insecure: bool, ca_path: Option<&str>, connect_to: Option<&str>) -> Result<(u16, String, String), String> {
    let mut cfg = curl_config(url, headers, body, insecure);
    if let Some(p) = ca_path {
        cfg += &pinned_ca_config(p);
    }
    if let Some(c) = connect_to {
        cfg += &format!("connect-to = {}\n", crate::sys::curl::quote(c));
    }
    let out = crate::sys::curl::run(&cfg, None)?;
    if !out.status.success() {
        return Err(if out.status.code() == Some(60) {
            "the server's certificate isn't trusted".to_owned()
        } else {
            format!("can't reach the server: {}", String::from_utf8_lossy(&out.stderr).trim())
        });
    }
    Ok(split_reply(&String::from_utf8_lossy(&out.stdout)))
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
    fn a_plugin_cannot_keep_a_transaction_open_or_run_for_ever() {
        let mut h = host_with_db("mine");
        let r = h.handle(HostCall::DbExec { sql: "CREATE TABLE p_mine__t (x INTEGER); BEGIN IMMEDIATE".into() });
        assert!(matches!(r, HostReply::Err(_)), "{r:?}");
        assert!(h.db.as_ref().unwrap().is_autocommit(), "rolled back");
        let r = h.handle(HostCall::DbQuery { sql: "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c) SELECT count(*) FROM c".into() });
        assert!(matches!(r, HostReply::Err(_)), "{r:?}");
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
        assert!(curl_config("https://h", &[], None, false).contains(r#"write-out = "\n%header{set-cookie}\n%{http_code}""#), "the cookie and status markers must stay on their own lines");
    }

    #[test]
    fn connect_to_is_a_name_and_an_ipv4_address_only() {
        assert_eq!(connect_address("newyork438:1337:191.96.227.10:1337"), Some("191.96.227.10"));
        assert_eq!(connect_address("host.example::10.0.0.1:"), Some("10.0.0.1"));
        assert_eq!(connect_address("a:1:b:2"), None);
        assert_eq!(connect_address("x\nurl = evil:1:1.2.3.4:1"), None);
        assert_eq!(connect_address("h:1:1.2.3.4"), None);
        assert_eq!(connect_address("h:1:1.2.3:4:5"), None);
    }

    #[test]
    fn a_pinned_ca_is_checked_and_its_file_removed() {
        assert!(CaFile::write("not a certificate").is_err());
        assert!(CaFile::write("-----BEGIN CERTIFICATE-----\nAA\"; rm\n-----END CERTIFICATE-----").is_err());
        let path = {
            let f = CaFile::write("-----BEGIN CERTIFICATE-----\nMIIFqDCC\n-----END CERTIFICATE-----\n").unwrap();
            assert!(std::path::Path::new(f.path()).exists());
            f.path().to_owned()
        };
        assert!(!std::path::Path::new(&path).exists(), "the file goes with the request");
    }

    #[test]
    fn a_pinned_ca_skips_the_revocation_lookup_a_private_ca_cannot_answer() {
        let cfg = pinned_ca_config("C:\\x\\ca.pem");
        assert!(cfg.contains("cacert = ") && cfg.lines().any(|l| l == "ssl-revoke-best-effort"));
    }

    #[test]
    fn base64_matches_the_standard_with_padding() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn a_keypair_is_32_bytes_each_and_the_public_key_follows_from_the_private() {
        let k = wg_keypair();
        let (private, public) = (k["private"].as_str().unwrap(), k["public"].as_str().unwrap());
        assert_eq!((private.len(), public.len()), (44, 44));
        assert!(private.ends_with('=') && public.ends_with('='));
        assert_ne!(private, wg_keypair()["private"].as_str().unwrap(), "every key is new");
        // RFC 7748 section 6.1: Alice's private key gives this public key.
        let alice: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c,
            0x2a,
        ];
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(alice));
        assert_eq!(b64(public.as_bytes()), "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=");
    }

    #[test]
    fn curl_output_is_split_into_status_body_and_cookie() {
        assert_eq!(split_reply("{\"a\":1}\nsysauth=abc; path=/\n200"), (200, "{\"a\":1}".to_owned(), "sysauth=abc; path=/".to_owned()));
        // No cookie: an empty line stands in; a body of several lines keeps its own breaks.
        assert_eq!(split_reply("one\ntwo\n\n404"), (404, "one\ntwo".to_owned(), String::new()));
        assert_eq!(split_reply("\n\n000"), (0, String::new(), String::new()));
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
