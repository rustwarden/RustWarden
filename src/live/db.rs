//! SQLite persistence: bucketed traffic history, apps, hostnames, alerts, devices and a
//! small key/value table for monitor baselines. Lives in `%LOCALAPPDATA%\RustWarden\`.

use super::bucket::Scale;
use crate::data::{AlertCheck, DnsEntry, Scope, TrafficDir, TrafficFilter};
use crate::export::{AlertRow, TrafficRow};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::path::Path;

pub struct Db {
    pub(crate) conn: Connection,
}

#[derive(Clone, Debug, Default)]
pub struct AppRecord {
    pub id: i64,
    /// Lower-cased executable path; empty path uses the display name (the "System" process).
    pub key: String,
    pub path: String,
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub hash: String,
    pub signed: Option<bool>,
    pub system: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    /// When the executable was first found missing; `None` while it exists.
    pub missing_since: Option<i64>,
    /// Windows service this row stands for (svchost.exe traffic is split by service); empty for a whole program.
    pub service: String,
}

#[derive(Clone, Debug)]
pub struct TrafficDelta {
    pub app_id: i64,
    pub remote: String,
    pub proto: String,
    /// 0 = WAN, 1 = LAN, 2 = not classified (adapter counters).
    pub kind: u8,
    pub down: u64,
    pub up: u64,
}

pub const KIND_WAN: u8 = 0;
pub const KIND_LAN: u8 = 1;
pub const KIND_UNKNOWN: u8 = 2;

#[derive(Clone, Debug)]
pub struct NewAlert {
    pub ts: i64,
    /// Stable monitor key, see `monitors::AlertKind::key`.
    pub kind: String,
    pub important: bool,
    pub app: String,
    pub text: String,
    pub target: String,
    /// "LOCAL", an ISO alpha-2 code, or empty for alerts that aren't about a host.
    pub country: String,
    pub unread: bool,
}

#[derive(Clone, Debug)]
pub struct StoredAlert {
    pub id: i64,
    pub new: NewAlert,
}

#[derive(Clone, Debug, Default)]
pub struct DeviceRow {
    pub network: String,
    pub mac: String,
    pub ip: String,
    pub name: String,
    pub vendor: String,
    pub system: String,
    pub kind: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub online: bool,
    pub seen_count: i64,
    /// Open TCP ports, comma separated; empty when none were found or the device was never scanned.
    pub ports: String,
    /// Marked by the user as a known device.
    pub trusted: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TotalsRow {
    pub down: f64,
    pub up: f64,
    pub wan: f64,
    pub wan_up: f64,
    pub lan: f64,
    pub lan_up: f64,
}

/// What a baseline item has been through: it counts as usual.
pub const BASE_LEARNED: u8 = 0;
/// An alert was raised for it and it is waiting for "mark as normal".
pub const BASE_ALERTED: u8 = 1;
/// The user marked it normal: it counts as usual and never expires.
pub const BASE_NORMAL: u8 = 2;

/// One thing an app was seen doing (a country, a network, an hour or a day's volume) and what the baseline made of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaselineItem {
    pub dim: String,
    pub val: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub state: u8,
    /// When an alert was last raised for it, 0 for never.
    pub alerted: i64,
    pub alert_id: Option<i64>,
}

/// A column of the traffic table that usage can be grouped or filtered by.
#[derive(Clone, Copy, Debug)]
pub enum Dim {
    App,
    Remote,
    Proto,
}

impl Dim {
    fn column(self) -> &'static str {
        match self {
            Dim::App => "app_id",
            Dim::Remote => "remote",
            Dim::Proto => "proto",
        }
    }
}

#[derive(Clone, Debug)]
pub struct UsageEntry {
    pub key: String,
    pub down: f64,
    pub up: f64,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE, path TEXT NOT NULL, name TEXT NOT NULL,
    publisher TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '', hash TEXT NOT NULL DEFAULT '',
    signed INTEGER, system INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, missing_since INTEGER, service TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS traffic (
    scale INTEGER NOT NULL, ts INTEGER NOT NULL, app_id INTEGER NOT NULL, remote TEXT NOT NULL,
    proto TEXT NOT NULL, kind INTEGER NOT NULL, down INTEGER NOT NULL, up INTEGER NOT NULL,
    PRIMARY KEY (scale, ts, app_id, remote, proto, kind)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hostnames (ip TEXT PRIMARY KEY, name TEXT NOT NULL, seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS app_hostnames (app_id INTEGER NOT NULL, ip TEXT NOT NULL, name TEXT NOT NULL, seen INTEGER NOT NULL, PRIMARY KEY (app_id, ip)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, important INTEGER NOT NULL,
    app TEXT NOT NULL, text TEXT NOT NULL, target TEXT NOT NULL, country TEXT NOT NULL, unread INTEGER NOT NULL,
    prev_hash TEXT NOT NULL DEFAULT '', hash TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS devices (
    network TEXT NOT NULL, mac TEXT NOT NULL, ip TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT '', system TEXT NOT NULL DEFAULT '', kind INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, online INTEGER NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1, ports TEXT, trusted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (network, mac));
CREATE TABLE IF NOT EXISTS hardware (
    ts INTEGER PRIMARY KEY, cpu REAL NOT NULL, memory REAL NOT NULL, disk REAL NOT NULL, gpu REAL NOT NULL);
CREATE TABLE IF NOT EXISTS hardware_app (
    ts INTEGER NOT NULL, app TEXT NOT NULL, cpu REAL NOT NULL, memory REAL NOT NULL, disk REAL NOT NULL, PRIMARY KEY (ts, app));
CREATE TABLE IF NOT EXISTS dns_log (
    ts INTEGER NOT NULL, app TEXT NOT NULL, name TEXT NOT NULL, qtype INTEGER NOT NULL, ips TEXT NOT NULL, status INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS dns_log_ts ON dns_log (ts);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS blocked (ts INTEGER NOT NULL, remote TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (ts, remote)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS baseline_item (
    app_id INTEGER NOT NULL, dim TEXT NOT NULL, val TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
    state INTEGER NOT NULL, alerted INTEGER NOT NULL DEFAULT 0, alert_id INTEGER,
    PRIMARY KEY (app_id, dim, val)) WITHOUT ROWID;
";

/// SHA-256 over the previous hash and the alert's fields as a JSON array, so no value can imitate a field boundary.
fn alert_hash(prev: &str, a: &NewAlert) -> String {
    use sha2::{Digest, Sha256};
    let body = serde_json::json!([prev, a.ts, a.kind, a.important, a.app, a.text, a.target, a.country]).to_string();
    Sha256::digest(body).iter().map(|b| format!("{b:02x}")).collect()
}

/// Runs an `ALTER TABLE .. ADD COLUMN`; `Ok(false)` when the column was already there, any other failure is an error
/// (a locked or damaged database must not look like a finished migration).
fn add_column(conn: &Connection, sql: &str) -> rusqlite::Result<bool> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(true),
        Err(e) if e.to_string().contains("duplicate column") => Ok(false),
        Err(e) => Err(e),
    }
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        // WAL lets the UI's read connection run while the collector writes.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        crate::plugins::legacy::migrate_tables(&conn)?;
        add_column(&conn, "ALTER TABLE devices ADD COLUMN seen_count INTEGER NOT NULL DEFAULT 1")?;
        // NULL = never port-scanned, which also marks devices stored before port scanning existed.
        add_column(&conn, "ALTER TABLE devices ADD COLUMN ports TEXT")?;
        add_column(&conn, "ALTER TABLE devices ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0")?;
        add_column(&conn, "ALTER TABLE apps ADD COLUMN service TEXT NOT NULL DEFAULT ''")?;
        // Alert log chain (see verify_alerts); older rows keep an empty hash.
        add_column(&conn, "ALTER TABLE alerts ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''")?;
        add_column(&conn, "ALTER TABLE alerts ADD COLUMN hash TEXT NOT NULL DEFAULT ''")?;
        let db = Self { conn };
        db.set_filter(&TrafficFilter::default(), None)?;
        Ok(db)
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let db = Self { conn };
        db.set_filter(&TrafficFilter::default(), None).unwrap();
        db
    }

    /// The matched devices by MAC, from the table each annotating plugin keeps (`p_<id>__devices`). A plugin that
    /// hasn't made its table yet simply has none.
    pub fn device_notes(&self, plugins: &[String]) -> rusqlite::Result<std::collections::HashMap<String, crate::data::DeviceNote>> {
        let mut out = std::collections::HashMap::new();
        for id in plugins {
            let table = format!("{}devices", crate::plugins::wasm::host::table_prefix(id));
            if self.conn.query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [&table], |_| Ok(())).is_err() {
                continue;
            }
            let mut stmt = self.conn.prepare_cached(&format!("SELECT mac, name, area, model, kind, url FROM {table} WHERE found = 1"))?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, crate::data::DeviceNote { name: r.get(1)?, area: r.get(2)?, model: r.get(3)?, kind: r.get(4)?, url: r.get(5)? })))?;
            for row in rows {
                let (mac, note) = row?;
                out.entry(mac).or_insert(note);
            }
        }
        Ok(out)
    }

    /// Points the read queries (temp view `t`) at the matching slice of `traffic`.
    /// Everything interpolated is an integer or a closed-set literal.
    pub fn set_filter(&self, f: &TrafficFilter, remotes: Option<&[String]>) -> rusqlite::Result<()> {
        let (d, u) = (f.dir != TrafficDir::Out, f.dir != TrafficDir::In);
        let kind = match f.scope {
            Scope::Both => "1".to_owned(),
            Scope::Wan => format!("kind = {KIND_WAN}"),
            Scope::Lan => format!("kind = {KIND_LAN}"),
        };
        let app = f.app.as_ref().and_then(|(k, _)| k.parse::<i64>().ok()).map_or("1".to_owned(), |id| format!("app_id = {id}"));
        // Only strings that parse as addresses get in, so nothing needs escaping.
        let remote = remotes.map_or("1".to_owned(), |r| {
            let ips: Vec<String> = r.iter().filter(|s| s.parse::<std::net::IpAddr>().is_ok()).map(|s| format!("'{s}'")).collect();
            if ips.is_empty() { "0".to_owned() } else { format!("remote IN ({})", ips.join(",")) }
        });
        self.conn.execute_batch(&format!(
            "DROP VIEW IF EXISTS temp.t;
             CREATE TEMP VIEW t AS SELECT scale, ts, app_id, remote, proto, kind, down * {d} AS down, up * {u} AS up
             FROM traffic WHERE {kind} AND {app} AND {remote} AND down * {d} + up * {u} > 0;",
            d = d as u8,
            u = u as u8
        ))
    }

    // ---- traffic ----

    /// Adds one second of traffic to every resolution. Upserts, so a crash loses at most a second.
    pub fn add_traffic(&mut self, ts: i64, rows: &[TrafficDelta]) -> rusqlite::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO traffic (scale, ts, app_id, remote, proto, kind, down, up) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(scale, ts, app_id, remote, proto, kind) DO UPDATE SET down = down + excluded.down, up = up + excluded.up",
            )?;
            for scale in Scale::ALL {
                let bucket = super::bucket::align(ts, scale);
                for r in rows {
                    stmt.execute(params![scale.secs(), bucket, r.app_id, r.remote, r.proto, r.kind, r.down as i64, r.up as i64])?;
                }
            }
        }
        tx.commit()
    }

    /// Deletes rows older than each resolution's retention.
    pub fn prune(&self, now: i64, retention_days: u32) -> rusqlite::Result<()> {
        for scale in Scale::ALL {
            self.conn.execute("DELETE FROM traffic WHERE scale = ?1 AND ts < ?2", params![scale.secs(), now - scale.retention_secs(retention_days)])?;
        }
        // Names not seen in the retention period are only kept for traffic that is gone by now.
        self.conn.execute("DELETE FROM hostnames WHERE seen < ?1", params![now - i64::from(retention_days) * 86_400])?;
        self.conn.execute("DELETE FROM app_hostnames WHERE seen < ?1", params![now - i64::from(retention_days) * 86_400])?;
        self.conn.execute("DELETE FROM blocked WHERE ts < ?1", params![now - i64::from(retention_days) * 86_400])?;
        Ok(())
    }

    /// Adds blocked connection attempts, `(minute, remote address) -> attempts`.
    pub fn add_blocked(&mut self, rows: &std::collections::HashMap<(i64, String), u32>) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached("INSERT INTO blocked (ts, remote, n) VALUES (?1,?2,?3) ON CONFLICT(ts, remote) DO UPDATE SET n = n + excluded.n")?;
            for ((ts, remote), n) in rows {
                stmt.execute(params![ts, remote, n])?;
            }
        }
        tx.commit()
    }

    /// Blocked attempts per remote address in `[t0, t1)`.
    pub fn blocked_by_remote(&self, t0: i64, t1: i64) -> rusqlite::Result<Vec<(String, u32)>> {
        let mut stmt = self.conn.prepare_cached("SELECT remote, SUM(n) FROM blocked WHERE ts >= ?1 AND ts < ?2 GROUP BY remote")?;
        stmt.query_map(params![t0, t1], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
    }

    // ---- hardware ----

    pub fn add_hardware(&self, ts: i64, s: &crate::data::HardwareSample) -> rusqlite::Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO hardware (ts, cpu, memory, disk, gpu) VALUES (?1,?2,?3,?4,?5)", params![ts, s.cpu, s.memory, s.disk, s.gpu])?;
        Ok(())
    }

    pub fn prune_hardware(&self, now: i64, hours: u32) -> rusqlite::Result<()> {
        let cutoff = now - i64::from(hours) * 3600;
        self.conn.execute("DELETE FROM hardware WHERE ts < ?1", params![cutoff])?;
        self.conn.execute("DELETE FROM hardware_app WHERE ts < ?1", params![cutoff])?;
        Ok(())
    }

    pub fn add_hardware_app(&self, ts: i64, app: &str, s: &crate::data::HardwareSample) -> rusqlite::Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO hardware_app (ts, app, cpu, memory, disk) VALUES (?1,?2,?3,?4,?5)", params![ts, app, s.cpu, s.memory, s.disk])?;
        Ok(())
    }

    /// Stored samples in `[t0, t1)`, oldest first; one program's when `app` is given (no GPU).
    pub fn hardware_series(&self, t0: i64, t1: i64, app: Option<&str>) -> rusqlite::Result<Vec<(i64, crate::data::HardwareSample)>> {
        let mut stmt = self.conn.prepare_cached(match app {
            Some(_) => "SELECT ts, cpu, memory, disk, 0.0 FROM hardware_app WHERE ts >= ?1 AND ts < ?2 AND app = ?3 ORDER BY ts",
            None => "SELECT ts, cpu, memory, disk, gpu FROM hardware WHERE ts >= ?1 AND ts < ?2 AND ?3 IS NULL ORDER BY ts",
        })?;
        stmt.query_map(params![t0, t1, app], |r| Ok((r.get(0)?, crate::data::HardwareSample { cpu: r.get(1)?, memory: r.get(2)?, disk: r.get(3)?, gpu: r.get(4)? })))?.collect()
    }

    /// Programs with stored hardware history since `t0`.
    pub fn hardware_apps(&self, t0: i64) -> rusqlite::Result<Vec<String>> {
        self.conn.prepare_cached("SELECT DISTINCT app FROM hardware_app WHERE ts >= ?1 ORDER BY app COLLATE NOCASE")?.query_map(params![t0], |r| r.get(0))?.collect()
    }

    /// Every remote address with recorded traffic.
    pub fn remotes(&self) -> rusqlite::Result<Vec<String>> {
        self.conn.prepare_cached("SELECT DISTINCT remote FROM traffic WHERE remote <> ''")?.query_map([], |r| r.get(0))?.collect()
    }

    pub fn clear_traffic(&self) -> rusqlite::Result<()> {
        self.conn.execute("DELETE FROM traffic", [])?;
        self.conn.execute("DELETE FROM blocked", [])?;
        Ok(())
    }

    // ---- behaviour baseline ----

    /// Bytes a program moved to internet addresses, per 10-minute bucket in `[t0, t1)`.
    pub fn wan_buckets(&self, app_id: i64, t0: i64, t1: i64) -> rusqlite::Result<Vec<(i64, f64)>> {
        let mut stmt = self.conn.prepare_cached("SELECT ts, SUM(down + up) FROM traffic WHERE scale = ?1 AND app_id = ?2 AND kind = ?3 AND ts >= ?4 AND ts < ?5 GROUP BY ts")?;
        stmt.query_map(params![Scale::S600.secs(), app_id, KIND_WAN, t0, t1], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
    }

    /// Internet addresses each program has talked to from bucket `from` on, with the first bucket each showed up in.
    pub fn wan_remotes_since(&self, from: i64) -> rusqlite::Result<Vec<(i64, String, i64)>> {
        let mut stmt = self.conn.prepare_cached("SELECT app_id, remote, MIN(ts) FROM traffic WHERE scale = ?1 AND kind = ?2 AND ts >= ?3 GROUP BY app_id, remote")?;
        stmt.query_map(params![Scale::S600.secs(), KIND_WAN, from], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
    }

    /// Newest 10-minute bucket with traffic, 0 when there is none.
    pub fn newest_bucket(&self) -> rusqlite::Result<i64> {
        self.conn.query_row("SELECT COALESCE(MAX(ts), 0) FROM traffic WHERE scale = ?1", params![Scale::S600.secs()], |r| r.get(0))
    }

    pub fn baseline_items(&self, app_id: i64, dim: &str) -> rusqlite::Result<Vec<BaselineItem>> {
        let mut stmt = self.conn.prepare_cached("SELECT val, first_seen, last_seen, state, alerted, alert_id FROM baseline_item WHERE app_id = ?1 AND dim = ?2")?;
        stmt.query_map(params![app_id, dim], |r| {
            Ok(BaselineItem { dim: dim.to_owned(), val: r.get(0)?, first_seen: r.get(1)?, last_seen: r.get(2)?, state: r.get::<_, i64>(3)? as u8, alerted: r.get(4)?, alert_id: r.get(5)? })
        })?
        .collect()
    }

    pub fn save_baseline_item(&self, app_id: i64, it: &BaselineItem) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO baseline_item (app_id, dim, val, first_seen, last_seen, state, alerted, alert_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(app_id, dim, val) DO UPDATE SET last_seen = excluded.last_seen, state = excluded.state, alerted = excluded.alerted, alert_id = excluded.alert_id",
            params![app_id, it.dim, it.val, it.first_seen, it.last_seen, i64::from(it.state), it.alerted, it.alert_id],
        )?;
        Ok(())
    }

    /// Marks the baseline item behind alert `alert_id` as normal. False when no item came from that alert.
    pub fn mark_normal(&self, alert_id: i64, now: i64) -> rusqlite::Result<bool> {
        Ok(self.conn.execute("UPDATE baseline_item SET state = ?2, last_seen = ?3 WHERE alert_id = ?1", params![alert_id, BASE_NORMAL, now])? > 0)
    }

    /// Alerts whose baseline item can still be marked normal: it exists and the user hasn't marked it yet.
    pub fn markable_alerts(&self) -> rusqlite::Result<std::collections::HashSet<i64>> {
        let mut stmt = self.conn.prepare_cached("SELECT alert_id FROM baseline_item WHERE alert_id IS NOT NULL AND state != ?1")?;
        stmt.query_map(params![BASE_NORMAL], |r| r.get(0))?.collect()
    }

    /// Forgets baseline items not seen for `days`; the ones the user marked normal stay.
    pub fn prune_baseline(&self, now: i64, days: u32) -> rusqlite::Result<()> {
        self.conn.execute("DELETE FROM baseline_item WHERE state != ?1 AND last_seen < ?2", params![BASE_NORMAL, now - i64::from(days) * 86_400])?;
        Ok(())
    }

    /// `(bucket ts, down, up)` per bucket in `[t0, t1)`.
    pub fn series(&self, scale: Scale, t0: i64, t1: i64) -> rusqlite::Result<Vec<(i64, f64, f64)>> {
        let mut stmt = self.conn.prepare_cached("SELECT ts, SUM(down), SUM(up) FROM t WHERE scale = ?1 AND ts >= ?2 AND ts < ?3 GROUP BY ts ORDER BY ts")?;
        stmt.query_map(params![scale.secs(), t0, t1], |r| Ok((r.get(0)?, r.get::<_, f64>(1)?, r.get::<_, f64>(2)?)))?.collect()
    }

    pub fn totals(&self, scale: Scale, t0: i64, t1: i64) -> rusqlite::Result<TotalsRow> {
        self.conn.query_row(
            "SELECT COALESCE(SUM(down),0), COALESCE(SUM(up),0),
                    COALESCE(SUM(CASE kind WHEN 0 THEN down END),0), COALESCE(SUM(CASE kind WHEN 0 THEN up END),0),
                    COALESCE(SUM(CASE kind WHEN 1 THEN down END),0), COALESCE(SUM(CASE kind WHEN 1 THEN up END),0)
             FROM t WHERE scale = ?1 AND ts >= ?2 AND ts < ?3",
            params![scale.secs(), t0, t1],
            |r| Ok(TotalsRow { down: r.get(0)?, up: r.get(1)?, wan: r.get::<_, f64>(2)? + r.get::<_, f64>(3)?, wan_up: r.get(3)?, lan: r.get::<_, f64>(4)? + r.get::<_, f64>(5)?, lan_up: r.get(5)? }),
        )
    }

    /// Bytes moved in `[t0, t1)` for a data quota: internet traffic only (known-local bytes are left out),
    /// of one app or of everything. Reads the coarsest scale, like the data plan.
    pub fn quota_used(&self, app_id: Option<i64>, t0: i64, t1: i64) -> rusqlite::Result<f64> {
        self.conn.query_row(
            "SELECT COALESCE(SUM(down + up), 0) FROM traffic WHERE scale = ?1 AND ts >= ?2 AND ts < ?3 AND kind <> ?4 AND (?5 IS NULL OR app_id = ?5)",
            params![Scale::S600.secs(), t0, t1, KIND_LAN, app_id],
            |r| r.get(0),
        )
    }

    /// Usage grouped by `column` (one of the fixed names below), biggest first.
    fn usage(&self, column: &str, scale: Scale, t0: i64, t1: i64) -> rusqlite::Result<Vec<UsageEntry>> {
        let sql = match column {
            "app" => "SELECT CAST(app_id AS TEXT), SUM(down), SUM(up) FROM t WHERE scale=?1 AND ts>=?2 AND ts<?3 AND app_id > 0 GROUP BY app_id ORDER BY SUM(down)+SUM(up) DESC",
            "remote" => "SELECT remote, SUM(down), SUM(up) FROM t WHERE scale=?1 AND ts>=?2 AND ts<?3 AND remote <> '' GROUP BY remote ORDER BY SUM(down)+SUM(up) DESC",
            _ => "SELECT proto, SUM(down), SUM(up) FROM t WHERE scale=?1 AND ts>=?2 AND ts<?3 AND proto <> '' GROUP BY proto ORDER BY SUM(down)+SUM(up) DESC",
        };
        let mut stmt = self.conn.prepare_cached(sql)?;
        stmt.query_map(params![scale.secs(), t0, t1], |r| Ok(UsageEntry { key: r.get(0)?, down: r.get(1)?, up: r.get(2)? }))?.collect()
    }

    /// Usage grouped by one dimension while another is fixed: "which apps talked to this host".
    pub fn grouped(&self, by: Dim, filter: (Dim, &str), scale: Scale, t0: i64, t1: i64) -> rusqlite::Result<Vec<UsageEntry>> {
        // Column names come from the closed `Dim` set, never from user input; the value is bound.
        let sql = format!(
            "SELECT CAST({b} AS TEXT), SUM(down), SUM(up) FROM t WHERE scale=?1 AND ts>=?2 AND ts<?3 AND CAST({f} AS TEXT) = ?4 AND remote <> ''
             GROUP BY {b} ORDER BY SUM(down)+SUM(up) DESC",
            b = by.column(),
            f = filter.0.column()
        );
        let mut stmt = self.conn.prepare(&sql)?;
        stmt.query_map(params![scale.secs(), t0, t1, filter.1], |r| Ok(UsageEntry { key: r.get(0)?, down: r.get(1)?, up: r.get(2)? }))?.collect()
    }

    pub fn usage_by_app(&self, scale: Scale, t0: i64, t1: i64) -> rusqlite::Result<Vec<UsageEntry>> {
        self.usage("app", scale, t0, t1)
    }
    pub fn usage_by_remote(&self, scale: Scale, t0: i64, t1: i64) -> rusqlite::Result<Vec<UsageEntry>> {
        self.usage("remote", scale, t0, t1)
    }
    pub fn usage_by_proto(&self, scale: Scale, t0: i64, t1: i64) -> rusqlite::Result<Vec<UsageEntry>> {
        self.usage("proto", scale, t0, t1)
    }

    /// Distinct remote addresses per app in the window, biggest first (for the Firewall tab's "Hosts" column).
    pub fn hosts_by_app(&self, scale: Scale, t0: i64, t1: i64) -> rusqlite::Result<Vec<(i64, String, f64)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT app_id, remote, SUM(down)+SUM(up) FROM traffic WHERE scale=?1 AND ts>=?2 AND ts<?3 AND app_id > 0 AND remote <> ''
             GROUP BY app_id, remote ORDER BY app_id, SUM(down)+SUM(up) DESC",
        )?;
        stmt.query_map(params![scale.secs(), t0, t1], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
    }

    /// Per-app `(ts, bytes)` for the activity sparkline.
    pub fn app_activity(&self, scale: Scale, t0: i64, t1: i64) -> rusqlite::Result<Vec<(i64, i64, f64)>> {
        let mut stmt = self.conn.prepare_cached("SELECT app_id, ts, SUM(down)+SUM(up) FROM traffic WHERE scale=?1 AND ts>=?2 AND ts<?3 AND app_id > 0 GROUP BY app_id, ts")?;
        stmt.query_map(params![scale.secs(), t0, t1], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
    }

    // ---- apps ----

    fn app_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AppRecord> {
        Ok(AppRecord {
            id: r.get(0)?,
            key: r.get(1)?,
            path: r.get(2)?,
            name: r.get(3)?,
            publisher: r.get(4)?,
            version: r.get(5)?,
            hash: r.get(6)?,
            signed: r.get::<_, Option<i64>>(7)?.map(|v| v != 0),
            system: r.get::<_, i64>(8)? != 0,
            first_seen: r.get(9)?,
            last_seen: r.get(10)?,
            missing_since: r.get(11)?,
            service: r.get(12)?,
        })
    }

    const APP_COLS: &'static str = "id, key, path, name, publisher, version, hash, signed, system, first_seen, last_seen, missing_since, service";

    pub fn app_by_key(&self, key: &str) -> rusqlite::Result<Option<AppRecord>> {
        self.conn.query_row(&format!("SELECT {} FROM apps WHERE key = ?1", Self::APP_COLS), params![key], Self::app_from_row).optional()
    }

    pub fn apps(&self) -> rusqlite::Result<Vec<AppRecord>> {
        let mut stmt = self.conn.prepare(&format!("SELECT {} FROM apps ORDER BY last_seen DESC", Self::APP_COLS))?;
        stmt.query_map([], Self::app_from_row)?.collect()
    }

    /// Hash of the most recently seen program with this name (names can repeat; pass the hash when known).
    pub fn hash_of(&self, name: &str) -> rusqlite::Result<Option<String>> {
        let mut stmt = self.conn.prepare_cached("SELECT hash FROM apps WHERE name = ?1 AND hash <> '' ORDER BY last_seen DESC LIMIT 1")?;
        stmt.query_row([name], |r| r.get(0)).map(Some).or_else(|e| if matches!(e, rusqlite::Error::QueryReturnedNoRows) { Ok(None) } else { Err(e) })
    }

    pub fn app_count(&self) -> rusqlite::Result<i64> {
        self.conn.query_row("SELECT COUNT(*) FROM apps", [], |r| r.get(0))
    }

    /// Inserts a new app and returns its id.
    pub fn insert_app(&self, a: &AppRecord) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO apps (key, path, name, publisher, version, hash, signed, system, first_seen, last_seen, service) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9,?10)",
            params![a.key, a.path, a.name, a.publisher, a.version, a.hash, a.signed.map(i64::from), i64::from(a.system), a.first_seen, a.service],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Updates descriptive fields (after a change was noticed and alerted).
    pub fn update_app_info(&self, a: &AppRecord) -> rusqlite::Result<()> {
        self.conn.execute("UPDATE apps SET name=?2, publisher=?3, version=?4, hash=?5, signed=?6 WHERE id=?1", params![a.id, a.name, a.publisher, a.version, a.hash, a.signed.map(i64::from)])?;
        Ok(())
    }

    pub fn touch_app(&self, id: i64, now: i64) -> rusqlite::Result<()> {
        self.conn.execute("UPDATE apps SET last_seen = ?2, missing_since = NULL WHERE id = ?1", params![id, now])?;
        Ok(())
    }

    pub fn set_missing(&self, id: i64, since: Option<i64>) -> rusqlite::Result<()> {
        self.conn.execute("UPDATE apps SET missing_since = ?2 WHERE id = ?1", params![id, since])?;
        Ok(())
    }

    // ---- hostnames ----

    pub fn set_hostname(&self, ip: &str, name: &str, now: i64) -> rusqlite::Result<()> {
        self.conn.execute("INSERT INTO hostnames (ip, name, seen) VALUES (?1,?2,?3) ON CONFLICT(ip) DO UPDATE SET name=excluded.name, seen=excluded.seen", params![ip, name, now])?;
        Ok(())
    }

    /// The name one program used for an address (shared CDN addresses serve different names to different programs).
    pub fn set_app_hostname(&self, app_id: i64, ip: &str, name: &str, now: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO app_hostnames (app_id, ip, name, seen) VALUES (?1,?2,?3,?4) ON CONFLICT(app_id, ip) DO UPDATE SET name=excluded.name, seen=excluded.seen",
            params![app_id, ip, name, now],
        )?;
        Ok(())
    }

    /// The name `app_id` itself looked up or sent for `ip`, if it is known.
    pub fn app_hostname(&self, app_id: i64, ip: &str) -> Option<String> {
        let mut stmt = self.conn.prepare_cached("SELECT name FROM app_hostnames WHERE app_id = ?1 AND ip = ?2").ok()?;
        stmt.query_row(params![app_id, ip], |r| r.get(0)).optional().ok().flatten()
    }

    pub fn app_hostnames(&self) -> rusqlite::Result<Vec<(i64, String, String)>> {
        let mut stmt = self.conn.prepare("SELECT app_id, ip, name FROM app_hostnames")?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
    }

    /// Usage per (program, remote address): `(app_id, remote, down, up)`.
    pub fn usage_by_app_remote(&self, scale: Scale, t0: i64, t1: i64) -> rusqlite::Result<Vec<(i64, String, f64, f64)>> {
        let mut stmt = self.conn.prepare_cached("SELECT app_id, remote, SUM(down), SUM(up) FROM t WHERE scale=?1 AND ts>=?2 AND ts<?3 AND remote <> '' GROUP BY app_id, remote")?;
        stmt.query_map(params![scale.secs(), t0, t1], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect()
    }

    pub fn hostnames(&self) -> rusqlite::Result<Vec<(String, String)>> {
        self.hostnames_since(i64::MIN)
    }

    /// Names last seen at or after `since`: what the live views keep in memory (older ones stay here for history).
    pub fn hostnames_since(&self, since: i64) -> rusqlite::Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare("SELECT ip, name FROM hostnames WHERE seen >= ?1")?;
        stmt.query_map(params![since], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
    }

    // ---- DNS log ----

    pub fn add_dns(&mut self, rows: &[DnsEntry]) -> rusqlite::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached("INSERT INTO dns_log (ts, app, name, qtype, ips, status) VALUES (?1,?2,?3,?4,?5,?6)")?;
            for r in rows {
                stmt.execute(params![r.ts, r.app, r.name, r.qtype, r.ips.join(";"), r.status])?;
            }
        }
        tx.commit()
    }

    /// The newest `limit` lookups, newest first.
    pub fn dns_recent(&self, limit: usize) -> rusqlite::Result<Vec<DnsEntry>> {
        let mut stmt = self.conn.prepare_cached("SELECT ts, app, name, qtype, ips, status FROM dns_log ORDER BY ts DESC, rowid DESC LIMIT ?1")?;
        stmt.query_map([limit as i64], |r| {
            let ips: String = r.get(4)?;
            Ok(DnsEntry {
                ts: r.get(0)?,
                app: r.get(1)?,
                name: r.get(2)?,
                qtype: r.get(3)?,
                ips: ips.split(';').filter(|s| !s.is_empty()).map(str::to_owned).collect(),
                status: r.get(5)?,
                listed: false,
            })
        })?
        .collect()
    }

    pub fn prune_dns(&self, now: i64, days: u32) -> rusqlite::Result<()> {
        self.conn.execute("DELETE FROM dns_log WHERE ts < ?1", params![now - i64::from(days) * 86_400])?;
        Ok(())
    }

    // ---- alerts ----

    /// Stores an alert, chained to the one before it: each hash covers the previous hash and the contents
    /// (not `unread`, which `mark_read` changes).
    pub fn insert_alert(&self, a: &NewAlert) -> rusqlite::Result<i64> {
        // Immediate, so a second writer waits (busy_timeout) instead of failing after it has read the previous hash.
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let prev: String = tx.query_row("SELECT hash FROM alerts ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).optional()?.unwrap_or_default();
        let hash = alert_hash(&prev, a);
        tx.execute(
            "INSERT INTO alerts (ts, kind, important, app, text, target, country, unread, prev_hash, hash) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![a.ts, a.kind, i64::from(a.important), a.app, a.text, a.target, a.country, i64::from(a.unread), prev, hash],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Walks every entry oldest first. An entry fails when its stored hash no longer matches its contents, or its
    /// `prev_hash` is not the hash of the entry before it. Editing one entry breaks it; removing one breaks the next.
    /// shortcut: removing the newest entries leaves a valid chain; the head hash shown to the user is the only anchor.
    pub fn verify_alerts(&self) -> rusqlite::Result<AlertCheck> {
        let mut stmt = self.conn.prepare("SELECT id, ts, kind, important, app, text, target, country, prev_hash, hash FROM alerts ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            let a = NewAlert { ts: r.get(1)?, kind: r.get(2)?, important: r.get::<_, i64>(3)? != 0, app: r.get(4)?, text: r.get(5)?, target: r.get(6)?, country: r.get(7)?, unread: false };
            Ok((r.get::<_, i64>(0)?, a, r.get::<_, String>(8)?, r.get::<_, String>(9)?))
        })?;
        let mut out = AlertCheck::default();
        let mut prev = String::new();
        let mut started = false;
        for row in rows {
            let (id, a, stored_prev, hash) = row?;
            if hash.is_empty() {
                // Blank hashes are only allowed before the chain starts; after that one means a hash was wiped.
                if started {
                    out.first_bad.get_or_insert(id);
                } else {
                    out.unchained += 1;
                }
                continue;
            }
            started = true;
            out.checked += 1;
            if stored_prev != prev || alert_hash(&prev, &a) != hash {
                out.first_bad.get_or_insert(id);
            }
            prev = hash;
        }
        out.head = prev;
        Ok(out)
    }

    /// Removes alerts RustWarden raised in error, with their baseline marks, and re-links the chain over the gap.
    /// `Ok(false)` without changing anything when the chain already fails its check, so a real break is never hidden.
    pub fn remove_alerts(&self, ids: &[i64]) -> rusqlite::Result<bool> {
        let Some(&first) = ids.iter().min() else { return Ok(true) };
        if self.verify_alerts()?.first_bad.is_some() {
            return Ok(false);
        }
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        for id in ids {
            tx.execute("DELETE FROM alerts WHERE id = ?1", params![id])?;
            tx.execute("DELETE FROM baseline_item WHERE alert_id = ?1", params![id])?;
        }
        let mut prev: String = tx.query_row("SELECT hash FROM alerts WHERE id < ?1 AND hash != '' ORDER BY id DESC LIMIT 1", params![first], |r| r.get(0)).optional()?.unwrap_or_default();
        let rows: Vec<(i64, NewAlert, String)> = {
            let mut stmt = tx.prepare("SELECT id, ts, kind, important, app, text, target, country, hash FROM alerts WHERE id > ?1 ORDER BY id")?;
            stmt.query_map(params![first], |r| {
                let a = NewAlert { ts: r.get(1)?, kind: r.get(2)?, important: r.get::<_, i64>(3)? != 0, app: r.get(4)?, text: r.get(5)?, target: r.get(6)?, country: r.get(7)?, unread: false };
                Ok((r.get(0)?, a, r.get(8)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        for (id, a, hash) in rows {
            if hash.is_empty() && prev.is_empty() {
                continue; // from before the chain started
            }
            let next = alert_hash(&prev, &a);
            tx.execute("UPDATE alerts SET prev_hash = ?1, hash = ?2 WHERE id = ?3", params![prev, next, id])?;
            prev = next;
        }
        tx.commit()?;
        Ok(true)
    }

    /// (id, target) of every alert of one kind.
    pub fn alerts_of_kind(&self, kind: &str) -> rusqlite::Result<Vec<(i64, String)>> {
        let mut stmt = self.conn.prepare("SELECT id, target FROM alerts WHERE kind = ?1 ORDER BY id")?;
        stmt.query_map(params![kind], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
    }

    /// Newest first.
    pub fn alerts(&self, limit: usize) -> rusqlite::Result<Vec<StoredAlert>> {
        let mut stmt = self.conn.prepare_cached("SELECT id, ts, kind, important, app, text, target, country, unread FROM alerts ORDER BY ts DESC, id DESC LIMIT ?1")?;
        stmt.query_map(params![limit as i64], |r| {
            Ok(StoredAlert {
                id: r.get(0)?,
                new: NewAlert {
                    ts: r.get(1)?,
                    kind: r.get(2)?,
                    important: r.get::<_, i64>(3)? != 0,
                    app: r.get(4)?,
                    text: r.get(5)?,
                    target: r.get(6)?,
                    country: r.get(7)?,
                    unread: r.get::<_, i64>(8)? != 0,
                },
            })
        })?
        .collect()
    }

    /// Alerts raised per kind key, all time.
    pub fn alert_counts(&self) -> rusqlite::Result<Vec<(String, u64)>> {
        let mut stmt = self.conn.prepare_cached("SELECT kind, COUNT(*) FROM alerts GROUP BY kind ORDER BY kind")?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)))?.collect()
    }

    /// Alerts raised per kind key in `[t0, t1)`.
    pub fn alert_counts_between(&self, t0: i64, t1: i64) -> rusqlite::Result<Vec<(String, u64)>> {
        let mut stmt = self.conn.prepare_cached("SELECT kind, COUNT(*) FROM alerts WHERE ts >= ?1 AND ts < ?2 GROUP BY kind ORDER BY kind")?;
        stmt.query_map(params![t0, t1], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)))?.collect()
    }

    /// Internet addresses seen in `[t0, t1)`, from the ten-minute history.
    pub fn wan_remotes_between(&self, t0: i64, t1: i64) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self.conn.prepare_cached("SELECT DISTINCT remote FROM traffic WHERE scale = ?1 AND kind = ?2 AND remote <> '' AND ts >= ?3 AND ts < ?4")?;
        stmt.query_map(params![Scale::S600.secs(), KIND_WAN, t0, t1], |r| r.get(0))?.collect()
    }

    /// Start of the oldest ten-minute bucket kept, if any.
    pub fn history_start(&self) -> rusqlite::Result<Option<i64>> {
        self.conn.query_row("SELECT MIN(ts) FROM traffic WHERE scale = ?1", params![Scale::S600.secs()], |r| r.get(0))
    }

    /// Alerts from `since` on, oldest first, for export.
    pub fn alerts_since(&self, since: i64) -> rusqlite::Result<Vec<AlertRow>> {
        let mut stmt = self.conn.prepare_cached("SELECT ts, kind, app, text, target, country, important FROM alerts WHERE ts >= ?1 ORDER BY ts, id")?;
        stmt.query_map(params![since], |r| {
            Ok(AlertRow { ts: r.get(0)?, kind: r.get(1)?, app: r.get(2)?, text: r.get(3)?, target: r.get(4)?, country: r.get(5)?, important: r.get::<_, i64>(6)? != 0 })
        })?
        .collect()
    }

    /// Ten-minute traffic rows from `since` on, oldest first, with the app name and any host name seen for the remote.
    /// The country is left empty: the database does not know geography.
    pub fn history_rows(&self, since: i64) -> rusqlite::Result<Vec<TrafficRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT t.ts, a.name, t.remote, COALESCE(h.name, ''), t.down, t.up FROM traffic t JOIN apps a ON a.id = t.app_id LEFT JOIN hostnames h ON h.ip = t.remote WHERE t.scale = ?1 AND t.ts >= ?2 ORDER BY t.ts, a.name, t.remote",
        )?;
        stmt.query_map(params![Scale::S600.secs(), since], |r| {
            Ok(TrafficRow { ts: r.get(0)?, app: r.get(1)?, remote: r.get(2)?, host: r.get(3)?, down: r.get::<_, i64>(4)? as u64, up: r.get::<_, i64>(5)? as u64, ..Default::default() })
        })?
        .collect()
    }

    pub fn mark_read(&self, id: Option<i64>) -> rusqlite::Result<()> {
        match id {
            Some(id) => self.conn.execute("UPDATE alerts SET unread = 0 WHERE id = ?1", params![id])?,
            None => self.conn.execute("UPDATE alerts SET unread = 0", [])?,
        };
        Ok(())
    }

    // ---- devices ----

    pub fn devices(&self, network: &str) -> rusqlite::Result<Vec<DeviceRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT network, mac, ip, name, vendor, system, kind, first_seen, last_seen, online, seen_count, COALESCE(ports, ''), trusted FROM devices WHERE network = ?1 ORDER BY online DESC, ip",
        )?;
        stmt.query_map(params![network], |r| {
            Ok(DeviceRow {
                network: r.get(0)?,
                mac: r.get(1)?,
                ip: r.get(2)?,
                name: r.get(3)?,
                vendor: r.get(4)?,
                system: r.get(5)?,
                kind: r.get(6)?,
                first_seen: r.get(7)?,
                last_seen: r.get(8)?,
                online: r.get::<_, i64>(9)? != 0,
                seen_count: r.get(10)?,
                ports: r.get(11)?,
                trusted: r.get::<_, i64>(12)? != 0,
            })
        })?
        .collect()
    }

    /// MACs and addresses of devices that were never port-scanned.
    pub fn unscanned_devices(&self, network: &str) -> rusqlite::Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare("SELECT mac, ip FROM devices WHERE network = ?1 AND ports IS NULL")?;
        stmt.query_map(params![network], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
    }

    pub fn set_ports(&self, network: &str, mac: &str, ports: &str) -> rusqlite::Result<()> {
        self.conn.execute("UPDATE devices SET ports = ?3 WHERE network = ?1 AND mac = ?2", params![network, mac, ports])?;
        Ok(())
    }

    /// Inserts or refreshes a device found by a scan. A name the user typed is kept (`keep_name`).
    pub fn upsert_device(&self, d: &DeviceRow) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO devices (network, mac, ip, name, vendor, system, kind, first_seen, last_seen, online)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8,?9)
             ON CONFLICT(network, mac) DO UPDATE SET ip=excluded.ip, vendor=excluded.vendor,
               name=CASE WHEN name = '' THEN excluded.name ELSE name END,
               system=CASE WHEN excluded.system <> '' THEN excluded.system ELSE system END,
               kind=excluded.kind, last_seen=excluded.last_seen, online=excluded.online,
               seen_count=seen_count + (online = 0)",
            params![d.network, d.mac, d.ip, d.name, d.vendor, d.system, d.kind, d.last_seen, i64::from(d.online)],
        )?;
        Ok(())
    }

    pub fn set_devices_offline(&self, network: &str, except: &[String]) -> rusqlite::Result<()> {
        let mut stmt = self.conn.prepare("SELECT mac FROM devices WHERE network = ?1 AND online = 1")?;
        let macs: Vec<String> = stmt.query_map(params![network], |r| r.get(0))?.collect::<Result<_, _>>()?;
        for mac in macs.into_iter().filter(|m| !except.contains(m)) {
            self.conn.execute("UPDATE devices SET online = 0 WHERE network = ?1 AND mac = ?2", params![network, mac])?;
        }
        Ok(())
    }

    pub fn set_trusted(&self, network: &str, mac: &str, trusted: bool) -> rusqlite::Result<()> {
        self.conn.execute("UPDATE devices SET trusted = ?3 WHERE network = ?1 AND mac = ?2", params![network, mac, i64::from(trusted)])?;
        Ok(())
    }

    pub fn rename_device(&self, network: &str, mac: &str, name: &str) -> rusqlite::Result<()> {
        self.conn.execute("UPDATE devices SET name = ?3 WHERE network = ?1 AND mac = ?2", params![network, mac, name])?;
        Ok(())
    }

    pub fn forget_network(&self, network: &str) -> rusqlite::Result<()> {
        self.conn.execute("DELETE FROM devices WHERE network = ?1", params![network])?;
        Ok(())
    }

    // ---- key/value ----

    pub fn kv_get(&self, k: &str) -> Option<String> {
        self.conn.query_row("SELECT v FROM kv WHERE k = ?1", params![k], |r| r.get(0)).optional().ok().flatten()
    }

    pub fn kv_set(&self, k: &str, v: &str) -> rusqlite::Result<()> {
        self.conn.execute("INSERT INTO kv (k, v) VALUES (?1,?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v", params![k, v])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delta(app: i64, remote: &str, kind: u8, down: u64, up: u64) -> TrafficDelta {
        TrafficDelta { app_id: app, remote: remote.into(), proto: "Other".into(), kind, down, up }
    }

    #[test]
    fn traffic_rolls_into_every_resolution() {
        let mut db = Db::memory();
        db.add_traffic(1_000_001, &[delta(1, "8.8.8.8", KIND_WAN, 100, 10)]).unwrap();
        db.add_traffic(1_000_002, &[delta(1, "8.8.8.8", KIND_WAN, 50, 5)]).unwrap();
        // Same second and key accumulate.
        db.add_traffic(1_000_002, &[delta(1, "8.8.8.8", KIND_WAN, 1, 1)]).unwrap();

        let s1 = db.series(Scale::S1, 1_000_000, 1_000_010).unwrap();
        assert_eq!(s1, vec![(1_000_001, 100.0, 10.0), (1_000_002, 51.0, 6.0)]);
        // 1_000_001 and 1_000_002 share the 30 s bucket starting at 1_000_000 - 1_000_000 % 30.
        let s30 = db.series(Scale::S30, 0, i64::MAX).unwrap();
        assert_eq!(s30.len(), 1);
        assert_eq!((s30[0].1, s30[0].2), (151.0, 16.0));
    }

    #[test]
    fn totals_split_wan_and_lan() {
        let mut db = Db::memory();
        db.add_traffic(100, &[delta(1, "8.8.8.8", KIND_WAN, 100, 20), delta(1, "192.168.1.1", KIND_LAN, 40, 10), delta(0, "", KIND_UNKNOWN, 5, 5)]).unwrap();
        let t = db.totals(Scale::S1, 0, 1000).unwrap();
        assert_eq!((t.down, t.up), (145.0, 35.0));
        assert_eq!((t.wan, t.wan_up), (120.0, 20.0));
        assert_eq!((t.lan, t.lan_up), (50.0, 10.0));
        // A window that excludes the bucket sees nothing.
        assert_eq!(db.totals(Scale::S1, 101, 1000).unwrap().down, 0.0);
    }

    #[test]
    fn filter_narrows_reads() {
        let mut db = Db::memory();
        db.add_traffic(100, &[delta(1, "8.8.8.8", KIND_WAN, 100, 20), delta(2, "192.168.1.1", KIND_LAN, 40, 10)]).unwrap();
        let f = |app: Option<&str>, scope, dir| TrafficFilter { app: app.map(|k| (k.to_owned(), String::new())), scope, dir, network: String::new() };
        db.set_filter(&f(None, Scope::Lan, TrafficDir::Both), None).unwrap();
        assert_eq!(db.totals(Scale::S1, 0, 1000).unwrap().down, 40.0);
        db.set_filter(&f(Some("1"), Scope::Both, TrafficDir::Out), None).unwrap();
        let t = db.totals(Scale::S1, 0, 1000).unwrap();
        assert_eq!((t.down, t.up), (0.0, 20.0));
        assert_eq!(db.usage_by_app(Scale::S1, 0, 1000).unwrap().len(), 1);
        db.set_filter(&TrafficFilter::default(), Some(&["8.8.8.8".to_owned(), "x'; DROP".to_owned()])).unwrap();
        assert_eq!(db.totals(Scale::S1, 0, 1000).unwrap().down, 100.0);
        db.set_filter(&TrafficFilter::default(), Some(&[])).unwrap();
        assert_eq!(db.totals(Scale::S1, 0, 1000).unwrap().down, 0.0);
        db.set_filter(&TrafficFilter::default(), None).unwrap();
        assert_eq!(db.totals(Scale::S1, 0, 1000).unwrap().down, 140.0);
    }

    #[test]
    fn retention_prunes_each_scale_separately() {
        let mut db = Db::memory();
        let now = 10_000_000;
        db.add_traffic(now - 2 * 3600, &[delta(1, "1.1.1.1", KIND_WAN, 1, 1)]).unwrap();
        db.add_traffic(now - 10, &[delta(1, "1.1.1.1", KIND_WAN, 1, 1)]).unwrap();
        db.prune(now, 30).unwrap();
        // The 1 s row from two hours ago is gone; the 600 s row is still there (30 days).
        assert_eq!(db.series(Scale::S1, 0, i64::MAX).unwrap().len(), 1);
        assert_eq!(db.series(Scale::S600, 0, i64::MAX).unwrap().len(), 2);
        db.clear_traffic().unwrap();
        assert!(db.series(Scale::S600, 0, i64::MAX).unwrap().is_empty());
    }

    #[test]
    fn blocked_attempts_add_up_prune_and_clear() {
        let mut db = Db::memory();
        let rows = |n| std::collections::HashMap::from([((600, "9.9.9.9".to_owned()), n)]);
        db.add_blocked(&rows(2)).unwrap();
        db.add_blocked(&rows(3)).unwrap();
        assert_eq!(db.blocked_by_remote(0, 1000).unwrap(), [("9.9.9.9".to_owned(), 5)]);
        assert!(db.blocked_by_remote(0, 600).unwrap().is_empty());
        db.prune(600 + 31 * 86_400, 30).unwrap();
        assert!(db.blocked_by_remote(0, i64::MAX).unwrap().is_empty());
        db.add_blocked(&rows(1)).unwrap();
        db.clear_traffic().unwrap();
        assert!(db.blocked_by_remote(0, i64::MAX).unwrap().is_empty());
    }

    #[test]
    fn usage_orders_biggest_first() {
        let mut db = Db::memory();
        db.add_traffic(5, &[delta(1, "1.1.1.1", KIND_WAN, 10, 0), delta(2, "2.2.2.2", KIND_WAN, 90, 10)]).unwrap();
        let apps = db.usage_by_app(Scale::S1, 0, 100).unwrap();
        assert_eq!(apps.iter().map(|a| a.key.as_str()).collect::<Vec<_>>(), ["2", "1"]);
        assert_eq!(db.usage_by_remote(Scale::S1, 0, 100).unwrap()[0].key, "2.2.2.2");
    }

    #[test]
    fn dns_log_round_trips_and_prunes() {
        let mut db = Db::memory();
        let mk = |ts, name: &str, ips: &[&str]| DnsEntry { ts, app: "curl.exe".into(), name: name.into(), qtype: 1, ips: ips.iter().map(|s| s.to_string()).collect(), status: 0, listed: false };
        db.add_dns(&[mk(10, "old.example", &["1.1.1.1"]), mk(86_400 * 3, "new.example", &["2.2.2.2", "::1"]), mk(86_400 * 3 + 1, "nxd.example", &[])]).unwrap();
        let all = db.dns_recent(10).unwrap();
        assert_eq!(all.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["nxd.example", "new.example", "old.example"]);
        assert_eq!(all[1].ips, ["2.2.2.2", "::1"]);
        assert!(all[0].ips.is_empty());
        assert_eq!(db.dns_recent(1).unwrap().len(), 1);
        db.prune_dns(86_400 * 3 + 5, 1).unwrap();
        assert_eq!(db.dns_recent(10).unwrap().len(), 2);
    }

    #[test]
    fn alerts_round_trip_and_mark_read() {
        let db = Db::memory();
        let mk = |ts| NewAlert { ts, kind: "arp".into(), important: true, app: "ARP".into(), text: "t".into(), target: "x".into(), country: String::new(), unread: true };
        let a = db.insert_alert(&mk(10)).unwrap();
        db.insert_alert(&mk(20)).unwrap();
        let all = db.alerts(10).unwrap();
        assert_eq!(all[0].new.ts, 20);
        db.mark_read(Some(a)).unwrap();
        assert_eq!(db.alerts(10).unwrap().iter().filter(|a| a.new.unread).count(), 1);
        db.mark_read(None).unwrap();
        assert!(db.alerts(10).unwrap().iter().all(|a| !a.new.unread));
    }

    #[test]
    fn only_recently_seen_hostnames_are_loaded_for_memory() {
        let db = Db::memory();
        db.set_hostname("1.1.1.1", "old.example", 100).unwrap();
        db.set_hostname("2.2.2.2", "new.example", 200).unwrap();
        assert_eq!(db.hostnames_since(150).unwrap(), vec![("2.2.2.2".to_owned(), "new.example".to_owned())]);
        assert_eq!(db.hostnames().unwrap().len(), 2);
    }

    #[test]
    fn concurrent_writers_all_store_and_keep_the_chain() {
        let path = std::env::temp_dir().join(format!("rustwarden-chain-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Db::open(&path).unwrap();
        let writers: Vec<_> = (0..4)
            .map(|w| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let db = Db::open(&path).unwrap();
                    for i in 0..25 {
                        db.insert_alert(&NewAlert {
                            ts: w * 100 + i,
                            kind: "arp".into(),
                            important: true,
                            app: "ARP".into(),
                            text: "t".into(),
                            target: "x".into(),
                            country: String::new(),
                            unread: true,
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        let db = Db::open(&path).unwrap();
        assert_eq!(db.alerts(1000).unwrap().len(), 100);
        let check = db.verify_alerts().unwrap();
        assert_eq!((check.checked, check.first_bad), (100, None));
        drop(db);
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
    }

    fn chained(db: &Db, n: i64) -> Vec<i64> {
        let mk = |ts| NewAlert { ts, kind: "arp".into(), important: true, app: "ARP".into(), text: "t".into(), target: "x".into(), country: String::new(), unread: true };
        (0..n).map(|i| db.insert_alert(&mk(10 + i)).unwrap()).collect()
    }

    #[test]
    fn alert_chain_survives_reads_and_names_the_first_change() {
        let db = Db::memory();
        let ids = chained(&db, 4);
        db.mark_read(None).unwrap();
        let ok = db.verify_alerts().unwrap();
        assert_eq!((ok.checked, ok.unchained, ok.first_bad), (4, 0, None));
        assert_eq!(ok.head.len(), 64);

        db.conn.execute("UPDATE alerts SET text = 'changed' WHERE id = ?1", params![ids[1]]).unwrap();
        assert_eq!(db.verify_alerts().unwrap().first_bad, Some(ids[1]));
    }

    #[test]
    fn removing_an_entry_breaks_the_link_after_it() {
        let db = Db::memory();
        let ids = chained(&db, 4);
        db.conn.execute("DELETE FROM alerts WHERE id = ?1", params![ids[1]]).unwrap();
        let check = db.verify_alerts().unwrap();
        assert_eq!((check.checked, check.first_bad), (3, Some(ids[2])));
    }

    #[test]
    fn removed_alerts_leave_a_chain_that_checks() {
        let db = Db::memory();
        let ids = chained(&db, 5);
        assert!(db.remove_alerts(&[ids[1], ids[3]]).unwrap());
        let check = db.verify_alerts().unwrap();
        assert_eq!((check.checked, check.first_bad), (3, None));
        // A chain that already fails is left alone.
        db.conn.execute("UPDATE alerts SET text = 'changed' WHERE id = ?1", params![ids[2]]).unwrap();
        assert!(!db.remove_alerts(&[ids[4]]).unwrap());
        assert_eq!(db.verify_alerts().unwrap().checked, 3);
    }

    #[test]
    fn history_export_joins_names_and_respects_the_window() {
        let mut db = Db::memory();
        let app = db.insert_app(&AppRecord { key: "c:\\curl.exe".into(), path: "C:\\curl.exe".into(), name: "curl".into(), first_seen: 1, ..Default::default() }).unwrap();
        db.add_traffic(1_000_000, &[delta(app, "8.8.8.8", KIND_WAN, 100, 10)]).unwrap();
        db.set_hostname("8.8.8.8", "dns.google", 0).unwrap();
        let rows = db.history_rows(0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].app.as_str(), rows[0].host.as_str(), rows[0].down, rows[0].up), ("curl", "dns.google", 100, 10));
        assert_eq!(db.history_rows(i64::MAX).unwrap().len(), 0);

        db.insert_alert(&NewAlert { ts: 50, kind: "arp".into(), important: false, app: "ARP".into(), text: "t".into(), target: "x".into(), country: String::new(), unread: true }).unwrap();
        assert_eq!(db.alerts_since(51).unwrap().len(), 0);
        assert_eq!(db.alerts_since(0).unwrap()[0].kind, "arp");
    }

    #[test]
    fn report_queries_split_the_week_from_what_came_before() {
        let mut db = Db::memory();
        assert_eq!(db.history_start().unwrap(), None);
        let app = db.insert_app(&AppRecord { key: "c:\\a.exe".into(), path: "C:\\a.exe".into(), name: "a".into(), first_seen: 1, ..Default::default() }).unwrap();
        db.add_traffic(1_000, &[delta(app, "1.1.1.1", KIND_WAN, 1, 1), delta(app, "192.168.1.1", KIND_LAN, 1, 1)]).unwrap();
        db.add_traffic(9_000, &[delta(app, "8.8.8.8", KIND_WAN, 1, 1)]).unwrap();
        assert_eq!(db.history_start().unwrap(), Some(600));
        assert_eq!(db.wan_remotes_between(i64::MIN, 5_000).unwrap(), ["1.1.1.1"]);
        assert_eq!(db.wan_remotes_between(5_000, i64::MAX).unwrap(), ["8.8.8.8"]);

        let mk = |ts, kind: &str| NewAlert { ts, kind: kind.into(), important: false, app: "a".into(), text: "t".into(), target: "x".into(), country: String::new(), unread: true };
        for (ts, kind) in [(10, "quota"), (20, "quota"), (30, "arp"), (99, "arp")] {
            db.insert_alert(&mk(ts, kind)).unwrap();
        }
        assert_eq!(db.alert_counts_between(0, 50).unwrap(), [("arp".to_string(), 1), ("quota".to_string(), 2)]);
    }

    #[test]
    fn entries_from_before_the_chain_are_counted_not_failed() {
        let db = Db::memory();
        db.conn.execute("INSERT INTO alerts (ts, kind, important, app, text, target, country, unread) VALUES (1, 'arp', 1, 'a', 't', 'x', '', 0)", []).unwrap();
        chained(&db, 2);
        let check = db.verify_alerts().unwrap();
        assert_eq!((check.unchained, check.checked, check.first_bad), (1, 2, None));
        assert!(check.summary().starts_with("Alert log intact: 2 entries checked, 1 from before"));
    }

    #[test]
    fn app_records_and_missing_state() {
        let db = Db::memory();
        let id = db.insert_app(&AppRecord { key: "c:\\a.exe".into(), path: "C:\\a.exe".into(), name: "a".into(), first_seen: 5, ..Default::default() }).unwrap();
        let mut rec = db.app_by_key("c:\\a.exe").unwrap().unwrap();
        assert_eq!((rec.id, rec.first_seen, rec.missing_since), (id, 5, None));
        db.set_missing(id, Some(99)).unwrap();
        assert_eq!(db.app_by_key("c:\\a.exe").unwrap().unwrap().missing_since, Some(99));
        db.touch_app(id, 120).unwrap();
        assert_eq!(db.app_by_key("c:\\a.exe").unwrap().unwrap().missing_since, None);
        rec.version = "2".into();
        db.update_app_info(&rec).unwrap();
        assert_eq!(db.app_by_key("c:\\a.exe").unwrap().unwrap().version, "2");
    }

    #[test]
    fn service_rows_keep_their_service() {
        let db = Db::memory();
        let host = r"C:\Windows\System32\svchost.exe";
        db.insert_app(&AppRecord {
            key: format!("{host}|svc:bits"),
            path: host.into(),
            name: "Background Intelligent Transfer Service (BITS)".into(),
            service: "bits".into(),
            first_seen: 5,
            ..Default::default()
        })
        .unwrap();
        db.insert_app(&AppRecord { key: host.to_lowercase(), path: host.into(), name: "Host Process for Windows Services".into(), first_seen: 5, ..Default::default() }).unwrap();
        let svc = db.app_by_key(&format!("{host}|svc:bits")).unwrap().unwrap();
        assert_eq!(svc.service, "bits");
        assert_eq!(db.app_by_key(&host.to_lowercase()).unwrap().unwrap().service, "");
    }

    #[test]
    fn devices_keep_user_names_and_go_offline() {
        let db = Db::memory();
        let d = DeviceRow { network: "net".into(), mac: "aa".into(), ip: "192.168.1.5".into(), name: String::new(), vendor: "V".into(), last_seen: 10, online: true, ..Default::default() };
        db.upsert_device(&d).unwrap();
        db.rename_device("other", "aa", "Elsewhere").unwrap();
        db.rename_device("net", "aa", "Printer").unwrap();
        db.set_trusted("net", "aa", true).unwrap();
        db.upsert_device(&DeviceRow { last_seen: 30, ..d.clone() }).unwrap();
        assert!(db.devices("net").unwrap()[0].trusted); // a rescan keeps it
        db.upsert_device(&DeviceRow { ip: "192.168.1.6".into(), last_seen: 20, ..d.clone() }).unwrap();
        let got = db.devices("net").unwrap();
        assert_eq!((got[0].name.as_str(), got[0].ip.as_str(), got[0].first_seen), ("Printer", "192.168.1.6", 10));
        assert_eq!(got[0].seen_count, 1, "a rescan while online doesn't count");
        assert_eq!(db.unscanned_devices("net").unwrap().len(), 1);
        db.set_ports("net", "aa", "22,80").unwrap();
        assert!(db.unscanned_devices("net").unwrap().is_empty());
        assert_eq!(db.devices("net").unwrap()[0].ports, "22,80");
        db.set_devices_offline("net", &[]).unwrap();
        assert!(!db.devices("net").unwrap()[0].online);
        db.upsert_device(&d).unwrap();
        assert_eq!(db.devices("net").unwrap()[0].seen_count, 2, "back online after being offline counts");
        // A name found on a later scan fills an empty one.
        let b = DeviceRow { mac: "bb".into(), ..d.clone() };
        db.upsert_device(&b).unwrap();
        db.upsert_device(&DeviceRow { name: "nas".into(), ..b }).unwrap();
        assert!(db.devices("net").unwrap().iter().any(|x| x.mac == "bb" && x.name == "nas"));
        db.forget_network("net").unwrap();
        assert!(db.devices("net").unwrap().is_empty());
    }
}

#[cfg(test)]
mod inspect {
    use super::*;

    /// Manual: `CC_DB=path cargo test inspect_db -- --ignored --nocapture` prints what a Live run recorded.
    #[test]
    #[ignore]
    fn inspect_db() {
        let db = Db::open(std::path::Path::new(&std::env::var("CC_DB").unwrap())).unwrap();
        let t = db.totals(Scale::S600, 0, i64::MAX).unwrap();
        println!("totals {t:?}");
        for e in db.usage_by_proto(Scale::S600, 0, i64::MAX).unwrap().iter().take(8) {
            println!("proto {} {} {}", e.key, e.down, e.up);
        }
        let apps = db.apps().unwrap();
        for e in db.usage_by_app(Scale::S600, 0, i64::MAX).unwrap().iter().take(8) {
            let name = apps.iter().find(|a| a.id.to_string() == e.key).map(|a| a.name.clone()).unwrap_or_default();
            println!("app {name} {} {}", e.down, e.up);
        }
        for e in db.usage_by_remote(Scale::S600, 0, i64::MAX).unwrap().iter().take(5) {
            println!("host {} {}", e.key, e.down + e.up);
        }
        println!("hostnames {}", db.hostnames().unwrap().len());
    }
}

#[cfg(test)]
mod inspect_detail {
    use super::*;

    /// Manual: like `inspect_db`, for the per-host app breakdown the detail popup uses.
    #[test]
    #[ignore]
    fn inspect_detail() {
        let db = Db::open(std::path::Path::new(&std::env::var("CC_DB").unwrap())).unwrap();
        let apps = db.apps().unwrap();
        let top = db.usage_by_remote(Scale::S600, 0, i64::MAX).unwrap();
        for host in top.iter().take(3) {
            println!("detail host {}", host.key);
            for e in db.grouped(Dim::App, (Dim::Remote, &host.key), Scale::S600, 0, i64::MAX).unwrap() {
                let name = apps.iter().find(|a| a.id.to_string() == e.key).map(|a| a.name.clone()).unwrap_or_default();
                println!("detail   {name} {} {}", e.down, e.up);
            }
        }
    }
}
