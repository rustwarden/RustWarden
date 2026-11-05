//! One row per finished test.

use super::SpeedResult;
use crate::live::db::Db;
use rusqlite::params;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS speedtest_results (
    ts INTEGER PRIMARY KEY, ping REAL NOT NULL, jitter REAL NOT NULL, down REAL NOT NULL, up REAL NOT NULL,
    loss REAL NOT NULL, server TEXT NOT NULL, isp TEXT NOT NULL, url TEXT NOT NULL,
    server_ip TEXT NOT NULL DEFAULT '', client_ip TEXT NOT NULL DEFAULT '');
";

/// Databases created before the route map; `Db::open` runs these and ignores \"duplicate column\".
pub const MIGRATIONS: [&str; 2] = ["ALTER TABLE speedtest_results ADD COLUMN server_ip TEXT NOT NULL DEFAULT ''", "ALTER TABLE speedtest_results ADD COLUMN client_ip TEXT NOT NULL DEFAULT ''"];

impl Db {
    pub fn speedtest_put(&self, r: &SpeedResult) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO speedtest_results (ts, ping, jitter, down, up, loss, server, isp, url, server_ip, client_ip) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![r.ts, r.ping_ms, r.jitter_ms, r.down_mbps, r.up_mbps, r.loss, r.server, r.isp, r.url, r.server_ip, r.client_ip],
        )?;
        Ok(())
    }

    /// Results from `since` on, oldest first.
    pub fn speedtest_since(&self, since: i64) -> rusqlite::Result<Vec<SpeedResult>> {
        let mut stmt = self.conn.prepare_cached("SELECT ts, ping, jitter, down, up, loss, server, isp, url, server_ip, client_ip FROM speedtest_results WHERE ts >= ?1 ORDER BY ts")?;
        stmt.query_map(params![since], |r| {
            Ok(SpeedResult {
                ts: r.get(0)?,
                ping_ms: r.get(1)?,
                jitter_ms: r.get(2)?,
                down_mbps: r.get(3)?,
                up_mbps: r.get(4)?,
                loss: r.get(5)?,
                server: r.get(6)?,
                isp: r.get(7)?,
                url: r.get(8)?,
                server_ip: r.get(9)?,
                client_ip: r.get(10)?,
            })
        })?
        .collect()
    }

    pub fn speedtest_prune(&self, before: i64) -> rusqlite::Result<usize> {
        self.conn.execute("DELETE FROM speedtest_results WHERE ts < ?1", params![before])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_are_read_back_in_order_and_pruned() {
        let db = Db::memory();
        let r = |ts| SpeedResult { ts, down_mbps: 100.0, server: "S".into(), ..Default::default() };
        db.speedtest_put(&r(200)).unwrap();
        db.speedtest_put(&r(100)).unwrap();
        assert_eq!(db.speedtest_since(0).unwrap().iter().map(|r| r.ts).collect::<Vec<_>>(), [100, 200]);
        assert_eq!(db.speedtest_since(150).unwrap().len(), 1);
        assert_eq!(db.speedtest_prune(150).unwrap(), 1);
        assert_eq!(db.speedtest_since(0).unwrap()[0].server, "S");
    }
}
