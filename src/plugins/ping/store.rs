//! One row per host and ping round.

use crate::live::db::Db;
use crate::plugins::core::latency::Sample;
use rusqlite::params;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS ping_samples (
    host INTEGER NOT NULL, ts INTEGER NOT NULL, min REAL NOT NULL, avg REAL NOT NULL, max REAL NOT NULL, loss REAL NOT NULL,
    PRIMARY KEY (host, ts)) WITHOUT ROWID;
";

impl Db {
    pub fn ping_put(&self, host: u32, s: &Sample) -> rusqlite::Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO ping_samples (host, ts, min, avg, max, loss) VALUES (?1,?2,?3,?4,?5,?6)", params![host, s.ts, s.min, s.avg, s.max, s.loss])?;
        Ok(())
    }

    /// Samples of one host from `since` on, oldest first.
    pub fn ping_since(&self, host: u32, since: i64) -> rusqlite::Result<Vec<Sample>> {
        let mut stmt = self.conn.prepare_cached("SELECT ts, min, avg, max, loss FROM ping_samples WHERE host = ?1 AND ts >= ?2 ORDER BY ts")?;
        stmt.query_map(params![host, since], |r| Ok(Sample { ts: r.get(0)?, min: r.get(1)?, avg: r.get(2)?, max: r.get(3)?, loss: r.get(4)? }))?.collect()
    }

    /// Drops old rows, which also cleans up after removed hosts.
    pub fn ping_prune(&self, before: i64) -> rusqlite::Result<usize> {
        self.conn.execute("DELETE FROM ping_samples WHERE ts < ?1", params![before])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_are_read_back_per_host_in_order() {
        let db = Db::memory();
        let s = |ts| Sample { ts, min: 1.0, avg: 2.0, max: 3.0, loss: 0.0 };
        db.ping_put(1, &s(200)).unwrap();
        db.ping_put(1, &s(100)).unwrap();
        db.ping_put(2, &s(150)).unwrap();
        assert_eq!(db.ping_since(1, 0).unwrap().iter().map(|s| s.ts).collect::<Vec<_>>(), [100, 200]);
        assert_eq!(db.ping_prune(160).unwrap(), 2);
        assert_eq!(db.ping_since(1, 0).unwrap().len(), 1);
    }
}
