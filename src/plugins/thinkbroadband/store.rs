//! The downloaded samples, one row per monitor and poll round (re-downloads just overwrite).

use super::Sample;
use crate::live::db::Db;
use rusqlite::params;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS tbb_samples (
    monitor INTEGER NOT NULL, ts INTEGER NOT NULL, min REAL NOT NULL, avg REAL NOT NULL, max REAL NOT NULL, loss REAL NOT NULL,
    PRIMARY KEY (monitor, ts)) WITHOUT ROWID;
";

impl Db {
    pub fn tbb_put(&self, monitor: u32, samples: &[Sample]) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached("INSERT OR REPLACE INTO tbb_samples (monitor, ts, min, avg, max, loss) VALUES (?1,?2,?3,?4,?5,?6)")?;
            for s in samples {
                stmt.execute(params![monitor, s.ts, s.min, s.avg, s.max, s.loss])?;
            }
        }
        tx.commit()
    }

    /// Samples of one monitor from `since` on, oldest first.
    pub fn tbb_since(&self, monitor: u32, since: i64) -> rusqlite::Result<Vec<Sample>> {
        let mut stmt = self.conn.prepare_cached("SELECT ts, min, avg, max, loss FROM tbb_samples WHERE monitor = ?1 AND ts >= ?2 ORDER BY ts")?;
        stmt.query_map(params![monitor, since], |r| Ok(Sample { ts: r.get(0)?, min: r.get(1)?, avg: r.get(2)?, max: r.get(3)?, loss: r.get(4)? }))?.collect()
    }

    /// Drops samples older than `before`, so the table doesn't grow for ever.
    pub fn tbb_prune(&self, before: i64) -> rusqlite::Result<usize> {
        self.conn.execute("DELETE FROM tbb_samples WHERE ts < ?1", params![before])
    }

    pub fn tbb_clear(&self) -> rusqlite::Result<usize> {
        self.conn.execute("DELETE FROM tbb_samples", [])
    }

    pub fn tbb_latest(&self, monitor: u32) -> Option<i64> {
        self.conn.query_row("SELECT MAX(ts) FROM tbb_samples WHERE monitor = ?1", params![monitor], |r| r.get(0)).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_are_replaced_and_read_back_in_order() {
        let db = Db::memory();
        let s = |ts, loss| Sample { ts, min: 1.0, avg: 2.0, max: 3.0, loss };
        db.tbb_put(7, &[s(200, 0.0), s(100, 0.0)]).unwrap();
        db.tbb_put(7, &[s(200, 9.0)]).unwrap();
        db.tbb_put(8, &[s(300, 0.0)]).unwrap();
        let got = db.tbb_since(7, 0).unwrap();
        assert_eq!(got.iter().map(|x| (x.ts, x.loss)).collect::<Vec<_>>(), vec![(100, 0.0), (200, 9.0)]);
        assert_eq!(db.tbb_since(7, 150).unwrap().len(), 1);
        assert_eq!((db.tbb_latest(7), db.tbb_latest(9)), (Some(200), None));
        assert_eq!(db.tbb_prune(150).unwrap(), 1);
        assert_eq!(db.tbb_since(7, 0).unwrap().len(), 1);
        db.tbb_clear().unwrap();
        assert_eq!(db.tbb_latest(8), None);
    }
}
