//! Remembers which devices were looked up and what Home Assistant said. A device it doesn't
//! know is stored as checked-but-not-found, so it is retried hourly instead of constantly.

use super::HaInfo;
use crate::live::db::Db;
use rusqlite::params;
use std::collections::HashMap;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS ha_devices (
    mac TEXT PRIMARY KEY, checked INTEGER NOT NULL, found INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL DEFAULT '', area TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', device_id TEXT NOT NULL DEFAULT '');
";

const RECHECK_MISSING: i64 = 3600;
const RECHECK_FOUND: i64 = 24 * 3600;

impl Db {
    /// A scanned device that is due a lookup: never checked first, then the longest overdue.
    pub fn ha_next(&self, now: i64) -> rusqlite::Result<Option<String>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT d.mac FROM devices d LEFT JOIN ha_devices h ON h.mac = d.mac
             WHERE h.mac IS NULL OR h.checked < ?1 - CASE h.found WHEN 1 THEN ?3 ELSE ?2 END
             ORDER BY h.mac IS NOT NULL, h.checked LIMIT 1",
        )?;
        let mut rows = stmt.query(params![now, RECHECK_MISSING, RECHECK_FOUND])?;
        rows.next()?.map(|r| r.get(0)).transpose()
    }

    pub fn ha_set(&self, mac: &str, info: Option<&HaInfo>, now: i64) -> rusqlite::Result<()> {
        let i = info.cloned().unwrap_or_default();
        self.conn.execute(
            "INSERT OR REPLACE INTO ha_devices (mac, checked, found, name, area, kind, model, device_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![mac, now, i64::from(info.is_some()), i.name, i.area, i.kind, i.model, i.device_id],
        )?;
        Ok(())
    }

    /// Makes every device due again ("Sync now", or a different Home Assistant).
    pub fn ha_reset(&self) -> rusqlite::Result<()> {
        self.conn.execute("UPDATE ha_devices SET checked = 0", [])?;
        Ok(())
    }

    /// Matched devices by MAC.
    pub fn ha_all(&self) -> rusqlite::Result<HashMap<String, HaInfo>> {
        let mut stmt = self.conn.prepare_cached("SELECT mac, name, area, model, kind, device_id FROM ha_devices WHERE found = 1")?;
        stmt.query_map([], |r| Ok((r.get(0)?, HaInfo { name: r.get(1)?, area: r.get(2)?, model: r.get(3)?, kind: r.get(4)?, device_id: r.get(5)? })))?.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::db::DeviceRow;

    fn dev(mac: &str) -> DeviceRow {
        DeviceRow {
            network: "n".into(),
            mac: mac.into(),
            ip: "1.1.1.1".into(),
            name: String::new(),
            vendor: String::new(),
            system: String::new(),
            kind: 0,
            first_seen: 1,
            last_seen: 1,
            online: true,
            seen_count: 1,
            ports: String::new(),
            trusted: false,
        }
    }

    #[test]
    fn lookups_are_remembered_and_retried_on_schedule() {
        let db = Db::memory();
        db.upsert_device(&dev("AA")).unwrap();
        db.upsert_device(&dev("BB")).unwrap();
        let a = db.ha_next(1000).unwrap().unwrap();
        db.ha_set(&a, Some(&HaInfo { name: "Lamp".into(), ..Default::default() }), 1000).unwrap();
        let b = db.ha_next(1000).unwrap().unwrap();
        assert_ne!(a, b);
        db.ha_set(&b, None, 1000).unwrap();
        assert_eq!(db.ha_next(1000).unwrap(), None); // both checked
        assert_eq!(db.ha_next(1000 + 3601).unwrap().as_deref(), Some(b.as_str())); // unmatched: hourly
        assert!(db.ha_next(1000 + 24 * 3600 + 1).unwrap().is_some());
        assert_eq!(db.ha_all().unwrap().len(), 1); // only the match is kept as one
        db.ha_set(&b, None, 1000 + 3601).unwrap();
        db.ha_reset().unwrap();
        assert!(db.ha_next(1000 + 3602).unwrap().is_some());
    }
}
