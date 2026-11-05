//! System-wide byte counters from the interface table (`GetIfTable2`). Works without
//! administrator rights, but can't say which app the bytes belong to.

use std::collections::HashMap;
use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub rx: u64,
    pub tx: u64,
}

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_OPER_STATUS_UP: i32 = 1;

/// Received/sent bytes per up interface (keyed by LUID), over physical interfaces; if the machine
/// has none (virtual-only), over every non-loopback up interface.
pub fn read() -> Result<HashMap<u64, Counters>, String> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    unsafe {
        GetIfTable2(&mut table).ok().map_err(|e| format!("GetIfTable2 failed: {e}"))?;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let (mut physical, mut any) = (HashMap::new(), HashMap::new());
        for r in rows {
            if r.Type == IF_TYPE_SOFTWARE_LOOPBACK || r.OperStatus.0 != IF_OPER_STATUS_UP {
                continue;
            }
            let (luid, c) = (r.InterfaceLuid.Value, Counters { rx: r.InOctets, tx: r.OutOctets });
            any.insert(luid, c);
            // Bit 0 of the flags is HardwareInterface. Counting only those avoids
            // double-counting traffic that also flows through a VPN adapter.
            if r.InterfaceAndOperStatusFlags._bitfield & 1 != 0 {
                physical.insert(luid, c);
            }
        }
        FreeMibTable(table as *const _);
        Ok(if physical.is_empty() { any } else { physical })
    }
}

/// Bytes since the previous reading. A counter that went backwards (adapter reset) counts as zero,
/// and an interface with no earlier reading (just came up) counts nothing: its counters hold bytes since boot.
pub fn delta(prev: &HashMap<u64, Counters>, now: &HashMap<u64, Counters>) -> Counters {
    now.iter().filter_map(|(k, n)| Some((prev.get(k)?, n))).fold(Counters::default(), |t, (p, n)| Counters { rx: t.rx + n.rx.saturating_sub(p.rx), tx: t.tx + n.tx.saturating_sub(p.tx) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_ignores_resets() {
        let one = |rx, tx| HashMap::from([(1, Counters { rx, tx })]);
        assert_eq!(delta(&one(100, 50), &one(180, 10)), Counters { rx: 80, tx: 0 });
    }

    #[test]
    fn delta_skips_interfaces_that_just_appeared() {
        let now = HashMap::from([(1, Counters { rx: 180, tx: 10 }), (2, Counters { rx: 9_000_000, tx: 9_000_000 })]);
        let prev = HashMap::from([(1, Counters { rx: 100, tx: 10 })]);
        assert_eq!(delta(&prev, &now), Counters { rx: 80, tx: 0 });
    }
}
