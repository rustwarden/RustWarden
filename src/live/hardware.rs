//! Hardware collector: one PDH sample per second into a 5-minute ring.

use super::store::{HW_WINDOW, HwNow, Shared};
use crate::data::{HardwareSample, StatusNote};
use crate::sys::pdh::Pdh;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Seconds covered by one stored history row.
pub const HISTORY_STEP: i64 = 10;

const GB: f64 = 1024.0 * 1024.0 * 1024.0;
const MB: f64 = 1024.0 * 1024.0;

pub fn run(shared: Arc<Shared>) {
    let mut pdh = match Pdh::new() {
        Ok(p) => p,
        Err(e) => {
            shared.set_note("hardware", Some(StatusNote::warn(format!("Hardware monitoring unavailable: {e}"))));
            return;
        }
    };
    let db = shared.open_db().ok();
    if db.is_none() {
        shared.set_note("hardware-db", Some(StatusNote::warn("Hardware history isn't being saved: the database couldn't be opened.")));
    }
    // After a restart, refill the live ring from the stored rows so the 5-minute view has no leading gap.
    if let Some(db) = &db {
        let now = crate::clock::now_unix();
        let rows: std::collections::HashMap<i64, HardwareSample> = db.hardware_series(now - HW_WINDOW as i64, now + HISTORY_STEP, None).unwrap_or_default().into_iter().collect();
        let mut st = shared.state();
        // A row is stamped with the end of the HISTORY_STEP seconds it averages.
        for t in now - HW_WINDOW as i64..now {
            let row = rows.get(&((t / HISTORY_STEP + 1) * HISTORY_STEP));
            if row.is_some() || !st.hw.is_empty() {
                st.hw.push_back(row.copied().unwrap_or_default());
            }
        }
    }
    // Seconds are averaged into HISTORY_STEP-second rows of the history table.
    let mut acc: Vec<HardwareSample> = Vec::new();
    let mut app_acc: std::collections::HashMap<String, [f32; 3]> = std::collections::HashMap::new();
    let mut next = Instant::now() + Duration::from_secs(1);
    let mut gpu_seen = false;
    let mut last_slot = crate::clock::now_unix() / HISTORY_STEP;
    while !shared.stopping() {
        if !shared.sleep(next.saturating_duration_since(Instant::now()).as_secs_f64()) {
            break;
        }
        next += Duration::from_secs(1);
        let s = pdh.sample();
        gpu_seen |= s.gpu_pct.is_some();
        let sample = HardwareSample { cpu: s.cpu_pct, memory: (s.memory_used / GB) as f32, disk: ((s.disk_read + s.disk_write) / MB) as f32, gpu: s.gpu_pct.unwrap_or(0.0) };
        if let Some(db) = &db {
            acc.push(sample);
            for (name, cpu, mem, io) in &s.apps {
                let a = app_acc.entry(name.clone()).or_default();
                (a[0], a[1], a[2]) = (a[0] + cpu, a[1] + (mem / GB) as f32, a[2] + (io / MB) as f32);
            }
            let now = crate::clock::now_unix();
            // Flush when a new HISTORY_STEP slot starts, not only when a tick lands exactly on it (a late tick would skip the row).
            if now / HISTORY_STEP != last_slot {
                last_slot = now / HISTORY_STEP;
                let now = last_slot * HISTORY_STEP;
                let n = acc.len() as f32;
                // Only programs that did something are stored, to keep the table small.
                for (name, a) in app_acc.drain() {
                    let row = HardwareSample { cpu: a[0] / n, memory: a[1] / n, disk: a[2] / n, gpu: 0.0 };
                    if row.cpu >= 0.1 || row.disk >= 0.1 {
                        let _ = db.add_hardware_app(now, &name, &row);
                    }
                }
                let avg = |f: fn(&HardwareSample) -> f32| acc.iter().map(f).sum::<f32>() / n;
                let row = HardwareSample { cpu: avg(|s| s.cpu), memory: avg(|s| s.memory), disk: avg(|s| s.disk), gpu: avg(|s| s.gpu) };
                let _ = db.add_hardware(now, &row);
                acc.clear();
                if now % 600 == 0 {
                    let _ = db.prune_hardware(now, shared.settings().hardware_history_hours);
                }
            }
        }
        {
            let mut st = shared.state();
            st.hw.push_back(sample);
            while st.hw.len() > HW_WINDOW {
                st.hw.pop_front();
            }
            st.hw_secs = crate::clock::to_local(crate::clock::now_unix());
            st.hw_now = HwNow {
                cpu_pct: s.cpu_pct,
                memory_used: s.memory_used,
                memory_total: s.memory_total,
                disk_read: s.disk_read,
                disk_write: s.disk_write,
                gpu_pct: s.gpu_pct.unwrap_or(0.0),
                gpu_memory: s.gpu_memory.unwrap_or(0.0),
                gpu_available: gpu_seen,
            };
        }
        shared.set_note("gpu", (!gpu_seen).then(|| StatusNote::info("No GPU counters found: GPU usage and memory are not shown")));
        shared.repaint();
    }
}
