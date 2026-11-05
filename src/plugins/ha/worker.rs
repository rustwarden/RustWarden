//! Looks scanned devices up in Home Assistant one after another, as soon as they appear.

use super::{active, client};
use crate::data::StatusNote;
use crate::live::store::Shared;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set by the "Sync now" button: look every device up again.
pub static SYNC_NOW: AtomicBool = AtomicBool::new(false);

const NOTE: &str = "homeassistant";

pub fn run(shared: Arc<Shared>) {
    let mut db = None;
    let (mut retry_at, mut fails) = (0, 0u32);
    while shared.sleep(0.5) {
        let s = shared.settings();
        let Some(cfg) = active(&s) else {
            shared.set_note(NOTE, None);
            continue;
        };
        if db.is_none() {
            db = shared.open_db().ok();
        }
        let Some(db) = db.as_ref() else { continue };
        let now = crate::clock::now_unix();
        // Kept in the database, so only a different Home Assistant (not a restart) makes every device due again.
        let cfg_key = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(cfg.url.as_bytes());
            h.update([0]);
            h.update(cfg.token.as_bytes());
            h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        if SYNC_NOW.swap(false, Ordering::Relaxed) || db.kv_get("ha_cfg").as_deref() != Some(&cfg_key) {
            let _ = db.kv_set("ha_cfg", &cfg_key);
            (retry_at, fails) = (0, 0);
            let _ = db.ha_reset();
        }
        if now < retry_at {
            continue;
        }
        let Ok(Some(mac)) = db.ha_next(now) else { continue };
        match client::lookup(&cfg.url, &cfg.token, &mac) {
            Ok(info) => {
                fails = 0;
                shared.set_note(NOTE, None);
                if db.ha_set(&mac, info.as_ref(), now).is_ok() && info.is_some() {
                    shared.repaint();
                }
                shared.sleep(1.0); // one request a second at most
            }
            Err(e) => {
                // Nothing is recorded, so the device is tried again after the pause, which grows from a minute to an hour.
                fails += 1;
                let pause = (60i64 << (fails - 1).min(6)).min(3600);
                shared.set_note(NOTE, Some(StatusNote::warn(format!("{e} Trying again in {} min.", pause / 60))));
                retry_at = now + pause;
            }
        }
    }
}
