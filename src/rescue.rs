//! `rustywire --remove-all-rules`: removes every Windows Firewall rule RustWarden owns, with no window
//! and no single-instance check, so a scheduled task can undo a block that has gone wrong.
//! Exit codes: 0 done, 1 some rules could not be removed, 2 not elevated (nothing was changed).

use crate::applog;
use crate::live::firewall::remove_all_owned;
use std::io::Write;

const LOG: &str = "rescue.log";

pub fn run() -> i32 {
    // The exe is a GUI app with no console; attach to the terminal that started it, if there is one.
    let _ = unsafe { windows::Win32::System::Console::AttachConsole(u32::MAX) };
    let mut say = |msg: &str| {
        let _ = writeln!(std::io::stdout(), "{msg}");
        applog::line(LOG, msg);
    };
    if !crate::sys::is_elevated() {
        say("Not run as administrator, so nothing was changed. Run it from an elevated prompt, or from a scheduled task set to run with highest privileges.");
        return 2;
    }
    // Bandwidth limits first: a failed QoS cleanup must not stop the firewall rules from going.
    match crate::sys::qos::remove_all() {
        Ok(n) if n > 0 => say(&format!("Removed {n} bandwidth limit(s).")),
        Ok(_) => {}
        Err(e) => say(&format!("Bandwidth limits could not be removed: {e}")),
    }
    match remove_all_owned(&mut say) {
        Ok(r) => {
            say(&format!("Done: {} removed, {} handed back to the app that made them, {} could not be changed.", r.removed, r.handed_back, r.failed.len()));
            i32::from(!r.failed.is_empty())
        }
        Err(e) => {
            say(&e);
            1
        }
    }
}
