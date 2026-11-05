//! `rustwarden --verify-alert-log`: checks the alert log's hash chain from a terminal, with no window.
//! Exit codes: 0 intact, 1 an entry was edited or removed, 2 the log could not be read.

use crate::live::db::Db;
use std::io::Write;

pub fn run() -> i32 {
    // The exe is a GUI app with no console; attach to the terminal that started it, if there is one.
    let _ = unsafe { windows::Win32::System::Console::AttachConsole(u32::MAX) };
    match Db::open(&crate::live::db_path()).and_then(|db| db.verify_alerts()) {
        Ok(check) => {
            let _ = writeln!(std::io::stdout(), "{}", check.summary());
            i32::from(check.first_bad.is_some())
        }
        Err(e) => {
            let _ = writeln!(std::io::stdout(), "Could not read the alert log: {e}");
            2
        }
    }
}
