//! Writes alerts to the Windows Application event log. The source isn't registered with a
//! message file, so Event Viewer prefixes the text with a note about the missing description;
//! the text itself still shows.

use super::wide;
use windows::Win32::System::EventLog::{DeregisterEventSource, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, RegisterEventSourceW, ReportEventW};
use windows::core::{PCWSTR, w};

/// Event id of every RustWarden entry.
const EVENT_ID: u32 = 1000;

pub fn write(important: bool, message: &str) {
    let Ok(h) = (unsafe { RegisterEventSourceW(PCWSTR::null(), w!("RustyWire")) }) else { return };
    let text = wide(message);
    let strings = [PCWSTR(text.as_ptr())];
    let kind = if important { EVENTLOG_WARNING_TYPE } else { EVENTLOG_INFORMATION_TYPE };
    unsafe {
        let _ = ReportEventW(h, kind, 0, EVENT_ID, None, 0, Some(&strings), None);
        let _ = DeregisterEventSource(h);
    }
}
