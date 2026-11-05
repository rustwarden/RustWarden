//! Remote Desktop sessions through the Terminal Services API.

use super::from_wide;
use std::collections::BTreeMap;
use windows::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSConnected, WTSEnumerateSessionsW, WTSFreeMemory, WTSINFOEXW, WTSQuerySessionInformationW, WTSSessionInfoEx, WTSUserName,
};
use windows::core::PWSTR;

/// Active remote (RDP) sessions: session id to user name. The idle "RDP-Tcp" listener is skipped.
pub fn remote_sessions() -> Result<BTreeMap<u32, String>, String> {
    let mut out = BTreeMap::new();
    let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    unsafe {
        WTSEnumerateSessionsW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut info, &mut count).map_err(|e| format!("WTSEnumerateSessions failed: {e}"))?;
        for s in std::slice::from_raw_parts(info, count as usize) {
            let name = s.pWinStationName.to_string().unwrap_or_default();
            if !name.starts_with("RDP-Tcp#") || !(s.State == WTSActive || s.State == WTSConnected) {
                continue;
            }
            let mut user = PWSTR::null();
            let mut len = 0u32;
            let user_name = if WTSQuerySessionInformationW(Some(WTS_CURRENT_SERVER_HANDLE), s.SessionId, WTSUserName, &mut user, &mut len).is_ok() {
                let u = from_wide(std::slice::from_raw_parts(user.0, (len as usize / 2).max(1)));
                WTSFreeMemory(user.0 as *mut _);
                u
            } else {
                String::new()
            };
            out.insert(s.SessionId, if user_name.is_empty() { "unknown user".to_string() } else { user_name });
        }
        WTSFreeMemory(info as *mut _);
    }
    Ok(out)
}

/// Whether the current session is locked; None if the query fails.
pub fn is_locked() -> Option<bool> {
    let mut buf = PWSTR::null();
    let mut len = 0u32;
    unsafe {
        WTSQuerySessionInformationW(Some(WTS_CURRENT_SERVER_HANDLE), u32::MAX, WTSSessionInfoEx, &mut buf, &mut len).ok()?;
        let info = (buf.0 as *const WTSINFOEXW).read_unaligned();
        WTSFreeMemory(buf.0 as *mut _);
        // WTS_SESSIONSTATE_LOCK = 0, UNLOCK = 1; anything else (unknown) is not treated as locked.
        match info.Data.WTSInfoExLevel1.SessionFlags {
            0 => Some(true),
            1 => Some(false),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn enumerating_sessions_works() {
        assert!(super::remote_sessions().is_ok());
    }
}
