//! Local Windows user accounts and Task Scheduler entries, for the account and task monitors.

use std::collections::{BTreeMap, BTreeSet};
use windows::Win32::NetworkManagement::NetManagement::{FILTER_NORMAL_ACCOUNT, NetApiBufferFree, NetUserEnum, UF_ACCOUNTDISABLE, USER_INFO_1};
use windows::core::PCWSTR;

/// Local user accounts: name to whether the account is enabled.
pub fn local_users() -> Result<BTreeMap<String, bool>, String> {
    let mut out = BTreeMap::new();
    let mut resume = 0u32;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let (mut read, mut total) = (0u32, 0u32);
        // 0 = success, 234 = ERROR_MORE_DATA (the page is still valid).
        let rc = unsafe { NetUserEnum(PCWSTR::null(), 1, FILTER_NORMAL_ACCOUNT, &mut buf, 0xFFFF_FFFF, &mut read, &mut total, Some(&mut resume)) };
        if rc != 0 && rc != 234 {
            return Err(format!("NetUserEnum failed: {rc}"));
        }
        unsafe {
            for u in std::slice::from_raw_parts(buf as *const USER_INFO_1, read as usize) {
                let name = u.usri1_name.to_string().unwrap_or_default();
                out.insert(name, !u.usri1_flags.contains(UF_ACCOUNTDISABLE));
            }
            NetApiBufferFree(Some(buf as *const _));
        }
        if rc == 0 {
            return Ok(out);
        }
    }
}

/// Scheduled tasks as their paths under `Windows\System32\Tasks` (e.g. `Microsoft\Windows\Foo\Bar`).
/// Fails when the folder can't be read (not elevated), so the caller skips the round.
pub fn scheduled_tasks() -> Result<BTreeSet<String>, String> {
    let root = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join(r"System32\Tasks");
    let mut out = BTreeSet::new();
    let mut dirs = vec![root.clone()];
    while let Some(dir) = dirs.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                dirs.push(path);
            } else if let Ok(rel) = path.strip_prefix(&root) {
                out.insert(rel.to_string_lossy().into_owned());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn enumerating_users_works() {
        assert!(super::local_users().is_ok_and(|u| !u.is_empty()));
    }
}
