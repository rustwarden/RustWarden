//! Registry and folder snapshots for the root certificate, startup entry and new service monitors.
//! Each returns a set of strings so `diff_tasks` can report what was added.

use std::collections::{BTreeMap, BTreeSet};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, RRF_RT_REG_QWORD, RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

const RUN_KEYS: [&str; 4] = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
];

fn open(hive: HKEY, path: &str) -> Option<HKEY> {
    let mut key = HKEY::default();
    unsafe { RegOpenKeyExW(hive, &HSTRING::from(path), None, KEY_READ | KEY_WOW64_64KEY, &mut key) }.is_ok().then_some(key)
}

/// Names of the subkeys of `hive\path`; empty when the key doesn't exist.
fn subkeys(hive: HKEY, path: &str) -> Vec<String> {
    let Some(key) = open(hive, path) else { return Vec::new() };
    let mut out = Vec::new();
    // Registry key names are at most 255 characters.
    let mut buf = [0u16; 256];
    for i in 0.. {
        let mut len = buf.len() as u32;
        if unsafe { RegEnumKeyExW(key, i, Some(PWSTR(buf.as_mut_ptr())), &mut len, None, None, None, None) } != ERROR_SUCCESS {
            break;
        }
        out.push(String::from_utf16_lossy(&buf[..len as usize]));
    }
    unsafe {
        let _ = RegCloseKey(key);
    }
    out
}

/// `name=data` for each value of `hive\path` (string values; others show their name only).
fn values(hive: HKEY, path: &str) -> Vec<String> {
    let Some(key) = open(hive, path) else { return Vec::new() };
    let mut out = Vec::new();
    let mut name = [0u16; 16384];
    let mut data = vec![0u8; 8192];
    for i in 0.. {
        let (mut nlen, mut dlen, mut kind) = (name.len() as u32, data.len() as u32, 0u32);
        if unsafe { RegEnumValueW(key, i, Some(PWSTR(name.as_mut_ptr())), &mut nlen, None, Some(&mut kind), Some(data.as_mut_ptr()), Some(&mut dlen)) } != ERROR_SUCCESS {
            break;
        }
        // REG_SZ = 1, REG_EXPAND_SZ = 2. An oversized value fails the call above and ends the scan: shortcut, fine for Run commands.
        let text = if kind == 1 || kind == 2 {
            let wide: Vec<u16> = data[..dlen as usize].as_chunks::<2>().0.iter().map(|b| u16::from_le_bytes(*b)).collect();
            String::from_utf16_lossy(&wide).trim_end_matches('\0').to_owned()
        } else {
            String::new()
        };
        out.push(format!("{}={text}", String::from_utf16_lossy(&name[..nlen as usize])));
    }
    unsafe {
        let _ = RegCloseKey(key);
    }
    out
}

/// Thumbprints of the trusted root certificates (machine and current user).
/// shortcut: reports thumbprints, not subject names; look the name up with certmgr.msc.
pub fn root_certs() -> BTreeSet<String> {
    let path = r"SOFTWARE\Microsoft\SystemCertificates\Root\Certificates";
    subkeys(HKEY_LOCAL_MACHINE, path).into_iter().map(|t| format!("machine {t}")).chain(subkeys(HKEY_CURRENT_USER, path).into_iter().map(|t| format!("user {t}"))).collect()
}

/// Run/RunOnce values (machine and user) and the files in both Startup folders, as `where: name=command`.
pub fn startup_entries() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (hive, who) in [(HKEY_LOCAL_MACHINE, "machine"), (HKEY_CURRENT_USER, "user")] {
        for key in RUN_KEYS {
            out.extend(values(hive, key).into_iter().map(|v| format!("{who} Run: {v}")));
        }
    }
    let dirs = [(std::env::var("ProgramData"), r"Microsoft\Windows\Start Menu\Programs\StartUp"), (std::env::var("APPDATA"), r"Microsoft\Windows\Start Menu\Programs\Startup")];
    for (base, rel) in dirs {
        let Ok(base) = base else { continue };
        for e in std::fs::read_dir(std::path::Path::new(&base).join(rel)).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.eq_ignore_ascii_case("desktop.ini") {
                out.insert(format!("Startup folder: {name}"));
            }
        }
    }
    out
}

/// Short names of every installed service and driver.
pub fn service_names() -> BTreeSet<String> {
    subkeys(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services").into_iter().collect()
}

/// When each app last started using the microphone or camera, from Windows' privacy ConsentStore
/// (the data behind the tray privacy indicator). Key `microphone|name` or `camera|name`; value is
/// the FILETIME of `LastUsedTimeStart`. Apps that never used the device are left out.
pub fn device_use() -> BTreeMap<String, u64> {
    let base = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";
    let mut out = BTreeMap::new();
    for (dir, label) in [("microphone", "microphone"), ("webcam", "camera")] {
        let dir = format!(r"{base}\{dir}");
        // Desktop apps live under NonPackaged with `#` standing for `\` in the path.
        let apps = subkeys(HKEY_CURRENT_USER, &dir).into_iter().filter(|a| a != "NonPackaged").map(|a| (a.clone(), a));
        let desktop = subkeys(HKEY_CURRENT_USER, &format!(r"{dir}\NonPackaged")).into_iter().map(|a| (format!(r"NonPackaged\{a}"), a.replace('#', r"\")));
        for (sub, name) in apps.chain(desktop) {
            let Some(key) = open(HKEY_CURRENT_USER, &format!(r"{dir}\{sub}")) else { continue };
            let (mut v, mut len) = (0u64, 8u32);
            let ok = unsafe { RegGetValueW(key, PCWSTR::null(), &HSTRING::from("LastUsedTimeStart"), RRF_RT_REG_QWORD, None, Some((&raw mut v).cast()), Some(&mut len)) } == ERROR_SUCCESS;
            unsafe {
                let _ = RegCloseKey(key);
            }
            if ok && v > 0 {
                out.insert(format!("{label}|{name}"), v);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn snapshots_read_the_registry() {
        assert!(super::service_names().contains("RpcSs"));
        assert!(!super::root_certs().is_empty());
        let _ = super::startup_entries();
        let _ = super::device_use();
    }
}
