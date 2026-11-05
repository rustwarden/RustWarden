//! Identity of a running program: executable path from a pid, version resources, signature, hash.

use super::{from_wide, wide};
use sha2::{Digest, Sha256};
use windows::Win32::Foundation::{CloseHandle, HWND};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
use windows::core::{PCWSTR, PWSTR};

/// Full path of the process image, if the process exists and we may query it.
pub fn pid_path(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return None;
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).is_ok();
        let _ = CloseHandle(h);
        ok.then(|| from_wide(&buf[..len as usize]))
    }
}

/// Every running process we can query, with its lower-cased image path.
pub fn running_paths() -> Vec<(u32, String)> {
    let mut pids = vec![0u32; 4096];
    let mut bytes = 0u32;
    let ok = unsafe { windows::Win32::System::ProcessStatus::EnumProcesses(pids.as_mut_ptr(), (pids.len() * 4) as u32, &mut bytes).is_ok() };
    if !ok {
        return Vec::new();
    }
    pids.truncate(bytes as usize / 4);
    pids.into_iter().filter_map(|pid| pid_path(pid).map(|p| (pid, p.to_lowercase()))).collect()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionInfo {
    pub description: String,
    pub company: String,
    pub version: String,
}

/// File description, company and file version from the executable's version resource.
pub fn version_info(path: &str) -> VersionInfo {
    let p = wide(path);
    unsafe {
        let size = GetFileVersionInfoSizeW(PCWSTR(p.as_ptr()), None);
        if size == 0 {
            return VersionInfo::default();
        }
        let mut data = vec![0u8; size as usize];
        if GetFileVersionInfoW(PCWSTR(p.as_ptr()), None, size, data.as_mut_ptr() as *mut _).is_err() {
            return VersionInfo::default();
        }
        // The string table is named after the first language/codepage pair.
        let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        let translation = wide(r"\VarFileInfo\Translation");
        let lang = if VerQueryValueW(data.as_ptr() as *const _, PCWSTR(translation.as_ptr()), &mut ptr, &mut len).as_bool() && len >= 4 {
            let pair = std::slice::from_raw_parts(ptr as *const u16, 2);
            format!("{:04x}{:04x}", pair[0], pair[1])
        } else {
            "040904b0".to_string()
        };
        let read = |name: &str| -> String {
            let sub = wide(&format!(r"\StringFileInfo\{lang}\{name}"));
            let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut len = 0u32;
            if VerQueryValueW(data.as_ptr() as *const _, PCWSTR(sub.as_ptr()), &mut ptr, &mut len).as_bool() && len > 0 {
                from_wide(std::slice::from_raw_parts(ptr as *const u16, len as usize))
            } else {
                String::new()
            }
        };
        VersionInfo { description: read("FileDescription"), company: read("CompanyName"), version: read("FileVersion") }
    }
}

/// Whether the file carries a valid embedded Authenticode signature. Files signed through a
/// Windows catalog (most of System32) have no embedded signature, so `false` is not proof of
/// tampering; callers decide how to word it.
pub fn has_valid_embedded_signature(path: &str) -> bool {
    let p = wide(path);
    let mut file = WINTRUST_FILE_INFO { cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32, pcwszFilePath: PCWSTR(p.as_ptr()), ..Default::default() };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    unsafe {
        let rc = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);
        rc == 0
    }
}

/// SHA-256 of the file as lower-case hex; empty when it can't be read.
pub fn hash_file(path: &str) -> String {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else { return String::new() };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return String::new(),
        }
    }
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The shell's large icon for the file at `path` as straight RGBA, with its side in pixels.
pub fn file_icon_rgba(path: &str) -> Option<(Vec<u8>, usize)> {
    use windows::Win32::Graphics::Gdi::{BITMAP, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC};
    use windows::Win32::UI::Shell::{SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON, SHGetFileInfoW};
    use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};
    unsafe {
        let mut fi = SHFILEINFOW::default();
        let w = wide(path);
        if SHGetFileInfoW(PCWSTR(w.as_ptr()), Default::default(), Some(&mut fi), std::mem::size_of::<SHFILEINFOW>() as u32, SHGFI_ICON | SHGFI_LARGEICON) == 0 || fi.hIcon.is_invalid() {
            return None;
        }
        let mut ii = ICONINFO::default();
        let mut out = None;
        if GetIconInfo(fi.hIcon, &mut ii).is_ok() {
            let mut bm = BITMAP::default();
            if GetObjectW(ii.hbmColor.into(), std::mem::size_of::<BITMAP>() as i32, Some(&mut bm as *mut _ as *mut _)) != 0 && bm.bmWidth > 0 && bm.bmHeight > 0 {
                let (w, h) = (bm.bmWidth as usize, bm.bmHeight as usize);
                let mut info = BITMAPINFO {
                    bmiHeader: BITMAPINFOHEADER { biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32, biWidth: w as i32, biHeight: -(h as i32), biPlanes: 1, biBitCount: 32, ..Default::default() },
                    ..Default::default()
                };
                let mut px = vec![0u8; w * h * 4];
                let dc = GetDC(None);
                if GetDIBits(dc, ii.hbmColor, 0, h as u32, Some(px.as_mut_ptr().cast()), &mut info, DIB_RGB_COLORS) != 0 {
                    // BGRA to RGBA; icons without an alpha channel come back all transparent.
                    let opaque = px.as_chunks::<4>().0.iter().all(|c| c[3] == 0);
                    for c in px.as_chunks_mut::<4>().0 {
                        c.swap(0, 2);
                        if opaque {
                            c[3] = 255;
                        }
                    }
                    out = Some((px, w));
                }
                ReleaseDC(None, dc);
            }
            let _ = DeleteObject(ii.hbmColor.into());
            let _ = DeleteObject(ii.hbmMask.into());
        }
        let _ = DestroyIcon(fi.hIcon);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_has_a_path() {
        let path = pid_path(std::process::id()).expect("own path");
        assert!(path.to_lowercase().ends_with(".exe"));
        assert!(!hash_file(&path).is_empty());
    }

    #[test]
    fn notepad_like_system_binary_has_version_info() {
        let cmd = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()) + r"\System32\cmd.exe";
        let v = version_info(&cmd);
        assert!(!v.version.is_empty());
        assert!(!v.description.is_empty());
    }

    #[test]
    fn hash_of_known_content() {
        let path = std::env::temp_dir().join("rustywire-hash-test.txt");
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(hash_file(&path.to_string_lossy()), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let _ = std::fs::remove_file(path);
        assert_eq!(hash_file("Z:\\definitely\\missing.bin"), "");
    }
}
