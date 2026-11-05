//! The Windows accent colour and light/dark app mode (Settings > Personalisation > Colours), read from the registry.

use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
use windows::core::{PCWSTR, w};

fn dword(subkey: PCWSTR, name: PCWSTR) -> Option<u32> {
    let mut value = 0u32;
    let mut len = 4u32;
    // SAFETY: `value` and `len` are valid for a DWORD read.
    let rc = unsafe { RegGetValueW(HKEY_CURRENT_USER, subkey, name, RRF_RT_REG_DWORD, None, Some(&mut value as *mut _ as *mut _), Some(&mut len)) };
    (rc.0 == 0).then_some(value)
}

/// Whether Windows is set to dark mode for apps; `None` when it can't be read (very old Windows).
pub fn windows_dark() -> Option<bool> {
    dword(w!(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"), w!("AppsUseLightTheme")).map(|v| v == 0)
}

/// The user's accent colour, if Windows has one set. Cheap enough to poll.
pub fn windows_accent() -> Option<[u8; 3]> {
    // AccentColorMenu is 0xAABBGGRR; ColorizationColor (the older value) is 0xAARRGGBB.
    if let Some(v) = dword(w!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Accent"), w!("AccentColorMenu")) {
        return Some([v as u8, (v >> 8) as u8, (v >> 16) as u8]);
    }
    dword(w!(r"Software\Microsoft\Windows\DWM"), w!("ColorizationColor")).map(|v| [(v >> 16) as u8, (v >> 8) as u8, v as u8])
}
