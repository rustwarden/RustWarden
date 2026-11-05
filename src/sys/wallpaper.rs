//! Sets the desktop wallpaper (the About-picture easter egg).

use windows::Win32::Foundation::COLORREF;
use windows::Win32::Graphics::Gdi::{COLOR_BACKGROUND, SetSysColors};
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ, RegSetKeyValueW};
use windows::Win32::UI::WindowsAndMessaging::{SPI_SETDESKWALLPAPER, SPIF_SENDCHANGE, SPIF_UPDATEINIFILE, SystemParametersInfoW};
use windows::core::{PCWSTR, w};

fn reg_str(key: PCWSTR, name: PCWSTR, value: &str) -> Result<(), String> {
    let v = super::wide(value);
    let bytes = unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, v.len() * 2) };
    unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, key, name, REG_SZ.0, Some(bytes.as_ptr().cast()), bytes.len() as u32) }.ok().map_err(|e| e.to_string())
}

/// Shows `png` centred on the desktop; the bars around it get the colour `bg` so a picture that doesn't fill the screen still looks intentional.
pub fn set_wallpaper(png: &std::path::Path, bg: [u8; 3]) -> Result<(), String> {
    reg_str(w!(r"Control Panel\Desktop"), w!("WallpaperStyle"), "0")?;
    reg_str(w!(r"Control Panel\Desktop"), w!("TileWallpaper"), "0")?;
    reg_str(w!(r"Control Panel\Colors"), w!("Background"), &format!("{} {} {}", bg[0], bg[1], bg[2]))?;
    let colour = COLORREF(bg[0] as u32 | (bg[1] as u32) << 8 | (bg[2] as u32) << 16);
    unsafe {
        let _ = SetSysColors(1, &(COLOR_BACKGROUND.0), &colour);
        let mut path = super::wide(&png.to_string_lossy());
        SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, Some(path.as_mut_ptr().cast()), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE).map_err(|e| e.to_string())
    }
}
