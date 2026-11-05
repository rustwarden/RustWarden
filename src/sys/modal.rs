//! Native modal dialogs: a dialog window is owned by the window that opened it (so it stays in front
//! of it and off the taskbar), and that window is disabled while the dialog is up, as Win32 dialogs do.

use std::cell::RefCell;
use std::sync::atomic::{AtomicIsize, Ordering};
use windows::Win32::Foundation::{HWND, LPARAM};
use windows::Win32::Graphics::Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::{EnumThreadWindows, GWLP_HWNDPARENT, GetWindowTextW, SetForegroundWindow, SetWindowLongPtrW};
use windows::core::BOOL;

static MAIN: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    /// (owners held this frame, owners currently disabled).
    static HELD: RefCell<(Vec<isize>, Vec<isize>)> = const { RefCell::new((Vec::new(), Vec::new())) };
}

/// Remembers the main window, the owner of top-level dialogs.
pub fn set_main(hwnd: isize) {
    MAIN.store(hwnd, Ordering::Relaxed);
}

pub fn main() -> isize {
    MAIN.load(Ordering::Relaxed)
}

/// This thread's windows titled `title`, other than the main window. The UI thread owns every
/// window egui makes, so a dialog is found by its title the frame after egui creates it.
pub fn find_all(title: &str) -> Vec<isize> {
    struct Search {
        title: Vec<u16>,
        found: Vec<isize>,
    }
    unsafe extern "system" fn each(hwnd: HWND, lp: LPARAM) -> BOOL {
        // SAFETY: lp is the &mut Search passed below, alive for the whole enumeration.
        let s = unsafe { &mut *(lp.0 as *mut Search) };
        let mut buf = [0u16; 256];
        let n = unsafe { GetWindowTextW(hwnd, &mut buf) } as usize;
        if hwnd.0 as isize != main() && buf[..n] == s.title[..] {
            s.found.push(hwnd.0 as isize);
        }
        BOOL(1)
    }
    let mut s = Search { title: title.encode_utf16().collect(), found: Vec::new() };
    // SAFETY: the callback only reads window text into a local buffer and writes `s`.
    unsafe {
        let _ = EnumThreadWindows(GetCurrentThreadId(), Some(each), LPARAM(&mut s as *mut Search as isize));
    }
    s.found
}

/// The first of [`find_all`].
pub fn find(title: &str) -> Option<isize> {
    find_all(title).first().copied()
}

/// Gives `hwnd` the icons embedded in the exe, so the title bar and taskbar get the art drawn for their size
/// instead of one big picture scaled down by Windows.
pub fn use_exe_icons(hwnd: isize) {
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_DEFAULTCOLOR, LoadImageW, SM_CXICON, SM_CXSMICON, SM_CYICON, SM_CYSMICON, SendMessageW, WM_SETICON,
    };
    use windows::core::PCWSTR;
    // SAFETY: plain user32 calls on our own window; resource id 1 is the icon the build embeds.
    unsafe {
        let Ok(module) = GetModuleHandleW(None) else { return };
        for (kind, cx, cy) in [(ICON_SMALL, SM_CXSMICON, SM_CYSMICON), (ICON_BIG, SM_CXICON, SM_CYICON)] {
            if let Ok(icon) = LoadImageW(Some(module.into()), PCWSTR(std::ptr::without_provenance::<u16>(1)), IMAGE_ICON, GetSystemMetrics(cx), GetSystemMetrics(cy), LR_DEFAULTCOLOR) {
                SendMessageW(HWND(hwnd as *mut _), WM_SETICON, Some(WPARAM(kind as usize)), Some(LPARAM(icon.0 as isize)));
            }
        }
    }
}

/// Makes `owner` own `dialog` and gives the dialog's title bar the app's theme.
pub fn adopt(dialog: isize, owner: isize, dark: bool) {
    let dark = dark as i32;
    // SAFETY: both handles are live windows of this thread; the attribute is a 4-byte BOOL.
    unsafe {
        SetWindowLongPtrW(HWND(dialog as *mut _), GWLP_HWNDPARENT, owner);
        let _ = DwmSetWindowAttribute(HWND(dialog as *mut _), DWMWA_USE_IMMERSIVE_DARK_MODE, &dark as *const _ as _, 4);
    }
}

/// Keeps `owner` disabled this frame: it takes no clicks, keys or moves while its dialog is up.
pub fn hold(owner: isize) {
    HELD.with_borrow_mut(|(now, off)| {
        now.push(owner);
        if !off.contains(&owner) {
            off.push(owner);
            // SAFETY: plain call on a window of this thread.
            unsafe {
                let _ = EnableWindow(HWND(owner as *mut _), false);
            }
        }
    });
}

/// Runs at the end of each frame: re-enables owners whose dialogs closed. That happens before egui
/// destroys the dialog window, so Windows hands focus back to the owner.
pub fn release_unheld() {
    HELD.with_borrow_mut(|(now, off)| {
        for h in off.iter().filter(|h| !now.contains(h)) {
            // SAFETY: plain call on a window of this thread.
            unsafe {
                let _ = EnableWindow(HWND(*h as *mut _), true);
                // Closing a dialog opened from another dialog can leave the owner behind other windows.
                let _ = SetForegroundWindow(HWND(*h as *mut _));
            }
        }
        *off = std::mem::take(now);
    });
}
