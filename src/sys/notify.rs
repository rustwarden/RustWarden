//! Desktop notifications as tray balloons (`Shell_NotifyIconW`). One worker thread owns a hidden
//! message-only window and shows the icon only while a balloon is on screen.

use super::wide;
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::{NIF_ICON, NIF_INFO, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW};
use windows::Win32::UI::WindowsAndMessaging::{CreateWindowExW, DestroyWindow, HWND_MESSAGE, IDI_APPLICATION, LoadIconW, WINDOW_EX_STYLE, WS_OVERLAPPED};
use windows::core::{PCWSTR, w};

/// How long the icon stays registered after the last balloon.
const LINGER: Duration = Duration::from_secs(10);

fn copy(dst: &mut [u16], text: &str) {
    let src: Vec<u16> = text.encode_utf16().take(dst.len() - 1).collect();
    dst[..src.len()].copy_from_slice(&src);
}

fn worker(rx: std::sync::mpsc::Receiver<(String, String)>) {
    let hinst = unsafe { GetModuleHandleW(PCWSTR::null()) }.ok();
    let hwnd = unsafe {
        CreateWindowExW(WINDOW_EX_STYLE(0), w!("STATIC"), PCWSTR(wide("RustyWire notifications").as_ptr()), WS_OVERLAPPED, 0, 0, 0, 0, Some(HWND_MESSAGE), None, hinst.map(|h| h.into()), None)
    };
    let Ok(hwnd) = hwnd else { return };
    let mut added = false;
    loop {
        let next = if added { rx.recv_timeout(LINGER) } else { rx.recv().map_err(|_| RecvTimeoutError::Disconnected) };
        let (title, body) = match next {
            Ok(m) => m,
            Err(RecvTimeoutError::Timeout) => {
                icon(hwnd, NIM_DELETE, None);
                added = false;
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if !added {
            added = icon(hwnd, NIM_ADD, None);
        }
        if added {
            icon(hwnd, NIM_MODIFY, Some((&title, &body)));
        }
    }
    icon(hwnd, NIM_DELETE, None);
    unsafe { DestroyWindow(hwnd).ok() };
}

fn icon(hwnd: HWND, op: windows::Win32::UI::Shell::NOTIFY_ICON_MESSAGE, info: Option<(&str, &str)>) -> bool {
    let mut nid = NOTIFYICONDATAW { cbSize: size_of::<NOTIFYICONDATAW>() as u32, hWnd: hwnd, uID: 1, uFlags: NIF_ICON, ..Default::default() };
    nid.hIcon = unsafe { LoadIconW(None, IDI_APPLICATION) }.unwrap_or_default();
    if let Some((title, body)) = info {
        nid.uFlags |= NIF_INFO;
        nid.dwInfoFlags = NIIF_INFO;
        copy(&mut nid.szInfoTitle, title);
        copy(&mut nid.szInfo, body);
    }
    unsafe { Shell_NotifyIconW(op, &nid) }.as_bool()
}

/// Shows a balloon; fire and forget (a failure just means no popup, the alert is still logged).
pub fn balloon(title: &str, body: &str) {
    static TX: OnceLock<Mutex<Sender<(String, String)>>> = OnceLock::new();
    let tx = TX.get_or_init(|| {
        let (tx, rx) = channel();
        std::thread::spawn(move || worker(rx));
        Mutex::new(tx)
    });
    let _ = tx.lock().unwrap_or_else(|e| e.into_inner()).send((title.to_owned(), body.to_owned()));
}

#[cfg(test)]
mod tests {
    #[test]
    fn copy_truncates_and_terminates() {
        let mut buf = [0xffffu16; 4];
        super::copy(&mut buf, "abcdef");
        assert_eq!(buf[..3], [b'a' as u16, b'b' as u16, b'c' as u16]);
    }
}
