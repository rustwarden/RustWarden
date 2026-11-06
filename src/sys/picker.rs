//! "Block an app by clicking it": a see-through window over every screen with a + cursor that tints the
//! window under the mouse. A click picks that window's program, Esc or a right click cancels.

use std::cell::RefCell;
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Dwm::{DWMWA_CLOAKED, DWMWA_EXTENDED_FRAME_BOUNDS, DwmGetWindowAttribute};
use windows::Win32::Graphics::Gdi::{BeginPaint, CreateSolidBrush, DeleteObject, EndPaint, FillRect, HGDIOBJ, InvalidateRect, PAINTSTRUCT};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_ESCAPE};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{BOOL, w};

/// The program under the click.
#[derive(Clone, Debug, PartialEq)]
pub struct Pick {
    pub pid: u32,
    /// Full path of its exe.
    pub path: String,
}

#[derive(Default)]
struct State {
    /// The window being tinted: its screen rectangle and process.
    target: Option<(RECT, u32)>,
    /// Top-left of the covered area, to turn screen coordinates into window ones.
    origin: (i32, i32),
    /// The instruction banner, a window of its own so it stays fully opaque.
    hint: HWND,
    done: bool,
    picked: Option<u32>,
}

thread_local! {
    static ST: RefCell<State> = RefCell::new(State::default());
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    ST.with(|s| f(&mut s.borrow_mut()))
}

/// A UWP app's window belongs to this host program; the app is a child window of another process.
fn is_frame_host(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with("\\applicationframehost.exe")
}

struct Search {
    point: POINT,
    ours: HWND,
    hint: HWND,
    found: Option<(RECT, u32, HWND)>,
}

unsafe extern "system" fn each_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: lparam is the `Search` on the stack of `window_at`, which outlives the enumeration.
    let search = unsafe { &mut *(lparam.0 as *mut Search) };
    if hwnd == search.ours || hwnd == search.hint {
        return BOOL(1);
    }
    unsafe {
        if !IsWindowVisible(hwnd).as_bool() || IsIconic(hwnd).as_bool() {
            return BOOL(1);
        }
        let mut cloaked = 0u32;
        let _ = DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, (&mut cloaked as *mut u32).cast(), 4);
        if cloaked != 0 {
            return BOOL(1);
        }
        // The visible frame, without the invisible resize border a window has on Windows 10 and 11.
        let mut rect = RECT::default();
        if DwmGetWindowAttribute(hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, (&mut rect as *mut RECT).cast(), std::mem::size_of::<RECT>() as u32).is_err() && GetWindowRect(hwnd, &mut rect).is_err() {
            return BOOL(1);
        }
        let p = search.point;
        if p.x < rect.left || p.x >= rect.right || p.y < rect.top || p.y >= rect.bottom {
            return BOOL(1);
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        // EnumWindows goes from the top of the z-order down, so the first hit is what the user sees.
        search.found = Some((rect, pid, hwnd));
    }
    BOOL(0)
}

/// The window on top at `point`, with the process that owns it (a UWP app's own process, not its frame host).
fn window_at(point: POINT, ours: HWND) -> Option<(RECT, u32)> {
    let mut search = Search { point, ours, hint: with(|s| s.hint), found: None };
    unsafe {
        let _ = EnumWindows(Some(each_window), LPARAM(&mut search as *mut Search as isize));
    }
    let (rect, pid, hwnd) = search.found?;
    let app = crate::sys::apps::pid_path(pid).filter(|p| is_frame_host(p)).and_then(|_| app_in(hwnd, pid));
    Some((rect, app.unwrap_or(pid)))
}

/// For a frame host window: the process of the app inside it, a child window of another process.
fn app_in(frame: HWND, host_pid: u32) -> Option<u32> {
    struct Find {
        host: u32,
        found: Option<u32>,
    }
    unsafe extern "system" fn each_child(hwnd: HWND, lparam: LPARAM) -> BOOL {
        // SAFETY: lparam is the `Find` on the stack of `app_in`.
        let find = unsafe { &mut *(lparam.0 as *mut Find) };
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if pid != 0 && pid != find.host {
            find.found = Some(pid);
            return BOOL(0);
        }
        BOOL(1)
    }
    let mut find = Find { host: host_pid, found: None };
    unsafe {
        let _ = EnumChildWindows(Some(frame), Some(each_child), LPARAM(&mut find as *mut Find as isize));
    }
    find.found
}

unsafe extern "system" fn proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_SETCURSOR => {
                if let Ok(c) = LoadCursorW(None, IDC_CROSS) {
                    SetCursor(Some(c));
                }
                LRESULT(1)
            }
            WM_MOUSEMOVE | WM_TIMER => {
                let mut p = POINT::default();
                let _ = GetCursorPos(&mut p);
                let now = window_at(p, hwnd);
                if with(|s| std::mem::replace(&mut s.target, now) != now) {
                    let _ = InvalidateRect(Some(hwnd), None, true);
                }
                if msg == WM_TIMER && GetAsyncKeyState(i32::from(VK_ESCAPE.0)) < 0 {
                    with(|s| s.done = true);
                    let _ = DestroyWindow(hwnd);
                }
                LRESULT(0)
            }
            WM_LBUTTONDOWN => {
                with(|s| {
                    s.picked = s.target.map(|t| t.1);
                    s.done = true;
                });
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }
            WM_RBUTTONDOWN => {
                with(|s| s.done = true);
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                let (target, origin) = with(|s| (s.target, s.origin));
                // The whole screen is the dim; the window under the mouse is drawn in the accent colour.
                let dim = CreateSolidBrush(COLORREF(0));
                FillRect(hdc, &ps.rcPaint, dim);
                let _ = DeleteObject(HGDIOBJ(dim.0));
                if let Some((r, _)) = target {
                    let rect = RECT { left: r.left - origin.0, top: r.top - origin.1, right: r.right - origin.0, bottom: r.bottom - origin.1 };
                    let accent = CreateSolidBrush(COLORREF(0x00D7_7800));
                    FillRect(hdc, &rect, accent);
                    let _ = DeleteObject(HGDIOBJ(accent.0));
                }
                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            WM_DESTROY => {
                let _ = DestroyWindow(with(|s| s.hint));
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// Runs the picker on its own thread and calls `on_done` with the program clicked (`None` if cancelled).
pub fn start(on_done: impl FnOnce(Option<Pick>) + Send + 'static) {
    std::thread::spawn(move || on_done(run()));
}

fn run() -> Option<Pick> {
    with(|s| *s = State::default());
    unsafe {
        let inst = GetModuleHandleW(None).ok()?;
        let class = w!("RustWardenAppPicker");
        let wc = WNDCLASSW { lpfnWndProc: Some(proc), hInstance: inst.into(), lpszClassName: class, ..Default::default() };
        RegisterClassW(&wc);
        let (x, y) = (GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN));
        let (w, h) = (GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
        with(|s| s.origin = (x, y));
        let hwnd =
            CreateWindowExW(WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, class, w!("RustWarden app picker"), WS_POPUP, x, y, w, h, None, None, Some(inst.into()), None).ok()?;
        let _ = SetLayeredWindowAttributes(hwnd, COLORREF(0), 90, LWA_ALPHA);
        let (bw, bh) = (560, 44);
        let banner = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT,
            w!("STATIC"),
            w!("Click an app to block it  -  Esc or right click to cancel"),
            WS_POPUP | WS_VISIBLE | WINDOW_STYLE(0x1 | 0x200),
            GetSystemMetrics(SM_CXSCREEN) / 2 - bw / 2,
            24,
            bw,
            bh,
            None,
            None,
            Some(inst.into()),
            None,
        );
        with(|s| s.hint = banner.unwrap_or_default());
        let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        // Polls the Esc key (the window never takes focus) and the mouse position.
        SetTimer(Some(hwnd), 1, 40, None);
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let _ = UnregisterClassW(class, Some(inst.into()));
    }
    let pid = with(|s| s.picked)?;
    crate::sys::apps::pid_path(pid).map(|path| Pick { pid, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uwp_windows_are_found_by_their_frame_host() {
        assert!(is_frame_host(r"C:\Windows\System32\ApplicationFrameHost.exe"));
        assert!(!is_frame_host(r"C:\Program Files\App\app.exe"));
    }
}
