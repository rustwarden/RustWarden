//! Thin wrappers over the Win32 calls RustWarden needs. Each submodule is one OS
//! facility, so the collectors above them can be tested against small traits.

pub mod accent;
pub mod accounts;
pub mod apps;
pub mod audit;
pub mod autostart;
pub mod conns;
pub mod curl;
pub mod defender;
pub mod dpapi;
pub mod etw;
pub mod eventlog;
pub mod filedialog;
pub mod firewall;
pub mod helper;
pub mod icmp;
pub mod ifstats;
pub mod modal;
pub mod netinfo;
pub mod notify;
pub mod pdh;
pub mod picker;
pub mod proc;
pub mod qos;
pub mod services;
pub mod session;
pub mod upnp;
pub mod wallpaper;
pub mod watch;
pub mod webview;
pub mod wfp;
pub mod windivert;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{PCWSTR, w};

/// `CREATE_NO_WINDOW`: console helpers (curl, PowerShell, sc) run without flashing a window.
pub const NO_WINDOW: u32 = 0x0800_0000;

/// A Windows tool by its full path. Started by bare name, Windows would look beside this exe first,
/// so a file planted there would run with RustWarden's rights.
pub fn tool(name: &str) -> std::process::Command {
    std::process::Command::new(tool_path(name))
}

fn tool_path(name: &str) -> String {
    let mut buf = [0u16; 260];
    let n = unsafe { windows::Win32::System::SystemInformation::GetSystemDirectoryW(Some(&mut buf)) } as usize;
    let system = if n > 0 && n < buf.len() { String::from_utf16_lossy(&buf[..n]) } else { r"C:\Windows\System32".to_owned() };
    match name.trim_end_matches(".exe") {
        "powershell" => format!(r"{system}\WindowsPowerShell\v1.0\powershell.exe"),
        stem => format!(r"{system}\{stem}.exe"),
    }
}

/// UTF-16 with a trailing NUL, for APIs that take `PCWSTR`.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Reads a NUL-terminated UTF-16 buffer.
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Redirection Guard (Windows 11 22H2 and later): file opens refuse to follow a junction that a non-administrator made.
/// The service hands out an elevated window without a prompt, and that window writes into the user's own folders
/// (%LOCALAPPDATA%, %TEMP%); without this, a program running as the user could plant a junction there and aim those
/// writes at a system file. Older Windows doesn't know the policy and the call fails harmlessly.
pub fn redirection_guard() {
    use windows::Win32::System::Threading::{ProcessRedirectionTrustPolicy, SetProcessMitigationPolicy};
    // PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY is one DWORD of flags; bit 0 is EnforceRedirectionTrust.
    let enforce: u32 = 1;
    // SAFETY: the buffer is the 4-byte policy structure and lives for the call.
    let _ = unsafe { SetProcessMitigationPolicy(ProcessRedirectionTrustPolicy, (&raw const enforce).cast(), size_of::<u32>()) };
}

/// Whether this process runs with an elevated token.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(token, TokenElevation, Some(&mut elevation as *mut _ as *mut _), size_of::<TOKEN_ELEVATION>() as u32, &mut len).is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// Opens a URL in the default browser.
pub fn open_url(url: &str) {
    let url = wide(url);
    unsafe { ShellExecuteW(None, w!("open"), PCWSTR(url.as_ptr()), PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL) };
}

/// Starts a new elevated copy of this program (UAC prompt). The caller then closes the window.
pub fn restart_elevated() -> Result<(), String> {
    if !is_elevated() && autostart::run_service(hidden_start()) {
        return Ok(());
    }
    runas_self(true)
}

/// Starts a fresh copy of this program at the same privilege (service if installed, else a direct spawn,
/// with no UAC prompt). The caller then closes the window; `--elevated` makes the new copy wait for this one to exit.
pub fn restart_app() -> Result<(), String> {
    if is_elevated() {
        if autostart::stop_start_service() {
            return Ok(());
        }
    } else if autostart::run_service(hidden_start()) {
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    std::process::Command::new(exe).arg("--elevated").spawn().map(|_| ()).map_err(|e| format!("Couldn't restart: {e}"))
}

/// Started by the service (or an update restart) with `--elevated`, in the user's environment but with an administrator's rights.
pub fn from_service() -> bool {
    std::env::args().any(|a| a == "--elevated")
}

/// Started by the logon entry with "hide the window".
pub fn hidden_start() -> bool {
    std::env::args().any(|a| a == "--hidden")
}

/// Shows a message box with an OK button.
pub fn message(title: &str, text: &str) {
    use windows::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxW};
    let (title, text) = (wide(title), wide(text));
    unsafe { MessageBoxW(None, PCWSTR(text.as_ptr()), PCWSTR(title.as_ptr()), MB_OK | MB_ICONINFORMATION) };
}

/// Asks Windows (UAC prompt) to run this exe elevated, bypassing the service. `skip_running_check` passes
/// `--elevated`, so the new copy doesn't mistake the still-closing unelevated window for a running one and quit.
pub fn runas_self(skip_running_check: bool) -> Result<(), String> {
    let exe = match autostart::MOVED_TO.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(p) => p,
        None => std::env::current_exe().map_err(|e| e.to_string())?,
    };
    let exe = wide(&exe.to_string_lossy());
    let args = wide(&format!("{}{}", if skip_running_check { "--elevated " } else { "" }, if hidden_start() { "--hidden" } else { "" }));
    let result = unsafe { ShellExecuteW(None, w!("runas"), PCWSTR(exe.as_ptr()), PCWSTR(args.as_ptr()), PCWSTR::null(), SW_SHOWNORMAL) };
    // ShellExecute returns a value greater than 32 on success.
    if result.0 as isize > 32 { Ok(()) } else { Err("Administrator restart was cancelled or failed".into()) }
}

/// Initialises COM for the calling thread (multithreaded apartment) once.
pub fn com_init() {
    use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx};
    thread_local! {
        static DONE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    DONE.with(|d| {
        if !d.get() {
            // S_FALSE (already initialised) and RPC_E_CHANGED_MODE are fine for our use.
            let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            d.set(true);
        }
    });
}

/// Region of the user's locale ("GB" for "en-GB"), used to place "home" on the map.
pub fn home_region() -> Option<[u8; 2]> {
    use windows::Win32::Globalization::GetUserDefaultLocaleName;
    let mut buf = [0u16; 85];
    let n = unsafe { GetUserDefaultLocaleName(&mut buf) };
    if n <= 0 {
        return None;
    }
    let name = from_wide(&buf);
    let region = name.rsplit('-').next()?;
    crate::countries::parse_a2(region)
}

/// Shows the standard Save As dialog; `None` when cancelled. `ext` has no dot (`"csv"`).
/// Asks which existing `*.ext` file to open; `None` when cancelled.
pub fn open_dialog(title: &str, kind: &str, ext: &str) -> Option<std::path::PathBuf> {
    use windows::Win32::UI::Controls::Dialogs::{GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_HIDEREADONLY, OFN_PATHMUSTEXIST, OPENFILENAMEW};
    let filter: Vec<u16> = format!("{kind}\0*.{ext}\0\0").encode_utf16().collect();
    let title = wide(title);
    let mut file = [0u16; 520];
    let mut ofn = OPENFILENAMEW {
        lStructSize: size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: unsafe { windows::Win32::UI::Input::KeyboardAndMouse::GetActiveWindow() },
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: windows::core::PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        lpstrTitle: PCWSTR(title.as_ptr()),
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY,
        ..Default::default()
    };
    unsafe { GetOpenFileNameW(&mut ofn) }.as_bool().then(|| from_wide(&file).into())
}

pub fn save_dialog(title: &str, default_name: &str, kind: &str, ext: &str) -> Option<std::path::PathBuf> {
    use windows::Win32::UI::Controls::Dialogs::{GetSaveFileNameW, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW};
    let filter: Vec<u16> = format!("{kind}\0*.{ext}\0\0").encode_utf16().collect();
    let (title, ext) = (wide(title), wide(ext));
    let mut file = [0u16; 520];
    for (d, s) in file.iter_mut().zip(default_name.encode_utf16().take(259)) {
        *d = s;
    }
    let mut ofn = OPENFILENAMEW {
        lStructSize: size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: unsafe { windows::Win32::UI::Input::KeyboardAndMouse::GetActiveWindow() },
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: windows::core::PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        lpstrTitle: PCWSTR(title.as_ptr()),
        lpstrDefExt: PCWSTR(ext.as_ptr()),
        Flags: OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST,
        ..Default::default()
    };
    unsafe { GetSaveFileNameW(&mut ofn) }.as_bool().then(|| from_wide(&file).into())
}
