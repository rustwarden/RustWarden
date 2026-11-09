//! The RustWarden Windows service and start-with-Windows.
//!
//! The service (this exe with `--service`, LocalSystem, automatic start) owns no window: when
//! asked (user control code 128) it starts the GUI in the active user's session with that
//! user's elevated token, so no UAC prompt appears. Installing or removing it asks for
//! administrator once. The service also launches the GUI itself when a user logs on (session-change
//! event), so it appears after a boot even without the start-with-Windows entry (`--launch`), which
//! just sends the same request at logon.

use std::ffi::c_void;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Security::{GetTokenInformation, TOKEN_LINKED_TOKEN, TokenLinkedToken};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::Win32::System::Services::*;
use windows::Win32::System::Threading::{CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, PROCESS_INFORMATION, STARTUPINFOW, WaitForSingleObject};
use windows::Win32::UI::WindowsAndMessaging::{WTS_CONSOLE_CONNECT, WTS_SESSION_LOGON};
use windows::core::{PWSTR, w};

const SERVICE: &str = "RustWarden";
/// What Services (services.msc) lists; the short name above stays for compatibility.
const DISPLAY: windows::core::PCWSTR = w!("RustWarden Firewall");
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
use super::NO_WINDOW;
/// User-defined service control: "start the GUI in the active session".
const LAUNCH: u32 = 128;
/// Same, with the window left hidden in the tray.
const LAUNCH_HIDDEN: u32 = 129;
// ---- client side (called from the GUI) ----

fn quiet(program: &str) -> Command {
    let mut c = super::tool(program);
    c.creation_flags(NO_WINDOW);
    c
}

fn ok(mut c: Command) -> bool {
    c.status().is_ok_and(|s| s.success())
}

pub fn service_installed() -> bool {
    let mut c = quiet("sc");
    c.args(["query", SERVICE]);
    ok(c)
}

/// Re-runs this exe with `flag` elevated (one UAC prompt unless already elevated), waits for it and
/// returns its exit code; `None` if the prompt was declined.
fn run_elevated(flag: &str) -> Option<u32> {
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    let exe = crate::sys::wide(&std::env::current_exe().ok()?.to_string_lossy());
    let flag = crate::sys::wide(flag);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: windows::core::PCWSTR(exe.as_ptr()),
        lpParameters: windows::core::PCWSTR(flag.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe {
        ShellExecuteExW(&mut info).ok()?;
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1;
        let _ = GetExitCodeProcess(info.hProcess, &mut code);
        let _ = CloseHandle(info.hProcess);
        Some(code)
    }
}

/// True if `exe` is under `dir`.
fn under(exe: &Path, dir: &str) -> bool {
    exe.to_string_lossy().to_lowercase().starts_with(&format!("{}\\", dir.to_lowercase().trim_end_matches('\\')))
}

/// Asks Windows for Program Files: an environment variable could point the elevated service install at a folder the user controls.
fn in_program_files(exe: &Path) -> bool {
    use windows::Win32::UI::Shell::{FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86};
    [FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86].iter().filter_map(crate::settings::known_folder).any(|d| under(exe, &d))
}

/// `RustWarden.lnk` in a known folder (the user's Desktop, or their Start menu Programs).
fn lnk_in(folder: &windows::core::GUID) -> Option<std::path::PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    unsafe {
        let p = SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, None).ok()?;
        let dir = p.to_string().ok();
        CoTaskMemFree(Some(p.0 as *const c_void));
        Some(std::path::PathBuf::from(dir?).join("RustWarden.lnk"))
    }
}

fn desktop_lnk() -> Option<std::path::PathBuf> {
    lnk_in(&windows::Win32::UI::Shell::FOLDERID_Desktop)
}

fn start_menu_lnk() -> Option<std::path::PathBuf> {
    lnk_in(&windows::Win32::UI::Shell::FOLDERID_Programs)
}

fn shortcut(lnk: Option<std::path::PathBuf>, exe: &Path) {
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, IPersistFile};
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    use windows::core::{Interface, PCWSTR};
    let Some(lnk) = lnk else { return };
    crate::sys::com_init();
    let target = crate::sys::wide(&exe.to_string_lossy());
    let dir = crate::sys::wide(&exe.parent().unwrap_or(exe).to_string_lossy());
    let lnk = crate::sys::wide(&lnk.to_string_lossy());
    let _ = (|| -> windows::core::Result<()> {
        unsafe {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            link.SetPath(PCWSTR(target.as_ptr()))?;
            link.SetWorkingDirectory(PCWSTR(dir.as_ptr()))?;
            link.cast::<IPersistFile>()?.Save(PCWSTR(lnk.as_ptr()), true)
        }
    })();
}

/// Where the service's exe lives: this exe if it is already in Program Files, else `%ProgramFiles%\RustWarden`.
pub(crate) fn installed_exe() -> Result<std::path::PathBuf, String> {
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    // An exe updated in place inside the old RustyWire folder is copied to the new one.
    if in_program_files(&me) && !me.starts_with(crate::settings::legacy_admin_dir()) {
        return Ok(me);
    }
    Ok(crate::settings::admin_dir().join("RustWarden.exe"))
}

/// Installs the service from wherever the exe is run (e.g. Downloads) by re-running it elevated with
/// `--install-service`: one UAC prompt, no helper scripts. Outside Program Files that run first copies the
/// exe to `%ProgramFiles%\RustWarden` and the service runs the copy, so it survives the original being
/// moved or rebuilt. Adds the desktop and Start menu shortcuts asked for.
pub fn install_service(desktop: bool, start_menu: bool) -> Result<(), String> {
    match run_elevated("--install-service") {
        None => return Err("Service was not installed (administrator approval is required)".into()),
        Some(0) => {}
        Some(_) => return Err("Service install failed; is RustWarden.exe in Program Files still running?".into()),
    }
    let exe = installed_exe()?;
    if !service_installed() || !exe.exists() {
        return Err("Service was not installed".into());
    }
    if desktop {
        shortcut(desktop_lnk(), &exe);
    }
    if start_menu {
        shortcut(start_menu_lnk(), &exe);
    }
    // Without a running service nothing opens the window (it would be left as a background process).
    let mut c = quiet("sc");
    c.args(["query", SERVICE]);
    let running = c.output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"));
    if !running {
        return Err("Service was installed but did not start; see Event Viewer > System for RustWarden".into());
    }
    Ok(())
}

/// Where the running exe went after an uninstall; a restart must launch it from here.
pub static MOVED_TO: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

/// Removes the service, moves the installed exe to the user's Downloads, and deletes the desktop shortcut
/// and the start-with-Windows entry (both would point at the moved exe).
pub fn uninstall_service() -> Result<(), String> {
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let installed = installed_exe()?;
    let dest = downloads_exe()?;
    run_elevated("--uninstall-service");
    if service_installed() {
        return Err("Service was not removed (administrator approval is required)".into());
    }
    for lnk in [desktop_lnk(), start_menu_lnk()].into_iter().flatten() {
        let _ = std::fs::remove_file(lnk);
    }
    let _ = set_startup(false, false);
    if dest.exists() && !installed.exists() && installed == me {
        *MOVED_TO.lock().unwrap_or_else(|e| e.into_inner()) = Some(dest);
    }
    Ok(())
}

fn downloads_exe() -> Result<std::path::PathBuf, String> {
    Ok(std::path::PathBuf::from(std::env::var("USERPROFILE").map_err(|e| e.to_string())?).join("Downloads").join("RustWarden.exe"))
}

// ---- elevated side (`--install-service` / `--uninstall-service`) ----

/// Stops and deletes the service if it exists, waiting (up to 5 s) for it to stop so its exe can be replaced.
unsafe fn remove_service(scm: SC_HANDLE) {
    unsafe {
        let Ok(svc) = OpenServiceW(scm, w!("RustWarden"), SERVICE_ALL_ACCESS) else { return };
        authorize_stop();
        let mut st = SERVICE_STATUS::default();
        let _ = ControlService(svc, SERVICE_CONTROL_STOP, &mut st);
        for _ in 0..50 {
            if QueryServiceStatus(svc, &mut st).is_err() || st.dwCurrentState == SERVICE_STOPPED {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = DeleteService(svc);
        let _ = CloseServiceHandle(svc);
    }
}

/// Elevated: replaces the service with one that runs the installed exe (copying this exe there first
/// when it is elsewhere), then starts it.
pub fn install_elevated() -> Result<(), String> {
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = installed_exe()?;
    let e = |e: windows::core::Error| e.to_string();
    unsafe {
        let scm = OpenSCManagerW(windows::core::PCWSTR::null(), windows::core::PCWSTR::null(), SC_MANAGER_ALL_ACCESS).map_err(e)?;
        remove_service(scm);
        if me != exe {
            std::fs::create_dir_all(exe.parent().unwrap_or(&exe)).map_err(|e| e.to_string())?;
            // The old service process may still be releasing the file.
            let mut copied = std::fs::copy(&me, &exe);
            for _ in 0..20 {
                if copied.is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
                copied = std::fs::copy(&me, &exe);
            }
            copied.map_err(|e| e.to_string())?;
        }
        let bin = crate::sys::wide(&format!("\"{}\" --service", exe.display()));
        let svc = CreateServiceW(
            scm,
            w!("RustWarden"),
            DISPLAY,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            windows::core::PCWSTR(bin.as_ptr()),
            windows::core::PCWSTR::null(),
            None,
            windows::core::PCWSTR::null(),
            windows::core::PCWSTR::null(),
            windows::core::PCWSTR::null(),
        )
        .map_err(e)?;
        let mut desc = crate::sys::wide("Starts RustWarden as administrator without a prompt.");
        let info = SERVICE_DESCRIPTIONW { lpDescription: PWSTR(desc.as_mut_ptr()) };
        let _ = ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, Some(&info as *const _ as *const c_void));
        set_recovery(svc);
        // SYSTEM and Administrators full control; any logged-on user may query and send LAUNCH.
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(w!("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LCCR;;;IU)"), SDDL_REVISION_1, &mut sd, None).map_err(e)?;
        SetServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, sd).map_err(e)?;
        let _ = StartServiceW(svc, None);
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }
    Ok(())
}

/// Elevated: removes the service and moves the installed exe to Downloads.
pub fn uninstall_elevated() -> Result<(), String> {
    let installed = installed_exe()?;
    let dest = downloads_exe()?;
    unsafe {
        let scm = OpenSCManagerW(windows::core::PCWSTR::null(), windows::core::PCWSTR::null(), SC_MANAGER_ALL_ACCESS).map_err(|e| e.to_string())?;
        remove_service(scm);
        let _ = CloseServiceHandle(scm);
    }
    if installed.exists() {
        // A running exe can be renamed but not deleted, so `rename` (same drive) works while it is still open.
        std::fs::rename(&installed, &dest).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_dir(installed.parent().unwrap_or(&installed));
    }
    Ok(())
}

/// Set when a later launch asked the running window to come forward.
pub static SHOW: AtomicBool = AtomicBool::new(false);
const SHOW_EVENT: windows::core::PCWSTR = w!("Local\\RustWardenShow");

/// Running GUI: lets a later launch (which may be unelevated) bring this window back from the tray.
pub fn watch_show(ctx: egui::Context) {
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::System::Threading::{CreateEventW, INFINITE};
    unsafe {
        // Everyone may signal it, including a medium-integrity process (the default would let only admins).
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(w!("D:(A;;GA;;;WD)S:(ML;;NW;;;LW)"), SDDL_REVISION_1, &mut sd, None).is_err() {
            return;
        }
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: false.into() };
        let Ok(ev) = CreateEventW(Some(&sa), false, false, SHOW_EVENT) else { return };
        let ev = ev.0 as isize;
        std::thread::spawn(move || {
            while WaitForSingleObject(HANDLE(ev as *mut c_void), INFINITE) == WAIT_OBJECT_0 {
                SHOW.store(true, Ordering::SeqCst);
                ctx.request_repaint();
            }
        });
    }
}

/// True if a RustWarden window is already running and was asked to show itself.
pub fn signal_show() -> bool {
    use windows::Win32::System::Threading::{EVENT_MODIFY_STATE, OpenEventW, SetEvent};
    unsafe {
        OpenEventW(EVENT_MODIFY_STATE, false, SHOW_EVENT).is_ok_and(|e| {
            let sent = SetEvent(e).is_ok();
            let _ = CloseHandle(e);
            sent
        })
    }
}

/// Claims the one-GUI-per-session lock (held until the process exits) so a second copy can't run and corrupt
/// the first's ETW session and data. `patient` (an update or admin restart, whose predecessor is still closing)
/// waits up to 10 s for it. If it stays taken, the running window is asked to come forward and this returns false.
pub fn claim_instance(patient: bool) -> bool {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;
    for _ in 0..if patient { 100 } else { 1 } {
        match unsafe { CreateMutexW(None, false, w!("Local\\RustWardenInstance")) } {
            // The handle is deliberately never closed: the lock lasts as long as the process.
            Ok(_) if unsafe { windows::Win32::Foundation::GetLastError() } != ERROR_ALREADY_EXISTS => return true,
            // An elevated owner's mutex can't be opened from an unelevated process: still taken.
            Err(e) if e.code() != ERROR_ACCESS_DENIED.to_hresult() => return true,
            _ => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    signal_show();
    false
}

fn service_running() -> bool {
    let mut c = quiet("sc");
    c.args(["query", SERVICE]);
    c.output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
}

/// Starts the service if it is installed but stopped (needs administrator). The extra `quiet` argument
/// tells it not to open a window: this GUI is already running.
pub fn ensure_service_running() {
    ensure_recovery();
    if service_installed() && !service_running() {
        let mut c = quiet("sc");
        c.args(["start", SERVICE, "quiet"]);
        let _ = c.status();
    }
}

/// Ending RustWarden.exe in Task Manager kills the service without a stop request; Windows starts it again a second later.
fn set_recovery(svc: SC_HANDLE) {
    let mut actions = [SC_ACTION { Type: SC_ACTION_RESTART, Delay: 1000 }; 3];
    let fail = SERVICE_FAILURE_ACTIONSW { dwResetPeriod: 60, cActions: actions.len() as u32, lpsaActions: actions.as_mut_ptr(), ..Default::default() };
    unsafe {
        let _ = ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, Some(&fail as *const _ as *const c_void));
    }
}

/// Elevated window: gives a service installed by an older version the restart-after-kill action and
/// the current display name too.
fn ensure_recovery() {
    unsafe {
        let Ok(scm) = OpenSCManagerW(windows::core::PCWSTR::null(), windows::core::PCWSTR::null(), SC_MANAGER_CONNECT) else { return };
        if let Ok(svc) = OpenServiceW(scm, w!("RustWarden"), SERVICE_CHANGE_CONFIG) {
            set_recovery(svc);
            let _ = ChangeServiceConfigW(
                svc,
                ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                SERVICE_START_TYPE(SERVICE_NO_CHANGE),
                SERVICE_ERROR(SERVICE_NO_CHANGE),
                windows::core::PCWSTR::null(),
                windows::core::PCWSTR::null(),
                None,
                windows::core::PCWSTR::null(),
                windows::core::PCWSTR::null(),
                windows::core::PCWSTR::null(),
                DISPLAY,
            );
            let _ = CloseServiceHandle(svc);
        }
        let _ = CloseServiceHandle(scm);
    }
}

/// Ends every other process running this exe's image name (the GUI, however it was started); returns how many.
fn end_other_instances() -> i32 {
    std::env::current_exe().ok().and_then(|p| p.file_name().map(|n| end_processes(&n.to_string_lossy()))).unwrap_or(0)
}

/// Ends every process but this one whose image is called `name` (any case); returns how many.
fn end_processes(name: &str) -> i32 {
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
    use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_TERMINATE, TerminateProcess};
    let name = name.to_lowercase();
    let mut ended = 0;
    unsafe {
        let me = GetCurrentProcessId();
        if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut e = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
            let mut more = Process32FirstW(snap, &mut e).is_ok();
            while more {
                if e.th32ProcessID != me
                    && crate::sys::from_wide(&e.szExeFile).to_lowercase() == name
                    && let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, e.th32ProcessID)
                {
                    ended += i32::from(TerminateProcess(h, 0).is_ok());
                    let _ = CloseHandle(h);
                }
                more = Process32NextW(snap, &mut e).is_ok();
            }
            let _ = CloseHandle(snap);
        }
    }
    ended
}

/// Debug builds only, elevated: stops the installed service and ends every other RustWarden process, so a
/// development run can't fight an installed copy over the ETW session and window. Returns what it did.
pub fn prepare_debug() -> Option<String> {
    let mut did = Vec::new();
    if service_installed() && service_running() {
        authorize_stop();
        let mut c = quiet("sc");
        c.args(["stop", SERVICE]);
        let _ = c.status();
        for _ in 0..50 {
            if !service_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        did.push("stopped the RustWarden service".to_owned());
    }
    let ended = end_other_instances();
    if ended > 0 {
        did.push(format!("closed {ended} other running RustWarden process{}", if ended == 1 { "" } else { "es" }));
    }
    (!did.is_empty())
        .then(|| format!("This is a debug build, so RustWarden {}.\n\nThat keeps it from clashing with an installed copy. The service stays stopped until you run a release build.", did.join(" and ")))
}

/// Asks the service to start the elevated GUI; false if it isn't installed or running.
pub fn run_service(hidden: bool) -> bool {
    let mut c = quiet("sc");
    c.args(["control", SERVICE, &(if hidden { LAUNCH_HIDDEN } else { LAUNCH }).to_string()]);
    ok(c)
}

/// Restart of the service after an update, from a detached helper: stopping the service ends this window
/// too, so the helper (which outlives it) waits for the stop and starts the service again from the new exe,
/// which opens the new window. False if the helper couldn't be started.
pub fn stop_start_service() -> bool {
    if !service_installed() {
        return false;
    }
    authorize_stop();
    let mut c = quiet("powershell");
    c.args(["-NoProfile", "-NonInteractive", "-Command", &format!("Stop-Service {SERVICE} -Force; Start-Service {SERVICE}")]);
    c.spawn().is_ok()
}

/// A newer exe run from elsewhere (e.g. Downloads) than the installed service's copy: reinstalls the service
/// from it (one UAC prompt, none when already elevated) so the old service doesn't open an old window.
/// True if it did, and the service has opened the new window; this process should then exit.
pub fn refresh_stale_service() -> bool {
    let (Ok(installed), Ok(me)) = (installed_exe(), std::env::current_exe()) else { return false };
    if me == installed || !service_installed() {
        return false;
    }
    let newer = || {
        // The version built into each exe decides; an older exe with a fresh file time (copied, unzipped) never replaces a newer one.
        if let Some(theirs) = file_version(&installed)
            && theirs != own_version()
        {
            return Some(own_version() > theirs);
        }
        // Same version (a rebuild during development), or an installed exe with no version: a changed, more recent file is newer.
        let (a, b) = (std::fs::metadata(&me).ok()?, std::fs::metadata(&installed).ok()?);
        Some(a.modified().ok()? > b.modified().ok()? && (a.len() != b.len() || std::fs::read(&me).ok()? != std::fs::read(&installed).ok()?))
    };
    newer() == Some(true) && run_elevated("--install-service") == Some(0)
}

/// This build's version as (major, minor, patch), as the exe's version resource carries it.
fn own_version() -> (u16, u16, u16) {
    let p = |s: &str| s.parse().unwrap_or(0);
    (p(env!("CARGO_PKG_VERSION_MAJOR")), p(env!("CARGO_PKG_VERSION_MINOR")), p(env!("CARGO_PKG_VERSION_PATCH")))
}

/// The (major, minor, patch) file version in an exe's version resource; `None` without one.
fn file_version(exe: &Path) -> Option<(u16, u16, u16)> {
    use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW};
    use windows::core::{HSTRING, w};
    let name = HSTRING::from(exe.as_os_str());
    unsafe {
        let size = GetFileVersionInfoSizeW(&name, None);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        GetFileVersionInfoW(&name, None, size, buf.as_mut_ptr().cast()).ok()?;
        let (mut info, mut len) = (std::ptr::null_mut(), 0u32);
        if !VerQueryValueW(buf.as_ptr().cast(), w!("\\"), &mut info, &mut len).as_bool() || info.is_null() || (len as usize) < size_of::<VS_FIXEDFILEINFO>() {
            return None;
        }
        // SAFETY: VerQueryValueW pointed into `buf` (still alive) at a structure of at least this size; it may be unaligned.
        let fixed = std::ptr::read_unaligned(info as *const VS_FIXEDFILEINFO);
        (fixed.dwSignature == 0xFEEF_04BD).then_some(((fixed.dwFileVersionMS >> 16) as u16, fixed.dwFileVersionMS as u16, (fixed.dwFileVersionLS >> 16) as u16))
    }
}

pub fn startup_enabled() -> bool {
    let mut c = quiet("reg");
    c.args(["query", RUN_KEY, "/v", SERVICE]);
    ok(c)
}

/// The logon entry starts the window hidden (it carries `--hidden`).
pub fn startup_hidden() -> bool {
    let mut c = quiet("reg");
    c.args(["query", RUN_KEY, "/v", SERVICE]);
    c.output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("--hidden"))
}

pub fn set_startup(on: bool, hidden: bool) -> Result<(), String> {
    set_startup_for(&std::env::current_exe().map_err(|e| e.to_string())?, on, hidden)
}

fn set_startup_for(exe: &Path, on: bool, hidden: bool) -> Result<(), String> {
    let mut c = quiet("reg");
    if on {
        c.args(["add", RUN_KEY, "/v", SERVICE, "/t", "REG_SZ", "/d", &format!("\"{}\" --launch{}", exe.display(), if hidden { " --hidden" } else { "" }), "/f"]);
    } else {
        c.args(["delete", RUN_KEY, "/v", SERVICE, "/f"]);
    }
    if ok(c) { Ok(()) } else { Err("Couldn't change the startup entry".into()) }
}

// ---- migration from the old name (RustyWire), see migrate.rs ----

/// Elevated: deletes the service called RustyWire and ends the processes of that name (a kill would otherwise
/// be undone by the service's restart action). True if the service existed.
pub fn remove_legacy_service() -> bool {
    let existed = unsafe {
        let Ok(scm) = OpenSCManagerW(windows::core::PCWSTR::null(), windows::core::PCWSTR::null(), SC_MANAGER_ALL_ACCESS) else { return false };
        let svc = OpenServiceW(scm, w!("RustyWire"), SERVICE_ALL_ACCESS);
        if let Ok(svc) = &svc {
            // No actions and no array removes the restart-after-kill actions.
            let _ = ChangeServiceConfig2W(*svc, SERVICE_CONFIG_FAILURE_ACTIONS, Some(&SERVICE_FAILURE_ACTIONSW::default() as *const _ as *const c_void));
            let _ = DeleteService(*svc);
            let _ = CloseServiceHandle(*svc);
        }
        let _ = CloseServiceHandle(scm);
        svc.is_ok()
    };
    end_processes("RustyWire.exe");
    // A killed process leaves its ETW session running.
    let mut c = quiet("logman");
    c.args(["stop", "RustyWire-Net", "-ets"]);
    let _ = c.status();
    existed
}

/// Moves the start-with-Windows entry and the shortcuts called RustyWire over to RustWarden, pointing at `exe`.
pub fn adopt_legacy_entries(exe: &Path) {
    let mut c = quiet("reg");
    c.args(["query", RUN_KEY, "/v", "RustyWire"]);
    if let Ok(o) = c.output()
        && o.status.success()
    {
        let mut d = quiet("reg");
        d.args(["delete", RUN_KEY, "/v", "RustyWire", "/f"]);
        let _ = d.status();
        let _ = set_startup_for(exe, true, String::from_utf8_lossy(&o.stdout).contains("--hidden"));
    }
    for lnk in [desktop_lnk(), start_menu_lnk()].into_iter().flatten() {
        let old = lnk.with_file_name("RustyWire.lnk");
        if old.exists() {
            let _ = std::fs::remove_file(old);
            shortcut(Some(lnk), exe);
        }
    }
}

// ---- stop requests (services.msc, sc stop) ----
//
// With a password set, a stop from outside asks the window for it first. The service (session 0) can't show
// UI, so it signals the window through named events only administrators can use: the service sets `ASK`,
// the window answers `ACK` at once, then `OK` (right password, or no password set) or `NO`. A stop the window
// starts itself (restart, update, install) sets `OK` beforehand.
const EV_ASK: windows::core::PCWSTR = w!("Global\\RustWardenStopAsk");
const EV_ACK: windows::core::PCWSTR = w!("Global\\RustWardenStopAck");
const EV_OK: windows::core::PCWSTR = w!("Global\\RustWardenStopOk");
const EV_NO: windows::core::PCWSTR = w!("Global\\RustWardenStopNo");

/// How long the service waits for the password (the window gives up after the same time).
pub const STOP_ASK_MS: u32 = 300_000;

/// Set when the service asked for the password to allow a stop.
pub static STOP_ASK: AtomicBool = AtomicBool::new(false);

fn open_event(name: windows::core::PCWSTR) -> Option<HANDLE> {
    use windows::Win32::System::Threading::{EVENT_ALL_ACCESS, OpenEventW};
    unsafe { OpenEventW(EVENT_ALL_ACCESS, false, name).ok() }
}

fn signal(name: windows::core::PCWSTR) {
    if let Some(e) = open_event(name) {
        unsafe {
            let _ = windows::Win32::System::Threading::SetEvent(e);
            let _ = CloseHandle(e);
        }
    }
}

/// The window's answer to a stop request: true lets the service stop.
pub fn answer_stop(allow: bool) {
    signal(if allow { EV_OK } else { EV_NO });
}

/// Called before a stop the window (or the installer) starts itself, so the service doesn't ask for the password.
pub fn authorize_stop() {
    signal(EV_OK);
}

/// Running GUI: turns the service's stop requests into `STOP_ASK`.
pub fn watch_stop_ask(ctx: egui::Context) {
    use windows::Win32::System::Threading::INFINITE;
    std::thread::spawn(move || {
        // The service makes the events before it opens the window; none appear when the service isn't installed.
        let mut found = None;
        for _ in 0..10 {
            found = open_event(EV_ASK);
            if found.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        let Some(ask) = found else { return };
        let ask = ask.0 as isize;
        while unsafe { WaitForSingleObject(HANDLE(ask as *mut c_void), INFINITE) } == WAIT_OBJECT_0 {
            signal(EV_ACK);
            STOP_ASK.store(true, Ordering::SeqCst);
            ctx.request_repaint();
        }
    });
}

// ---- service side (`--service`) ----

static STATUS: AtomicIsize = AtomicIsize::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
/// A refused stop: the service must still leave "stopping" (it can't go back to running), so it ends and
/// starts itself again, leaving the window alone.
static REFUSED: AtomicBool = AtomicBool::new(false);
/// Process handle of the GUI we started, so a second request doesn't open a second window.
static CHILD: Mutex<isize> = Mutex::new(0);
/// The service's ends of the stop-request events: ask, ack, ok, no (0 if they couldn't be made).
static EVENTS: [AtomicIsize; 4] = [AtomicIsize::new(0), AtomicIsize::new(0), AtomicIsize::new(0), AtomicIsize::new(0)];

fn make_events() {
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::System::Threading::CreateEventW;
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(w!("D:(A;;GA;;;SY)(A;;GA;;;BA)"), SDDL_REVISION_1, &mut sd, None).is_err() {
            return;
        }
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: false.into() };
        for (slot, name) in EVENTS.iter().zip([EV_ASK, EV_ACK, EV_OK, EV_NO]) {
            if let Ok(h) = CreateEventW(Some(&sa), false, false, name) {
                slot.store(h.0 as isize, Ordering::SeqCst);
            }
        }
    }
}

/// Whether a stop request may go ahead: the window pre-authorised it, there is no window to ask, or the
/// window got the password (or has none set). A denied or unanswered request leaves the service running.
fn stop_allowed() -> bool {
    use windows::Win32::System::Threading::{ResetEvent, SetEvent, WaitForMultipleObjects};
    let [ask, ack, ok, no] = [0, 1, 2, 3].map(|i| HANDLE(EVENTS[i].load(Ordering::SeqCst) as *mut c_void));
    if ask.0.is_null() || ok.0.is_null() {
        return true;
    }
    unsafe {
        if WaitForSingleObject(ok, 0) == WAIT_OBJECT_0 {
            return true;
        }
        let _ = ResetEvent(ack);
        let _ = ResetEvent(no);
        let _ = SetEvent(ask);
        // No window answers within 3 s: nobody to ask.
        if WaitForSingleObject(ack, 3000) != WAIT_OBJECT_0 {
            return true;
        }
        // Finding the window and typing the password takes a while.
        WaitForMultipleObjects(&[ok, no], false, STOP_ASK_MS) == WAIT_OBJECT_0
    }
}

/// Blocks until the service is stopped. Fails when not started by the service manager.
pub fn run_dispatcher() -> windows::core::Result<()> {
    let mut name = crate::sys::wide(SERVICE);
    let table = [SERVICE_TABLE_ENTRYW { lpServiceName: PWSTR(name.as_mut_ptr()), lpServiceProc: Some(service_main) }, SERVICE_TABLE_ENTRYW::default()];
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }
}

fn report(state: SERVICE_STATUS_CURRENT_STATE) {
    report_step(state, 0);
}

/// Reports `state`; a pending state carries a checkpoint so the service manager keeps waiting (restart in services.msc).
fn report_step(state: SERVICE_STATUS_CURRENT_STATE, checkpoint: u32) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwCheckPoint: checkpoint,
        dwWaitHint: if state == SERVICE_STOP_PENDING { 10_000 } else { 0 },
        dwControlsAccepted: if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE } else { 0 },
        ..Default::default()
    };
    unsafe {
        let _ = SetServiceStatus(SERVICE_STATUS_HANDLE(STATUS.load(Ordering::SeqCst) as *mut c_void), &status);
    }
}

unsafe extern "system" fn service_main(argc: u32, _argv: *mut PWSTR) {
    let Ok(handle) = (unsafe { RegisterServiceCtrlHandlerExW(w!("RustWarden"), Some(handler), None) }) else { return };
    STATUS.store(handle.0 as isize, Ordering::SeqCst);
    make_events();
    report(SERVICE_RUNNING);
    // Installing starts the service with a user at the console: open the window right away. At boot
    // nobody is logged on yet, so this fails harmlessly and the logon entry asks for it later.
    // A start with an argument (`ensure_service_running`) comes from a window that is already open.
    if argc < 2 {
        let _ = launch_gui(false);
    }
    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    if REFUSED.load(Ordering::SeqCst) {
        // Stopping can't be undone once reported, so come straight back up (`quiet`: the window is still open).
        let _ = quiet("cmd").args(["/c", &format!("ping -n 3 127.0.0.1 >nul & sc start {SERVICE} quiet")]).spawn();
    } else {
        // Stopping the service stops RustWarden too, whichever way the window was started.
        end_other_instances();
    }
    report(SERVICE_STOPPED);
}

unsafe extern "system" fn handler(control: u32, _event: u32, _data: *mut c_void, _ctx: *mut c_void) -> u32 {
    match control {
        // May wait for the password, which would block the service manager's reply, so it runs apart.
        SERVICE_CONTROL_STOP => {
            std::thread::spawn(|| {
                // Say "stopping" while the password is awaited, or a restart from services.msc gives up on us.
                let done = AtomicBool::new(false);
                let allowed = std::thread::scope(|s| {
                    s.spawn(|| {
                        let mut n = 1;
                        while !done.load(Ordering::SeqCst) {
                            report_step(SERVICE_STOP_PENDING, n);
                            n += 1;
                            std::thread::sleep(std::time::Duration::from_secs(2));
                        }
                    });
                    let allowed = stop_allowed();
                    done.store(true, Ordering::SeqCst);
                    allowed
                });
                REFUSED.store(!allowed, Ordering::SeqCst);
                report(SERVICE_STOP_PENDING);
                STOP.store(true, Ordering::SeqCst);
            });
        }
        LAUNCH => {
            // A non-zero return makes `sc control` fail, so the caller falls back to a normal start.
            return u32::from(launch_gui(false).is_err());
        }
        LAUNCH_HIDDEN => return u32::from(launch_gui(true).is_err()),
        SERVICE_CONTROL_SESSIONCHANGE if matches!(_event, WTS_SESSION_LOGON | WTS_CONSOLE_CONNECT) => {
            // At boot nobody is logged on, so the start-up launch failed. Don't block the handler: the
            // user's token and desktop may take a moment to be ready, so retry for up to 30 s.
            std::thread::spawn(|| {
                for _ in 0..30 {
                    if launch_gui(logon_hidden()).is_ok() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            });
        }
        _ => {}
    }
    0
}

/// True if the console user's start-with-Windows entry carries `--hidden` (their wish to stay in the tray).
fn logon_hidden() -> bool {
    use windows::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
    use windows::Win32::System::Registry::{HKEY, KEY_READ, RRF_RT_REG_SZ, RegCloseKey, RegGetValueW, RegOpenCurrentUser};
    unsafe {
        let mut user = HANDLE::default();
        if WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &mut user).is_err() {
            return false;
        }
        let mut hidden = false;
        if ImpersonateLoggedOnUser(user).is_ok() {
            let mut hkcu = HKEY::default();
            if RegOpenCurrentUser(KEY_READ.0, &mut hkcu).is_ok() {
                let mut buf = [0u16; 1024];
                let mut len = size_of_val(&buf) as u32;
                let r = RegGetValueW(hkcu, w!(r"Software\Microsoft\Windows\CurrentVersion\Run"), w!("RustWarden"), RRF_RT_REG_SZ, None, Some(buf.as_mut_ptr() as *mut c_void), Some(&mut len));
                hidden = r.is_ok() && crate::sys::from_wide(&buf).contains("--hidden");
                let _ = RegCloseKey(hkcu);
            }
            let _ = RevertToSelf();
        }
        let _ = CloseHandle(user);
        hidden
    }
}

/// Starts the GUI on the console session's desktop with the logged-on user's elevated token.
fn launch_gui(hidden: bool) -> windows::core::Result<()> {
    let mut child = CHILD.lock().unwrap_or_else(|e| e.into_inner());
    if *child != 0 && unsafe { WaitForSingleObject(HANDLE(*child as *mut c_void), 0) } == WAIT_TIMEOUT {
        return Ok(());
    }
    unsafe {
        let mut user = HANDLE::default();
        WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &mut user)?;
        // For an administrator the user token is the filtered one; its linked token is the full one.
        let mut linked = TOKEN_LINKED_TOKEN::default();
        let mut len = 0u32;
        let token = if GetTokenInformation(user, TokenLinkedToken, Some(&mut linked as *mut _ as *mut c_void), size_of::<TOKEN_LINKED_TOKEN>() as u32, &mut len).is_ok() {
            let _ = CloseHandle(user);
            linked.LinkedToken
        } else {
            user
        };
        let result = (|| {
            let exe = std::env::current_exe().map_err(|_| windows::core::Error::from_thread())?;
            let mut cmd = crate::sys::wide(&format!("\"{}\" --elevated{}", exe.display(), if hidden { " --hidden" } else { "" }));
            let mut desktop = crate::sys::wide("winsta0\\default");
            let mut env = std::ptr::null_mut();
            CreateEnvironmentBlock(&mut env, Some(token), false)?;
            let si = STARTUPINFOW { cb: size_of::<STARTUPINFOW>() as u32, lpDesktop: PWSTR(desktop.as_mut_ptr()), ..Default::default() };
            let mut pi = PROCESS_INFORMATION::default();
            let r = CreateProcessAsUserW(Some(token), None, Some(PWSTR(cmd.as_mut_ptr())), None, None, false, CREATE_UNICODE_ENVIRONMENT, Some(env), None, &si, &mut pi);
            let _ = DestroyEnvironmentBlock(env);
            r?;
            let _ = CloseHandle(pi.hThread);
            // The previous GUI has exited; its handle is no longer needed.
            if *child != 0 {
                let _ = CloseHandle(HANDLE(*child as *mut c_void));
            }
            *child = pi.hProcess.0 as isize;
            Ok(())
        })();
        let _ = CloseHandle(token);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_version_built_into_an_exe() {
        // Every Windows exe carries one; a file that isn't a program has none.
        let notepad = std::path::PathBuf::from(crate::settings::windows_dir()).join("notepad.exe");
        // Windows shims its own files' version to 6.2 for a program without a compatibility manifest (the test binary), so
        // only "it has one" is checked here; RustWarden's own exe carries its real version.
        assert!(file_version(&notepad).is_some_and(|v| v.0 >= 6));
        let plain = std::env::temp_dir().join(format!("rustwarden-version-test-{}.txt", std::process::id()));
        std::fs::write(&plain, b"not a program").unwrap();
        assert_eq!(file_version(&plain), None);
        let _ = std::fs::remove_file(&plain);
        assert_eq!(own_version().0, env!("CARGO_PKG_VERSION_MAJOR").parse::<u16>().unwrap());
    }
}
