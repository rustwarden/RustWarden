//! Starts a program with the user's normal rights while RustWarden itself runs elevated.
//!
//! The service hands out an administrator window without a prompt, so everything that window starts would also be an
//! administrator: curl on an address from a feed, a downloaded speedtest or cloudflared, the browser helper. None of
//! them need that, and a flaw in any of them would otherwise be a way to the administrator rights. The token here is
//! a copy of the desktop shell's (explorer.exe), which is the user's ordinary medium-integrity token, handed to the program through
//! the secondary logon service. If Windows refuses that, the program is started
//! as before rather than not at all, and the reason is logged.
//!
//! `std::process::Command` can't take a token, so this has its own small `Child` with the parts the callers use.

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Read};
use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
use std::os::windows::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Output};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Security::{
    DuplicateTokenEx, GetLengthSid, GetTokenInformation, SECURITY_ATTRIBUTES, SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER, TokenPrimary, TokenUser,
};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows::Win32::System::Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_PROCESS_LOGON_FLAGS, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, CreateProcessWithTokenW, GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcess, OpenProcessToken,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};
use windows::core::{PCWSTR, PWSTR, w};

/// Which of the program's standard streams are pipes to us; the others go nowhere.
#[derive(Clone, Copy, Debug, Default)]
pub struct Pipes {
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
}

impl Pipes {
    pub const NONE: Pipes = Pipes { stdin: false, stdout: false, stderr: false };
    /// Output and errors read, nothing written.
    pub const OUT: Pipes = Pipes { stdin: false, stdout: true, stderr: true };
    /// Everything piped.
    pub const ALL: Pipes = Pipes { stdin: true, stdout: true, stderr: true };
}

/// A running program. Shaped like `std::process::Child` for the calls RustWarden makes.
pub struct Child {
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
    /// Started with the limited token (false: with this process's own rights).
    #[cfg_attr(not(test), allow(dead_code))]
    pub limited: bool,
    process: OwnedHandle,
    pid: u32,
}

fn raw(h: &OwnedHandle) -> HANDLE {
    use std::os::windows::io::AsRawHandle;
    HANDLE(h.as_raw_handle())
}

impl Child {
    pub fn id(&self) -> u32 {
        self.pid
    }

    pub fn kill(&mut self) -> io::Result<()> {
        unsafe { TerminateProcess(raw(&self.process), 1) }.map_err(io::Error::other)
    }

    fn exit_code(&self) -> io::Result<ExitStatus> {
        let mut code = 0u32;
        unsafe { GetExitCodeProcess(raw(&self.process), &mut code) }.map_err(io::Error::other)?;
        Ok(ExitStatus::from_raw(code))
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match unsafe { WaitForSingleObject(raw(&self.process), 0) } {
            WAIT_OBJECT_0 => self.exit_code().map(Some),
            WAIT_TIMEOUT => Ok(None),
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.stdin.take();
        if unsafe { WaitForSingleObject(raw(&self.process), INFINITE) } != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        self.exit_code()
    }

    /// Waits for it to end, reading what it wrote. Errors are read on a thread of their own so neither pipe can fill up and stall it.
    pub fn wait_with_output(mut self) -> io::Result<Output> {
        self.stdin.take();
        let stderr = self.stderr.take().map(|mut e| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = e.read_to_end(&mut buf);
                buf
            })
        });
        let mut stdout = Vec::new();
        if let Some(mut o) = self.stdout.take() {
            let _ = o.read_to_end(&mut stdout);
        }
        let stderr = stderr.map(|t| t.join().unwrap_or_default()).unwrap_or_default();
        Ok(Output { status: self.wait()?, stdout, stderr })
    }
}

/// One argument as the Windows command line wants it (the rules `CommandLineToArgvW` reads back).
fn quote(arg: &str, out: &mut String) {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut slashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => slashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', slashes));
                out.push(c);
                slashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
}

fn command_line(cmd: &Command) -> Vec<u16> {
    let mut line = String::new();
    quote(&cmd.get_program().to_string_lossy(), &mut line);
    for a in cmd.get_args() {
        line.push(' ');
        quote(&a.to_string_lossy(), &mut line);
    }
    line.encode_utf16().chain(std::iter::once(0)).collect()
}

/// This process's environment with the command's changes applied, as the double-NUL block `CreateProcess` takes; `None` when
/// the command changes nothing, so the program just inherits.
fn environment(cmd: &Command) -> Option<Vec<u16>> {
    cmd.get_envs().next()?;
    let mut vars: std::collections::BTreeMap<String, (String, String)> =
        std::env::vars_os().map(|(k, v)| (k.to_string_lossy().to_uppercase(), (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()))).collect();
    for (k, v) in cmd.get_envs() {
        let name = k.to_string_lossy().into_owned();
        match v {
            Some(v) => vars.insert(name.to_uppercase(), (name, v.to_string_lossy().into_owned())),
            None => vars.remove(&name.to_uppercase()),
        };
    }
    let mut block: Vec<u16> = Vec::new();
    for (name, value) in vars.values() {
        block.extend(format!("{name}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    Some(block)
}

fn inheritable() -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: std::ptr::null_mut(), bInheritHandle: true.into() }
}

fn owned(h: HANDLE) -> OwnedHandle {
    // SAFETY: the handle was just made by Windows and nothing else owns it.
    unsafe { OwnedHandle::from_raw_handle(h.0 as RawHandle) }
}

/// (our end, the program's end). Only the program's end can be inherited.
fn pipe(we_read: bool) -> io::Result<(OwnedHandle, OwnedHandle)> {
    let (mut r, mut wr) = (HANDLE::default(), HANDLE::default());
    unsafe { CreatePipe(&mut r, &mut wr, Some(&inheritable()), 0) }.map_err(io::Error::other)?;
    let (r, wr) = (owned(r), owned(wr));
    let (ours, theirs) = if we_read { (r, wr) } else { (wr, r) };
    unsafe { SetHandleInformation(raw(&ours), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }.map_err(io::Error::other)?;
    Ok((ours, theirs))
}

/// The null device, for a stream that isn't piped.
fn null() -> io::Result<OwnedHandle> {
    let h = unsafe { CreateFileW(w!("NUL"), GENERIC_READ.0 | GENERIC_WRITE.0, FILE_SHARE_READ | FILE_SHARE_WRITE, Some(&inheritable()), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None) }
        .map_err(io::Error::other)?;
    Ok(owned(h))
}

/// The user of a token, as the bytes of its SID.
fn user_sid(token: HANDLE) -> Option<Vec<u8>> {
    unsafe {
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len).ok()?;
        let user = std::ptr::read_unaligned(buf.as_ptr().cast::<TOKEN_USER>());
        let sid = user.User.Sid;
        Some(std::slice::from_raw_parts(sid.0.cast::<u8>(), GetLengthSid(sid) as usize).to_vec())
    }
}

/// A copy of the desktop shell's token: the same user, as an ordinary (unelevated) start would have it. A token cut down from
/// this window's own can't be used: its logon session isn't the one the desktop and window station let in, so the program
/// dies in start-up (0xC0000142).
fn shell_token() -> Result<OwnedHandle, String> {
    unsafe {
        let shell = GetShellWindow();
        let mut pid = 0u32;
        if shell.0.is_null() || GetWindowThreadProcessId(shell, Some(&mut pid)) == 0 {
            return Err("there is no desktop shell".into());
        }
        let process = owned(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| format!("open the desktop shell: {e}"))?);
        let mut theirs = HANDLE::default();
        OpenProcessToken(raw(&process), TOKEN_DUPLICATE | TOKEN_QUERY, &mut theirs).map_err(|e| format!("open the shell's token: {e}"))?;
        let theirs = owned(theirs);
        let mut mine = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut mine).map_err(|e| format!("open this window's token: {e}"))?;
        let mine = owned(mine);
        // Elevated as another account (a UAC prompt with other credentials): the shell's user is not ours, so don't borrow it.
        if user_sid(raw(&theirs)) != user_sid(raw(&mine)) {
            return Err("the desktop shell runs as another user".into());
        }
        let mut dup = HANDLE::default();
        DuplicateTokenEx(raw(&theirs), TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, &mut dup).map_err(|e| format!("copy the shell's token: {e}"))?;
        Ok(owned(dup))
    }
}

/// The folder to start in: the command's, else (for the secondary logon service, which has no folder of its own) this process's.
fn dir_ptr_or(set: PCWSTR, here: Option<&Vec<u16>>) -> PCWSTR {
    if set.is_null() { here.map_or(PCWSTR::null(), |h| PCWSTR(h.as_ptr())) } else { set }
}

/// The secondary logon service takes a command line of 1024 characters at most (counting the end), so a longer one can't be started
/// with the shell's token: callers send long input on stdin or in a file instead.
const MAX_LINE: usize = 1024;

/// Starts `cmd` (its program, arguments, environment changes and folder; its stream settings are not used).
/// `window` lets the program show one. Elevated, the program gets the desktop shell's token (see [`shell_token`]), and runs elevated only if
/// Windows won't give it that.
pub fn spawn(cmd: &Command, pipes: Pipes, window: bool) -> io::Result<Child> {
    spawn_with(cmd, pipes, window, super::is_elevated())
}

/// [`spawn`], with the shell's token asked for whatever this process runs as.
fn spawn_with(cmd: &Command, pipes: Pipes, window: bool, limit: bool) -> io::Result<Child> {
    let program: Vec<u16> = cmd.get_program().to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
    let mut line = command_line(cmd);
    let env = environment(cmd);
    let dir: Option<Vec<u16>> = cmd.get_current_dir().map(|d| d.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect());

    // Our ends of the pipes, and the program's ends which we drop once it has started.
    let (mut stdin, mut stdout, mut stderr) = (None, None, None);
    let mut theirs = Vec::new();
    let mut slot = |piped: bool, we_read: bool, ours: &mut Option<OwnedHandle>| -> io::Result<HANDLE> {
        let end = if piped {
            let (o, t) = pipe(we_read)?;
            *ours = Some(o);
            t
        } else {
            null()?
        };
        let h = raw(&end);
        theirs.push(end);
        Ok(h)
    };
    let hin = slot(pipes.stdin, false, &mut stdin)?;
    let hout = slot(pipes.stdout, true, &mut stdout)?;
    let herr = slot(pipes.stderr, true, &mut stderr)?;

    let startup = STARTUPINFOW { cb: size_of::<STARTUPINFOW>() as u32, dwFlags: STARTF_USESTDHANDLES, hStdInput: hin, hStdOutput: hout, hStdError: herr, ..Default::default() };
    let flags = PROCESS_CREATION_FLAGS(CREATE_UNICODE_ENVIRONMENT.0 | if window { 0 } else { CREATE_NO_WINDOW.0 });
    let env_ptr = env.as_ref().map(|e| e.as_ptr().cast::<c_void>());
    let dir_ptr = dir.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr()));
    let mut info = PROCESS_INFORMATION::default();

    // A program that can't start must fail quietly, not put up Windows' "application error" box.
    static QUIET: std::sync::Once = std::sync::Once::new();
    QUIET.call_once(|| {
        // SAFETY: only sets this process's error mode, which its children inherit.
        unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
    });

    let token = if limit && line.len() > MAX_LINE {
        crate::applog::line("rustwarden.log", &format!("{} is started with administrator rights: its command line is too long for the secondary logon service", cmd.get_program().to_string_lossy()));
        None
    } else if limit {
        shell_token().inspect_err(|e| crate::applog::line("rustwarden.log", &format!("{} is started with administrator rights: {e}", cmd.get_program().to_string_lossy()))).ok()
    } else {
        None
    };
    let mut started = Err(io::Error::other("not tried"));
    let mut is_limited = false;
    if let Some(token) = &token {
        // The secondary logon service starts it as the shell's user and duplicates the standard handles we gave it.
        let here = std::env::current_dir().ok().map(|d| d.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>());
        let cwd = dir_ptr_or(dir_ptr, here.as_ref());
        started = unsafe { CreateProcessWithTokenW(raw(token), CREATE_PROCESS_LOGON_FLAGS(0), PCWSTR(program.as_ptr()), Some(PWSTR(line.as_mut_ptr())), flags, env_ptr, cwd, &startup, &mut info) }
            .map_err(io::Error::other);
        is_limited = started.is_ok();
        if let Err(e) = &started {
            crate::applog::line("rustwarden.log", &format!("{} is started with administrator rights: {e}", cmd.get_program().to_string_lossy()));
        }
    }
    if started.is_err() {
        started = unsafe { CreateProcessW(PCWSTR(program.as_ptr()), Some(PWSTR(line.as_mut_ptr())), None, None, true, flags, env_ptr, dir_ptr, &startup, &mut info) }.map_err(io::Error::other);
    }
    started?;
    drop(theirs);
    unsafe {
        let _ = CloseHandle(info.hThread);
    }
    let file = |h: Option<OwnedHandle>| h.map(File::from);
    Ok(Child { stdin: file(stdin), stdout: file(stdout), stderr: file(stderr), limited: is_limited, process: owned(info.hProcess), pid: info.dwProcessId })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::UI::Shell::CommandLineToArgvW;

    /// What `CommandLineToArgvW` makes of a command line we built.
    fn parsed(args: &[&str]) -> Vec<String> {
        let mut line = String::from("prog.exe");
        for a in args {
            line.push(' ');
            quote(a, &mut line);
        }
        let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
        let mut n = 0;
        let list = unsafe { CommandLineToArgvW(PCWSTR(wide.as_ptr()), &mut n) };
        let out = (0..n as usize).map(|i| unsafe { String::from_utf16_lossy(list.add(i).read().as_wide()) }).collect::<Vec<_>>();
        unsafe { LocalFree(Some(HLOCAL(list.cast()))) };
        out[1..].to_vec()
    }

    #[test]
    fn arguments_survive_the_command_line() {
        let args = ["plain", "two words", "", "say \"hi\"", r"C:\Program Files\x\", r"C:\a b\\", r#"back\\\"slash"#, "tab\there", r"{dir}\login-1\.cloudflared\cert.pem", "--token", "a=b;c"];
        assert_eq!(parsed(&args), args);
    }

    #[test]
    fn environment_changes_are_applied_and_nothing_means_inherit() {
        let mut c = Command::new("x.exe");
        assert!(environment(&c).is_none());
        c.env("RW_TEST_ONE", "1").env_remove("RW_TEST_GONE");
        let block = String::from_utf16_lossy(&environment(&c).unwrap());
        assert!(block.contains("RW_TEST_ONE=1\0") && !block.contains("RW_TEST_GONE") && block.ends_with("\0\0"));
    }

    /// Starts the real cmd.exe: its output is read, its exit code is returned, and a kill ends one that would run on.
    #[test]
    fn runs_a_program_reads_its_output_and_can_kill_it() {
        let mut c = Command::new(super::super::tool_path("cmd"));
        c.args(["/c", "echo hello & echo oops 1>&2 & exit 3"]);
        let out = spawn(&c, Pipes::OUT, false).unwrap().wait_with_output().unwrap();
        assert_eq!((out.status.code(), String::from_utf8_lossy(&out.stdout).trim().to_owned(), String::from_utf8_lossy(&out.stderr).trim().to_owned()), (Some(3), "hello".into(), "oops".into()));

        let mut c = Command::new(super::super::tool_path("cmd"));
        c.args(["/c", "ping -n 30 127.0.0.1 >nul"]);
        let mut child = spawn(&c, Pipes::NONE, false).unwrap();
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        assert!(child.wait().unwrap().code() != Some(0));
    }

    /// The shell's token starts programs that really run (curl once failed to start with 0xC0000142 under a token cut down from an
    /// elevated one), at medium integrity even when this process is elevated. Skipped where there is no desktop shell.
    #[test]
    fn the_shell_token_starts_working_programs_without_administrator_rights() {
        if shell_token().is_err() {
            eprintln!("skipped: no desktop shell");
            return;
        }
        let mut c = Command::new(super::super::tool_path("whoami"));
        c.arg("/groups");
        let child = spawn_with(&c, Pipes::OUT, false, true).unwrap();
        assert!(child.limited, "Windows refused the shell's token: see rustwarden.log");
        let out = child.wait_with_output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(out.status.success() && text.contains("Medium Mandatory Level") && !text.contains("High Mandatory Level"), "{:?} {text} {}", out.status, String::from_utf8_lossy(&out.stderr));

        let mut c = Command::new(super::super::tool_path("curl"));
        c.arg("--version");
        let out = spawn_with(&c, Pipes::OUT, false, true).unwrap().wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0), "curl did not start: {:?}", out.status);
        assert!(String::from_utf8_lossy(&out.stdout).starts_with("curl "));
    }

    /// A script far longer than the 1024-character command line limit runs from an environment variable, with its output and exit
    /// code (the GeoIP download is one); a command line that is too long still starts, with this process's rights.
    #[test]
    fn a_long_script_runs_from_the_environment_and_a_long_command_line_falls_back() {
        let mut script = String::from(
            "$ErrorActionPreference = 'Stop'
foreach ($i in 1, 2) {
    try {
        \"P $($i * 50)\"
    } catch { }
}
",
        );
        script.push_str(
            &"# padding to be far longer than a command line may be
"
            .repeat(60),
        );
        script.push_str(
            "exit 3
",
        );
        assert!(script.len() > 2000);
        let mut c = Command::new(super::super::tool_path("powershell"));
        c.args(["-NoProfile", "-NonInteractive", "-Command", "Invoke-Expression $env:RW_TEST_SCRIPT"]).env("RW_TEST_SCRIPT", &script);
        let out = spawn_with(&c, Pipes::OUT, false, true).unwrap().wait_with_output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert_eq!(out.status.code(), Some(3), "{text} {}", String::from_utf8_lossy(&out.stderr));
        assert!(text.contains("P 50") && text.contains("P 100"), "{text}");

        let mut c = Command::new(super::super::tool_path("cmd"));
        c.args(["/c", &format!("echo {}", "x".repeat(1500))]);
        let child = spawn_with(&c, Pipes::OUT, false, true).unwrap();
        assert!(!child.limited, "too long for the secondary logon service, so started as it was");
        let out = child.wait_with_output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim().len(), 1500);
    }

    /// With stdin piped, what is written reaches the program (as curl's config does).
    #[test]
    fn stdin_reaches_the_program() {
        use std::io::Write;
        let mut c = Command::new(super::super::tool_path("findstr"));
        c.arg("hello");
        let mut child = spawn(&c, Pipes::ALL, false).unwrap();
        child.stdin.take().unwrap().write_all(b"say hello\r\nno\r\n").unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "say hello");
    }
}
