//! For plugin authors: everything a plugin needs to speak the ABI. Implement [`Guest`], then call
//! `plugin_sdk::export!(MyPlugin);` once. Build with `cargo build --release --target wasm32-wasip1`.

use crate::{Call, HostCall, HostReply, Manifest, Reply};
use std::cell::{Cell, RefCell};

pub trait Guest {
    fn manifest() -> Manifest;
    /// Answers every call except `Call::Manifest`.
    fn handle(call: Call) -> Reply;
}

thread_local! {
    /// Buffers handed to the host; freed when the next top-level call begins.
    static POOL: RefCell<Vec<Box<[u8]>>> = const { RefCell::new(Vec::new()) };
    static IN_CALL: Cell<bool> = const { Cell::new(false) };
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
unsafe extern "C" {
    #[link_name = "host"]
    fn host_raw(ptr: i32, len: i32) -> i64;
}

/// Off wasm there is no host; this only lets the crate type-check on the development machine.
#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_raw(_: i32, _: i32) -> i64 {
    0
}

fn pack(ptr: usize, len: usize) -> i64 {
    ((ptr as u32 as u64) << 32 | len as u32 as u64) as i64
}

fn unpack(v: i64) -> (usize, usize) {
    ((v as u64 >> 32) as usize, (v as u64 & 0xffff_ffff) as usize)
}

fn stash(data: Vec<u8>) -> (usize, usize) {
    let b = data.into_boxed_slice();
    let at = (b.as_ptr() as usize, b.len());
    POOL.with(|p| p.borrow_mut().push(b));
    at
}

/// Used by [`export!`]; not for plugins to call.
#[doc(hidden)]
pub fn __alloc(n: i32) -> i32 {
    // Not inside a call: the host is starting a new one, so the last call's buffers are done with.
    if !IN_CALL.with(Cell::get) {
        POOL.with(|p| p.borrow_mut().clear());
    }
    stash(vec![0; n.max(0) as usize]).0 as i32
}

/// Used by [`export!`]; not for plugins to call.
#[doc(hidden)]
pub fn __call<G: Guest>(ptr: i32, len: i32) -> i64 {
    IN_CALL.with(|c| c.set(true));
    // SAFETY: the host wrote `len` bytes at `ptr`, a buffer from `__alloc`.
    let req = unsafe { std::slice::from_raw_parts(ptr as u32 as usize as *const u8, len as u32 as usize) };
    let reply = match serde_json::from_slice::<Call>(req) {
        Ok(Call::Manifest) => Reply::Manifest(G::manifest()),
        Ok(c) => G::handle(c),
        Err(e) => Reply::Err(format!("bad call: {e}")),
    };
    let (p, l) = stash(serde_json::to_vec(&reply).unwrap_or_default());
    IN_CALL.with(|c| c.set(false));
    pack(p, l)
}

/// Asks the host to do something. Prefer the typed helpers below.
pub fn host(call: &HostCall) -> HostReply {
    let json = serde_json::to_vec(call).unwrap_or_default();
    // SAFETY: the buffer outlives the call and the host only reads it.
    let (p, l) = unpack(unsafe { host_raw(json.as_ptr() as usize as i32, json.len() as i32) });
    // SAFETY: the host wrote the reply with this module's `alloc`; it stays valid until the next top-level call.
    let reply = unsafe { std::slice::from_raw_parts(p as *const u8, l) };
    serde_json::from_slice(reply).unwrap_or_else(|e| HostReply::Err(format!("bad reply from the host: {e}")))
}

fn text(r: HostReply) -> Result<String, String> {
    match r {
        HostReply::Ok(s) => Ok(s),
        HostReply::Err(e) => Err(e),
    }
}

pub fn config_get(key: &str) -> String {
    text(host(&HostCall::ConfigGet { key: key.into() })).unwrap_or_default()
}

pub fn config_set(key: &str, value: &str) {
    let _ = host(&HostCall::ConfigSet { key: key.into(), value: value.into() });
}

pub fn secret_get(key: &str) -> String {
    text(host(&HostCall::SecretGet { key: key.into() })).unwrap_or_default()
}

pub fn secret_set(key: &str, value: &str) {
    let _ = host(&HostCall::SecretSet { key: key.into(), value: value.into() });
}

pub fn db_exec(sql: &str) -> Result<(), String> {
    text(host(&HostCall::DbExec { sql: sql.into() })).map(|_| ())
}

/// Rows as a JSON array of arrays.
pub fn db_query(sql: &str) -> Result<String, String> {
    text(host(&HostCall::DbQuery { sql: sql.into() }))
}

/// Posts when `body` is given, else gets. An error is `"HTTP <status>"` for an answer of 400 or more, else what went wrong.
pub fn http_request(url: &str, headers: &[String], body: Option<&str>) -> Result<String, String> {
    text(host(&HostCall::HttpRequest { url: url.into(), headers: headers.to_vec(), body: body.map(str::to_owned) }))
}

/// The status and body of any answer, such as a 401 or 404; only a server that can't be reached is an error.
pub fn http_raw(url: &str, headers: &[String], body: Option<&str>, insecure: bool) -> Result<(u16, String), String> {
    let json = text(host(&HostCall::HttpRaw { url: url.into(), headers: headers.to_vec(), body: body.map(str::to_owned), insecure }))?;
    let v: serde_json::Value = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    Ok((v["status"].as_u64().unwrap_or(0) as u16, v["body"].as_str().unwrap_or("").to_owned()))
}

/// Needs "alerts.write".
pub fn raise_alert(kind: &str, who: &str, text: &str) {
    let _ = host(&HostCall::RaiseAlert { kind: kind.into(), who: who.into(), text: text.into() });
}

/// Needs "browser.session". Blocks until the window is closed.
pub fn browser_sign_in() -> Result<(), String> {
    text(host(&HostCall::BrowserSignIn)).map(|_| ())
}

/// Needs "browser.session". (HTTP status, body) per URL, in order.
pub fn browser_fetch(urls: &[String]) -> Result<Vec<(u16, String)>, String> {
    let json = text(host(&HostCall::BrowserFetch { urls: urls.to_vec() }))?;
    let v: Vec<serde_json::Value> = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    Ok(v.iter().map(|x| (x["status"].as_u64().unwrap_or(0) as u16, x["body"].as_str().unwrap_or("").to_owned())).collect())
}

/// Needs "browser.session".
pub fn browser_sign_out() -> Result<(), String> {
    text(host(&HostCall::BrowserSignOut)).map(|_| ())
}

/// Needs "helper.exe".
pub fn helper_ready(exe: &str, exe_sha256: &str) -> bool {
    text(host(&HostCall::HelperReady { exe: exe.into(), exe_sha256: exe_sha256.into() })).is_ok_and(|s| s == "1")
}

/// Needs "helper.exe". Blocks until the download is done.
pub fn helper_install(url: &str, zip_sha256: &str, exe: &str) -> Result<(), String> {
    text(host(&HostCall::HelperInstall { url: url.into(), zip_sha256: zip_sha256.into(), exe: exe.into() })).map(|_| ())
}

/// Needs "helper.exe". Returns at once; the output arrives as `Call::HelperLine` and `Call::HelperDone`.
pub fn helper_start(exe: &str, args: &[String], timeout_secs: u32) -> Result<(), String> {
    text(host(&HostCall::HelperStart { exe: exe.into(), args: args.to_vec(), timeout_secs })).map(|_| ())
}

/// How often this plugin wants `Call::Tick`, in milliseconds (0 = as the manifest says).
pub fn set_tick(millis: u32) {
    let _ = host(&HostCall::SetTick { millis });
}

/// True in Demo mode: make up believable data instead of measuring.
pub fn is_demo() -> bool {
    text(host(&HostCall::IsDemo)).is_ok_and(|s| s == "1")
}

/// A device the network scan found.
#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize)]
pub struct DeviceInfo {
    pub mac: String,
    pub ip: String,
    pub name: String,
}

/// Needs the "devices.annotate" permission.
pub fn devices() -> Result<Vec<DeviceInfo>, String> {
    let json = text(host(&HostCall::Devices))?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

/// One address's ping results; see [`ping_round`].
#[derive(Clone, Copy, Debug, Default, PartialEq, serde::Deserialize)]
pub struct PingResult {
    pub min: f32,
    pub avg: f32,
    pub max: f32,
    pub loss: f32,
}

/// Needs the "ping" permission.
pub fn ping_round(addrs: &[String], count: u32) -> Result<Vec<PingResult>, String> {
    let json = text(host(&HostCall::PingRound { addrs: addrs.to_vec(), count }))?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

/// Seconds since 1970.
pub fn now() -> i64 {
    text(host(&HostCall::Now)).ok().and_then(|s| s.parse().ok()).unwrap_or(0)
}

pub fn log(msg: &str) {
    let _ = host(&HostCall::Log { msg: msg.into() });
}

pub fn notify_in_app(msg: &str) {
    let _ = host(&HostCall::NotifyInApp { msg: msg.into() });
}

/// Writes the two exports RustWarden looks for.
#[macro_export]
macro_rules! export {
    ($guest:ty) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn alloc(n: i32) -> i32 {
            $crate::guest::__alloc(n)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn call(ptr: i32, len: i32) -> i64 {
            $crate::guest::__call::<$guest>(ptr, len)
        }
    };
}
