//! Loads a `.wasm` file into a sandbox and calls it. No WASI is linked (imports other than
//! `env.host` become traps), memory is capped, and every call runs on a fuel budget so a plugin
//! that loops forever is stopped.

use super::host::{Host, restrict_db};
use plugin_sdk::{API_VERSION, Call, HostCall, HostReply, Manifest, Reply};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::OnceLock;
use wasmtime::{Caller, Config, Engine, Linker, Memory, Module, Store, TypedFunc};

/// Instructions a single call may run. shortcut: one budget for all calls, make it per-call if a plugin legitimately needs more.
const FUEL: u64 = 1_000_000_000;

fn engine() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| {
        let mut c = Config::new();
        c.consume_fuel(true);
        Engine::new(&c).expect("wasmtime engine")
    })
}

pub struct Plugin {
    store: Store<Host>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    call: TypedFunc<(i32, i32), i64>,
    pub manifest: Manifest,
    /// SHA-256 of the file, shown at approval and compared on every load.
    pub hash: String,
}

/// Ids become file names, config file names and table prefixes, so they are kept plain: `a-b-2`, never `-a`, `a--b` or `A_b`.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 40 && !id.starts_with('-') && !id.ends_with('-') && !id.contains("--") && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub fn hash_of(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn pack(ptr: i32, len: usize) -> i64 {
    ((ptr as u32 as u64) << 32 | len as u32 as u64) as i64
}

fn unpack(v: i64) -> (usize, usize) {
    ((v as u64 >> 32) as usize, (v as u64 & 0xffff_ffff) as usize)
}

fn slice(mem: &[u8], ptr: usize, len: usize) -> Result<&[u8], String> {
    ptr.checked_add(len).and_then(|end| mem.get(ptr..end)).ok_or_else(|| "the plugin gave an out-of-range buffer".to_owned())
}

/// Copies `data` into the plugin's memory through its `alloc` and returns the address.
fn put(store: &mut impl wasmtime::AsContextMut, memory: Memory, alloc: &TypedFunc<i32, i32>, data: &[u8]) -> Result<i32, String> {
    let ptr = alloc.call(&mut *store, data.len() as i32).map_err(|e| e.root_cause().to_string())?;
    memory.write(&mut *store, ptr as u32 as usize, data).map_err(|e| e.to_string())?;
    Ok(ptr)
}

impl Plugin {
    /// Instantiates the module and reads its manifest. The returned plugin has no database and no
    /// permissions until [`Plugin::bind`].
    pub fn load(bytes: &[u8]) -> Result<Self, String> {
        let module = Module::new(engine(), bytes).map_err(|e| e.to_string())?;
        let mut linker = Linker::new(engine());
        linker.func_wrap("env", "host", host_import).map_err(|e| e.to_string())?;
        // A hash map needs a random seed; that is all of WASI a plugin gets, and it is no more than random numbers.
        linker.func_wrap("wasi_snapshot_preview1", "random_get", random_get).map_err(|e| e.to_string())?;
        // Anything else the module imports (WASI and the like) becomes a trap, so it can't reach the system.
        linker.define_unknown_imports_as_traps(&module).map_err(|e| e.to_string())?;
        let mut store = Store::new(engine(), Host::blank());
        store.limiter(|h| &mut h.limits);
        store.set_fuel(FUEL).map_err(|e| e.to_string())?;
        let inst = linker.instantiate(&mut store, &module).map_err(|e| e.to_string())?;
        let memory = inst.get_memory(&mut store, "memory").ok_or("the plugin exports no memory")?;
        let alloc = inst.get_typed_func(&mut store, "alloc").map_err(|e| e.to_string())?;
        let call = inst.get_typed_func(&mut store, "call").map_err(|e| e.to_string())?;
        let mut p = Self { store, memory, alloc, call, manifest: Manifest::default(), hash: hash_of(bytes) };
        match p.call(&Call::Manifest)? {
            Reply::Manifest(m) => p.manifest = m,
            _ => return Err("the plugin did not return a manifest".into()),
        }
        if p.manifest.api_version != API_VERSION {
            return Err(format!("the plugin targets plugin API {}, this RustWarden speaks {API_VERSION}", p.manifest.api_version));
        }
        if !valid_id(&p.manifest.id) {
            return Err("the plugin id must be lowercase letters and digits, with single dashes between them".into());
        }
        Ok(p)
    }

    /// Gives the plugin its database (restricted to `p_<id>_*`), its approved permissions and its manifest's hosts.
    pub fn bind(&mut self, mut db: Connection, granted: BTreeSet<String>, demo: bool) -> Result<(), String> {
        // If the restriction can't be set the plugin gets no database at all.
        restrict_db(&mut db, &self.manifest.id).map_err(|e| e.to_string())?;
        let h = self.store.data_mut();
        h.id = self.manifest.id.clone();
        h.http_hosts = self.manifest.http_hosts.clone();
        h.granted = granted.into_iter().filter(|g| self.manifest.permissions.contains(g)).collect();
        h.db = Some(db);
        h.demo = demo;
        h.allow_insecure = self.manifest.allow_insecure_tls;
        Ok(())
    }

    pub fn host(&mut self) -> &mut Host {
        self.store.data_mut()
    }

    /// One call into the plugin on a fresh fuel budget; a trap (including running out of fuel) is an error.
    pub fn call(&mut self, call: &Call) -> Result<Reply, String> {
        self.store.set_fuel(FUEL).map_err(|e| e.root_cause().to_string())?;
        let json = serde_json::to_vec(call).map_err(|e| e.to_string())?;
        let ptr = put(&mut self.store, self.memory, &self.alloc, &json)?;
        let (ptr, len) = unpack(self.call.call(&mut self.store, (ptr, json.len() as i32)).map_err(|e| e.root_cause().to_string())?);
        let reply = slice(self.memory.data(&self.store), ptr, len)?;
        match serde_json::from_slice(reply).map_err(|e| format!("bad reply from the plugin: {e}"))? {
            Reply::Err(e) => Err(e),
            r => Ok(r),
        }
    }
}

/// WASI's `random_get`: fills the buffer with random bytes (for hash map seeds; not for cryptography). 0 is success.
fn random_get(mut c: Caller<'_, Host>, ptr: i32, len: i32) -> i32 {
    use std::hash::{BuildHasher, RandomState};
    const EINVAL: i32 = 28;
    let len = len as u32 as usize;
    let Some(memory) = c.get_export("memory").and_then(|e| e.into_memory()) else { return EINVAL };
    if len > 1 << 20 {
        return EINVAL;
    }
    let seed = RandomState::new();
    let mut buf = vec![0u8; len];
    for (i, chunk) in buf.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&seed.hash_one(i as u64).to_le_bytes()[..chunk.len()]);
    }
    if memory.write(&mut c, ptr as u32 as usize, &buf).is_ok() { 0 } else { EINVAL }
}

/// `env.host`: reads a `HostCall` from the plugin's memory, runs it and writes the `HostReply` back.
fn host_import(mut c: Caller<'_, Host>, ptr: i32, len: i32) -> wasmtime::Result<i64> {
    let memory = c.get_export("memory").and_then(|e| e.into_memory()).ok_or_else(|| wasmtime::Error::msg("no memory"))?;
    let alloc = c.get_export("alloc").and_then(|e| e.into_func()).ok_or_else(|| wasmtime::Error::msg("no alloc"))?.typed::<i32, i32>(&c)?;
    let raw = slice(memory.data(&c), ptr as u32 as usize, len as u32 as usize).map_err(wasmtime::Error::msg)?.to_vec();
    let reply = match serde_json::from_slice::<HostCall>(&raw) {
        Ok(call) => c.data_mut().handle(call),
        Err(e) => HostReply::Err(format!("bad host call: {e}")),
    };
    let out = serde_json::to_vec(&reply)?;
    let ptr = put(&mut c, memory, &alloc, &out).map_err(wasmtime::Error::msg)?;
    Ok(pack(ptr, out.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plugin written in WAT: `alloc` is a bump allocator, `call` answers every call with a fixed reply
    /// and, when `body` says so, misbehaves first. The manifest reply is the same for all of them.
    fn module(body: &str) -> Vec<u8> {
        let manifest = r#"{"manifest":{"id":"t","name":"T","api_version":1,"http_hosts":["ok.example"],"permissions":["ping"]}}"#;
        let done = r#""done""#;
        let wat = format!(
            r#"(module
              (import "env" "host" (func $host (param i32 i32) (result i64)))
              (memory (export "memory") 2)
              (global $top (mut i32) (i32.const 4096))
              (data (i32.const 0) "{m}")
              (data (i32.const 1024) "{d}")
              (func (export "alloc") (param $n i32) (result i32)
                (local $p i32) (local.set $p (global.get $top))
                (global.set $top (i32.add (global.get $top) (local.get $n))) (local.get $p))
              (func (export "call") (param $p i32) (param $n i32) (result i64)
                (local $r i64)
                {body}
                ;; the Manifest call is the JSON string "manifest": 'm' is byte 1
                (if (i32.eq (i32.load8_u (i32.add (local.get $p) (i32.const 1))) (i32.const 109))
                  (then (return (i64.or (i64.shl (i64.const 0) (i64.const 32)) (i64.const {ml})))))
                (i64.or (i64.shl (i64.const 1024) (i64.const 32)) (i64.const {dl}))))"#,
            m = manifest.replace('"', "\\\""),
            d = done.replace('"', "\\\""),
            ml = manifest.len(),
            dl = done.len(),
        );
        wat.into_bytes()
    }

    fn call_tick(p: &mut Plugin) -> Result<Reply, String> {
        p.call(&Call::Tick)
    }

    #[test]
    fn loads_reads_the_manifest_and_hashes_the_file() {
        let bytes = module("");
        let p = Plugin::load(&bytes).unwrap();
        assert_eq!(p.manifest.id, "t");
        assert_eq!(p.hash, hash_of(&bytes));
        assert_ne!(hash_of(&bytes), hash_of(&module("(nop)")), "a changed file has a different hash");
    }

    #[test]
    fn an_infinite_loop_is_stopped_by_the_fuel_limit() {
        // Loops only on Tick (the request is the JSON string "tick": 't' is byte 1).
        let looping = "(if (i32.eq (i32.load8_u (i32.add (local.get $p) (i32.const 1))) (i32.const 116)) (then (loop $l (br $l))))";
        let mut p = Plugin::load(&module(looping)).unwrap();
        let err = call_tick(&mut p).unwrap_err();
        assert!(err.to_lowercase().contains("fuel") || err.contains("trap") || err.contains("wasm"), "{err}");
        // The plugin is still usable afterwards.
        assert!(p.call(&Call::Manifest).is_ok());
    }

    #[test]
    fn host_calls_are_checked_by_the_host() {
        let mut p = Plugin::load(&module("")).unwrap();
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::from(["ping".to_owned(), "bogus".to_owned()]), false).unwrap();
        assert_eq!(p.host().granted, BTreeSet::from(["ping".to_owned()]), "only permissions the manifest declares can be granted");
        assert!(matches!(p.host().handle(HostCall::HttpRequest { url: "https://evil.example/".into(), headers: vec![], body: None }), HostReply::Err(_)));
    }

    #[test]
    fn ids_are_plain() {
        for ok in ["ping", "a-b", "x2", "a-b-c"] {
            assert!(valid_id(ok), "{ok}");
        }
        for bad in ["", "-a", "a-", "a--b", "A", "a_b", "a b", "../x", "a.b"] {
            assert!(!valid_id(bad), "{bad}");
        }
    }

    /// Runs the real example plugin built by `cargo build -p example-hello --release --target wasm32-wasip1`.
    /// Skipped (with a note) when that file hasn't been built.
    #[test]
    fn the_example_plugin_works_through_the_real_sdk() {
        use plugin_sdk::{Event, UiTree};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/wasm32-wasip1/release/example_hello.wasm");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipped: {} is not built", path.display());
            return;
        };
        let mut p = Plugin::load(&bytes).unwrap();
        assert_eq!((p.manifest.id.as_str(), p.manifest.tabs.len()), ("example-hello", 1));
        p.bind(Connection::open_in_memory().unwrap(), BTreeSet::new(), false).unwrap();
        let shows = |p: &mut Plugin| match p.call(&Call::RenderTab { tab: "hello".into() }).unwrap() {
            Reply::Ui(UiTree::Column(c)) => c.iter().any(|w| matches!(w, UiTree::Weak(t) if t.contains("Clicked 1 times"))),
            other => panic!("unexpected page {other:?}"),
        };
        assert!(!shows(&mut p));
        p.call(&Call::Event(Event::Click { id: "click".into() })).unwrap();
        assert!(shows(&mut p));
        assert_eq!(p.host().config.get("clicks").map(String::as_str), Some("1"));
        // Many calls in a row stay inside the 64 MB memory cap: the guest frees each call's buffers.
        for _ in 0..3000 {
            p.call(&Call::RenderSettings).unwrap();
        }
    }

    /// The six notification plugins, built the same way. Nothing here posts: the addresses used are ones the
    /// plugin refuses, so no request is made.
    #[test]
    fn the_notification_plugins_load_and_keep_their_secrets() {
        use plugin_sdk::{Event, Kind, UiTree};
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/wasm32-wasip1/release");
        for id in ["discord", "slack", "pushbullet", "ntfy", "gotify", "webhook"] {
            let Ok(bytes) = std::fs::read(dir.join(format!("{id}.wasm"))) else {
                eprintln!("skipped {id}: not built");
                continue;
            };
            let mut p = Plugin::load(&bytes).unwrap();
            assert_eq!((p.manifest.id.as_str(), p.manifest.kind, p.manifest.permissions.as_slice()), (id, Kind::Notification, ["alerts.read".to_owned()].as_slice()));
            // Only the self-hosted services may reach any host; Discord and Pushbullet name theirs.
            assert_eq!(p.manifest.http_hosts.iter().any(|h| h == "*"), !matches!(id, "discord" | "pushbullet"), "{id}");
            p.bind(Connection::open_in_memory().unwrap(), BTreeSet::from(["alerts.read".to_owned()]), false).unwrap();
            let Reply::Ui(UiTree::Column(page)) = p.call(&Call::RenderSettings).unwrap() else { panic!("{id}: no page") };
            let first = page.iter().find_map(|w| if let UiTree::Password { id, .. } = w { Some(id.clone()) } else { None }).expect("a secret field");
            p.call(&Call::Event(Event::Text { id: first.clone(), value: " https://example.com/not-this-service ".into() })).unwrap();
            assert_eq!(p.host().secrets.get(&first).map(String::as_str), Some("https://example.com/not-this-service"), "{id}: trimmed and kept as a secret");
            // Unconfigured or refused addresses: the alert is dropped without a request or an error.
            assert!(matches!(p.call(&Call::Alert { important: true, title: "t".into(), text: "d".into() }), Ok(Reply::Done)), "{id}");
        }
    }

    #[test]
    fn a_wrong_api_version_is_refused() {
        let bytes = String::from_utf8(module("")).unwrap().replace("api_version\\\":1", "api_version\\\":2");
        assert!(Plugin::load(bytes.as_bytes()).err().unwrap().contains("API"));
    }
}
