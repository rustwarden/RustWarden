//! Finds, runs and removes `.wasm` plugins. Files live in `Program Files\RustWarden\plugins`, which only
//! administrators can write, so nothing the user's own account can drop there is ever loaded.
//!
//! A plugin runs only while the user has approved this exact file (its SHA-256) and switched it on.
//! Each running plugin has one worker thread that owns the module: the UI sends it jobs and reads the
//! pages it produces, so the UI thread never waits on plugin code.

use super::host::table_prefix;
use super::loader::Plugin;
use super::ui_tree;
use crate::settings::{Mode, PluginState, Settings};
use plugin_sdk::{Call, Event, HostCall, HostReply, Manifest, Reply, UiTree};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// Page key of a plugin's settings page; tab pages use the tab id from the manifest.
pub const SETTINGS_KEY: &str = "@settings";
const MAX_FILE: u64 = 32 << 20;

pub fn plugin_dir() -> PathBuf {
    crate::settings::admin_dir().join("plugins")
}

/// Where a plugin's bytes come from.
#[derive(Clone)]
pub enum Source {
    /// A file in the plugin folder: third-party, trusted only while the user's approval matches its hash.
    File(PathBuf),
    /// Built into RustWarden itself (`bundled.rs`): trusted like the rest of the exe, runs with all it asks for.
    Bundled(&'static [u8]),
}

/// A plugin that loaded far enough to read its manifest.
#[derive(Clone)]
pub struct Found {
    pub source: Source,
    pub hash: String,
    pub manifest: Manifest,
}

impl Found {
    pub fn first_party(&self) -> bool {
        matches!(self.source, Source::Bundled(_))
    }

    pub fn path(&self) -> Option<&Path> {
        match &self.source {
            Source::File(p) => Some(p),
            Source::Bundled(_) => None,
        }
    }
}

/// What the user's settings allow this plugin to do, if anything. A built-in plugin needs only its switch on;
/// a file needs the approval of exactly this file (a changed file asks again).
fn trusted(want: &BTreeMap<String, PluginState>, f: &Found) -> Option<PluginState> {
    let w = want.get(&f.manifest.id).filter(|w| w.enabled && !w.removed)?;
    if f.first_party() {
        return Some(PluginState { granted: f.manifest.permissions.clone(), ..w.clone() });
    }
    (w.approved_hash == f.hash).then(|| w.clone())
}

#[derive(Default)]
struct Pages {
    trees: BTreeMap<String, UiTree>,
    /// Pages asked for and not drawn yet.
    pending: BTreeSet<String>,
    notes: Vec<String>,
    error: String,
    /// Page jobs sent by the UI and not finished yet, so the page can say the plugin is working.
    busy: usize,
}

enum Job {
    Render(String),
    Event(String, Event),
    Alert {
        important: bool,
        title: String,
        text: String,
    },
    /// A call from a host thread (the helper program's output).
    Call(Call),
    /// Sent when the plugin is switched off. The worker holds a sender of its own (for the helper's output), so
    /// closing the channel alone would never end it.
    Stop,
}

struct Active {
    tx: Sender<Job>,
    pages: Arc<Mutex<Pages>>,
    manifest: Manifest,
    hash: String,
    granted: Vec<String>,
    /// The plugin's own settings as of its last job, for host code that is the plugin's other half (Scanner marks, VirusTotal lookups).
    saved: Arc<Mutex<Saved>>,
}

impl Drop for Active {
    fn drop(&mut self) {
        let _ = self.tx.send(Job::Stop);
    }
}

struct State {
    found: Vec<Found>,
    bad: Vec<(PathBuf, String)>,
    scanning: bool,
    scanned: bool,
    active: BTreeMap<String, Active>,
    /// The saved settings' plugin decisions, and whether Demo mode is on.
    want: BTreeMap<String, PluginState>,
    demo: bool,
    ctx: Option<egui::Context>,
    message: String,
    /// Config laid over a plugin's saved settings when it starts (screenshot runs; nothing is written).
    presets: BTreeMap<String, BTreeMap<String, String>>,
    /// Workers still alive per plugin id (one that was switched off may take a moment to end).
    workers: BTreeMap<String, usize>,
}

static STATE: Mutex<State> = Mutex::new(State {
    found: Vec::new(),
    bad: Vec::new(),
    scanning: false,
    scanned: false,
    active: BTreeMap::new(),
    want: BTreeMap::new(),
    demo: false,
    ctx: None,
    message: String::new(),
    presets: BTreeMap::new(),
    workers: BTreeMap::new(),
});

fn st() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn repaint(ctx: &Option<egui::Context>) {
    if let Some(c) = ctx {
        c.request_repaint();
    }
}

/// Called at start and whenever settings are applied: remembers what the user allowed and starts or stops plugins to match.
pub fn apply(s: &Settings, ctx: &egui::Context) {
    let first = {
        let mut g = st();
        g.want = s.plugins.clone();
        g.demo = s.mode == Mode::Demo;
        g.ctx = Some(ctx.clone());
        !std::mem::replace(&mut g.scanned, true)
    };
    if first { scan() } else { reconcile() }
}

/// Starts or stops plugins to match switches the user just flipped in the open Settings dialog, before Save (Cancel
/// goes back through `apply` with the saved settings).
pub fn preview(plugins: &BTreeMap<String, PluginState>) {
    st().want = plugins.clone();
    reconcile();
}

/// Reads the plugin folder again (in the background).
pub fn scan() {
    {
        let mut g = st();
        if g.scanning {
            return;
        }
        g.scanning = true;
    }
    std::thread::spawn(|| {
        let (found, bad) = scan_dir(&plugin_dir());
        let ctx = {
            let mut g = st();
            g.found = found;
            g.bad = bad;
            g.scanning = false;
            g.ctx.clone()
        };
        reconcile();
        repaint(&ctx);
    });
}

fn scan_dir(dir: &Path) -> (Vec<Found>, Vec<(PathBuf, String)>) {
    let (mut found, mut bad): (Vec<Found>, Vec<(PathBuf, String)>) = (super::bundled::found(), Vec::new());
    let Ok(rd) = std::fs::read_dir(dir) else { return (found, bad) };
    let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("wasm"))).collect();
    files.sort();
    for path in files {
        match inspect(&path) {
            Ok(f) if found.iter().any(|o| o.manifest.id == f.manifest.id) => bad.push((path, format!("the plugin id \"{}\" is already taken (built-in plugins keep their ids)", f.manifest.id))),
            Ok(f) => found.push(f),
            Err(e) => bad.push((path, e)),
        }
    }
    (found, bad)
}

/// Loads the file once to read its manifest and hash. The module runs with no database, no network and no permissions.
fn inspect(path: &Path) -> Result<Found, String> {
    if std::fs::metadata(path).map_err(|e| e.to_string())?.len() > MAX_FILE {
        return Err("the file is too large for a plugin".into());
    }
    let p = Plugin::load(&std::fs::read(path).map_err(|e| e.to_string())?)?;
    Ok(Found { source: Source::File(path.to_owned()), hash: p.hash.clone(), manifest: p.manifest.clone() })
}

/// Makes the running set match the approved, switched-on plugins found on disk.
fn reconcile() {
    let mut starts = Vec::new();
    let (demo, ctx) = {
        let mut g = st();
        let (want, found) = (g.want.clone(), g.found.clone());
        // Dropping an `Active` closes its channel, which ends the worker and unloads the module.
        g.active.retain(|id, a| found.iter().find(|f| f.manifest.id == *id && f.hash == a.hash).and_then(|f| trusted(&want, f)).is_some_and(|w| w.granted == a.granted));
        for f in found {
            if g.active.contains_key(&f.manifest.id) {
                continue;
            }
            let Some(state) = trusted(&want, &f) else { continue };
            let (tx, rx) = mpsc::channel();
            let tx_worker = tx.clone();
            let pages = Arc::new(Mutex::new(Pages::default()));
            let config: Arc<Mutex<Saved>> = Arc::default();
            g.active.insert(f.manifest.id.clone(), Active { tx, pages: pages.clone(), manifest: f.manifest.clone(), hash: f.hash.clone(), granted: state.granted.clone(), saved: config.clone() });
            starts.push((f, state, (tx_worker, rx), pages, config));
        }
        (g.demo, g.ctx.clone())
    };
    for (f, state, channel, pages, config) in starts {
        let ctx = ctx.clone();
        let id = f.manifest.id.clone();
        *st().workers.entry(id.clone()).or_default() += 1;
        std::thread::spawn(move || {
            run(f, state, demo, ctx, channel, pages, config);
            if let Some(n) = st().workers.get_mut(&id) {
                *n -= 1;
            }
        });
    }
    repaint(&ctx);
}

/// The worker: loads the file again (checking it is still the approved one), then serves jobs and ticks until the UI lets go of it.
fn run(f: Found, state: PluginState, demo: bool, ctx: Option<egui::Context>, (tx, rx): (Sender<Job>, Receiver<Job>), pages: Arc<Mutex<Pages>>, view: Arc<Mutex<Saved>>) {
    let fail = |e: String| {
        lock(&pages).error = e;
        repaint(&ctx);
    };
    let bytes = match &f.source {
        Source::File(path) => match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => return fail(e.to_string()),
        },
        Source::Bundled(b) => b.to_vec(),
    };
    let mut p = match Plugin::load(&bytes) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    if p.hash != f.hash {
        return fail("the file changed after it was approved; review it again".into());
    }
    // Demo mode keeps the plugin's tables in memory (shared with the page that draws them), so it never touches the real database.
    let db = if demo { open_demo_db(&f.manifest.id) } else { Connection::open(crate::live::db_path()) };
    let db = match db {
        Ok(d) => d,
        Err(e) => return fail(e.to_string()),
    };
    let _ = db.busy_timeout(Duration::from_secs(5));
    if let Err(e) = p.bind(db, state.granted.iter().cloned().collect(), demo) {
        return fail(e);
    }
    let mut saved = load_saved(&f.manifest.id);
    if let Some(preset) = st().presets.get(&f.manifest.id) {
        saved.config.extend(preset.clone());
    }
    p.host().config = saved.config.clone();
    p.host().secrets = saved.secrets.clone();
    // The helper program runs on host threads and reports back through the plugin's own job queue.
    let wake = ctx.clone();
    p.host().notify = Some(Arc::new(move |call| {
        let _ = tx.send(Job::Call(call));
        repaint(&wake);
    }));
    let sql = p.manifest.schema.clone();
    if !sql.is_empty()
        && let HostReply::Err(e) = p.host().handle(HostCall::DbExec { sql })
    {
        return fail(format!("the plugin's tables could not be created: {e}"));
    }

    *lock(&view) = Saved { config: p.host().config.clone(), secrets: p.host().secrets.clone() };
    let mut last = saved;
    let base_tick = (p.manifest.tick_secs != 0).then(|| Duration::from_secs(u64::from(p.manifest.tick_secs)));
    // A plugin with background work does its first round at once, not a whole interval after it starts.
    let mut first = base_tick.is_some();
    loop {
        // The plugin may ask for its own rhythm (a speed test animating its dial) and later go back to the manifest's.
        let tick = p.host().tick_ms.map(|ms| Duration::from_millis(u64::from(ms))).or(base_tick);
        let job = if std::mem::take(&mut first) {
            None
        } else if let Some(tick) = tick {
            match rx.recv_timeout(tick) {
                Ok(j) => Some(j),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match rx.recv() {
                Ok(j) => Some(j),
                Err(_) => break,
            }
        };
        if matches!(job, Some(Job::Stop)) {
            break;
        }
        let counted = matches!(job, Some(Job::Render(_) | Job::Event(..)));
        let result: Result<Vec<(String, UiTree)>, String> = match job {
            Some(Job::Render(key)) => render(&mut p, &key).map(|t| vec![(key, t)]),
            Some(Job::Event(key, ev)) => p.call(&Call::Event(ev)).and_then(|_| render(&mut p, &key)).map(|t| vec![(key, t)]),
            Some(Job::Alert { important, title, text }) => p.call(&Call::Alert { important, title, text }).map(|_| Vec::new()),
            Some(Job::Call(c)) => p.call(&c).and_then(|_| redraw(&mut p, &pages)),
            Some(Job::Stop) => Ok(Vec::new()),
            // A tick redraws the pages on screen, so live data keeps moving.
            None => p.call(&Call::Tick).and_then(|_| redraw(&mut p, &pages)),
        };
        let notes = std::mem::take(&mut p.host().notes);
        {
            let mut g = lock(&pages);
            if counted {
                g.busy = g.busy.saturating_sub(1);
            }
            match result {
                Ok(list) => {
                    g.error.clear();
                    for (k, t) in list {
                        g.pending.remove(&k);
                        g.trees.insert(k, t);
                    }
                }
                // A page that failed to draw stays pending, so it isn't asked for again every frame.
                Err(e) => g.error = e,
            }
            g.notes.extend(notes);
            let over = g.notes.len().saturating_sub(20);
            g.notes.drain(..over);
        }
        let now = Saved { config: p.host().config.clone(), secrets: p.host().secrets.clone() };
        if now != last {
            *lock(&view) = now.clone();
            if let Err(e) = save_saved(&f.manifest.id, &now) {
                lock(&pages).error = e;
            }
            last = now;
        }
        repaint(&ctx);
    }
}

/// The plugin's in-memory database in Demo mode. Named and shared, so the page that draws its charts can read it too.
fn open_demo_db(id: &str) -> rusqlite::Result<Connection> {
    use rusqlite::OpenFlags;
    Connection::open_with_flags(format!("file:rwplug_{id}?mode=memory&cache=shared"), OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_URI)
}

/// One read-only connection per plugin for drawing its charts, limited to the plugin's own tables like its own connection.
static READERS: Mutex<BTreeMap<String, Connection>> = Mutex::new(BTreeMap::new());

/// Runs `f` on the plugin's read-only connection (made on first use), which can reach only the plugin's own tables.
fn with_reader<T>(id: &str, demo: bool, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
    let mut readers = lock(&READERS);
    let key = format!("{id}:{demo}");
    if !readers.contains_key(&key) {
        let mut conn = if demo { open_demo_db(id)? } else { Connection::open_with_flags(crate::live::db_path(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)? };
        super::host::restrict_db(&mut conn, id)?;
        readers.insert(key.clone(), conn);
    }
    f(&readers[&key])
}

/// Runs a chart query a plugin declared (`?1` the chart, `?2` the first second wanted) and reads (ts, min, avg, max, loss).
pub fn query_samples(id: &str, demo: bool, sql: &str, line: u32, since: i64) -> rusqlite::Result<Vec<crate::plugins::core::latency::Sample>> {
    use crate::plugins::core::latency::Sample;
    with_reader(id, demo, |conn| {
        let mut stmt = conn.prepare_cached(sql)?;
        let rows = stmt.query_map(rusqlite::params![line, since], |r| {
            Ok(Sample { ts: r.get(0)?, min: r.get::<_, f64>(1)? as f32, avg: r.get::<_, f64>(2)? as f32, max: r.get::<_, f64>(3)? as f32, loss: r.get::<_, f64>(4)? as f32 })
        })?;
        rows.collect()
    })
}

/// Runs the query of a Speedtest page (`?1` the first second wanted) and reads the finished tests.
pub fn query_speed(id: &str, demo: bool, sql: &str, since: i64) -> rusqlite::Result<Vec<crate::ui::speed::SpeedResult>> {
    use crate::ui::speed::SpeedResult;
    with_reader(id, demo, |conn| {
        let mut stmt = conn.prepare_cached(sql)?;
        let rows = stmt.query_map(rusqlite::params![since], |r| {
            Ok(SpeedResult {
                ts: r.get(0)?,
                ping_ms: r.get::<_, f64>(1)? as f32,
                jitter_ms: r.get::<_, f64>(2)? as f32,
                down_mbps: r.get::<_, f64>(3)? as f32,
                up_mbps: r.get::<_, f64>(4)? as f32,
                loss: r.get::<_, f64>(5)? as f32,
                server: r.get(6)?,
                isp: r.get(7)?,
                url: r.get(8)?,
                server_ip: r.get(9)?,
                client_ip: r.get(10)?,
            })
        })?;
        rows.collect()
    })
}

/// A plugin's saved settings as they are now (with any preset laid over), for code outside the plugin that reads them.
pub fn saved_config(id: &str) -> BTreeMap<String, String> {
    let mut config = load_saved(id).config;
    if let Some(preset) = st().presets.get(id) {
        config.extend(preset.clone());
    }
    config
}

/// Laid over a plugin's saved settings every time it starts, without writing anything.
pub fn preset(id: &str, config: BTreeMap<String, String>) {
    st().presets.insert(id.to_owned(), config);
}

/// Draws every page the UI has asked for again.
fn redraw(p: &mut Plugin, pages: &Arc<Mutex<Pages>>) -> Result<Vec<(String, UiTree)>, String> {
    let keys: Vec<String> = lock(pages).trees.keys().cloned().collect();
    keys.into_iter().map(|k| render(p, &k).map(|t| (k, t))).collect()
}

fn render(p: &mut Plugin, key: &str) -> Result<UiTree, String> {
    let call = if key == SETTINGS_KEY { Call::RenderSettings } else { Call::RenderTab { tab: key.to_owned() } };
    match p.call(&call)? {
        Reply::Ui(t) => Ok(t),
        _ => Err("the plugin did not return a page".into()),
    }
}

// ---- config and secrets, one file per plugin ----

#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    config: BTreeMap<String, String>,
    #[serde(with = "secret_map")]
    secrets: BTreeMap<String, String>,
}

/// Secret values are written encrypted for this Windows user, like every other token in the settings.
mod secret_map {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    struct Sealed<'a>(&'a str);
    impl Serialize for Sealed<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            crate::settings::secret::serialize(self.0, s)
        }
    }

    struct Open(String);
    impl<'de> Deserialize<'de> for Open {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            crate::settings::secret::deserialize(d).map(Open)
        }
    }

    pub fn serialize<S: Serializer>(m: &BTreeMap<String, String>, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(m.iter().map(|(k, v)| (k, Sealed(v))))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<String, String>, D::Error> {
        Ok(BTreeMap::<String, Open>::deserialize(d)?.into_iter().map(|(k, v)| (k, v.0)).collect())
    }
}

fn saved_path(id: &str) -> PathBuf {
    crate::settings::config_dir().join("plugins").join(format!("{id}.toml"))
}

/// Writes a plugin's first saved settings, for the move from the old typed settings. Does nothing if it already has some.
pub fn seed(id: &str, config: BTreeMap<String, String>, secrets: BTreeMap<String, String>) {
    if saved_path(id).exists() {
        return;
    }
    if let Err(e) = save_saved(id, &Saved { config, secrets }) {
        crate::applog::line("plugins.log", &format!("couldn't carry the old settings into {id}: {e}"));
    }
}

fn load_saved(id: &str) -> Saved {
    std::fs::read_to_string(saved_path(id)).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
}

fn save_saved(id: &str, s: &Saved) -> Result<(), String> {
    let path = saved_path(id);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, toml::to_string_pretty(s).map_err(|e| e.to_string())?).map_err(|e| format!("couldn't save the plugin's settings: {e}"))
}

// ---- what the interface asks ----

pub struct View {
    pub found: Vec<Found>,
    pub bad: Vec<(PathBuf, String)>,
    pub scanning: bool,
    pub message: String,
}

pub fn view() -> View {
    let g = st();
    View { found: g.found.clone(), bad: g.bad.clone(), scanning: g.scanning, message: g.message.clone() }
}

/// Whether any notification plugin is switched on (and running), so "send to notification plugins" has somewhere to go.
pub fn any_notification_plugin() -> bool {
    st().active.values().any(|a| a.manifest.kind == plugin_sdk::Kind::Notification)
}

pub fn running(id: &str) -> bool {
    st().active.contains_key(id)
}

pub struct PluginTab {
    /// The plugin and the tab id inside it.
    pub id: String,
    pub tab: String,
    pub title: &'static str,
}

/// Interned so the sub-tab strip, which wants `&'static str`, can show manifest titles; bounded by the titles plugins declare.
pub fn intern(s: &str) -> &'static str {
    static T: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());
    let mut g = lock(&T);
    if let Some(x) = g.get(s) {
        return x;
    }
    let x: &'static str = Box::leak(s.to_owned().into_boxed_str());
    g.insert(x);
    x
}

/// The tabs of the running plugins, in a stable order (by plugin id, then manifest order).
pub fn tabs() -> Vec<PluginTab> {
    let g = st();
    g.active.iter().flat_map(|(id, a)| a.manifest.tabs.iter().map(move |t| PluginTab { id: id.clone(), tab: t.id.clone(), title: intern(&t.title.chars().take(40).collect::<String>()) })).collect()
}

/// Messages plugins sent with `notify_in_app` since the last call, as (plugin id, text).
pub fn take_notes() -> Vec<(String, String)> {
    let g = st();
    g.active.iter().flat_map(|(id, a)| std::mem::take(&mut lock(&a.pages).notes).into_iter().map(move |n| (id.clone(), n))).collect()
}

/// Alerts kept back while the internet is down, as (when, important, title, text).
static HELD: Mutex<Vec<(std::time::Instant, bool, String, String)>> = Mutex::new(Vec::new());
/// At most this many are kept; the oldest go first.
const HELD_MAX: usize = 50;
static WATCH: std::sync::Once = std::sync::Once::new();
static OFFLINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Hands an alert to every running plugin the user gave "alerts.read". Returns at once; delivery is the plugin's own business.
/// While the internet is down the alert is held and handed over, marked as delayed, once it is back.
pub fn broadcast_alert(important: bool, title: &str, text: &str) {
    WATCH.call_once(|| {
        std::thread::spawn(|| {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let offline = crate::sys::netinfo::internet_connected() == Some(false);
                OFFLINE.store(offline, std::sync::atomic::Ordering::Relaxed);
                if !offline {
                    release_held();
                }
            }
        });
    });
    if OFFLINE.load(std::sync::atomic::Ordering::Relaxed) {
        let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
        if held.len() >= HELD_MAX {
            held.remove(0);
        }
        held.push((std::time::Instant::now(), important, title.to_owned(), text.to_owned()));
        return;
    }
    deliver_alert(important, title, text);
}

/// Sends what was held, oldest first, each with how late it is.
fn release_held() {
    let held = std::mem::take(&mut *HELD.lock().unwrap_or_else(|e| e.into_inner()));
    for (when, important, title, text) in held {
        deliver_alert(
            important,
            &title,
            &format!(
                "{text}
(Delayed {}: the internet was down.)",
                late(when.elapsed().as_secs())
            ),
        );
    }
}

fn late(secs: u64) -> String {
    match secs {
        0..=89 => format!("{secs} s"),
        90..=5399 => format!("{} min", (secs + 30) / 60),
        _ => format!("{} h", (secs + 1800) / 3600),
    }
}

fn deliver_alert(important: bool, title: &str, text: &str) {
    let g = st();
    for a in g.active.values() {
        let allowed = |p: &String| p == "alerts.read";
        if a.granted.iter().any(allowed) && a.manifest.permissions.iter().any(allowed) {
            let _ = a.tx.send(Job::Alert { important, title: title.to_owned(), text: text.to_owned() });
        }
    }
}

#[cfg(test)]
mod hold_tests {
    #[test]
    fn says_how_late() {
        assert_eq!(super::late(30), "30 s");
        assert_eq!(super::late(600), "10 min");
        assert_eq!(super::late(7200), "2 h");
    }
}

/// The running plugin that names and marks scanned devices (permission "devices.annotate"), and what the Scanner needs of it.
pub struct Annotator {
    pub id: String,
    pub name: String,
    pub icon: Arc<Vec<u8>>,
    pub config: BTreeMap<String, String>,
}

fn annotates(a: &Active) -> bool {
    let has = |p: &String| p == "devices.annotate";
    a.granted.iter().any(has) && a.manifest.permissions.iter().any(has)
}

pub fn annotator_ids() -> Vec<String> {
    st().active.iter().filter(|(_, a)| annotates(a)).map(|(id, _)| id.clone()).collect()
}

pub fn annotator() -> Option<Annotator> {
    let g = st();
    let (id, a) = g.active.iter().find(|(_, a)| annotates(a))?;
    Some(Annotator { id: id.clone(), name: a.manifest.name.clone(), icon: Arc::new(a.manifest.icon.clone()), config: lock(&a.saved).config.clone() })
}

/// A running plugin's own settings, as of its last job.
pub fn plugin_config(id: &str) -> Option<BTreeMap<String, String>> {
    st().active.get(id).map(|a| lock(&a.saved).config.clone())
}

/// Tells the user something on a running plugin's behalf (a finished export), as `notify_in_app` does.
pub fn note(plugin: &str, msg: String) {
    if let Some(a) = st().active.get(plugin) {
        lock(&a.pages).notes.push(msg);
    }
}

/// Where a running plugin's tab sits among the plugin tabs (`Tab::Plugin(index)`).
pub fn tab_index(plugin: &str) -> Option<usize> {
    tabs().iter().position(|t| t.id == plugin)
}

/// A running plugin's settings and secrets, for the host code that does its work on a permission the user granted
/// (the plugin must hold `permission`, both in its manifest and from the user). `None` while it isn't running.
pub fn granted_settings(id: &str, permission: &str) -> Option<(BTreeMap<String, String>, BTreeMap<String, String>)> {
    let g = st();
    let a = g.active.get(id)?;
    let has = |p: &String| p == permission;
    if !(a.granted.iter().any(has) && a.manifest.permissions.iter().any(has)) {
        return None;
    }
    let saved = lock(&a.saved);
    Some((saved.config.clone(), saved.secrets.clone()))
}

/// Draws one page of a running plugin (a tab or `SETTINGS_KEY`), asking for it on first sight.
pub fn page(ui: &mut egui::Ui, id: &str, key: &str, backend: Option<Arc<dyn crate::data::Backend>>) {
    let (found, demo) = {
        let g = st();
        (g.active.get(id).map(|a| (a.tx.clone(), a.pages.clone())), g.demo)
    };
    let Some((tx, pages)) = found else {
        ui.weak("This plugin isn't running.");
        return;
    };
    let mut g = lock(&pages);
    if !g.error.is_empty() {
        ui.colored_label(crate::theme::red(), g.error.clone());
    }
    if g.busy > 0 {
        ui.weak("Working…");
    }
    if let Some(tree) = g.trees.get_mut(key) {
        let env = ui_tree::Env { plugin: id, demo, key: format!("{id}/{key}"), backend };
        // A tab page sits in from the window's edge like the built-in tabs; the chart pages draw to the edge themselves.
        let inset = key != SETTINGS_KEY && !matches!(tree, UiTree::Speedtest(_) | UiTree::LatencyChart(_));
        let events = if inset { egui::Frame::NONE.inner_margin(egui::Margin::symmetric(12, 0)).show(ui, |ui| ui_tree::show(ui, tree, &env)).inner } else { ui_tree::show(ui, tree, &env) };
        drop(g);
        lock(&pages).busy += events.len();
        for e in events {
            let _ = tx.send(Job::Event(key.to_owned(), e));
        }
    } else {
        if g.pending.insert(key.to_owned()) {
            g.busy += 1;
            let _ = tx.send(Job::Render(key.to_owned()));
        }
        ui.weak("Loading…");
    }
}

/// Copies a `.wasm` file into the plugin folder (it must load as a plugin). Needs administrator rights.
pub fn install(src: &str) {
    let src = PathBuf::from(src.trim().trim_matches('"'));
    std::thread::spawn(move || {
        let result = inspect(&src).and_then(|f| {
            let dir = plugin_dir();
            let need_admin = |e: std::io::Error| format!("couldn't write to {}: {e}. Installing a plugin needs administrator rights.", dir.display());
            std::fs::create_dir_all(&dir).map_err(need_admin)?;
            std::fs::copy(&src, dir.join(format!("{}.wasm", f.manifest.id))).map(|_| ()).map_err(need_admin)
        });
        st().message = match result {
            Ok(()) => "Installed. Review and approve it in the list, then press Save.".into(),
            Err(e) => e,
        };
        scan();
    });
}

/// Deletes a plugin file; with `data`, also its saved settings and tables.
pub fn remove(path: PathBuf, id: Option<String>, data: bool) {
    if let Some(id) = &id {
        st().active.remove(id);
    }
    std::thread::spawn(move || {
        let mut message = match std::fs::remove_file(&path) {
            Ok(()) => String::new(),
            Err(e) => format!("couldn't delete {}: {e}. Removing a plugin needs administrator rights.", path.display()),
        };
        if let (true, Some(id)) = (data, id) {
            wait_stopped(&id);
            let _ = std::fs::remove_file(saved_path(&id));
            drop_tables(&id);
        }
        if message.is_empty() {
            message = "Removed.".into();
        }
        st().message = message;
        scan();
    });
}

/// Waits until the plugin's worker has ended, so nothing is writing to the tables about to be dropped.
fn wait_stopped(id: &str) {
    // shortcut: gives up after 30 s (a worker stuck in a long browser or download call) and carries on.
    for _ in 0..300 {
        if st().workers.get(id).is_none_or(|n| *n == 0) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Stops a plugin and deletes its saved settings, secrets and tables (the plugin itself stays installed). It waits for the
/// plugin's worker to end first, so nothing is writing to the tables being dropped.
pub fn erase(id: String) {
    st().active.remove(&id);
    std::thread::spawn(move || {
        wait_stopped(&id);
        let _ = std::fs::remove_file(saved_path(&id));
        drop_tables(&id);
        repaint(&st().ctx);
    });
}

/// Drops every table the plugin owned in the real database.
fn drop_tables(id: &str) {
    let Ok(c) = Connection::open(crate::live::db_path()) else { return };
    let prefix = table_prefix(id);
    let names: Vec<String> = c.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").and_then(|mut s| s.query_map([], |r| r.get(0))?.collect()).unwrap_or_default();
    for n in names.into_iter().filter(|n| n.starts_with(&prefix)) {
        let _ = c.execute_batch(&format!("DROP TABLE \"{}\"", n.replace('"', "\"\"")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_written_and_read_back() {
        // Secrets go through DPAPI, which needs a Windows user session; plain config always round-trips.
        let s = Saved { config: BTreeMap::from([("a".to_owned(), "1".to_owned())]), secrets: BTreeMap::new() };
        let text = toml::to_string_pretty(&s).unwrap();
        assert!(toml::from_str::<Saved>(&text).unwrap() == s);
    }

    #[test]
    fn a_plugins_secrets_are_encrypted_in_its_file_and_read_back() {
        let s = Saved {
            config: BTreeMap::from([("url".to_owned(), "https://fw".to_owned())]),
            secrets: BTreeMap::from([("key".to_owned(), "opnkey123".to_owned()), ("secret".to_owned(), "opnsecret456".to_owned())]),
        };
        let text = toml::to_string_pretty(&s).unwrap();
        assert!(!text.contains("opnkey123") && !text.contains("opnsecret456") && text.contains("dpapi:"), "{text}");
        assert!(text.contains("https://fw"), "plain settings stay readable");
        assert!(toml::from_str::<Saved>(&text).unwrap() == s);
    }

    #[test]
    fn titles_are_interned_once() {
        assert!(std::ptr::eq(intern("Same title"), intern("Same title")));
    }

    #[test]
    fn a_changed_hash_is_not_approved() {
        let state = PluginState { enabled: true, approved_hash: "abc".into(), ..PluginState::default() };
        let want = BTreeMap::from([("p".to_owned(), state)]);
        let found = |id: &str, hash: &str, source: Source| Found { source, hash: hash.into(), manifest: Manifest { id: id.into(), permissions: vec!["alerts.read".into()], ..Manifest::default() } };
        let file = Source::File(PathBuf::from("p.wasm"));
        assert!(trusted(&want, &found("p", "abc", file.clone())).is_some());
        assert!(trusted(&want, &found("p", "abd", file.clone())).is_none(), "a changed file asks again");
        assert!(trusted(&want, &found("other", "abc", file)).is_none());
        // A built-in plugin needs only its switch, gets everything it asks for, and is not tied to a hash.
        let granted = trusted(&want, &found("p", "anything", Source::Bundled(b""))).unwrap().granted;
        assert_eq!(granted, vec!["alerts.read".to_owned()]);
        let off = BTreeMap::from([("p".to_owned(), PluginState { enabled: false, ..PluginState::default() })]);
        assert!(trusted(&off, &found("p", "x", Source::Bundled(b""))).is_none());
        let gone = BTreeMap::from([("p".to_owned(), PluginState { enabled: true, removed: true, ..PluginState::default() })]);
        assert!(trusted(&gone, &found("p", "x", Source::Bundled(b""))).is_none());
    }
}
