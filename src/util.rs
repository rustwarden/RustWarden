use egui::{Color32, FontId, Painter};
use std::sync::atomic::{AtomicBool, Ordering};

/// Runs reads on a worker thread and hands each result back to the UI thread, which polls for it. One runs at a
/// time; a request made meanwhile replaces any waiting one and starts when the running one lands. A worker that
/// panics comes back as one `Err`, repeated failures are not reported again until one succeeds.
pub struct Bg<T> {
    ctx: egui::Context,
    slot: std::sync::Arc<std::sync::Mutex<Option<Result<T, String>>>>,
    busy: bool,
    pending: Option<Box<dyn FnOnce() -> T + Send>>,
    failing: bool,
}

impl<T: Send + 'static> Bg<T> {
    pub fn new(ctx: egui::Context) -> Self {
        Self { ctx, slot: Default::default(), busy: false, pending: None, failing: false }
    }

    pub fn request(&mut self, f: impl FnOnce() -> T + Send + 'static) {
        if self.busy {
            self.pending = Some(Box::new(f));
        } else {
            self.spawn(Box::new(f));
        }
    }

    pub fn poll(&mut self) -> Option<Result<T, String>> {
        let done = self.slot.lock().unwrap_or_else(|e| e.into_inner()).take()?;
        self.busy = false;
        if let Some(f) = self.pending.take() {
            self.spawn(f);
        }
        match &done {
            Ok(_) => self.failing = false,
            Err(_) if self.failing => return None,
            Err(_) => self.failing = true,
        }
        Some(done)
    }

    fn spawn(&mut self, f: Box<dyn FnOnce() -> T + Send>) {
        self.busy = true;
        let (slot, ctx) = (self.slot.clone(), self.ctx.clone());
        std::thread::spawn(move || {
            let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| "the data worker stopped unexpectedly".to_owned());
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(done);
            ctx.request_repaint();
        });
    }
}

/// Like `Memo`, but the value is read on a worker: `get` returns at once with what it has for `key` (`None` until the
/// first read for that key lands) and asks for a refresh when it is older than `ttl`.
pub struct AsyncMemo<K, V> {
    bg: Bg<(K, V)>,
    have: Option<(std::time::Instant, K, V)>,
    asked: Option<(std::time::Instant, K)>,
    /// A failed read, for the caller to show.
    pub error: Option<String>,
}

impl<K: PartialEq + Clone + Send + 'static, V: Send + 'static> AsyncMemo<K, V> {
    pub fn new(ctx: egui::Context) -> Self {
        Self { bg: Bg::new(ctx), have: None, asked: None, error: None }
    }

    pub fn get(&mut self, key: K, ttl: std::time::Duration, f: impl FnOnce() -> V + Send + 'static) -> Option<&V> {
        match self.bg.poll() {
            Some(Ok((k, v))) => self.have = Some((std::time::Instant::now(), k, v)),
            Some(Err(e)) => self.error = Some(e),
            None => {}
        }
        let fresh = self.have.as_ref().is_some_and(|(at, k, _)| *k == key && at.elapsed() < ttl);
        let asked = self.asked.as_ref().is_some_and(|(at, k)| *k == key && at.elapsed() < ttl);
        if !fresh && !asked {
            self.asked = Some((std::time::Instant::now(), key.clone()));
            let k = key.clone();
            self.bg.request(move || (k, f()));
        }
        self.have.as_ref().filter(|(_, k, _)| *k == key).map(|(_, _, v)| v)
    }
}

/// A value recomputed at most once per `ttl`, or when `key` changes, so UI code that runs every frame can
/// ask the backend (often a database query) without paying for it each time.
pub struct Memo<K, V>(Option<(std::time::Instant, K, V)>);

impl<K, V> Default for Memo<K, V> {
    fn default() -> Self {
        Self(None)
    }
}

impl<K: PartialEq, V> Memo<K, V> {
    pub fn get(&mut self, key: K, ttl: std::time::Duration, f: impl FnOnce() -> V) -> &V {
        if !self.0.as_ref().is_some_and(|(at, k, _)| *k == key && at.elapsed() < ttl) {
            self.0 = Some((std::time::Instant::now(), key, f()));
        }
        &self.0.as_ref().expect("filled above").2
    }
}

/// "Release build" or "Debug build", with the CI run number when the build was made by one.
pub fn build_label() -> String {
    let kind = if cfg!(debug_assertions) { "Debug" } else { "Release" };
    match option_env!("GITHUB_RUN_NUMBER") {
        Some(n) => format!("{kind} build #{n}"),
        None => format!("{kind} build"),
    }
}

const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
const BIT_UNITS: [&str; 5] = ["b", "Kb", "Mb", "Gb", "Tb"];

/// Show sizes and rates in bits (network convention, powers of 1000) instead of bytes.
static BITS: AtomicBool = AtomicBool::new(false);

pub fn set_bits(on: bool) {
    BITS.store(on, Ordering::Relaxed);
}

fn scale(bytes: f64) -> (f64, &'static str) {
    scale_in(bytes, BITS.load(Ordering::Relaxed))
}

fn scale_in(bytes: f64, bits: bool) -> (f64, &'static str) {
    let (mut v, base, units) = if bits { (bytes.max(0.0) * 8.0, 1000.0, &BIT_UNITS) } else { (bytes.max(0.0), 1024.0, &UNITS) };
    let mut i = 0;
    // 999.5 and up would print as "1000", so it moves to the next unit.
    while v >= 999.5 && i < units.len() - 1 {
        v /= base;
        i += 1;
    }
    (v, units[i])
}

/// `s` as the inside of a JSON string.
pub fn json_escape(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// "101.4 KB", "175 B".
pub fn fmt_bytes(bytes: f64) -> String {
    let (v, unit) = scale(bytes);
    if v < 1000.0 && unit.len() == 1 { format!("{} {unit}", v.round()) } else { format!("{v:.1} {unit}") }
}

/// Like [`fmt_bytes`], but always in bytes: memory and disk aren't network traffic, so the bits setting doesn't apply.
pub fn fmt_size(bytes: f64) -> String {
    let (v, unit) = scale_in(bytes, false);
    if unit.len() == 1 { format!("{} {unit}", v.round()) } else { format!("{v:.1} {unit}") }
}

/// "21 KB/s", "0 B/s".
pub fn fmt_rate(bytes_per_sec: f64) -> String {
    let (v, unit) = scale(bytes_per_sec);
    // One decimal below 10 in the larger units, so 1.5 MB/s doesn't read as 1 or 2.
    if v < 10.0 && unit.len() > 1 { format!("{v:.1} {unit}/s") } else { format!("{} {unit}/s", v.round()) }
}

/// Minute of day to "6:26 PM".
pub fn fmt_clock(minute_of_day: f32) -> String {
    fmt_clock_secs((minute_of_day * 60.0).round() as i64, false)
}

/// Second of day to "9:16:00 PM" (or "9:16 PM").
pub fn fmt_clock_secs(secs: i64, with_secs: bool) -> String {
    let secs = secs.rem_euclid(86_400);
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    let (h12, ampm) = match h {
        0 => (12, "AM"),
        1..=11 => (h, "AM"),
        12 => (12, "PM"),
        _ => (h - 12, "PM"),
    };
    if with_secs { format!("{h12}:{m:02}:{s:02} {ampm}") } else { format!("{h12}:{m:02} {ampm}") }
}

/// Shortens `text` with an ellipsis so it fits in `max_width`.
pub fn fit_text(painter: &Painter, text: &str, font: &FontId, max_width: f32) -> String {
    let width = |s: &str| painter.layout_no_wrap(s.to_owned(), font.clone(), Color32::WHITE).size().x;
    if width(text) <= max_width {
        return text.to_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    for n in (0..chars.len()).rev() {
        let candidate: String = chars[..n].iter().collect::<String>().trim_end().to_owned() + "…";
        if width(&candidate) <= max_width {
            return candidate;
        }
    }
    "…".to_owned()
}

/// Deterministic noise in 0..1 for placeholder data.
pub fn noise(seed: u64) -> f32 {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0x632B_E59B_D9B4_E019);
    x ^= x >> 31;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 29;
    (x % 10_000) as f32 / 10_000.0
}

/// The 256x256 RGBA application icon (`assets/icon.png`), used for the window and tray.
pub fn app_icon_rgba() -> (Vec<u8>, u32, u32) {
    decode_png(include_bytes!("../assets/icon.png"))
}

/// The 64x64 RGBA icon drawn for small sizes (bold rim, flat colours), used for the tray and the header logo.
pub fn small_icon_rgba() -> (Vec<u8>, u32, u32) {
    decode_png(include_bytes!("../assets/icon-small.png"))
}

fn decode_png(bytes: &[u8]) -> (Vec<u8>, u32, u32) {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().expect("icon png header");
    let mut buf = vec![0; reader.output_buffer_size().expect("icon png size")];
    let info = reader.next_frame(&mut buf).expect("icon png data");
    buf.truncate(info.buffer_size());
    (buf, info.width, info.height)
}

/// Area-averages a square RGBA image down to `size` x `size` (alpha-weighted, so edges don't halo).
pub fn downscale_rgba(src: &[u8], w: u32, h: u32, size: u32) -> Vec<u8> {
    let (sx, sy) = (w as f32 / size as f32, h as f32 / size as f32);
    let mut out = vec![0u8; (size * size * 4) as usize];
    for oy in 0..size {
        for ox in 0..size {
            let (x0, x1, y0, y1) = (ox as f32 * sx, (ox + 1) as f32 * sx, oy as f32 * sy, (oy + 1) as f32 * sy);
            let (mut acc, mut weight) = ([0f32; 4], 0f32);
            for y in y0.floor() as u32..(y1.ceil() as u32).min(h) {
                let wy = (y1.min(y as f32 + 1.0) - y0.max(y as f32)).max(0.0);
                for x in x0.floor() as u32..(x1.ceil() as u32).min(w) {
                    let wt = wy * (x1.min(x as f32 + 1.0) - x0.max(x as f32)).max(0.0);
                    let i = ((y * w + x) * 4) as usize;
                    let a = src[i + 3] as f32 / 255.0;
                    for c in 0..3 {
                        acc[c] += src[i + c] as f32 * a * wt;
                    }
                    acc[3] += a * wt;
                    weight += wt;
                }
            }
            let o = ((oy * size + ox) * 4) as usize;
            if acc[3] > 0.0 {
                for c in 0..3 {
                    out[o + c] = (acc[c] / acc[3]).round() as u8;
                }
                out[o + 3] = (acc[3] / weight * 255.0).round() as u8;
            }
        }
    }
    out
}

/// Paints an anti-aliased dot with a white rim in the top-right corner of a square RGBA image.
pub fn paint_dot(img: &mut [u8], size: u32, color: [u8; 3]) {
    let s = size as f32;
    let (r, cx, cy) = (s * 0.3, s - s * 0.3, s * 0.3);
    for y in 0..size {
        for x in 0..size {
            let d = ((x as f32 + 0.5 - cx).powi(2) + (y as f32 + 0.5 - cy).powi(2)).sqrt();
            let rim = (r + 0.5 - d).clamp(0.0, 1.0);
            if rim == 0.0 {
                continue;
            }
            let fill = (r - s * 0.07 + 0.5 - d).clamp(0.0, 1.0);
            let i = ((y * size + x) * 4) as usize;
            for c in 0..3 {
                let top = 255.0 * (1.0 - fill) + color[c] as f32 * fill;
                img[i + c] = (img[i + c] as f32 * (1.0 - rim) + top * rim) as u8;
            }
            img[i + 3] = img[i + 3].max((rim * 255.0) as u8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait<T: Send + 'static>(bg: &mut Bg<T>) -> Result<T, String> {
        for _ in 0..500 {
            if let Some(r) = bg.poll() {
                return r;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("worker never finished");
    }

    #[test]
    fn bg_runs_the_latest_waiting_request_and_reports_a_panic_once() {
        let mut bg = Bg::<i32>::new(egui::Context::default());
        let (open, gate) = std::sync::mpsc::channel::<()>();
        bg.request(move || {
            gate.recv().ok();
            1
        });
        // Both arrive while the first runs: only the last one is kept.
        bg.request(|| 2);
        bg.request(|| 3);
        open.send(()).unwrap();
        assert_eq!(wait(&mut bg), Ok(1));
        assert_eq!(wait(&mut bg), Ok(3));
        bg.request(|| panic!("boom"));
        assert!(wait(&mut bg).is_err());
        bg.request(|| panic!("boom again"));
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(bg.poll().is_none(), "a repeated failure is not reported again");
        bg.request(|| 4);
        assert_eq!(wait(&mut bg), Ok(4));
    }

    #[test]
    fn async_memo_answers_none_until_the_read_lands_then_keeps_it() {
        let mut m = AsyncMemo::<i32, i32>::new(egui::Context::default());
        let ttl = std::time::Duration::from_secs(60);
        assert!(m.get(1, ttl, || 10).is_none());
        let mut got = None;
        for _ in 0..500 {
            if let Some(v) = m.get(1, ttl, || unreachable!("asked again within the ttl")) {
                got = Some(*v);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(got, Some(10));
        // Another key has nothing yet, and doesn't show the old key's value.
        assert!(m.get(2, ttl, || 20).is_none());
    }

    #[test]
    fn memo_recomputes_on_key_change_or_expiry() {
        let (mut m, mut calls) = (Memo::<i32, i32>::default(), 0);
        let ttl = std::time::Duration::from_secs(60);
        for key in [1, 1, 2, 2] {
            m.get(key, ttl, || {
                calls += 1;
                key
            });
        }
        assert_eq!(calls, 2);
        m.get(2, std::time::Duration::ZERO, || {
            calls += 1;
            2
        });
        assert_eq!(calls, 3);
    }

    #[test]
    fn units_roll_over_before_printing_four_digits() {
        assert_eq!(fmt_bytes(500.0), "500 B");
        assert_eq!(fmt_bytes(1010.0), "1.0 KB");
        assert_eq!(fmt_bytes(1023.0 * 1024.0), "1.0 MB");
        assert_eq!(fmt_rate(1.5 * 1024.0 * 1024.0), "1.5 MB/s");
        assert_eq!(fmt_rate(999.7), "1.0 KB/s");
        assert_eq!(fmt_rate(0.0), "0 B/s");
        assert_eq!(fmt_size(1.5 * 1024.0 * 1024.0 * 1024.0), "1.5 GB");
    }
}
