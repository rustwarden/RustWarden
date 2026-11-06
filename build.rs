//! Embeds the application icon into the Windows executable, and draws the About picture:
//! a PNG of the code knowledge graph (assets/about_graph.json).

use std::collections::HashMap;
use std::path::PathBuf;

const W: usize = 1600;
const H: usize = 1200;
const BG: [f32; 3] = [15.0, 15.0, 26.0];
const PALETTE: [[f32; 3]; 10] = [
    [78.0, 121.0, 167.0],
    [242.0, 142.0, 43.0],
    [225.0, 87.0, 89.0],
    [118.0, 183.0, 178.0],
    [89.0, 161.0, 79.0],
    [237.0, 201.0, 72.0],
    [176.0, 122.0, 161.0],
    [255.0, 157.0, 167.0],
    [156.0, 117.0, 95.0],
    [186.0, 176.0, 172.0],
];

/// The first-party plugins embedded in the exe (plugin id, crate name). Keep in step with `src/plugins/wasm/bundled.rs`.
const PLUGINS: &[(&str, &str)] = &[
    ("discord", "plugin-discord"),
    ("slack", "plugin-slack"),
    ("pushbullet", "plugin-pushbullet"),
    ("ntfy", "plugin-ntfy"),
    ("gotify", "plugin-gotify"),
    ("webhook", "plugin-webhook"),
    ("ping", "plugin-ping"),
    ("ha", "plugin-ha"),
    ("virustotal", "plugin-virustotal"),
    ("opnsense", "plugin-opnsense"),
    ("speedtest", "plugin-speedtest"),
    ("thinkbroadband", "plugin-thinkbroadband"),
    ("prometheus", "plugin-prometheus"),
    ("upnp", "plugin-upnp"),
    ("cloudflare", "plugin-cloudflare"),
];

/// Builds the plugins for wasm32-wasip1 into OUT_DIR/plugins/<id>.wasm so `bundled.rs` can embed them.
/// If that can't be done (no wasm target installed, say) empty files are written and a warning is printed:
/// RustWarden still builds, it just ships without those plugins.
fn bundle_plugins() {
    println!("cargo:rerun-if-changed=plugins");
    println!("cargo:rerun-if-changed=plugin-sdk");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out.join("plugins");
    std::fs::create_dir_all(&dest).expect("create plugins dir");
    let target_dir = out.join("plugin-target");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = std::process::Command::new(cargo);
    cmd.args(["build", "--release", "--locked", "--target", "wasm32-wasip1"]).current_dir(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    for (_, krate) in PLUGINS {
        cmd.args(["-p", krate]);
    }
    cmd.env("CARGO_TARGET_DIR", &target_dir)
        // Small plugins: they are embedded in the exe.
        .env("CARGO_PROFILE_RELEASE_OPT_LEVEL", "s")
        .env("CARGO_PROFILE_RELEASE_LTO", "true")
        .env("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1")
        .env("CARGO_PROFILE_RELEASE_STRIP", "true")
        // The release workflow sets flags meant for the Windows exe (+crt-static); wasm must not get them.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTC_WRAPPER");
    let built = cmd.status().map(|s| s.success()).unwrap_or(false);
    if !built {
        println!("cargo:warning=the first-party plugins were not built (rustup target add wasm32-wasip1); this build ships without them");
    }
    for (id, krate) in PLUGINS {
        let from = target_dir.join("wasm32-wasip1").join("release").join(format!("{}.wasm", id));
        let bytes = if built { std::fs::read(&from).unwrap_or_default() } else { Vec::new() };
        let _ = krate;
        std::fs::write(dest.join(format!("{id}.wasm")), bytes).expect("write plugin");
    }
}

fn main() {
    bundle_plugins();
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=assets/about_graph.json");
    println!("cargo:rerun-if-changed=build.rs");
    // The exe's version resource comes from the package version, so a bump must rebuild it.
    println!("cargo:rerun-if-changed=Cargo.toml");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("about_graph.png");
    let pixels = graph_pixels().unwrap_or_else(|| BG.iter().map(|&c| c as u8).cycle().take(W * H * 3).collect());
    let file = std::io::BufWriter::new(std::fs::File::create(out).expect("create about_graph.png"));
    let mut enc = png::Encoder::new(file, W as u32, H as u32);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header().and_then(|mut w| w.write_image_data(&pixels)).expect("write about_graph.png");

    #[cfg(windows)]
    winresource::WindowsResource::new().set_icon("assets/icon.ico").compile().expect("embed icon");
}

/// Lays the graph out with a force simulation and rasterises it; `None` when there is no graph file.
fn graph_pixels() -> Option<Vec<u8>> {
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read("assets/about_graph.json").ok()?).ok()?;
    let nodes = json["nodes"].as_array()?;
    let n = nodes.len();
    let index: HashMap<&str, usize> = nodes.iter().enumerate().filter_map(|(i, v)| Some((v["id"].as_str()?, i))).collect();
    let comm: Vec<usize> = nodes.iter().map(|v| v["community"].as_u64().unwrap_or(0) as usize).collect();
    let edges: Vec<(usize, usize)> = json["links"].as_array()?.iter().filter_map(|e| Some((*index.get(e["source"].as_str()?)?, *index.get(e["target"].as_str()?)?))).filter(|(a, b)| a != b).collect();
    let mut deg = vec![0usize; n];
    for &(a, b) in &edges {
        deg[a] += 1;
        deg[b] += 1;
    }

    // Fruchterman-Reingold, seeded so the same graph always draws the same picture.
    let mut seed = 0x2545F4914F6CDD1Du64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed >> 11) as f32 / (1u64 << 53) as f32
    };
    let side = 1000.0f32;
    let mut pos: Vec<[f32; 2]> = (0..n).map(|_| [rnd() * side, rnd() * side]).collect();
    let k = (side * side / n.max(1) as f32).sqrt();
    let iterations = 220;
    for it in 0..iterations {
        let temp = side * 0.1 * (1.0 - it as f32 / iterations as f32) + 1.0;
        let mut disp = vec![[0f32; 2]; n];
        for i in 0..n {
            for j in i + 1..n {
                let (dx, dy) = (pos[i][0] - pos[j][0], pos[i][1] - pos[j][1]);
                let d2 = (dx * dx + dy * dy).max(0.01);
                let f = k * k / d2;
                disp[i][0] += dx * f;
                disp[i][1] += dy * f;
                disp[j][0] -= dx * f;
                disp[j][1] -= dy * f;
            }
        }
        for &(a, b) in &edges {
            let (dx, dy) = (pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]);
            let d = (dx * dx + dy * dy).sqrt().max(0.01);
            let f = d / k;
            disp[a][0] -= dx * f;
            disp[a][1] -= dy * f;
            disp[b][0] += dx * f;
            disp[b][1] += dy * f;
        }
        // Gravity keeps unconnected pieces from being flung off the page.
        for i in 0..n {
            disp[i][0] -= (pos[i][0] - side / 2.0) * 3.0;
            disp[i][1] -= (pos[i][1] - side / 2.0) * 3.0;
        }
        for i in 0..n {
            let d = (disp[i][0] * disp[i][0] + disp[i][1] * disp[i][1]).sqrt().max(0.01);
            let step = d.min(temp);
            pos[i][0] += disp[i][0] / d * step;
            pos[i][1] += disp[i][1] / d * step;
        }
    }

    // Fit to the picture, keeping the aspect ratio.
    // The 1st to 99th percentile sets the frame so a few strays can't shrink the picture.
    let (mut lo, mut hi) = ([0f32; 2], [0f32; 2]);
    for a in 0..2 {
        let mut v: Vec<f32> = pos.iter().map(|p| p[a]).collect();
        v.sort_by(|x, y| x.total_cmp(y));
        lo[a] = v[n / 100];
        hi[a] = v[n - 1 - n / 100];
    }
    for p in &mut pos {
        for a in 0..2 {
            p[a] = p[a].clamp(lo[a], hi[a]);
        }
    }
    let margin = 30.0;
    let scale = ((W as f32 - 2.0 * margin) / (hi[0] - lo[0]).max(1.0)).min((H as f32 - 2.0 * margin) / (hi[1] - lo[1]).max(1.0));
    let px: Vec<[f32; 2]> = pos
        .iter()
        .map(|p| {
            [
                margin + (p[0] - lo[0]) * scale + ((W as f32 - 2.0 * margin) - (hi[0] - lo[0]) * scale) / 2.0,
                margin + (p[1] - lo[1]) * scale + ((H as f32 - 2.0 * margin) - (hi[1] - lo[1]) * scale) / 2.0,
            ]
        })
        .collect();

    let mut img: Vec<f32> = BG.iter().copied().cycle().take(W * H * 3).collect();
    let color = |i: usize| PALETTE[comm[i] % PALETTE.len()];
    let mut blend = |x: i32, y: i32, c: [f32; 3], a: f32| {
        if x >= 0 && y >= 0 && (x as usize) < W && (y as usize) < H {
            let o = (y as usize * W + x as usize) * 3;
            for ch in 0..3 {
                img[o + ch] += (c[ch] - img[o + ch]) * a;
            }
        }
    };
    for &(a, b) in &edges {
        let (steps, c) = (((px[a][0] - px[b][0]).abs().max((px[a][1] - px[b][1]).abs()).ceil() as i32).max(1), color(a));
        for s in 0..=steps {
            let t = s as f32 / steps as f32;
            blend((px[a][0] + (px[b][0] - px[a][0]) * t) as i32, (px[a][1] + (px[b][1] - px[a][1]) * t) as i32, c, 0.22);
        }
    }
    for i in 0..n {
        let r = 1.2 + (deg[i] as f32).sqrt() * 0.25;
        let (x0, y0) = (px[i][0], px[i][1]);
        for y in (y0 - r - 1.0) as i32..=(y0 + r + 1.0) as i32 {
            for x in (x0 - r - 1.0) as i32..=(x0 + r + 1.0) as i32 {
                let d = ((x as f32 + 0.5 - x0).powi(2) + (y as f32 + 0.5 - y0).powi(2)).sqrt();
                blend(x, y, color(i), (r + 0.5 - d).clamp(0.0, 1.0));
            }
        }
    }
    Some(img.iter().map(|&v| v.clamp(0.0, 255.0) as u8).collect())
}
