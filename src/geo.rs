//! World geometry for the connections map: Natural Earth 50m admin-0 countries
//! (public domain), simplified and packed by `assets/build_world.py`.

use std::sync::OnceLock;

static WORLD_BIN: &[u8] = include_bytes!("../assets/world.bin");

/// One polygon with holes, triangulated for filling and kept as rings for outlines.
pub struct Poly {
    pub rings: Vec<Vec<[f32; 2]>>,
    pub points: Vec<[f32; 2]>,
    pub triangles: Vec<u32>,
}

pub struct Country {
    /// ISO-style 3-letter code (Natural Earth ADM0_A3), e.g. "USA".
    pub iso: String,
    pub polys: Vec<Poly>,
    /// (min lon, min lat, max lon, max lat)
    pub bbox: [f32; 4],
}

/// Web-Mercator "y" in degrees-equivalent, so x and y share one scale.
pub fn mercator_y(lat: f32) -> f32 {
    lat.clamp(-85.0, 85.0).to_radians().tan().asinh().to_degrees()
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn u32(&mut self) -> u32 {
        let (head, rest) = self.0.split_at(4);
        self.0 = rest;
        u32::from_le_bytes(head.try_into().unwrap())
    }
    fn f32(&mut self) -> f32 {
        f32::from_bits(self.u32())
    }
    fn bytes(&mut self, n: usize) -> &[u8] {
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        head
    }
}

fn load() -> Vec<Country> {
    let mut r = Reader(WORLD_BIN);
    let countries = r.u32();
    (0..countries)
        .map(|_| {
            let iso = String::from_utf8_lossy(r.bytes(3)).into_owned();
            let mut bbox = [f32::MAX, f32::MAX, f32::MIN, f32::MIN];
            let polys = (0..r.u32())
                .map(|_| {
                    let rings: Vec<Vec<[f32; 2]>> = (0..r.u32())
                        .map(|_| {
                            (0..r.u32())
                                .map(|_| {
                                    let p = [r.f32(), r.f32()];
                                    bbox = [bbox[0].min(p[0]), bbox[1].min(p[1]), bbox[2].max(p[0]), bbox[3].max(p[1])];
                                    p
                                })
                                .collect()
                        })
                        .collect();
                    let mut points = Vec::new();
                    let mut flat = Vec::new();
                    let mut holes = Vec::new();
                    for (i, ring) in rings.iter().enumerate() {
                        if i > 0 {
                            holes.push(points.len());
                        }
                        for p in ring {
                            points.push(*p);
                            flat.extend([p[0] as f64, p[1] as f64]);
                        }
                    }
                    let triangles = earcutr::earcut(&flat, &holes, 2).unwrap_or_default().into_iter().map(|i| i as u32).collect();
                    Poly { rings, points, triangles }
                })
                .collect();
            Country { iso, polys, bbox }
        })
        .collect()
}

/// All countries, parsed and triangulated on first use.
pub fn world() -> &'static [Country] {
    static WORLD: OnceLock<Vec<Country>> = OnceLock::new();
    WORLD.get_or_init(load)
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_giant_triangles() {
        for c in super::world() {
            for p in &c.polys {
                for t in p.triangles.chunks(3) {
                    let d = |a: usize, b: usize| {
                        let (a, b) = (p.points[t[a] as usize], p.points[t[b] as usize]);
                        ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2)).sqrt()
                    };
                    let longest = d(0, 1).max(d(1, 2)).max(d(2, 0));
                    let ext = ((c.bbox[2] - c.bbox[0]).powi(2) + (c.bbox[3] - c.bbox[1]).powi(2)).sqrt();
                    assert!(longest <= ext * 1.01, "{} triangle {longest} > extent {ext}", c.iso);
                }
            }
        }
    }
}
