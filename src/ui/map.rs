use crate::app::RustWarden;
use crate::data::UsageKind;
use crate::geo;
use crate::theme;
use crate::widgets;
use egui::{Align2, Color32, Mesh, Pos2, Rect, Sense, Shape, Stroke, Ui, pos2, vec2};

fn ocean() -> Color32 {
    theme::pick(Color32::from_rgb(0xe9, 0xeb, 0xf2), Color32::from_rgb(0x1d, 0x20, 0x24))
}
fn land() -> Color32 {
    theme::pick(Color32::from_rgb(0xc1, 0xcf, 0xf0), Color32::from_rgb(0x3b, 0x46, 0x5e))
}
fn land_active() -> Color32 {
    theme::pick(Color32::from_rgb(0x70, 0x84, 0xb0), Color32::from_rgb(0x7f, 0x9b, 0xd6))
}
fn land_edge() -> Color32 {
    theme::pick(Color32::from_rgb(0x9f, 0xb2, 0xe0), Color32::from_rgb(0x55, 0x62, 0x80))
}
pub(super) fn home_dot() -> Color32 {
    theme::pick(Color32::from_rgb(0x2e, 0x9e, 0x6b), Color32::from_rgb(0x5f, 0xcf, 0x9b))
}
fn land_hover() -> Color32 {
    theme::pick(Color32::from_rgb(0xe8, 0x90, 0x8a), Color32::from_rgb(0x9a, 0x5e, 0x5e))
}
const ARC: Color32 = Color32::from_rgb(0xf2, 0x6f, 0x64);
/// Blocked attempts: deeper and more saturated than the coral of allowed arcs so the two read apart.
pub(super) fn blocked_color() -> Color32 {
    theme::pick(Color32::from_rgb(0xc4, 0x1e, 0x3a), Color32::from_rgb(0xff, 0x4d, 0x6d))
}

/// Pulls a map centre back so a view `half` (degrees, half its width and height) around it stays inside the world
/// (longitude -180 to 180, latitude up to the projection's 85 degrees). A view bigger than the world is centred.
fn clamp_center(c: (f32, f32), half: (f32, f32)) -> (f32, f32) {
    let top = geo::mercator_y(85.0);
    let fit = |v: f32, limit: f32, half: f32| if half >= limit { 0.0 } else { v.clamp(half - limit, limit - half) };
    (fit(c.0, 180.0, half.0), fit(c.1, top, half.1))
}

/// Shades the night side: a vertex grid whose alpha follows the sun's altitude, so dusk fades in and the
/// terminator moves with the pan/zoom projection every frame.
/// shortcut: ignores the equation of time (up to ~16 min of terminator drift), upgrade if exact dusk matters.
fn night(p: &egui::Painter, rect: Rect, project: &dyn Fn(f32, f32) -> Pos2) {
    let t = crate::clock::now_unix() as f64;
    let day = t / 86_400.0 + 2_440_587.5 - 2_451_545.0; // days since J2000
    let dec = (-23.44_f64 * (std::f64::consts::TAU * (day.rem_euclid(365.25) + 10.0) / 365.25).cos()).to_radians();
    let sun_lon = 180.0 - (t / 240.0).rem_euclid(360.0); // degrees east where it is noon
    const STEP: f32 = 3.0;
    let (cols, rows) = ((360.0 / STEP) as usize + 1, (170.0 / STEP) as usize + 1);
    let peak = theme::pick(Color32::from_black_alpha(70), Color32::from_black_alpha(100)).a() as f32;
    let mut mesh = Mesh::default();
    for c in 0..cols {
        let lon = -180.0 + c as f32 * STEP;
        let h = (f64::from(lon) - sun_lon).to_radians();
        for r in 0..rows {
            let lat = -85.0 + r as f32 * STEP;
            let la = f64::from(lat).to_radians();
            let alt = (la.sin() * dec.sin() + la.cos() * dec.cos() * h.cos()).asin().to_degrees();
            let k = ((4.0 - alt as f32) / 16.0).clamp(0.0, 1.0); // fully dark by -12 degrees
            mesh.colored_vertex(project(lon, lat), Color32::from_black_alpha((k * k * (3.0 - 2.0 * k) * peak) as u8));
        }
    }
    for c in 0..cols - 1 {
        if project(-180.0 + c as f32 * STEP, 0.0).x > rect.right() || project(-180.0 + (c + 1) as f32 * STEP, 0.0).x < rect.left() {
            continue;
        }
        for r in 0..rows - 1 {
            let i = (c * rows + r) as u32;
            let n = rows as u32;
            mesh.indices.extend([i, i + 1, i + n, i + 1, i + n + 1, i + n]);
        }
    }
    p.add(Shape::mesh(mesh));
}

/// A fixed, non-interactive map framing `home` and `server` (both lon, lat) with an arc between them. While
/// `flow` (a test is running) packets travel along the arc in the given colour, from `home` to `server` when the
/// bool is true and back when it is false, and the caller's frame keeps repainting.
pub(crate) fn route_map(ui: &Ui, rect: Rect, home: (f32, f32), server: (f32, f32), labels: (&str, &str), flow: Option<(bool, Color32)>) {
    let p = ui.painter().with_clip_rect(rect);
    p.rect_filled(rect, 12, ocean());
    let (ya, yb) = (geo::mercator_y(home.1), geo::mercator_y(server.1));
    // Room around the pair, and never closer than a regional view: two points a few miles apart would zoom into nothing.
    let span_x = ((home.0 - server.0).abs() * 1.8).max(10.0);
    let span_y = ((ya - yb).abs() * 1.8).max(10.0 * rect.height() / rect.width());
    let scale = (rect.width() / span_x).min(rect.height() / span_y);
    let (clon, cy) = ((home.0 + server.0) / 2.0, (ya + yb) / 2.0);
    let project = |lon: f32, lat: f32| pos2(rect.center().x + (lon - clon) * scale, rect.center().y - (geo::mercator_y(lat) - cy) * scale);
    let edge = Stroke::new(0.7, land_edge());
    for country in geo::world() {
        let [x0, y0, x1, y1] = country.bbox;
        if !rect.intersects(Rect::from_min_max(project(x0, y1), project(x1, y0))) {
            continue;
        }
        for poly in &country.polys {
            let mut mesh = Mesh::default();
            for q in &poly.points {
                mesh.colored_vertex(project(q[0], q[1]), land());
            }
            mesh.indices = poly.triangles.clone();
            p.add(Shape::mesh(mesh));
            for ring in &poly.rings {
                p.add(Shape::closed_line(ring.iter().map(|q| project(q[0], q[1])).collect(), edge));
            }
        }
    }
    let (a, b) = (project(home.0, home.1), project(server.0, server.1));
    let ctrl = pos2((a.x + b.x) / 2.0, (a.y + b.y) / 2.0 - a.distance(b) * 0.18);
    let at = |t: f32| {
        let k = 1.0 - t;
        pos2(k * k * a.x + 2.0 * k * t * ctrl.x + t * t * b.x, k * k * a.y + 2.0 * k * t * ctrl.y + t * t * b.y)
    };
    p.add(Shape::line((0..=48).map(|i| at(i as f32 / 48.0)).collect(), Stroke::new(1.6, ARC)));
    if let Some((outbound, tint)) = flow {
        let time = ui.input(|i| i.time);
        for d in 0..3 {
            let t = (time * 0.5 + d as f64 / 3.0).rem_euclid(1.0) as f32;
            p.circle_filled(at(if outbound { t } else { 1.0 - t }), 3.5, tint);
        }
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(16));
    }
    for (pt, other, color, label) in [(a, b, home_dot(), labels.0), (b, a, ARC, labels.1)] {
        p.circle_filled(pt, 5.0, color);
        p.circle_stroke(pt, 5.0, Stroke::new(1.5, ocean()));
        // Labels sit on the side of their dot that faces away from the other one, so they don't cross the arc.
        let left = if pt.x == other.x { pt == a } else { pt.x < other.x };
        let (anchor, dx) = if left { (Align2::RIGHT_CENTER, -10.0) } else { (Align2::LEFT_CENTER, 10.0) };
        p.text(pt + vec2(dx, 0.0), anchor, label, theme::font(12.0), theme::text());
    }
}

impl RustWarden {
    /// Interactive connections map: drag to pan, scroll or +/- to zoom.
    pub(crate) fn traffic_map(&mut self, ui: &mut Ui, rect: Rect) {
        let p = ui.painter().with_clip_rect(rect);
        p.rect_filled(rect, 0, ocean());

        let (show_names, show_flags, animate) = (self.settings.map_names, self.settings.map_flags, self.settings.map_animate);
        let (show_allowed, show_blocked) = (self.settings.map_allowed, self.settings.map_blocked);
        let visible = |c: &crate::data::MapConnection| (show_allowed && c.count > 0) || (show_blocked && c.blocked > 0);
        let a3_of = |key: &str| crate::countries::parse_a2(key).and_then(crate::countries::by_a2).map(|e| e.a3);
        let st = &mut self.traffic;
        let drag = ui.interact(rect, ui.scope_id().with("map_drag"), Sense::click_and_drag());
        let base = rect.width() / 165.0;
        let scroll = if drag.hovered() { ui.input(|i| i.smooth_scroll_delta.y) } else { 0.0 };
        if scroll != 0.0 {
            st.map_zoom = (st.map_zoom * (1.0 + scroll * 0.002)).clamp(0.6, 12.0);
            st.map_zoom_to = st.map_zoom;
            st.map_touched = true;
        }
        if !st.map_touched && st.map_center_to.is_none() {
            st.map_center = (st.map.home.0, geo::mercator_y(st.map.home.1));
            st.map_zoom = 1.0;
            st.map_zoom_to = 1.0;
        }
        // Ease toward the target set by the +/- buttons.
        if let Some(to) = st.map_center_to {
            let k = 1.0 - (-10.0 * ui.input(|i| i.stable_dt)).exp();
            st.map_center = (st.map_center.0 + (to.0 - st.map_center.0) * k, st.map_center.1 + (to.1 - st.map_center.1) * k);
            if (to.0 - st.map_center.0).abs() < 0.01 && (to.1 - st.map_center.1).abs() < 0.01 {
                st.map_center = to;
                st.map_center_to = None;
            }
            ui.ctx().request_repaint();
        }
        if (st.map_zoom_to - st.map_zoom).abs() > 0.001 {
            let k = 1.0 - (-12.0 * ui.input(|i| i.stable_dt)).exp();
            st.map_zoom += (st.map_zoom_to - st.map_zoom) * k;
            ui.ctx().request_repaint();
        } else {
            st.map_zoom = st.map_zoom_to;
        }
        if drag.dragged() {
            st.map_center_to = None;
            st.map_touched = true;
            let d = drag.drag_delta() / (base * st.map_zoom);
            st.map_center = (st.map_center.0 - d.x, st.map_center.1 + d.y);
        }
        let scale = base * st.map_zoom;
        // Keep the view inside the world, whatever dragged, eased or zoomed it out of bounds.
        let half = (rect.width() / 2.0 / scale, rect.height() / 2.0 / scale);
        st.map_center = clamp_center(st.map_center, half);
        st.map_center_to = st.map_center_to.map(|to| clamp_center(to, half));
        let (clon, clat) = st.map_center;
        let project = |lon: f32, lat: f32| pos2(rect.center().x + (lon - clon) * scale, rect.center().y - (geo::mercator_y(lat) - clat) * scale);

        // Hovering a country with connections tints it; clicking opens its detail like the bubble does.
        // Buttons on the floating bars don't take hover from the map under them (it also senses drags), so skip those spots.
        let on_bar = |m: egui::Pos2| [false, true].iter().any(|&r| ui.data(|d| d.get_temp::<Rect>(super::traffic::command_card_id(ui, r))).is_some_and(|c| c.contains(m)));
        let hovered = if st.live && drag.hovered() { ui.input(|i| i.pointer.hover_pos()).filter(|&m| !on_bar(m)) } else { None }.and_then(|m| {
            let key = |c: &&crate::data::MapConnection| c.key.clone();
            geo::world().iter().find_map(|country| {
                let c = st.map.connections.iter().filter(|c| visible(c)).find(|c| {
                    crate::countries::parse_a2(&c.key).and_then(crate::countries::by_a2).map_or(c.key.as_str(), |e| e.a3) == country.iso
                        || crate::countries::TABLE.iter().any(|e| e.a3 == country.iso && e.name == c.key)
                })?;
                let inside = country.polys.iter().any(|poly| {
                    let mut odd = false;
                    for ring in &poly.rings {
                        let mut j = ring.len().wrapping_sub(1);
                        for i in 0..ring.len() {
                            let (a, b) = (project(ring[i][0], ring[i][1]), project(ring[j][0], ring[j][1]));
                            if (a.y > m.y) != (b.y > m.y) && m.x < (b.x - a.x) * (m.y - a.y) / (b.y - a.y) + a.x {
                                odd = !odd;
                            }
                            j = i;
                        }
                    }
                    odd
                });
                inside.then(|| (country.iso.clone(), key(&c)))
            })
        });
        if hovered.is_some() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }

        // With a layer hidden, only countries that still have a visible connection are shaded.
        let active: Vec<&str> = if (show_allowed && show_blocked) || !st.live {
            st.map.active.iter().map(String::as_str).collect()
        } else {
            st.map.connections.iter().filter(|c| visible(c)).filter_map(|c| a3_of(&c.key)).collect()
        };
        let edge = Stroke::new(0.7, land_edge());
        for country in geo::world() {
            let [x0, y0, x1, y1] = country.bbox;
            let (a, b) = (project(x0, y1), project(x1, y0));
            if !rect.intersects(Rect::from_min_max(a, b)) {
                continue;
            }
            let base_fill = if active.contains(&country.iso.as_str()) { land_active() } else { land() };
            let t = ui.ctx().animate_bool_with_time(ui.scope_id().with(("map_hover", &country.iso)), hovered.as_ref().is_some_and(|h| h.0 == country.iso), 0.15);
            let fill = base_fill.lerp_to_gamma(land_hover(), t);
            for poly in &country.polys {
                let mut mesh = Mesh::default();
                for q in &poly.points {
                    mesh.colored_vertex(project(q[0], q[1]), fill);
                }
                mesh.indices = poly.triangles.clone();
                p.add(Shape::mesh(mesh));
                for ring in &poly.rings {
                    p.add(Shape::closed_line(ring.iter().map(|q| project(q[0], q[1])).collect(), edge));
                }
            }
        }

        night(&p, rect, &project);

        let mut clicked: Option<(String, Pos2)> = None;
        if let (true, Some((_, key)), Some(m)) = (drag.clicked(), &hovered, drag.interact_pointer_pos()) {
            clicked = Some((key.clone(), m));
        }
        if st.live {
            let home = project(st.map.home.0, st.map.home.1);
            let mut bubbles = Vec::new();
            let time = ui.input(|i| i.time) as f32; // f32 is plenty: it only drives a phase
            if animate && !st.map.connections.is_empty() {
                ui.ctx().request_repaint_after(std::time::Duration::from_millis(16));
            }
            // Bearing from home to each visible destination: arcs leaving at nearly the same bearing would lie on top
            // of each other, and only those get spread apart.
            let bearings: Vec<f32> = st
                .map
                .connections
                .iter()
                .filter(|c| visible(c))
                .map(|c| {
                    let d = project(c.lon, c.lat);
                    (d.y - home.y).atan2(d.x - home.x)
                })
                .collect();
            for (c, bearing) in st.map.connections.iter().filter(|c| visible(c)).zip(&bearings) {
                let (allowed_on, blocked_on) = (show_allowed && c.count > 0, show_blocked && c.blocked > 0);
                let dst = project(c.lon, c.lat);
                let seed = c.key.bytes().fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(b))) % 1000;
                let dist = home.distance(dst).max(1.0);
                let crowded = bearings
                    .iter()
                    .filter(|b| {
                        let d = (**b - bearing).rem_euclid(std::f32::consts::TAU);
                        d.min(std::f32::consts::TAU - d) < 0.12
                    })
                    .count()
                    > 1;
                let ctrl = if crowded {
                    // Bows to its own side by its own amount (stable per country) so the pile fans out.
                    let bow = dist * (0.12 + (seed / 2 % 100) as f32 * 0.003) * if seed % 2 == 0 { 1.0 } else { -1.0 };
                    let (dx, dy) = ((dst.x - home.x) / dist, (dst.y - home.y) / dist);
                    pos2((home.x + dst.x) / 2.0 - dy * bow, (home.y + dst.y) / 2.0 + dx * bow)
                } else {
                    pos2((home.x + dst.x) / 2.0, (home.y + dst.y) / 2.0 - dist * 0.18)
                };
                let curve: Vec<Pos2> = (0..=48)
                    .map(|i| {
                        let t = i as f32 / 48.0;
                        let a = 1.0 - t;
                        pos2(a * a * home.x + 2.0 * a * t * ctrl.x + t * t * dst.x, a * a * home.y + 2.0 * a * t * ctrl.y + t * t * dst.y)
                    })
                    .collect();
                if blocked_on {
                    // Dashed and red: attempts that never connected, so there are no packets on it.
                    p.extend(Shape::dashed_line(&curve, Stroke::new(1.3, blocked_color()), 6.0, 5.0));
                }
                if allowed_on {
                    p.add(Shape::line(curve, Stroke::new(1.3, ARC)));
                }
                // Packets drift out along the arc for sent bytes and back for received ones. The phase comes from
                // the country key, not the list position, so a reload can't make the dots jump.
                let at = |t: f32| {
                    let a = 1.0 - t;
                    pos2(a * a * home.x + 2.0 * a * t * ctrl.x + t * t * dst.x, a * a * home.y + 2.0 * a * t * ctrl.y + t * t * dst.y)
                };
                let n_dots = 1 + (c.count > 5) as usize + (c.count > 50) as usize;
                for (bytes, out, tint) in [(c.up, true, ARC), (c.down, false, home_dot())] {
                    if !animate || !allowed_on {
                        break;
                    }
                    if bytes <= 0.0 {
                        continue;
                    }
                    for d in 0..n_dots {
                        let t = (time as f64 * 0.18 + seed as f64 * 0.001 + d as f64 / n_dots as f64 + if out { 0.0 } else { 0.5 / n_dots as f64 }).rem_euclid(1.0) as f32;
                        let fade = (t * 8.0).min(1.0) * ((1.0 - t) * 8.0).min(1.0);
                        for k in 0..4 {
                            let tt = (t - k as f32 * 0.012).max(0.0);
                            let tt = if out { tt } else { 1.0 - tt };
                            let al = (fade * (1.0 - k as f32 * 0.25) * 200.0) as u8;
                            p.circle_filled(at(tt), 2.6 - k as f32 * 0.4, tint.lerp_to_gamma(Color32::WHITE, 0.45).gamma_multiply_u8(al));
                        }
                    }
                }
                // The bubble counts allowed hosts; a country with only blocked attempts counts those instead.
                bubbles.push((dst, if allowed_on { c.count } else { c.blocked }, c.key.clone(), c.label.clone(), allowed_on, blocked_on));
            }
            p.circle_filled(home, 5.0, home_dot());
            p.circle_stroke(home, 5.0, Stroke::new(1.5, theme::surface_solid()));
            // Greedy clustering: bubbles closer than a bubble diameter merge into one numbered circle.
            struct Cluster {
                pos: Pos2,
                count: usize,
                members: usize,
                /// Key and label of the first member.
                key: String,
                label: String,
                allowed: bool,
                blocked: bool,
                /// Every member is in the same country.
                one_country: bool,
            }
            let mut clusters: Vec<Cluster> = Vec::new();
            for (pos, count, key, label, allowed, blocked) in bubbles {
                match clusters.iter_mut().find(|c| c.pos.distance(pos) < 30.0) {
                    Some(c) => {
                        let n = c.members as f32;
                        c.pos = pos2((c.pos.x * n + pos.x) / (n + 1.0), (c.pos.y * n + pos.y) / (n + 1.0));
                        c.count += count as usize;
                        c.members += 1;
                        c.allowed |= allowed;
                        c.blocked |= blocked;
                        c.one_country &= c.key == key;
                    }
                    None => clusters.push(Cluster { pos, count: count as usize, members: 1, key, label, allowed, blocked, one_country: true }),
                }
            }
            for (i, Cluster { pos, count, members, key, label, allowed, blocked, one_country }) in clusters.into_iter().enumerate() {
                let resp = ui.interact(Rect::from_center_size(pos, vec2(28.0, 28.0)), ui.scope_id().with(("bubble", i)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                if resp.clicked() {
                    if members > 1 && one_country {
                        // Several places of one country (a city database puts them a few km apart, so zooming never
                        // separates them): show the country's connections.
                        clicked = Some((key.clone(), pos + vec2(0.0, 18.0)));
                    } else if members > 1 {
                        // Different countries: zoom in on the cluster so it splits.
                        st.map_touched = true;
                        st.map_center_to = Some((clon + (pos.x - rect.center().x) / scale, clat + (rect.center().y - pos.y) / scale));
                        st.map_zoom_to = (st.map_zoom_to * 2.0).clamp(0.6, 12.0);
                    } else {
                        // "GB:London" narrows the detail to that city; a bare code is the whole country.
                        let detail_key = if label.is_empty() { key.clone() } else { format!("{key}:{label}") };
                        clicked = Some((detail_key, pos + vec2(0.0, 18.0)));
                    }
                }
                p.circle_filled(pos + vec2(0.0, 1.5), 14.0, Color32::from_black_alpha(25));
                // A connection to the home country sits on the home dot, so it takes the Home colour.
                let is_home = members == 1 && pos.distance(home) < 1.0;
                // Blocked-only bubbles are red; a mix keeps the white bubble with a red dot on its corner.
                let only_blocked = blocked && !allowed;
                p.circle_filled(
                    pos,
                    14.0,
                    if only_blocked {
                        blocked_color()
                    } else if is_home {
                        home_dot()
                    } else {
                        theme::WHITE
                    },
                );
                p.circle_stroke(pos, 14.0, Stroke::new(1.0, theme::border()));
                // Fixed dark: the bubble is white in both themes, so the themed text vanished in dark mode.
                p.text(pos, Align2::CENTER_CENTER, count.to_string(), theme::bold(15.0), if only_blocked { Color32::WHITE } else { Color32::from_rgb(0x22, 0x26, 0x2e) });
                if blocked && allowed {
                    p.circle_filled(pos + vec2(10.0, -10.0), 5.5, blocked_color());
                    p.circle_stroke(pos + vec2(10.0, -10.0), 5.5, Stroke::new(1.5, theme::WHITE));
                }
                if members == 1 && (show_names || show_flags) {
                    let a2 = crate::countries::parse_a2(&key);
                    let name = if label.is_empty() { a2.and_then(crate::countries::by_a2).map_or(key.as_str(), |e| e.name) } else { label.as_str() };
                    let galley = p.layout_no_wrap(name.to_owned(), theme::font(13.0), theme::text());
                    let flag_w = if show_flags && a2.is_some() { 20.0 } else { 0.0 };
                    let text_w = if show_names { galley.size().x } else { 0.0 };
                    let gap = if flag_w > 0.0 && text_w > 0.0 { 6.0 } else { 0.0 };
                    if flag_w + text_w > 0.0 {
                        let pill = Rect::from_center_size(pos + vec2(0.0, 32.0), vec2(flag_w + gap + text_w + 14.0, 22.0));
                        widgets::shadowed_pill(&p, pill, theme::surface_solid());
                        let mut x = pill.left() + 7.0;
                        if let (true, Some(a2)) = (flag_w > 0.0, a2) {
                            crate::icons::flag(&p, crate::data::Country::from_a2(a2), Rect::from_min_size(pos2(x, pill.center().y - 6.6), vec2(flag_w, 13.2)));
                            x += flag_w + gap;
                        }
                        if show_names {
                            p.galley(pos2(x, pill.center().y - galley.size().y / 2.0), galley, theme::text());
                        }
                    }
                }
            }
        }

        // Bottom-left: live toggle.
        let live = Rect::from_min_size(pos2(rect.left() + 16.0, rect.bottom() - 62.0), vec2(214.0, 44.0));
        p.rect_filled(live.translate(vec2(0.0, 1.5)), 22, Color32::from_black_alpha(16));
        p.rect_filled(live, 22, theme::surface());
        super::row_in(ui, live.shrink2(vec2(20.0, 0.0)), |ui| {
            ui.label(egui::RichText::new("Live Connections").font(theme::font(16.0)).color(theme::text()));
            ui.add_space(6.0);
            let mut on = st.live;
            if widgets::small_toggle(ui, &mut on).clicked() {
                st.live = on;
            }
        });

        // Bottom-right: zoom buttons.
        let zoom = Rect::from_min_size(pos2(rect.right() - 16.0 - 104.0, rect.bottom() - 62.0), vec2(104.0, 44.0));
        p.rect_filled(zoom.translate(vec2(0.0, 1.5)), 22, Color32::from_black_alpha(16));
        p.rect_filled(zoom, 22, theme::surface());
        p.vline(zoom.center().x, zoom.y_range().shrink(8.0), Stroke::new(1.0, theme::border()));
        for (i, sign) in [1.0_f32, -1.0].into_iter().enumerate() {
            let r = Rect::from_min_size(zoom.min + vec2(52.0 * i as f32, 0.0), vec2(52.0, 44.0));
            let resp = ui.interact(r, ui.scope_id().with(("zoom", i)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
            if resp.hovered() {
                p.rect_filled(r.shrink(2.0), 20, theme::panel_bg());
            }
            if resp.clicked() {
                st.map_touched = true;
                st.map_zoom_to = (st.map_zoom_to * if sign > 0.0 { 1.5 } else { 1.0 / 1.5 }).clamp(0.6, 12.0);
            }
            let c = r.center();
            let s = Stroke::new(2.0, theme::text());
            p.line_segment([c - vec2(8.0, 0.0), c + vec2(8.0, 0.0)], s);
            if sign > 0.0 {
                p.line_segment([c - vec2(0.0, 8.0), c + vec2(0.0, 8.0)], s);
            }
        }
        if let Some((key, pos)) = clicked {
            self.traffic.detail = self.backend.usage_detail(self.traffic.range, self.traffic.window, UsageKind::Country, &key).map(|d| (pos, d));
            self.traffic.detail_back.clear();
        }
        self.traffic_detail(ui.ctx());
    }
}

#[cfg(test)]
mod tests {
    use super::clamp_center;

    #[test]
    fn the_view_cannot_leave_the_world() {
        // zoomed in: 20 degrees either side of the centre
        assert_eq!(clamp_center((-175.0, 0.0), (20.0, 10.0)), (-160.0, 0.0));
        assert_eq!(clamp_center((175.0, 0.0), (20.0, 10.0)), (160.0, 0.0));
        let (_, y) = clamp_center((0.0, 500.0), (20.0, 10.0));
        assert!(y < 180.0 && y > 160.0);
        // already inside: untouched
        assert_eq!(clamp_center((10.0, 20.0), (20.0, 10.0)), (10.0, 20.0));
        // zoomed out past the world: centred
        assert_eq!(clamp_center((90.0, 90.0), (200.0, 300.0)), (0.0, 0.0));
    }
}
