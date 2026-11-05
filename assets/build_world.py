"""Packs Natural Earth 50m countries (public domain) into assets/world.bin.

Usage: python build_world.py ne_50m_admin_0_countries.geojson world.bin
Format (little endian): u32 countries; per country: 3-byte ADM0_A3, u32 polygons;
per polygon: u32 rings (first = outer); per ring: u32 points, then f32 lon, f32 lat pairs.
"""
import json, struct, sys

TOL = 0.03

def simplify(pts, tol):
    if len(pts) < 5:
        return pts
    def dist(p, a, b):
        dx, dy = b[0]-a[0], b[1]-a[1]
        if dx == 0 and dy == 0:
            return ((p[0]-a[0])**2 + (p[1]-a[1])**2) ** .5
        t = ((p[0]-a[0])*dx + (p[1]-a[1])*dy) / (dx*dx+dy*dy)
        t = max(0, min(1, t))
        return ((p[0]-a[0]-t*dx)**2 + (p[1]-a[1]-t*dy)**2) ** .5
    keep = [False]*len(pts); keep[0] = keep[-1] = True
    stack = [(0, len(pts)-1)]
    while stack:
        i, j = stack.pop()
        best, k = 0, None
        for m in range(i+1, j):
            d = dist(pts[m], pts[i], pts[j])
            if d > best: best, k = d, m
        if k is not None and best > tol:
            keep[k] = True; stack += [(i, k), (k, j)]
    return [p for p, kp in zip(pts, keep) if kp]

src = json.load(open(sys.argv[1], encoding="utf8"))
out = bytearray(); n = 0; body = bytearray()
for f in src["features"]:
    iso = f["properties"]["ADM0_A3"]
    if iso == "ATA": continue
    g = f["geometry"]
    polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
    packed = []
    for poly in polys:
        rings = []
        for r in poly:
            r = simplify([tuple(p[:2]) for p in r[:-1]], TOL)  # drop closing duplicate
            if len(r) >= 3: rings.append(r)
        if rings: packed.append(rings)
    if not packed: continue
    body += iso.encode()[:3].ljust(3, b"_") + struct.pack("<I", len(packed))
    for rings in packed:
        body += struct.pack("<I", len(rings))
        for r in rings:
            body += struct.pack("<I", len(r))
            for x, y in r: body += struct.pack("<ff", x, y)
    n += 1
open(sys.argv[2], "wb").write(struct.pack("<I", n) + body)
print(n, "countries,", len(body)//1024, "KiB")
