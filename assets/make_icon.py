#!/usr/bin/env python3
"""Draws the Latency Checker app icon and writes icon.png / .icns / .ico (needs Pillow + numpy).

    python3 assets/make_icon.py
"""
from pathlib import Path
import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageFilter

OUT = Path(__file__).resolve().parent
S = 2048                      # supersampled canvas → downscaled to 1024 for smooth edges
K = S / 1024


def rounded_mask(size, box, radius):
    m = Image.new("L", size, 0)
    ImageDraw.Draw(m).rounded_rectangle(box, radius=radius, fill=255)
    return m


def gradient(size, c1, c2, c3):
    """Diagonal 3-stop gradient (top-left → bottom-right)."""
    w, h = size
    y, x = np.mgrid[0:h, 0:w].astype(np.float32)
    t = ((x / w) * 0.45 + (y / h) * 0.55)[..., None]
    c1, c2, c3 = (np.array(c, np.float32) for c in (c1, c2, c3))
    col = np.where(t < 0.5, c1 + (c2 - c1) * (t / 0.5), c2 + (c3 - c2) * ((t - 0.5) / 0.5))
    return Image.fromarray(np.clip(col, 0, 255).astype(np.uint8), "RGB")


def catmull_rom(p, n):
    """Smooth curve through the knots (n samples per segment)."""
    p = [p[0]] + list(p) + [p[-1]]
    out = []
    for i in range(1, len(p) - 2):
        p0, p1, p2, p3 = (np.array(q) for q in (p[i - 1], p[i], p[i + 1], p[i + 2]))
        for t in np.linspace(0, 1, n, endpoint=False):
            t2, t3 = t * t, t * t * t
            q = 0.5 * ((2 * p1) + (-p0 + p2) * t + (2 * p0 - 5 * p1 + 4 * p2 - p3) * t2
                       + (-p0 + 3 * p1 - 3 * p2 + p3) * t3)
            out.append((float(q[0]), float(q[1])))
    out.append(tuple(map(float, p[-2])))
    return out


def resample(p, step):
    """Evenly spaced points along a polyline (for a smooth stamped stroke)."""
    out = [p[0]]
    for (x0, y0), (x1, y1) in zip(p, p[1:]):
        seg = float(np.hypot(x1 - x0, y1 - y0))
        n = max(1, int(seg / step))
        for k in range(1, n + 1):
            out.append((x0 + (x1 - x0) * k / n, y0 + (y1 - y0) * k / n))
    return out


def main():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # Apple icon grid: 824 pt tile centred in 1024, continuous-corner radius ≈ 185.
    x0, y0, x1, y1 = (int(v * K) for v in (100, 100, 924, 924))
    r = int(185 * K)

    # soft drop shadow
    sh = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(sh).rounded_rectangle((x0, y0 + int(14 * K), x1, y1 + int(14 * K)),
                                         radius=r, fill=(0, 0, 0, 110))
    img = Image.alpha_composite(img, sh.filter(ImageFilter.GaussianBlur(28 * K)))

    tile_mask = rounded_mask((S, S), (x0, y0, x1, y1), r)
    bg = gradient((S, S), (16, 32, 84), (14, 58, 110), (8, 118, 128)).convert("RGBA")
    # top highlight
    hl = Image.new("L", (S, S), 0)
    ImageDraw.Draw(hl).ellipse((x0 - int(200 * K), y0 - int(620 * K), x1 + int(200 * K), y0 + int(300 * K)),
                               fill=38)
    hl = hl.filter(ImageFilter.GaussianBlur(120 * K))
    bg = Image.composite(Image.new("RGBA", (S, S), (255, 255, 255, 255)), bg, hl)
    tile = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    tile.paste(bg, (0, 0), tile_mask)

    # faint chart grid (own layer, blended — drawing straight onto the tile would punch holes)
    left, right = int(200 * K), int(824 * K)
    top, bottom = int(250 * K), int(760 * K)
    grid = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grid)
    for i in range(5):
        yy = int(top + (bottom - top) * i / 4)
        gd.line((left, yy, right, yy), fill=(190, 230, 255, 34), width=int(3 * K))
    tile = Image.alpha_composite(tile, grid)

    # latency trace: calm, a spike, calm again
    xs = np.linspace(left, right - int(40 * K), 14)
    base = [0.30, 0.34, 0.28, 0.36, 0.31, 0.33, 0.95, 0.40, 0.29, 0.35, 0.30, 0.37, 0.32, 0.34]
    knots = [(float(x), float(bottom - (bottom - top) * v * 0.9)) for x, v in zip(xs, base)]
    pts = catmull_rom(knots, 24)
    spike_i = 6 * 24                                   # index of the spike's knot in pts

    # area under the line
    area = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ad = ImageDraw.Draw(area)
    ad.polygon(pts + [(pts[-1][0], bottom), (pts[0][0], bottom)], fill=(94, 234, 212, 70))
    fade = Image.new("L", (S, S), 0)
    fd = ImageDraw.Draw(fade)
    for i in range(top, bottom):
        fd.line((0, i, S, i), fill=int(255 * (i - top) / (bottom - top)))
    area.putalpha(ImageChops.multiply(area.getchannel("A"), ImageChops.invert(fade)))
    tile = Image.alpha_composite(tile, area)

    # glow + line
    lw = int(30 * K)
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(glow).line(pts, fill=(94, 234, 212, 200), width=lw * 3, joint="curve")
    tile = Image.alpha_composite(tile, glow.filter(ImageFilter.GaussianBlur(30 * K)))
    line = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ld = ImageDraw.Draw(line)
    teal, amber = np.array((153, 246, 228)), np.array((251, 191, 36))
    span = 16                                            # samples over which teal → amber
    path = resample(pts, lw / 8)                         # dense, evenly spaced points
    spike_xy = np.array(pts[spike_i])
    d_spike = np.array([np.hypot(*(np.array(q) - spike_xy)) for q in path])
    fade_len = (lw / 8) * span * 6
    for q, dist in zip(path, d_spike):
        t = max(0.0, 1 - dist / fade_len)                 # 1 at the peak → 0 away from it
        c = tuple(int(v) for v in teal + (amber - teal) * min(1.0, t * 1.7))
        ld.ellipse((q[0] - lw / 2, q[1] - lw / 2, q[0] + lw / 2, q[1] + lw / 2), fill=c + (255,))
    tile = Image.alpha_composite(tile, line)

    # live "pulse" dot at the end
    ex, ey = pts[-1]
    pulse = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    pd = ImageDraw.Draw(pulse)
    for rad, a in ((104, 55), (74, 105)):
        rr = rad * K
        pd.ellipse((ex - rr, ey - rr, ex + rr, ey + rr), outline=(153, 246, 228, a), width=int(10 * K))
    rr = 34 * K
    pd.ellipse((ex - rr, ey - rr, ex + rr, ey + rr), fill=(255, 255, 255, 255))
    tile = Image.alpha_composite(tile, pulse)

    # keep everything inside the tile, add a hairline edge
    tile.putalpha(ImageChops.multiply(tile.getchannel("A"), tile_mask))
    edge = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(edge).rounded_rectangle((x0, y0, x1, y1), radius=r, outline=(255, 255, 255, 40),
                                           width=int(3 * K))
    img = Image.alpha_composite(img, Image.alpha_composite(tile, edge))

    icon = img.resize((1024, 1024), Image.LANCZOS)
    icon.save(OUT / "icon.png")
    icon.resize((256, 256), Image.LANCZOS).save(OUT / "icon-256.png")
    icon.save(OUT / "icon.icns", sizes=[(16, 16), (32, 32), (64, 64), (128, 128),
                                         (256, 256), (512, 512), (1024, 1024)])
    icon.save(OUT / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64),
                                        (128, 128), (256, 256)])
    print("wrote", ", ".join(p.name for p in sorted(OUT.glob("icon*"))))


if __name__ == "__main__":
    main()
