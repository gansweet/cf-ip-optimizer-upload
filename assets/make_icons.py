#!/usr/bin/env python3
"""由主页 logo（assets/logo.svg）生成各平台图标：PNG / Windows ICO / macOS ICNS。需要 Pillow。"""
import math, os
from PIL import Image, ImageDraw

S = 1536; K = S / 48.0
def P(x, y): return (x * K, y * K)

base = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ImageDraw.Draw(base).rounded_rectangle([0, 0, S - 1, S - 1], radius=11 * K, fill=(16, 21, 40, 255))

mask = Image.new("L", (S, S), 0); d = ImageDraw.Draw(mask)
cx, cy, r = 24 * K, 24 * K, 20 * K                       # 虚线轨道
for i in range(36):
    a0 = i * 10 + 4; d.arc([cx - r, cy - r, cx + r, cy + r], a0, a0 + 6, fill=255, width=int(1.8 * K))
w = int(4 * K)                                            # A 字母，圆头圆角
for seg in ([(13, 35), (24, 11), (35, 35)], [(17.5, 27), (30.5, 27)]):
    pts = [P(*p) for p in seg]; d.line(pts, fill=255, width=w, joint="curve")
    for p in pts: d.ellipse([p[0] - w / 2, p[1] - w / 2, p[0] + w / 2, p[1] + w / 2], fill=255)

g = Image.new("RGB", (2, 2)); c1, c2 = (124, 140, 255), (255, 122, 217); mid = tuple((a + b) // 2 for a, b in zip(c1, c2))
g.putpixel((0, 0), c1); g.putpixel((1, 1), c2); g.putpixel((1, 0), mid); g.putpixel((0, 1), mid)
g = g.resize((S, S), Image.BILINEAR)
base.paste(g, (0, 0), mask)
dot = ImageDraw.Draw(base); x, y = P(24, 11); rr = 3 * K
dot.ellipse([x - rr, y - rr, x + rr, y + rr], fill=(255, 122, 217, 255))

here = os.path.dirname(os.path.abspath(__file__)); os.makedirs(os.path.join(here, "icons"), exist_ok=True)
for n in (16, 32, 48, 64, 128, 256, 512, 1024):
    base.resize((n, n), Image.LANCZOS).save(os.path.join(here, "icons", f"cfip-{n}.png"))
big = base.resize((1024, 1024), Image.LANCZOS)
big.save(os.path.join(here, "cfip.ico"), sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
big.save(os.path.join(here, "cfip.icns"))
print("icons ok")
