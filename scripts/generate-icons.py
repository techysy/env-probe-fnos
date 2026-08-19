#!/usr/bin/env python3
"""生成 fn-netdiag 图标 — 绿色雷达/放大镜主题, 对齐 fnOS 圆角 18.75%"""
from PIL import Image, ImageDraw
import os

BRAND = (34, 197, 94)      # #22c55e 绿
DARK = (15, 23, 42)        # #0f172a 深底

def make(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    radius = int(size * 0.1875)
    # 背景圆角矩形 (深色)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=DARK)
    c = size / 2
    # 雷达同心圆 (绿色描边)
    ring = max(2, int(size * 0.03))
    for r in (int(size * 0.42), int(size * 0.28)):
        d.ellipse([c - r, c - r, c + r, c + r], outline=BRAND, width=ring)
    # 中心圆点
    dot = int(size * 0.06)
    d.ellipse([c - dot, c - dot, c + dot, c + dot], fill=BRAND)
    # 十字准线
    lw = max(1, int(size * 0.015))
    d.line([c, c - size * 0.42, c, c - size * 0.14], fill=BRAND, width=lw)
    d.line([c, c + size * 0.14, c, c + size * 0.42], fill=BRAND, width=lw)
    d.line([c - size * 0.42, c, c - size * 0.14, c], fill=BRAND, width=lw)
    d.line([c + size * 0.14, c, c + size * 0.42, c], fill=BRAND, width=lw)
    return img

base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # 项目根
# 包图标
for f, s in (("ICON.PNG", 64), ("ICON_256.PNG", 256)):
    make(s).save(os.path.join(base, f))
# 入口图标
for s in (64, 128, 256):
    make(s).save(os.path.join(base, "app", "ui", "images", f"icon_{s}.png"))
print("icons generated")
