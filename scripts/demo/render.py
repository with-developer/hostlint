#!/usr/bin/env python3
"""Render docs/demo/scan.txt (a captured `vmsctl scan`) as an animated GIF.

    python3 scripts/demo/render.py docs/demo/scan.txt docs/demo/scan.gif [--font PATH]

docs/demo/scan.txt is the real output of `vmsctl scan` (abridged, host name
shortened) on a Debian 12 container with PermitRootLogin yes, an inetd telnet
service, /etc/shadow at 0640 and a stock /etc/inetd.conf; update it when the
output format or the wording of these checks changes.

Needs Python 3 and Pillow (pip install pillow) and a monospace font that has the
check and cross marks (DejaVu Sans Mono, Menlo, ...). Long lines wrap at 110
columns, as they do in a terminal.
"""
import argparse
import os
import sys
import textwrap

from PIL import Image, ImageDraw, ImageFont

COLS = 110
FONTS = [
    "/System/Library/Fonts/Menlo.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
]
BG, FG, DIM = (30, 30, 36), (220, 220, 226), (140, 140, 150)
RED, GREEN, YELLOW, BOLD = (255, 105, 97), (120, 220, 130), (240, 200, 90), (255, 255, 255)
PROMPT = "$ sudo vmsctl scan"


def color(line):
    s = line.lstrip()
    if s.startswith("✗"):
        return RED
    if s.startswith("✓"):
        return GREEN
    if s.startswith("?"):
        return YELLOW
    if line.startswith("vmsctl ") or line.startswith("kisa-2026"):
        return BOLD
    return DIM if line.startswith("        ") else FG


def wrap(lines):
    out = []
    for line in lines:
        parts = textwrap.wrap(line, COLS, drop_whitespace=False, replace_whitespace=False) or [""]
        out += [(p, color(line)) for p in parts]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("gif")
    ap.add_argument("--font")
    ap.add_argument("--size", type=int, default=15)
    args = ap.parse_args()
    font_path = args.font or next((f for f in FONTS if os.path.exists(f)), None)
    if not font_path:
        sys.exit("no monospace font found: pass --font PATH")
    font = ImageFont.truetype(font_path, args.size)
    cw = round(font.getlength("M"))
    lh = args.size + 6
    lines = wrap(open(args.capture, encoding="utf-8").read().rstrip("\n").split("\n"))
    rows = len(lines) + 2
    pad = 16
    size = (COLS * cw + 2 * pad, rows * lh + 2 * pad)

    def frame(typed, shown, cursor):
        im = Image.new("RGB", size, BG)
        d = ImageDraw.Draw(im)
        text = PROMPT[:typed]
        d.text((pad, pad), text, font=font, fill=FG)
        if cursor:
            x = pad + len(text) * cw
            d.rectangle((x, pad + 2, x + cw - 2, pad + lh - 2), fill=FG)
        for i, (text, col) in enumerate(lines[:shown]):
            d.text((pad, pad + (i + 2) * lh), text, font=font, fill=col)
        return im

    frames, delays = [frame(0, 0, True)], [600]
    for n in range(2, len(PROMPT) + 1, 2):
        frames.append(frame(n, 0, True)); delays.append(70)
    frames.append(frame(len(PROMPT), 0, False)); delays.append(500)
    for n in range(3, len(lines) + 3, 3):
        frames.append(frame(len(PROMPT), min(n, len(lines)), False)); delays.append(110)
    delays[-1] = 5000
    frames[0].save(args.gif, save_all=True, append_images=frames[1:], duration=delays, loop=0, optimize=True)
    print(f"{args.gif}: {len(frames)} frames, {size[0]}x{size[1]}, {os.path.getsize(args.gif) // 1024} KiB")


if __name__ == "__main__":
    main()
