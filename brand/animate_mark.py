"""Animate the existing vector mark, preserving its geometry and transparent corners.

python brand/animate_mark.py
Uses the asset-authoring dependencies in brand/requirements.txt.
"""

import copy
from io import BytesIO
import math
from pathlib import Path
import xml.etree.ElementTree as ET

from PIL import Image, ImageChops
import resvg_py

ROOT = Path(__file__).resolve().parent
SVG = "{http://www.w3.org/2000/svg}"
ET.register_namespace("", SVG[1:-1])
DURATION_MS, FRAME_MS, SIZE = 4000, 80, 256


def dot_state(dot, seconds):
    phase = seconds / (DURATION_MS / 1000)
    envelope = math.sin(math.pi * phase) ** 2
    scale = 1 - .10 * envelope
    x, y = float(dot.attrib["cx"]), float(dot.attrib["cy"])
    distance = math.hypot(x - 128, y - 128)
    wave = (1 + math.cos(2 * math.pi * (phase + distance / 128))) / 2
    opacity = float(dot.get("opacity", "1"))
    return {"cx": 128 + (x - 128) * scale, "cy": 128 + (y - 128) * scale,
            "opacity": opacity + (1 - opacity) * .45 * envelope * wave}


def scan_state(seconds):
    envelope = math.sin(math.pi * seconds / 4) ** 2
    y = 64 + 128 * envelope
    return {"y1": y, "y2": y, "opacity": .14 * envelope}


def prepare():
    root = ET.parse(ROOT / "secchecker-mark.svg").getroot()
    root.set("width", str(SIZE))
    root.set("height", str(SIZE))
    root.find(SVG + "title").text = "Animated trust-boundary scan mark"
    root.find(SVG + "desc").text = (
        "Fixed scan brackets surround a dot field that gently converges toward the center. "
        "A faint scan line passes through the field in a four-second loop."
    )
    # Keep the scan stroke behind the original mark, including its central pixel.
    scan = ET.Element(SVG + "line", {
        "x1": "56", "x2": "200", "y1": "64", "y2": "64",
        "stroke": "#111111", "stroke-width": "1", "opacity": "0",
    })
    root.insert(3, scan)
    return root, scan


def render_frame(source, seconds):
    root = copy.deepcopy(source)
    for dot in root.iter(SVG + "circle"):
        for attribute, value in dot_state(dot, seconds).items():
            dot.set(attribute, str(value))
    scan = root.find(SVG + "line")
    for attribute, value in scan_state(seconds).items():
        scan.set(attribute, str(value))
    png = resvg_py.svg_to_bytes(svg_string=ET.tostring(root, encoding="unicode"))
    return Image.open(BytesIO(png)).convert("RGBA")


def add_keyframes(element, states):
    for attribute in states[0]:
        ET.SubElement(element, SVG + "animate", {
            "attributeName": attribute,
            "values": ";".join(f"{state[attribute]:.4f}" for state in states),
            "dur": "4s", "repeatCount": "indefinite",
        })


def main():
    original = (ROOT / "secchecker-mark.svg").read_bytes()
    source, scan = prepare()
    ticks = range(DURATION_MS // FRAME_MS)
    frames = [render_frame(source, tick * FRAME_MS / 1000) for tick in ticks]
    # Preserve the rounded silhouette. GIF supports binary transparency; index
    # 255 is reserved so no opaque palette colour is accidentally transparent.
    palette_sheet = Image.new("RGB", (SIZE * len(frames), SIZE), "#F4F4EF")
    for i, frame in enumerate(frames):
        palette_sheet.paste(frame, (i * SIZE, 0), frame)
    palette = palette_sheet.quantize(colors=64)
    encoded = []
    for frame in frames:
        matte = Image.new("RGB", frame.size, "#F4F4EF")
        matte.paste(frame, mask=frame.getchannel("A"))
        converted = matte.quantize(palette=palette, dither=Image.Dither.NONE)
        converted.paste(255, mask=frame.getchannel("A").point(lambda alpha: 255 if alpha < 128 else 0))
        encoded.append(converted)
    encoded[0].save(ROOT / "secchecker-mark.gif", save_all=True, append_images=encoded[1:],
                    duration=FRAME_MS, loop=0, transparency=255, disposal=2, optimize=False)
    frames[0].save(ROOT / "secchecker-mark-static.png", optimize=True)

    # SVG uses the same samples plus the closing state for an identical loop.
    times = [tick * FRAME_MS / 1000 for tick in range(len(frames) + 1)]
    for dot in source.iter(SVG + "circle"):
        add_keyframes(dot, [dot_state(dot, seconds) for seconds in times])
    add_keyframes(scan, [scan_state(seconds) for seconds in times])
    (ROOT / "secchecker-mark-animated.svg").write_text(ET.tostring(source, encoding="unicode"), encoding="utf-8")

    with Image.open(ROOT / "secchecker-mark.gif") as gif:
        assert gif.size == (SIZE, SIZE) and gif.info["loop"] == 0
        assert gif.n_frames == len(frames)
        total = 0
        for i in range(gif.n_frames):
            gif.seek(i)
            assert gif.convert("RGBA").getpixel((0, 0))[3] == 0
            total += gif.info["duration"]
        assert total == DURATION_MS
    assert ImageChops.difference(frames[0].convert("RGB"), frames[25].convert("RGB")).getbbox()
    # Every pixel outside the dot-field window, including the brackets, stays fixed.
    fixed = frames[0].convert("RGB")
    for frame in frames:
        difference = ImageChops.difference(fixed, frame.convert("RGB"))
        difference.paste((0, 0, 0), (54, 54, 202, 202))
        assert not difference.getbbox()
    assert (ROOT / "secchecker-mark.svg").read_bytes() == original
    print(f"Verified: {len(frames)} frames, 4s loop, fixed brackets, transparent corners.")
    print(f"secchecker-mark.gif: {(ROOT / 'secchecker-mark.gif').stat().st_size / 1024:.1f} KiB")


if __name__ == "__main__":
    main()
