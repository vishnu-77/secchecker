"""Check illustrated CLI results and generated README media, without executing examples."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from PIL import Image, ImageChops

from scenarios import SCENARIOS, STAGE_SECONDS

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
SVG = "{http://www.w3.org/2000/svg}"


def verify_scenarios():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    for scenario in SCENARIOS:
        assert (REPO / scenario.fixture).is_file()
        assert (REPO / scenario.safe_fixture).is_file()
        with tempfile.TemporaryDirectory(prefix="readme-example-") as directory:
            folder = Path(directory)
            (folder / "config.yml").write_text("# Isolated example scan\n", encoding="utf-8")
            for name, source, expected in (("vulnerable", scenario.risky, 1), ("safe", scenario.safer, 0)):
                (folder / f"{name}.py").write_text(source + "\n", encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-m", "secchecker.cli", f"{name}.py", "--type", "llm",
                     "--config", "config.yml", "--format", "json", "-o", f"{name}.json"],
                    cwd=folder, env=env, capture_output=True, text=True, timeout=45,
                )
                assert result.returncode == expected, (scenario.slug, name, result.stdout, result.stderr)
                if expected:
                    report = json.loads((folder / f"{name}.json").read_text(encoding="utf-8"))
                    finding = report["findings"][f"{name}.py"][scenario.finding]
                    assert finding["severity"] == scenario.severity
                    assert finding["count"] > 0
                else:
                    assert "[+] No findings detected." in result.stdout
                    assert not (folder / f"{name}.json").exists()
        print(f"Verified {scenario.slug}: {scenario.severity} finding; safer example clean.", flush=True)


def verify_assets():
    specs = [("secchecker-hero", (1200, 520), (3, 3, 3, 3))]
    specs += [(s.slug, (1200, 720), STAGE_SECONDS) for s in SCENARIOS]
    total_bytes = 0
    for stem, size, durations in specs:
        path = ROOT / f"{stem}.gif"
        total_bytes += path.stat().st_size
        with Image.open(path) as gif:
            assert gif.format == "GIF" and gif.size == size
            assert gif.info["loop"] == 0
            elapsed = 0
            starts = [1000 * sum(durations[:i]) for i in range(len(durations))]
            samples = []
            for i in range(gif.n_frames):
                gif.seek(i)
                if elapsed in starts:
                    samples.append(gif.convert("RGB").copy())
                elapsed += gif.info["duration"]
            assert elapsed == sum(durations) * 1000
            assert len(samples) == len(durations)
            assert all(ImageChops.difference(a, b).getbbox() for a, b in zip(samples, samples[1:]))
        with Image.open(ROOT / f"{stem}-static.png") as still:
            assert still.size == (size if stem == "secchecker-hero" else (1200, 2160))
        tree = ET.parse(ROOT / f"{stem}-animated.svg")
        animations = tree.findall(f".//{SVG}animate")
        assert animations and all(a.attrib["dur"] == f"{sum(durations)}s" for a in animations)
        assert tree.find(f"{SVG}title") is not None
        print(f"Verified {stem}: {sum(durations)}s, {size[0]} x {size[1]}, {path.stat().st_size / 1024:.1f} KiB.")
    assert total_bytes < 1.5 * 1024 * 1024, f"Combined GIF budget exceeded: {total_bytes} bytes"
    for name in ("README.md", "brand/README.md"):
        path = REPO / name
        source = path.read_text(encoding="utf-8")
        for target in re.findall(r'(?:src="|\]\()([^"\)]+)', source):
            if not target.startswith(("https:", "http:", "#")):
                assert (path.parent / target.split("#")[0]).exists(), (name, target)
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert not re.search(r"^#{1,6}\s+.*(?:\bHero\b|15-second demonstration)", readme, re.M)
    for scenario in SCENARIOS:
        assert scenario.risky in readme and scenario.safer in readme
    print(f"README links and SVGs verified. Combined GIF size: {total_bytes / 1024:.1f} KiB.")
