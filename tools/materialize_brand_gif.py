"""Materialise the lightweight README animation from the committed base64 source.

Usage:
    python tools/materialize_brand_gif.py

This is kept separate because GitHub's text-oriented connector cannot create binary files
directly through the contents API. Running this once writes brand/secchecker-hero.gif.
"""
from base64 import b64decode
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / "brand" / "secchecker-hero.gif.b64"
target = ROOT / "brand" / "secchecker-hero.gif"
target.write_bytes(b64decode(source.read_text(encoding="utf-8").strip()))
print(target)
