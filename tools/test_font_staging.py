#!/usr/bin/env python3
"""Verify sysroot font deployment invariants."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_font_in_manifest():
    manifest_path = ROOT / "harmonios/src/main/resources/rawfile/sysroot/manifest.json"
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    assert "System/Library/Fonts/SF-Pro.ttf" in manifest["files"]

def test_font_file_exists():
    font_file = ROOT / "harmonios/src/main/resources/rawfile/sysroot/System/Library/Fonts/SF-Pro.ttf"
    assert font_file.exists()
    assert font_file.stat().st_size > 0

if __name__ == '__main__':
    test_font_in_manifest()
    test_font_file_exists()
    print("Font staging tests passed")
