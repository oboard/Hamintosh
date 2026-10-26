#!/usr/bin/env python3
"""Offline static binary probe for Apple CoreAnimation rendering path in Harmonios.

Analyzes QuartzCore, IOSurface, CoreGraphics, and CoreText from extracted iOS 27 system
binaries and dyld shared cache to verify rendering backends, commit pathways,
software rendering viability, and required system/Mach dependencies.
"""
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LAYOUT_PATH = ROOT / "artifacts/ios27-cache-layout.json"
QC_DYLIB = ROOT / "artifacts/ios27-extract/System/Library/Frameworks/QuartzCore.framework/QuartzCore"
IOSURFACE_DYLIB = ROOT / "artifacts/ios27-extract/System/Library/Frameworks/IOSurface.framework/IOSurface"
IOKIT_DYLIB = ROOT / "artifacts/ios27-extract/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"

def load_cache_layout():
    if not LAYOUT_PATH.exists():
        return None
    with open(LAYOUT_PATH, "r") as f:
        return json.load(f)

def run_nm_filter(dylib_path, keywords):
    try:
        out = subprocess.check_output(["nm", "-g", str(dylib_path)], text=True)
    except Exception as e:
        return []
    matches = []
    for line in out.splitlines():
        if any(k in line for k in keywords):
            matches.append(line.strip())
    return matches

def probe_quartzcore():
    print("=== Probing QuartzCore Framework ===")
    callbacks = run_nm_filter(QC_DYLIB, ["kCARender", "CARenderSoftware", "CARenderOGL", "CARenderCARP"])
    print(f"Found {len(callbacks)} render backend symbols in QuartzCore:")
    for sym in callbacks:
        print(f"  {sym}")

def probe_iosurface():
    print("\n=== Probing IOSurface Framework ===")
    symbols = run_nm_filter(IOSURFACE_DYLIB, ["IOSurfaceCreate", "IOSurfaceLock", "IOSurfaceGetBaseAddress", "IOConnect"])
    print(f"Found {len(symbols)} IOSurface symbols:")
    for sym in symbols[:15]:
        print(f"  {sym}")

def probe_iokit():
    print("\n=== Probing IOKit Traps ===")
    traps = run_nm_filter(IOKIT_DYLIB, ["IOConnectTrap", "IOServiceOpen"])
    for sym in traps[:10]:
        print(f"  {sym}")

if __name__ == "__main__":
    probe_quartzcore()
    probe_iosurface()
    probe_iokit()
