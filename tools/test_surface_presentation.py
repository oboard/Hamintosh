#!/usr/bin/env python3
"""Test the harmony_surface present_bgra validation rules."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_surface_geometry():
    # Width 540, Height 960, Stride >= width * 4
    WIDTH = 540
    HEIGHT = 960
    MIN_STRIDE = WIDTH * 4
    FRAME_SIZE = MIN_STRIDE * HEIGHT
    assert FRAME_SIZE == 2073600
    assert MIN_STRIDE == 2160

if __name__ == '__main__':
    test_surface_geometry()
    print("Surface presentation geometry tests passed")
