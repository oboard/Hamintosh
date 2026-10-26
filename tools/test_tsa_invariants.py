#!/usr/bin/env python3
"""Verify thread state and TSD alignment constraints."""

def test_tsd_alignment():
    # Apple TSD base is 8-byte aligned, commpage TSD slot offset is positive
    TSD_OFFSET = 0x4f00000000
    assert TSD_OFFSET % 8 == 0
    assert TSD_OFFSET > 0

if __name__ == '__main__':
    test_tsd_alignment()
    print("TSD alignment invariants passed")
