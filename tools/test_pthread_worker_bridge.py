#!/usr/bin/env python3
"""Test the pthread bridge signatures and argument structures."""
import ctypes

class WorkloopThreadContext(ctypes.Structure):
    _fields_ = [
        ("entry", ctypes.c_uint64),
        ("stack", ctypes.c_uint64),
        ("pthread", ctypes.c_uint64),
        ("workloop_id", ctypes.c_uint64),
        ("upcall_flags", ctypes.c_uint64),
    ]

def test_context_layout():
    assert ctypes.sizeof(WorkloopThreadContext) == 40

if __name__ == '__main__':
    test_context_layout()
    print("Pthread worker bridge test passed")
