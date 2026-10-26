#!/usr/bin/env python3
"""Verify worker stack layout and parameter conventions."""

def test_worker_stack_size():
    # 512KB per guest worker thread
    STACK_SIZE = 512 * 1024
    PAGE_SIZE = 16 * 1024
    assert STACK_SIZE % PAGE_SIZE == 0

def test_upcall_flags():
    # Bit 22 is workloop, bit 19 is kevent
    WORKLOOP = 1 << 22
    assert WORKLOOP == 0x400000

if __name__ == '__main__':
    test_worker_stack_size()
    test_upcall_flags()
    print("Worker spawn tests passed")
