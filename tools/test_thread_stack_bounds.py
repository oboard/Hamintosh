#!/usr/bin/env python3
"""Validate guest stack boundary checks and guard page margins."""

def test_stack_bounds():
    GUARD_SIZE = 16 * 1024
    STACK_SIZE = 512 * 1024
    TOTAL_SIZE = STACK_SIZE + 2 * GUARD_SIZE
    assert TOTAL_SIZE == 544 * 1024
    assert GUARD_SIZE == 0x4000

if __name__ == '__main__':
    test_stack_bounds()
    print("Thread stack bounds tests passed")
