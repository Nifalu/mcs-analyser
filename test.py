#!/usr/bin/env python3
"""
Demonstrate 32-bit unsigned overflow.
$ python overflow32.py 0x80000005 0x80000002
"""

import sys

MASK32 = 0xFFFF_FFFF            # keeps only the lowest 32 bits


def u32(val: int) -> int:
    """Return val modulo 2³² (i.e., as an unsigned 32-bit value)."""
    return val & MASK32


def mul_u32(a: int, b: int) -> int:
    """Unsigned 32-bit multiplication with wrap-around."""
    return u32(a * b)


def main():
    # if the user gave numbers on the command line, use them; otherwise use a demo list
    inputs = [int(arg, 0) for arg in sys.argv[1:]] or [
        0x80000005,
        0x80000002,
        0x00000005,
    ]

    for x in inputs:
        y = mul_u32(x, 2)
        print(f"x = {x:#010x} ({x:>12,d})  ->  2*x (mod 2^32) = {y:#010x} ({y:>12,d})")


if __name__ == "__main__":
    main()
