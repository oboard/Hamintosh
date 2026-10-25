#!/usr/bin/env python3
"""Generate an owned ARM64e MH_DYLINKER using an authenticated chained rebase."""
import argparse
from pathlib import Path
import struct
import subprocess


def generate(output: Path, clang: str, objcopy: str):
    output.mkdir(parents=True, exist_ok=True)
    source = output / 'entry.S'
    source.write_text('''.arch armv8.3-a
.arch_extension pauth
.text
.org 0x1000
.Lentry:
    pacibsp
    stp x29,x30,[sp,#-16]!
    adr x8,.Lslot
    ldr x9,[x8]
    mov x10,x8
    movk x10,#0x1234,lsl #48
    blraa x9,x10
    ldp x29,x30,[sp],#16
    autibsp
    ret
.org 0x1100
.Lcallee:
    mov w0,#42
    ret
.org 0x4000
.Lslot:
    .quad 0x8001123400001100
''')
    obj = output / 'entry.o'
    raw = output / 'entry.bin'
    subprocess.run([clang, '--target=aarch64-linux-ohos', '-c', str(source), '-o', str(obj)], check=True)
    subprocess.run([objcopy, '--dump-section', f'.text={raw}', str(obj)], check=True)
    text = raw.read_bytes()
    if len(text) != 0x4008:
        raise ValueError('Unexpected bootstrap fixture code size')
    # A local ADR uses no linker relocations; ensure its encoded target is our slot.
    adr, = struct.unpack_from('<I', text, 0x1008)
    immediate = ((adr >> 5) & 0x7ffff) << 2 | ((adr >> 29) & 3)
    if immediate & (1 << 20): immediate -= 1 << 21
    if 0x1008 + immediate != 0x4000:
        raise ValueError('Unresolved bootstrap fixture ADR')
    starts = struct.pack('<4I', 3, 0, 16, 0) + struct.pack('<IHHQIH', 24, 0x4000, 9, 0x4000, 0, 1) + struct.pack('<H', 0)
    payload = struct.pack('<7I', 0, 28, 28 + len(starts), 28 + len(starts), 0, 1, 0) + starts
    def segment(name, vmoff, fileoff, size, prot):
        return struct.pack('<II16sQQQQiiII', 0x19, 72, name, 0x100000000 + vmoff,
                           0x4000, fileoff, size, prot, prot, 0, 0)
    state = bytearray(272)
    struct.pack_into('<Q', state, 256, 0x100001000)
    commands = segment(b'__TEXT', 0, 0, 0x4000, 5) + \
        segment(b'__AUTH_CONST', 0x4000, 0x4000, 0x4000, 3) + \
        segment(b'__LINKEDIT', 0x8000, 0x8000, len(payload), 1) + \
        struct.pack('<4I', 5, 288, 6, 68) + state + \
        struct.pack('<4I', 0x80000034, 16, 0x8000, len(payload)) + \
        struct.pack('<6I', 0x32, 24, 2, 27 << 16, 27 << 16, 0)
    header = struct.pack('<8I', 0xfeedfacf, 0x0100000c, 0x80000002, 7, 6, len(commands), 0, 0)
    image = bytearray(text[:0x4000] + text[0x4000:].ljust(0x4000, b'\0') + payload)
    image[:len(header+commands)] = header + commands
    (output / 'bootstrap.macho').write_bytes(image)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--clang', required=True)
    parser.add_argument('--objcopy', required=True)
    args = parser.parse_args()
    generate(args.output, args.clang, args.objcopy)
