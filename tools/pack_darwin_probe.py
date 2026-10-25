#!/usr/bin/env python3
"""Build audited syscall Mach-O fixtures and redirect their SVC sites before HAP signing."""
import argparse
from pathlib import Path
import struct
from prepare_ipa import make_probe

SVC = 0xD4001001  # svc #0x80
TRAP = 0xD4200000 | (0x484D << 5)  # brk #0x484d; handled only inside guest text
RET = 0xD65F03C0
FAIL = [0x52800000, RET]  # mov w0,#0; ret

# Branches verify that the handler also restores Darwin's carry-bit convention.
PROBES = {
    "getpid": [0xEB1F03FF, 0xD2800290, SVC, 0x54000042, RET] + FAIL,
    "unix_error": [0xD28FFFF0, SVC, 0x54000043, RET] + FAIL,
    "mach_self": [0x92800370, SVC, RET],
    "mach_error": [0x928FFFD0, SVC, 0x54000042, RET] + FAIL,
}


def generate(output: Path):
    output.mkdir(parents=True, exist_ok=True)
    assembly = ['// Generated from owned Mach-O fixtures; only SVC #0x80 is redirected.']
    header = ['#pragma once', '#include <stdint.h>']
    for name, instructions in PROBES.items():
        original = make_probe(struct.pack('<' + 'I' * len(instructions), *instructions))
        fixture = output / f'darwin_{name}.macho'
        fixture.write_bytes(original)
        symbol = f'hm_darwin_{name}_image'
        assembly += ['.section .text.hm_darwin,"ax",%progbits', '.p2align 14',
                     f'.global {symbol}', f'.hidden {symbol}', f'{symbol}:']
        path = str(fixture.resolve()).replace('\\', '\\\\').replace('"', '\\"')
        start = 0
        for i, instruction in enumerate(instructions):
            if instruction != SVC:
                continue
            at = 0x1000 + i * 4
            assembly += [f'.incbin "{path}",{start},{at-start}', f'.word {TRAP:#x}']
            start = at + 4
        assembly += [f'.incbin "{path}",{start},{len(original)-start}']
        header += [f'extern "C" const uint8_t {symbol}[{len(original)}];',
                   f'#define HM_DARWIN_{name.upper()}_CODE_SIZE {len(instructions)*4}']
    assembly += ['.section .note.GNU-stack,"",%progbits']
    (output / 'darwin_probes.S').write_text('\n'.join(assembly) + '\n')
    (output / 'darwin_probes.h').write_text('\n'.join(header) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    generate(args.output)
