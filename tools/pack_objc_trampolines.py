#!/usr/bin/env python3
"""Embed an owned iOS ObjC trampoline image and immutable AOT page groups."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

PAGE = 0x4000


def inspect(data):
    if len(data) < 32:
        raise ValueError('Truncated trampoline Mach-O')
    magic, cpu, subtype, kind, count, size, _, _ = struct.unpack_from('<8I', data)
    if (magic, cpu, subtype & 0xffffff, kind) != (0xfeedfacf, 0x100000c, 2, 6):
        raise ValueError('Expected an ARM64e trampoline dylib')
    if count > 64 or size > len(data) - 32:
        raise ValueError('Invalid trampoline load commands')
    segments, signature, symbols, identity, uuid, platform = [], None, None, None, None, None
    at = 32
    for _ in range(count):
        if at + 8 > 32 + size:
            raise ValueError('Truncated trampoline load command')
        command, length = struct.unpack_from('<II', data, at)
        if length < 8 or at + length > 32 + size:
            raise ValueError('Invalid trampoline command bounds')
        if command == 25:
            if length < 72:
                raise ValueError('Truncated trampoline segment')
            _, _, name, address, vm_size, fileoff, filesize, maxprot, prot, _, _ = struct.unpack_from('<II16sQQQQiiII', data, at)
            if fileoff + filesize > len(data) or filesize > vm_size or maxprot != prot:
                raise ValueError('Invalid trampoline segment bounds')
            segments.append((name.rstrip(b'\0').decode(), address, vm_size, fileoff, filesize, prot))
        elif command == 0x1d:
            signature = struct.unpack_from('<II', data, at + 8)
        elif command == 2:
            symbols = struct.unpack_from('<4I', data, at + 8)
        elif command == 0xd:
            offset, = struct.unpack_from('<I', data, at + 8)
            identity = data[at+offset:at+length].split(b'\0')[0]
        elif command == 0x1b:
            uuid = data[at+8:at+24].hex()
        elif command == 0x32:
            platform, = struct.unpack_from('<I', data, at+8)
        elif command == 0x2c:
            raise ValueError('Encrypted trampoline image')
        at += length
    if (at != 32 + size or identity != b'/usr/lib/libobjc-trampolines.dylib' or platform != 2
            or not uuid or not signature or not symbols or len(segments) != 2):
        raise ValueError('Unsupported trampoline image identity')
    text, linkedit = segments
    if (text != ('__TEXT', 0, 3*PAGE, 0, 3*PAGE, 5) or linkedit[:4] != ('__LINKEDIT', 3*PAGE, 2*PAGE, 3*PAGE)
            or linkedit[5] != 1):
        raise ValueError('Unsupported trampoline VM layout')
    symoff, nsyms, stroff, strsize = symbols
    if nsyms > 1024 or symoff + nsyms*16 > len(data) or stroff+strsize > len(data):
        raise ValueError('Invalid trampoline symbol table')
    exports = {}
    for i in range(nsyms):
        index, typ, _, _, value = struct.unpack_from('<IBBHQ', data, symoff+i*16)
        if index >= strsize:
            raise ValueError('Invalid trampoline symbol string')
        name = data[stroff+index:stroff+strsize].split(b'\0')[0].decode()
        if typ & 1 and typ & 0xe == 0xe:
            exports[name] = value
    if exports != {'__objc_blockTrampolineImpl': PAGE, '__objc_blockTrampolineStart': PAGE+32,
                   '__objc_blockTrampolineLast': 2*PAGE-8}:
        raise ValueError('Unsupported trampoline exports')
    sigoff, sigsize = signature
    if sigsize < 12 or sigoff + sigsize != len(data):
        raise ValueError('Invalid trampoline signature extent')
    magic, length, slots = struct.unpack_from('>3I', data, sigoff)
    if magic != 0xfade0cc0 or length > sigsize or slots > 64 or 12+slots*8 > length:
        raise ValueError('Invalid trampoline signature superblob')
    code_end = None
    for i in range(slots):
        kind, offset = struct.unpack_from('>2I', data, sigoff+12+i*8)
        if offset+44 > length:
            continue
        blob = sigoff+offset
        if kind == 0 and struct.unpack_from('>I', data, blob)[0] == 0xfade0c02:
            limit, = struct.unpack_from('>I', data, blob+32)
            shift = data[blob+39]
            if shift > 16 or limit != sigoff:
                raise ValueError('Invalid trampoline code limit')
            code_end = (limit+(1<<shift)-1) & ~((1<<shift)-1)
    if code_end is None:
        raise ValueError('Missing trampoline CodeDirectory')
    return dict(uuid=uuid, fileSize=len(data), textSize=3*PAGE, span=5*PAGE,
                signatureOffset=sigoff, signatureSize=sigsize, codeEnd=code_end,
                sha256=hashlib.sha256(data).hexdigest())


def pack(image, output, pools=8):
    if not 1 <= pools <= 64:
        raise ValueError('Trampoline pool count must be between 1 and 64')
    meta = inspect(image.read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    source = str(image.resolve()).replace('\\', '\\\\').replace('"', '\\"')
    asm = ['// Generated: original Apple instructions, including PAC, are unchanged.']
    layout = ['SECTIONS {']
    header = ['#pragma once', '#include <cstdint>', '#include <cstddef>', 'extern "C" const uint8_t hm_objc_image[];']
    for name, offset, size, file_size, flags in [('image_text',0,3*PAGE,3*PAGE,'ax'),
                                               ('image_linkedit',3*PAGE,2*PAGE,meta['fileSize']-3*PAGE,'a')]:
        asm += [f'.section .hm_objc_{name},"{flags}",%progbits', '.p2align 14']
        if not offset:
            asm += ['.global hm_objc_image', '.hidden hm_objc_image', 'hm_objc_image:']
        asm += [f'.incbin "{source}", {offset}, {file_size}', f'.zero {size-file_size}']
        addr = 'ALIGN(0x4000)' if not offset else f'(ADDR(.hm_objc_image_text) + {offset})'
        layout.append(f'  .hm_objc_{name} {addr} : {{ KEEP(*(.hm_objc_{name})) }}')
    for i in range(pools):
        header.append(f'extern "C" uint8_t hm_objc_pool_{i}[];')
        asm += [f'.section .hm_objc_pool_{i}_data,"aw",%progbits', '.p2align 14',
                f'.global hm_objc_pool_{i}', f'.hidden hm_objc_pool_{i}', f'hm_objc_pool_{i}:', f'.zero {PAGE}',
                f'.section .hm_objc_pool_{i}_text,"ax",%progbits', '.p2align 14',
                f'.incbin "{source}", 0, {meta["textSize"]}']
        layout += [f'  .hm_objc_pool_{i}_data ALIGN(0x4000) : {{ KEEP(*(.hm_objc_pool_{i}_data)) }}',
                   f'  .hm_objc_pool_{i}_text (ADDR(.hm_objc_pool_{i}_data) + {PAGE}) : {{ KEEP(*(.hm_objc_pool_{i}_text)) }}']
    asm.append('.section .note.GNU-stack,"",%progbits')
    layout += ['}', 'INSERT AFTER .text;']
    for name in ['fileSize','textSize','span','signatureOffset','signatureSize','codeEnd']:
        header.append(f'constexpr uint64_t HM_OBJC_{name.upper()} = {meta[name]}ULL;')
    header += [f'constexpr size_t HM_OBJC_POOL_COUNT = {pools};',
               'static uint8_t *const HM_OBJC_POOLS[] = {'+','.join(f'hm_objc_pool_{i}' for i in range(pools))+'};']
    (output/'objc_trampolines.S').write_text('\n'.join(asm)+'\n')
    (output/'objc_trampolines.ld').write_text('\n'.join(layout)+'\n')
    (output/'objc_trampolines.h').write_text('\n'.join(header)+'\n')
    (output/'manifest.json').write_text(json.dumps({**meta,'pools':pools},indent=2)+'\n')
    return meta


def verify_elf(elf, image, pools=8):
    """Check immutable source bytes, ELF load permissions, and clone geometry."""
    original = image.read_bytes()
    identity = inspect(original)
    data = elf.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or len(data) < 64:
        raise ValueError('Expected a little-endian ELF64 wrapper')
    phoff, shoff = struct.unpack_from('<QQ', data, 32)
    phsize, phnum, shsize, shnum, strings_index = struct.unpack_from('<5H', data, 54)
    if phsize != 56 or shsize != 64 or strings_index >= shnum or shoff+shnum*shsize > len(data) or phoff+phnum*phsize > len(data):
        raise ValueError('Invalid ELF wrapper tables')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff+i*shsize) for i in range(shnum)]
    strings = sections[strings_index]
    names = data[strings[4]:strings[4]+strings[5]]
    named = {}
    for section in sections:
        name = names[section[0]:].split(b'\0')[0].decode()
        if name.startswith('.hm_objc_'):
            if name in named: raise ValueError('Duplicate ObjC AOT section')
            named[name] = section
    loads = [struct.unpack_from('<IIQQQQQQ', data, phoff+i*phsize) for i in range(phnum)]
    loads = [load for load in loads if load[0] == 1]
    if any(load[1] & 3 == 3 for load in loads):
        raise ValueError('Writable executable ELF load segment')
    def check(name, expected, flags):
        section = named.get(name)
        if section is None or section[5] != len(expected) or section[4]+section[5] > len(data):
            raise ValueError('Missing or malformed ObjC AOT section: '+name)
        if data[section[4]:section[4]+section[5]] != expected:
            raise ValueError('ObjC AOT bytes differ from the original: '+name)
        if not any(load[3] <= section[3] and section[3]+section[5] <= load[3]+load[5]
                   and load[2]+section[3]-load[3] == section[4] and load[1] == flags for load in loads):
            raise ValueError('Incorrect ObjC AOT load permissions: '+name)
        return section[3]
    text = original[:3*PAGE]
    base = check('.hm_objc_image_text', text, 5)
    link = check('.hm_objc_image_linkedit', original[3*PAGE:].ljust(2*PAGE,b'\0'), 4)
    if link != base+3*PAGE: raise ValueError('ObjC AOT image layout changed')
    for i in range(pools):
        datum = check(f'.hm_objc_pool_{i}_data', bytes(PAGE), 6)
        code = check(f'.hm_objc_pool_{i}_text', text, 5)
        if code != datum+PAGE: raise ValueError('ObjC trampoline/data offset changed')
    return {**identity, 'pools': pools, 'elf': str(elf.resolve()), 'verified': True,
            'codeBytesUnchanged': True, 'noWritableExecutableLoads': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path, nargs='?')
    parser.add_argument('--verify-elf', type=Path)
    parser.add_argument('--pools', type=int, default=8)
    args = parser.parse_args()
    if args.verify_elf:
        result = verify_elf(args.verify_elf,args.image,args.pools)
    else:
        if args.output is None: parser.error('output is required when packing')
        result = pack(args.image,args.output,args.pools)
    print(json.dumps(result,indent=2))
