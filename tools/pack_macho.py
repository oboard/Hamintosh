#!/usr/bin/env python3
"""Preserve ARM64 Mach-O segment layout inside a signed ELF. Does not link iOS imports."""
import argparse
import json
from pathlib import Path
import subprocess
import struct

ROOT = Path(__file__).resolve().parents[1]


def objc_ro_slots(data, meta, fixups):
    """Describe unsigned ARM64 class RO pointers needing the ARM64e ABI."""
    base = fixups['preferredBase']
    segments = meta['segments']
    def contains(offset, size, writable=False):
        return any(s['vmAddress'] <= base + offset and
                   base + offset + size <= s['vmAddress'] + s['vmSize'] and
                   s['protection'] & (2 if writable else 1) and not s['protection'] & 4
                   for s in segments)
    rebases = {f['vmOffset']: f for f in fixups['fixups']}
    def target(slot):
        f = rebases.get(slot)
        if f is None or f['target']['kind'] != 'rebase':
            return None
        if f['authentication'] is not None or f['target']['high8'] != 0:
            raise ValueError('Expected unsigned local Objective-C rebase')
        return f['target']['offset']
    start = meta['sliceOffset']
    count, command_size = struct.unpack_from('<II', data, start + 16)
    end = start + 32 + command_size
    if end > len(data) or count > 4096:
        raise ValueError('Invalid Objective-C load commands')
    at = start + 32
    pending = []
    for _ in range(count):
        if at + 8 > end:
            raise ValueError('Truncated Objective-C load command')
        command, length = struct.unpack_from('<II', data, at)
        if length < 8 or at + length > end:
            raise ValueError('Invalid Objective-C load command')
        if command == 25:
            if length < 72:
                raise ValueError('Truncated Objective-C segment')
            sections = struct.unpack_from('<I', data, at + 64)[0]
            if 72 + sections * 80 > length:
                raise ValueError('Invalid Objective-C sections')
            for index in range(sections):
                section = at + 72 + index * 80
                if data[section:section + 16].rstrip(b'\0') != b'__objc_classlist':
                    continue
                address, size = struct.unpack_from('<QQ', data, section + 32)
                offset = address - base
                if offset % 8 or size % 8 or size > 32768 or not contains(offset, size):
                    raise ValueError('Invalid Objective-C class list')
                for slot in range(offset, offset + size, 8):
                    value = target(slot)
                    if value is None:
                        raise ValueError('Objective-C class list is not a local rebase')
                    pending.append(value)
        at += length
    visited, slots = set(), []
    for offset in pending:
        if offset in visited:
            continue
        visited.add(offset)
        if len(visited) > 4096 or offset % 8 or not contains(offset, 40, True):
            raise ValueError('Objective-C class escapes writable App data')
        value = target(offset + 32)
        if value is None or not contains(value & ~7, 72):
            raise ValueError('Objective-C RO pointer escapes App metadata')
        slots.append((offset + 32, value))
        isa = target(offset)
        if isa is not None:
            pending.append(isa)
    return slots


def pack(image: Path, output: Path, role="target"):
    inspected = subprocess.run([
        "cargo", "run", "--quiet", "--locked", "--manifest-path", str(ROOT / "runtime/Cargo.toml"),
        "--bin", "hm-inspect", "--", str(image.resolve()),
    ], capture_output=True, text=True, check=False)
    if inspected.returncode not in (0, 3):
        raise ValueError(f"Mach-O inspection failed: {inspected.stdout}\n{inspected.stderr}")
    meta = json.loads(inspected.stdout)["image"]
    subtype = meta["cpuSubtype"] & 0x00FFFFFF
    if meta["encrypted"] or (role == "target" and (subtype != 0 or meta["fileType"] != 2)) or \
            (role in ("bootstrap", "dyld") and (subtype not in (0, 2) or meta["fileType"] != 7)):
        raise ValueError("AOT requires an ARM64 executable or an ARM64/ARM64e bootstrap dyld")
    segments = [s for s in meta["segments"] if s["protection"] and s["vmSize"]]
    text = next(s for s in segments if s["name"] == "__TEXT")
    base = text["vmAddress"]
    segments.sort(key=lambda s: s["vmAddress"])
    if segments[0] is not text or text["fileOffset"] != 0:
        raise ValueError("Expected __TEXT as the first mapped segment at file offset zero")
    span = max(s["vmAddress"] + s["vmSize"] for s in segments) - base
    if span > 512 * 1024 * 1024 or meta["entryFileOffset"] is None:
        raise ValueError("Unsupported image span or missing entry point")
    output.mkdir(parents=True, exist_ok=True)
    path = str(image.resolve()).replace("\\", "\\\\").replace('"', '\\"')
    assembly = ["// Generated; original Mach-O segment bytes are unchanged."]
    layout = ["SECTIONS {"]
    for i, segment in enumerate(segments):
        protection = segment["protection"]
        if protection & 6 == 6:
            raise ValueError("Writable executable segments cannot be packaged")
        flags = "ax" if protection & 4 else ("aw" if protection & 2 else "a")
        name = f".hm_{role}_{i}"
        assembly += [f'.section {name},"{flags}",%progbits', '.p2align 2']
        if i == 0:
            assembly += [f".global hm_{role}_image", f".hidden hm_{role}_image", f"hm_{role}_image:"]
        if segment["fileSize"]:
            assembly.append(f'.incbin "{path}", {meta["sliceOffset"] + segment["fileOffset"]}, {segment["fileSize"]}')
        assembly.append(f'.zero {segment["vmSize"] - segment["fileSize"]}')
        address = "ALIGN(0x4000)" if i == 0 else f"(ADDR(.hm_{role}_0) + {segment['vmAddress'] - base})"
        layout.append(f"  {name} {address} : {{ KEEP(*({name})) }}")
    header = '#pragma once\n#include <stdint.h>\n' + \
        f'extern "C" const uint8_t hm_{role}_image[];\n#define HM_{role.upper()}_SPAN {span}ULL\n' + \
        f'#define HM_{role.upper()}_ENTRY_OFFSET {meta["entryVmAddress"] - base}ULL\n'
    if role == 'target':
        fixups = json.loads(subprocess.check_output([
            'cargo', 'run', '--quiet', '--locked', '--manifest-path', str(ROOT / 'runtime/Cargo.toml'),
            '--bin', 'hm-fixups', '--', str(image.resolve())], text=True))
        ro = objc_ro_slots(image.read_bytes(), meta, fixups)
        slots = [(slot, target, 0x61f8, 0) for slot, target in ro]
        cache_primary = ROOT / 'artifacts/ios27-system/cache/dyld_shared_cache_arm64e'
        cache_uuid = bytes(16)
        if ro and cache_primary.is_file():
            import pack_cache
            cache = json.loads(pack_cache.rust('hm-cache-info', cache_primary.resolve()))
            cache_uuid = bytes.fromhex(cache['files'][0]['uuid'])
            by_slot = {f['vmOffset']: f for f in fixups['fixups']}
            classes = {slot - 32 for slot, _ in ro}
            for cls in sorted(classes):
                for field, diversity in [(0, 0x6ae1), (8, 0xb5ab)]:
                    f = by_slot.get(cls + field)
                    if f is None:
                        continue  # Null superclass/ISA has no fixup.
                    if f['authentication'] is not None:
                        raise ValueError('Expected unsigned ARM64 class relationship')
                    target = f['target']
                    if target['kind'] == 'rebase':
                        if target['offset'] not in classes or target['high8']:
                            raise ValueError('Class relationship escapes audited App classes')
                        slots.append((cls + field, target['offset'], diversity, 0))
                    else:
                        imp = fixups['imports'][target['import']]
                        ordinal = imp['libraryOrdinal']
                        if (not 0 < ordinal <= len(meta['dependencies']) or imp['weak'] or
                                imp['addend'] or target['addend'] or not imp['name'].startswith('_OBJC_')):
                            raise ValueError('Unsupported Objective-C superclass binding')
                        path = meta['dependencies'][ordinal - 1]['path']
                        offset = pack_cache.export_offset(cache, path, imp['name'])
                        slots.append((cls + field, offset, diversity, 1))
        header += 'struct HmTargetObjcPointer { uint64_t slot, target, diversity, cacheTarget; };\n'
        header += f'#define HM_TARGET_OBJC_POINTER_COUNT {len(slots)}\n'
        header += 'static constexpr uint8_t HM_TARGET_OBJC_CACHE_UUID[] = {' + ','.join(map(str, cache_uuid)) + '};\n'
        header += 'static constexpr HmTargetObjcPointer HM_TARGET_OBJC_POINTERS[] = {\n'
        header += ''.join(f'{{{slot}ULL, {target}ULL, {diversity}ULL, {origin}ULL}},\n'
                          for slot, target, diversity, origin in slots) or '{0, 0, 0, 0},\n'
        header += '};\n'
    if role in ("bootstrap", "dyld"):
        assembly += [f'.section .rodata.hm_{role}_original,"a",%progbits', '.p2align 3',
                     f'.global hm_{role}_original', f'.hidden hm_{role}_original',
                     f'hm_{role}_original:', f'.incbin "{path}"']
        header += f'extern "C" const uint8_t hm_{role}_original[];\n' + \
                  f'#define HM_{role.upper()}_ORIGINAL_SIZE {image.stat().st_size}ULL\n'
    if role == "dyld":
        header += 'struct HmDyldSegment { uint64_t offset, size, protection; };\n'
        header += 'static constexpr HmDyldSegment HM_DYLD_SEGMENTS[] = {\n'
        header += ''.join(f'{{{s["vmAddress"] - base}ULL, {s["vmSize"]}ULL, {s["protection"]}ULL}},\n' for s in segments)
        header += '};\n'
    assembly.append('.section .note.GNU-stack,"",%progbits')
    layout += ["} INSERT BEFORE .data;"]
    (output / f"packed_{role}.S").write_text("\n".join(assembly) + "\n")
    (output / f"packed_{role}.ld").write_text("\n".join(layout) + "\n")
    (output / f"packed_{role}.h").write_text(header)
    (output / "layout.json").write_text(json.dumps(meta, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--role", choices=["target", "bootstrap", "dyld"], default="target")
    args = parser.parse_args()
    pack(args.image, args.output, args.role)
