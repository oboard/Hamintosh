#!/usr/bin/env python3
"""Preserve ARM64 Mach-O segment layout inside a signed ELF. Does not link iOS imports."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


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
