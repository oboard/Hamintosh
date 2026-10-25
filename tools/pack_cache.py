#!/usr/bin/env python3
"""AOT-package selected iOS cache pages, retaining a single shared VM slide.

Default selection is dyld's code/data and mapped cache headers. Non-executable
pages live in a read-only blob and are copied only to selected VM ranges at
startup; shared LINKEDIT remains deferred. No Apple code is reconstructed. Darwin SVC #0x80 and thread
pointer reads in instruction sections are redirected to the host trap boundary.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PAGE = 0x4000
DEFERRED_SEGMENTS = {'__LINKEDIT', '__OBJC_RO', '__OBJC_RW'}


def rust(binary, *args):
    return subprocess.check_output([
        "cargo", "run", "--quiet", "--locked", "--manifest-path", str(ROOT / "runtime/Cargo.toml"),
        "--bin", binary, "--", *map(str, args)], text=True)


def location(cache, address, size):
    for file in cache["files"]:
        for mapping in file["mappings"]:
            if mapping["address"] <= address and address + size <= mapping["address"] + mapping["size"]:
                return file, mapping, mapping["fileOffset"] + address - mapping["address"]
    raise ValueError(f"VM range outside cache: {address:#x}+{size:#x}")


def read_vm(cache, address, size):
    file, _, offset = location(cache, address, size)
    with Path(file["path"]).open("rb") as source:
        source.seek(offset)
        result = source.read(size)
    if len(result) != size:
        raise ValueError("Truncated cache read")
    return result


def image_segments(cache, header_address, expected_kind, reexports=None):
    header = read_vm(cache, header_address, 32)
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack("<8I", header)
    if magic != 0xFEEDFACF or cpu != 0x100000C or kind != expected_kind or count > 4096 or size > 1024 * 1024:
        raise ValueError("Invalid cached ARM64 image header")
    data = read_vm(cache, header_address + 32, size)
    segments, instructions = [], []
    exports = None
    pos = 0
    for _ in range(count):
        if pos + 8 > len(data):
            raise ValueError("Truncated dyld command")
        command, length = struct.unpack_from("<II", data, pos)
        if length < 8 or length % 8 or pos + length > len(data):
            raise ValueError("Invalid dyld command size")
        if command == 25:
            if length < 72:
                raise ValueError("Truncated dyld segment")
            _, _, name, address, vm_size, fileoff, filesize, maxprot, prot, sections, _ = struct.unpack_from("<II16sQQQQiiII", data, pos)
            if filesize > vm_size or sections > (length - 72) // 80:
                raise ValueError("Invalid dyld segment contents")
            name = name.rstrip(b"\0").decode("ascii")
            location(cache, address, vm_size)
            segments.append({"name": name, "address": address, "size": vm_size, "protection": prot,
                             "fileOffset": fileoff, "fileSize": filesize})
            for i in range(sections):
                section = pos + 72 + i * 80
                section_addr, section_size = struct.unpack_from("<QQ", data, section + 32)
                section_flags = struct.unpack_from("<I", data, section + 64)[0]
                if section_addr < address or section_addr + section_size > address + vm_size:
                    raise ValueError("dyld section escapes segment")
                if section_flags & 0x80000400:
                    if not prot & 4 or section_size % 4:
                        raise ValueError("Invalid instruction section")
                    instructions.append((section_addr, section_size))
        elif command == 0x80000033:  # LC_DYLD_EXPORTS_TRIE
            if length != 16 or exports is not None:
                raise ValueError('Invalid or duplicate export trie command')
            exports = struct.unpack_from('<II', data, pos + 8)
        elif command == 0x8000001f:  # LC_REEXPORT_DYLIB
            if length < 24:
                raise ValueError('Truncated reexport command')
            name_offset = struct.unpack_from('<I', data, pos + 8)[0]
            if not 24 <= name_offset < length:
                raise ValueError('Invalid reexport name offset')
            name = data[pos + name_offset:pos + length]
            if b'\0' not in name:
                raise ValueError('Unterminated reexport name')
            if reexports is not None:
                reexports.append(name.split(b'\0', 1)[0].decode('utf-8'))
        pos += length
    if pos != len(data):
        raise ValueError("dyld command count mismatch")
    if exports is not None and exports[1]:
        matches = [s for s in segments if s['name'] == '__LINKEDIT' and
                   s['fileOffset'] <= exports[0] and
                   exports[0] + exports[1] <= s['fileOffset'] + s['fileSize']]
        if len(matches) != 1:
            raise ValueError('Export trie escapes LINKEDIT')
        segment = matches[0]
        segment['exportsAddress'] = segment['address'] + exports[0] - segment['fileOffset']
        segment['exportsSize'] = exports[1]
    return segments, instructions


def dyld_segments(cache):
    return image_segments(cache, cache['dyldHeaderAddress'], 7)


def select(cache, segments, full=False, pages=(), spans=(), stubs=False):
    base = cache["preferredBase"]
    if full:
        ranges = [(m["address"], m["address"] + m["size"]) for f in cache["files"] for m in f["mappings"]]
    else:
        # Include the primary header/metadata and dyld's own pages. Shared
        # LINKEDIT belongs to all images and is deliberately demand-loaded later.
        ranges = [(m["address"], m["address"] + m["size"]) for m in cache["files"][0]["mappings"]]
        # dyld inspects mapped subcache headers while configuring the cache.
        # Data-only subcache headers with no VM mapping remain on disk.
        ranges += [(m['address'], m['address'] + PAGE) for f in cache['files'][1:]
                   for m in f['mappings'] if m['fileOffset'] == 0 and m['size'] >= PAGE]
        ranges += [(s["address"] // PAGE * PAGE, (s["address"] + s["size"] + PAGE - 1) // PAGE * PAGE)
                   for s in segments if s["name"] not in DEFERRED_SEGMENTS]
    if stubs:
        ranges += [(m['address'], m['address'] + m['size']) for f in cache['files']
                   for m in f['mappings'] if m.get('flags', 0) & 8]
    for offset in pages:
        if type(offset) is not int or offset < 0 or offset % PAGE or offset + PAGE > cache['regionSize']:
            raise ValueError('Demand page must be an aligned cache-relative offset')
        ranges.append((base + offset, base + offset + PAGE))
    for start, end in spans:
        if (type(start) is not int or type(end) is not int or start < 0 or end <= start or
                start % PAGE or end % PAGE or end > cache['regionSize']):
            raise ValueError('Demand range must contain aligned cache-relative pages')
        ranges.append((base + start, base + end))
    result = []
    for start, end in sorted(ranges):
        file, mapping, offset = location(cache, start, end - start)
        # Cache CONST mappings are initially read-only on Apple systems but
        # permit a kernel relocation pass. The signed ELF must expose that
        # writable data during our corresponding relocation pass as well.
        prot = mapping["maxProtection"]
        if prot & 6 == 6 or start % PAGE or (end - start) % PAGE:
            raise ValueError("Cache mappings must be page aligned and never W+X")
        if result and start <= result[-1]["address"] + result[-1]["size"]:
            prev = result[-1]
            if prev["path"] != file["path"] or prev["protection"] != prot:
                if start < prev["address"] + prev["size"]:
                    raise ValueError("Conflicting cache mappings")
            elif prev['fileOffset'] + start - prev['address'] == offset:
                prev["size"] = max(prev["address"] + prev["size"], end) - prev["address"]
                continue
        result.append({"address": start, "offset": start - base, "size": end - start,
                       "path": file["path"], "fileOffset": offset, "protection": prot,
                       "initialProtection": mapping["protection"]})
    return result


def verify_elf(library, ranges, start, span, blob_start=None):
    """Verify linked load bytes and VM protections, not just the assembly inputs."""
    with library.open("rb") as elf:
        header = elf.read(64)
        if header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<HH", header, 16) != (3, 183):
            raise ValueError("Expected an ARM64 ELF shared library")
        phoff = struct.unpack_from("<Q", header, 32)[0]
        phsize, phcount = struct.unpack_from("<HH", header, 54)
        if phsize != 56 or not 1 <= phcount <= 2048:
            raise ValueError("Invalid ELF program header table")
        if phsize * phcount > PAGE:
            raise ValueError('ELF program header table exceeds device code-signing limit')
        elf.seek(phoff)
        entries = elf.read(phsize * phcount)
        loads = [p for p in struct.iter_unpack("<II6Q", entries) if p[0] == 1]
        if any(p[1] & 3 == 3 or p[5] > p[6] or p[7] == 0 or p[2] % p[7] != p[3] % p[7] for p in loads):
            raise ValueError("Invalid ELF load permissions, size or alignment")
        if max(p[3] + p[6] for p in loads) < start + span:
            raise ValueError("ELF does not reserve the deferred cache address interval")
        for r in ranges:
            if 'dataOffset' in r:
                if blob_start is None or r['protection'] & 4:
                    raise ValueError('Invalid non-executable cache data blob')
                address = blob_start + r['dataOffset']
                matches = [p for p in loads if p[3] <= address and address + r['size'] <= p[3] + p[5] and p[1] == 4]
                if len(matches) != 1 or address + r['size'] > start:
                    raise ValueError('Cache data blob escapes read-only metadata')
                position = matches[0][2] + address - matches[0][3]
            else:
                matches = [p for p in loads if p[3] == start + r["offset"] and p[5] == p[6] == r["size"]]
                if len(matches) != 1:
                    raise ValueError("Linked cache mapping differs from its planned VM layout")
                p = matches[0]
                prot = r["protection"]
                flags = (4 if prot & 1 else 0) | (2 if prot & 2 else 0) | (1 if prot & 4 else 0)
                if p[1] != flags:
                    raise ValueError("Linked cache page protection differs from plan")
                position = p[2]
            digest = hashlib.sha256()
            elf.seek(position)
            left = r["size"]
            while left:
                block = elf.read(min(left, 8 * 1024 * 1024))
                if not block:
                    raise ValueError("Truncated ELF cache page")
                digest.update(block)
                left -= len(block)
            if digest.hexdigest() != r["packedSha256"]:
                raise ValueError("Linked ELF changed original cache page contents")


def package(primary, output, clang, full=False, pages_file=None):
    output.mkdir(parents=True, exist_ok=True)
    cache = json.loads(rust("hm-cache-info", primary.resolve()))
    if cache["platform"] != 2 or cache["osVersion"] < 27 << 16:
        raise ValueError("Expected an iOS 27+ device cache")
    segments, instructions = dyld_segments(cache)
    pages = []
    spans = []
    images = []
    stubs = False
    if pages_file is not None:
        demand = json.loads(pages_file.read_text())
        if demand['primaryUUID'] != cache['files'][0]['uuid']:
            raise ValueError('Demand pages belong to a different shared cache')
        stubs = demand.get('stubs', False)
        def number(value):
            return int(value, 0) if isinstance(value, str) else value
        pages = [number(p) for p in demand.get('pages', [])]
        spans = [[number(s), number(e)] for s, e in demand.get('ranges', [])]
        pending = list(dict.fromkeys(demand.get('images', [])))
        visited = set()
        for path in pending:
            if path in visited:
                continue
            visited.add(path)
            matches = [image for image in cache['images'] if image['path'] == path]
            if len(matches) != 1:
                raise ValueError(f'Demand image must identify one cached library: {path}')
            image = matches[0]
            reexports = []
            parts, code = image_segments(cache, image['address'], 6, reexports)
            if demand.get('reexports', False):
                pending.extend(reexports)
            # Symbol binding needs the image's export trie, not the shared
            # cache's entire LINKEDIT segment. Select that bounded structure.
            for part in parts:
                if 'exportsAddress' in part:
                    start = part['exportsAddress'] - cache['preferredBase']
                    end = start + part['exportsSize']
                    spans.append([start // PAGE * PAGE, (end + PAGE - 1) // PAGE * PAGE])
            segments += parts
            instructions += code
            images.append({**image, 'segments': parts, 'reexports': reexports})
    ranges = select(cache, segments, full, pages, spans, stubs)
    # A 16 KiB page can also contain the tail of a neighboring image's text.
    # Audit its instruction sections too, so no SVC in a signed selected page
    # can silently enter the host kernel with Darwin's syscall numbering.
    ordered_images = sorted(cache['images'], key=lambda image: image['address'])
    addresses = [image['address'] for image in ordered_images]
    audited = set()
    for r in ranges:
        if not r['protection'] & 4:
            continue
        first = max(0, bisect.bisect_right(addresses, r['address']) - 1)
        last = bisect.bisect_left(addresses, r['address'] + r['size'])
        for image in ordered_images[first:last]:
            if image['path'] not in audited:
                kind = 7 if image['address'] == cache['dyldHeaderAddress'] else 6
                _, code = image_segments(cache, image['address'], kind)
                instructions += code
                audited.add(image['path'])
    for file in cache['files']:
        for mapping in file['mappings']:
            if mapping['flags'] & 8:  # DYLD_CACHE_MAPPING_TEXT_STUBS
                # The file's first page is a cache header, followed by code
                # stubs that are not owned by an individual Mach-O section.
                skip = PAGE if mapping['fileOffset'] == 0 else 0
                if mapping['size'] > skip:
                    instructions.append((mapping['address'] + skip, mapping['size'] - skip))
    instructions = sorted(set(instructions))
    data_size = 0
    for r in ranges:
        if not r['protection'] & 4:
            r['dataOffset'] = data_size
            data_size += r['size']
    selected = output / "ranges.json"
    selected.write_text(json.dumps([[r["offset"], r["offset"] + r["size"]] for r in ranges]))
    records = output / "fixups.bin"
    summary = json.loads(rust("hm-cache-plan", primary.resolve(), selected.resolve(), records.resolve()))
    if records.stat().st_size != summary["locations"] * 24:
        raise ValueError("Invalid rebase record count")
    descriptor = output / "descriptor.bin"
    # All words are little endian, independent of native compiler struct layout.
    descriptor.write_bytes(struct.pack("<8Q", int.from_bytes(b"HMCACHE1", "little"), 2,
        cache["preferredBase"], cache["regionSize"], cache["dyldHeaderAddress"] - cache["preferredBase"],
        cache["dyldEntryAddress"] - cache["preferredBase"], len(ranges), summary["locations"]) +
        b"".join(struct.pack("<4Q", r["offset"], r["size"], r["protection"], r.get('dataOffset', (1 << 64) - 1)) for r in ranges) + records.read_bytes())
    asm = ['.section .rodata.hm_cache_descriptor,"a",%progbits', '.p2align 3',
           '.global hm_ios_cache_descriptor', 'hm_ios_cache_descriptor:',
           f'.incbin "{descriptor.resolve()}"', '.global hm_ios_cache_descriptor_end', 'hm_ios_cache_descriptor_end:']
    asm += ['.section .rodata.hm_cache_data,"a",%progbits', '.p2align 14',
            '.global hm_ios_cache_data', 'hm_ios_cache_data:']
    phdr = ['PHDRS { metadata PT_LOAD FLAGS(4) FILEHDR PHDRS; dynamic PT_DYNAMIC FLAGS(4);']
    layout = ['SECTIONS { . = SIZEOF_HEADERS;',
              '.hash : { *(.hash) } :metadata', '.gnu.hash : { *(.gnu.hash) } :metadata',
              '.dynsym : { *(.dynsym) } :metadata', '.dynstr : { *(.dynstr) } :metadata',
              '.dynamic : { *(.dynamic) } :metadata :dynamic',
              '.rodata : { *(.rodata*) } :metadata']
    patches = []
    for i, r in enumerate(ranges):
        piece = output / f"pages-{i:03}.bin"
        digest = hashlib.sha256()
        with Path(r["path"]).open("rb") as source, piece.open("wb") as dest:
            source.seek(r["fileOffset"])
            left = r["size"]
            while left:
                block = source.read(min(left, 8 * 1024 * 1024))
                if not block:
                    raise ValueError("Truncated cache mapping")
                digest.update(block)
                dest.write(block)
                left -= len(block)
        r["originalSha256"] = digest.hexdigest()
        # Patch audited instruction ranges only. Data words that resemble SVC
        # are never rewritten; original App instructions remain unchanged.
        if r["protection"] & 4:
            with piece.open("r+b") as dest:
                for address, size in instructions:
                    start = max(address, r['address'])
                    end = min(address + size, r['address'] + r['size'])
                    if end <= start:
                        continue
                    at = start - r["address"]
                    dest.seek(at)
                    data = dest.read(end - start)
                    for p in range(0, len(data), 4):
                        word = struct.unpack_from("<I", data, p)[0]
                        replacement = None
                        if word == 0xD4001001:
                            replacement, original = 0xD42909A0, "svc #0x80"
                        elif word & ~31 == 0xD53BD060:
                            replacement, original = 0xD4294000 | ((word & 31) << 5), f"mrs x{word & 31}, tpidrro_el0"
                        if replacement is not None:
                            dest.seek(at + p)
                            dest.write(struct.pack("<I", replacement))
                            patches.append({"offset": start + p - cache["preferredBase"], "original": original,
                                            "replacement": f"brk #{(replacement >> 5) & 65535:#x}"})
        with piece.open("rb") as packed:
            r["packedSha256"] = hashlib.file_digest(packed, "sha256").hexdigest()
        if 'dataOffset' in r:
            asm += ['.section .rodata.hm_cache_data,"a",%progbits', f'.incbin "{piece.resolve()}"']
            continue
        flags = "ax" if r["protection"] & 4 else "aw" if r["protection"] & 2 else "a"
        asm += [f'.section .hm_cache_{i},"{flags}",%progbits', '.p2align 14']
        if i == 0:
            if r["offset"] != 0:
                raise ValueError("Missing primary cache base")
            asm += ['.global hm_ios_cache_base', 'hm_ios_cache_base:']
        asm += [f'.incbin "{piece.resolve()}"']
        elf_flags = (4 if r["protection"] & 1 else 0) | (2 if r["protection"] & 2 else 0) | (1 if r["protection"] & 4 else 0)
        phdr += [f'cache{i} PT_LOAD FLAGS({elf_flags});']
        # Put cache after metadata with enough space for the selected fixup plan.
        layout += [f'.hm_cache_{i} (HM_CACHE_START + {r["offset"]}) : {{ *(.hm_cache_{i}) }} :cache{i}']
    # Extend ELF's reserved address interval across the whole cache, including
    # deferred LINKEDIT/framework pages. Missing pointers must fault in our own
    # reservation rather than aliasing an unrelated host mapping.
    tail = (cache["regionSize"] + PAGE - 1) // PAGE * PAGE - PAGE
    if max(r["offset"] + r["size"] for r in ranges) <= tail:
        asm += ['.section .hm_cache_reserve,"a",%nobits', '.p2align 14', f'.zero {PAGE}']
        phdr += ['reserve PT_LOAD FLAGS(4);']
        layout += [f'.hm_cache_reserve (HM_CACHE_START + {tail}) (NOLOAD) : {{ *(.hm_cache_reserve) }} :reserve']
    asm += ['.section .rodata.hm_cache_data,"a",%progbits', '.global hm_ios_cache_data_end', 'hm_ios_cache_data_end:']
    phdr += ['stack PT_GNU_STACK FLAGS(6); }']
    if len(phdr) * 56 > PAGE:
        raise ValueError('Too many executable ranges for device code signing')
    start = (descriptor.stat().st_size + data_size + 65536 + PAGE - 1) // PAGE * PAGE
    layout.insert(1, f'HM_CACHE_START = {start};')
    layout += [' /DISCARD/ : { *(.comment) *(.note*) }', '}']
    asm += ['.section .note.GNU-stack,"",%progbits']
    assembly = output / "cache.S"
    script = output / "cache.ld"
    assembly.write_text("\n".join(asm) + "\n")
    script.write_text("\n".join(phdr + layout) + "\n")
    obj = output / "cache.o"
    library = output / "libhm_ioscache.so"
    subprocess.run([str(clang), "--target=aarch64-linux-ohos", "-c", str(assembly), "-o", str(obj)], check=True)
    subprocess.run([str(clang.parent / "ld.lld"), "-shared", "--hash-style=both", "-soname", library.name,
                    "-T", str(script), str(obj), "-o", str(library)], check=True)
    symbols = subprocess.check_output([str(clang.parent / 'llvm-nm'), '-D', '--defined-only', str(library)], text=True)
    blob_start = next(int(line.split()[0], 16) for line in symbols.splitlines() if line.split()[-1] == 'hm_ios_cache_data')
    verify_elf(library, ranges, start, cache["regionSize"], blob_start)
    manifest = {"scope": "full-cache" if full else "dyld-demand-pages", "runtimeComplete": False,
                "demandPages": pages,
                "demandRanges": spans,
                "demandImages": images,
                "dataBlobBytes": data_size, "descriptorVersion": 2,
                "cacheTextStubs": stubs,
                "instructionAuditImages": sorted(audited),
                "primaryUUID": cache["files"][0]["uuid"], "regionSize": cache["regionSize"],
                "selectedBytes": sum(r["size"] for r in ranges), "ranges": ranges,
                "deferredSegments": [s for s in segments if s["name"] in DEFERRED_SEGMENTS] if not full else [],
                "relocations": summary, "syscallPatches": patches, "library": str(library.resolve())}
    (output / "package.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({k: v for k, v in manifest.items() if k not in ("ranges", "syscallPatches")}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("primary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--pages", type=Path, help="UUID-bound JSON list of cache-relative 16 KiB pages")
    args = parser.parse_args()
    package(args.primary, args.output, args.clang, args.full, args.pages)
