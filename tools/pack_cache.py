#!/usr/bin/env python3
"""AOT-package selected iOS cache pages, retaining a single shared VM slide.

Default selection is dyld's code/data and mapped cache headers. Non-executable
pages live in a read-only blob and are copied only to selected VM ranges at
startup; shared LINKEDIT remains deferred. No Apple code is reconstructed. Darwin SVC #0x80 and thread
pointer reads in instruction sections are redirected to the host trap boundary.
"""
import argparse
import bisect
from collections import deque
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


def image_segments(cache, header_address, expected_kind, reexports=None, dependencies=None,
                   thread_variables=None, section_ranges=None):
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
                if section_ranges is not None and section_size:
                    section_name = data[section:section + 16].rstrip(b'\0').decode('ascii')
                    section_ranges.append((name, section_name, section_addr, section_size))
                if thread_variables is not None and section_flags & 0xff == 0x13:
                    if section_size % 24 or section_addr % 8 or not prot & 2 or prot & 4:
                        raise ValueError('Invalid thread variable descriptor section')
                    if section_size:
                        thread_variables.append((section_addr, section_size))
                if section_flags & 0x80000400:
                    if not prot & 4 or section_size % 4:
                        raise ValueError("Invalid instruction section")
                    instructions.append((section_addr, section_size))
        elif command == 0x80000033:  # LC_DYLD_EXPORTS_TRIE
            if length != 16 or exports is not None:
                raise ValueError('Invalid or duplicate export trie command')
            exports = struct.unpack_from('<II', data, pos + 8)
        elif command in (0xC, 0x80000018, 0x8000001f, 0x80000023):
            if length < 24:
                raise ValueError('Truncated dylib command')
            name_offset = struct.unpack_from('<I', data, pos + 8)[0]
            if not 24 <= name_offset < length:
                raise ValueError('Invalid dylib name offset')
            name = data[pos + name_offset:pos + length]
            if b'\0' not in name:
                raise ValueError('Unterminated dylib name')
            name = name.split(b'\0', 1)[0].decode('utf-8')
            if dependencies is not None:
                dependencies.append(name)
            if command == 0x8000001f and reexports is not None:
                reexports.append(name)
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


def export_offset(cache, path, name, *, swift_conformance=False):
    image = next((i for i in cache['images'] if i['path'] == path), None)
    if image is None:
        raise ValueError('Objective-C binding library is absent from cache')
    sections = []
    segments, instructions = image_segments(cache, image['address'], 6, section_ranges=sections)
    segment = next((s for s in segments if 'exportsAddress' in s), None)
    if segment is None:
        raise ValueError('Objective-C binding has no export trie')
    data = read_vm(cache, segment['exportsAddress'], segment['exportsSize'])
    def uleb(at):
        value = 0
        for shift in range(0, 64, 7):
            if at >= len(data):
                break
            byte = data[at]
            at += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value, at
        raise ValueError('Invalid export trie integer')
    at, consumed, visited = 0, 0, set()
    name = name.encode('utf-8')
    while at not in visited and len(visited) <= len(name) + 1:
        visited.add(at)
        size, terminal = uleb(at)
        end = terminal + size
        if end >= len(data):
            raise ValueError('Export trie terminal escapes data')
        if consumed == len(name) and size:
            flags, cursor = uleb(terminal)
            value, cursor = uleb(cursor)
            if flags & ~4 or cursor > end:
                raise ValueError('Objective-C binding requires a direct data export')
            address = image['address'] + value
            if swift_conformance:
                if (address % 4 or not any(segment == '__TEXT' and section in ('__const', '__constg_swiftt')
                        and start <= address and address + 16 <= start + size
                        for segment, section, start, size in sections)
                        or any(start < address + 16 and address < start + size for start, size in instructions)):
                    raise ValueError('Swift conformance export escapes read-only metadata')
                _, metadata_mapping, _ = location(cache, address, 16)
                if metadata_mapping['protection'] & 2:
                    raise ValueError('Swift conformance export is writable')
                return address - cache['preferredBase']
            _, mapping, _ = location(cache, address, 40)
            if mapping['maxProtection'] & 4:
                raise ValueError('Objective-C class export points into code')
            return address - cache['preferredBase']
        count = data[end]
        cursor = end + 1
        matches = []
        for _ in range(count):
            edge_end = data.find(b'\0', cursor)
            if edge_end < 0:
                raise ValueError('Unterminated export trie edge')
            edge = data[cursor:edge_end]
            child, cursor = uleb(edge_end + 1)
            if edge and name[consumed:].startswith(edge):
                matches.append((child, consumed + len(edge)))
        if len(matches) != 1:
            raise ValueError('Objective-C class export was not uniquely resolved')
        at, consumed = matches[0]
    raise ValueError('Cyclic export trie')


def stub_data_spans(cache):
    """Select GOT pages addressed by the shared branch stubs we package."""
    pages = set()
    for file in cache['files']:
        for mapping in file['mappings']:
            if not mapping.get('flags', 0) & 8:
                continue
            skip = PAGE if mapping['fileOffset'] == 0 else 0
            start = mapping['address'] + skip
            data = read_vm(cache, start, mapping['size'] - skip)
            for at in range(0, len(data) - 4, 4):
                word = struct.unpack_from('<I', data, at)[0]
                if word & 0x9f000000 != 0x90000000:  # ADRP
                    continue
                reg = word & 31
                if reg == 31:
                    continue
                immediate = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3)
                if immediate & (1 << 20):
                    immediate -= 1 << 21
                address = (start + at) // 4096 * 4096 + immediate * 4096
                next_at = at + 4
                word = struct.unpack_from('<I', data, next_at)[0]
                if word & 0xff800000 == 0x91000000 and (word >> 5) & 31 == reg:  # ADD immediate
                    address += ((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0)
                    reg = word & 31
                    next_at += 4
                    if next_at + 4 > len(data) or reg == 31:
                        continue
                    word = struct.unpack_from('<I', data, next_at)[0]
                if word & 0xffc00000 != 0xf9400000 or (word >> 5) & 31 != reg:  # LDR 64-bit
                    continue
                address += ((word >> 10) & 0xfff) * 8
                _, target, _ = location(cache, address, 8)
                if not target['protection'] & 1 or target['maxProtection'] & 4:
                    raise ValueError('Branch stub GOT slot is outside cache data')
                pages.add((address - cache['preferredBase']) // PAGE * PAGE)
    return [[page, page + PAGE] for page in sorted(pages)]


def _arm64_branch_target(pc, instruction):
    """Return a direct B/BL target, or None for a non-branch instruction."""
    if instruction & 0x7c000000 != 0x14000000:
        return None
    immediate = instruction & 0x03ffffff
    if immediate & (1 << 25):
        immediate -= 1 << 26
    return pc + (immediate << 2)


def selector_stub_pages(cache, instructions):
    """Select selector stub pages called by the packaged code.

    The shared cache places `__objc_stubs` entries in RX regions between the
    tiny `libobjcMsgSend*` images. Those pages are not owned by a Mach-O
    segment, so segment-based selection misses them even though UIKit branches
    to them directly. Follow direct branches from selected code and from the
    reached stub pages, and include only page-aligned targets in those regions.
    """
    base = cache['preferredBase']
    images = sorted(cache['images'], key=lambda image: image['address'])
    regions = []
    for index, image in enumerate(images[:-1]):
        path = image['path']
        prefix, suffix = '/usr/lib/objc/libobjcMsgSend', '.dylib'
        if not path.startswith(prefix) or not path.endswith(suffix):
            continue
        shard = path[len(prefix):-len(suffix)]
        if shard and not (shard.isascii() and shard.isdecimal()):
            continue
        start = image['address'] + PAGE
        end = images[index + 1]['address']
        if start < end:
            regions.append((start, end))

    def region_page(address):
        for start, end in regions:
            if start <= address < end:
                page = (address - base) // PAGE * PAGE
                try:
                    location(cache, base + page, PAGE)
                except ValueError:
                    return None
                return page
        return None

    pages = set()

    def scan_ranges(ranges):
        for first, size in ranges:
            data = read_vm(cache, first, size)
            for at in range(0, size - 3, 4):
                target = _arm64_branch_target(first + at, struct.unpack_from('<I', data, at)[0])
                if target is not None:
                    page = region_page(target)
                    if page is not None:
                        pages.add(page)

    scan_ranges(instructions)
    pending = list(pages)
    while pending:
        page = pending.pop()
        size = min(PAGE, cache['regionSize'] - page)
        if size <= 0 or size % 4:
            raise ValueError('Invalid Objective-C stub page')
        data = read_vm(cache, base + page, size)
        for at in range(0, size - 3, 4):
            target = _arm64_branch_target(base + page + at, struct.unpack_from('<I', data, at)[0])
            if target is None:
                continue
            target_page = region_page(target)
            if target_page is not None and target_page not in pages:
                pages.add(target_page)
                pending.append(target_page)
    return [[page, page + PAGE] for page in sorted(pages)]


def selector_ranges(cache):
    """Select shared ObjC selector/class/protocol hashes and string storage."""
    base = cache['preferredBase']
    header = read_vm(cache, base, 480)
    opts, opts_size = struct.unpack_from('<QQ', header, 464)
    if opts_size < 48:
        raise ValueError('Missing Objective-C optimization header')
    optimization = read_vm(cache, base + opts, 48)
    if not 1 <= struct.unpack_from('<I', optimization)[0] <= 4:
        raise ValueError('Unsupported Objective-C optimization header')
    strings = {}
    spans = [(base + opts, opts_size)]
    for field in (24, 32, 40):
        table_offset = struct.unpack_from('<Q', optimization, field)[0]
        if not table_offset:
            continue
        table = base + table_offset
        version, capacity, occupied, shift, mask = struct.unpack('<5I', read_vm(cache, table, 20))
        if (version != 0 or not 0 < capacity <= 1 << 24 or capacity & (capacity - 1) or
                occupied > capacity or shift > 64 or mask >= 1 << 24 or mask & (mask + 1)):
            raise ValueError('Invalid Objective-C string hash table')
        offsets_start = 32 + 256 * 4 + mask + 1 + capacity
        table_size = offsets_start + capacity * 4
        offsets = read_vm(cache, table + offsets_start, capacity * 4)
        if field != 24:
            # Class/protocol maps append one 64-bit object record per bucket,
            # then a count and an array of duplicate object records.
            duplicates_offset = table_size + capacity * 8
            duplicates = struct.unpack('<I', read_vm(cache, table + duplicates_offset, 4))[0]
            if duplicates > 1 << 24:
                raise ValueError('Invalid Objective-C duplicate object count')
            table_size = duplicates_offset + 4 + duplicates * 8
        location(cache, table, table_size)
        spans.append((table, table_size))
        for (relative,) in struct.iter_unpack('<i', offsets):
            if relative == 0:
                continue
            address = table + relative
            file, mapping, _ = location(cache, address, 1)
            if not mapping['protection'] & 1 or mapping['protection'] & 4:
                raise ValueError('ObjC name is outside read-only cache storage')
            key = (file['path'], mapping['address'])
            if key not in strings:
                strings[key] = [address, address, mapping]
            else:
                strings[key][0] = min(strings[key][0], address)
                strings[key][1] = max(strings[key][1], address)
    for field, expected_size in [(8, 24), (16, 8)]:
        info_offset = struct.unpack_from('<Q', optimization, field)[0]
        if not info_offset:
            continue
        info_address = base + info_offset
        count, entry_size = struct.unpack('<II', read_vm(cache, info_address, 8))
        if count > len(cache['images']) or entry_size != expected_size:
            raise ValueError('Invalid Objective-C header info table')
        size = 8 + count * entry_size
        info = read_vm(cache, info_address, size)
        spans.append((info_address, size))
        if field == 8:
            # HeaderInfoRO stores a relative objc_image_info pointer in its
            # second word. The corresponding flags are coalesced separately.
            for index in range(count):
                slot = 8 + index * entry_size + 8
                relative = struct.unpack_from('<q', info, slot)[0]
                if relative:
                    address = info_address + slot + relative
                    location(cache, address, 8)
                    spans.append((address, 8))
    for start, last, mapping in strings.values():
        limit = min(65536, mapping['address'] + mapping['size'] - last)
        end = read_vm(cache, last, limit).find(b'\0')
        if end < 0:
            raise ValueError('Unterminated Objective-C selector string')
        spans.append((start, last + end + 1 - start))
    return [[(address - base) // PAGE * PAGE,
             (address + size - base + PAGE - 1) // PAGE * PAGE]
            for address, size in spans]


def select(cache, segments, full=False, pages=(), spans=(), stubs=False, headers=False, lazy_data=False):
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
    if headers and not full:
        # libdyld inspects headers of cached images which have not been loaded
        # by the process. Keep these pages in the data blob: they need no RX
        # mapping unless an explicitly selected code range already covers them.
        metadata = []
        covered = [(r['address'], r['address'] + r['size']) for r in result]
        for image in cache['images']:
            address = image['address']
            header = read_vm(cache, address, 32)
            magic, cpu, _, kind, count, size, _, _ = struct.unpack('<8I', header)
            if (magic != 0xfeedfacf or cpu != 0x100000c or kind not in (6, 7) or
                    count > 4096 or size > 1024 * 1024):
                raise ValueError('Invalid cached image metadata header')
            start = address // PAGE * PAGE
            end = (address + 32 + size + PAGE - 1) // PAGE * PAGE
            for low, high in covered:
                if high <= start:
                    continue
                if low >= end:
                    break
                if start < low:
                    metadata.append((start, low))
                start = max(start, high)
                if start >= end:
                    break
            if start < end:
                metadata.append((start, end))
        for start, end in sorted(metadata):
            file, _, offset = location(cache, start, end - start)
            metadata_range = dict(address=start, offset=start - base, size=end - start,
                                  path=file['path'], fileOffset=offset,
                                  protection=1, initialProtection=1)
            result.append(metadata_range)
        merged = []
        for r in sorted(result, key=lambda r: r['address']):
            if merged:
                prev = merged[-1]
                if (r['address'] <= prev['address'] + prev['size'] and
                        r['path'] == prev['path'] and r['protection'] == prev['protection'] and
                        prev['fileOffset'] + r['address'] - prev['address'] == r['fileOffset']):
                    prev['size'] = max(prev['address'] + prev['size'], r['address'] + r['size']) - prev['address']
                    continue
            merged.append(r)
        result = merged
    return [r for r in result if r['protection'] & 4] if lazy_data else result


def coalesce_executable_ranges(cache, ranges, maximum):
    """Bound ELF headers by filling the smallest gaps in identical RX mappings.

    XPM parses the program table before permitting signed-file mappings. More
    disjoint selector pages must not grow that table without a configured bound.
    Added bytes still come from the original cache and undergo instruction audit.
    """
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
        raise ValueError('Invalid executable range limit')
    if len(ranges) <= maximum:
        return ranges
    candidates = []
    for index, (left, right) in enumerate(zip(ranges, ranges[1:])):
        if left['protection'] != 5 or right['protection'] != 5:
            continue
        end = left['address'] + left['size']
        gap = right['address'] - end
        if gap < 0 or left['path'] != right['path']:
            continue
        if left['fileOffset'] + right['address'] - left['address'] != right['fileOffset']:
            continue
        try:
            file, mapping, offset = location(cache, left['address'],
                right['address'] + right['size'] - left['address'])
        except ValueError:
            continue
        if file['path'] == left['path'] and mapping['maxProtection'] == 5 and offset == left['fileOffset']:
            candidates.append((gap, index))
    required = len(ranges) - maximum
    if len(candidates) < required:
        raise ValueError('Cannot meet ELF program-header bound within original RX mappings')
    joined = {index for _, index in sorted(candidates)[:required]}
    result = []
    for index, item in enumerate(ranges):
        if index and index - 1 in joined:
            result[-1]['size'] = item['address'] + item['size'] - result[-1]['address']
        else:
            result.append(dict(item))
    return result


def verify_elf(library, ranges, start, span, blob_start=None, max_header_bytes=None):
    """Verify linked load bytes and VM protections, not just the assembly inputs."""
    with library.open("rb") as elf:
        header = elf.read(64)
        if header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<HH", header, 16) != (3, 183):
            raise ValueError("Expected an ARM64 ELF shared library")
        phoff = struct.unpack_from("<Q", header, 32)[0]
        phsize, phcount = struct.unpack_from("<HH", header, 54)
        if phsize != 56 or not 1 <= phcount <= 2048:
            raise ValueError("Invalid ELF program header table")
        if max_header_bytes is not None and phoff + phsize * phcount > max_header_bytes:
            raise ValueError("Linked ELF exceeds the program-header byte limit")
        elf.seek(phoff)
        entries = elf.read(phsize * phcount)
        if len(entries) != phsize * phcount:
            raise ValueError("Truncated ELF program header table")
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


def demand_images(cache, demand):
    """Resolve explicit images plus a bounded dependency/reexport closure."""
    explicit = set(demand.get('images', []))
    depth_limit = demand.get('dependencyDepth', 0)
    if isinstance(depth_limit, bool):
        depth_limit = (1 << 32) if depth_limit else 0
    if not isinstance(depth_limit, int) or depth_limit < 0 or depth_limit > 64:
        raise ValueError('Invalid demand dependency depth')
    if demand.get('dependencies', False) and depth_limit == 0:
        depth_limit = 1 << 32
    queue = deque((path, 0) for path in dict.fromkeys(demand.get('images', [])))
    visited = set()
    images = []
    while queue:
        path, depth = queue.popleft()
        if path in visited:
            continue
        visited.add(path)
        matches = [image for image in cache['images'] if image['path'] == path]
        if len(matches) != 1:
            if path in explicit:
                raise ValueError(f'Demand image must identify one cached library: {path}')
            continue
        image = matches[0]
        reexports = []
        dependencies = []
        parts, code = image_segments(cache, image['address'], 6, reexports, dependencies)
        if depth < depth_limit:
            queue.extend((dependency, depth + 1) for dependency in dependencies if dependency.startswith('/'))
        if demand.get('reexports', False):
            queue.extend((dependency, depth + 1) for dependency in reexports)
        images.append({**image, 'segments': parts, 'reexports': reexports,
                       'dependencies': dependencies,
                       'closureDepth': depth})
    return images


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
    headers = False
    tlv = False
    selectors = False
    lazy_data = False
    if pages_file is not None:
        demand = json.loads(pages_file.read_text())
        if demand['primaryUUID'] != cache['files'][0]['uuid']:
            raise ValueError('Demand pages belong to a different shared cache')
        stubs = demand.get('stubs', False)
        headers = demand.get('headers', False)
        tlv = demand.get('tlv', False)
        selectors = demand.get('objcSelectors', False)
        lazy_data = demand.get('lazyData', False)
        def number(value):
            return int(value, 0) if isinstance(value, str) else value
        pages = [number(p) for p in demand.get('pages', [])]
        spans = [[number(s), number(e)] for s, e in demand.get('ranges', [])]
        images = demand_images(cache, demand)
        for image in images:
            parts = image['segments']
            _, code = image_segments(cache, image['address'], 6)
            # Symbol binding needs the image's export trie, not the shared
            # cache's entire LINKEDIT segment. Select that bounded structure.
            for part in parts:
                if 'exportsAddress' in part:
                    start = part['exportsAddress'] - cache['preferredBase']
                    end = start + part['exportsSize']
                    spans.append([start // PAGE * PAGE, (end + PAGE - 1) // PAGE * PAGE])
            segments += parts
            instructions += code
    if stubs and not lazy_data:
        spans += stub_data_spans(cache)
    if selectors:
        if not lazy_data:
            spans += selector_ranges(cache)
        # Selector-stub regions are executable and therefore cannot come from
        # the non-executable lazy-data pager.
        spans += selector_stub_pages(cache, instructions)
    if tlv and not lazy_data:
        variables = []
        for image in cache['images']:
            kind = 7 if image['address'] == cache['dyldHeaderAddress'] else 6
            image_segments(cache, image['address'], kind, thread_variables=variables)
        for address, size in variables:
            start = (address - cache['preferredBase']) // PAGE * PAGE
            end = (address + size - cache['preferredBase'] + PAGE - 1) // PAGE * PAGE
            spans.append([start, end])
    ranges = select(cache, segments, full, pages, spans, stubs, headers and not lazy_data, lazy_data)
    header_limit = demand.get('maxProgramHeaderBytes') if pages_file is not None else None
    if header_limit is not None:
        if type(header_limit) is not int or not 4096 <= header_limit <= 65536:
            raise ValueError('Invalid ELF program-header byte limit')
        # Metadata LOAD, DYNAMIC, terminal reservation LOAD and GNU_STACK.
        ranges = coalesce_executable_ranges(cache, ranges, (header_limit - 64) // 56 - 4)
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
    descriptor_version = 3 if lazy_data else 2
    descriptor.write_bytes(struct.pack("<8Q", int.from_bytes(b"HMCACHE1", "little"), descriptor_version,
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
    breakpoints = []
    instruction_patches = {}
    page_config = json.loads((pages_file or Path('/dev/null')).read_text()) if pages_file else {}
    for item in page_config.get('instructionPatches', []):
        offset = int(item['offset'], 0)
        expected = int(item['expected'], 0)
        replacement = int(item['replacement'], 0)
        if (offset < 0 or offset % 4 or not 0 <= expected <= 0xffffffff
                or not 0 <= replacement <= 0xffffffff):
            raise ValueError('Invalid audited instruction patch')
        address = cache['preferredBase'] + offset
        if address in instruction_patches:
            raise ValueError('Duplicate audited instruction patch')
        instruction_patches[address] = (expected, replacement, item.get('reason', ''))
    for item in page_config.get('breakpoints', []):
        offset = int(item['offset'], 0)
        immediate = int(item.get('immediate', '0x484d'), 0)
        if offset < 0 or offset % 4 or immediate < 0 or immediate > 0xffff:
            raise ValueError('Invalid diagnostic breakpoint')
        breakpoints.append((cache['preferredBase'] + offset, immediate))
    patched_instructions = set()
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
                        address_at = start + p
                        for breakpoint, immediate in breakpoints:
                            if address_at == breakpoint:
                                original = struct.unpack_from("<I", data, p)[0]
                                replacement = 0xD4400000 | (immediate << 5)
                                dest.seek(at + p)
                                dest.write(struct.pack("<I", replacement))
                                patches.append({"offset": breakpoint - cache["preferredBase"],
                                    "original": f"0x{original:08x}",
                                    "replacement": f"hlt #{immediate:#x}"})
                        word = struct.unpack_from("<I", data, p)[0]
                        custom = instruction_patches.get(address_at)
                        if custom is not None:
                            expected, custom_replacement, reason = custom
                            if word != expected:
                                raise ValueError(
                                    f'Audited instruction mismatch at {address_at:#x}')
                            dest.seek(at + p)
                            dest.write(struct.pack("<I", custom_replacement))
                            record = {"offset": address_at - cache["preferredBase"],
                                "original": f"0x{expected:08x}",
                                "replacement": f"0x{custom_replacement:08x}"}
                            if reason:
                                record["reason"] = reason
                            patches.append(record)
                            patched_instructions.add(address_at)
                            word = custom_replacement
                        replacement = None
                        original = None
                        # Root queues are intentionally non-activatable. The
                        # ARM64 compatibility path reaches this assertion stub
                        # while restoring libdispatch state; activation returns
                        # void, so make this audited stub a no-op.
                        if address_at in {
                            cache["preferredBase"] + 0x2eb28e60,
                            cache["preferredBase"] + 0x2eb28eb0,
                            cache["preferredBase"] + 0x2eb28edc,
                        }:
                            replacement, original = 0xD65F03C0, "dispatch-void-stub-brk"
                        elif word == 0xD4001001:
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
    missing_instruction_patches = set(instruction_patches) - patched_instructions
    if missing_instruction_patches:
        missing = min(missing_instruction_patches)
        raise ValueError(f'Audited instruction patch was not in executable cache: {missing:#x}')
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
    # Program headers also occupy the metadata PT_LOAD. Account for the full
    # table instead of rejecting larger dependency closures at one page.
    header_bytes = 64 + len(phdr) * 56
    start = (header_bytes + descriptor.stat().st_size + data_size + 65536 + PAGE - 1) // PAGE * PAGE
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
    verify_elf(library, ranges, start, cache["regionSize"], blob_start, header_limit)
    manifest = {"scope": "full-cache" if full else "dyld-demand-pages", "runtimeComplete": False,
                "demandPages": pages,
                "demandRanges": spans,
                "demandImages": images,
                "dataBlobBytes": data_size, "descriptorVersion": descriptor_version,
                "dataPaging": lazy_data,
                "cacheTextStubs": stubs,
                "cacheImageHeaders": headers,
                "cacheThreadVariables": tlv,
                "cacheObjCSelectors": selectors,
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
