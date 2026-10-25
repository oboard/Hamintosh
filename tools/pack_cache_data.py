#!/usr/bin/env python3
"""Pack original non-executable cache mappings for bounded runtime demand paging."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

from pack_cache import PAGE, image_segments, location, read_vm, rust


def code_metadata(cache):
    """Read-only source pages; they are never eligible for anonymous execution."""
    spans = []
    for file in cache['files']:
        for mapping in file['mappings']:
            if mapping['maxProtection'] & 4 and mapping['fileOffset'] == 0:
                spans.append((mapping['address'], mapping['address'] + PAGE))
    for image in cache.get('images', []):
        address = image['address']
        size = struct.unpack_from('<I', read_vm(cache, address, 32), 20)[0]
        spans.append((address // PAGE * PAGE, (address + 32 + size + PAGE - 1) // PAGE * PAGE))
        sections = []
        kind = 7 if address == cache.get('dyldHeaderAddress') else 6
        _, instructions = image_segments(cache, address, kind, section_ranges=sections)
        instructions = set(instructions)
        for _, _, at, length in sections:
            if (at, length) in instructions:
                continue
            _, mapping, _ = location(cache, at, length)
            if mapping['maxProtection'] & 4:
                spans.append((at // PAGE * PAGE, (at + length + PAGE - 1) // PAGE * PAGE))
    merged = []
    for start, end in sorted(spans):
        file, mapping, offset = location(cache, start, end - start)
        if merged:
            f, previous = merged[-1]
            if (f['path'] == file['path'] and start <= previous['address'] + previous['size'] and
                    previous['fileOffset'] + start - previous['address'] == offset):
                previous['size'] = max(previous['address'] + previous['size'], end) - previous['address']
                continue
        merged.append((file, dict(address=start, size=end - start, fileOffset=offset,
                                  maxProtection=1, protection=1, slideInfoSize=0, slideInfoOffset=0)))
    return merged


def write_pack(cache, output):
    mappings = []
    for file in cache['files']:
        for mapping in file['mappings']:
            if not mapping['maxProtection'] & 4:
                mappings.append((file, mapping))
    metadata_mappings = code_metadata(cache)
    mappings += metadata_mappings
    mappings.sort(key=lambda item: item[1]['address'])
    if not 0 < len(mappings) <= 16384:
        raise ValueError('Invalid data mapping count')
    metadata = bytearray(len(mappings) * 80)
    records = []
    for file, m in mappings:
        offset = m['address'] - cache['preferredBase']
        if (offset < 0 or offset % PAGE or m['size'] % PAGE or not m['size'] or
                offset + m['size'] > cache['regionSize'] or m['maxProtection'] & ~3 or
                m['protection'] & ~m['maxProtection']):
            raise ValueError('Invalid non-executable cache mapping')
        page_size = value_add = starts_offset = count = 0
        if m['slideInfoSize']:
            with Path(file['path']).open('rb') as source:
                source.seek(m['slideInfoOffset'])
                slide = source.read(m['slideInfoSize'])
            if len(slide) < 24:
                raise ValueError('Truncated data slide header')
            version, page_size, count, _, value_add = struct.unpack_from('<4IQ', slide)
            if (version != 5 or page_size not in (4096, PAGE) or
                    count > m['size'] // page_size or 24 + count * 2 > len(slide)):
                raise ValueError('Invalid data slide table')
            starts_offset = 64 + len(metadata)
            metadata += slide[24:24 + count * 2]
        crc_offset = 64 + len(metadata)
        metadata += bytes(m['size'] // PAGE * 4)
        records.append([offset, m['size'], 0, m['maxProtection'] | (m['protection'] << 8),
                        page_size, value_add, starts_offset, count, crc_offset, 0])
    metadata_size = (64 + len(metadata) + PAGE - 1) // PAGE * PAGE
    metadata += bytes(metadata_size - 64 - len(metadata))
    position = metadata_size
    for record in records:
        record[2] = position
        position += record[1]
    temporary = output.with_suffix(output.suffix + '.partial')
    output.parent.mkdir(parents=True, exist_ok=True)
    with temporary.open('w+b') as dest:
        dest.seek(metadata_size)
        for index, ((file, m), record) in enumerate(zip(mappings, records)):
            with Path(file['path']).open('rb') as source:
                source.seek(m['fileOffset'])
                for start in range(0, m['size'], 8 * 1024 * 1024):
                    size = min(8 * 1024 * 1024, m['size'] - start)
                    block = source.read(size)
                    if len(block) != size:
                        raise ValueError('Truncated cache data')
                    for at in range(0, size, PAGE):
                        crc = zlib.crc32(block[at:at + PAGE])
                        slot = record[8] - 64 + (start + at) // PAGE * 4
                        struct.pack_into('<I', metadata, slot, crc)
                    dest.write(block)
            struct.pack_into('<10Q', metadata, index * 80, *record)
        dest.seek(0)
        dest.write(struct.pack('<8s16s4QII', b'HMDATA01', bytes.fromhex(cache['files'][0]['uuid']),
                               cache['preferredBase'], cache['regionSize'], len(records),
                               position, metadata_size, zlib.crc32(metadata)))
        dest.write(metadata)
    if temporary.stat().st_size != position:
        raise ValueError('Cache data file length mismatch')
    temporary.replace(output)
    with output.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    manifest = dict(primaryUUID=cache['files'][0]['uuid'], sha256=digest, bytes=position,
                    mappings=len(records), dataBytes=position - metadata_size,
                    executableBytes=0, pageSize=PAGE,
                    codeMetadataBytes=sum(m['size'] for _, m in metadata_mappings))
    output.with_suffix(output.suffix + '.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('primary', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    cache = json.loads(rust('hm-cache-info', args.primary.resolve()))
    print(json.dumps(write_pack(cache, args.output.resolve()), indent=2))
