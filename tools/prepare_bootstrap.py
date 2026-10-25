#!/usr/bin/env python3
"""Package the official standalone iOS dyld paired by UUID with the selected cache."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from pack_cache import read_vm, rust
from pack_macho import ROOT, pack


def uuid(data):
    if len(data) < 32 or data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('Expected thin ARM64 Mach-O')
    pos = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        if pos + 8 > len(data):
            raise ValueError('Truncated Mach-O command')
        command, length = struct.unpack_from('<II', data, pos)
        if length < 8 or pos + length > len(data):
            raise ValueError('Invalid Mach-O command size')
        if command == 0x1b and length == 24:
            return data[pos + 8:pos + 24].hex()
        pos += length
    raise ValueError('Missing dyld UUID')


def prepare(original, cache_path, output):
    cache = json.loads(rust('hm-cache-info', cache_path.resolve()))
    data = original.read_bytes()
    identity = uuid(data)
    if identity != uuid(read_vm(cache, cache['dyldHeaderAddress'], 65536)):
        raise ValueError('Standalone dyld UUID does not match the cache dyld')
    # hm-inspect returns 3 for valid images whose host runtime is incomplete.
    result = subprocess.run(['cargo', 'run', '--quiet', '--locked', '--manifest-path', str(ROOT / 'runtime/Cargo.toml'),
        '--bin', 'hm-inspect', '--', str(original.resolve())], text=True, capture_output=True)
    if result.returncode not in (0, 3):
        raise ValueError(f'Invalid bootstrap dyld: {result.stderr}')
    info = json.loads(result.stdout)['image']
    if info['fileType'] != 7 or info['platform'] != 2 or info['dependencies'] or not info['chainedFixups']:
        raise ValueError('Expected a self-contained iOS bootstrap dyld with chained fixups')
    patched = bytearray(data)
    changes = []
    for section in info['sections']:
        if not section['flags'] & 0x80000400:
            continue
        offset, size = section['fileOffset'], section['size']
        if offset + size > len(data) or size % 4:
            raise ValueError('Invalid bootstrap instruction section')
        for pos in range(offset, offset + size, 4):
            word = struct.unpack_from('<I', data, pos)[0]
            replacement = None
            if word == 0xD4001001:
                replacement = 0xD42909A0
            elif word & ~31 == 0xD53BD060:
                replacement = 0xD4294000 | ((word & 31) << 5)
            if replacement is not None:
                struct.pack_into('<I', patched, pos, replacement)
                changes.append({'fileOffset': pos, 'originalWord': word, 'replacementWord': replacement})
    output.mkdir(parents=True, exist_ok=True)
    bridged = output / 'dyld.bridged'
    bridged.write_bytes(patched)
    pack(bridged, output, role='dyld')
    plan = json.loads(rust('hm-fixups', original.resolve()))
    const = next(s for s in info['segments'] if s['name'] == '__DATA_CONST')
    witness = next(f for f in plan['fixups'] if f['authentication'] is None and
        f['target']['kind'] == 'rebase' and f['target']['high8'] == 0 and
        const['vmAddress'] - plan['preferredBase'] <= f['vmOffset'] <
        const['vmAddress'] - plan['preferredBase'] + const['vmSize'])
    header = output / 'packed_dyld.h'
    with header.open('a') as generated:
        generated.write(f'#define HM_DYLD_WITNESS_LOCATION {witness["vmOffset"]}ULL\n')
        generated.write(f'#define HM_DYLD_WITNESS_TARGET {witness["target"]["offset"]}ULL\n')
    (output / 'bridge.json').write_text(json.dumps({'uuid': identity,
        'source': str(original.resolve()), 'originalSha256': hashlib.sha256(data).hexdigest(),
        'bridgedSha256': hashlib.sha256(patched).hexdigest(), 'patches': changes,
        'selfRebase': 'Apple dyld performs its own chained fixups at startup',
        'rebaseWitness': witness}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('cache', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    prepare(args.original, args.cache, args.output)
