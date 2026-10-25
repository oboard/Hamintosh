#!/usr/bin/env python3
"""Map a Harmintosh device fault back to the original dyld cache layout."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from pack_cache import image_segments

ROOT = Path(__file__).resolve().parents[1]
PAGE = 0x4000
DEFAULT_REPORT = ROOT / 'artifacts/device-compat-report.json'
DEFAULT_PRIMARY = ROOT / 'artifacts/ios27-system/cache/dyld_shared_cache_arm64e'
DEFAULT_PACKAGE = ROOT / 'artifacts/ios27-aot/package.json'
DEFAULT_MANIFEST = ROOT / 'tools/hello-world-cache-pages.json'


def load_cache_info(primary):
    output = subprocess.check_output([
        'cargo', 'run', '--quiet', '--locked', '--manifest-path',
        str(ROOT / 'runtime/Cargo.toml'), '--bin', 'hm-cache-info', '--', str(primary),
    ], text=True)
    return json.loads(output)


def find_mapping(cache, address):
    for file in cache['files']:
        for mapping in file['mappings']:
            if mapping['address'] <= address < mapping['address'] + mapping['size']:
                return file, mapping
    return None, None


def find_image(cache, address):
    candidates = [image for image in cache['images'] if image['address'] <= address]
    if not candidates or find_mapping(cache, address)[1] is None:
        return None
    candidate = max(candidates, key=lambda image: image['address'])
    def segments(image, sections=None):
        kind = 7 if image['address'] == cache.get('dyldHeaderAddress') else 6
        return image_segments(cache, image['address'], kind, section_ranges=sections)[0]
    # Header ordering only identifies TEXT ownership. DATA/AUTH/ObjC sections
    # are arranged independently, often in entirely different subcache files.
    if any(s['name'] == '__TEXT' and s['address'] <= address < s['address'] + s['size']
           for s in segments(candidate)):
        return candidate
    for image in cache['images']:
        sections = []
        segments(image, sections)
        for segment, section, start, size in sections:
            if start <= address < start + size:
                return {**image, 'segment': segment, 'section': section}
    return None


def selected(package, offset):
    return any(item['offset'] <= offset < item['offset'] + item['size']
               for item in package.get('ranges', []))


def manifest_contains(manifest, offset):
    for item in manifest.get('pages', []):
        if int(item, 0) == offset:
            return True
    for start, end in manifest.get('ranges', []):
        if int(start, 0) <= offset < int(end, 0):
            return True
    return False


def analyze(report, cache, package, manifest):
    dyld = report.get('dyldBootstrap', {})
    detail = dyld.get('detail', '')
    match = re.search(r'PC cache\+0x([0-9a-fA-F]+)', detail)
    if not match:
        raise ValueError('report does not contain a cache PC offset')
    if dyld.get('faultPc') in (None, ''):
        raise ValueError('report does not contain faultPc')
    pc_offset = int(match.group(1), 16)
    runtime_pc = int(dyld['faultPc'])
    fault_runtime = int(dyld.get('faultAddress', '0'))
    cache_base = runtime_pc - pc_offset
    preferred = cache['preferredBase']
    unslid_pc = preferred + pc_offset
    unslid_fault = preferred + fault_runtime - cache_base
    fault_offset = fault_runtime - cache_base
    page = fault_offset // PAGE * PAGE

    pc_image = find_image(cache, unslid_pc)
    fault_image = find_image(cache, unslid_fault)
    fault_file, fault_mapping = find_mapping(cache, unslid_fault)
    mapping_range = None
    suggestion = None
    if fault_mapping:
        mapping_start = fault_mapping['address'] - preferred
        mapping_end = mapping_start + fault_mapping['size']
        mapping_range = [mapping_start, mapping_end]
        suggestion = [max(page - 0x10 * PAGE, mapping_start),
                      min(page + 0x10 * PAGE, mapping_end)]

    result = {
        'status': dyld.get('status'),
        'traps': dyld.get('traps'),
        'signal': dyld.get('signal'),
        'cacheBase': f'{cache_base:#x}',
        'pcOffset': f'{pc_offset:#x}',
        'pcImage': pc_image['path'] if pc_image else None,
        'pcImageOffset': f'{unslid_pc - pc_image["address"]:#x}' if pc_image else None,
        'faultAddress': f'{unslid_fault:#x}',
        'faultCacheOffset': f'{fault_offset:#x}',
        'faultPage': f'{page:#x}',
        'faultImage': fault_image['path'] if fault_image else None,
        'faultSegment': fault_image.get('segment') if fault_image else None,
        'faultSection': fault_image.get('section') if fault_image else None,
        'faultImageOffset': f'{unslid_fault - fault_image["address"]:#x}' if fault_image else None,
        'mappingPath': fault_file['path'] if fault_file else None,
        'mappingRange': [f'{mapping_range[0]:#x}', f'{mapping_range[1]:#x}'] if mapping_range else None,
        'faultSize': fault_mapping['size'] if fault_mapping else None,
        'faultFlags': fault_mapping.get('flags') if fault_mapping else None,
        'selectedInPackage': selected(package, fault_offset),
        'selectedInManifest': manifest_contains(manifest, fault_offset),
        'suggestedManifestRange': [f'{suggestion[0]:#x}', f'{suggestion[1]:#x}'] if suggestion else None,
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', nargs='?', type=Path, default=DEFAULT_REPORT)
    parser.add_argument('--primary', type=Path, default=DEFAULT_PRIMARY)
    parser.add_argument('--package', type=Path, default=DEFAULT_PACKAGE)
    parser.add_argument('--manifest', type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument('--cache-info', type=Path, help='reuse an hm-cache-info JSON output')
    args = parser.parse_args()
    cache = json.loads(args.cache_info.read_text()) if args.cache_info else load_cache_info(args.primary)
    result = analyze(
        json.loads(args.report.read_text()),
        cache,
        json.loads(args.package.read_text()),
        json.loads(args.manifest.read_text()),
    )
    json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
