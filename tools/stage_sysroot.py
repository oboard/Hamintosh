#!/usr/bin/env python3
"""Stage verified runtime files needed by the current launch, excluding bulk caches."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def stage(source, output):
    metadata = json.loads((source / 'bootstrap/source.json').read_text())
    dyld = source / 'bootstrap/dyld'
    if hashlib.sha256(dyld.read_bytes()).hexdigest() != metadata['sha256']:
        raise ValueError('Standalone dyld differs from verified extraction')
    destination = output / 'usr/lib/dyld'
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(dyld, destination)
    files = ['usr/lib/dyld']
    system_version = source / 'SystemVersion.plist'
    if not system_version.is_file():
        system_version = ROOT / 'runtime/sysroot/SystemVersion.plist'
    if system_version.is_file():
        relative = 'System/Library/CoreServices/SystemVersion.plist'
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(system_version, destination)
        files.append(relative)
    trampolines = source / 'usr/lib/libobjc-trampolines.dylib'
    aot_images = []
    if trampolines.is_file():
        from pack_objc_trampolines import inspect
        identity = inspect(trampolines.read_bytes())
        relative = 'usr/lib/libobjc-trampolines.dylib'
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(trampolines, destination)
        files.append(relative)
        aot_images.append({'path': '/' + relative, **identity})
    cache = json.loads((source / 'cache-layout.json').read_text())
    primary = cache['files'][0]
    if primary['uuid'] != metadata['cachePrimaryUUID']:
        raise ValueError('System cryptex cache identity mismatch')
    relative = 'System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e'
    destination = output / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    local_primary = source / 'cache' / Path(primary['path']).name
    shutil.copyfile(local_primary if local_primary.is_file() else primary['path'], destination)
    files.append(relative)
    (output / 'manifest.json').write_text(json.dumps({
        'files': files, 'aotImages': aot_images, 'dyldUUID': metadata['uuid'], 'dyldSHA256': metadata['sha256'],
    }, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'harmonios/src/main/resources/rawfile/sysroot')
    args = parser.parse_args()
    stage(args.source.resolve(), args.output.resolve())
