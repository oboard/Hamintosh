#!/usr/bin/env python3
"""Verify an owned SystemOS AEA download, decrypt it, and import a complete iOS cache set."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]


def wait_for_download(path: Path, pid):
    metadata = path.with_suffix(path.suffix + '.source.json')
    while not path.is_file() or not metadata.is_file():
        if pid is None:
            raise ValueError('The verified download is not complete')
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            raise ValueError('Download process ended without a complete verified archive') from None
        time.sleep(2)
    source = json.loads(metadata.read_text())
    if path.stat().st_size != source['size']:
        raise ValueError('SystemOS archive size differs from download metadata')
    crc = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            crc = zlib.crc32(block, crc)
    if crc != source['crc32']:
        raise ValueError('SystemOS archive CRC32 verification failed')
    return source


def inspect_cache(path: Path):
    result = subprocess.run(['cargo', 'run', '--quiet', '--locked', '--manifest-path',
        str(ROOT / 'runtime/Cargo.toml'), '--bin', 'hm-cache-info', '--', str(path)],
        capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def extract(archive: Path, output: Path, ipsw: Path, pem_db: Path, wait_pid=None):
    output.mkdir(parents=True, exist_ok=True)
    status = output / 'extraction-status.json'

    def record(stage, **extra):
        value = {'stage': stage, 'runtimeComplete': False, **extra}
        status.write_text(json.dumps(value, indent=2) + '\n')
        print(stage, flush=True)

    record('waiting-for-verified-download', pid=wait_pid)
    source = wait_for_download(archive, wait_pid)
    record('decrypting-systemos', source=source)
    decrypted = output / 'system-image'
    decrypted.mkdir(exist_ok=True)
    dmg = decrypted / archive.name.removesuffix('.aea')
    if not dmg.is_file():
        with (output / 'decryption.log').open('w') as log:
            subprocess.run([str(ipsw), 'fw', 'aea', '--pem-db', str(pem_db), '--output',
                str(decrypted), str(archive)], stdout=log, stderr=subprocess.STDOUT, check=True)
    if not dmg.is_file():
        raise ValueError(f'Decrypted image was not created: {dmg}')
    record('mounting-readonly-systemos')
    mounted = subprocess.run(['hdiutil', 'attach', '-readonly', '-nobrowse', '-plist', str(dmg)],
        capture_output=True, check=True)
    (output / 'mount.plist').write_bytes(mounted.stdout)
    entities = plistlib.loads(mounted.stdout)['system-entities']
    mounts = [Path(e['mount-point']) for e in entities if 'mount-point' in e]
    if not mounts:
        raise ValueError('SystemOS mounted without a readable filesystem')
    try:
        candidates = []
        for mount in mounts:
            for relative in ['System/Library/Caches/com.apple.dyld', 'System/Library/dyld']:
                directory = mount / relative
                if directory.is_dir():
                    candidates += [p for p in directory.glob('dyld_shared_cache_arm64e*')
                                   if p.name in ['dyld_shared_cache_arm64e', 'dyld_shared_cache_arm64e_x1']]
        preferred = [p for p in candidates if p.name == 'dyld_shared_cache_arm64e']
        if len(preferred) == 1:
            candidates = preferred
        if len(candidates) != 1:
            raise ValueError(f'Expected exactly one primary iOS ARM64e cache, found {len(candidates)}')
        record('validating-mounted-cache')
        layout = inspect_cache(candidates[0])
        if layout['platform'] != 2 or layout.get('osVersion', 0) >> 16 < 27:
            raise ValueError('Cache does not match the required iOS 27 device platform')
        destination = output / 'cache'
        destination.mkdir(exist_ok=True)
        record('copying-complete-cache-set', files=len(layout['files']))
        for item in layout['files']:
            path = Path(item['path'])
            target = destination / path.name
            # Copy atomically so interrupted extraction never leaves a member looking complete.
            partial = target.with_name(target.name + '.partial')
            shutil.copyfile(path, partial)
            partial.replace(target)
        primary = destination / candidates[0].name
        copied = inspect_cache(primary)
        (output / 'cache-layout.json').write_text(json.dumps(copied, indent=2) + '\n')
        for mount in mounts:
            dyld = mount / 'usr/lib/dyld'
            if dyld.is_file() and not dyld.is_symlink():
                (output / 'usr/lib').mkdir(parents=True, exist_ok=True)
                shutil.copyfile(dyld, output / 'usr/lib/dyld')
                break
        for mount in mounts:
            trampoline = mount / 'usr/lib/libobjc-trampolines.dylib'
            if trampoline.is_file() and not trampoline.is_symlink():
                from pack_objc_trampolines import inspect
                identity = inspect(trampoline.read_bytes())
                target = output / 'usr/lib/libobjc-trampolines.dylib'
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(trampoline, target)
                target.with_suffix('.dylib.json').write_text(json.dumps(identity, indent=2) + '\n')
                break
        record('cache-imported', primary=str(primary.resolve()), files=len(copied['files']),
               images=len(copied['images']), source=source)
    finally:
        for mount in reversed(mounts):
            subprocess.run(['hdiutil', 'detach', str(mount)], check=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--ipsw', required=True, type=Path)
    parser.add_argument('--pem-db', required=True, type=Path)
    parser.add_argument('--wait-pid', type=int)
    args = parser.parse_args()
    try:
        extract(args.archive.resolve(), args.output.resolve(), args.ipsw.resolve(), args.pem_db.resolve(), args.wait_pid)
    except Exception as error:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'extraction-error.json').write_text(json.dumps({'error': str(error), 'runtimeComplete': False}, indent=2)+'\n')
        raise
