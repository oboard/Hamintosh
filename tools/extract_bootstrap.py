#!/usr/bin/env python3
"""Extract standalone dyld from a verified RestoreRamDisk, checking cache UUID."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
from extract_sysroot import wait_for_download
from pack_cache import read_vm, rust
from prepare_bootstrap import uuid
from stage_sysroot import stage, ROOT


def extract(archive, output, ipsw, cache_path, wait_pid=None):
    source = wait_for_download(archive, wait_pid)
    output.mkdir(parents=True, exist_ok=True)
    payload = output / 'bootstrap-ramdisk.dmg'
    subprocess.run([str(ipsw), 'img4', 'im4p', 'extract', '--output', str(payload), str(archive)], check=True)
    attached = subprocess.run(['hdiutil', 'attach', '-readonly', '-nobrowse', '-plist', str(payload)],
                              capture_output=True, check=True)
    mounts = [Path(e['mount-point']) for e in plistlib.loads(attached.stdout)['system-entities'] if 'mount-point' in e]
    try:
        candidates = [m / 'usr/lib/dyld' for m in mounts if (m / 'usr/lib/dyld').is_file()]
        if len(candidates) != 1 or candidates[0].is_symlink():
            raise ValueError('RestoreRamDisk must contain one regular /usr/lib/dyld')
        data = candidates[0].read_bytes()
        identity = uuid(data)
        cache = json.loads(rust('hm-cache-info', cache_path.resolve()))
        cached_id = uuid(read_vm(cache, cache['dyldHeaderAddress'], 65536))
        if identity != cached_id:
            raise ValueError('RestoreRamDisk dyld does not match selected cache')
        directory = output / 'bootstrap'
        directory.mkdir(exist_ok=True)
        temporary = directory / 'dyld.partial'
        temporary.write_bytes(data)
        temporary.replace(directory / 'dyld')
        record = {'stage': 'standalone-dyld-imported', 'runtimeComplete': False,
                  'source': source, 'uuid': identity, 'size': len(data),
                  'sha256': hashlib.sha256(data).hexdigest(), 'cachePrimaryUUID': cache['files'][0]['uuid']}
        (directory / 'source.json').write_text(json.dumps(record, indent=2) + '\n')
        stage(output, ROOT / 'harmonios/src/main/resources/rawfile/sysroot')
        print(json.dumps(record, indent=2))
    finally:
        for mount in reversed(mounts):
            subprocess.run(['diskutil', 'eject', str(mount)], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--ipsw', required=True, type=Path)
    parser.add_argument('--cache', required=True, type=Path)
    parser.add_argument('--wait-pid', type=int)
    args = parser.parse_args()
    extract(args.archive.resolve(), args.output.resolve(), args.ipsw.resolve(), args.cache.resolve(), args.wait_pid)
