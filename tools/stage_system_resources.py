#!/usr/bin/env python3
"""Stage selected Apple resource files, preserving bytes and source identity."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'harmonios/src/main/resources/rawfile/sysroot'
CODE_MAGICS = {bytes.fromhex(value) for value in (
    'cffaedfe', 'feedfacf', 'cefaedfe', 'feedface', 'cafebabe',
    'bebafeca', 'cafebabf', 'bfbafeca', '7f454c46')}


def stage(source, output, paths):
    source, output = Path(source).resolve(), Path(output).resolve()
    version = plistlib.loads((source / 'System/Library/CoreServices/SystemVersion.plist').read_bytes())
    if (version.get('ProductVersion', '').split('.')[0] != '27'
            or version.get('ProductName') != 'iPhone OS'):
        raise ValueError('Expected an iOS 27 resource source')
    manifest_path = output / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    files = {}
    # Validate the complete selection before changing the staged sysroot.
    for relative in paths:
        relative = Path(relative)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Resources must stay below the supplied system root')
        selected = source / relative
        if selected.is_symlink() or not selected.exists():
            raise ValueError(f'Missing or symbolic resource: {relative}')
        candidates = sorted(selected.rglob('*')) if selected.is_dir() else [selected]
        for path in candidates:
            if path.is_symlink() or not path.resolve().is_relative_to(source):
                raise ValueError(f'Resource escapes the supplied system root: {path}')
            if not path.is_file():
                continue
            with path.open('rb') as stream:
                if stream.read(4) in CODE_MAGICS:
                    raise ValueError(f'Executable code must use signed AOT packaging: {path}')
                stream.seek(0)
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            name = path.relative_to(source).as_posix()
            files[name] = {'bytes': path.stat().st_size,
                           'sha256': digest}
    for name in files:
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    manifest['files'] = sorted(set(manifest['files']) | files.keys())
    sources = manifest.setdefault('resourceSources', [])
    sources.append({'root': str(source), 'systemVersion': version, 'files': files})
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')
    return files


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('resources', nargs='+', help='source-relative files or directories')
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    print(json.dumps(stage(args.source, args.output, args.resources), indent=2))
