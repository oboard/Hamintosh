"""Content identity and debug-device reuse for the signed cache HSP."""
import hashlib
import json
from pathlib import Path
import shutil
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
HSP = ROOT / 'ioscache/build/default/outputs/default/ioscache-default-signed.hsp'
PREBUILT = ROOT / 'ioscache/libs/arm64-v8a/libhm_ioscache.so'
STAMP = 'data/storage/el2/base/haps/harmonios/files/ioscache-installed.json'


def stage_prebuilt(source):
    with source.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    previous = None
    if PREBUILT.is_file():
        with PREBUILT.open('rb') as stream:
            previous = hashlib.file_digest(stream, 'sha256').hexdigest()
    if previous != digest or PREBUILT.samefile(source):
        PREBUILT.parent.mkdir(parents=True, exist_ok=True)
        partial = PREBUILT.with_suffix('.partial')
        shutil.copyfile(source, partial)
        partial.replace(PREBUILT)
    return digest


def identity(path):
    # HAP/HSP signing blocks and ZIP timestamps can change on a rebuild.
    # Hash every uncompressed member, including module/app metadata and native
    # code, so a re-sign alone cannot cause a 660 MB retransmission.
    digest = hashlib.sha256()
    cache_digest = None
    cache_size = 0
    with zipfile.ZipFile(path) as archive:
        for item in sorted(archive.infolist(), key=lambda value: value.filename):
            name = item.filename.encode('utf-8')
            digest.update(len(name).to_bytes(4, 'little') + name)
            digest.update(item.file_size.to_bytes(8, 'little'))
            cache = hashlib.sha256() if item.filename == 'libs/arm64-v8a/libhm_ioscache.so' else None
            with archive.open(item) as stream:
                for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
                    digest.update(block)
                    if cache is not None:
                        cache.update(block)
            if cache is not None:
                cache_digest, cache_size = cache.hexdigest(), item.file_size
    if cache_digest is None:
        raise ValueError('Signed cache HSP does not contain its ARM64 ELF')
    return {'sha256': digest.hexdigest(), 'cacheSHA256': cache_digest,
            'cacheBytes': cache_size, 'module': 'ioscache', 'ready': True}


def cached_identity(path):
    # Rehash a rebuilt archive, but do not read an unchanged 660 MB file on
    # every install. Replacement, resize or modification invalidates this
    # local cache; the device still compares the verified payload SHA-256.
    info = path.stat()
    fingerprint = [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
    cache = path.with_suffix(path.suffix + '.identity.json')
    try:
        saved = json.loads(cache.read_text())
        if saved['file'] == fingerprint and saved['payload'].get('ready') is True:
            return saved['payload']
    except (OSError, ValueError, KeyError, TypeError):
        pass
    payload = identity(path)
    cache.write_text(json.dumps({'file': fingerprint, 'payload': payload}, indent=2) + '\n')
    return payload


def install(args, hap, run, device_command):
    if not HSP.is_file():
        raise RuntimeError(f'Signed cache HSP not found: {HSP}')
    with zipfile.ZipFile(hap) as archive:
        if any(name.endswith('/libhm_ioscache.so') for name in archive.namelist()):
            raise RuntimeError('Entry HAP must not contain the cache ELF')
    started = time.monotonic()
    current = dict(cached_identity(HSP))
    current['bundle'] = args.bundle
    received = args.output / 'ioscache-device-stamp.json'
    received.unlink(missing_ok=True)
    run(device_command(args, 'file', 'recv', '-b', args.bundle, STAMP, received), capture=True, check=False)
    try:
        previous = json.loads(received.read_text())
    except (OSError, ValueError):
        previous = {}
    dumped = run(device_command(args, 'shell', 'bm', 'dump', '-n', args.bundle), capture=True, check=False)
    try:
        bundle = json.loads(dumped.stdout[dumped.stdout.index('{'):])
        present = 'ioscache' in bundle.get('moduleNames', [])
    except (ValueError, TypeError):
        present = False
    reuse = present and previous == current and not args.force_cache_hsp
    timings = {'hapBytes': hap.stat().st_size, 'cacheHspBytes': HSP.stat().st_size,
               'cacheHsp': 'reuse' if reuse else 'transferred', **current}
    timings['cacheCheckSeconds'] = time.monotonic() - started
    remote_hap = '/data/local/tmp/harmonios-install.hap'
    remote_hsp = '/data/local/tmp/harmonios-ioscache.hsp'
    paths = [remote_hap]
    if reuse:
        print('==> reuse installed cache HSP; skip cache transfer', flush=True)
    else:
        print('==> stage signed cache HSP', flush=True)
        sent = run(device_command(args, 'file', 'send', '-z', HSP, remote_hsp), capture=True)
        if 'FileTransfer finish' not in sent.stdout:
            raise RuntimeError('cache HSP transfer did not finish: ' + sent.stdout + sent.stderr)
        print(sent.stdout.strip(), flush=True)
        paths.append(remote_hsp)
    timings['cacheHspSeconds'] = time.monotonic() - started
    begin = time.monotonic()
    compression = ['-z'] if args.compressed_install else []
    sent = run(device_command(args, 'file', 'send', *compression, hap, remote_hap), capture=True)
    if 'FileTransfer finish' not in sent.stdout:
        raise RuntimeError('entry HAP transfer did not finish: ' + sent.stdout + sent.stderr)
    print(sent.stdout.strip(), flush=True)
    timings['hapTransferSeconds'] = time.monotonic() - begin
    begin = time.monotonic()
    result = run(device_command(args, 'shell', 'bm', 'install', '-r', '-p', *paths), capture=True)
    message = result.stdout + result.stderr
    print(message.strip(), flush=True)
    if 'install bundle successfully' not in message:
        raise RuntimeError('HAP/HSP installation failed')
    timings['bmInstallSeconds'] = time.monotonic() - begin
    if not reuse:
        stamp = args.output / 'ioscache-installed.json'
        stamp.write_text(json.dumps(current, indent=2) + '\n')
        run(device_command(args, 'file', 'send', '-b', args.bundle, stamp, STAMP), capture=True)
    run(device_command(args, 'shell', 'rm', '-f', *paths), capture=True, check=False)
    timings['installSeconds'] = time.monotonic() - started
    (args.output / 'iteration-timings.json').write_text(json.dumps(timings, indent=2) + '\n')
    print(f'==> install completed in {timings["installSeconds"]:.3f}s', flush=True)
    return timings
