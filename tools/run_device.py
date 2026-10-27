#!/usr/bin/env python3
"""Build, install, launch, and collect one Harmonios device run."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

from analyze_device_fault import analyze, load_cache_info
import cache_hsp

ROOT = Path(__file__).resolve().parents[1]
HVIGOR = Path('/Applications/DevEco-Studio.app/Contents/tools/hvigor/bin/hvigorw')
HAP = ROOT / 'harmonios/build/default/outputs/default/harmonios-default-signed.hap'
PAGES = ROOT / 'tools/hello-world-cache-pages.json'
CACHE_PRIMARY = ROOT / 'artifacts/ios27-system/cache/dyld_shared_cache_arm64e'
CACHE_OUTPUT = ROOT / 'artifacts/ios27-aot'
CACHE_ELF = CACHE_OUTPUT / 'libhm_ioscache.so'
CACHE_LAYOUT = ROOT / 'artifacts/ios27-cache-layout.json'
CACHE_CLANG = Path('/Applications/DevEco-Studio.app/Contents/sdk/default/hms/native/BiSheng/bin/clang')
DEFAULT_BUNDLE = 'fun.oboard.hamintosh'
DEFAULT_ABILITY = 'HarmoniosAbility'
REPORT_TAG = 'HarmoniosReport'
REPORT_RE = re.compile(r'HarmoniosReport:\s*(?:\[[^]]+\])?\s*(\d+) (.*)')
# HDC -b resolves paths below its debug mount, not the app's root mount.
CACHE_DATA_REMOTE = 'data/storage/el2/base/haps/harmonios/files/sysroot/cache-data.pack'


def cache_reader_inputs():
    # These are the actual dependencies of hm-cache-info/plan. Darwin syscall
    # and thread fixes must rebuild the small runtime, not regenerate the AOT
    # cache or its independent non-executable data pack.
    source = ROOT / 'runtime/src'
    return [ROOT / 'runtime/Cargo.toml', ROOT / 'runtime/Cargo.lock', source / 'lib.rs',
            source / 'cache.rs', source / 'macho.rs', source / 'bin/cache_info.rs',
            source / 'bin/cache_plan.rs', *(source / 'cache').glob('*.rs'),
            *(source / 'macho').glob('*.rs'),
            *CACHE_PRIMARY.parent.glob('dyld_shared_cache_arm64e*')]


def run(command, *, capture=False, check=True):
    result = subprocess.run(
        [str(item) for item in command],
        cwd=ROOT,
        text=True,
        encoding='utf-8',
        errors='replace',
        capture_output=capture,
        check=False,
    )
    if check and result.returncode:
        message = (result.stderr or result.stdout or '').strip()
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(map(str, command))}\n{message}")
    return result


def device_command(args, *command):
    return ['hdc'] + (['-t', args.device] if args.device else []) + list(command)


def hvigor(args, task, module='harmonios'):
    common = [
        HVIGOR,
        task,
        '--mode',
        'module',
        '-p',
        'product=default',
        '-p',
        f'module={module}@default',
        '--no-daemon',
    ]
    if task in ('assembleHap', 'assembleHsp'):
        common[2:2] = ['-p', 'buildMode=debug']
    print(f'==> hvigor {task}', flush=True)
    run(common)


def decode_report(records):
    chunks = {}
    for match in REPORT_RE.finditer(records):
        offset = int(match.group(1))
        if offset == 0:
            chunks = {}
        chunks[offset] = match.group(2)
    if not chunks:
        return None
    text = ''
    for offset in sorted(chunks):
        if offset != len(text):
            return None
        text += chunks[offset]
    try:
        report = json.loads(text)
    except json.JSONDecodeError:
        return None
    return report, text


def has_cache_fault(dyld):
    return (dyld.get('faultPc') not in (None, '', 0, '0', '0x0')
            and re.search(r'PC cache\+0x[0-9a-fA-F]+', dyld.get('detail', '')) is not None)


def capture_screenshot(args, output):
    remote = '/data/local/tmp/harmonios-latest.jpeg'
    run(device_command(args, 'shell', 'snapshot_display', '-f', remote))
    run(device_command(args, 'file', 'recv', remote, output / 'harmonios-latest.jpeg'))
    return output / 'harmonios-latest.jpeg'


def capture_incomplete_run(args, records):
    """Preserve evidence when a crash or a blocked guest prevents a report."""
    (args.output / 'report-device-incomplete.log').write_text(records)
    evidence = {}
    for name, command in {
        'process': ('pidof', args.bundle),
        'runtime': ('hilog', '-x', '-T', 'Harmonios'),
        'system': ('hilog', '-x'),
    }.items():
        result = run(device_command(args, 'shell', *command), capture=True, check=False)
        evidence[name] = {'exitCode': result.returncode,
                          'output': result.stdout + result.stderr}
        (args.output / f'incomplete-{name}.log').write_text(evidence[name]['output'])
    # No PID can also mean a lookup/connection failure; never label that a crash.
    process = evidence['process']
    evidence['processObservedAlive'] = (
        process['exitCode'] == 0 and bool(re.fullmatch(r'\s*\d+(?:\s+\d+)*\s*', process['output']))
    )
    try:
        evidence['screenshot'] = str(capture_screenshot(args, args.output))
    except (OSError, RuntimeError) as error:
        evidence['screenshotError'] = str(error)
    (args.output / 'incomplete-run.json').write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + '\n')
    return evidence


def launch_command(args):
    return ['aa', 'start', '-a', args.ability, '-b', args.bundle]


def launch_application(args, label='launch'):
    print(f'==> {label}', flush=True)
    launched = run(device_command(args, 'shell', *launch_command(args)), capture=True, check=False)
    launch_text = launched.stdout + launched.stderr
    if 'error:' in launch_text and 'screen is locked' in launch_text:
        print('==> screen locked; try wake and swipe', flush=True)
        run(device_command(args, 'shell', 'uitest', 'uiInput', 'swipe',
                           '636', '2400', '636', '500', '1000'), check=False)
        launched = run(device_command(args, 'shell', *launch_command(args)), capture=True, check=False)
        launch_text = launched.stdout + launched.stderr
    if launch_text.strip():
        print(launch_text.strip(), flush=True)
    if 'error:' in launch_text:
        raise SystemExit('launch failed; unlock the device and rerun')
    return launch_text


def warm_up_guest_data(args):
    """Let ArkTS create its private sysroot before HDC stages the data pack."""
    launch_application(args, 'warm-up launch')
    print(f'==> wait {args.warm_up_timeout:g}s for guest directories', flush=True)
    time.sleep(args.warm_up_timeout)
    run(device_command(args, 'shell', 'aa', 'force-stop', args.bundle), check=False)


def stage_cache_data(args):
    pack = args.cache_data_pack.resolve()
    if not args.stage_cache_data or not pack.is_file():
        return
    manifest = json.loads(pack.with_suffix(pack.suffix + '.json').read_text())
    if (manifest['bytes'] != pack.stat().st_size or
            manifest['primaryUUID'] != json.loads(PAGES.read_text())['primaryUUID']):
        raise RuntimeError('cache data package identity or size mismatch')
    remote = CACHE_DATA_REMOTE
    stamp = args.output / 'cache-data-device.json'
    stamp.unlink(missing_ok=True)
    run(device_command(args, 'file', 'recv', '-b', args.bundle, remote + '.json', stamp), capture=True, check=False)
    try:
        previous = json.loads(stamp.read_text())
    except (OSError, ValueError):
        previous = {}
    if all(previous.get(key) == manifest[key] for key in ('sha256', 'bytes', 'primaryUUID')):
        check_pack = run(device_command(args, 'shell', '-b', args.bundle, 'ls', CACHE_DATA_REMOTE), capture=True, check=False)
        if 'cache-data.pack' in check_pack.stdout:
            print('==> reuse staged cache data', flush=True)
            return
    if args.warm_up:
        warm_up_guest_data(args)
    with pack.open('rb') as source:
        if hashlib.file_digest(source, 'sha256').hexdigest() != manifest['sha256']:
            raise RuntimeError('cache data package SHA-256 mismatch')
    print('==> stage non-executable cache data', flush=True)
    transferred = run(device_command(args, 'file', 'send', '-b', args.bundle, '-z', pack, remote), capture=True)
    if 'FileTransfer finish' not in transferred.stdout:
        raise RuntimeError('cache data transfer did not finish: ' + transferred.stdout + transferred.stderr)
    print(transferred.stdout.strip(), flush=True)
    run(device_command(args, 'file', 'send', '-b', args.bundle,
                       pack.with_suffix(pack.suffix + '.json'), remote + '.json'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', help='HDC connection identifier')
    parser.add_argument('--bundle', default=DEFAULT_BUNDLE,
                        help='installed bundle name used for launch and debug file staging')
    parser.add_argument('--ability', default=DEFAULT_ABILITY, help='entry ability name')
    parser.add_argument('--skip-build', action='store_true')
    parser.add_argument('--skip-install', action='store_true')
    parser.add_argument('--force-cache-hsp', action='store_true',
                        help='reinstall the signed cache HSP even if its payload stamp matches')
    parser.add_argument('--compressed-install', action='store_true',
                        help='compress HDC transfer of HAPs containing uncompressed native libraries')
    parser.add_argument('--cache-data-pack', type=Path, default=ROOT / 'artifacts/ios27-data/cache-data.pack')
    parser.add_argument('--stage-cache-data', action=argparse.BooleanOptionalAction, default=True,
                        help='stage an existing cache data pack once per content hash')
    parser.add_argument('--repack-cache', action=argparse.BooleanOptionalAction, default=True,
                        help='repack selected cache pages when their manifest is newer')
    parser.add_argument('--clean', action=argparse.BooleanOptionalAction, default=True,
                        help='clean before building to avoid stale packaged native libraries')
    parser.add_argument('--timeout', type=float, default=60, help='diagnostic timeout in seconds')
    parser.add_argument('--interval', type=float, default=0.5, help='poll interval in seconds')
    parser.add_argument('--warm-up', action=argparse.BooleanOptionalAction, default=True,
                        help='launch once before staging data when the remote stamp is absent')
    parser.add_argument('--warm-up-timeout', type=float, default=15,
                        help='seconds to let the first launch create guest directories')
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts')
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)

    if not args.skip_build:
        if json.loads(PAGES.read_text()).get('lazyData') and CACHE_PRIMARY.is_file():
            data_inputs = [ROOT / 'tools/pack_cache_data.py', ROOT / 'tools/pack_cache.py', *cache_reader_inputs()]
            if not args.cache_data_pack.is_file() or any(
                    p.stat().st_mtime > args.cache_data_pack.stat().st_mtime for p in data_inputs):
                print('==> prepare demand-paged cache data', flush=True)
                prepared = run([sys.executable, ROOT / 'tools/pack_cache_data.py',
                                CACHE_PRIMARY, args.cache_data_pack], capture=True)
                (args.output / 'cache-data-pack.log').write_text(prepared.stdout + prepared.stderr)
        cache_inputs = [PAGES, ROOT / 'tools/pack_cache.py', *cache_reader_inputs()]
        cache_stale = (not CACHE_ELF.is_file() or any(
            path.stat().st_mtime > CACHE_ELF.stat().st_mtime for path in cache_inputs))
        if args.repack_cache and CACHE_PRIMARY.is_file() and cache_stale:
            print('==> repack cache', flush=True)
            packed = run([
                sys.executable,
                ROOT / 'tools/pack_cache.py',
                CACHE_PRIMARY,
                CACHE_OUTPUT,
                '--clang',
                CACHE_CLANG,
                '--pages',
                PAGES,
            ], capture=True)
            (args.output / 'cache-pack.log').write_text(packed.stdout + packed.stderr)
        if CACHE_PRIMARY.is_file() and CACHE_LAYOUT.is_file() and (CACHE_OUTPUT / 'package.json').is_file():
            print('==> audit Darwin syscall boundary', flush=True)
            audited = run([
                sys.executable, ROOT / 'tools/audit_libsystem_shim.py',
                CACHE_PRIMARY, CACHE_LAYOUT,
                CACHE_OUTPUT / 'package.json', CACHE_OUTPUT,
                '--reuse',
            ], capture=True)
            (args.output / 'libsystem-shim-audit.log').write_text(audited.stdout + audited.stderr)
            if 'reuse verified Darwin boundary audit' in audited.stdout:
                print('==> reuse verified Darwin boundary audit', flush=True)
        if args.clean:
            hvigor(args, 'clean')
        cache_hsp.stage_prebuilt(CACHE_ELF)
        hvigor(args, 'assembleHsp', 'ioscache')
        hvigor(args, 'assembleHap')
    if not HAP.is_file():
        raise SystemExit(f'HAP not found: {HAP}')

    if not args.skip_install:
        print('==> install', flush=True)
        cache_hsp.install(args, HAP, run, device_command)

    print('==> wake', flush=True)
    run(device_command(args, 'shell', 'power-shell', 'wakeup'), check=False)
    print('==> force-stop', flush=True)
    run(device_command(args, 'shell', 'aa', 'force-stop', args.bundle), check=False)
    stage_cache_data(args)
    # Debug-sandbox access can start the app before the data pack is ready.
    # Restart it after staging so aboutToAppear runs diagnostics with that pack.
    print('==> force-stop after staging', flush=True)
    run(device_command(args, 'shell', 'aa', 'force-stop', args.bundle), check=False)
    print('==> clear log', flush=True)
    run(device_command(args, 'shell', 'hilog', '-r'), check=False)
    date_res = run(device_command(args, 'shell', 'date', '+%s%3N'), capture=True, check=False)
    launch_time_ms = int(date_res.stdout.strip()) if date_res.returncode == 0 and date_res.stdout.strip().isdigit() else 0

    launch_application(args)

    deadline = time.monotonic() + args.timeout
    records = ''
    report = None
    report_text = None
    while time.monotonic() < deadline:
        remote_report = 'data/storage/el2/base/haps/harmonios/files/compat-report.json'
        disk_report = args.output / 'device-compat-report.json'
        disk_res = run(device_command(args, 'file', 'recv', '-b', args.bundle, remote_report, disk_report),
                       capture=True, check=False)
        if disk_res.returncode == 0 and disk_report.is_file():
            try:
                content = disk_report.read_text()
                parsed = json.loads(content)
                if parsed.get('timestamp', 0) >= launch_time_ms and (
                        parsed.get('dyldBootstrap', {}).get('status') or parsed.get('preflight', {}).get('appExecuted')):
                    report = parsed
                    report_text = content
                    break
            except Exception:
                pass
        result = run(device_command(args, 'shell', 'hilog', '-x', '-T', REPORT_TAG),
                     capture=True, check=False)
        records = result.stdout
        decoded = decode_report(records)
        if decoded is not None:
            report, report_text = decoded
            dyld = report.get('dyldBootstrap', {})
            if dyld.get('status') or report.get('preflight', {}).get('appExecuted'):
                break
        time.sleep(args.interval)

    if report is None or report_text is None:
        evidence = capture_incomplete_run(args, records)
        print(evidence['runtime']['output'][-12000:], file=sys.stderr)
        raise SystemExit(f'diagnostic report not completed within {args.timeout:g}s; '
                         f'evidence: {args.output / "incomplete-run.json"}')

    (args.output / 'report-device.log').write_text(records)
    (args.output / 'device-compat-report.json').write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + '\n'
    )
    screenshot = capture_screenshot(args, args.output)
    dyld = report.get('dyldBootstrap', {})
    fault = None
    if has_cache_fault(dyld):
        fault = analyze(
            report,
            load_cache_info(CACHE_PRIMARY),
            json.loads((CACHE_OUTPUT / 'package.json').read_text()),
            json.loads(PAGES.read_text()),
        )
        (args.output / 'fault-analysis.json').write_text(
            json.dumps(fault, indent=2, ensure_ascii=False) + '\n'
        )
    print(json.dumps({
        'report': str(args.output / 'device-compat-report.json'),
        'screenshot': str(screenshot),
        'status': dyld.get('status'),
        'traps': dyld.get('traps'),
        'signal': dyld.get('signal'),
        'appExecuted': report.get('preflight', {}).get('appExecuted'),
        'detail': dyld.get('detail'),
        'faultPage': fault.get('faultPage') if fault else None,
        'faultImage': fault.get('faultImage') if fault else None,
        'selectedInPackage': fault.get('selectedInPackage') if fault else None,
    }, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
