#!/usr/bin/env python3
"""Build, install, launch, and collect one Hamintosh device run."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

from analyze_device_fault import analyze, load_cache_info

ROOT = Path(__file__).resolve().parents[1]
HVIGOR = Path('/Applications/DevEco-Studio.app/Contents/tools/hvigor/bin/hvigorw')
HAP = ROOT / 'hamintosh/build/default/outputs/default/hamintosh-default-signed.hap'
PAGES = ROOT / 'tools/hello-world-cache-pages.json'
CACHE_PRIMARY = ROOT / 'artifacts/ios27-system/cache/dyld_shared_cache_arm64e'
CACHE_OUTPUT = ROOT / 'artifacts/ios27-aot'
CACHE_ELF = CACHE_OUTPUT / 'libhm_ioscache.so'
CACHE_CLANG = Path('/Applications/DevEco-Studio.app/Contents/sdk/default/hms/native/BiSheng/bin/clang')
BUNDLE = 'fun.oboard.hamintosh'
ABILITY = 'HamintoshAbility'
REPORT_TAG = 'HamintoshReport'
REPORT_RE = re.compile(r'HamintoshReport:\s*(?:\[[^]]+\])?\s*(\d+) (.*)')


def run(command, *, capture=False, check=True):
    result = subprocess.run(
        [str(item) for item in command],
        cwd=ROOT,
        text=True,
        capture_output=capture,
        check=False,
    )
    if check and result.returncode:
        message = (result.stderr or result.stdout or '').strip()
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(map(str, command))}\n{message}")
    return result


def device_command(args, *command):
    return ['hdc'] + (['-t', args.device] if args.device else []) + list(command)


def hvigor(args, task):
    common = [
        HVIGOR,
        task,
        '--mode',
        'module',
        '-p',
        'product=default',
        '-p',
        'module=hamintosh@default',
        '--no-daemon',
    ]
    if task == 'assembleHap':
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


def capture_screenshot(args, output):
    remote = '/data/local/tmp/hamintosh-latest.jpeg'
    run(device_command(args, 'shell', 'snapshot_display', '-f', remote))
    run(device_command(args, 'file', 'recv', remote, output / 'hamintosh-latest.jpeg'))
    return output / 'hamintosh-latest.jpeg'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', help='HDC connection identifier')
    parser.add_argument('--skip-build', action='store_true')
    parser.add_argument('--skip-install', action='store_true')
    parser.add_argument('--compressed-install', action='store_true',
                        help='compress HDC transfer of HAPs containing uncompressed native libraries')
    parser.add_argument('--repack-cache', action=argparse.BooleanOptionalAction, default=True,
                        help='repack selected cache pages when their manifest is newer')
    parser.add_argument('--clean', action=argparse.BooleanOptionalAction, default=True,
                        help='clean before building to avoid stale packaged native libraries')
    parser.add_argument('--timeout', type=float, default=60, help='diagnostic timeout in seconds')
    parser.add_argument('--interval', type=float, default=0.5, help='poll interval in seconds')
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts')
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)

    if not args.skip_build:
        cache_inputs = [PAGES, ROOT / 'tools/pack_cache.py', *(
            ROOT / 'runtime/src').rglob('*.rs')]
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
        if args.clean:
            hvigor(args, 'clean')
        hvigor(args, 'assembleHap')
    if not HAP.is_file():
        raise SystemExit(f'HAP not found: {HAP}')

    if not args.skip_install:
        print('==> install', flush=True)
        if args.compressed_install:
            remote = '/data/local/tmp/hamintosh-install.hap'
            run(device_command(args, 'file', 'send', '-z', HAP, remote))
            installed = run(device_command(args, 'shell', 'bm', 'install', '-r', '-p', remote), capture=True)
            message = installed.stdout + installed.stderr
            print(message.strip(), flush=True)
            if 'install bundle successfully' not in message:
                raise SystemExit('compressed HAP installation failed')
            run(device_command(args, 'shell', 'rm', '-f', remote))
        else:
            run(device_command(args, 'install', '-r', HAP))

    print('==> wake', flush=True)
    run(device_command(args, 'shell', 'power-shell', 'wakeup'), check=False)
    print('==> force-stop', flush=True)
    run(device_command(args, 'shell', 'aa', 'force-stop', BUNDLE), check=False)
    print('==> clear log', flush=True)
    run(device_command(args, 'shell', 'hilog', '-r'), check=False)

    launch = ['aa', 'start', '-a', ABILITY, '-b', BUNDLE]
    print('==> launch', flush=True)
    launched = run(device_command(args, 'shell', *launch), capture=True, check=False)
    launch_text = launched.stdout + launched.stderr
    if 'error:' in launch_text and 'screen is locked' in launch_text:
        print('==> screen locked; try wake and swipe', flush=True)
        run(device_command(args, 'shell', 'uitest', 'uiInput', 'swipe',
                           '636', '2400', '636', '500', '1000'), check=False)
        launched = run(device_command(args, 'shell', *launch), capture=True, check=False)
        launch_text = launched.stdout + launched.stderr
    if launch_text.strip():
        print(launch_text.strip(), flush=True)
    if 'error:' in launch_text:
        raise SystemExit('launch failed; unlock the device and rerun')

    deadline = time.monotonic() + args.timeout
    records = ''
    report = None
    report_text = None
    while time.monotonic() < deadline:
        result = run(device_command(args, 'shell', 'hilog', '-x', '-T', REPORT_TAG),
                     capture=True, check=False)
        records = result.stdout
        decoded = decode_report(records)
        if decoded is not None:
            report, report_text = decoded
            dyld = report.get('dyldBootstrap', {})
            if dyld.get('traps', 0) > 0 or report.get('preflight', {}).get('appExecuted'):
                break
        time.sleep(args.interval)

    if report is None or report_text is None:
        log = run(device_command(args, 'shell', 'hilog', '-x', '-T', 'Hamintosh'),
                  capture=True, check=False).stdout
        print(log[-12000:], file=sys.stderr)
        raise SystemExit(f'diagnostic report not completed within {args.timeout:g}s')

    (args.output / 'report-device.log').write_text(records)
    (args.output / 'device-compat-report.json').write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + '\n'
    )
    screenshot = capture_screenshot(args, args.output)
    dyld = report.get('dyldBootstrap', {})
    fault = None
    if dyld.get('faultPc'):
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
