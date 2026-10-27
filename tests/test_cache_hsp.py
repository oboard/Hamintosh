import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import cache_hsp


def package(path, cache=b'original cache', year=2024):
    with zipfile.ZipFile(path, 'w') as archive:
        entry = zipfile.ZipInfo('libs/arm64-v8a/libhm_ioscache.so', (year, 1, 1, 0, 0, 0))
        archive.writestr(entry, cache)
        archive.writestr('module.json', '{"module":{"name":"ioscache"}}')


class CacheHspTests(unittest.TestCase):
    def test_staging_does_not_share_a_mutable_inode_with_the_aot_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, staged = root / 'source.so', root / 'staged.so'
            source.write_bytes(b'original code')
            staged.hardlink_to(source)
            with patch.object(cache_hsp, 'PREBUILT', staged):
                cache_hsp.stage_prebuilt(source)
                source.write_bytes(b'updated code')
                self.assertEqual(staged.read_bytes(), b'original code')
                cache_hsp.stage_prebuilt(source)
                self.assertEqual(staged.read_bytes(), b'updated code')

    def test_payload_identity_ignores_zip_timestamps_and_detects_cache_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cache.hsp'
            package(path)
            first = cache_hsp.identity(path)
            package(path, year=2025)
            self.assertEqual(cache_hsp.identity(path), first)
            package(path, cache=b'changed cache')
            changed = cache_hsp.identity(path)
            self.assertNotEqual(changed['sha256'], first['sha256'])
            self.assertNotEqual(changed['cacheSHA256'], first['cacheSHA256'])
            self.assertEqual(cache_hsp.cached_identity(path), changed)
            with patch.object(cache_hsp, 'identity', side_effect=AssertionError('unchanged archive rehashed')):
                self.assertEqual(cache_hsp.cached_identity(path), changed)
            package(path, cache=b'new cache')
            self.assertNotEqual(cache_hsp.cached_identity(path)['cacheSHA256'], changed['cacheSHA256'])

    def test_only_reuses_an_installed_matching_module_and_publishes_after_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hsp, hap = root / 'cache.hsp', root / 'entry.hap'
            package(hsp)
            with zipfile.ZipFile(hap, 'w') as archive:
                archive.writestr('module.json', '{}')
            args = SimpleNamespace(bundle='test.bundle', output=root,
                                   compressed_install=True, force_cache_hsp=False)
            remote, events = {}, []
            installed = False
            fail = False

            def run(command, **kwargs):
                nonlocal installed
                words = list(map(str, command))
                if 'recv' in words and remote:
                    Path(words[-1]).write_text(json.dumps(remote))
                if 'dump' in words:
                    output = json.dumps({'moduleNames': ['ioscache'] if installed else []})
                elif 'install' in words:
                    events.append(('install', words))
                    if fail:
                        output = 'installation failed'
                    else:
                        installed, output = True, 'install bundle successfully.'
                elif 'send' in words:
                    if words[-1] == cache_hsp.STAMP:
                        remote.update(json.loads(Path(words[-2]).read_text()))
                        events.append(('stamp', words))
                    else:
                        events.append(('payload', words[-2]))
                    output = 'FileTransfer finish'
                else:
                    output = ''
                return subprocess.CompletedProcess(words, 0, output, '')

            command = lambda args, *parts: ['hdc', *parts]
            with patch.object(cache_hsp, 'HSP', hsp), contextlib.redirect_stdout(io.StringIO()):
                first = cache_hsp.install(args, hap, run, command)
                self.assertEqual(first['cacheHsp'], 'transferred')
                self.assertEqual([event[0] for event in events], ['payload', 'payload', 'install', 'stamp'])
                events.clear()
                package(hsp, year=2025)
                second = cache_hsp.install(args, hap, run, command)
                self.assertEqual(second['cacheHsp'], 'reuse')
                self.assertEqual([event[0] for event in events], ['payload', 'install'])
                self.assertNotIn('/data/local/tmp/harmonios-ioscache.hsp', events[-1][1])
                events.clear()
                installed = False
                third = cache_hsp.install(args, hap, run, command)
                self.assertEqual(third['cacheHsp'], 'transferred')
                before = dict(remote)
                fail = True
                package(hsp, cache=b'new cache')
                events.clear()
                with self.assertRaisesRegex(RuntimeError, 'installation failed'):
                    cache_hsp.install(args, hap, run, command)
                self.assertEqual(remote, before)
                self.assertFalse(any(kind == 'stamp' for kind, _ in events))

    def test_rejects_cache_in_entry_hap(self):
        with tempfile.TemporaryDirectory() as directory:
            hsp, hap = Path(directory) / 'cache.hsp', Path(directory) / 'entry.hap'
            package(hsp)
            package(hap)
            with patch.object(cache_hsp, 'HSP', hsp):
                with self.assertRaisesRegex(RuntimeError, 'Entry HAP'):
                    cache_hsp.install(None, hap, None, None)


if __name__ == '__main__':
    unittest.main()
