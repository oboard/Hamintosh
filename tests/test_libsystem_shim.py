from pathlib import Path
import json
import os
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import audit_libsystem_shim as audit


class LibsystemShimAuditTests(unittest.TestCase):
    def fixture(self, directory):
        source = directory / 'source-page'
        source.write_bytes(struct.pack('<4I', audit.SVC80, 0xD53BD068, 0, 0))
        output = directory / 'pages-000.bin'
        output.write_bytes(struct.pack('<4I', audit.TRAP_MARKER, 0xD4294100, 0, 0))
        ranges = [dict(path=str(source), fileOffset=0, offset=0, size=16, protection=5)]
        patches = [
            dict(offset=0, original='svc #0x80'),
            dict(offset=4, original='mrs x8, tpidrro_el0'),
        ]
        return ranges, patches, output

    def test_selected_pages_have_no_untranslated_darwin_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            ranges, patches, output = self.fixture(Path(temporary))
            result = audit.audit_ranges(ranges, patches, output.parent)
            self.assertEqual(result['issues'], [])
            self.assertEqual(result['source'], {'svc80': 1, 'tpidrro': 1})
            self.assertEqual(result['patched'], {'svc80': 1, 'tpidrro': 1})
            self.assertEqual(result['packedRemaining'], {'svc80': 0, 'tpidrro': 0})
            self.assertEqual(result['trapMarkers'], {'svc80': 1, 'tpidrro': 1})


    def test_missing_absolute_path_is_rebased_to_the_current_cache_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            name = 'dyld_shared_cache_arm64e.03'
            (root / name).write_bytes(b'cache-page')
            record = dict(path=str(root / 'old' / name),
                          fileOffset=0, offset=0, size=10, protection=5)
            self.assertEqual(audit._read_range(record, root), b'cache-page')

    def test_raw_source_call_or_missing_patch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            ranges, patches, output = self.fixture(Path(temporary))
            output.write_bytes(struct.pack('<4I', audit.SVC80, audit.TRAP_MARKER, 0, 0))
            result = audit.audit_ranges(ranges[:1], [], output.parent)
            self.assertTrue(result['issues'])
            self.assertEqual(result['packedRemaining']['svc80'], 1)

    def test_export_trie_is_enumerated_without_following_cycles(self):
        trie = b'\x00\x01_foo\x00\x08\x03\x00\x10\x00\x00'
        self.assertEqual(audit.parse_export_trie(trie, 0x1000),
                         [{'name': '_foo', 'address': 0x1010}])

    def test_manifest_never_claims_full_image_replacement(self):
        boundary = dict(issues=[], selectedExecutableRanges=1,
                        source={'svc80': 1, 'tpidrro': 1},
                        patched={'svc80': 1, 'tpidrro': 1},
                        packedRemaining={'svc80': 0, 'tpidrro': 0},
                        trapMarkers={'svc80': 1, 'tpidrro': 1})
        manifest = audit.build_manifest({'demandImages': []}, {}, boundary)
        self.assertEqual(manifest['status'], 'svc-boundary-verified-wrapper-still-executed')
        self.assertFalse(manifest['directHostSyscallABI'])
        self.assertFalse(manifest['fullLibsystemKernelReplacement'])
        self.assertEqual(manifest['replacementLevel'], 'svc-trap-boundary')
        self.assertEqual(manifest['libsystemKernel']['exportCount'], 0)
        self.assertEqual(manifest['libsystemKernel']['exports'], [])
        self.assertIn('remainingHardBlocker', manifest)

    def cache_fixture(self, root):
        ranges, patches, piece = self.fixture(root)
        cache_info = root / 'cache.json'
        cache_info.write_text(json.dumps({'files': []}))
        package = root / 'package.json'
        package.write_text(json.dumps({'ranges': ranges, 'syscallPatches': patches}))
        script = root / 'audit_libsystem_shim.py'
        script.write_text('audit implementation')
        pack_script = root / 'pack_cache.py'
        pack_script.write_text('cache reader implementation')
        return Path(ranges[0]['path']), cache_info, package, piece, script, pack_script

    def test_audit_reuse_invalidates_on_all_inputs_and_report_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, info, package, piece, script, reader = self.cache_fixture(root)
            with patch.object(audit, '__file__', str(script)), \
                    patch.object(audit, 'audit_ranges', wraps=audit.audit_ranges) as scan:
                args = (source, info, package, root)
                self.assertFalse(audit.audit_cached(*args, reuse=True)[1])
                self.assertTrue(audit.audit_cached(*args, reuse=True)[1])
                self.assertEqual(scan.call_count, 1)
                relative_args = tuple(Path(os.path.relpath(p)) for p in args)
                self.assertTrue(audit.audit_cached(*relative_args, reuse=True)[1])
                for changed in (source, piece, info, package, script, reader):
                    # Preserve size, content AND mtime; ctime must invalidate
                    # even a rewrite that a size/mtime-only cache would miss.
                    before = changed.stat()
                    changed.write_bytes(changed.read_bytes())
                    os.utime(changed, ns=(before.st_atime_ns, before.st_mtime_ns))
                    calls = scan.call_count
                    self.assertFalse(audit.audit_cached(*args, reuse=True)[1], changed.name)
                    self.assertEqual(scan.call_count, calls + 1)
                    self.assertTrue(audit.audit_cached(*args, reuse=True)[1])
                report = root / 'libsystem-shim.json'
                report.write_text(report.read_text() + '\n')
                self.assertFalse(audit.audit_cached(*args, reuse=True)[1])
                (root / 'libsystem-shim.identity.json').write_text('corrupt stamp')
                self.assertFalse(audit.audit_cached(*args, reuse=True)[1])

    def test_input_changed_during_audit_does_not_publish_a_stamp(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, info, package, piece, script, _ = self.cache_fixture(root)
            scan = audit.audit_ranges
            def scan_and_replace(*args):
                result = scan(*args)
                piece.write_bytes(piece.read_bytes())
                return result
            with patch.object(audit, '__file__', str(script)), \
                    patch.object(audit, 'audit_ranges', side_effect=scan_and_replace):
                self.assertFalse(audit.audit_cached(source, info, package, root)[1])
                self.assertFalse((root / 'libsystem-shim.identity.json').exists())

    def test_failed_audit_never_publishes_a_reusable_stamp(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, info, package, piece, script, _ = self.cache_fixture(root)
            with patch.object(audit, '__file__', str(script)):
                args = (source, info, package, root)
                self.assertFalse(audit.audit_cached(*args)[1])
                piece.write_bytes(struct.pack('<4I', audit.SVC80, 0, 0, 0))
                manifest, reused = audit.audit_cached(*args, reuse=True)
                self.assertEqual(manifest['status'], 'invalid')
                self.assertFalse(reused)
                self.assertFalse((root / 'libsystem-shim.identity.json').exists())
                piece.unlink()
                self.assertFalse(audit.audit_cached(*args, reuse=True)[1])


if __name__ == '__main__':
    unittest.main()
