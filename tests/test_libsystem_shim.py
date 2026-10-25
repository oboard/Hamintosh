from pathlib import Path
import struct
import sys
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
