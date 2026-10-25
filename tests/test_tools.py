import io
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import json
import zlib
import struct
import hashlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import prepare_ipa
import extract_sysroot
import pack_cache


class CachePackageTests(unittest.TestCase):
    def test_data_pages_are_verified_in_readonly_blob_before_runtime_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            page = pack_cache.PAGE
            content = b'owned-data-page'.ljust(page, b'\0')
            image = bytearray(2 * page)
            image[:6] = b'\x7fELF\x02\x01'
            struct.pack_into('<HH', image, 16, 3, 183)
            struct.pack_into('<Q', image, 32, 64)
            struct.pack_into('<HH', image, 54, 56, 2)
            struct.pack_into('<II6Q', image, 64, 1, 4, 0, 0, 0, 2 * page, 2 * page, page)
            struct.pack_into('<II6Q', image, 120, 1, 4, 2 * page, 4 * page, 4 * page, 0, page, page)
            image[page:] = content
            library = Path(directory) / 'owned-cache-data.so'
            library.write_bytes(image)
            ranges = [dict(offset=0, size=page, protection=3, dataOffset=0,
                           packedSha256=hashlib.sha256(content).hexdigest())]
            pack_cache.verify_elf(library, ranges, 4 * page, page, page)
            image[page] ^= 1
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'contents'):
                pack_cache.verify_elf(library, ranges, 4 * page, page, page)
            image[page:] = content
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'escapes'):
                pack_cache.verify_elf(library, ranges, 4 * page, page, 4 * page)
            ranges[0]['protection'] = 5
            with self.assertRaisesRegex(ValueError, 'non-executable'):
                pack_cache.verify_elf(library, ranges, 4 * page, page, page)

    def test_reexports_require_bounded_terminated_install_names(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            image = bytearray(page)
            struct.pack_into('<8I', image, 0, 0xfeedfacf, 0x100000c, 0, 6, 2, 104, 0, 0)
            struct.pack_into('<II16sQQQQiiII', image, 32, 25, 72, b'__TEXT', base, page, 0, page, 5, 5, 0, 0)
            struct.pack_into('<6I', image, 104, 0x8000001f, 32, 24, 0, 0, 0)
            image[128:136] = b'/next\0\0\0'
            source = Path(directory) / 'owned-reexport-cache'
            source.write_bytes(image)
            cache = {'files': [dict(path=str(source), mappings=[dict(address=base, size=page, fileOffset=0)])]}
            names = []
            pack_cache.image_segments(cache, base, 6, names)
            self.assertEqual(names, ['/next'])
            struct.pack_into('<I', image, 112, 8)
            source.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'name offset'):
                pack_cache.image_segments(cache, base, 6, [])
            struct.pack_into('<I', image, 112, 24)
            image[128:136] = b'nonullll'
            source.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'Unterminated'):
                pack_cache.image_segments(cache, base, 6, [])

    def test_export_trie_uses_linkedit_file_to_vm_translation(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            image = bytearray(2 * page)
            struct.pack_into('<8I', image, 0, 0xfeedfacf, 0x100000c, 0x80000002, 6, 3, 160, 0, 0)
            for at, name, address, file_offset, protection in [
                    (32, b'__TEXT', base, 0, 5), (104, b'__LINKEDIT', base + 4 * page, page, 1)]:
                struct.pack_into('<II16sQQQQiiII', image, at, 25, 72, name, address, page,
                                 file_offset, page, protection, protection, 0, 0)
            struct.pack_into('<4I', image, 176, 0x80000033, 16, page + 8, 32)
            source = Path(directory) / 'owned-export-cache'
            source.write_bytes(image)
            cache = {'files': [dict(path=str(source), mappings=[
                dict(address=base, size=page, fileOffset=0),
                dict(address=base + 4 * page, size=page, fileOffset=page)])]}
            segments, _ = pack_cache.image_segments(cache, base, 6)
            self.assertEqual(segments[1]['exportsAddress'], base + 4 * page + 8)
            self.assertEqual(segments[1]['exportsSize'], 32)
            struct.pack_into('<I', image, 184, 2 * page - 8)
            source.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'escapes LINKEDIT'):
                pack_cache.image_segments(cache, base, 6)

    def test_cached_library_instruction_sections_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            image = bytearray(page)
            command_size = 72 + 2 * 80
            struct.pack_into('<8I', image, 0, 0xfeedfacf, 0x100000c, 0x80000002, 6, 1, command_size, 0, 0)
            struct.pack_into('<II16sQQQQiiII', image, 32, 25, command_size, b'__TEXT', base, page, 0, page, 5, 5, 2, 0)
            for i, flags in enumerate([0x80000400, 0]):
                at = 32 + 72 + i * 80
                struct.pack_into('<QQ', image, at + 32, base + 512 + 4 * i, 4)
                struct.pack_into('<I', image, at + 64, flags)
            source = Path(directory) / 'owned-library-cache'
            source.write_bytes(image)
            cache = {'files': [dict(path=str(source), mappings=[dict(address=base, size=page, fileOffset=0)])]}
            segments, code = pack_cache.image_segments(cache, base, 6)
            self.assertEqual(code, [(base + 512, 4)])
            self.assertEqual(segments[0]['size'], page)
            with self.assertRaisesRegex(ValueError, 'header'):
                pack_cache.image_segments(cache, base, 7)
            struct.pack_into('<Q', image, 32 + 72 + 32, base + page)
            source.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'escapes'):
                pack_cache.image_segments(cache, base, 6)

    def test_demand_pages_preserve_gaps_and_reject_unmapped_addresses(self):
        page = pack_cache.PAGE
        cache = {'preferredBase': 0x180000000, 'regionSize': 8 * page, 'files': []}
        def mapping(offset, size):
            return dict(address=cache['preferredBase'] + offset, size=size,
                        fileOffset=page, protection=1, maxProtection=1)
        cache['files'] = [dict(path='header', mappings=[mapping(0, page)]),
                          dict(path='data', mappings=[mapping(4 * page, 3 * page)])]
        ranges = pack_cache.select(cache, [], pages=[5 * page, 4 * page, 5 * page])
        self.assertEqual([(r['offset'], r['size']) for r in ranges], [(0, page), (4 * page, 2 * page)])
        self.assertEqual(ranges[1]['fileOffset'], page)
        for offset in [-page, 1, 8 * page, 2 * page]:
            with self.assertRaises(ValueError):
                pack_cache.select(cache, [], pages=[offset])
        ranges = pack_cache.select(cache, [], spans=[(4 * page, 7 * page)])
        self.assertEqual(ranges[1]['size'], 3 * page)
        for span in [(0, 0), (page, 3 * page), (-page, 0), (4 * page, 9 * page), (1, page)]:
            with self.assertRaises(ValueError):
                pack_cache.select(cache, [], spans=[span])
        stub_mapping = cache['files'][1]['mappings'][0]
        stub_mapping.update(flags=8, maxProtection=5, protection=5)
        ranges = pack_cache.select(cache, [], stubs=True)
        self.assertEqual([(r['offset'], r['size']) for r in ranges], [(0, page), (4 * page, 3 * page)])
        self.assertEqual(ranges[1]['protection'], 5)

    def test_linked_vm_layout_protections_and_page_bytes_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            library = Path(directory) / 'owned-cache.so'
            page = pack_cache.PAGE
            content = b'owned-cache-fixture'.ljust(page, b'\0')
            image = bytearray(2 * page)
            image[:6] = b'\x7fELF\x02\x01'
            struct.pack_into('<HH', image, 16, 3, 183)
            struct.pack_into('<Q', image, 32, 64)
            struct.pack_into('<HH', image, 54, 56, 1)
            struct.pack_into('<II6Q', image, 64, 1, 4, page, page, page, page, page, page)
            image[page:] = content
            library.write_bytes(image)
            ranges = [{'offset': 0, 'size': page, 'protection': 1,
                       'packedSha256': hashlib.sha256(content).hexdigest()}]
            pack_cache.verify_elf(library, ranges, page, page)
            image[page] ^= 1
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'contents'):
                pack_cache.verify_elf(library, ranges, page, page)
            image[page:] = content
            struct.pack_into('<I', image, 68, 7)
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'permissions'):
                pack_cache.verify_elf(library, ranges, page, page)
            struct.pack_into('<I', image, 68, 4)
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'reserve'):
                pack_cache.verify_elf(library, ranges, page, page * 2)
            struct.pack_into('<H', image, 56, 293)
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'code-signing limit'):
                pack_cache.verify_elf(library, ranges, page, page)


class ImportTests(unittest.TestCase):
    def make_ipa(self, path, extra=None, executable="Hello"):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("Payload/Hello.app/Info.plist", plistlib.dumps({
                "CFBundleExecutable": executable, "CFBundleIdentifier": "test.hello",
                "MinimumOSVersion": "27.0",
            }))
            archive.writestr("Payload/Hello.app/Hello", prepare_ipa.make_probe())
            if extra:
                archive.writestr(*extra)

    def test_stages_original_executable_and_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ipa = root / "Hello.ipa"
            self.make_ipa(ipa)
            with patch.object(prepare_ipa, "ROOT", root), patch.object(prepare_ipa, "RAW", root / "raw"), patch("sys.stdout", io.StringIO()):
                prepare_ipa.stage(ipa)
            self.assertEqual((root / "raw/target/executable").read_bytes(), prepare_ipa.make_probe())
            self.assertTrue((root / "artifacts/imported/Hello.app/Info.plist").exists())
            self.assertEqual((root / "raw/target/bundle/Hello").read_bytes(), prepare_ipa.make_probe())
            manifest = json.loads((root / "raw/target/manifest.json").read_text())
            self.assertEqual(manifest['bundleDirectory'], 'Hello.app')
            self.assertEqual(manifest['bundleFiles'], ['Hello', 'Info.plist'])

    def test_rejects_archive_traversal_and_symlinks_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ["../escape", "/escape", "Payload/Hello.app/../../escape", "Payload\\escape"]:
                ipa = root / "bad.ipa"
                self.make_ipa(ipa, (name, b"bad"))
                with self.assertRaises(ValueError):
                    prepare_ipa.stage(ipa)
            link = zipfile.ZipInfo("Payload/Hello.app/link")
            link.create_system = 3
            link.external_attr = 0o120777 << 16
            self.make_ipa(ipa, (link, "../../escape"))
            with self.assertRaises(ValueError):
                prepare_ipa.stage(ipa)


    def test_rejects_executable_path_in_plist(self):
        with tempfile.TemporaryDirectory() as directory:
            ipa = Path(directory) / "bad.ipa"
            self.make_ipa(ipa, executable="../escape")
            with self.assertRaises(ValueError):
                prepare_ipa.stage(ipa)


class SystemImageTests(unittest.TestCase):
    def test_only_completed_crc_verified_download_can_be_decrypted(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'SystemOS.dmg.aea'
            archive.with_suffix('.aea.partial').write_bytes(b'partial')
            with self.assertRaises(ValueError):
                extract_sysroot.wait_for_download(archive, None)
            archive.write_bytes(b'owned-system-image-fixture')
            meta = archive.with_suffix('.aea.source.json')
            source = {'size': archive.stat().st_size, 'crc32': zlib.crc32(archive.read_bytes())}
            meta.write_text(json.dumps(source))
            self.assertEqual(extract_sysroot.wait_for_download(archive, None), source)
            corrupted = bytearray(archive.read_bytes())
            corrupted[0] ^= 1
            archive.write_bytes(corrupted)
            with self.assertRaises(ValueError):
                extract_sysroot.wait_for_download(archive, None)

if __name__ == "__main__":
    unittest.main()
