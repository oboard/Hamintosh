import copy
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import pack_cache_data


class DemandPagingTests(unittest.TestCase):
    def test_code_segment_metadata_is_packaged_with_readonly_nonexecuting_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            page, base = 0x4000, 0x180000000
            data = bytearray(3 * page)
            struct.pack_into('<8I', data, 0, 0xfeedfacf, 0x100000c, 2, 6, 1, 232, 0, 0)
            struct.pack_into('<II16sQQQQiiII', data, 32, 25, 232, b'__TEXT',
                             base, 3 * page, 0, 3 * page, 5, 5, 2, 0)
            for at, name, address, size, flags in [(104, b'__text', base + 4096, 4, 0x80000400),
                                                   (184, b'__cstring', base + page + 128, 8, 0)]:
                data[at:at + 16] = name.ljust(16, b'\0')
                struct.pack_into('<QQ', data, at + 32, address, size)
                struct.pack_into('<I', data, at + 64, flags)
            source = directory / 'owned-text-metadata'
            source.write_bytes(data)
            cache = dict(preferredBase=base, regionSize=4 * page, images=[dict(address=base, path='/owned')],
                         files=[dict(path=str(source), uuid='11' * 16, mappings=[dict(
                             address=base, size=len(data), fileOffset=0, protection=5, maxProtection=5)])])
            mappings = pack_cache_data.code_metadata(cache)
            self.assertEqual([(m['address'], m['size'], m['maxProtection']) for _, m in mappings],
                             [(base, 2 * page, 1)])
            manifest = pack_cache_data.write_pack(cache, directory / 'readonly.pack')
            self.assertEqual((manifest['executableBytes'], manifest['codeMetadataBytes']), (0, 2 * page))

    def fixture(self, directory):
        page, base = 0x4000, 0x180000000
        data = bytearray(0xd000)
        auth = (1 << 63) | (1 << 52) | (1 << 51) | (1 << 50) | (0x1234 << 34) | 0x80
        struct.pack_into('<QQ', data, 0x1000, auth, 0x90)
        struct.pack_into('<II', data, 0x1100, 0xe000000f, 5)
        struct.pack_into('<Q', data, 0x3000, 0x200)
        struct.pack_into('<4IQ4H', data, 0x7000, 5, 4096, 4, 0, base, 0, 0xffff, 0, 0xffff)
        data[0x9000:0x9008] = b'other!!!'
        source = directory / 'owned-cache-data'
        source.write_bytes(data)
        cache = dict(preferredBase=base, regionSize=0x20000, files=[dict(
            path=str(source), uuid='11' * 16, mappings=[
                dict(address=base + page, size=page, fileOffset=0x1000, protection=1,
                     maxProtection=3, slideInfoOffset=0x7000, slideInfoSize=32),
                dict(address=base + 3 * page, size=page, fileOffset=0x9000, protection=3,
                     maxProtection=3, slideInfoOffset=0, slideInfoSize=0)])])
        return cache, source, data

    def test_native_pager_preserves_permissions_and_rejects_corrupt_or_executable_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cache, source, raw = self.fixture(directory)
            good = directory / 'good.pack'
            manifest = pack_cache_data.write_pack(cache, good)
            self.assertEqual((manifest['mappings'], manifest['executableBytes'], manifest['dataBytes']),
                             (2, 0, 0x8000))
            data = good.read_bytes()
            metadata_size = struct.unpack_from('<I', data, 56)[0]
            corrupt = bytearray(data)
            corrupt[metadata_size] ^= 1
            bad_data = directory / 'bad-data.pack'
            bad_data.write_bytes(corrupt)
            corrupt = bytearray(data)
            corrupt[80] ^= 1
            bad_metadata = directory / 'bad-index.pack'
            bad_metadata.write_bytes(corrupt)
            corrupt = bytearray(data)
            struct.pack_into('<Q', corrupt, 64 + 24, 0x105)
            struct.pack_into('<I', corrupt, 60, zlib.crc32(corrupt[64:metadata_size]))
            executable = directory / 'executable.pack'
            executable.write_bytes(corrupt)
            struct.pack_into('<H', raw, 0x7018, 4092)
            source.write_bytes(raw)
            bad_chain = directory / 'bad-chain.pack'
            pack_cache_data.write_pack(cache, bad_chain)
            binary = directory / 'test-pager'
            subprocess.run([shutil.which('c++'), '-std=c++17', '-Wall', '-Wextra', '-Werror',
                            '-I', str(ROOT / 'native/platform'), str(ROOT / 'tests/native_data_pager.cpp'),
                            str(ROOT / 'native/platform/data_pager.cpp'), '-o', str(binary)], check=True)
            subprocess.run([str(binary), str(good), str(bad_data), str(bad_metadata),
                            str(executable), str(bad_chain)], check=True)

    def test_pack_refuses_unaligned_ranges_and_malformed_slide_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cache, source, raw = self.fixture(directory)
            for change in [dict(address=cache['preferredBase'] + 1), dict(size=1),
                           dict(protection=4), dict(slideInfoSize=8)]:
                bad = copy.deepcopy(cache)
                bad['files'][0]['mappings'][0].update(change)
                with self.assertRaises(ValueError):
                    pack_cache_data.write_pack(bad, directory / 'invalid.pack')
