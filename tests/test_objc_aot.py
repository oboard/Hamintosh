import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ObjcAotTests(unittest.TestCase):
    def test_native_signed_image_policy(self):
        compiler = shutil.which('c++')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/'objc-aot'
            subprocess.run([compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror',
                            '-DHM_HAS_OBJC_AOT=1', '-I', str(ROOT/'tests/objc_aot'),
                            '-I', str(ROOT/'native/platform'),
                            str(ROOT/'tests/native_objc_aot.cpp'),
                            str(ROOT/'native/platform/objc_aot.cpp'), '-o', str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
            self.assertIn('immutable RX, pool bounds and reset passed', result.stdout)


def synthetic_trampoline():
    import struct
    page = 0x4000
    data = bytearray(0xc200)
    def segment(name, address, size, fileoff, filesize, protection):
        return struct.pack('<II16sQQQQiiII', 25, 72, name, address, size,
                           fileoff, filesize, protection, protection, 0, 0)
    name = b'/usr/lib/libobjc-trampolines.dylib\0'
    identity = struct.pack('<6I', 13, 64, 24, 0, 1, 1)+name
    identity = identity.ljust(64,b'\0')
    strings = b'\0'
    symbols = bytearray()
    for symbol, address in [(b'__objc_blockTrampolineImpl',page),
                            (b'__objc_blockTrampolineStart',page+32),
                            (b'__objc_blockTrampolineLast',2*page-8)]:
        symbols += struct.pack('<IBBHQ',len(strings),0xf,1,0,address)
        strings += symbol+b'\0'
    commands = [segment(b'__TEXT',0,0xc000,0,0xc000,5),
                segment(b'__LINKEDIT',0xc000,0x8000,0xc000,0x200,1), identity,
                struct.pack('<6I',2,24,0xc000,3,0xc030,len(strings)),
                struct.pack('<4I',0x1d,16,0xc100,0x100),
                struct.pack('<II16s',0x1b,24,bytes(range(16))),
                struct.pack('<6I',0x32,24,2,27<<16,27<<16,0)]
    body = b''.join(commands)
    struct.pack_into('<8I',data,0,0xfeedfacf,0x100000c,2,6,len(commands),len(body),0,0)
    data[32:32+len(body)] = body
    data[0xc000:0xc030] = symbols
    data[0xc030:0xc030+len(strings)] = strings
    struct.pack_into('>5I',data,0xc100,0xfade0cc0,108,1,0,20)
    struct.pack_into('>II',data,0xc114,0xfade0c02,88)
    struct.pack_into('>I',data,0xc114+32,0xc100)
    data[0xc114+39] = 12
    return data


class ObjcTrampolinePackTests(unittest.TestCase):
    def setUp(self):
        import sys
        sys.path.insert(0,str(ROOT/'tools'))
        import pack_objc_trampolines
        self.packer = pack_objc_trampolines

    def test_preserves_source_bytes_and_page_group_geometry(self):
        data = synthetic_trampoline()
        meta = self.packer.inspect(data)
        self.assertEqual((meta['textSize'],meta['span'],meta['codeEnd']), (0xc000,0x14000,0xd000))
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'owned-trampolines'
            output = Path(directory)/'packed'
            source.write_bytes(data)
            self.packer.pack(source,output,2)
            self.assertEqual(source.read_bytes(),data)
            assembly = (output/'objc_trampolines.S').read_text()
            self.assertEqual(assembly.count(f'.incbin "{source.resolve()}", 0, 49152'),3)
            self.assertIn('.hm_objc_pool_1_text (ADDR(.hm_objc_pool_1_data) + 16384)',
                          (output/'objc_trampolines.ld').read_text())
            self.assertIn('.hm_objc_pool_1_data,"aw"',assembly)
            self.assertIn('.hm_objc_pool_1_text,"ax"',assembly)
            self.assertNotIn('.inst',assembly)

    def test_rejects_wrong_architecture_mutable_text_and_truncated_signatures(self):
        import struct
        data = synthetic_trampoline()
        for prefix in (0,31,100,len(data)-1):
            with self.assertRaises(ValueError):self.packer.inspect(data[:prefix])
        for offset,value in [(8,0),(12,2),(32+60,7),(20,0xffffff)]:
            bad = bytearray(data)
            struct.pack_into('<I',bad,offset,value)
            with self.assertRaises(ValueError):self.packer.inspect(bad)


if __name__ == '__main__':
    unittest.main()
