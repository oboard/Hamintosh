import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GuestFileTests(unittest.TestCase):
    def test_bundle_directory_and_files_remain_confined(self):
        compiler = shutil.which('c++')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'native-file-stat'
            subprocess.run([
                compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror',
                '-I', str(ROOT / 'native/platform'),
                '-I', str(ROOT / 'native/include'),
                str(ROOT / 'tests/native_file_stat.cpp'),
                str(ROOT / 'native/platform/guest_files.cpp'),
                '-o', str(binary),
            ], check=True)
            result = subprocess.run([str(binary)], text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout.strip(),
                             'file stat: guest root, descriptor and symlink confinement passed')


if __name__ == '__main__':
    unittest.main()
