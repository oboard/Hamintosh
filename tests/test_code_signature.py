import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CodeSignatureTests(unittest.TestCase):
    def test_padded_superblob_length_is_parsed_with_its_own_bound(self):
        compiler = shutil.which('c++')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'native-code-signature'
            subprocess.run([
                compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror',
                '-I', str(ROOT / 'native/platform'),
                str(ROOT / 'tests/native_code_signature.cpp'),
                str(ROOT / 'native/platform/code_signature.cpp'),
                '-o', str(binary),
            ], check=True)
            result = subprocess.run([str(binary)], text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout.strip(),
                             'code signature: padded superblob and entitlements passed')


if __name__ == '__main__':
    unittest.main()
