import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RendererTests(unittest.TestCase):
    def test_bgra_submission_copies_rows_with_destination_stride(self):
        compiler = shutil.which("c++")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "native-bgra-frame"
            subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                            "-I", str(ROOT / "native/graphics"),
                            str(ROOT / "tests/native_bgra_frame.cpp"),
                            str(ROOT / "native/graphics/bgra_frame.cpp"),
                            "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout.strip(),
                             "BGRA frame: stride, bounds and row copies passed")

    def test_frame_diagnostics_provenance_and_hashing(self):
        compiler = shutil.which("c++")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "native-frame-diagnostics"
            subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                            "-I", str(ROOT / "native/graphics"),
                            str(ROOT / "tests/native_frame_diagnostics.cpp"),
                            str(ROOT / "native/graphics/frame_diagnostics.cpp"),
                            "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout.strip(),
                             "Frame diagnostics: recording, provenance, hashing and JSON passed")


if __name__ == "__main__":
    unittest.main()
