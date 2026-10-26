import hashlib
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from stage_system_resources import stage


class SystemResourceTests(unittest.TestCase):
    def test_preserves_bytes_provenance_and_existing_aot_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / 'source', root / 'output'
            version = source / 'System/Library/CoreServices/SystemVersion.plist'
            version.parent.mkdir(parents=True)
            version.write_bytes(plistlib.dumps({'ProductVersion': '27.0',
                                                'ProductName': 'iPhone OS',
                                                'ProductBuildVersion': 'fixture'}))
            output.mkdir()
            manifest = output / 'manifest.json'
            manifest.write_text(json.dumps({'files': ['usr/lib/dyld'],
                                            'aotImages': [{'uuid': 'unchanged'}]}))
            resource = source / 'Example.framework/Info.plist'
            resource.parent.mkdir()
            data = plistlib.dumps({'CFBundleIdentifier': 'example'}, fmt=plistlib.FMT_BINARY)
            resource.write_bytes(data)
            files = stage(source, output, ['Example.framework'])
            self.assertEqual((output / 'Example.framework/Info.plist').read_bytes(), data)
            result = json.loads(manifest.read_text())
            self.assertEqual(result['aotImages'], [{'uuid': 'unchanged'}])
            self.assertIn('usr/lib/dyld', result['files'])
            self.assertEqual(files['Example.framework/Info.plist']['sha256'],
                             hashlib.sha256(data).hexdigest())
            self.assertEqual(result['resourceSources'][0]['systemVersion']['ProductBuildVersion'],
                             'fixture')
            before = manifest.read_bytes()
            (source / 'code').write_bytes(b'\xcf\xfa\xed\xfeARM64')
            (source / 'escape').symlink_to(root)
            for selection in [['Example.framework', 'code'], ['escape'], ['../outside']]:
                with self.assertRaises(ValueError):
                    stage(source, output, selection)
                self.assertEqual(manifest.read_bytes(), before)
            self.assertFalse((output / 'code').exists())
            version.write_bytes(plistlib.dumps({'ProductVersion': '27.0',
                                                'ProductName': 'macOS'}))
            with self.assertRaises(ValueError):
                stage(source, output, ['Example.framework'])
            self.assertEqual(manifest.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
