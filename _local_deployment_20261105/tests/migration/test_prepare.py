import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('prepare_migration', ROOT/'scripts/prepare_migration.py')
kit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kit)


class PrepareTests(unittest.TestCase):
    def source(self, base):
        root = base/'source'
        root.mkdir()
        for name in kit.FILES:
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('tool-code:'+name)
        (root/'.env').write_text('SECRET_SENTINEL_NEVER_PACKAGE')
        (root/'state').mkdir()
        (root/'state/private.json').write_text('SECRET_SENTINEL_NEVER_PACKAGE')
        return root

    def test_archive_is_allowlisted_and_checksums_cover_every_carried_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self.source(base)
            result = kit.prepare(base/'kit', root)
            with tarfile.open(result['archive']) as archive:
                names = archive.getnames()
                self.assertEqual(set(names), {'kit/'+name for name in (*kit.FILES, 'START-HERE.txt', 'kit.json', 'SHA256SUMS')})
                self.assertTrue(all(member.isfile() for member in archive.getmembers()))
                for member in archive.getmembers():
                    self.assertNotIn(b'SECRET_SENTINEL_NEVER_PACKAGE', archive.extractfile(member).read())
            output = base/'kit'
            for line in (output/'SHA256SUMS').read_text().splitlines():
                digest, name = line.split('  ', 1)
                self.assertEqual(digest, kit.sha((output/name).read_bytes()))
            manifest = json.loads((output/'kit.json').read_text())
            self.assertFalse(manifest['containsProductionData'])
            self.assertEqual(result['sha256'], kit.sha(Path(result['archive']).read_bytes()))

    def test_existing_directory_or_archive_is_preserved(self):
        for suffix in ('', '.tar.gz', '.tar.gz.sha256'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = self.source(base)
                existing = base/('kit'+suffix)
                existing.write_text('keep')
                with self.assertRaises(ValueError):
                    kit.prepare(base/'kit', root)
                self.assertEqual(existing.read_text(), 'keep')

    def test_allowlisted_file_cannot_be_redirected_to_a_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self.source(base)
            path = root/kit.FILES[0]
            path.unlink()
            path.symlink_to(root/'.env')
            with self.assertRaises(ValueError):
                kit.prepare(base/'kit', root)
            self.assertFalse((base/'kit').exists())

    def test_symlinked_parent_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self.source(base)
            (root/'scripts').rename(root/'private-scripts')
            (root/'scripts').symlink_to(root/'private-scripts', target_is_directory=True)
            with self.assertRaises(ValueError):
                kit.prepare(base/'kit', root)


if __name__ == '__main__':
    unittest.main()
