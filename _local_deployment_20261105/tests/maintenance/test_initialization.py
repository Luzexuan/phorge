import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('maintenance_init',ROOT/'scripts/init-maintenance.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@unittest.skipUnless(os.geteuid()==0,'private deployment ownership requires root')
class InitializationTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        previous=module.ROOT
        module.ROOT=self.root
        self.addCleanup(setattr,module,'ROOT',previous)
        for folder in ('state/registration','config/warden','config/passwords'):
            (self.root/folder).mkdir(parents=True,exist_ok=True)
        (self.root/'state/registration/registrations.sqlite3').touch()
        (self.root/'config/warden/users.json').write_text('[]\n')

    def initialize(self):
        with contextlib.redirect_stdout(io.StringIO()):module.main()

    def test_private_ownership_shared_lock_and_unchanged_directory(self):
        self.initialize()
        keys=self.root/'config/maintenance/keys'
        self.assertEqual((keys/'php.key').read_bytes(),(keys/'service.key').read_bytes())
        self.assertEqual(len((keys/'php.key').read_bytes()),32)
        for name,owner in [('php.key',33),('service.key',10001)]:
            info=(keys/name).stat()
            self.assertEqual((info.st_uid,info.st_gid,info.st_mode&0o777),(owner,owner,0o400))
        info=(self.root/'state/registration/approval.lock').stat()
        self.assertEqual((info.st_uid,info.st_mode&0o777),(10001,0o600))
        self.assertEqual((self.root/'config/warden/users.json').read_text(),'[]\n')

    def test_rerun_preserves_key_and_inode(self):
        self.initialize()
        key=self.root/'config/maintenance/keys/service.key'
        before=key.read_bytes();inode=key.stat().st_ino
        self.initialize()
        self.assertEqual(key.read_bytes(),before)
        self.assertEqual(key.stat().st_ino,inode)

    def test_differing_key_copies_fail_without_rotation(self):
        self.initialize()
        key=self.root/'config/maintenance/keys/service.key'
        other=self.root/'config/maintenance/keys/php.key'
        key.write_bytes(b'Q'*32)
        before=other.read_bytes()
        with self.assertRaises(SystemExit):self.initialize()
        self.assertEqual(key.read_bytes(),b'Q'*32)
        self.assertEqual(other.read_bytes(),before)

    def test_symlink_key_is_rejected(self):
        self.initialize()
        key=self.root/'config/maintenance/keys/service.key'
        key.unlink();key.symlink_to(self.root/'config/warden/users.json')
        with self.assertRaises(SystemExit):self.initialize()
        self.assertEqual((self.root/'config/warden/users.json').read_text(),'[]\n')


if __name__=='__main__':unittest.main(verbosity=2)
