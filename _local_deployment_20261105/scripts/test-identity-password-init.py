#!/usr/bin/env python3
"""First-deployment and rerun checks, entirely in a temporary deployment tree."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('identity_generator',ROOT/'scripts/generate-identity.py')
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
sys.path.insert(0,str(ROOT/'scripts'))
import password_store


@unittest.skipUnless(os.geteuid()==0,'deployment initializer requires root ownership')
class IdentityPasswordInitializationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old_root,self.old_env = generator.ROOT,generator.ENV_FILE
        generator.ROOT = self.root
        generator.ENV_FILE = self.root/'.env.identity'
        self.addCleanup(self.restore)

    def restore(self):
        generator.ROOT,generator.ENV_FILE = self.old_root,self.old_env

    def run_generator(self):
        with contextlib.redirect_stdout(io.StringIO()):
            generator.main()

    def test_first_deployment_creates_private_empty_store_and_shared_lock(self):
        self.run_generator()
        path = self.root/'config/passwords/users.json'
        self.assertEqual(json.loads(path.read_text()),{'version':1,'users':{}})
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777,0o700)
        self.assertEqual((path.stat().st_uid,path.stat().st_gid),(10001,10001))
        lock = self.root/'state/registration/approval.lock'
        self.assertEqual(lock.stat().st_mode & 0o777,0o600)
        self.assertEqual(lock.stat().st_uid,0)
        self.assertFalse((lock.parent/'registrations.sqlite3').exists())

    def test_rerun_preserves_existing_hash_revision_file_and_identity_secrets(self):
        self.run_generator()
        path = self.root/'config/passwords/users.json'
        before,value = password_store.load_store(path)
        value['users']['existing-admin'] = {
            'password_hash':'scrypt$32768$8$3$'+'01'*16+'$'+'02'*32,
            'revision':uuid.uuid4().hex}
        password_store.atomic_store_write(path,before,value)
        before = path.read_bytes()
        inode = path.stat().st_ino
        secrets_before = generator.ENV_FILE.read_bytes()
        self.run_generator()
        self.assertEqual(path.read_bytes(),before)
        self.assertEqual(path.stat().st_ino,inode)
        self.assertEqual(generator.ENV_FILE.read_bytes(),secrets_before)

    def test_invalid_existing_store_is_preserved_and_refused(self):
        self.run_generator()
        path = self.root/'config/passwords/users.json'
        path.write_text('{invalid existing file}')
        before = path.read_bytes()
        with self.assertRaises(password_store.PasswordStoreError): self.run_generator()
        self.assertEqual(path.read_bytes(),before)


if __name__=='__main__':
    unittest.main(verbosity=2)
