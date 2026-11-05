#!/usr/bin/env python3
"""Real scrypt and temporary-file password-management regression tests."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import password_store as store
from credential_hashes import hash_password, valid_hash, validate_password, verify_password
import credential_hashes
spec = importlib.util.spec_from_file_location('password_management',ROOT/'scripts/manage-password.py')
manager = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = manager
spec.loader.exec_module(manager)


class CredentialHashTest(unittest.TestCase):
    def test_real_scrypt_roundtrip_preserves_unicode_and_whitespace(self):
        password = ' 密码 空格 café 🔐 123456789 '
        encoded = hash_password(password)
        self.assertTrue(valid_hash(encoded))
        self.assertTrue(verify_password(password,encoded))
        self.assertFalse(verify_password(password.strip(),encoded))
        self.assertFalse(verify_password(password.replace('é','e\u0301'),encoded))
        self.assertNotEqual(encoded,hash_password(password))

    def test_character_limits_and_nul(self):
        for password in ('a'*15,'密'*128,' '*15):
            self.assertEqual(validate_password(password),password)
        for password in ('a'*14,'密'*129,'a'*16+'\0','a'*16+'\ud800',None):
            with self.assertRaises(ValueError): validate_password(password)
        self.assertFalse(verify_password('short','not-an-encoding'))

    def test_work_factors_lengths_and_encoding_are_strict(self):
        good = 'scrypt$32768$8$3$'+'01'*16+'$'+'02'*32
        self.assertTrue(valid_hash(good))
        for bad in (good+'\n',good.replace('$32768$','$65536$'),good.upper(),
                    good.replace('$3$','$1$'),good[:-1],None,{'hash':good}):
            self.assertFalse(valid_hash(bad))
        with mock.patch.object(credential_hashes.hashlib,'scrypt') as kdf:
            self.assertFalse(verify_password('long-enough-password',good.replace('$32768$','$1$')))
            kdf.assert_not_called()

    def test_hash_workers_are_bounded_to_two(self):
        active = 0
        peak = 0
        lock = threading.Lock()
        def fake(*args,**kwargs):
            nonlocal active,peak
            with lock:
                active += 1
                peak = max(peak,active)
            time.sleep(0.04)
            with lock: active -= 1
            return b'X'*32
        with mock.patch.object(credential_hashes.hashlib,'scrypt',side_effect=fake):
            workers = [threading.Thread(target=hash_password,args=('a'*16,)) for _ in range(8)]
            for worker in workers: worker.start()
            for worker in workers: worker.join()
        self.assertEqual(peak,2)


class PasswordManagementTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.passwords = self.root/'passwords/users.json'
        self.database = self.root/'registrations.sqlite3'
        self.directory = self.root/'warden.json'
        self.identity = {'username':'local_person','user_id':'stable-existing-principal',
            'phorge_phid':'PHID-USER-existingperson','email':'existing@example.test',
            'is_approved':True,'is_disabled':False,'is_system_agent':False,'is_mailing_list':False}
        self.rows = [{'user_id':self.identity['user_id'],'mail':self.identity['email'],
                      'status':'active','role':'admin'}]
        self.directory.write_text(json.dumps(self.rows))

    def run_set(self,**kwargs):
        options = {'password':'independent personal password','lookup':lambda username:dict(self.identity)}
        options.update(kwargs)
        return manager.set_password(self.database,self.directory,self.passwords,'local_person',**options)

    def test_existing_person_initialization_and_explicit_reset_preserve_other_people(self):
        self.run_set()
        original,value = store.load_store(self.passwords)
        initial = dict(value['users'][self.identity['user_id']])
        other = {'password_hash':hash_password('another independent password'),'revision':uuid.uuid4().hex}
        value['users']['another-person'] = other
        store.atomic_store_write(self.passwords,original,value)
        with self.assertRaises(manager.approval.ApprovalError): self.run_set()
        self.run_set(password='a changed personal password',reset=True)
        _,after = store.load_store(self.passwords)
        current = after['users'][self.identity['user_id']]
        self.assertNotEqual(initial['revision'],current['revision'])
        self.assertFalse(verify_password('independent personal password',current['password_hash']))
        self.assertTrue(verify_password('a changed personal password',current['password_hash']))
        self.assertEqual(other,after['users']['another-person'])
        self.assertEqual(json.loads(self.directory.read_text()),self.rows)

    def test_pending_disabled_and_unmapped_users_have_no_password(self):
        for changes in ({'is_approved':False},{'is_disabled':True},{'is_system_agent':True},
                        {'is_mailing_list':True},{'username':'siteadmin'},{'user_id':'different'}):
            with self.assertRaises(manager.approval.ApprovalError):
                self.run_set(lookup=lambda username:dict(self.identity,**changes))
        self.assertFalse(self.passwords.exists())

    def test_inactive_or_ambiguous_warden_mapping_refused(self):
        for rows in ([dict(self.rows[0],status='inactive')],[],
                     self.rows+[dict(self.rows[0],user_id='another-principal')],
                     [dict(self.rows[0],mail='changed@example.test')]):
            self.directory.write_text(json.dumps(rows))
            with self.assertRaises(manager.approval.ApprovalError): self.run_set()
        self.assertFalse(self.passwords.exists())

    def test_generated_output_is_private_retrievable_and_never_stdout_secret(self):
        output = self.root/'password.txt'
        result = self.run_set(password=None,generate=True,output=output)
        password = output.read_text().removesuffix('\n')
        self.assertEqual(len(password),32)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600)
        self.assertNotIn(password,json.dumps(result))
        _,value = store.load_store(self.passwords)
        self.assertTrue(verify_password(password,value['users'][self.identity['user_id']]['password_hash']))
        with self.assertRaises(manager.approval.ApprovalError):
            self.run_set(password=None,generate=True,output=output)
        self.run_set(password=None,generate=True,output=output,reset=True)
        self.assertNotEqual(password,output.read_text().removesuffix('\n'))

    def test_output_symlink_and_public_parent_refused_before_publication(self):
        target = self.root/'unrelated.txt'; target.write_text('unchanged')
        output = self.root/'link'; output.symlink_to(target)
        with self.assertRaises(manager.approval.ApprovalError):
            self.run_set(password=None,generate=True,output=output,reset=True)
        self.assertEqual(target.read_text(),'unchanged')
        self.root.chmod(0o755)
        with self.assertRaises(manager.approval.ApprovalError):
            self.run_set(password=None,generate=True,output=self.root/'new.txt')
        self.assertFalse(self.passwords.exists())

    def test_store_concurrent_change_does_not_get_lost(self):
        store.initialize_store(self.passwords)
        original,value = store.load_store(self.passwords)
        changed = {'version':1,'users':{'another':{
            'password_hash':'scrypt$32768$8$3$'+'01'*16+'$'+'02'*32,'revision':uuid.uuid4().hex}}}
        store.atomic_store_write(self.passwords,original,changed)
        with self.assertRaises(store.PasswordStoreError):
            store.atomic_store_write(self.passwords,original,value)
        self.assertEqual(store.load_store(self.passwords)[1],changed)

    def test_store_symlink_hardlink_and_invalid_hash_fail_closed(self):
        store.initialize_store(self.passwords)
        other = self.passwords.with_name('other.json')
        self.passwords.rename(other); self.passwords.symlink_to(other)
        with self.assertRaises(OSError): store.load_store(self.passwords)
        self.passwords.unlink(); os.link(other,self.passwords)
        with self.assertRaises(store.PasswordStoreError): store.load_store(self.passwords)
        self.passwords.unlink(); other.rename(self.passwords)
        original,value = store.load_store(self.passwords)
        value['users']['bad']={'password_hash':'plaintext','revision':uuid.uuid4().hex}
        with self.assertRaises(store.PasswordStoreError): store.atomic_store_write(self.passwords,original,value)

    def test_empty_initialization_private_and_no_credentials(self):
        store.initialize_store(self.passwords)
        self.assertEqual(store.load_store(self.passwords)[1],{'version':1,'users':{}})
        self.assertEqual(stat.S_IMODE(self.passwords.stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(self.passwords.parent.stat().st_mode),0o700)
        if os.geteuid()==0:
            self.assertEqual((self.passwords.stat().st_uid,self.passwords.stat().st_gid),(10001,10001))
        before = self.passwords.read_bytes()
        store.initialize_store(self.passwords)
        self.assertEqual(before,self.passwords.read_bytes())


if __name__=='__main__':
    unittest.main(verbosity=2)
