#!/usr/bin/env python3
"""Transactional approval tests against real temporary SQLite/directory files."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('registration_approval',ROOT/'scripts/approve-registration.py')
approval = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = approval
spec.loader.exec_module(approval)

class ApprovalTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)/'users.json'
        self.admin = {'user_id':'existing-admin','mail':'reserved@example.test',
                      'phone':'13900000001','name':'Existing Admin','role':'admin','status':'active','scope':['unchanged']}
        self.directory.write_text(json.dumps([self.admin]))
        self.database = Path(self.temporary.name)/'registrations.sqlite3'
        self.passwords = Path(self.temporary.name)/'passwords/users.json'
        approval.registrar.initialize_db(self.database)
        self.identifier = str(uuid.uuid4())
        with approval.database_connection(self.database) as connection:
            connection.execute('INSERT INTO registrations(registration_id,user_id,phone,email,name,status,created_at,updated_at) '
                'VALUES(?,?,?,?,?,\'pending\',?,?)',(self.identifier,'reg-'+self.identifier,'19900000001',
                'new@acceptance.test','Approval Test',int(time.time()),int(time.time())))
        self.native = {}
        self.creations = 0

    def provision(self,payload):
        created = payload['user_id'] not in self.native
        if created:
            self.creations += 1
            self.native[payload['user_id']] = {'user_id':payload['user_id'],'username':payload['username'],
                'phorge_phid':'PHID-USER-testregistration0001','is_admin':False,
                'email_verified':False,'external_email_verified':False}
        return dict(self.native[payload['user_id']],created=created)

    def run_approval(self,**kwargs):
        options = dict(approved_by='siteadmin',confirmed_phone='19900000001',acceptance_only=True,
                       provisioner=self.provision,delivery_check=lambda row,testing:None,
                       passwords=self.passwords)
        options.update(kwargs)
        return approval.approve(self.database,self.directory,self.identifier,**options)

    def test_success_and_idempotence_preserve_existing_admin(self):
        first = self.run_approval()
        first_row = approval.load_record(self.database,self.identifier)
        before = self.directory.read_bytes()
        second = self.run_approval()
        self.assertTrue(first['created']); self.assertFalse(second['created'])
        self.assertEqual(self.creations,1)
        self.assertEqual(before,self.directory.read_bytes())
        rows = json.loads(before)
        self.assertEqual(rows[0],self.admin)
        self.assertEqual(rows[1]['role'],'user'); self.assertEqual(rows[1]['scope'],[])
        self.assertEqual(first_row['status'],'approved')
        self.assertEqual(first_row['approved_at'],approval.load_record(self.database,self.identifier)['approved_at'])
        self.assertEqual(first_row['updated_at'],approval.load_record(self.database,self.identifier)['updated_at'])
        self.assertTrue(all(first_row[key] is None for key in ('org_unit_id','manager_user_id','position')))

    def test_duplicate_existing_warden_phone_never_calls_phorge(self):
        with approval.database_connection(self.database) as connection:
            connection.execute('UPDATE registrations SET phone=? WHERE registration_id=?',('13900000001',self.identifier))
        with self.assertRaises(approval.ApprovalError): self.run_approval(confirmed_phone='13900000001')
        self.assertEqual(self.creations,0)
        self.assertEqual(json.loads(self.directory.read_text()),[self.admin])

    def test_duplicate_existing_warden_email_is_case_insensitive(self):
        self.admin['mail'] = 'RESERVED@EXAMPLE.TEST'
        self.directory.write_text(json.dumps([self.admin]))
        with approval.database_connection(self.database) as connection:
            connection.execute('UPDATE registrations SET email=? WHERE registration_id=?',('reserved@example.test',self.identifier))
        with self.assertRaises(approval.ApprovalError): self.run_approval()
        self.assertEqual(self.creations,0)

    def test_reserved_username_and_wrong_confirmed_phone(self):
        for options in ({'username':'siteadmin'},{'confirmed_phone':'19900000002'}):
            with self.assertRaises(approval.ApprovalError): self.run_approval(**options)
        self.assertEqual(self.creations,0)

    def test_missing_fields_and_organization_are_rejected(self):
        for field,value in [('name',''),('org_unit_id',None),('position','Manager')]:
            if field=='org_unit_id': continue
            with approval.database_connection(self.database) as connection:
                connection.execute(f'UPDATE registrations SET {field}=? WHERE registration_id=?',(value,self.identifier))
            with self.assertRaises(approval.ApprovalError): self.run_approval()
            with approval.database_connection(self.database) as connection:
                connection.execute(f'UPDATE registrations SET {field}=? WHERE registration_id=?',
                                   ('Approval Test' if field=='name' else None,self.identifier))

    def test_native_failure_keeps_pending_and_no_login_directory_entry(self):
        def fail(_): raise approval.ApprovalError('Simulated native transaction failure')
        with self.assertRaises(approval.ApprovalError): self.run_approval(provisioner=fail)
        row = approval.load_record(self.database,self.identifier)
        self.assertEqual(row['status'],'pending'); self.assertIsNone(row['phorge_phid'])
        self.assertEqual(len(json.loads(self.directory.read_text())),1)
        with self.assertRaises(approval.ApprovalError):
            approval.reject(self.database,self.identifier,approved_by='siteadmin',reason='Cannot discard in-progress intent')
        self.assertEqual(self.run_approval()['status'],'approved')

    def test_publish_failure_recovers_same_native_principal(self):
        def fail(*_): raise OSError('Simulated directory failure')
        with self.assertRaises(OSError): self.run_approval(publisher=fail)
        self.assertEqual(approval.load_record(self.database,self.identifier)['status'],'pending')
        self.assertEqual(len(json.loads(self.directory.read_text())),1)
        self.run_approval()
        self.assertEqual(self.creations,1)
        self.assertEqual(len(json.loads(self.directory.read_text())),2)

    def test_crash_after_publish_before_final_sqlite_mark_recovers(self):
        def publish_then_fail(*args):
            approval.atomic_directory_write(*args)
            raise OSError('Simulated crash after atomic publication')
        with self.assertRaises(OSError): self.run_approval(publisher=publish_then_fail)
        self.assertEqual(approval.load_record(self.database,self.identifier)['status'],'pending')
        self.assertEqual(len(json.loads(self.directory.read_text())),2)
        self.run_approval()
        self.assertEqual(self.creations,1)
        self.assertEqual(len(json.loads(self.directory.read_text())),2)

    def test_reject_is_final_and_does_not_publish(self):
        approval.reject(self.database,self.identifier,approved_by='siteadmin',reason='Test rejection')
        approval.reject(self.database,self.identifier,approved_by='siteadmin',reason='Repeat')
        with self.assertRaises(approval.ApprovalError): self.run_approval()
        self.assertEqual(len(json.loads(self.directory.read_text())),1)

    def test_privileged_or_verified_native_result_never_publishes(self):
        for field in ('is_admin','email_verified','external_email_verified'):
            def bad(payload): return dict(self.provision(payload),**{field:True})
            with self.assertRaises(approval.ApprovalError): self.run_approval(provisioner=bad)
            self.assertEqual(len(json.loads(self.directory.read_text())),1)

    def test_do_not_reactivate_modified_or_removed_approved_identity(self):
        self.run_approval()
        rows = json.loads(self.directory.read_text()); rows[1]['status']='inactive'
        self.directory.write_text(json.dumps(rows))
        with self.assertRaises(approval.ApprovalError): self.run_approval()
        self.directory.write_text(json.dumps([self.admin]))
        with self.assertRaises(approval.ApprovalError): self.run_approval()

    def test_live_delivery_not_assumed_and_synthetic_domain_required(self):
        row = approval.load_record(self.database,self.identifier)
        with self.assertRaises(approval.ApprovalError):
            approval.ensure_delivery_mode(row,False,Path(self.temporary.name))
        approval.ensure_delivery_mode(row,True,Path(self.temporary.name))
        with self.assertRaises(approval.ApprovalError):
            approval.ensure_delivery_mode(dict(row,email='real@example.test'),True,Path(self.temporary.name))

    def test_database_symlink_refused_without_changing_target(self):
        alias = self.database.with_name('alias.sqlite3')
        alias.symlink_to(self.database)
        before = self.database.stat().st_mode
        with self.assertRaises(approval.ApprovalError):
            with approval.database_connection(alias): pass
        self.assertEqual(before,self.database.stat().st_mode)

    def test_concurrent_directory_change_not_overwritten(self):
        original = self.directory.read_bytes()
        changed = [dict(self.admin,name='Operator Updated Admin')]
        self.directory.write_text(json.dumps(changed))
        with self.assertRaises(approval.ApprovalError):
            approval.atomic_directory_write(self.directory,original,[self.admin,{'user_id':'new'}])
        self.assertEqual(json.loads(self.directory.read_text()),changed)

    def password_application(self):
        # Encoding validation is tested here without repeating an expensive KDF;
        # the separate credential suite verifies actual scrypt interoperability.
        encoded = 'scrypt$32768$8$3$'+'01'*16+'$'+'02'*32
        with approval.database_connection(self.database) as connection:
            connection.execute('UPDATE registrations SET password_hash=? WHERE registration_id=?',
                               (encoded,self.identifier))
        return encoded

    def test_pending_password_stays_private_until_native_approval(self):
        self.password_application()
        self.assertFalse(self.passwords.exists())
        def fail(payload):
            self.assertNotIn('password_hash',payload)
            self.assertTrue(payload['password_approval'])
            raise approval.ApprovalError('Native transaction rejected')
        with self.assertRaises(approval.ApprovalError): self.run_approval(provisioner=fail)
        self.assertFalse(self.passwords.exists())
        self.assertEqual(len(json.loads(self.directory.read_text())),1)

    def test_password_approval_needs_no_dingtalk_and_publishes_before_warden(self):
        encoded = self.password_application()
        row = approval.load_record(self.database,self.identifier)
        approval.ensure_delivery_mode(row,False,Path(self.temporary.name))
        def publish_directory(*args):
            store = json.loads(self.passwords.read_text())
            self.assertEqual(store['users'][row['user_id']]['password_hash'],encoded)
            self.assertEqual(approval.load_record(self.database,self.identifier)['status'],'pending')
            approval.atomic_directory_write(*args)
        self.run_approval(publisher=publish_directory,delivery_check=approval.ensure_delivery_mode,
                          acceptance_only=False)
        self.assertEqual(self.passwords.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.passwords.parent.stat().st_mode & 0o777,0o700)
        if os.geteuid()==0:
            self.assertEqual((self.passwords.stat().st_uid,self.passwords.stat().st_gid),(10001,10001))

    def test_invalid_password_hash_never_creates_native_or_active_identity(self):
        for encoded in ('', 'scrypt$2$8$3$bad$bad', 'plaintext-secret'):
            with approval.database_connection(self.database) as connection:
                connection.execute('UPDATE registrations SET password_hash=? WHERE registration_id=?',
                                   (encoded,self.identifier))
            with self.assertRaises(approval.ApprovalError): self.run_approval()
        self.assertEqual(self.creations,0)
        self.assertFalse(self.passwords.exists())

    def test_crash_after_password_publication_recovers_without_login_admission(self):
        self.password_application()
        def publish_then_fail(*args):
            approval.publish_initial_password(*args)
            raise OSError('Crash after credential publication')
        with self.assertRaises(OSError): self.run_approval(password_publisher=publish_then_fail)
        self.assertEqual(approval.load_record(self.database,self.identifier)['status'],'pending')
        self.assertEqual(len(json.loads(self.directory.read_text())),1)
        before = self.passwords.read_bytes()
        self.run_approval()
        self.assertEqual(self.passwords.read_bytes(),before)
        self.assertEqual(self.creations,1)

    def test_approval_replay_never_restores_registration_password_after_reset(self):
        self.password_application()
        self.run_approval()
        from password_store import load_store, atomic_store_write
        original, store = load_store(self.passwords)
        store['users']['reg-'+self.identifier] = {
            'password_hash':'scrypt$32768$8$3$'+'03'*16+'$'+'04'*32,
            'revision':uuid.uuid4().hex}
        atomic_store_write(self.passwords,original,store)
        reset = self.passwords.read_bytes()
        self.run_approval()
        self.assertEqual(self.passwords.read_bytes(),reset)

    def test_approval_replay_does_not_republish_removed_credential(self):
        self.password_application()
        self.run_approval()
        from password_store import load_store, atomic_store_write
        original, store = load_store(self.passwords)
        store['users'].clear()
        atomic_store_write(self.passwords,original,store)
        with self.assertRaises(approval.ApprovalError): self.run_approval()
        self.assertEqual(json.loads(self.passwords.read_text())['users'],{})

    def test_separate_operator_process_waits_for_serial_lock(self):
        marker = Path(self.temporary.name)/'lock-acquired'
        script = '''import importlib.util,sys,pathlib
spec=importlib.util.spec_from_file_location('approval_lock_test',sys.argv[1])
module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
with module.approval_lock(pathlib.Path(sys.argv[2])):pathlib.Path(sys.argv[3]).write_text('acquired')
'''
        with approval.approval_lock(self.database):
            child = subprocess.Popen([sys.executable,'-c',script,str(ROOT/'scripts/approve-registration.py'),
                                      str(self.database),str(marker)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            time.sleep(0.15)
            self.assertFalse(marker.exists())
        stdout,stderr=child.communicate(timeout=5)
        self.assertEqual(child.returncode,0,stderr.decode())
        self.assertEqual(marker.read_text(),'acquired')

    @unittest.skipUnless(os.geteuid()==0,'root ownership check')
    def test_sqlite_owner_can_write_during_and_after_root_connection(self):
        # Use /tmp (traversable parents) and retain a live root WAL connection.
        os.chown(self.database,10001,10001)
        os.chown(self.database.parent,10001,10001)
        self.database.parent.chmod(0o700)
        with approval.database_connection(self.database) as connection:
            connection.execute('PRAGMA wal_autocheckpoint=0')
            connection.execute('UPDATE registrations SET updated_at=updated_at+1')
            script = 'import sqlite3; c=sqlite3.connect('+repr(str(self.database))+'); c.execute("UPDATE registrations SET updated_at=updated_at+1"); c.commit(); c.close()'
            completed = subprocess.run(['setpriv','--reuid=10001','--regid=10001','--clear-groups',
                                        sys.executable,'-c',script],capture_output=True)
            self.assertEqual(completed.returncode,0,completed.stderr.decode())
        for suffix in ('','-wal','-shm'):
            item = Path(str(self.database)+suffix)
            if item.exists(): self.assertEqual(item.stat().st_uid,10001)
        completed = subprocess.run(['setpriv','--reuid=10001','--regid=10001','--clear-groups',
                                    sys.executable,'-c',script],capture_output=True)
        self.assertEqual(completed.returncode,0,completed.stderr.decode())

if __name__=='__main__':
    unittest.main(verbosity=2)
