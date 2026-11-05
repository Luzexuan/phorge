import copy
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('maintenance_test_service',Path(os.environ.get('TEAM_MAINTENANCE_TEST_SOURCE',ROOT/'config/maintenance/service.py')))
service=importlib.util.module_from_spec(spec);sys.modules[spec.name]=service;spec.loader.exec_module(service)
from credential_hashes import hash_password,verify_password
from password_store import initialize_store,load_store,atomic_store_write

ADMIN='PHID-USER-'+'a'*20
OTHER='PHID-USER-'+'b'*20
PASSWORD='  Initial password 🔐 2026  '
NEW_PASSWORD='  Updated password 🔐 2026  '

class Native:
    def __init__(self):
        self.calls=[];self.fail_disable=False
        self.users=[self.person('siteadmin','site-admin',ADMIN,True),self.person('member','member-id',OTHER)]
    @staticmethod
    def person(name,principal,phid,admin=False):
        return dict(username=name,user_id=principal,phorge_phid=phid,name=name,mail=name+'@acceptance.test',
            is_admin=admin,is_approved=True,is_disabled=False,is_system_agent=False,is_mailing_list=False,binding_valid=True)
    def __call__(self,action,actor_phid,actor_principal,**params):
        self.calls.append(action)
        actor=next((x for x in self.users if x['phorge_phid']==actor_phid),None)
        if (not actor or actor['user_id']!=actor_principal or not actor['is_admin'] or
            not actor['is_approved'] or actor['is_disabled']):raise service.RPCError('forbidden',403)
        if action=='snapshot':return {'actor':copy.deepcopy(actor),'users':copy.deepcopy(self.users)}
        if action=='provision':
            r=params['registration'];username=r['username']
            user=next((x for x in self.users if x['user_id']==r['user_id']),None)
            created=user is None
            if not user:
                user=self.person(username,r['user_id'],'PHID-USER-'+uuid.uuid4().hex[:20]);user.update(mail=r['email'],name=r['name']);self.users.append(user)
            return dict(user_id=r['user_id'],username=username,phorge_phid=user['phorge_phid'],created=created,is_admin=False,email_verified=False,external_email_verified=False)
        if action=='set_disabled':
            if self.fail_disable:raise service.RPCError('native_unavailable',503)
            user=next(x for x in self.users if x['user_id']==params['user_id'])
            user['is_disabled']=params['disabled']
            return {k:user[k] for k in ('user_id','phorge_phid','is_disabled')}
        raise AssertionError(action)

class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'state/registration').mkdir(parents=True)
        (self.root/'config/warden').mkdir(parents=True)
        (self.root/'config/passwords').mkdir(parents=True)
        self.settings=service.Settings(self.root,b'k'*32,0,'127.0.0.1','127.0.0.1')
        service.approval.registrar.initialize_db(self.settings.registration)
        self.native=Native()
        self.directory=[dict(user_id=u['user_id'],mail=u['mail'],name=u['name'],phone='19900000001' if u['is_admin'] else '19900000002',status='active',scope=[],role='user') for u in self.native.users]
        self.settings.directory.write_text(json.dumps(self.directory))
        initialize_store(self.settings.passwords)
        original,store=load_store(self.settings.passwords)
        for user in self.native.users:store['users'][user['user_id']]={'password_hash':hash_password(PASSWORD),'revision':uuid.uuid4().hex}
        atomic_store_write(self.settings.passwords,original,store)
        self.app=service.Application(self.settings,self.native)
    def request(self,action,params=None,**updates):
        result=dict(action=action,params=params or {},actor_phid=ADMIN,actor_principal='site-admin',request_id=uuid.uuid4().hex)
        result.update(updates);return result
    def call(self,action,params=None,**updates):return self.app.handle(self.request(action,params,**updates))
    def error(self,code,fn):
        with self.assertRaises(service.RPCError) as e:fn()
        self.assertEqual(e.exception.code,code)
    def audit(self):
        with self.app.state() as db:return [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id')]
    def register(self):
        rid=str(uuid.uuid4())
        with service.approval.database_connection(self.settings.registration) as db:
            db.execute('INSERT INTO registrations(registration_id,user_id,phone,email,name,status,created_at,updated_at,password_hash) VALUES(?,?,?,?,?,?,?,?,?)',
                (rid,'reg-'+rid,'19900000003','new@acceptance.test','New Person','pending',int(time.time()),int(time.time()),hash_password(PASSWORD)))
        return rid
    def test_private_lists_allow_fields_search_and_pagination(self):
        result=self.call('list_users',{'q':'member-id','limit':1,'offset':0})
        self.assertEqual(result['total'],1);self.assertEqual(result['items'][0]['user_id'],'member-id')
        self.assertTrue(result['items'][0]['can_disable'])
        dumped=json.dumps(result)
        self.assertNotIn('password_hash',dumped);self.assertNotIn('revision',dumped);self.assertNotIn(PASSWORD,dumped)
        self.assertFalse(self.call('list_users',{'q':'site-admin'})['items'][0]['can_disable'])
    def test_fresh_native_authorization_and_directory_binding(self):
        self.native.users[0]['is_admin']=False
        self.error('forbidden',lambda:self.call('overview'))
        self.native.users[0]['is_admin']=True
        rows=json.loads(self.settings.directory.read_text());rows[0]['status']='inactive';self.settings.directory.write_text(json.dumps(rows))
        self.error('forbidden',lambda:self.call('overview'))
    def test_actor_is_not_taken_from_params(self):
        self.error('invalid_request',lambda:self.call('overview',{'approved_by':'siteadmin'}))
        self.error('forbidden',lambda:self.call('overview',actor_phid=OTHER,actor_principal='member-id'))
        self.error('forbidden',lambda:self.call('overview',actor_principal='member-id'))
    def test_alias_collision_allows_only_narrow_entry_revocation(self):
        rows=json.loads(self.settings.directory.read_text());rows.append(dict(rows[1],user_id='duplicate'))
        self.settings.directory.write_text(json.dumps(rows))
        target=self.call('list_users',{'q':'member-id'})['items'][0]
        self.assertTrue(target['entry_only']);self.assertTrue(target['can_disable'])
        self.assertFalse(target['can_enable']);self.assertFalse(target['can_set_password'])
        result=self.call('set_user_status',{'user_id':'member-id','status':'inactive','reason':'test'})
        self.assertTrue(result['entry_only'])
        rows=json.loads(self.settings.directory.read_text())
        self.assertEqual(rows[1]['status'],'inactive');self.assertEqual(rows[2]['status'],'active')
        self.assertNotIn('set_disabled',self.native.calls)
    def test_orphan_directory_entry_can_be_revoked_without_touching_native(self):
        rows=json.loads(self.settings.directory.read_text())
        rows.append(dict(user_id='orphan-id',mail='orphan@acceptance.test',phone='19900000009',name='Directory Person',status='active'))
        self.settings.directory.write_text(json.dumps(rows))
        original,store=load_store(self.settings.passwords)
        store['users']['orphan-id']=copy.deepcopy(store['users']['member-id'])
        atomic_store_write(self.settings.passwords,original,store)
        revision=store['users']['orphan-id']['revision']
        target=self.call('list_users',{'q':'orphan-id'})['items'][0]
        self.assertTrue(target['entry_only']);self.assertTrue(target['can_disable']);self.assertFalse(target['native_state_known'])
        result=self.call('set_user_status',{'user_id':'orphan-id','status':'inactive','reason':'Remove stale admission'})
        self.assertTrue(result['entry_only']);self.assertNotIn('is_disabled',result)
        self.assertEqual(json.loads(self.settings.directory.read_text())[-1]['status'],'inactive')
        _,store=load_store(self.settings.passwords)
        self.assertNotEqual(revision,store['users']['orphan-id']['revision'])
        self.assertNotIn('set_disabled',self.native.calls)
        self.error('identity_conflict',lambda:self.call('set_user_status',{'user_id':'orphan-id','status':'active','reason':'Forbidden restore'}))
        self.error('identity_conflict',lambda:self.call('set_password',{'user_id':'orphan-id','password':NEW_PASSWORD,'password_confirm':NEW_PASSWORD,'reason':'Forbidden reset'}))
    def test_unapproved_identity_revocation_preserves_native_account(self):
        self.native.users[1]['is_approved']=False
        row=self.call('list_users',{'q':'member-id'})['items'][0]
        self.assertTrue(row['can_disable']);self.assertTrue(row['entry_only'])
        self.assertFalse(row['can_enable']);self.assertFalse(row['can_set_password'])
        result=self.call('set_user_status',{'user_id':'member-id','status':'inactive','reason':'Remove unapproved access'})
        self.assertTrue(result['entry_only']);self.assertFalse(self.native.users[1]['is_disabled'])
        self.assertNotIn('set_disabled',self.native.calls)
    def test_mismatched_mapping_displays_directory_identity_and_does_not_touch_native(self):
        self.native.users[1].update(mail='someone-else@acceptance.test',name='Another Native Person')
        row=self.call('list_users',{'q':'member-id'})['items'][0]
        self.assertEqual(row['mail'],'member@acceptance.test');self.assertEqual(row['name'],'member')
        self.assertEqual(row['username'],'');self.assertEqual(row['phorge_phid'],'')
        self.assertFalse(row['native_state_known']);self.assertTrue(row['entry_only'])
        self.call('set_user_status',{'user_id':'member-id','status':'inactive','reason':'Remove inconsistent entry'})
        self.assertFalse(self.native.users[1]['is_disabled']);self.assertNotIn('set_disabled',self.native.calls)
    def test_duplicate_principal_is_not_mutated_or_bulk_disabled(self):
        rows=json.loads(self.settings.directory.read_text());rows.append(dict(rows[1],mail='duplicate@acceptance.test',phone='19900000008'))
        self.settings.directory.write_text(json.dumps(rows));before=self.settings.directory.read_bytes()
        row=self.call('list_users',{'q':'member-id'})['items'][0]
        self.assertFalse(row['can_disable']);self.assertIn('重复',row['manage_reason'])
        self.error('identity_conflict',lambda:self.call('set_user_status',{'user_id':'member-id','status':'inactive','reason':'No ambiguous changes'}))
        self.assertEqual(before,self.settings.directory.read_bytes())
    def test_entry_only_partial_retry_keeps_narrow_scope_after_mapping_repair(self):
        self.native.users[1]['is_approved']=False
        req=self.request('set_user_status',{'user_id':'member-id','status':'inactive','reason':'Remove unapproved entry'})
        with mock.patch.object(service,'atomic_store_write',side_effect=OSError('Simulated unavailable store')):
            self.error('operation_failed',lambda:self.app.handle(req))
        self.assertEqual(json.loads(self.settings.directory.read_text())[1]['status'],'inactive')
        self.native.users[1]['is_approved']=True
        result=self.app.handle(req)
        self.assertTrue(result['entry_only']);self.assertFalse(self.native.users[1]['is_disabled'])
        self.assertNotIn('set_disabled',self.native.calls)
        before=self.settings.passwords.read_bytes()
        self.assertEqual(result,self.app.handle(req));self.assertEqual(before,self.settings.passwords.read_bytes())
    def test_registration_approval_publishes_password_before_access_and_is_idempotent(self):
        rid=self.register();q=self.call('list_registrations',{'q':rid,'status':'pending'})
        self.assertEqual(q['total'],1);self.assertTrue(q['items'][0]['can_approve'])
        self.assertNotIn('password_hash',json.dumps(q))
        req=self.request('approve',{'registration_id':rid,'confirmed_phone':'19900000003','note':'Approved test'})
        result=self.app.handle(req)
        self.assertEqual(result['status'],'approved')
        self.assertEqual(self.app.handle(req),result)
        self.assertEqual(self.native.calls.count('provision'),1)
        _,store=load_store(self.settings.passwords)
        self.assertTrue(verify_password(PASSWORD,store['users']['reg-'+rid]['password_hash']))
        self.assertEqual(self.audit()[0]['actor_phid'],ADMIN)
        self.assertEqual(self.audit()[0]['status'],'succeeded')
        self.assertNotIn(PASSWORD,json.dumps(self.audit()))
    def test_unsupported_phone_fails_before_provisioning_and_remains_rejectable(self):
        rid=self.register()
        with service.approval.database_connection(self.settings.registration) as db:
            db.execute('UPDATE registrations SET phone=? WHERE registration_id=?',('+12025550117',rid))
        before_directory=self.settings.directory.read_bytes()
        before_passwords=self.settings.passwords.read_bytes()
        self.error('unsupported_phone',lambda:self.call('approve',{'registration_id':rid,'confirmed_phone':'+12025550117'}))
        self.assertNotIn('provision',self.native.calls)
        self.assertEqual(before_directory,self.settings.directory.read_bytes())
        self.assertEqual(before_passwords,self.settings.passwords.read_bytes())
        row=service.approval.load_record(self.settings.registration,rid)
        self.assertEqual('pending',row['status'])
        self.assertFalse(row.get('phorge_phid'))
        self.assertFalse(row.get('phorge_username'))
        audit=self.audit()[0]
        self.assertEqual('failed',audit['status'])
        self.assertEqual('unsupported_phone',audit['error_code'])
        self.assertFalse(json.loads(audit['context_json']).get('mutation_started'))
        self.assertEqual('rejected',self.call('reject',{'registration_id':rid,'reason':'Unsupported test phone'})['status'])
    def test_legacy_registration_remains_rejectable_but_not_approved(self):
        rid=self.register()
        with service.approval.database_connection(self.settings.registration) as db:db.execute('UPDATE registrations SET password_hash=NULL WHERE registration_id=?',(rid,))
        self.error('legacy_application',lambda:self.call('approve',{'registration_id':rid,'confirmed_phone':'19900000003'}))
        self.assertEqual(self.call('reject',{'registration_id':rid,'reason':'Please register with password'})['status'],'rejected')
    def test_password_update_preserves_unicode_and_old_password_fails(self):
        result=self.call('set_password',{'user_id':'member-id','password':NEW_PASSWORD,'password_confirm':NEW_PASSWORD,'reason':'Requested reset'})
        _,store=load_store(self.settings.passwords);encoded=store['users']['member-id']['password_hash']
        self.assertTrue(verify_password(NEW_PASSWORD,encoded));self.assertFalse(verify_password(PASSWORD,encoded))
        self.assertFalse(result['reauth_required'])
        raw=json.dumps(self.audit())
        self.assertNotIn(NEW_PASSWORD,raw);self.assertNotIn(encoded,raw)
    def test_self_password_update_requires_reauthentication(self):
        result=self.call('set_password',{'user_id':'site-admin','password':NEW_PASSWORD,'password_confirm':NEW_PASSWORD,'reason':'My change'})
        self.assertTrue(result['reauth_required'])
    def test_password_validation_and_secret_in_note(self):
        p={'user_id':'member-id','password':NEW_PASSWORD,'password_confirm':'different','reason':'Reset'}
        self.error('password_invalid',lambda:self.call('set_password',p))
        p.update(password_confirm=NEW_PASSWORD,reason='Copied '+NEW_PASSWORD)
        self.error('invalid_request',lambda:self.call('set_password',p))
        self.assertEqual(self.audit(),[])
    def test_same_id_different_body_conflicts_and_does_not_reset(self):
        req=self.request('set_password',{'user_id':'member-id','password':NEW_PASSWORD,'password_confirm':NEW_PASSWORD,'reason':'Reset'})
        self.app.handle(req);before=self.settings.passwords.read_bytes()
        self.app.handle(req);self.assertEqual(before,self.settings.passwords.read_bytes())
        req['params']['reason']='Changed'
        self.error('operation_conflict',lambda:self.app.handle(req));self.assertEqual(before,self.settings.passwords.read_bytes())
    def test_password_recovers_after_publication_before_audit_result(self):
        req=self.request('set_password',{'user_id':'member-id','password':NEW_PASSWORD,'password_confirm':NEW_PASSWORD,'reason':'Reset'})
        result=self.app.handle(req);before=self.settings.passwords.read_bytes()
        with self.app.state() as db:db.execute("UPDATE audit SET status='intent',result_json=NULL")
        self.assertEqual(result,self.app.handle(req));self.assertEqual(before,self.settings.passwords.read_bytes())
    def test_later_operation_prevents_resuming_stale_request(self):
        req=self.request('set_password',{'user_id':'member-id','password':NEW_PASSWORD,'password_confirm':NEW_PASSWORD,'reason':'Reset'})
        self.app.handle(req)
        with self.app.state() as db:db.execute("UPDATE audit SET status='intent',result_json=NULL")
        self.call('set_password',dict(req['params'],reason='Later reset'))
        self.error('operation_superseded',lambda:self.app.handle(req))
    def test_completed_old_password_form_cannot_claim_current_success(self):
        req=self.request('set_password',{'user_id':'member-id','password':NEW_PASSWORD,'password_confirm':NEW_PASSWORD,'reason':'Reset'})
        self.app.handle(req)
        self.call('set_password',dict(req['params'],reason='Later reset'))
        before=self.settings.passwords.read_bytes()
        self.error('operation_superseded',lambda:self.app.handle(req))
        self.assertEqual(before,self.settings.passwords.read_bytes())
    def test_status_updates_both_stores_and_rotates_password_revision(self):
        _,before=load_store(self.settings.passwords)
        self.call('set_user_status',{'user_id':'member-id','status':'inactive','reason':'Offboard'})
        self.assertTrue(self.native.users[1]['is_disabled'])
        self.assertEqual(json.loads(self.settings.directory.read_text())[1]['status'],'inactive')
        _,after=load_store(self.settings.passwords)
        self.assertEqual(before['users']['member-id']['password_hash'],after['users']['member-id']['password_hash'])
        self.assertNotEqual(before['users']['member-id']['revision'],after['users']['member-id']['revision'])
        self.call('set_user_status',{'user_id':'member-id','status':'active','reason':'Approved return'})
        self.assertFalse(self.native.users[1]['is_disabled'])
        self.assertEqual(json.loads(self.settings.directory.read_text())[1]['status'],'active')
    def test_status_failure_leaves_directory_denied_and_retries(self):
        self.native.fail_disable=True
        req=self.request('set_user_status',{'user_id':'member-id','status':'inactive','reason':'Offboard'})
        self.error('native_unavailable',lambda:self.app.handle(req))
        self.assertEqual(json.loads(self.settings.directory.read_text())[1]['status'],'inactive')
        self.native.fail_disable=False;self.app.handle(req)
        self.assertTrue(self.native.users[1]['is_disabled'])
    def test_cannot_disable_self_or_reset_inactive_password(self):
        self.error('self_disable',lambda:self.call('set_user_status',{'user_id':'site-admin','status':'inactive','reason':'test'}))
        self.native.users[1]['is_disabled']=True
        self.error('account_inactive',lambda:self.call('set_password',{'user_id':'member-id','password':NEW_PASSWORD,'password_confirm':NEW_PASSWORD,'reason':'Reset'}))
    def test_authorization_occurs_after_shared_lock(self):
        # A request queued behind another operation sees the actor's new state.
        lock=service.approval.approval_lock(self.settings.registration);lock.__enter__()
        result=[]
        thread=threading.Thread(target=lambda: self._queued(result));thread.start();time.sleep(.05)
        self.native.users[0]['is_admin']=False;lock.__exit__(None,None,None);thread.join(timeout=3)
        self.assertEqual(result,['forbidden'])
    def _queued(self,result):
        try:self.call('overview')
        except service.RPCError as e:result.append(e.code)
    def test_signatures_freshness_nonce_and_duplicate_json(self):
        raw=b'{"test":true}';now=int(time.time());nonce=uuid.uuid4().hex
        canonical='POST\n/rpc\n'+str(now)+'\n'+nonce+'\n'+hashlib.sha256(raw).hexdigest()
        signature=hmac.new(self.settings.secret,canonical.encode(),hashlib.sha256).hexdigest()
        self.app.authenticate(raw,str(now),nonce,signature)
        self.error('replayed_request',lambda:self.app.authenticate(raw,str(now),nonce,signature))
        self.error('unauthorized',lambda:self.app.authenticate(raw,str(now-61),nonce,signature))
        self.error('unauthorized',lambda:self.app.authenticate(raw+b' ',str(now),uuid.uuid4().hex,signature))
        self.error('invalid_request',lambda:service.strict_json(b'{"a":1,"a":2}'))
        self.error('invalid_request',lambda:service.strict_json(b'{"a":NaN}'))
    def test_real_http_signed_requests_and_forbidden_origin(self):
        server=service.HTTPServer(('127.0.0.1',0),service.handler_for(self.app))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        def send(raw,extra=None):
            stamp=str(int(time.time()));nonce=uuid.uuid4().hex
            canonical='POST\n/rpc\n'+stamp+'\n'+nonce+'\n'+hashlib.sha256(raw).hexdigest()
            headers={'Content-Type':'application/json','X-Maintenance-Timestamp':stamp,'X-Maintenance-Nonce':nonce,
                     'X-Maintenance-Signature':hmac.new(self.settings.secret,canonical.encode(),hashlib.sha256).hexdigest()}
            headers.update(extra or {})
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3);conn.request('POST','/rpc',raw,headers)
            response=conn.getresponse();status=response.status;value=json.loads(response.read());conn.close();return status,value
        raw=json.dumps(self.request('overview')).encode()
        status,value=send(raw);self.assertEqual(status,200);self.assertTrue(value['ok'])
        status,value=send(raw,{'X-Maintenance-Signature':'0'*64});self.assertEqual(status,403)
        status,value=send(raw,{'Origin':'https://attacker.invalid'});self.assertEqual(status,400)
        self.settings.client_ip='192.0.2.1';status,value=send(raw);self.assertEqual(status,403)
        self.assertNotIn(PASSWORD,json.dumps(value))

if __name__=='__main__':unittest.main(verbosity=2)
