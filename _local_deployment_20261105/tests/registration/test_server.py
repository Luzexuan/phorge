import concurrent.futures
import http.client
import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import threading
import unittest
from urllib.parse import urlencode

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('registration_server',ROOT/'config/registration/server.py')
server=importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name]=server
SPEC.loader.exec_module(server)
TEST_PASSWORD = 'Acceptance Password 2026!'


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.directory=Path(self.temp.name)/'warden.json'
        self.directory.write_text(json.dumps([{'user_id':'existing-admin','mail':'admin@example.test','phone':'13800000000','status':'active'}]))
        self.database=Path(self.temp.name)/'registrations.sqlite3'
        self.app=server.Application(server.Settings(self.database,self.directory,b'x'*32,
                origin='https://signup.example.test',trusted_proxy='127.0.0.1'))
        self.http=server.RegistrationHTTPServer(('127.0.0.1',0),server.handler_for(self.app))
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True)
        self.thread.start()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()
        self.temp.cleanup()

    def rows(self):
        c=server.connect_db(self.database)
        try:
            return [dict(r) for r in c.execute('SELECT * FROM registrations')]
        finally:
            c.close()

    def request(self,method='GET',body=None,headers=None,path='/_register'):
        h={'Host':'signup.example.test','X-Forwarded-Proto':'https','X-Forwarded-For':'192.0.2.10'}
        h.update(headers or {})
        c=http.client.HTTPConnection('127.0.0.1',self.http.server_port,timeout=5)
        try:
            c.request(method,path,body=body,headers=h)
            r=c.getresponse()
            return r.status,dict(r.getheaders()),r.read().decode()
        finally:
            c.close()

    def form(self,**changes):
        status,h,body=self.request()
        self.assertEqual(status,200)
        token=re.search(r'name="csrf" value="([^"]+)"',body).group(1)
        data={'csrf':token,'name':'测试用户','phone':'+86 139 0000 0001','email':' New.User@Example.Test ',
              'password':TEST_PASSWORD,'password_confirm':TEST_PASSWORD}
        data.update(changes)
        headers={'Origin':'https://signup.example.test','Content-Type':'application/x-www-form-urlencoded','Cookie':h['Set-Cookie'].split(';',1)[0]}
        return data,headers

    def submit(self,**changes):
        data,h=self.form(**changes)
        return self.request('POST',urlencode(data),h)

    def test_valid_request_is_private_pending_without_authorization(self):
        original=self.directory.read_bytes()
        status,headers,_=self.submit()
        self.assertEqual(status,303)
        self.assertEqual(headers['Location'],'/_register?submitted=1')
        self.assertNotIn('Set-Cookie',headers)
        self.assertEqual(self.directory.read_bytes(),original)
        row=self.rows()[0]
        self.assertEqual(row['user_id'],'reg-'+row['registration_id'])
        self.assertEqual(row['phone'],'13900000001')
        self.assertEqual(row['email'],'new.user@example.test')
        self.assertEqual(row['status'],'pending')
        self.assertTrue(server.valid_hash(row['password_hash']))
        self.assertNotIn(TEST_PASSWORD,row['password_hash'])
        for name in ['org_unit_id','manager_user_id','position','approved_at','approved_by','phorge_username','phorge_phid']:
            self.assertIsNone(row[name])
        c=server.connect_db(self.database)
        self.assertEqual(c.execute('SELECT count(*) FROM org_units').fetchone()[0],0)
        c.close()

    def test_each_required_field_rejected_server_side(self):
        for field in ('name','phone','email','password','password_confirm'):
            with self.subTest(field=field):
                data,h=self.form()
                data.pop(field)
                self.assertEqual(self.request('POST',urlencode(data),h)[0],400)
                data,h=self.form(**{field:''})
                self.assertEqual(self.request('POST',urlencode(data),h)[0],400)
        self.assertEqual(self.rows(),[])

    def test_duplicates_and_reserved_contact_have_indistinguishable_receipts(self):
        first=self.submit()
        row=self.rows()[0]
        duplicate=self.submit(name='replacement name',password='A replacement password 2026!',password_confirm='A replacement password 2026!')
        phone_conflict=self.submit(email='another@example.test')
        mail_conflict=self.submit(phone='13900000002')
        reserved_mail=self.submit(email='ADMIN@EXAMPLE.TEST',phone='13900000003')
        reserved_phone=self.submit(email='unused@example.test',phone='+86 13800000000')
        for response in (duplicate,phone_conflict,mail_conflict,reserved_mail,reserved_phone):
            self.assertEqual((response[0],response[1].get('Location'),response[2]),(first[0],first[1].get('Location'),first[2]))
        self.assertEqual(self.rows(),[row])

    def test_csrf_missing_forged_expired_and_unicode_rejected(self):
        data,h=self.form()
        for value in ('bad',self.app.csrf(now=1),'é'*20):
            data['csrf']=value
            h['Cookie']=server.COOKIE+'='+value
            self.assertEqual(self.request('POST',urlencode(data),h)[0],403)
        data,h=self.form()
        h.pop('Cookie')
        self.assertEqual(self.request('POST',urlencode(data),h)[0],403)
        self.assertEqual(self.rows(),[])

    def test_cross_origin_and_untrusted_direct_access_rejected(self):
        data,h=self.form()
        for origin in ('https://evil.example','null','http://signup.example.test'):
            h['Origin']=origin
            self.assertEqual(self.request('POST',urlencode(data),h)[0],403)
        h.pop('Origin')
        self.assertEqual(self.request('POST',urlencode(data),h)[0],403)
        self.app.settings.trusted_proxy='192.0.2.200'
        self.assertEqual(self.request()[0],403)
        self.assertEqual(self.rows(),[])

    def test_host_and_proto_must_match_trusted_origin(self):
        self.assertEqual(self.request(headers={'Host':'evil.example'})[0],403)
        self.assertEqual(self.request(headers={'X-Forwarded-Proto':'http'})[0],403)

    def test_body_limit_and_extra_privilege_fields_rejected(self):
        data,h=self.form()
        data['role']='admin'
        self.assertEqual(self.request('POST',urlencode(data),h)[0],400)
        data,h=self.form()
        data['org_unit_id']='secret-team'
        self.assertEqual(self.request('POST',urlencode(data),h)[0],400)
        self.assertEqual(self.request('POST','x'*(server.MAX_BODY+1),h)[0],413)
        self.assertEqual(self.rows(),[])

    def test_unsupported_content_and_duplicate_parameters_rejected(self):
        data,h=self.form()
        h['Content-Type']='application/json'
        self.assertEqual(self.request('POST','{}',h)[0],415)
        data,h=self.form()
        self.assertEqual(self.request('POST',urlencode(data)+'&email=second@example.test',h)[0],400)

    def test_only_registration_route_is_public(self):
        for path in ('/admin','/registrations','/_register/list','/v1/approve'):
            self.assertEqual(self.request(path=path)[0],404)

    def test_response_contains_no_auth_cookie_and_has_browser_protections(self):
        _,h,body=self.request()
        self.assertTrue(h['Set-Cookie'].startswith(server.COOKIE+'='))
        for flag in ('Secure','HttpOnly','SameSite=Strict','Path=/'):
            self.assertIn(flag,h['Set-Cookie'])
        self.assertNotIn('stargate_session_id',h['Set-Cookie'])
        self.assertNotIn('phsid',h['Set-Cookie'])
        self.assertEqual(h['Cache-Control'],'no-store')
        self.assertEqual(h['Referrer-Policy'],'same-origin')
        self.assertIn("frame-ancestors 'none'",h['Content-Security-Policy'])
        self.assertIn('href="/_login"',body)

    def test_missing_or_invalid_directory_fails_closed(self):
        self.directory.write_text('{invalid')
        self.assertEqual(self.submit()[0],503)
        self.assertEqual(self.rows(),[])
        self.directory.unlink()
        self.assertEqual(self.submit()[0],503)

    def test_rate_limit_is_durable_and_uses_nearest_forwarded_address(self):
        self.app.settings.post_ip_limit=1
        self.assertEqual(self.submit()[0],303)
        data,h=self.form()
        h['X-Forwarded-For']='198.51.100.55, 192.0.2.10'
        self.assertEqual(self.request('POST',urlencode(data),h)[0],429)
        other=server.Application(self.app.settings)
        self.assertFalse(other.rate_allowed('192.0.2.10','POST'))

    def test_concurrent_duplicate_submissions_never_create_two_principals(self):
        encoded=server.hash_password(TEST_PASSWORD)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _:self.app.submit('13900000001','race@example.test','Concurrent',encoded),range(20)))
        self.assertEqual(len(self.rows()),1)

    def test_pending_capacity_is_bounded(self):
        self.app.settings.max_pending=1
        self.assertEqual(self.submit()[0],303)
        self.assertEqual(self.submit(phone='13900000002',email='another@example.test')[0],503)
        self.assertEqual(len(self.rows()),1)

    def test_data_validation_matches_phorge_and_canonical_phone(self):
        self.assertEqual(server.normalize_phone('0086 139-0000-0001'),'13900000001')
        self.assertEqual(server.normalize_phone('+1 (202) 555-0100'),'+12025550100')
        for bad in ('+8612000000000','123','1390000000é','13900000001\n'):
            with self.assertRaises(ValueError):server.normalize_phone(bad)
        for bad in ('a\n@example.test',"o'hara@example.test",'x'*65+'@example.test','a@'+('longdomain.'*11)+'example.test'):
            with self.assertRaises(ValueError):server.normalize_email(bad)
        for bad in ('','a\x00b','a\u202eb','a'*81):
            with self.assertRaises(ValueError):server.validate_name(bad)

    def test_password_strength_confirmation_and_no_reflection(self):
        for password in ('short password','x'*129,'valid long password\x00value'):
            with self.subTest(length=len(password)):
                status,_,body=self.submit(password=password,password_confirm=password)
                self.assertEqual(status,400)
                self.assertNotIn(password,body)
        status,_,body=self.submit(password_confirm='A different long password!')
        self.assertEqual(status,400)
        self.assertNotIn(TEST_PASSWORD,body)
        self.assertEqual(self.rows(),[])

    def test_old_database_migration_preserves_registration_and_null_credential(self):
        old=Path(self.temp.name)/'old.sqlite3'
        connection=sqlite3.connect(old)
        connection.executescript(server.SCHEMA.replace('  password_hash TEXT,\n',''))
        connection.execute("INSERT INTO registrations(registration_id,user_id,phone,email,name,status,created_at,updated_at) VALUES('old','reg-old','13900000007','old@example.test','Old','pending',1,1)")
        connection.commit();connection.close()
        server.initialize_db(old)
        server.initialize_db(old)
        connection=server.connect_db(old)
        row=dict(connection.execute('SELECT * FROM registrations').fetchone())
        connection.close()
        self.assertEqual(row['user_id'],'reg-old')
        self.assertEqual(row['status'],'pending')
        self.assertIsNone(row['password_hash'])

    def test_direct_submission_cannot_store_arbitrary_or_plaintext_hash(self):
        with self.assertRaises(ValueError):
            self.app.submit('13900000005','invalid@example.test','Invalid',TEST_PASSWORD)
        self.assertEqual(self.rows(),[])


if __name__=='__main__':
    unittest.main()
