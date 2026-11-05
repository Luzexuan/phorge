"""Actual child-process signal handling; no production service or data touched."""
import hashlib
import hmac
import http.client
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import signal
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('maintenance_shutdown_service',ROOT/'config/maintenance/service.py')
service=importlib.util.module_from_spec(spec);sys.modules[spec.name]=service;spec.loader.exec_module(service)
from password_store import initialize_store
ADMIN='PHID-USER-'+'a'*20
KEY=b's'*32
PASSWORD='Disposable shutdown test password 2026'

def child(root,ready,started,delay):
    def native(action,actor_phid,actor_principal,**params):
        started.set()
        time.sleep(delay)
        actor=dict(username='admin',name='Admin',mail='admin@acceptance.test',user_id='admin-id',phorge_phid=ADMIN,
            binding_valid=True,is_admin=True,is_approved=True,is_disabled=False,is_system_agent=False,is_mailing_list=False)
        return dict(actor=actor,users=[actor])
    settings=service.Settings(Path(root),KEY,0,'127.0.0.1','127.0.0.1')
    app=service.Application(settings,native)
    server=service.HTTPServer(('127.0.0.1',0),service.handler_for(app))
    ready.send(server.server_port)
    ready.close()
    service.serve(app,server)

class ShutdownTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'state/registration').mkdir(parents=True)
        (self.root/'config/warden').mkdir(parents=True)
        (self.root/'config/passwords').mkdir(parents=True)
        self.database=self.root/'state/registration/registrations.sqlite3'
        service.approval.registrar.initialize_db(self.database)
        (self.root/'config/warden/users.json').write_text(json.dumps([dict(user_id='admin-id',mail='admin@acceptance.test',phone='19900000001',name='Admin',status='active')]))
        initialize_store(self.root/'config/passwords/users.json')
        self.ctx=multiprocessing.get_context('fork')
    def start(self,delay=0):
        receive,send=self.ctx.Pipe(duplex=False)
        started=self.ctx.Event()
        process=self.ctx.Process(target=child,args=(str(self.root),send,started,delay))
        process.start();send.close()
        self.addCleanup(lambda: process.kill() if process.is_alive() else None)
        self.assertTrue(receive.poll(4));port=receive.recv();receive.close()
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
        conn.request('GET','/healthz');response=conn.getresponse();self.assertEqual(response.status,200);response.read();conn.close()
        return process,port,started
    def post(self,port,results):
        payload=dict(action='set_password',actor_phid=ADMIN,actor_principal='admin-id',request_id=uuid.uuid4().hex,
                     params=dict(user_id='admin-id',password=PASSWORD,password_confirm=PASSWORD,reason='Shutdown acceptance'))
        body=json.dumps(payload).encode();stamp=str(int(time.time()));nonce=uuid.uuid4().hex
        canonical='POST\n/rpc\n'+stamp+'\n'+nonce+'\n'+hashlib.sha256(body).hexdigest()
        headers={'Content-Type':'application/json','X-Maintenance-Timestamp':stamp,'X-Maintenance-Nonce':nonce,
                 'X-Maintenance-Signature':hmac.new(KEY,canonical.encode(),hashlib.sha256).hexdigest()}
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=6)
        try:
            conn.request('POST','/rpc',body,headers);response=conn.getresponse()
            results.append((response.status,json.loads(response.read())))
        except Exception as error:results.append(type(error).__name__)
        finally:conn.close()
    def test_idle_sigterm_exits_cleanly(self):
        process,_,_=self.start();os.kill(process.pid,signal.SIGTERM);process.join(3)
        self.assertFalse(process.is_alive());self.assertEqual(process.exitcode,0)
    def test_inflight_mutation_finishes_with_durable_success_audit(self):
        process,port,started=self.start(.4);results=[]
        thread=threading.Thread(target=self.post,args=(port,results));thread.start()
        self.assertTrue(started.wait(3));os.kill(process.pid,signal.SIGTERM)
        thread.join(5);process.join(3)
        self.assertFalse(process.is_alive());self.assertEqual(process.exitcode,0)
        self.assertEqual(results[0][0],200);self.assertTrue(results[0][1]['ok'])
        with sqlite3.connect(self.root/'state/maintenance/maintenance.sqlite3') as db:
            self.assertEqual(db.execute('SELECT status FROM audit').fetchone()[0],'succeeded')
        value=json.loads((self.root/'config/passwords/users.json').read_text())
        self.assertIn('admin-id',value['users'])
    def test_sigterm_cancels_waiting_backup_lock_without_mutation(self):
        process,port,started=self.start();results=[]
        with service.approval.approval_lock(self.database):
            thread=threading.Thread(target=self.post,args=(port,results));thread.start()
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                with sqlite3.connect(self.root/'state/maintenance/maintenance.sqlite3') as db:
                    count=db.execute('SELECT COUNT(*) FROM nonces').fetchone()[0]
                if count:break
                time.sleep(.02)
            self.assertEqual(count,1);self.assertFalse(started.is_set())
            os.kill(process.pid,signal.SIGTERM);thread.join(4);process.join(3)
            self.assertFalse(process.is_alive());self.assertEqual(process.exitcode,0)
        self.assertEqual(results[0][0],503)
        with sqlite3.connect(self.root/'state/maintenance/maintenance.sqlite3') as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],0)
        self.assertEqual(json.loads((self.root/'config/passwords/users.json').read_text())['users'],{})

if __name__=='__main__':unittest.main(verbosity=2)
