#!/usr/bin/env python3
"""Private signed maintenance RPC, with no Docker or shell execution access."""
from __future__ import annotations
import contextlib
import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = Path(os.environ.get('MAINTENANCE_ROOT', Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT/'scripts'))
sys.path.insert(0, str(ROOT/'config/registration'))
from password_store import atomic_store_write, load_store
from credential_hashes import hash_password, validate_password, valid_hash
_spec = importlib.util.spec_from_file_location('maintenance_approval', ROOT/'scripts/approve-registration.py')
approval = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = approval
_spec.loader.exec_module(approval)

MAX_BODY = 16384
READ_ACTIONS = {'overview', 'list_registrations', 'list_users', 'list_audit'}
WRITE_ACTIONS = {'approve', 'reject', 'set_user_status', 'set_password'}
MESSAGES = {
    'invalid_request':'请求格式不正确，请刷新页面后重试。',
    'unauthorized':'维护请求未通过身份验证。',
    'replayed_request':'请求已经使用，请刷新页面后重试。',
    'forbidden':'当前账号没有维护权限，或身份状态已经改变。',
    'not_found':'没有找到对应记录。',
    'identity_conflict':'账号的稳定身份、邮箱或白名单绑定不一致，请先核对资料。',
    'self_disable':'不能停用当前登录的管理员。',
    'last_admin':'不能停用最后一个可登录的管理员。',
    'account_inactive':'该账号尚未批准或已停用，请先检查账号状态。',
    'password_invalid':'密码必须为 15 至 128 个字符，且两次输入一致。',
    'legacy_application':'旧申请没有密码，请拒绝后让申请人重新填写密码注册。',
    'unsupported_phone':'当前仅支持审批中国大陆 11 位手机号；该申请的号码暂不支持，重复提交不会成功。请核对申请资料或拒绝申请并说明原因。',
    'operation_conflict':'同一操作标识不能用于不同请求，请刷新页面重新操作。',
    'operation_superseded':'该账号已有后续维护操作，请刷新页面核对当前状态。',
    'operation_failed':'操作未完成，已记录审计信息；请核对当前状态后重试。',
    'native_unavailable':'暂时无法核验业务账号，请稍后重试。',
    'storage_unavailable':'维护存储暂时不可用，请稍后重试。',
}

class RPCError(Exception):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code, self.status = code, status

def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))
    except (ValueError, UnicodeError, RecursionError):
        raise RPCError('invalid_request') from None

def text(value, maximum=500, required=False):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c)<32 and c not in '\n\t' for c in value):
        raise RPCError('invalid_request')
    value = value.strip()
    if required and not value:
        raise RPCError('invalid_request')
    return value

def exact_keys(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        raise RPCError('invalid_request')

def uuid_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})', value):
        raise RPCError('invalid_request')
    return value

@dataclass
class Settings:
    root: Path
    secret: bytes
    port: int = 8086
    bind_host: str = '172.30.20.3'
    client_ip: str = '172.30.20.2'
    def __post_init__(self):
        self.root = Path(self.root)
        if len(self.secret) != 32: raise ValueError('Maintenance signing key must be exactly 32 bytes.')
    @property
    def registration(self): return self.root/'state/registration/registrations.sqlite3'
    @property
    def directory(self): return self.root/'config/warden/users.json'
    @property
    def passwords(self): return self.root/'config/passwords/users.json'
    @property
    def database(self): return self.root/'state/maintenance/maintenance.sqlite3'

class NativeBridge:
    def __init__(self, root): self.root = Path(root)
    def __call__(self, action, actor_phid, actor_principal, **params):
        try:
            result = subprocess.run(['php', str(self.root/'config/maintenance/native.php')],
                input=json.dumps(dict(action=action,actor_phid=actor_phid,
                                     actor_principal=actor_principal,**params)),
                text=True,capture_output=True,timeout=60,cwd=self.root)
            if result.returncode:
                if result.stdout.strip() == '{"native_error":"actor"}':
                    raise RPCError('forbidden',403)
                raise RPCError('native_unavailable',503)
            if len(result.stdout) > 8*1024*1024:
                raise RPCError('native_unavailable',503)
            return strict_json(result.stdout)
        except (OSError, subprocess.TimeoutExpired):
            raise RPCError('native_unavailable',503) from None

class Application:
    def __init__(self, settings, native=None):
        self.settings = settings
        self.native = native or NativeBridge(settings.root)
        self.stop_requested = threading.Event()
        self.settings.database.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with self.state() as db:
            db.executescript('''
CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT UNIQUE NOT NULL,
 fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 actor_phid TEXT NOT NULL, actor_username TEXT NOT NULL, action TEXT NOT NULL,
 target TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL,
 error_code TEXT, result_json TEXT, context_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS audit_target ON audit(target,id);
''')
        self.settings.database.chmod(0o600)
    @contextlib.contextmanager
    def state(self):
        path = self.settings.database
        if path.exists() and (path.is_symlink() or not stat.S_ISREG(path.stat().st_mode)):
            raise RPCError('storage_unavailable',503)
        db = sqlite3.connect(str(path),timeout=5,isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA busy_timeout=5000')
            db.execute('PRAGMA journal_mode=WAL')
            yield db
        finally: db.close()
    def authenticate(self, raw, timestamp, nonce, signature, now=None):
        now = int(time.time()) if now is None else now
        if (not re.fullmatch(r'[0-9]{10}',str(timestamp or '')) or
            abs(now-int(timestamp)) > 60 or
            not re.fullmatch(r'[a-f0-9]{32}',str(nonce or '')) or
            not re.fullmatch(r'[a-f0-9]{64}',str(signature or ''))):
            raise RPCError('unauthorized',403)
        canonical = 'POST\n/rpc\n'+timestamp+'\n'+nonce+'\n'+hashlib.sha256(raw).hexdigest()
        expected = hmac.new(self.settings.secret,canonical.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected,signature): raise RPCError('unauthorized',403)
        with self.state() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM nonces WHERE expires_at < ?',(now,))
            try: db.execute('INSERT INTO nonces VALUES (?,?)',(nonce,now+180))
            except sqlite3.IntegrityError:
                db.rollback()
                raise RPCError('replayed_request',409) from None
            db.commit()
    def snapshot(self, request):
        result = self.native('snapshot',request['actor_phid'],request['actor_principal'])
        if not isinstance(result,dict) or not isinstance(result.get('users'),list):
            raise RPCError('native_unavailable',503)
        actor = result.get('actor')
        if (not isinstance(actor,dict) or actor.get('phorge_phid') != request['actor_phid'] or
            actor.get('user_id') != request['actor_principal'] or actor.get('is_admin') is not True or
            actor.get('is_approved') is not True or actor.get('is_disabled') is not False or
            actor.get('is_system_agent') is not False or actor.get('is_mailing_list') is not False or
            actor.get('binding_valid') is not True):
            raise RPCError('forbidden',403)
        _, directory = approval.load_directory(self.settings.directory)
        bound = self.bound(actor,directory,result['users'])
        if not bound or bound.get('status') != 'active': raise RPCError('forbidden',403)
        return actor,result['users'],directory
    @staticmethod
    def bound(native, directory, users):
        principal = native.get('user_id')
        if (not isinstance(principal,str) or not principal or not native.get('binding_valid') or
            sum(u.get('user_id')==principal for u in users) != 1): return None
        matches = [d for d in directory if d.get('user_id')==principal]
        if len(matches)!=1:return None
        own = matches[0]
        mail = str(own.get('mail','')).strip().casefold()
        if not mail or mail != str(native.get('mail','')).strip().casefold(): return None
        for other in directory:
            if other is own:continue
            if (str(other.get('mail','')).strip().casefold()==mail or
                (own.get('phone') and other.get('phone')==own['phone'])):return None
        return own
    def target(self, principal, users, directory):
        matches = [u for u in users if u.get('user_id')==principal]
        if len(matches)!=1: raise RPCError('identity_conflict',409)
        native=matches[0]
        own=self.bound(native,directory,users)
        if (not own or native.get('is_system_agent') or native.get('is_mailing_list') or
            native.get('is_approved') is not True):raise RPCError('identity_conflict',409)
        return native,own
    @staticmethod
    def isolated_entry(principal,users,directory):
        """Identify one directory row without trusting an unusable native link."""
        matches=[d for d in directory if d.get('user_id')==principal]
        if len(matches)!=1 or sum(u.get('user_id')==principal for u in users)>1:
            return None
        return matches[0]
    def validate(self, request):
        exact_keys(request,{'action','actor_phid','actor_principal','request_id','params'})
        action=request['action']
        if not isinstance(action,str) or action not in READ_ACTIONS|WRITE_ACTIONS:raise RPCError('invalid_request')
        if not isinstance(request['actor_phid'],str) or not re.fullmatch(r'PHID-USER-[a-zA-Z0-9]{20}',request['actor_phid']):
            raise RPCError('invalid_request')
        text(request['actor_principal'],255,True)
        uuid_id(request['request_id'])
        params=request['params']
        if action=='overview':exact_keys(params,set())
        elif action.startswith('list_'):
            exact_keys(params,set(),{'q','offset','limit'}|({'status'} if action=='list_registrations' else set()))
            text(params.get('q',''),200)
            if type(params.get('offset',0)) is not int or not 0<=params.get('offset',0)<=100000:
                raise RPCError('invalid_request')
            if type(params.get('limit',100)) is not int or not 1<=params.get('limit',100)<=100:
                raise RPCError('invalid_request')
            if action=='list_registrations' and params.get('status','all') not in {'all','pending','approved','rejected'}:
                raise RPCError('invalid_request')
        elif action=='approve':
            exact_keys(params,{'registration_id','confirmed_phone'},{'username','note'})
            uuid_id(params['registration_id']);text(params['confirmed_phone'],40,True)
            if params.get('username'):text(params['username'],64,True)
            text(params.get('note',''))
        elif action=='reject':
            exact_keys(params,{'registration_id','reason'})
            uuid_id(params['registration_id']);text(params['reason'],500,True)
        elif action=='set_user_status':
            exact_keys(params,{'user_id','status','reason'})
            text(params['user_id'],255,True);text(params['reason'],500,True)
            if params['status'] not in {'active','inactive'}:raise RPCError('invalid_request')
        elif action=='set_password':
            exact_keys(params,{'user_id','password','password_confirm','reason'})
            text(params['user_id'],255,True);text(params['reason'],500,True)
            try:validate_password(params['password'])
            except ValueError:raise RPCError('password_invalid') from None
            if params['password'] != params['password_confirm']:raise RPCError('password_invalid')
            if params['password'] in params['reason']:raise RPCError('invalid_request')
    def handle(self, request):
        self.validate(request)
        # One lock spans real actor revalidation, audit intent, all files/SQL,
        # and completion. CLI approval/password tools and backup use this lock.
        with self.operation_lock():
            actor,users,directory=self.snapshot(request)
            if request['action'] in READ_ACTIONS:
                return self.read(request,actor,users,directory)
            return self.mutate(request,actor,users,directory)
    @contextlib.contextmanager
    def operation_lock(self):
        """Use the common lock, but cancel an unstarted request during stop.

        Backup obtains this lock before stopping containers. A blocking flock
        here would otherwise keep shutdown waiting on the backup which is
        itself waiting for this service. An operation already holding the lock
        completes normally, including its durable audit result.
        """
        path=self.settings.registration.with_name('approval.lock')
        descriptor=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        acquired=False
        try:
            while not self.stop_requested.is_set():
                try:
                    fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    acquired=True
                    break
                except BlockingIOError:
                    self.stop_requested.wait(0.1)
            if not acquired or self.stop_requested.is_set():
                raise RPCError('storage_unavailable',503)
            yield
        finally:
            if acquired:fcntl.flock(descriptor,fcntl.LOCK_UN)
            os.close(descriptor)
    @staticmethod
    def page(items,params):
        q=params.get('q','').strip().casefold()
        if q:items=[x for x in items if any(q in str(v).casefold() for v in x.values() if isinstance(v,(str,int)))]
        total=len(items);offset=params.get('offset',0);limit=params.get('limit',100)
        return {'items':items[offset:offset+limit],'total':total,'offset':offset,'limit':limit}
    def user_rows(self,actor,users,directory):
        _,store=load_store(self.settings.passwords)
        admins=[u for u in users if u.get('is_admin') and u.get('is_approved') and not u.get('is_disabled')
                and (self.bound(u,directory,users) or {}).get('status')=='active'
                and not u.get('is_system_agent') and not u.get('is_mailing_list')]
        result=[]
        seen=set()
        for native in users:
            principal=native.get('user_id')
            own=self.bound(native,directory,users)
            valid=bool(own and native.get('is_approved') and not native.get('is_system_agent') and not native.get('is_mailing_list'))
            single=self.isolated_entry(principal,users,directory)
            entry_only=bool(not valid and single and principal!=actor['user_id'])
            if principal:seen.add(principal)
            active=bool(own and own.get('status')=='active' and not native.get('is_disabled'))
            self_target=native['phorge_phid']==actor['phorge_phid']
            disable=valid and not self_target and (not native.get('is_admin') or len(admins)>1)
            row={key:native.get(key) for key in ('user_id','username','phorge_phid','name','mail','is_admin','is_disabled','is_approved')}
            if not own:
                row.update(username='',phorge_phid='',is_admin=False,is_disabled=None,is_approved=None)
            if entry_only:
                row.update(name=single.get('name',''),mail=single.get('mail',''))
            duplicate=bool(principal and (sum(d.get('user_id')==principal for d in directory)>1 or sum(u.get('user_id')==principal for u in users)>1))
            row.update(phone=(single or {}).get('phone',''),entry_status=(single or {}).get('status','ambiguous' if duplicate else 'unbound'),
                has_password=principal in store['users'],can_manage=bool(valid or entry_only),
                can_disable=bool((disable and (active or not native.get('is_disabled'))) or (entry_only and single.get('status')=='active')),
                can_enable=bool(valid and not active and not self_target),
                can_set_password=bool(valid and active),
                entry_only=entry_only,native_state_known=bool(own),
                manage_reason=('稳定身份存在重复记录，无法确定唯一目标；请先诊断数据一致性。' if duplicate else
                    ('仅可撤销登录准入，不修改业务账号状态；恢复和设密需要完整的已批准身份绑定。' if entry_only else
                     ('' if valid else '缺少唯一的已批准账号及登录身份绑定。'))))
            result.append(row)
        for own in directory:
            if own['user_id'] in seen:continue
            single=self.isolated_entry(own['user_id'],users,directory)
            entry_only=bool(single and own['user_id']!=actor['user_id'])
            result.append(dict(user_id=own['user_id'],username='',phorge_phid='',name=own.get('name',''),mail=own.get('mail',''),phone=own.get('phone',''),entry_status=own.get('status','unknown'),is_admin=False,is_disabled=None,is_approved=None,has_password=own['user_id'] in store['users'],can_manage=entry_only,can_disable=bool(entry_only and own.get('status')=='active'),can_enable=False,can_set_password=False,entry_only=entry_only,native_state_known=False,manage_reason=('仅可撤销登录准入，不修改业务账号状态；请使用注册审批流程建立完整身份。' if single else '稳定身份存在重复记录，无法确定唯一目标；请先诊断数据一致性。')))
        return sorted(result,key=lambda x:(not x['is_admin'],str(x['username'])))
    def read(self,request,actor,users,directory):
        action,params=request['action'],request['params']
        if action=='list_users':return self.page(self.user_rows(actor,users,directory),params)
        if action=='list_audit':
            with self.state() as db:
                rows=[dict(r) for r in db.execute('SELECT id,request_id,created_at,updated_at,actor_phid,actor_username,action,target,reason,status,error_code FROM audit ORDER BY id DESC LIMIT 10000')]
            return self.page(rows,params)
        with approval.database_connection(self.settings.registration) as db:
            if action=='overview':
                counts={name:0 for name in ('pending','approved','rejected','active','inactive','passwords')}
                counts.update({r['status']:r['n'] for r in db.execute('SELECT status,COUNT(*) AS n FROM registrations GROUP BY status')})
                counts['active']=sum(d.get('status')=='active' for d in directory)
                counts['inactive']=sum(d.get('status')!='active' for d in directory)
                _,store=load_store(self.settings.passwords);counts['passwords']=len(store['users'])
                return {'counts':counts,'actor':{k:actor[k] for k in ('username','name','phorge_phid','user_id')}}
            rows=[dict(r) for r in db.execute('SELECT registration_id,user_id,name,phone,email,status,created_at,updated_at,approved_at,approved_by,approval_note,phorge_username,phorge_phid,password_hash IS NOT NULL AS password_available FROM registrations ORDER BY created_at DESC,registration_id DESC')]
        for row in rows:
            row['password_available']=bool(row['password_available'])
            row['can_approve']=row['status']=='pending' and row['password_available']
            row['can_reject']=row['status']=='pending' and not row['phorge_username'] and not row['phorge_phid']
        if params.get('status','all')!='all':rows=[r for r in rows if r['status']==params['status']]
        return self.page(rows,params)
    def mutate(self,request,actor,users,directory):
        action,params=request['action'],request['params']
        target=params.get('registration_id',params.get('user_id',''))
        reason=text(params.get('reason',params.get('note','')))
        serialized=json.dumps(request,sort_keys=True,separators=(',',':'),ensure_ascii=False)
        fingerprint=hmac.new(self.settings.secret,serialized.encode(),hashlib.sha256).hexdigest()
        now=int(time.time())
        with self.state() as db:
            previous=db.execute('SELECT * FROM audit WHERE request_id=?',(request['request_id'],)).fetchone()
            if previous:
                if not hmac.compare_digest(previous['fingerprint'],fingerprint):raise RPCError('operation_conflict',409)
                newer=db.execute('SELECT id FROM audit WHERE target=? AND id>? LIMIT 1',(target,previous['id'])).fetchone()
                if newer:raise RPCError('operation_superseded',409)
                if previous['status']=='succeeded':return json.loads(previous['result_json'])
                operation_id=previous['id'];context=json.loads(previous['context_json'])
                db.execute("UPDATE audit SET status='intent',error_code=NULL,updated_at=? WHERE id=?",(now,operation_id))
            else:
                context={}
                cursor=db.execute('INSERT INTO audit(request_id,fingerprint,created_at,updated_at,actor_phid,actor_username,action,target,reason,status) VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (request['request_id'],fingerprint,now,now,actor['phorge_phid'],actor['username'],action,target,reason,'intent'))
                operation_id=cursor.lastrowid
        try:
            result=self.execute_mutation(action,params,actor,users,directory,request,operation_id,context)
            with self.state() as db:db.execute("UPDATE audit SET status='succeeded',updated_at=?,result_json=?,error_code=NULL WHERE id=?",(int(time.time()),json.dumps(result,ensure_ascii=False),operation_id))
            return result
        except RPCError as error:
            with self.state() as db:
                saved=db.execute('SELECT context_json FROM audit WHERE id=?',(operation_id,)).fetchone()
                state=json.loads(saved['context_json'])
                status='partial' if state.get('mutation_started') or state.get('planned_revision') else 'failed'
                db.execute('UPDATE audit SET status=?,updated_at=?,error_code=? WHERE id=?',(status,int(time.time()),error.code,operation_id))
            raise
        except (approval.ApprovalError,ValueError,OSError,sqlite3.Error):
            with self.state() as db:db.execute("UPDATE audit SET status='partial',updated_at=?,error_code='operation_failed' WHERE id=?",(int(time.time()),operation_id))
            raise RPCError('operation_failed',409) from None
    def save_context(self,operation_id,context):
        with self.state() as db:db.execute('UPDATE audit SET context_json=?,updated_at=? WHERE id=?',(json.dumps(context),int(time.time()),operation_id))
    def execute_mutation(self,action,params,actor,users,directory,request,operation_id,context):
        if action=='approve':
            row=approval.load_record(self.settings.registration,params['registration_id'])
            if not valid_hash(row.get('password_hash')):raise RPCError('legacy_application',409)
            # Match the approval layer's supported-number contract before any
            # mutation is marked as started. This is a permanent validation
            # failure, not a partially provisioned identity or retryable outage.
            if not re.fullmatch(r'1[3-9][0-9]{9}',row['phone']):
                raise RPCError('unsupported_phone',409)
            context['mutation_started']=True;self.save_context(operation_id,context)
            return approval.approve(self.settings.registration,self.settings.directory,params['registration_id'],
                approved_by=actor['username'],confirmed_phone=params['confirmed_phone'],username=params.get('username') or None,note=params.get('note',''),
                passwords=self.settings.passwords,_lock_held=True,
                provisioner=lambda payload:self.native('provision',request['actor_phid'],request['actor_principal'],registration=payload))
        if action=='reject':
            context['mutation_started']=True;self.save_context(operation_id,context)
            return approval.reject(self.settings.registration,params['registration_id'],approved_by=actor['username'],reason=params['reason'],_lock_held=True)
        if action=='set_user_status' and params['user_id']==actor['user_id']:
            raise RPCError('self_disable',409)
        if action=='set_user_status' and params['status']=='inactive' and context.get('entry_only'):
            # A retry keeps its original narrow scope even if an independent
            # repair has since made a native mapping usable.
            own=self.isolated_entry(params['user_id'],users,directory)
            if not own:raise RPCError('identity_conflict',409)
            self.revoke_entry(params['user_id'],operation_id,context)
            return {'user_id':params['user_id'],'status':'inactive','entry_only':True,
                    'native_state_known':False,'reauth_required':False}
        try:
            native,own=self.target(params['user_id'],users,directory)
        except RPCError as error:
            if action!='set_user_status' or params['status']!='inactive' or error.code!='identity_conflict':
                raise
            own=self.isolated_entry(params['user_id'],users,directory)
            if not own:raise RPCError('identity_conflict',409)
            if own.get('status')!='active' and not context.get('entry_only'):
                raise RPCError('account_inactive',409)
            context.update(mutation_started=True,entry_only=True)
            self.save_context(operation_id,context)
            self.revoke_entry(params['user_id'],operation_id,context)
            return {'user_id':params['user_id'],'status':'inactive','entry_only':True,
                    'native_state_known':False,'reauth_required':False}
        if action=='set_password':
            if native['is_disabled'] or own.get('status')!='active':raise RPCError('account_inactive',409)
            original,store=load_store(self.settings.passwords)
            entry=store['users'].get(params['user_id'])
            current=entry.get('revision') if entry else None
            if not context:
                context={'original_revision':current,'planned_revision':uuid.uuid4().hex}
                self.save_context(operation_id,context)
            if current != context['planned_revision']:
                if current != context['original_revision']:raise RPCError('operation_superseded',409)
                encoded=hash_password(params['password'])
                store['users'][params['user_id']]={'password_hash':encoded,'revision':context['planned_revision']}
                atomic_store_write(self.settings.passwords,original,store)
            return {'user_id':params['user_id'],'username':native['username'],'password_set':True,
                    'reauth_required':native['phorge_phid']==actor['phorge_phid']}
        inactive=params['status']=='inactive'
        if native['phorge_phid']==actor['phorge_phid']:raise RPCError('self_disable',409)
        if inactive and native['is_admin']:
            available=[u for u in users if u.get('is_admin') and u.get('is_approved') and not u.get('is_disabled')
                and not u.get('is_system_agent') and not u.get('is_mailing_list')
                and (self.bound(u,directory,users) or {}).get('status')=='active']
            if len(available)<=1:raise RPCError('last_admin',409)
        context['mutation_started']=True;self.save_context(operation_id,context)
        if inactive:
            self.revoke_entry(params['user_id'],operation_id,context)
        result=self.native('set_disabled',request['actor_phid'],request['actor_principal'],
            phorge_phid=native['phorge_phid'],user_id=params['user_id'],disabled=inactive)
        if (result.get('user_id')!=params['user_id'] or result.get('phorge_phid')!=native['phorge_phid'] or result.get('is_disabled') is not inactive):
            raise RPCError('identity_conflict',409)
        if not inactive:
            raw,rows=approval.load_directory(self.settings.directory)
            for row in rows:
                if row['user_id']==params['user_id']:row['status']='active'
            if own.get('status')!='active':approval.atomic_directory_write(self.settings.directory,raw,rows)
        return {'user_id':params['user_id'],'status':params['status'],'is_disabled':inactive,
                'entry_only':False,'native_state_known':True,'reauth_required':False}

    def revoke_entry(self,principal,operation_id,context):
        raw,rows=approval.load_directory(self.settings.directory)
        matches=[row for row in rows if row['user_id']==principal]
        if len(matches)!=1:raise RPCError('identity_conflict',409)
        if matches[0].get('status')!='inactive':
            matches[0]['status']='inactive'
            approval.atomic_directory_write(self.settings.directory,raw,rows)
        original,store=load_store(self.settings.passwords)
        entry=store['users'].get(principal)
        if entry and not context.get('revision_rotated'):
            entry['revision']=uuid.uuid4().hex
            atomic_store_write(self.settings.passwords,original,store)
            context['revision_rotated']=True;self.save_context(operation_id,context)


def handler_for(application):
    class Handler(BaseHTTPRequestHandler):
        server_version='Maintenance';sys_version=''
        def log_message(self,*args): pass
        def setup(self):
            super().setup();self.connection.settimeout(10)
        def send_json(self,status,payload):
            raw=json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode()
            self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8')
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Length',str(len(raw)));self.send_header('Connection','close');self.end_headers()
            self.wfile.write(raw);self.close_connection=True
        def do_GET(self):
            if self.path=='/healthz':self.send_json(200,{'ok':True})
            else:self.send_json(404,{'ok':False})
        def do_POST(self):
            try:
                if self.path!='/rpc':self.send_json(404,{'ok':False});return
                if self.client_address[0] != application.settings.client_ip:
                    raise RPCError('unauthorized',403)
                if self.headers.get('Transfer-Encoding') or self.headers.get('Origin'):
                    raise RPCError('invalid_request')
                for name in ('Content-Length','Content-Type','X-Maintenance-Timestamp','X-Maintenance-Nonce','X-Maintenance-Signature'):
                    if len(self.headers.get_all(name,[]))!=1:raise RPCError('invalid_request')
                length=self.headers['Content-Length']
                if not re.fullmatch(r'[1-9][0-9]{0,5}',length):raise RPCError('invalid_request')
                if int(length)>MAX_BODY:raise RPCError('invalid_request',413)
                if self.headers['Content-Type'].split(';',1)[0].strip().lower()!='application/json':raise RPCError('invalid_request',415)
                raw=self.rfile.read(int(length))
                if len(raw)!=int(length):raise RPCError('invalid_request')
                application.authenticate(raw,self.headers['X-Maintenance-Timestamp'],self.headers['X-Maintenance-Nonce'],self.headers['X-Maintenance-Signature'])
                result=application.handle(strict_json(raw))
                self.send_json(200,{'ok':True,'data':result})
            except RPCError as error:self.send_json(error.status,{'ok':False,'error':{'code':error.code,'message':MESSAGES[error.code]}})
            except (OSError,ValueError,sqlite3.Error):self.send_json(503,{'ok':False,'error':{'code':'storage_unavailable','message':MESSAGES['storage_unavailable']}})
            except Exception:self.send_json(503,{'ok':False,'error':{'code':'operation_failed','message':MESSAGES['operation_failed']}})
    return Handler


def load_secret(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)&0o077:
            raise ValueError('Private maintenance signing key permissions are invalid.')
        value=stream.read(33)
    if len(value)!=32:raise ValueError('Private maintenance signing key length is invalid.')
    return value

def serve(application,server=None):
    """Install explicit PID 1 termination handlers and drain the active request."""
    server=server or HTTPServer((application.settings.bind_host,application.settings.port),handler_for(application))
    previous={}
    def stop(signum,frame):
        if application.stop_requested.is_set():return
        application.stop_requested.set()
        # shutdown() waits for serve_forever(), so it must not run inside this
        # main-thread signal callback. The current request is allowed to finish.
        threading.Thread(target=server.shutdown,daemon=True,name='maintenance-stop').start()
    for signum in (signal.SIGTERM,signal.SIGINT):
        previous[signum]=signal.signal(signum,stop)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
        for signum,handler in previous.items():signal.signal(signum,handler)

if __name__=='__main__':
    os.umask(0o077)
    secret=load_secret(Path('/run/secrets/maintenance.key'))
    app=Application(Settings(ROOT,secret,int(os.environ.get('PORT','8086')),
        os.environ.get('MAINTENANCE_BIND_HOST','172.30.20.3'),
        os.environ.get('MAINTENANCE_CLIENT_IP','172.30.20.2')))
    serve(app)
