#!/usr/bin/env python3
"""Root-only registration review; no OTP or external message is sent."""
import argparse
import base64
import contextlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from password_store import load_store, publish_initial_password
from credential_hashes import valid_hash

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('team_registration_server', ROOT/'config/registration/server.py')
registrar = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = registrar
spec.loader.exec_module(registrar)
RESERVED = {'admin','administrator','root','siteadmin','system','phabricator','phorge','test_admin'}

class ApprovalError(Exception):
    pass

@contextlib.contextmanager
def database_connection(database):
    """Keep registrar-owned SQLite/WAL writable while a root operator connects."""
    database = Path(database)
    owner = database.lstat()
    if not stat.S_ISREG(owner.st_mode):
        raise ApprovalError('Registration database must be a regular file, not a symlink.')
    for suffix in ('-wal','-shm'):
        sidecar = Path(str(database)+suffix)
        if os.path.lexists(sidecar) and not stat.S_ISREG(sidecar.lstat().st_mode):
            raise ApprovalError('SQLite sidecar must be a regular file, not a symlink.')
    shared = os.geteuid() == 0 and owner.st_uid != 0
    old_group = os.getegid()
    old_mask = None
    connection = None
    try:
        if shared:
            # The enclosing directory remains 0700. Only its existing private
            # owner/group gain access; SQLite copies DB mode to new WAL/SHM.
            os.setegid(owner.st_gid)
            old_mask = os.umask(0o007)
            database.chmod(0o660)
            for suffix in ('-wal','-shm'):
                sidecar = Path(str(database)+suffix)
                if sidecar.exists() and stat.S_ISREG(sidecar.lstat().st_mode):
                    os.chown(sidecar,owner.st_uid,owner.st_gid)
                    sidecar.chmod(0o660)
        connection = registrar.connect_db(database)
        yield connection
    finally:
        try:
            if connection is not None:
                connection.close()
            if shared:
                for suffix in ('','-wal','-shm'):
                    item = Path(str(database)+suffix)
                    try:
                        if stat.S_ISREG(item.lstat().st_mode):
                            os.chown(item,owner.st_uid,owner.st_gid)
                            item.chmod(0o600)
                    except FileNotFoundError:
                        # The web process may checkpoint/delete sidecars while
                        # this connection is closing. Absence needs no repair.
                        pass
        finally:
            if shared:
                os.setegid(old_group)
                if old_mask is not None:
                    os.umask(old_mask)

@contextlib.contextmanager
def approval_lock(database):
    lock = Path(database).with_name('approval.lock')
    lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(lock, os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    try:
        # The optional private maintenance container shares this lock as UID
        # 10001. Plain CLI-only deployments retain the original root ownership.
        deployment_root = Path(database).resolve().parents[2]
        if os.geteuid() == 0 and (deployment_root/'config/maintenance/keys/service.key').is_file():
            os.fchown(descriptor, 10001, 10001)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

def load_record(database, registration_id):
    with database_connection(database) as connection:
        row = connection.execute('SELECT * FROM registrations WHERE registration_id=?',
                                 (registration_id,)).fetchone()
    if row is None:
        raise ApprovalError('Registration does not exist.')
    return dict(row)

def validate_record(row, confirmed_phone, username=None):
    try:
        identifier = str(uuid.UUID(row['registration_id'], version=4))
        valid = (identifier == row['registration_id'] and row['user_id'] == 'reg-'+identifier
                 and registrar.normalize_phone(row['phone']) == row['phone']
                 and registrar.normalize_email(row['email']) == row['email']
                 and registrar.validate_name(row['name']) == row['name'])
    except (KeyError, ValueError, TypeError):
        raise ApprovalError('Registration identity fields are invalid.') from None
    if not valid or not re.fullmatch(r'1[3-9][0-9]{9}', row['phone']):
        raise ApprovalError('Only a complete registration with a supported mainland phone may be approved.')
    try:
        confirmed = registrar.normalize_phone(confirmed_phone)
    except ValueError:
        raise ApprovalError('The operator-confirmed phone is invalid.') from None
    if confirmed != row['phone']:
        raise ApprovalError('The operator-reviewed phone does not match the application.')
    if len(row['email']) > 128 or not re.fullmatch(r'[a-z0-9_+.!-]+@[a-z0-9_+:.-]+', row['email']):
        raise ApprovalError('Email is not supported by the pinned Phorge version.')
    if any(row.get(key) is not None for key in ('org_unit_id','manager_user_id','position')):
        raise ApprovalError('Organization placeholders must be empty; approval grants no team/project membership.')
    chosen = username or row.get('phorge_username') or 'reg_'+identifier.replace('-','')
    if (chosen.casefold() in RESERVED or not re.fullmatch(r'[a-z0-9._-]{2,63}[a-z0-9_-]', chosen)
            or (row.get('phorge_username') and chosen != row['phorge_username'])):
        raise ApprovalError('Username is reserved, invalid, or conflicts with an earlier approval attempt.')
    return chosen

def ensure_delivery_mode(row, acceptance_only, root=ROOT):
    encoded = row.get('password_hash')
    if encoded is not None:
        if not valid_hash(encoded):
            raise ApprovalError('Registration password hash is invalid; no credential or identity was published.')
        return
    enabled = (root/'.dingtalk-enabled').is_file()
    if acceptance_only:
        if not row['email'].endswith('@acceptance.test') or enabled:
            raise ApprovalError('Acceptance approval requires an acceptance.test identity with live DingTalk disabled.')
        return
    if not enabled:
        raise ApprovalError('This legacy application has no password. Configured DingTalk and a confirmed recipient are required; otherwise submit a new password registration.')
    env = root/'.env.dingtalk'
    values = {}
    if env.is_file():
        for line in env.read_text().splitlines():
            key, separator, value = line.partition('=')
            if separator and not key.startswith('#'):
                values[key] = value.strip().strip('\"\'')
    if any(not values.get(key) for key in ('DINGTALK_APP_KEY','DINGTALK_APP_SECRET','DINGTALK_AGENT_ID')):
        raise ApprovalError('DingTalk application configuration is incomplete.')

def load_directory(path):
    raw = Path(path).read_bytes()
    try:
        rows = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ApprovalError('Warden directory is invalid; no changes made.') from None
    if not isinstance(rows,list) or any(not isinstance(row,dict) or not row.get('user_id') for row in rows):
        raise ApprovalError('Warden directory must contain named identity records.')
    return raw, rows

def directory_entry(row):
    return {'user_id':row['user_id'], 'phone':row['phone'], 'mail':row['email'],
            'name':row['name'], 'status':'active', 'scope':[], 'role':'user'}

def check_directory(rows, row, username):
    expected = directory_entry(row)
    own = None
    for entry in rows:
        if entry['user_id'] == row['user_id']:
            if own is not None or any(entry.get(key) != value for key,value in expected.items()):
                raise ApprovalError('Existing Warden principal differs; refusing overwrite or reactivation.')
            own = entry
            continue
        phone = entry.get('phone','')
        try:
            phone = registrar.normalize_phone(phone) if phone else ''
        except ValueError:
            phone = str(phone).strip()
        if (phone == row['phone'] or str(entry.get('mail','')).strip().casefold() == row['email']
                or username.casefold() in {str(entry.get('username','')).casefold(),
                                          str(entry.get('phorge_username','')).casefold()}):
            raise ApprovalError('Phone, email or username is already reserved by another Warden identity.')
    return own

def atomic_directory_write(path, original, rows):
    path = Path(path)
    mode = path.stat().st_mode & 0o777
    descriptor, temporary = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    try:
        with os.fdopen(descriptor,'w') as stream:
            json.dump(rows,stream,ensure_ascii=False,indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary,mode)
        if path.read_bytes() != original:
            raise ApprovalError('Warden directory changed concurrently; rerun approval safely.')
        os.replace(temporary,path)
        directory_fd = os.open(path.parent,os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def provision_phorge(payload):
    source = (ROOT/'scripts/provision-registered-user.php').read_text()
    encoded = base64.b64encode(json.dumps(payload,ensure_ascii=False).encode()).decode()
    script = "<?php\n$registration = json_decode(base64_decode('"+encoded+"'), true);\n"+source.removeprefix('<?php')
    result = subprocess.run([str(ROOT/'scripts/compose.sh'),'exec','-T','phorge','php'],
                            input=script,text=True,capture_output=True,timeout=90)
    if result.returncode:
        # PHP traces can contain registration details. Keep raw stdout/stderr
        # out of the terminal, report and web service.
        raise ApprovalError('Phorge provisioning rejected the input or failed; pending state retained. Review local provider/account constraints.')
    try:
        value = json.loads(result.stdout)
    except ValueError:
        raise ApprovalError('Phorge result was incomplete; rerun to recover the same principal.') from None
    if (value.get('user_id') != payload['user_id'] or value.get('username') != payload['username']
            or not str(value.get('phorge_phid','')).startswith('PHID-USER-') or value.get('is_admin') is not False):
        raise ApprovalError('Unexpected Phorge identity result; Warden was not modified.')
    return value

def approve(database, directory, registration_id, *, approved_by, confirmed_phone,
            username=None, note='', acceptance_only=False, provisioner=provision_phorge,
            delivery_check=ensure_delivery_mode, publisher=atomic_directory_write,
            passwords=ROOT/'config/passwords/users.json', password_publisher=publish_initial_password,
            _lock_held=False):
    if not approved_by or len(approved_by)>64 or len(note)>500:
        raise ApprovalError('An administrator attribution and a short note are required.')
    # The private maintenance service holds this same lock across fresh actor
    # authorization, durable audit intent, mutation and the final audit result.
    with contextlib.nullcontext() if _lock_held else approval_lock(database):
        row = load_record(database,registration_id)
        if row['status'] == 'rejected':
            raise ApprovalError('Rejected applications cannot be approved; submit a new application.')
        chosen = validate_record(row,confirmed_phone,username)
        encoded = row.get('password_hash')
        if encoded is not None and not valid_hash(encoded):
            raise ApprovalError('Registration password hash is invalid.')
        delivery_check(row,acceptance_only)
        if encoded is not None:
            _, credential_store = load_store(passwords)
            if row['status']=='approved' and row['user_id'] not in credential_store['users']:
                raise ApprovalError('Approved credential was removed; use explicit password management, not approval replay.')
        _, rows = load_directory(directory)
        own = check_directory(rows,row,chosen)
        if row['status']=='approved' and own is None:
            raise ApprovalError('Approved identity is missing from Warden; do not silently reactivate it.')
        with database_connection(database) as connection:
            collision = connection.execute('SELECT registration_id FROM registrations WHERE '
                'registration_id != ? AND status IN (\'pending\',\'approved\') AND '
                '(phone=? OR email=? OR phorge_username=?)',
                (registration_id,row['phone'],row['email'],chosen)).fetchone()
            if collision:
                raise ApprovalError('Another live registration already reserves these identity fields.')
            # A durable intent marker prevents a failed/retried transaction from
            # being rejected or reassigned to a different username afterward.
            if row['status'] != 'approved':
                connection.execute('UPDATE registrations SET phorge_username=?,updated_at=? '
                                   'WHERE registration_id=?',(chosen,int(time.time()),registration_id))
        payload = dict(row,username=chosen,approved_by=approved_by,
                       confirmed_phone=row['phone'],acceptance_only=bool(acceptance_only),
                       password_approval=encoded is not None)
        # Credentials are neither needed nor allowed in PHP provisioning input.
        payload.pop('password_hash',None)
        native = provisioner(payload)
        if (native.get('user_id') != row['user_id'] or native.get('username') != chosen or
                not str(native.get('phorge_phid','')).startswith('PHID-USER-') or native.get('is_admin') is not False):
            raise ApprovalError('Provisioner returned a mismatched or privileged identity.')
        if row['status'] != 'approved' and (native.get('email_verified') is not False or
                                           native.get('external_email_verified') is not False):
            raise ApprovalError('New registrations must retain unverified email flags.')
        if row.get('phorge_phid') and row['phorge_phid'] != native['phorge_phid']:
            raise ApprovalError('Previously provisioned user changed; refusing reassignment.')
        if row['status'] != 'approved':
            with database_connection(database) as connection:
                connection.execute('UPDATE registrations SET phorge_phid=?,updated_at=? WHERE registration_id=?',
                                   (native['phorge_phid'],int(time.time()),registration_id))
        # Publish credentials before Warden admits this principal. On recovery,
        # an existing entry is retained, including any later password reset.
        if encoded is not None:
            password_publisher(passwords,row['user_id'],encoded)
        # Refresh after the native transaction so another administrative write
        # cannot be lost, then publish by atomic rename of the directory file.
        original, rows = load_directory(directory)
        own = check_directory(rows,row,chosen)
        if own is None:
            publisher(directory,original,rows+[directory_entry(row)])
        if row['status'] != 'approved':
            now = int(time.time())
            with database_connection(database) as connection:
                connection.execute('BEGIN IMMEDIATE')
                changed = connection.execute('UPDATE registrations SET status=\'approved\',approved_at=?, '
                    'approved_by=?,approval_note=?,updated_at=? WHERE registration_id=? AND status=\'pending\' '
                    'AND user_id=? AND phone=? AND email=? AND name=?',
                    (now,approved_by,note,now,registration_id,row['user_id'],row['phone'],row['email'],row['name']))
                if changed.rowcount != 1:
                    connection.rollback()
                    raise ApprovalError('Registration changed during approval; directory published, operator recovery required.')
                connection.commit()
        return {'registration_id':registration_id,'status':'approved','user_id':row['user_id'],
                'phorge_username':chosen,'phorge_phid':native['phorge_phid'],
                'created':bool(native.get('created')),'email_verified':bool(native.get('email_verified')),
                'organization_assigned':False,'acceptance_only':bool(acceptance_only),
                'password_available':encoded is not None}

def reject(database, registration_id, *, approved_by, reason, _lock_held=False):
    if not approved_by or not reason.strip() or len(reason)>500:
        raise ApprovalError('An administrator attribution and rejection reason are required.')
    with contextlib.nullcontext() if _lock_held else approval_lock(database):
        row = load_record(database,registration_id)
        if row['status']=='approved' or row.get('phorge_username') or row.get('phorge_phid'):
            raise ApprovalError('Approved or partially provisioned identities must be resolved, not rejected.')
        if row['status']!='rejected':
            with database_connection(database) as connection:
                connection.execute('UPDATE registrations SET status=\'rejected\',approved_by=?,approval_note=?, '
                    'updated_at=? WHERE registration_id=? AND status=\'pending\'',
                    (approved_by,reason,int(time.time()),registration_id))
        return {'registration_id':registration_id,'status':'rejected'}

def main():
    if os.geteuid()!=0:
        raise SystemExit('Run this approval command as the local root operator.')
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',type=Path,default=ROOT/'state/registration/registrations.sqlite3')
    parser.add_argument('--directory',type=Path,default=ROOT/'config/warden/users.json')
    parser.add_argument('--passwords',type=Path,default=ROOT/'config/passwords/users.json')
    commands = parser.add_subparsers(dest='command',required=True)
    listing = commands.add_parser('list')
    listing.add_argument('--status',choices=['pending','approved','rejected','all'],default='pending')
    approval = commands.add_parser('approve')
    approval.add_argument('registration_id')
    approval.add_argument('--by',required=True)
    approval.add_argument('--confirmed-phone',required=True,help='Registration phone reviewed by the administrator; not proof of DingTalk ownership')
    approval.add_argument('--username')
    approval.add_argument('--note',default='')
    approval.add_argument('--acceptance-only',action='store_true')
    rejection = commands.add_parser('reject')
    rejection.add_argument('registration_id')
    rejection.add_argument('--by',required=True)
    rejection.add_argument('--reason',required=True)
    args = parser.parse_args()
    if not args.database.is_file():
        parser.error('Registration database does not exist; initialize the registration service first.')
    try:
        if args.command=='list':
            # A read connection can still checkpoint WAL on close. Coordinate
            # it with operator mutations and the backup's same serial lock.
            with approval_lock(args.database):
                with database_connection(args.database) as connection:
                    where = '' if args.status=='all' else ' WHERE status=?'
                    rows = connection.execute('SELECT registration_id,user_id,phone,email,name,status,created_at,'
                        'phorge_username,phorge_phid,org_unit_id,manager_user_id,position FROM registrations'+where+
                        ' ORDER BY created_at', () if args.status=='all' else (args.status,)).fetchall()
                    result = [dict(row) for row in rows]
        elif args.command=='reject':
            result = reject(args.database,args.registration_id,approved_by=args.by,reason=args.reason)
        else:
            result = approve(args.database,args.directory,args.registration_id,approved_by=args.by,
                confirmed_phone=args.confirmed_phone,username=args.username,note=args.note,
                acceptance_only=args.acceptance_only,passwords=args.passwords)
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (ApprovalError,ValueError,OSError,sqlite3.Error,subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from None

if __name__=='__main__':
    main()
