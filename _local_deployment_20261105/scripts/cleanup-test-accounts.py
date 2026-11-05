#!/usr/bin/env python3
"""Review or apply a strictly scoped, backed-up acceptance-account cleanup.

Default is dry-run. No password, cookie, token, or real-user PII is emitted.
The operator must stop traefik, registration and maintenance before --apply.
This is a one-time deployment transition, not a daily account-management API.
"""
import argparse
import base64
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PROGRESS = None
sys.path.insert(0, str(ROOT/'scripts'))
from password_store import atomic_store_write, validate_store


def require(condition, message):
    if not condition:
        raise ValueError(message)


def private_json(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077,
            'Review file must be private and regular.')
    return json.loads(path.read_bytes())


def native(plan, apply):
    payload = {'operation':'purge-reviewed-acceptance-users', 'apply':apply,
               'users':[{key:user[key] for key in ('phid','username','principal','emails')}
                        for user in plan['nativeUsers']]}
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    result = subprocess.run([str(ROOT/'scripts/compose.sh'),'exec','-T','phorge',
        'php','/dev/stdin',encoded], input=(ROOT/'scripts/cleanup-test-accounts-native.php').read_bytes(),
        capture_output=True, timeout=180, cwd=ROOT)
    require(result.returncode == 0, 'Native fixture operation failed; raw diagnostics withheld.')
    return json.loads(result.stdout)


def directory_write(path, original, value):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Unsafe directory file.')
    fd, name = tempfile.mkstemp(prefix='.cleanup-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            stream.write((json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode())
            stream.flush();os.fsync(stream.fileno())
        require(path.read_bytes() == original, 'Directory changed concurrently.')
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(name):os.unlink(name)


def main():
    global PROGRESS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, default=ROOT/'state/acceptance/test-account-cleanup/plan.json')
    parser.add_argument('--backup', type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Deployment cleanup requires the root service operator.')
    os.umask(0o077)
    plan = private_json(args.plan)
    users = plan['nativeUsers'];registrations = plan['registrations']
    require(0 < len(users) <= 50, 'Unexpected target count.')
    ids = {u['principal'] for u in users};phids = {u['phid'] for u in users}
    require(len(ids) == len(phids) == len(users) and 'linkerbot-site-admin' not in ids,
            'Ambiguous or protected identity targets.')
    for u in users:
        require(not u['protectedSiteAdmin'] and not u['isSystemAgent'] and not u['isMailingList']
                and u['username'] not in ('siteadmin','admin','root') and bool(u['emails'])
                and all(re.fullmatch(r'[^@]+@acceptance\.test', e) for e in u['emails']),
                'Target is not an isolated synthetic person.')
    for row in users + registrations:
        require(bool(row['evidence']), 'Acceptance evidence is missing.')
        for evidence in row['evidence']:
            source = (ROOT/evidence['file']).resolve()
            require(source.is_relative_to(ROOT/'state') and source.is_file()
                    and hashlib.sha256(source.read_bytes()).hexdigest()==evidence['sha256'],
                    'Acceptance evidence changed; review again.')
    registration_ids = {r['registration_id'] for r in registrations}
    require(len(registration_ids)==len(registrations) and all(
        re.fullmatch(r'[0-9a-f-]{36}', r['registration_id']) and
        r['user_id']=='reg-'+r['registration_id'] and
        re.fullmatch(r'[^@]+@acceptance\.test', r['email']) for r in registrations),
        'Unsafe registration target.')
    directory = ROOT/'config/warden/users.json';password_path = ROOT/'config/passwords/users.json'
    database = ROOT/'state/registration/registrations.sqlite3'
    report = {'startedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'apply':args.apply, 'plannedCounts':plan['counts'], 'passed':False,
              'phase':'preflight'}
    PROGRESS = report
    if args.apply:
        require(args.backup is not None, 'A completed current-data backup is required.')
        backup = args.backup.resolve()
        require(backup.is_relative_to(ROOT/'backups'), 'Backup must be in the deployment backup directory.')
        manifest = json.loads((backup/'manifest.json').read_bytes())
        for name in ('application.sql','deployment-private.tar.gz'):
            require(hashlib.sha256((backup/name).read_bytes()).hexdigest()==manifest['sha256'][name],
                    'Backup checksum mismatch.')
        for service in ('traefik','registration','maintenance'):
            result = subprocess.run(['docker','inspect','--format','{{.State.Running}}',
                'team-management-'+service+'-1'],capture_output=True,text=True,check=True)
            require(result.stdout.strip()=='false', 'Public and account-writing services must be stopped before cleanup.')
        report['backup'] = str(backup.relative_to(ROOT))
    lock = os.open(database.with_name('approval.lock'), os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        directory_raw = directory.read_bytes();warden = json.loads(directory_raw)
        password_raw = password_path.read_bytes();passwords = validate_store(json.loads(password_raw))
        keep_warden = [e for e in warden if e['user_id'] not in ids]
        keep_passwords = {key:value for key,value in passwords['users'].items() if key not in ids}
        require(any(e['user_id']=='linkerbot-site-admin' and e['status']=='active' for e in keep_warden)
                and 'linkerbot-site-admin' in keep_passwords, 'Active administrator credentials must remain intact.')
        for u in users:
            entries = [e for e in warden if e['user_id']==u['principal']]
            require(len(entries)<=1 and all(e['mail'] in u['emails'] for e in entries),
                    'Directory target changed or became ambiguous.')
        if args.apply:
            with tarfile.open(backup/'deployment-private.tar.gz') as archive:
                old_passwords = json.loads(archive.extractfile('config/passwords/users.json').read())
            require(all(old_passwords['users'].get(key)==value for key,value in keep_passwords.items()),
                    'Backup does not capture current protected-user credentials.')
        report['phase'] = 'native-validation'
        report['nativeValidation'] = native(plan, False)
        require(report['nativeValidation']['validated'] is True, 'Native target validation failed.')
        conn = sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True)
        try:
            live = {row[0]:row for row in conn.execute('SELECT registration_id,user_id,email FROM registrations')}
        finally:conn.close()
        for r in registrations:
            require(r['registration_id'] not in live or live[r['registration_id']]==
                    (r['registration_id'],r['user_id'],r['email']), 'Registration target changed.')
        if not args.apply:
            report['passed'] = True
            report['mode'] = 'validated dry-run; no account or directory changes'
            return report
        report['directoryRemovalEpoch'] = time.time()
        report['phase'] = 'remove-directory-and-passwords'
        directory_write(directory, directory_raw, keep_warden)
        atomic_store_write(password_path, password_raw, {'version':1,'users':keep_passwords})
        report['phase'] = 'remove-native-identities'
        report['nativeDeletion'] = native(plan, True)
        require(report['nativeDeletion']['passed'] is True, 'Native cleanup did not complete.')
        spec = importlib.util.spec_from_file_location('cleanup_approval', ROOT/'scripts/approve-registration.py')
        approval = importlib.util.module_from_spec(spec);sys.modules[spec.name]=approval;spec.loader.exec_module(approval)
        report['phase'] = 'remove-exact-registration-rows'
        with approval.database_connection(database) as connection:
            connection.execute('BEGIN IMMEDIATE')
            deleted = 0
            for r in registrations:
                deleted += connection.execute('DELETE FROM registrations WHERE registration_id=? AND user_id=? AND email=?',
                    (r['registration_id'],r['user_id'],r['email'])).rowcount
            connection.commit()
        report['removedRegistrationRows'] = deleted
        require(json.loads(directory.read_bytes()) == keep_warden and
                json.loads(password_path.read_bytes()) == {'version':1,'users':keep_passwords},
                'Unexpected protected credential or directory changes.')
        report['protectedCredentialAndDirectoryEntriesUnchanged'] = True
        report['removedWardenEntries'] = len(warden)-len(keep_warden)
        report['removedPasswordRecords'] = len(passwords['users'])-len(keep_passwords)
        report['remainingNativeUsers'] = report['nativeValidation']['protectedUsers']
        report['earliestPublicReopenEpoch'] = report['directoryRemovalEpoch']+36
        report['redisPolicy'] = plan['redisPolicy']
        report['phase'] = 'completed'
        report['passed'] = True
        return report
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN);os.close(lock)


if __name__=='__main__':
    try:
        report = main();report['completedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        name = 'result.json' if report['apply'] else 'dry-run.json'
        path = ROOT/'state/acceptance/test-account-cleanup'/name
        path.write_text(json.dumps(report,indent=2)+'\n');path.chmod(0o600)
        print(json.dumps({'passed':report['passed'],'apply':report['apply'],'report':str(path.relative_to(ROOT))}))
    except Exception as error:
        # Exception messages are fixed validations; never emit subprocess stderr.
        if PROGRESS is not None and PROGRESS.get('apply'):
            PROGRESS.update(passed=False,errorType=type(error).__name__)
            path = ROOT/'state/acceptance/test-account-cleanup/result.json'
            path.write_text(json.dumps(PROGRESS,indent=2)+'\n');path.chmod(0o600)
        print(json.dumps({'passed':False,'errorType':type(error).__name__,
                          'phase':PROGRESS.get('phase') if PROGRESS else 'plan-validation'}),file=sys.stderr)
        sys.exit(1)
