#!/usr/bin/env python3
"""Set one existing person's entry password; no password is accepted in argv."""
import argparse
import base64
import getpass
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from password_store import atomic_store_write, initialize_store, load_store
from credential_hashes import hash_password, validate_password

spec = importlib.util.spec_from_file_location('password_registration_approval', ROOT/'scripts/approve-registration.py')
approval = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = approval
spec.loader.exec_module(approval)


def lookup_user(username):
    source = (ROOT/'scripts/lookup-password-user.php').read_text()
    encoded = base64.b64encode(username.encode('utf-8')).decode('ascii')
    script = "<?php\n$password_username = base64_decode('"+encoded+"');\n"+source.removeprefix('<?php')
    result = subprocess.run([str(ROOT/'scripts/compose.sh'),'exec','-T','phorge','php'],
                            input=script,text=True,capture_output=True,timeout=90)
    if result.returncode:
        raise approval.ApprovalError('Phorge identity lookup failed: require an approved, enabled person with one existing entry identity.')
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise approval.ApprovalError('Phorge identity lookup returned an invalid response.') from None


def validate_identity(native, username, directory_rows):
    if (not isinstance(native, dict) or native.get('username') != username or
            native.get('is_approved') is not True or native.get('is_disabled') is not False or
            native.get('is_system_agent') is not False or native.get('is_mailing_list') is not False or
            not str(native.get('phorge_phid','')).startswith('PHID-USER-') or
            not isinstance(native.get('user_id'), str) or not native['user_id'] or
            not isinstance(native.get('email'), str) or not native['email']):
        raise approval.ApprovalError('Password management requires the exact approved, enabled Phorge person.')
    matching = [row for row in directory_rows if row.get('user_id') == native['user_id']]
    if (len(matching) != 1 or matching[0].get('status') != 'active' or
            str(matching[0].get('mail','')).casefold() != native['email'].casefold()):
        raise approval.ApprovalError('The stable Phorge principal must already have a matching active Warden email binding.')
    # An ambiguous login alias could otherwise select the wrong stable principal.
    own = matching[0]
    for row in directory_rows:
        if row is own:
            continue
        if (str(row.get('mail','')).casefold() == native['email'].casefold() or
                (own.get('phone') and row.get('phone') == own['phone'])):
            raise approval.ApprovalError('The Warden login identifier is ambiguous.')
    return native['user_id']


def check_output(path, reset):
    path = Path(path)
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) & 0o077 or
            parent.st_uid != os.geteuid()):
        raise approval.ApprovalError('Generated password output requires an existing private operator-owned directory (0700).')
    if os.path.lexists(path):
        info = path.lstat()
        if (not reset or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise approval.ApprovalError('Output exists or is unsafe; use a new private path, or --reset for an existing private regular file.')


def write_output(path, password, reset):
    """Commit a retrievable private password before publishing its hash."""
    path = Path(path)
    check_output(path, reset)
    descriptor, temporary = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(password+'\n')
            stream.flush()
            os.fsync(stream.fileno())
        if reset:
            check_output(path, reset)
            os.replace(temporary, path)
        else:
            # link()+unlink() publishes without ever overwriting an existing path.
            os.link(temporary, path, follow_symlinks=False)
            os.unlink(temporary)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def set_password(database, directory, passwords, username, *, password=None,
                 reset=False, generate=False, output=None, lookup=lookup_user,
                 publisher=atomic_store_write):
    if generate != (output is not None) or (generate and password is not None):
        raise approval.ApprovalError('--generate and --output must be used together, without another password input.')
    if not username or len(username) > 64:
        raise approval.ApprovalError('An existing Phorge username is required.')
    if output is not None:
        check_output(output,reset)
    with approval.approval_lock(database):
        native = lookup(username)
        directory_original, rows = approval.load_directory(directory)
        principal = validate_identity(native,username,rows)
        original, store = load_store(passwords)
        if principal in store['users'] and not reset:
            raise approval.ApprovalError('This principal already has a password; an explicit --reset is required.')
        if generate:
            password = secrets.token_urlsafe(24)
        elif password is None:
            if not sys.stdin.isatty():
                raise approval.ApprovalError('Interactive password entry requires a terminal; use --generate --output for operator automation.')
            password = getpass.getpass('New personal password: ')
            confirm = getpass.getpass('Confirm personal password: ')
            if password != confirm:
                raise approval.ApprovalError('The two password entries differ.')
        validate_password(password)
        encoded = hash_password(password)
        # Respect another operator who does not use our advisory lock.
        if Path(directory).read_bytes() != directory_original:
            raise approval.ApprovalError('Warden changed during password management; no password was published.')
        entry = {'password_hash':encoded,'revision':uuid.uuid4().hex}
        store['users'][principal] = entry
        if output is not None:
            write_output(output,password,reset)
        try:
            publisher(passwords,original,store)
        except Exception:
            # Keep the private output retrievable if a crash/error occurred at
            # the atomic publication boundary; do not print the password.
            raise approval.ApprovalError('Password publication failed. If generated, the private output was retained; verify state before an explicit reset.') from None
        return {'username':username,'user_id':principal,'password_set':True,
                'reset':bool(reset),'generated':bool(generate),
                'output':str(output) if output is not None else None}


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run password management as the local root operator.')
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('username',nargs='?')
    parser.add_argument('--database',type=Path,default=ROOT/'state/registration/registrations.sqlite3')
    parser.add_argument('--directory',type=Path,default=ROOT/'config/warden/users.json')
    parser.add_argument('--passwords',type=Path,default=ROOT/'config/passwords/users.json')
    parser.add_argument('--reset',action='store_true')
    parser.add_argument('--generate',action='store_true')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--initialize-store',action='store_true',help='Create an empty private store; does not set any password')
    args = parser.parse_args()
    try:
        if args.initialize_store:
            if args.username or args.reset or args.generate or args.output:
                parser.error('--initialize-store must be used alone (apart from storage path options).')
            with approval.approval_lock(args.database):
                initialize_store(args.passwords)
            result = {'initialized':True,'password_set':False}
        else:
            result = set_password(args.database,args.directory,args.passwords,args.username,
                reset=args.reset,generate=args.generate,output=args.output)
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (approval.ApprovalError,ValueError,OSError,subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from None


if __name__=='__main__':
    main()
