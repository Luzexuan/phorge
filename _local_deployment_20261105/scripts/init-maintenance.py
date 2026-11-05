#!/usr/bin/env python3
"""Prepare private web-maintenance access without changing any user or password."""
import fcntl
import os
from pathlib import Path
import secrets
import stat

ROOT = Path(__file__).resolve().parents[1]


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit('Maintenance private files must be regular files without links.')
    return info


def private_directory(path, owner):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise SystemExit('Maintenance private paths must be real directories.')
    path.chmod(0o700)
    os.chown(path, owner, owner)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run deployment initialization as root.')
    os.umask(0o077)
    database = ROOT/'state/registration/registrations.sqlite3'
    if not database.is_file():
        raise SystemExit('Initialize registration storage before maintenance.')
    lock = database.with_name('approval.lock')
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        regular(lock)
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 10001, 10001)
        keys = ROOT/'config/maintenance/keys'
        private_directory(keys, 0)
        candidates = [keys/'service.key', keys/'php.key']
        existing = []
        for path in candidates:
            if os.path.lexists(path):
                regular(path)
                value = path.read_bytes()
                if len(value) != 32:
                    raise SystemExit('Invalid existing maintenance key; preserved for review.')
                existing.append(value)
        if existing and any(value != existing[0] for value in existing):
            raise SystemExit('Maintenance key copies differ; refusing to rotate them.')
        value = existing[0] if existing else secrets.token_bytes(32)
        for path, owner in zip(candidates, (10001, 33)):
            if not path.exists():
                with path.open('xb') as output:
                    output.write(value)
                    output.flush()
                    os.fsync(output.fileno())
            path.chmod(0o400)
            os.chown(path, owner, owner)
        private_directory(ROOT/'state/maintenance', 10001)
        directory = ROOT/'config/warden'
        if not stat.S_ISDIR(directory.lstat().st_mode):
            raise SystemExit('Warden directory must not be a symlink.')
        regular(directory/'users.json')
        os.chown(directory, 10001, 10001)
        directory.chmod(0o755)
        os.chown(directory/'users.json', 10001, 10001)
        # Directory readers remain read-only mounted in other services.
        (directory/'users.json').chmod(0o644)
        for item in (ROOT/'config/passwords', database.parent):
            if not stat.S_ISDIR(item.lstat().st_mode):
                raise SystemExit('Private identity state directory is invalid.')
        print('Private maintenance keys, shared lock and state permissions ready. No user changed.')
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


if __name__ == '__main__':
    main()
