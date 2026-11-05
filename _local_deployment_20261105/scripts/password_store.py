"""Private credential-file operations. Callers hold the shared approval lock."""
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'config/registration'))
from credential_hashes import valid_hash


class PasswordStoreError(ValueError):
    pass


def _check_directory(path):
    path = Path(path)
    if not path.exists():
        path.mkdir(mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise PasswordStoreError('Password directory must be a real directory, not a symlink.')
    if os.geteuid() == 0:
        os.chown(path, 10001, 10001)
    path.chmod(0o700)


def _read_regular(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PasswordStoreError('Password store must be a regular file with no hard links.')
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise PasswordStoreError('Password store must have mode 0600.')
        if os.geteuid() == 0 and (info.st_uid, info.st_gid) != (10001, 10001):
            raise PasswordStoreError('Password store must be owned by UID/GID 10001.')
        return stream.read()


def validate_store(value):
    if (not isinstance(value, dict) or set(value) != {'version', 'users'} or
            type(value.get('version')) is not int or value['version'] != 1 or
            not isinstance(value.get('users'), dict)):
        raise PasswordStoreError('Password store format is invalid.')
    for principal, entry in value['users'].items():
        if (not isinstance(principal, str) or not principal or len(principal) > 255 or
                any(ord(char) < 32 or ord(char) == 127 for char in principal) or
                not isinstance(entry, dict) or set(entry) != {'password_hash', 'revision'} or
                not valid_hash(entry.get('password_hash')) or
                not isinstance(entry.get('revision'), str) or
                re.fullmatch(r'[0-9a-f]{32}', entry['revision']) is None or
                uuid.UUID(hex=entry['revision']).version != 4):
            raise PasswordStoreError('Password store contains an invalid credential record.')
    return value


def load_store(path):
    path = Path(path)
    _check_directory(path.parent)
    raw = _read_regular(path)
    if raw is None:
        return None, {'version': 1, 'users': {}}
    try:
        # Duplicate keys must not have different meanings in Python and Go.
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise PasswordStoreError('Password store contains duplicate keys.')
                value[key] = item
            return value
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise PasswordStoreError('Password store cannot be decoded safely.') from None
    return raw, validate_store(value)


def atomic_store_write(path, original, value):
    path = Path(path)
    validate_store(value)
    _check_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            if os.geteuid() == 0:
                os.fchown(stream.fileno(), 10001, 10001)
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        if _read_regular(path) != original:
            raise PasswordStoreError('Password store changed concurrently; retry without overwriting it.')
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def initialize_store(path):
    original, value = load_store(path)
    if original is None:
        atomic_store_write(path, original, value)


def publish_initial_password(path, principal, encoded):
    """Never restore an old registration password over a later operator reset."""
    if not valid_hash(encoded):
        raise PasswordStoreError('Registration password hash is missing or invalid.')
    original, value = load_store(path)
    if principal in value['users']:
        return False
    value['users'][principal] = {'password_hash': encoded, 'revision': uuid.uuid4().hex}
    atomic_store_write(path, original, value)
    return True
