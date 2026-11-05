"""Personal-password encoding shared by registration and local operator tools.

Only the fixed deployment parameters are accepted. This prevents attacker-chosen
work factors from turning malformed stored input into unbounded resource usage.
"""
import hashlib
import hmac
import re
import secrets
import threading

_FORMAT = re.compile(r'scrypt\$32768\$8\$3\$([0-9a-f]{32})\$([0-9a-f]{64})\Z')
_HASH_SLOTS = threading.BoundedSemaphore(2)


def validate_password(password):
    """Return the unchanged password, or raise a message safe to show in a form."""
    if not isinstance(password, str) or not 15 <= len(password) <= 128:
        raise ValueError('密码必须为 15 至 128 个字符。')
    if '\x00' in password:
        raise ValueError('密码不能包含空字符。')
    try:
        password.encode('utf-8', errors='strict')
    except UnicodeError:
        raise ValueError('密码包含不支持的字符。') from None
    return password


def valid_hash(encoded):
    return isinstance(encoded, str) and _FORMAT.fullmatch(encoded) is not None


def _derive(password, salt):
    with _HASH_SLOTS:
        return hashlib.scrypt(password.encode('utf-8'), salt=salt,
                              n=32768, r=8, p=3, dklen=32, maxmem=64 * 1024 * 1024)


def hash_password(password):
    validate_password(password)
    salt = secrets.token_bytes(16)
    digest = _derive(password, salt)
    return 'scrypt$32768$8$3$' + salt.hex() + '$' + digest.hex()


def verify_password(password, encoded):
    if not valid_hash(encoded):
        return False
    try:
        validate_password(password)
    except ValueError:
        return False
    match = _FORMAT.fullmatch(encoded)
    calculated = _derive(password, bytes.fromhex(match.group(1)))
    return hmac.compare_digest(calculated, bytes.fromhex(match.group(2)))
