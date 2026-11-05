#!/usr/bin/env python3
"""Create persistent local identity secrets; never print or rotate existing ones."""
import os
import importlib.util
from pathlib import Path
import re
import secrets
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.identity"
SECRET_KEYS = (
    "WARDEN_API_KEY", "HERALD_API_KEY", "HERALD_SMTP_API_KEY",
    "STARGATE_REDIS_PASSWORD", "HERALD_REDIS_PASSWORD",
    "SESSION_EXCHANGE_SECRET", "HERALD_IDEMPOTENCY_SECRET", "HERALD_PII_PEPPER",
)


def private_write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            output.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def initialize_personal_passwords(root):
    """Create the empty store once, without rotating any published credential."""
    if os.geteuid() != 0:
        raise SystemExit('Identity initialization requires root to prepare UID 10001 private credentials.')
    scripts = Path(__file__).resolve().parent
    sys.path.insert(0, str(scripts))
    from password_store import initialize_store
    spec = importlib.util.spec_from_file_location('identity_registration_approval',
                                                  scripts/'approve-registration.py')
    approval = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = approval
    spec.loader.exec_module(approval)
    with approval.approval_lock(root/'state/registration/registrations.sqlite3'):
        initialize_store(root/'config/passwords/users.json')


def main():
    values = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                values[key] = value
    for key in SECRET_KEYS:
        if key in values and not re.fullmatch(r"[a-f0-9]{64}", values[key]):
            raise SystemExit(f"Refusing to replace invalid existing {key}; review {ENV_FILE}")
        values.setdefault(key, secrets.token_hex(32))
    private_write(ENV_FILE, "# Generated credentials. Keep private and back up securely.\n" +
                  "".join(f"{key}={value}\n" for key, value in values.items()))
    for name, key in (("stargate", "STARGATE_REDIS_PASSWORD"),
                      ("herald", "HERALD_REDIS_PASSWORD")):
        # Redis UID differs across upstream image variants. Parent config
        # directory is root-only on the host; a file bind is readable by Redis.
        private_write(ROOT / "config" / "redis" / f"{name}.conf",
                      "bind 0.0.0.0\nprotected-mode yes\nport 6379\n"
                      "dir /data\nappendonly yes\nappendfsync everysec\n"
                      "save 900 1\nmaxmemory 96mb\nmaxmemory-policy noeviction\n"
                      f"requirepass {values[key]}\n", mode=0o644)
    os.chmod(ROOT / "config" / "redis", 0o700)
    users = ROOT / "config" / "warden" / "users.json"
    if not users.exists():
        private_write(users, "[]\n", mode=0o644)
    initialize_personal_passwords(ROOT)
    print("Identity secrets, private personal-password store and persistent Redis configs are ready; existing credentials preserved.")


if __name__ == "__main__":
    main()
