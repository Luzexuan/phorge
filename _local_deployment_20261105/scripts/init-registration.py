#!/usr/bin/env python3
"""Initialize durable private pending registration storage, without granting access."""
import importlib.util
import os
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
os.umask(0o077)
spec = importlib.util.spec_from_file_location('registration_server', ROOT/'config/registration/server.py')
server = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = server
spec.loader.exec_module(server)
storage = ROOT/'state/registration'
storage.mkdir(parents=True, exist_ok=True, mode=0o700)
server.initialize_db(storage/'registrations.sqlite3')
secret = ROOT/'config/registration/csrf.key'
if not secret.exists():
    with secret.open('xb') as output:
        output.write(secrets.token_bytes(32))
if len(secret.read_bytes()) < 32:
    raise SystemExit('Existing registration CSRF key is too short; preserved for investigation.')
secret.chmod(0o400)
os.chown(secret, 10001, 10001)
storage.chmod(0o700)
os.chown(storage, 10001, 10001)
for item in storage.iterdir():
    if item.name == 'approval.lock':
        # Shared by approval, private maintenance service and backup.
        if item.is_symlink() or not item.is_file():
            raise SystemExit('Invalid approval lock; preserved for investigation.')
        item.chmod(0o600)
        owner = 10001 if (ROOT/'config/maintenance/keys/service.key').is_file() else 0
        os.chown(item, owner, owner)
        continue
    if item.is_file():
        item.chmod(0o600)
        os.chown(item, 10001, 10001)
environment = ROOT/'.env.registration'
if not environment.exists():
    environment.write_text('REGISTRATION_ORIGIN=https://45.77.36.106\n'
                           'REGISTRATION_TRUSTED_PROXY=172.30.10.2\n')
environment.chmod(0o600)
print('Private registration storage and CSRF key initialized. No account approved or service started.')
