#!/usr/bin/env python3
"""Generate local-only settings and secrets once, never overwrite existing keys."""
import json
import os
from pathlib import Path
import secrets
import subprocess

ROOT = Path(__file__).resolve().parent.parent
os.umask(0o077)
env_path = ROOT / '.env'
settings = {}
if env_path.exists():
    settings = dict(line.split('=', 1) for line in env_path.read_text().splitlines()
                    if line and not line.startswith('#') and '=' in line)
defaults = {
    'COMPOSE_PROJECT_NAME': 'team-management',
    'PHORGE_BASE_URI': 'https://pm.localhost:8443/',
    'PHORGE_HOST': 'pm.localhost',
    'AUTH_HOST': 'auth.localhost:8443',
    'AUTH_ROUTER_HOST': 'auth.localhost',
    'CALLBACK_ALLOWED_HOSTS': 'pm.localhost:8443',
    'PUBLIC_HTTPS_PORT': '8443',
    'PHORGE_TIMEZONE': 'Asia/Shanghai',
    'MYSQL_IMAGE': 'mysql@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b',
    'TRAEFIK_IMAGE': 'traefik:v3.7.16@sha256:c8a121e4bb1347e8fd52657fab12f2cb70b68f8a018895e2068f92c9e519b9c2',
}
for key in ('MYSQL_ROOT_PASSWORD', 'MYSQL_PASSWORD',
            *('GORGE_' + role + '_TOKEN' for role in
              ('RENDER', 'CONDUIT', 'FILE', 'WEBHOOK', 'TASKQUEUE', 'WORKER', 'DB')),
            *('GORGE_' + role + '_MYSQL_PASSWORD' for role in
              ('QUEUE', 'FILE', 'FEED', 'WEBHOOK', 'DB'))):
    defaults[key] = secrets.token_hex(32)
for key, value in defaults.items():
    settings.setdefault(key, value)
env_path.write_text(''.join(f'{key}={value}\n' for key, value in settings.items()))
env_path.chmod(0o600)
tls = ROOT / 'config/tls'
tls.mkdir(parents=True, exist_ok=True)
if not (tls / 'localhost.crt').exists():
    subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:3072',
                    '-sha256', '-days', '365', '-keyout', str(tls/'localhost.key'),
                    '-out', str(tls/'localhost.crt'), '-subj', '/CN=team-management-local',
                    '-addext', 'subjectAltName=DNS:pm.localhost,DNS:auth.localhost,DNS:localhost,IP:127.0.0.1'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print('Local settings and TLS certificate initialized; existing secrets preserved.')
