#!/usr/bin/env python3
"""Prepare private provider TLS and empty credentials, without starting services."""
import os
from pathlib import Path
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TLS = ROOT/'config/dingtalk/tls'
os.umask(0o077)
TLS.mkdir(parents=True, exist_ok=True)

def openssl(*args):
    subprocess.run(['openssl', *args], check=True, cwd=TLS,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if not (TLS/'ca.crt').exists():
    openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '365',
            '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=Team DingTalk provider CA',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
if not (TLS/'server.crt').exists():
    openssl('req', '-newkey', 'rsa:3072', '-nodes', '-keyout', 'server.key',
            '-out', 'server.csr', '-subj', '/CN=dingtalk-tls')
    (TLS/'server.ext').write_text('subjectAltName=DNS:dingtalk-tls\n'
                                 'extendedKeyUsage=serverAuth\n'
                                 'keyUsage=critical,digitalSignature,keyEncipherment\n'
                                 'basicConstraints=critical,CA:FALSE\n')
    openssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
            '-CAcreateserial', '-out', 'server.crt', '-days', '365', '-sha256', '-extfile', 'server.ext')
bundle=(TLS/'ca.crt').read_bytes()
testCA=ROOT/'config/testing/tls/ca.crt'
if testCA.exists():
    bundle+=testCA.read_bytes()
(TLS/'ca-bundle.crt').write_bytes(bundle)
(TLS/'ca-bundle.crt').chmod(0o644)
(TLS/'ca.crt').chmod(0o644)
envfile=ROOT/'.env.dingtalk'
if not envfile.exists():
    envfile.write_text('DINGTALK_PROVIDER_API_KEY='+secrets.token_hex(32)+'\n'
                       'DINGTALK_APP_KEY=\nDINGTALK_APP_SECRET=\nDINGTALK_AGENT_ID=\n')
envfile.chmod(0o600)
print('DingTalk TLS prepared; credentials remain private. No service started or message sent.')
