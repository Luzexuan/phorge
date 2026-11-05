#!/usr/bin/env python3
"""Generate a private provider CA and capture directory; preserve existing keys."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TLS = ROOT/'config/testing/tls'
os.umask(0o077)
TLS.mkdir(parents=True, exist_ok=True)
(ROOT/'state/testing-mail').mkdir(mode=0o700, parents=True, exist_ok=True)

def openssl(*args):
    subprocess.run(['openssl', *args], check=True, cwd=TLS,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if not (TLS/'ca.crt').exists():
    openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '365',
            '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=Team acceptance provider CA',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
if not (TLS/'server.crt').exists():
    openssl('req', '-newkey', 'rsa:3072', '-nodes', '-keyout', 'server.key',
            '-out', 'server.csr', '-subj', '/CN=identity-test-mail')
    (TLS/'server.ext').write_text('subjectAltName=DNS:identity-test-mail\n'
                                 'extendedKeyUsage=serverAuth\n'
                                 'keyUsage=critical,digitalSignature,keyEncipherment\n'
                                 'basicConstraints=critical,CA:FALSE\n')
    openssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
            '-CAcreateserial', '-out', 'server.crt', '-days', '365', '-sha256', '-extfile', 'server.ext')
# Public CA certificate must be readable by Herald UID 10001; keys stay root-only.
(TLS/'ca.crt').chmod(0o644)
print('Private test-mail TLS provider initialized. No public mailbox interface exists.')
