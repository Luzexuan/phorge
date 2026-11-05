#!/usr/bin/env python3
"""Prepare native Traefik IP certificates; never starts containers or contacts a CA.

Use --mode staging for the first HTTP-01 validation, then --mode production.
The two modes use separate private ACME stores. Force-recreate Traefik after
changing mode so bind-mounted configuration files are reopened. --mode self-signed
restores the saved pre-ACME dynamic configuration for service-level rollback.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import stat
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
IP = '45.77.36.106'
CA = {
    'staging': 'https://acme-staging-v02.api.letsencrypt.org/directory',
    'production': 'https://acme-v02.api.letsencrypt.org/directory',
}


def regular(path):
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Configuration must be a regular file: '+str(path.relative_to(ROOT)))


def atomic_write(path, data, mode):
    regular(path)
    descriptor, name = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def configure(mode, email):
    if os.geteuid() != 0:
        raise ValueError('Run this service initialization as root.')
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
        raise ValueError('A valid ACME account email is required.')
    directory = ROOT/'config/traefik'
    private = directory/'acme'
    if private.is_symlink():
        raise ValueError('ACME directory cannot be a symlink.')
    private.mkdir(mode=0o700, exist_ok=True)
    if not private.is_dir() or private.stat().st_uid != 0:
        raise ValueError('ACME directory must be owned by root.')
    private.chmod(0o700)
    dynamic_path = directory/'dynamic.yaml'
    backup_path = private/'original-self-signed-dynamic.yaml'
    regular(dynamic_path)
    regular(backup_path)
    dynamic = yaml.safe_load(dynamic_path.read_text())
    if not backup_path.exists():
        if 'defaultCertificate' not in dynamic.get('tls', {}).get('stores', {}).get('default', {}):
            raise ValueError('Original default certificate is missing; refusing to invent rollback state.')
        atomic_write(backup_path, dynamic_path.read_bytes(), 0o600)

    static = {
        'providers': {'docker': {'exposedByDefault': False},
                      'file': {'filename': '/etc/traefik/dynamic.yaml'}},
        'entryPoints': {name: {'address': ':'+str(port), 'http': {'aliasHeadersStrategy': 'reject'}}
                        for name, port in (('web',80),('websecure',443),('ping',8082))},
        'ping': {'entryPoint': 'ping'},
        'api': {'dashboard': False},
        'log': {'level': 'INFO'},
        'accessLog': {'fields': {'headers': {'defaultMode': 'drop'},
                                 'names': {'RequestPath': 'drop'}}},
    }
    if mode == 'self-signed':
        dynamic = yaml.safe_load(backup_path.read_text())
    else:
        store = private/(mode+'.json')
        regular(store)
        if not store.exists():
            atomic_write(store, b'{}\n', 0o600)
        else:
            if store.stat().st_uid != 0:
                raise ValueError('ACME store must be owned by root.')
            store.chmod(0o600)
            if store.stat().st_size:
                # Validate without printing or replacing existing private keys.
                content = json.loads(store.read_bytes())
                if not isinstance(content, dict):
                    raise ValueError('Existing ACME store is not a JSON object.')
        static['certificatesResolvers'] = {'public-ip': {'acme': {
            'email': email,
            'caServer': CA[mode],
            'storage': '/etc/traefik/acme/'+mode+'.json',
            'profile': 'shortlived',
            'disableCommonName': True,
            'certificatesDuration': 160,
            'keyType': 'EC256',
            'httpChallenge': {'entryPoint': 'web'},
        }}}
        dynamic = copy.deepcopy(dynamic)
        tls = dynamic.setdefault('tls', {})
        certificates = [item for item in tls.get('certificates', [])
                        if item.get('certFile') not in (
                            '/etc/traefik/tls/public-ip.crt', '/etc/traefik/tls/localhost.crt')]
        if certificates:
            tls['certificates'] = certificates
        else:
            tls.pop('certificates', None)
        default_store = tls.setdefault('stores', {}).setdefault('default', {})
        default_store.pop('defaultCertificate', None)
        default_store['defaultGeneratedCert'] = {'resolver': 'public-ip', 'domain': {'main': IP}}
        options = tls.setdefault('options', {}).setdefault('default', {})
        if options.get('minVersion') not in ('VersionTLS12','VersionTLS13'):
            options['minVersion'] = 'VersionTLS12'
    atomic_write(directory/'public-static.yaml', yaml.safe_dump(static, sort_keys=False).encode(), 0o644)
    atomic_write(dynamic_path, yaml.safe_dump(dynamic, sort_keys=False, allow_unicode=True).encode(), 0o644)
    print(json.dumps({'prepared': True, 'mode': mode, 'ip': IP,
        'automaticRenewal': mode != 'self-signed',
        'caContacted': False, 'containersChanged': False,
        'apply': 'scripts/compose.sh up -d --no-deps --force-recreate traefik'}))


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('staging','production','self-signed'), required=True)
    parser.add_argument('--email', default='177000177@qq.com')
    arguments = parser.parse_args()
    try:
        configure(arguments.mode, arguments.email)
    except (OSError, ValueError, yaml.YAMLError):
        raise SystemExit('Public TLS initialization failed; verify file ownership, backup state and configuration. No container was restarted.') from None
