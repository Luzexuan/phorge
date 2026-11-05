#!/usr/bin/env python3
"""Verify a backup in a new, network-isolated temporary MySQL container."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time
import re

ROOT = Path(__file__).resolve().parents[1]
if len(sys.argv) != 2:
    raise SystemExit('Usage: scripts/restore-check.py backups/TIMESTAMP')
directory = Path(sys.argv[1]).resolve()
manifest = json.loads((directory/'manifest.json').read_text())
namespace = manifest.get('databaseNamespace', 'phabricator')
if not re.fullmatch(r'[A-Za-z0-9_]{1,44}', namespace):
    raise SystemExit('Invalid database namespace in manifest')
def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()
for name, digest in manifest['sha256'].items():
    if Path(name).name != name:
        raise SystemExit('Invalid archive filename in manifest')
    if sha256(directory/name) != digest:
        raise SystemExit(f'Checksum failed: {name}')
    if name.endswith('.tar.gz'):
        with tarfile.open(directory/name) as archive:
            for member in archive.getmembers():
                if member.isfile():
                    with archive.extractfile(member) as data:
                        while data.read(1024*1024):
                            pass
name = 'team-management-restore-check-' + secrets.token_hex(4)
image = manifest.get('mysqlImage') or json.loads((ROOT/'vendor/phorge/deploy/acceptance/build-lock.json').read_text())['images']['mysql']
with tempfile.NamedTemporaryFile(mode='w', dir=ROOT/'state') as env:
    env.write('MYSQL_ROOT_PASSWORD='+secrets.token_hex(32)+'\n')
    env.flush()
    try:
        subprocess.run(['docker', 'run', '-d', '--name', name, '--network', 'none',
                        '--memory', '1g', '--cpus', '1', '--tmpfs', '/var/lib/mysql:rw,size=1g',
                        '--env-file', env.name, image, '--innodb-buffer-pool-size=128M'],
                       check=True, stdout=subprocess.DEVNULL)
        print('Waiting for isolated restore database.', flush=True)
        ready = False
        for _ in range(90):
            r = subprocess.run(['docker', 'exec', name, 'sh', '-ec',
                 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -NBe "SELECT 1"'],
                 capture_output=True)
            if r.returncode == 0:
                # Wait for final server, not the temporary initialization server.
                log = subprocess.run(['docker', 'logs', name], capture_output=True, text=True)
                if 'MySQL init process done. Ready for start up.' in log.stdout:
                    ready = True
                    break
            time.sleep(2)
        if not ready:
            raise RuntimeError('Isolated database did not become ready')
        with (directory/'application.sql').open('rb') as source:
            subprocess.run(['docker', 'exec', '-i', name, 'sh', '-ec',
                            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot'], stdin=source, check=True)
        prefix = namespace+'_'
        query = f"SELECT COUNT(*) FROM information_schema.TABLES WHERE LEFT(TABLE_SCHEMA,{len(prefix)})='{prefix}'"
        count = subprocess.run(['docker', 'exec', name, 'sh', '-ec',
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -NBe "$1"', 'sh', query],
            check=True, capture_output=True, text=True).stdout.strip()
        if int(count) == 0:
            raise RuntimeError('No application tables restored')
        if 'applicationTables' in manifest and int(count) != manifest['applicationTables']:
            raise RuntimeError('Restored table count differs from backup')
        result = dict(checksums='passed', tar_readability='passed', sql_import='passed',
                      restored_application_tables=int(count),
                      scope='isolated initial-data SQL restore; full business recovery G11 remains pending')
        (directory/'restore-check.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result), flush=True)
    finally:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, check=False)
