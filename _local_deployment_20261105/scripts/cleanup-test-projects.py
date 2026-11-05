#!/usr/bin/env python3
"""Dry-run or apply the exact historical ACC26 project cleanup.

The user authorized deleting test projects and users. The current reviewed
inventory contains nine historical test projects and no surviving test users.
This script never deletes user or task objects, and never selects by prefix.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'state/acceptance/test-project-cleanup'
PLAN = DIRECTORY / 'plan.json'
os.umask(0o077)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def native(plan):
    payload = base64.b64encode(json.dumps(plan, ensure_ascii=False).encode()).decode()
    result = subprocess.run([str(ROOT / 'scripts/compose.sh'), 'exec', '-T',
                             'phorge', 'php', '--', payload],
                            input=(ROOT / 'scripts/cleanup-test-projects-native.php').read_bytes(),
                            capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace').strip())
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--backup', type=Path, help='Completed application backup directory.')
    args = parser.parse_args()
    plan = json.loads(PLAN.read_text())
    require(plan['operation'] == 'purge-reviewed-acceptance-projects', 'Invalid cleanup operation')
    for evidence in plan['evidence']:
        path = (ROOT / evidence['file']).resolve()
        require(path.is_relative_to(ROOT / 'state') and digest(path) == evidence['sha256'],
                'Reviewed evidence changed')
    original = json.loads((ROOT / 'state/permissions-acceptance.json').read_text())['fixtures']
    original_projects = {p['phid']: p for p in original['projects'].values()}
    require(len(plan['projects']) == len(original_projects) == 9, 'Unexpected cleanup target count')
    for row in plan['projects']:
        known = original_projects[row['phid']]
        require(all(row[k] == known[k] for k in ('id', 'phid', 'name')),
                'Target identity does not match original acceptance fixtures')
        require(row['authorPHID'] == original['users']['test_admin']['phid'],
                'Target creator does not match original acceptance administrator')
    plan['apply'] = False
    preflight = native(plan)
    (DIRECTORY / 'preflight.json').write_text(json.dumps(preflight, indent=2) + '\n')
    if not args.apply:
        print(json.dumps(preflight, indent=2))
        return
    require(args.backup is not None, 'A current application SQL backup is required')
    backup = args.backup.resolve()
    require(backup.is_relative_to(ROOT / 'backups'), 'Backup must belong to this deployment')
    backup_manifest = json.loads((backup / 'manifest.json').read_text())
    require(digest(backup / 'application.sql') == backup_manifest['sha256']['application.sql'],
            'Backup checksum mismatch')
    databases = set(backup_manifest['databases'])
    require({'phabricator_project', 'phabricator_maniphest', 'phabricator_user'} <= databases,
            'Backup misses relevant databases')
    plan['apply'] = True
    plan['protectedState'] = preflight['protectedState']
    result = native(plan)
    result['completedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result['backup'] = str(backup.relative_to(ROOT))
    result['planSHA256'] = digest(PLAN)
    (DIRECTORY / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
