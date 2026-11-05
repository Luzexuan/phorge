#!/usr/bin/env python3
"""Read-only maintenance backup capture checks; never starts/stops containers.

Usage: python3 tests/maintenance/check_backup.py backups/TIMESTAMP
Only aggregate counts and boolean results are written to the acceptance report.
SQL import/recovery remains the responsibility of scripts/restore-check.py.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / 'state/acceptance/maintenance-backup-capture.json'
VOLUMES = ('phorge-conf', 'phorge-files', 'phorge-repo',
           'stargate-redis-data', 'herald-redis-data')
SOURCES = ('compose.maintenance.yaml', 'config/maintenance/service.py',
           'config/maintenance/native.php',
           'config/phorge/extensions/TeamMaintenanceApplication.php',
           'scripts/init-maintenance.py', 'scripts/build-maintenance.sh',
           'scripts/approve-registration.py', 'scripts/password_store.py',
           'scripts/backup.py', 'scripts/compose.sh',
           'docker/maintenance.Dockerfile')
HASH_PATTERN = re.compile(r'scrypt\$32768\$8\$3\$[0-9a-f]{32}\$[0-9a-f]{64}\Z')
AUDIT_COLUMNS = {'id', 'request_id', 'fingerprint', 'created_at', 'updated_at',
                 'actor_phid', 'actor_username', 'action', 'target', 'reason',
                 'status', 'error_code', 'result_json', 'context_json'}
PRIVATE_CONTEXT_KEYS = {'original_revision', 'planned_revision', 'mutation_started',
                        'revision_rotated', 'entry_only'}
FORBIDDEN_KEYS = {'password', 'password_confirm', 'confirm_password', 'password_hash',
                  'raw_request', 'request_body', 'raw_body', 'payload', 'params'}


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def digest_file(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def private_file(path, mode=0o600, owner=None):
    info = path.lstat()
    return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            stat.S_IMODE(info.st_mode) == mode and
            (owner is None or (info.st_uid, info.st_gid) == (owner, owner)))


class Capture:
    def __init__(self, archive):
        self.archive = archive
        self.members = {}
        for member in archive:
            # No extraction is performed, but ambiguous names are still unsafe.
            if member.name in self.members:
                raise ValueError('Duplicate archive member')
            self.members[member.name] = member

    def info(self, name):
        member = self.members[name]
        if not member.isfile() or not 0 <= member.size <= 128 * 1024 * 1024:
            raise ValueError('Unsafe archive member')
        return member

    def read(self, name):
        with self.archive.extractfile(self.info(name)) as stream:
            return stream.read()

    def json(self, name):
        return decode(self.read(name))

    def private(self, name, owner, mode=0o600):
        member = self.info(name)
        return (member.uid, member.gid, member.mode & 0o7777) == (owner, owner, mode)

    def sqlite(self, directory, name):
        # Only exact database/sidecar filenames enter a fresh private directory.
        target = directory / PurePosixPath(name).name
        for suffix in ('', '-wal', '-shm'):
            source = name + suffix
            if source in self.members:
                destination = Path(str(target) + suffix)
                with destination.open('xb') as stream:
                    stream.write(self.read(source))
                destination.chmod(0o600)
        connection = sqlite3.connect(str(target))
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA query_only=ON')
        return connection


def secret_keys_absent(value):
    if isinstance(value, dict):
        return all(key not in FORBIDDEN_KEYS and secret_keys_absent(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return all(secret_keys_absent(item) for item in value)
    return True


def check_backup(directory):
    report = {'verifiedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'checks': [], 'counts': {}, 'passed': False,
              'scope': 'Private archive capture only; no live mutations or SQL restore. '
                       'No PII, passwords, hashes, keys, revisions, or raw audit data emitted.'}

    def check(name, passed):
        report['checks'].append({'name': name, 'passed': bool(passed)})

    try:
        manifest = decode((directory / 'manifest.json').read_bytes())
        info = directory.lstat()
        check('backup_directory_and_sql_private', stat.S_ISDIR(info.st_mode) and
              stat.S_IMODE(info.st_mode) == 0o700 and
              private_file(directory / 'application.sql'))
        check('database_and_volume_inventory', len(manifest['databases']) == 55 and
              manifest['applicationTables'] == 518 and
              set(manifest['volumes']) == {'team-management_' + item for item in VOLUMES})
        required_archives = {'application.sql', 'deployment-private.tar.gz'} | {
            name + '.tar.gz' for name in VOLUMES}
        hashes = manifest['sha256']
        check('all_archive_checksums_match', required_archives <= set(hashes) and all(
            PurePosixPath(name).name == name and private_file(directory / name) and
            digest_file(directory / name) == hashes[name] for name in required_archives))
        report['counts']['databases'] = len(manifest['databases'])
        report['counts']['applicationTables'] = manifest['applicationTables']
        report['counts']['volumes'] = len(manifest['volumes'])
        with tarfile.open(directory / 'deployment-private.tar.gz', 'r:gz') as archive:
            capture = Capture(archive)
            release = capture.json('state/acceptance/release-manifest.json')
            live_release = decode((ROOT / 'state/acceptance/release-manifest.json').read_bytes())
            build = capture.json('state/acceptance/maintenance-build.json')
            check('maintenance_enablement_retained', release.get('maintenanceEnabled') is True and
                  capture.read('.maintenance-enabled') == (ROOT / '.maintenance-enabled').read_bytes())
            config_hashes = release['configurationSHA256']
            check('maintenance_sources_match_manifest_and_current_source', all(
                name in config_hashes and
                hashlib.sha256(capture.read(name)).hexdigest() == config_hashes[name] ==
                digest_file(ROOT / name) for name in SOURCES))
            archived_sources = [name for name in config_hashes if name in capture.members]
            check('all_archived_manifest_sources_match', all(
                hashlib.sha256(capture.read(name)).hexdigest() == config_hashes[name]
                for name in archived_sources))
            report['counts']['manifestSourcesCaptured'] = len(archived_sources)
            service = [row for row in release['services'] if row['service'] == 'maintenance']
            live_service = [row for row in live_release['services'] if row['service'] == 'maintenance']
            phorge = [row for row in release['services'] if row['service'] == 'phorge']
            check('build_provenance_matches_recorded_runtime', len(service) == len(live_service) == len(phorge) == 1 and
                  build['imageID'] == service[0]['imageID'] == live_service[0]['imageID'] and
                  build['image'] == service[0]['image'] and
                  build['phorgeBaseImageID'] == phorge[0]['imageID'] and
                  bool(build['packages']) and all(isinstance(p, str) and p.startswith('python3') for p in build['packages']) and
                  set(build['files']) == {'docker/maintenance.Dockerfile', 'scripts/build-maintenance.sh'} and
                  all(hashlib.sha256(capture.read(name)).hexdigest() == value == config_hashes[name]
                      for name, value in build['files'].items()))
            php_key = 'config/maintenance/keys/php.key'
            service_key = 'config/maintenance/keys/service.key'
            check('maintenance_keys_private_and_equal', capture.private(php_key, 33, 0o400) and
                  capture.private(service_key, 10001, 0o400) and
                  len(capture.read(php_key)) == 32 and capture.read(php_key) == capture.read(service_key))
            check('maintenance_keys_match_current', capture.read(php_key) == (ROOT / php_key).read_bytes() and
                  capture.read(service_key) == (ROOT / service_key).read_bytes())
            check('shared_lock_private_owner_retained',
                  capture.private('state/registration/approval.lock', 10001))
            password_path = 'config/passwords/users.json'
            passwords = capture.json(password_path)
            check('password_store_private_and_current', capture.private(password_path, 10001) and
                  capture.read(password_path) == (ROOT / password_path).read_bytes())
            users = passwords['users']
            check('password_store_has_only_encoded_credentials', set(passwords) == {'version', 'users'} and
                  type(passwords['version']) is int and passwords['version'] == 1 and all(
                      set(entry) == {'password_hash', 'revision'} and
                      HASH_PATTERN.fullmatch(entry['password_hash']) is not None and
                      re.fullmatch(r'[0-9a-f]{32}', entry['revision']) is not None and
                      uuid.UUID(hex=entry['revision']).version == 4 for entry in users.values()))
            report['counts']['publishedCredentials'] = len(users)
            warden = capture.json('config/warden/users.json')
            with tempfile.TemporaryDirectory(prefix='maintenance-capture-') as temporary:
                temporary_path = Path(temporary)
                registration_path = 'state/registration/registrations.sqlite3'
                maintenance_path = 'state/maintenance/maintenance.sqlite3'
                check('sqlite_private_owners_retained', all(capture.private(name, 10001) for name in
                      (registration_path, maintenance_path)))
                registration = capture.sqlite(temporary_path, registration_path)
                maintenance = capture.sqlite(temporary_path, maintenance_path)
                try:
                    check('both_sqlite_integrity_and_foreign_keys', all(
                        db.execute('PRAGMA integrity_check').fetchall()[0][0] == 'ok' and
                        not db.execute('PRAGMA foreign_key_check').fetchall()
                        for db in (registration, maintenance)))
                    registration_columns = {r['name'] for r in registration.execute('PRAGMA table_info(registrations)')}
                    check('registration_contains_hash_but_no_plaintext_credential_fields',
                          'password_hash' in registration_columns and
                          not (registration_columns & (FORBIDDEN_KEYS - {'password_hash'})))
                    empty_org = registration.execute('SELECT COUNT(*) FROM org_units').fetchone()[0]
                    assigned_org = registration.execute('SELECT COUNT(*) FROM registrations WHERE org_unit_id IS NOT NULL OR manager_user_id IS NOT NULL OR position IS NOT NULL').fetchone()[0]
                    check('organization_placeholders_remain_empty', empty_org == assigned_org == 0)
                    report['counts']['organizationUnits'] = empty_org
                    rows = registration.execute('SELECT user_id,email,status,password_hash FROM registrations').fetchall()
                    synthetic = [row for row in rows if row['status'] == 'approved' and
                                 row['email'].startswith('maintenance_') and row['email'].endswith('@acceptance.test')]
                    def inactive(row):
                        matches = [entry for entry in warden if entry.get('user_id') == row['user_id']]
                        return len(matches) == 1 and matches[0].get('status') == 'inactive'
                    check('new_approved_maintenance_fixtures_are_inactive', bool(synthetic) and all(inactive(row) for row in synthetic))
                    check('pending_credentials_are_not_published', all(row['user_id'] not in users for row in rows if row['status'] == 'pending'))
                    check('registration_hashes_use_fixed_encoding', all(row['password_hash'] is None or
                          HASH_PATTERN.fullmatch(row['password_hash']) is not None for row in rows))
                    report['counts']['registrations'] = len(rows)
                    report['counts']['approvedMaintenanceFixtures'] = len(synthetic)
                    report['counts']['registrationsWithPasswordHash'] = sum(row['password_hash'] is not None for row in rows)
                    columns = {r['name'] for r in maintenance.execute('PRAGMA table_info(audit)')}
                    check('audit_schema_has_no_plaintext_credential_or_request_fields', columns == AUDIT_COLUMNS)
                    audit = maintenance.execute('SELECT action,status,fingerprint,result_json,context_json FROM audit').fetchall()
                    statuses = ('intent', 'succeeded', 'failed', 'partial')
                    check('audit_has_real_successes_and_known_states', bool(audit) and
                          all(row['status'] in statuses for row in audit) and
                          any(row['status'] == 'succeeded' for row in audit))
                    actions = ('approve', 'reject', 'set_password', 'set_user_status')
                    check('successful_daily_maintenance_actions_captured', all(
                        any(row['action'] == action and row['status'] == 'succeeded' for row in audit) for action in actions))
                    check('audit_private_payloads_have_no_password_or_raw_request_fields', all(
                        re.fullmatch(r'[0-9a-f]{64}', row['fingerprint']) and
                        set(decode(row['context_json'])) <= PRIVATE_CONTEXT_KEYS and
                        secret_keys_absent(decode(row['context_json'])) and
                        (row['result_json'] is None or secret_keys_absent(decode(row['result_json']))) for row in audit))
                    report['counts']['auditRows'] = len(audit)
                    for status in statuses:
                        report['counts']['audit_' + status] = sum(row['status'] == status for row in audit)
                finally:
                    registration.close()
                    maintenance.close()
            check('temporary_sqlite_copies_removed', not temporary_path.exists())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, sqlite3.Error, tarfile.TarError):
        # Never print exception text: it may contain a stored identity or value.
        check('capture_parsed_without_errors', False)
    report['passed'] = all(item['passed'] for item in report['checks'])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backup', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    report = check_backup(args.backup)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    with REPORT.open('w') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    REPORT.chmod(0o600)
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks']),
                      'failedChecks': sum(not item['passed'] for item in report['checks'])}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
