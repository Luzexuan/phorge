#!/usr/bin/env python3
"""Read-only capture checks after synthetic-account removal and public TLS.

Usage: python3 tests/maintenance/check_real_users_backup.py backups/TIMESTAMP
No live database is opened, service is changed, or credential value is emitted.
The existing maintenance-era checker remains unchanged for its historical scope.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tarfile
import tempfile
import uuid

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_backup import (Capture, VOLUMES, HASH_PATTERN, AUDIT_COLUMNS,
    PRIVATE_CONTEXT_KEYS, FORBIDDEN_KEYS, decode, digest_file, private_file,
    secret_keys_absent)

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT/'state/acceptance/real-users-backup-capture.json'
TRAEFIK_IMAGE = 'traefik:v3.7.16@sha256:c8a121e4bb1347e8fd52657fab12f2cb70b68f8a018895e2068f92c9e519b9c2'
SOURCES = (
    'compose.gateway.yaml', 'compose.public.yaml', 'compose.maintenance.yaml',
    'config/traefik/public-static.yaml', 'config/traefik/dynamic.yaml',
    'config/phorge/extensions/TeamPrivateDefaults.php',
    'config/phorge/extensions/TeamMaintenanceApplication.php',
    'config/phorge/extensions/TeamEntrySessionGuard.php',
    'config/maintenance/service.py', 'config/maintenance/native.php',
    'scripts/configure-private-defaults.php',
    'scripts/cleanup-test-accounts.py', 'scripts/cleanup-test-accounts-native.php',
    'scripts/backup.py', 'scripts/verify-public.py', 'scripts/compose.sh',
)
EVIDENCE = (
    'state/acceptance/test-account-cleanup/plan.json',
    'state/acceptance/test-account-cleanup/result.json',
    'state/acceptance/test-account-cleanup/postcheck.json',
    'state/acceptance/public-ip-tls.json',
)


def archive_directory_private(capture, name, owner):
    entry = capture.members[name]
    return entry.isdir() and (entry.uid, entry.gid, entry.mode & 0o7777) == (owner, owner, 0o700)


def live_directory_private(path, owner):
    info = path.lstat()
    return stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (owner, owner, 0o700)


def check_backup(directory):
    report = {'verifiedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'passed':False, 'checks':[], 'counts':{}}

    def check(name, passed):
        report['checks'].append({'name':name, 'passed':bool(passed)})

    try:
        directory = Path(directory)
        manifest = decode((directory/'manifest.json').read_bytes())
        info = directory.lstat()
        check('private_backup_directory_and_sql', stat.S_ISDIR(info.st_mode) and
              stat.S_IMODE(info.st_mode)==0o700 and private_file(directory/'application.sql'))
        check('database_and_volume_inventory', len(manifest['databases'])==55 and
              manifest['applicationTables']==518 and
              set(manifest['volumes'])=={'team-management_'+name for name in VOLUMES})
        required = {'application.sql', 'deployment-private.tar.gz'} | {name+'.tar.gz' for name in VOLUMES}
        check('required_archive_checksums_match', required <= set(manifest['sha256']) and all(
              private_file(directory/name) and digest_file(directory/name)==manifest['sha256'][name]
              for name in required))
        report['counts'].update(databases=len(manifest['databases']),
                                applicationTables=manifest['applicationTables'], volumes=len(manifest['volumes']))
        with tarfile.open(directory/'deployment-private.tar.gz', 'r:gz') as archive:
            capture = Capture(archive)
            release = capture.json('state/acceptance/release-manifest.json')
            live_release = decode((ROOT/'state/acceptance/release-manifest.json').read_bytes())
            check('public_registration_and_maintenance_remain_enabled',
                  all(release.get(name) is True for name in ('publicEnabled','registrationEnabled','maintenanceEnabled')) and
                  all(capture.read(name)==(ROOT/name).read_bytes() for name in
                      ('.public-enabled','.registration-enabled','.maintenance-enabled')) and
                  ('.dingtalk-enabled' in capture.members)==(ROOT/'.dingtalk-enabled').is_file())
            plan = capture.json(EVIDENCE[0]);result = capture.json(EVIDENCE[1]);postcheck = capture.json(EVIDENCE[2])
            principals = {row['principal'] for row in plan['nativeUsers']}
            registration_ids = {row['registration_id'] for row in plan['registrations']}
            registration_principals = {row['user_id'] for row in plan['registrations']}
            check('reviewed_cleanup_scope_is_exact_and_excludes_administrator',
                  len(principals)==len(plan['nativeUsers'])==13 and len(registration_ids)==9 and
                  'linkerbot-site-admin' not in principals | registration_principals and
                  all(not row['protectedSiteAdmin'] and not row['isSystemAgent'] and
                      not row['isMailingList'] and row['username'] not in ('siteadmin','admin','root') and
                      row['emails'] and all(re.fullmatch(r'[^@]+@acceptance\.test', value)
                                           for value in row['emails']) for row in plan['nativeUsers']) and
                  all(row['user_id']=='reg-'+row['registration_id'] and
                      re.fullmatch(r'[^@]+@acceptance\.test',row['email']) for row in plan['registrations']))
            check('completed_cleanup_preserves_real_account_and_objects',
                  result['passed'] is True and result['apply'] is True and result['phase']=='completed' and
                  result['removedWardenEntries']==13 and result['removedPasswordRecords']==5 and
                  result['removedRegistrationRows']==9 and result['protectedCredentialAndDirectoryEntriesUnchanged'] is True and
                  result['nativeDeletion']['passed'] is True and result['nativeDeletion']['deletedUsers']==13 and
                  result['nativeDeletion']['protectedUsersUnchanged'] is True and
                  result['nativeDeletion']['protectedNativeSessionsUnchanged'] is True and
                  result['nativeDeletion']['projectsPreserved']==9 and result['nativeDeletion']['tasksPreserved']==9 and
                  postcheck['passed'] is True and postcheck['testNativeUsers']==0 and
                  postcheck['administratorPreserved'] is True)
            check('cleanup_and_tls_evidence_matches_current_private_records', all(
                  capture.private(name,0) and capture.read(name)==(ROOT/name).read_bytes() for name in EVIDENCE))
            report['counts'].update(removedNativeUsers=len(principals), removedRegistrationRows=len(registration_ids))
            hashes = release['configurationSHA256']
            check('new_sources_match_release_and_current_sources', all(
                  name in hashes and hashlib.sha256(capture.read(name)).hexdigest()==hashes[name]==digest_file(ROOT/name)
                  for name in SOURCES))
            archived_sources = [name for name in hashes if name in capture.members]
            check('all_archived_manifest_sources_match', all(
                  hashlib.sha256(capture.read(name)).hexdigest()==hashes[name] for name in archived_sources))
            report['counts']['manifestSourcesCaptured'] = len(archived_sources)
            env = dict(line.split('=',1) for line in capture.read('.env').decode().splitlines()
                       if line and not line.startswith('#') and '=' in line)
            gateway = [row for row in release['services'] if row['service']=='traefik']
            live_gateway = [row for row in live_release['services'] if row['service']=='traefik']
            check('traefik_version_and_digest_are_pinned_to_reviewed_runtime',
                  env.get('TRAEFIK_IMAGE')==TRAEFIK_IMAGE and len(gateway)==len(live_gateway)==1 and
                  gateway[0]['image']==live_gateway[0]['image']==TRAEFIK_IMAGE and
                  gateway[0]['imageID']==live_gateway[0]['imageID'])
            php_key = 'config/maintenance/keys/php.key';service_key='config/maintenance/keys/service.key'
            check('maintenance_rpc_keys_remain_private_and_unchanged',
                  capture.private(php_key,33,0o400) and capture.private(service_key,10001,0o400) and
                  len(capture.read(php_key))==32 and capture.read(php_key)==capture.read(service_key) and
                  all(capture.read(name)==(ROOT/name).read_bytes() for name in (php_key,service_key)))
            password_path = 'config/passwords/users.json'
            passwords = capture.json(password_path);users = passwords['users']
            check('password_directory_and_store_private_and_current',
                  archive_directory_private(capture,'config/passwords',10001) and
                  live_directory_private(ROOT/'config/passwords',10001) and
                  capture.private(password_path,10001) and private_file(ROOT/password_path,owner=10001) and
                  capture.read(password_path)==(ROOT/password_path).read_bytes())
            check('published_credentials_have_only_fixed_hashes_and_revisions',
                  set(passwords)=={'version','users'} and type(passwords['version']) is int and passwords['version']==1 and
                  all(set(entry)=={'password_hash','revision'} and HASH_PATTERN.fullmatch(entry['password_hash']) and
                      re.fullmatch(r'[0-9a-f]{32}',entry['revision']) and
                      uuid.UUID(hex=entry['revision']).version==4 for entry in users.values()))
            warden_path = 'config/warden/users.json';warden=capture.json(warden_path)
            check('directory_snapshot_matches_current_without_dropping_new_people',
                  capture.read(warden_path)==(ROOT/warden_path).read_bytes())
            check('planned_test_principals_absent_from_directory',
                  not (principals | registration_principals) & {row['user_id'] for row in warden})
            check('planned_test_credentials_absent', not (principals | registration_principals) & set(users))
            check('real_administrator_admission_and_password_retained',
                  len([row for row in warden if row['user_id']=='linkerbot-site-admin' and row['status']=='active'])==1 and
                  'linkerbot-site-admin' in users)
            report['counts'].update(directoryEntries=len(warden),publishedCredentials=len(users))
            acme_dir = 'config/traefik/acme';production=acme_dir+'/production.json'
            check('production_acme_private_ownership_and_modes',
                  archive_directory_private(capture,acme_dir,0) and capture.private(production,0) and
                  live_directory_private(ROOT/acme_dir,0) and private_file(ROOT/production,owner=0))
            check('production_acme_bytes_match_current',capture.read(production)==(ROOT/production).read_bytes())
            acme_state=capture.json(production)
            certificates=acme_state.get('public-ip',{}).get('Certificates',[])
            check('production_acme_contains_canonical_ip_certificate',
                  bool(certificates) and any(row.get('domain',{}).get('main')=='45.77.36.106' and
                      isinstance(row.get('certificate'),str) and bool(row['certificate']) for row in certificates))
            static=yaml.safe_load(capture.read('config/traefik/public-static.yaml'))
            acme=static['certificatesResolvers']['public-ip']['acme']
            check('production_acme_short_lived_160_hour_renewal_configuration',
                  acme.get('caServer')=='https://acme-v02.api.letsencrypt.org/directory' and
                  acme.get('storage')=='/etc/traefik/acme/production.json' and
                  acme.get('profile')=='shortlived' and acme.get('certificatesDuration')==160 and
                  acme.get('disableCommonName') is True and acme.get('httpChallenge',{}).get('entryPoint')=='web')
            dynamic=yaml.safe_load(capture.read('config/traefik/dynamic.yaml'))
            generated=dynamic['tls']['stores']['default']['defaultGeneratedCert']
            tls_options=dynamic['tls']['options']['default']
            check('canonical_ip_default_certificate_supports_clients_without_sni',
                  generated.get('resolver')=='public-ip' and generated.get('domain',{}).get('main')=='45.77.36.106' and
                  not dynamic['tls'].get('certificates') and not tls_options.get('sniStrict',False) and
                  tls_options.get('minVersion') in ('VersionTLS12','VersionTLS13'))
            tls_evidence=capture.json(EVIDENCE[3])
            check('trusted_public_tls_acceptance_record_is_successful',
                  tls_evidence['passed'] is True and tls_evidence['privateKeyPrinted'] is False and
                  all(row['passed'] for row in tls_evidence['checks']))
            with tempfile.TemporaryDirectory(prefix='real-users-capture-') as temporary:
                temporary_path=Path(temporary)
                registration_path='state/registration/registrations.sqlite3'
                audit_path='state/maintenance/maintenance.sqlite3'
                check('registration_and_audit_private_ownership_and_lock_retained',
                      all(capture.private(name,10001) for name in
                          (registration_path,audit_path,'state/registration/approval.lock')) and
                      all(archive_directory_private(capture,name,10001) for name in
                          ('state/registration','state/maintenance')))
                registration=capture.sqlite(temporary_path,registration_path)
                audit=capture.sqlite(temporary_path,audit_path)
                try:
                    check('both_sqlite_databases_pass_integrity_and_foreign_keys',all(
                          db.execute('PRAGMA integrity_check').fetchone()[0]=='ok' and
                          not db.execute('PRAGMA foreign_key_check').fetchall() for db in (registration,audit)))
                    rows=registration.execute('SELECT registration_id,user_id,status,password_hash FROM registrations').fetchall()
                    check('exact_test_registration_ids_and_principals_are_absent',
                          not registration_ids & {row['registration_id'] for row in rows} and
                          not (principals | registration_principals) & {row['user_id'] for row in rows})
                    check('remaining_registration_hashes_use_fixed_encoding',all(
                          row['password_hash'] is None or HASH_PATTERN.fullmatch(row['password_hash']) for row in rows))
                    check('pending_people_have_no_published_password',all(
                          row['user_id'] not in users for row in rows if row['status']=='pending'))
                    organization_count=registration.execute('SELECT COUNT(*) FROM org_units').fetchone()[0]
                    check('organization_placeholders_still_empty',organization_count==0 and
                          registration.execute('SELECT COUNT(*) FROM registrations WHERE org_unit_id IS NOT NULL OR manager_user_id IS NOT NULL OR position IS NOT NULL').fetchone()[0]==0)
                    audit_columns={row['name'] for row in audit.execute('PRAGMA table_info(audit)')}
                    events=audit.execute('SELECT action,target,status,fingerprint,result_json,context_json FROM audit').fetchall()
                    check('audit_schema_and_successful_history_retained',audit_columns==AUDIT_COLUMNS and bool(events) and
                          all(row['status'] in ('intent','succeeded','failed','partial') for row in events) and
                          all(any(row['action']==action and row['status']=='succeeded' for row in events) for action in
                              ('approve','reject','set_password','set_user_status')) and
                          any(row['target'] in principals | registration_ids and row['status']=='succeeded' for row in events))
                    check('audit_contains_no_credential_or_raw_request_fields',all(
                          re.fullmatch(r'[0-9a-f]{64}',row['fingerprint']) and
                          set(decode(row['context_json']))<=PRIVATE_CONTEXT_KEYS and
                          secret_keys_absent(decode(row['context_json'])) and
                          (row['result_json'] is None or secret_keys_absent(decode(row['result_json']))) for row in events))
                    report['counts'].update(registrations=len(rows),organizationUnits=organization_count,auditRows=len(events))
                finally:
                    registration.close();audit.close()
            check('temporary_database_copies_removed',not temporary_path.exists())
    except (OSError,ValueError,KeyError,TypeError,AttributeError,IndexError,sqlite3.Error,tarfile.TarError,yaml.YAMLError):
        # Exception strings can contain private source values. Emit no details.
        check('capture_parsed_without_errors',False)
    report['passed']=bool(report['checks']) and all(row['passed'] for row in report['checks'])
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backup',type=Path)
    args=parser.parse_args();os.umask(0o077)
    report=check_backup(args.backup)
    REPORT.parent.mkdir(parents=True,exist_ok=True)
    REPORT.write_text(json.dumps(report,indent=2)+'\n');REPORT.chmod(0o600)
    print(json.dumps({'passed':report['passed'],'checks':len(report['checks']),
                      'failedChecks':sum(not row['passed'] for row in report['checks'])}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__=='__main__':main()
