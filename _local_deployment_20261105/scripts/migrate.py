#!/usr/bin/env python3
"""Carry this deployment, its exact images and consistent data to another host.

Run ``python3 scripts/migrate.py --help``. Bundle directories contain secrets;
use ``seal`` before placing them in remote storage. Git is for reviewed source.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import secrets
import shutil
import signal
import socket
import socketserver
import select
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MARKER = '.migration-target.json'
FORMAT = 1

_PROCESS_SPEC = importlib.util.spec_from_file_location(
    'migration_process', Path(__file__).with_name('migration_process.py'))
_PROCESS = importlib.util.module_from_spec(_PROCESS_SPEC)
_PROCESS_SPEC.loader.exec_module(_PROCESS)
run_backup = _PROCESS.run_backup


class MigrationCancelled(KeyboardInterrupt):
    def __init__(self, signum=signal.SIGINT):
        self.signum = signum
        super().__init__('Migration cancelled.')


def cancel_migration(signum, frame):
    # Outside run_backup(), cancellation must unwind export's recovery guard.
    raise MigrationCancelled(signum)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.write('\n')
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def run(argv, *, cwd=None, input=None, stdout=None, timeout=None):
    result = subprocess.run([str(a) for a in argv], cwd=cwd, input=input,
                            stdout=stdout if stdout is not None else subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        # Compose and PHP errors may embed passwords, SQL or user content.
        raise RuntimeError('Command failed (exit %s): %s. Private data omitted.' %
                           (result.returncode, Path(str(argv[0])).name))
    return result.stdout


def compose(root, *args, **kwargs):
    return run([Path(root)/'scripts/compose.sh', *args], cwd=root, **kwargs)


def config(root):
    return json.loads(compose(root, 'config', '--format', 'json'))


def require_root():
    if os.geteuid() != 0:
        raise ValueError('Run as root to preserve private file ownership and volume data.')


def new_directory(path):
    path = Path(path).absolute()
    if path.exists() or path.is_symlink():
        raise ValueError('Destination must not exist: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(mode=0o700)
    return path.resolve()


def validate_archive(archive):
    """Reject traversal, external links and special files before any extraction."""
    seen = set()
    links = {}
    raw_links = {}
    for member in archive.getmembers():
        name = member.name
        normalized = posixpath.normpath(name)
        if (not name or name.startswith('/') or '\\' in name or
                '..' in PurePosixPath(name).parts or normalized in seen):
            raise ValueError('Unsafe or duplicate archive path.')
        seen.add(normalized)
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise ValueError('Unsupported special file in archive.')
        if member.issym() or member.islnk():
            link = member.linkname
            resolved = posixpath.normpath(posixpath.join(
                posixpath.dirname(normalized) if member.issym() else '', link))
            if (not link or link.startswith('/') or '\\' in link or
                    resolved == '..' or resolved.startswith('../')):
                raise ValueError('Archive link escapes its destination.')
            links[normalized] = resolved
            raw_links[normalized] = (member.issym(), link)
    # A lexical in-tree link may still escape through an earlier link. Never
    # extract children through links, or allow chained archive link targets.
    for name in seen:
        if any(str(parent) in links for parent in PurePosixPath(name).parents):
            raise ValueError('Archive member traverses another archive link.')
    for target in links.values():
        if target in links or any(str(parent) in links for parent in PurePosixPath(target).parents):
            raise ValueError('Chained archive links are unsupported.')
    for name, (symbolic, link) in raw_links.items():
        # Do not normalize away a symlink traversal followed by "..".
        parts = list(PurePosixPath(name).parent.parts) if symbolic else []
        for part in PurePosixPath(link).parts:
            if part == '..':
                if parts:
                    parts.pop()
            elif part != '.':
                parts.append(part)
            if '/'.join(parts) in links:
                raise ValueError('Archive link traverses another link before normalization.')


def extract(archive_path, destination):
    with tarfile.open(archive_path, 'r:*') as archive:
        validate_archive(archive)
        # Destination is newly created and all paths/links were checked above.
        archive.extractall(destination, numeric_owner=True, filter='fully_trusted')


def image_inventory(root):
    cfg = config(root)
    images = {}
    services = {}
    for service, value in cfg['services'].items():
        ref = value['image']
        info = json.loads(run(['docker', 'image', 'inspect', ref]))[0]
        services[service] = info['Id']
        images[info['Id']] = {'id': info['Id'], 'architecture': info['Architecture'],
                              'os': info['Os'], 'references': []}
    marker = json.loads((root/MARKER).read_text()) if (root/MARKER).exists() else {}
    helper_ref = marker.get('utilityImageID') or json.loads((root/'vendor/phorge/deploy/acceptance/build-lock.json').read_text())['images']['alpine']
    info = json.loads(run(['docker', 'image', 'inspect', helper_ref]))[0]
    images.setdefault(info['Id'], {'id': info['Id'], 'architecture': info['Architecture'],
                                   'os': info['Os'], 'references': []})
    return {'images': list(images.values()), 'serviceImages': services,
            'utilityImageID': info['Id'], 'sourceProject': cfg['name']}


def source_running_services(inventory):
    raw = compose(ROOT, 'ps', '--format', 'json').decode().strip()
    rows = json.loads(raw) if raw.startswith('[') else [json.loads(line) for line in raw.splitlines()]
    names = sorted({row['Service'] for row in rows
                    if row['State'] == 'running' and row['Service'] != 'mysql'})
    if not set(names).issubset(inventory['serviceImages']):
        raise ValueError('An unreviewed source service is running; no writer was stopped.')
    return names


def recover_export_source(dest, inventory, fallback_services, cancelled=False):
    """Recover only services known to this export, even after a partial backup."""
    names = list(fallback_services)
    status_source = 'export-source-state.json'
    for candidate in ('backup-status.json', 'manifest.json'):
        path = dest/'snapshot'/candidate
        if not path.exists():
            continue
        try:
            saved = json.loads(path.read_text())
            proposed = saved.get('runningServices')
            if (isinstance(proposed, list) and
                    all(isinstance(name, str) for name in proposed) and
                    set(proposed).issubset(inventory['serviceImages']) and 'mysql' not in proposed):
                names = sorted(set(proposed))
                status_source = 'snapshot/'+candidate
                break
        except (OSError, ValueError, TypeError):
            # A cancelled partial status write cannot erase the parent's
            # already-recorded, inventory-checked original running services.
            pass
    if not set(names).issubset(inventory['serviceImages']) or 'mysql' in names:
        raise ValueError('Invalid source recovery service set.')
    previous = {signum: signal.signal(signum, signal.SIG_IGN)
                for signum in (signal.SIGINT, signal.SIGTERM)}
    result = {'failedAt': now(), 'cancelled': cancelled, 'sourceRecoveryAttempted': bool(names),
              'sourceResumed': False, 'sourceServices': names, 'sourceStateEvidence': status_source}
    try:
        if names:
            compose(ROOT, 'start', *names)
        result['sourceResumed'] = True
    except BaseException:
        result['sourceRecoveryFailed'] = True
        raise RuntimeError('Export aborted and source recovery failed; inspect the private export-failure.json and source services.') from None
    finally:
        try:
            write_json(dest/'export-failure.json', result)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)


def export_bundle(output, leave_stopped=False):
    require_root()
    dest = new_directory(output)
    inventory = image_inventory(ROOT)
    print('Saving exact runtime images before the backup pause.', flush=True)
    raw = dest/'images.tar'
    run(['docker', 'image', 'save', '--output', raw,
         *[image['id'] for image in inventory['images']]])
    with raw.open('rb') as source, gzip.open(dest/'images.tar.gz', 'wb', compresslevel=1) as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    raw.unlink()
    print('Taking a consistent portable snapshot; application writers will pause.', flush=True)
    command = [sys.executable, ROOT/'scripts/backup.py', '--portable', '--output-dir', dest/'snapshot']
    if leave_stopped:
        command.append('--leave-stopped')
    original_running = source_running_services(inventory)
    write_json(dest/'export-source-state.json', {'sourceProject': inventory['sourceProject'],
               'runningServices': original_running, 'capturedAt': now()})
    try:
        with (dest/'backup.log').open('wb') as log:
            outcome = run_backup(command, cwd=ROOT, stdout=log)
        write_json(dest/'backup-process.json', outcome)
        if outcome['cancelled']:
            raise MigrationCancelled(outcome['signal'])
        if outcome['returncode']:
            raise RuntimeError('Portable backup failed; inspect its private status and log.')
        return finalize_export(dest, inventory, leave_stopped)
    except BaseException as error:
        # Includes failures/cancellation while backup.py itself is running.
        # run_backup has awaited the child's finally before returning here.
        # A successful leave-stopped snapshot is not yet a usable bundle.
        recover_export_source(dest, inventory, original_running,
                              cancelled=isinstance(error, KeyboardInterrupt))
        raise


def finalize_export(dest, inventory, leave_stopped):
    snapshot = json.loads((dest/'snapshot/manifest.json').read_text())
    actual = {item['service']: item['imageID'] for item in snapshot['sourceServices']}
    if actual != inventory['serviceImages']:
        raise RuntimeError('Runtime image inventory changed while exporting; bundle is incomplete.')
    bootstrap = dest/'tooling/scripts'
    bootstrap.mkdir(parents=True, mode=0o700)
    for name in ('migrate.py', 'migration_endpoint.py', 'migration_probe.php', 'migration_process.py', 'backup.py'):
        shutil.copy2(ROOT/'scripts'/name, bootstrap/name)
    for name in ('tests/browser/migration-smoke.mjs', 'tests/browser/package.json',
                 'tests/browser/package-lock.json', 'tests/migration/browser_probe.php'):
        destination = dest/'tooling'/name
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(ROOT/name, destination)
    (dest/'RESTORE.txt').write_text(
        'Private portable deployment. Requires Linux with matching CPU architecture, Docker Compose v2, '
        'Python 3.12+ and PyYAML.\n'
        'Verify: python3 tooling/scripts/migrate.py verify .\n'
        'Restore: python3 tooling/scripts/migrate.py restore . --target /srv/team-management '
        '--origin https://YOUR-NEW-HOST\n'
        'Start: python3 tooling/scripts/migrate.py start --target /srv/team-management\n'
        'Check: python3 tooling/scripts/migrate.py check --target /srv/team-management\n'
        'Keep the previous deployment stopped during the final cutover. Preserve the encryption key separately.\n')
    artifact_files = [dest/'images.tar.gz', dest/'RESTORE.txt', *sorted((dest/'snapshot').iterdir()),
                      *sorted(p for p in (dest/'tooling').rglob('*') if p.is_file())]
    manifest = {'formatVersion': FORMAT, 'kind': 'team-management-portable',
                'createdAt': now(), **inventory, 'sourceRoot': str(ROOT),
                'sourceOrigin': snapshot['sourceOrigin'],
                'leaveSourceStopped': leave_stopped,
                'snapshotManifest': 'snapshot/manifest.json',
                'files': {str(p.relative_to(dest)): {'sha256': digest(p), 'bytes': p.stat().st_size}
                          for p in artifact_files if p.is_file()}}
    write_json(dest/'bundle.json', manifest)
    verify_bundle(dest)
    print('Portable bundle ready: ' + str(dest), flush=True)
    return dest


def verify_bundle(bundle):
    bundle = Path(bundle).resolve()
    manifest = json.loads((bundle/'bundle.json').read_text())
    if manifest.get('kind') != 'team-management-portable' or manifest.get('formatVersion') != FORMAT:
        raise ValueError('Unsupported migration bundle.')
    required = {'images.tar.gz', 'snapshot/manifest.json', 'snapshot/application.sql',
                'snapshot/deployment-private.tar.gz', 'snapshot/source-snapshot.json',
                'snapshot/volume-inventories.json', 'snapshot/sqlite-snapshot.json',
                'tooling/scripts/migrate.py', 'tooling/scripts/migration_endpoint.py',
                'tooling/scripts/backup.py', 'tooling/scripts/migration_probe.php',
                'tooling/scripts/migration_process.py'}
    if not required.issubset(manifest['files']):
        raise ValueError('Incomplete migration bundle.')
    for name, metadata in manifest['files'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('Unsafe bundle manifest path.')
        path = bundle/name
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(bundle):
            raise ValueError('Missing or unsafe bundle artifact.')
        if path.stat().st_size != metadata['bytes'] or digest(path) != metadata['sha256']:
            raise ValueError('Bundle checksum failed: ' + name)
        if name.endswith('.tar.gz') and name != 'images.tar.gz':
            with tarfile.open(path, 'r:gz') as archive:
                validate_archive(archive)
    snapshot = json.loads((bundle/'snapshot/manifest.json').read_text())
    if not snapshot.get('portable'):
        raise ValueError('A portable snapshot is required.')
    expected_volumes = {'phorge-db': 'application.sql', **{
        name: name+'.tar.gz' for name in ('phorge-conf', 'phorge-files', 'phorge-repo',
                                         'stargate-redis-data', 'herald-redis-data')}}
    mappings = snapshot.get('volumeMap', [])
    if len(mappings) != len(expected_volumes) or {
            row.get('logicalName'): row.get('archive') for row in mappings} != expected_volumes:
        raise ValueError('The portable snapshot is missing a persistent volume.')
    for artifact in expected_volumes.values():
        if 'snapshot/'+artifact not in manifest['files'] or artifact not in snapshot['sha256']:
            raise ValueError('A persistent volume artifact is not verified.')
    service_images = {row['service']: row['imageID'] for row in snapshot['sourceServices']}
    if service_images != manifest['serviceImages']:
        raise ValueError('Snapshot and bundle image identities differ.')
    imageids = {row['id'] for row in manifest['images']}
    if not set(service_images.values()).issubset(imageids) or manifest['utilityImageID'] not in imageids:
        raise ValueError('The bundle lacks a required image identity.')
    for name, sha in snapshot['sha256'].items():
        if Path(name).name != name or digest(bundle/'snapshot'/name) != sha:
            raise ValueError('Snapshot checksum failed.')
    return manifest


def load_marker(root):
    root = Path(root).resolve()
    marker = json.loads((root/MARKER).read_text())
    if (marker.get('targetRoot') != str(root) or
            not re.fullmatch(r'tm-migrate-(?:test-)?[a-f0-9]{8,16}', marker.get('project', ''))):
        raise ValueError('Invalid migration target marker.')
    cfg = config(root)
    if cfg['name'] != marker['project']:
        raise ValueError('Target project differs from its migration marker.')
    for volume in cfg.get('volumes', {}).values():
        if volume.get('external') or not volume['name'].startswith(marker['project']+'_'):
            raise ValueError('Target contains an external or foreign volume.')
    for network in cfg.get('networks', {}).values():
        if network.get('external') or not network['name'].startswith((marker['project']+'_', marker['project']+'-')):
            raise ValueError('Target contains an external or foreign network.')
    for service in cfg['services'].values():
        for mount in service.get('volumes', []):
            if mount['type'] == 'bind' and not Path(mount['source']).resolve().is_relative_to(root):
                raise ValueError('Target contains a foreign host bind mount.')
    return marker, cfg


def wait_healthy(root, services, timeout=180):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        ids = compose(root, 'ps', '-q', *services).decode().split()
        if len(ids) == len(services):
            states = json.loads(run(['docker', 'inspect', *ids]))
            if all(x['State']['Status'] == 'running' and
                   x['State'].get('Health', {}).get('Status', 'healthy') == 'healthy' for x in states):
                return
            if any(x['State']['Status'] in ('dead', 'exited') for x in states):
                raise RuntimeError('A target service exited; inspect private target logs.')
        time.sleep(2)
    raise RuntimeError('Target health checks did not pass within the deadline.')


def probe(root, files=False):
    running = compose(root, 'ps', '--status', 'running', '-q', 'phorge').strip()
    args = ['exec', '-T'] if running else ['run', '--rm', '--no-deps', '-T']
    if files:
        args += ['-e', 'TEAM_MIGRATION_FILES=1']
    args += ['phorge', 'php'] if running else ['--entrypoint', 'php', 'phorge']
    return json.loads(compose(root, *args, input=(Path(root)/'scripts/migration_probe.php').read_bytes()))


def snapshot_equal(before, after):
    # The probe intentionally omits names and payloads; table digests are exact.
    return before['tables'] == after['tables'] and before['authorization'] == after['authorization']


def restore_bundle(bundle, target, origin, rehearsal=False, project=None, port=None):
    require_root()
    bundle = Path(bundle).resolve()
    manifest = verify_bundle(bundle)
    arch = run(['docker', 'info', '--format', '{{.Architecture}}']).decode().strip()
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(arch, arch)
    if any(x['os'] != 'linux' or x['architecture'] != arch for x in manifest['images']):
        raise ValueError('Bundle images do not match this host architecture.')
    project = project or ('tm-migrate-test-' if rehearsal else 'tm-migrate-')+secrets.token_hex(4)
    pattern = r'tm-migrate-test-[a-f0-9]{8,16}' if rehearsal else r'tm-migrate-[a-f0-9]{8,16}'
    if not re.fullmatch(pattern, project):
        raise ValueError('Use a unique migration project name with the documented prefix.')
    for kind in ['container', 'volume', 'network']:
        if run(['docker', kind, 'ls', '-q', '--filter', 'label=com.docker.compose.project='+project]).strip():
            raise ValueError('Target Docker resources already exist.')
    target = new_directory(target)
    if shutil.disk_usage(target).free < sum(x['bytes'] for x in manifest['files'].values())*2:
        raise ValueError('Insufficient free space to restore this bundle.')
    print('Loading the exact images and restoring to a new private directory.', flush=True)
    missing = any(subprocess.run(['docker', 'image', 'inspect', info['id']],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
                  for info in manifest['images'])
    if missing:
        run(['docker', 'image', 'load', '--input', bundle/'images.tar.gz'])
    for info in manifest['images']:
        actual = json.loads(run(['docker', 'image', 'inspect', info['id']]))[0]
        if actual['Id'] != info['id']:
            raise ValueError('Loaded image identity mismatch.')
    extract(bundle/'snapshot/deployment-private.tar.gz', target)
    # A carried target marker belongs to the previous host, never this restore.
    marker = {'formatVersion': FORMAT, 'project': project, 'targetRoot': str(target),
              'sourceRoot': manifest['sourceRoot'], 'bundle': str(bundle),
              'utilityImageID': manifest['utilityImageID'],
              'bundleSHA256': digest(bundle/'bundle.json'), 'origin': origin,
              'rehearsal': rehearsal, 'createdAt': now(), 'phase': 'preparing'}
    write_json(target/MARKER, marker)
    spec = importlib.util.spec_from_file_location('migration_endpoint', ROOT/'scripts/migration_endpoint.py')
    endpoint = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(endpoint)
    metadata = endpoint.prepare_target(target, origin, project, rehearsal=rehearsal, port=port)
    marker['origin'] = metadata['origin']
    cfgpath = target/'compose.migration.json'
    cfg = json.loads(cfgpath.read_text())
    for service, imageid in manifest['serviceImages'].items():
        cfg['services'][service]['image'] = imageid
        cfg['services'][service]['pull_policy'] = 'never'
    write_json(cfgpath, cfg)
    marker['endpoint'] = metadata
    write_json(target/MARKER, marker)
    marker, cfg = load_marker(target)
    snapshot_manifest = json.loads((bundle/'snapshot/manifest.json').read_text())
    helper = manifest['utilityImageID']
    backup_spec = importlib.util.spec_from_file_location('migration_backup_helpers', ROOT/'scripts/backup.py')
    backup_helpers = importlib.util.module_from_spec(backup_spec); backup_spec.loader.exec_module(backup_helpers)
    inventories = json.loads((bundle/'snapshot/volume-inventories.json').read_text())
    volume_checks = {}
    for logical, entry in cfg['volumes'].items():
        name = entry['name']
        if subprocess.run(['docker', 'volume', 'inspect', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            raise ValueError('Refusing to restore over an existing Docker volume.')
        run(['docker', 'volume', 'create', '--label', 'com.docker.compose.project='+project,
             '--label', 'com.docker.compose.volume='+logical, name])
    print('Restoring persistent volumes and database.', flush=True)
    for entry in snapshot_manifest['volumeMap']:
        if entry['archive'] == 'application.sql':
            continue
        volume = cfg['volumes'][entry['logicalName']]['name']
        archive = bundle/'snapshot'/entry['archive']
        run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
             '--mount', 'type=volume,src='+volume+',dst=/data',
             '--mount', 'type=bind,src='+str(archive)+',dst=/restore.tar.gz,readonly',
             helper, 'sh', '-ec', 'tar -xzf /restore.tar.gz -C /data'])
        with tempfile.NamedTemporaryFile(dir=target/'state', suffix='.tar.gz') as check:
            run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
                 '--mount', 'type=volume,src='+volume+',dst=/data,readonly', helper,
                 'tar', '-C', '/data', '-czf', '-', '.'], stdout=check)
            check.flush()
            recovered = backup_helpers.archive_inventory(check.name)
        if recovered != inventories[entry['logicalName']]:
            raise RuntimeError('Restored volume content/ownership differs: '+entry['logicalName'])
        volume_checks[entry['logicalName']] = {'passed': True, 'digest': recovered['digest'],
                                               'entries': recovered['entryCount']}
    sqlite_source = json.loads((bundle/'snapshot/sqlite-snapshot.json').read_text())
    if backup_helpers.sqlite_snapshot(target) != sqlite_source:
        raise RuntimeError('Restored registration/maintenance SQLite contents differ.')
    write_json(target/'state/migration-volume-check.json', {'passed': True, 'volumes': volume_checks,
                                                          'sqliteMatches': True})
    # Recreate SQL grants from original secrets; do not run a fresh deployment initializer.
    generator_spec = importlib.util.spec_from_file_location('restore_generate_core', target/'scripts/generate-core.py')
    generator = importlib.util.module_from_spec(generator_spec); generator_spec.loader.exec_module(generator)
    env = generator.load_env(target/'.env')
    sql = generator.generate_sql(target/'vendor/phorge', snapshot_manifest['databaseNamespace'])
    for key in set(re.findall(r'@@([A-Z_]+)@@', sql)):
        value = env.get(key, '')
        if not re.fullmatch(r'[a-fA-F0-9]{32,128}', value):
            raise ValueError('Invalid original database credential format.')
        sql = sql.replace('@@'+key+'@@', value)
    (target/'state').mkdir(exist_ok=True)
    (target/'state/mysql-accounts.sql').write_text(sql)
    (target/'state/mysql-accounts.sql').chmod(0o600)
    compose(target, 'up', '-d', '--no-build', '--pull', 'never', 'mysql')
    wait_healthy(target, ['mysql'])
    compose(target, 'run', '--rm', '--no-deps', '-T', 'db-init')
    with (bundle/'snapshot/application.sql').open('rb') as stream:
        result = subprocess.run([target/'scripts/compose.sh', 'exec', '-T', 'mysql', 'sh', '-ec',
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot'], stdin=stream,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError('SQL import failed; private database error omitted.')
    # Before any target application starts, require the complete SQL snapshot to match.
    print('Comparing every restored application table before enabling services.', flush=True)
    source_snapshot = json.loads((bundle/'snapshot/source-snapshot.json').read_text())
    restored_snapshot = probe(target)
    write_json(target/'state/migration-restored-snapshot.json', restored_snapshot)
    if not snapshot_equal(source_snapshot, restored_snapshot):
        raise RuntimeError('Restored database snapshot differs from the frozen source.')
    write_json(target/'state/migration-source-snapshot.json', source_snapshot)
    # Modify only the restored config volume, after its original bytes were recovered.
    conf_volume = cfg['volumes']['phorge-conf']['name']
    with tempfile.TemporaryDirectory(dir=target/'state', prefix='migration-conf-') as temporary:
        temporary = Path(temporary); conf = temporary/'conf'; conf.mkdir()
        extract(bundle/'snapshot/phorge-conf.tar.gz', conf)
        endpoint.rewrite_phorge_config(conf, metadata)
        changed = temporary/'conf.tar.gz'
        with tarfile.open(changed, 'w:gz') as archive:
            archive.add(conf, arcname='.')
        run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
             '--mount', 'type=volume,src='+conf_volume+',dst=/data',
             '--mount', 'type=bind,src='+str(changed)+',dst=/restore.tar.gz,readonly',
             helper, 'sh', '-ec', 'tar -xzf /restore.tar.gz -C /data'])
    marker['phase'] = 'restored'; marker['restoredAt'] = now(); marker['fullSQLSnapshotMatches'] = True
    write_json(target/MARKER, marker)
    print('Restore verified. Start with: python3 scripts/migrate.py start --target '+str(target), flush=True)
    return target


def start_target(root):
    root = Path(root).resolve(); marker, cfg = load_marker(root)
    if marker.get('phase') not in ('restored', 'started', 'checked'):
        raise ValueError('Complete and verify the restore before starting services.')
    compose(root, 'up', '-d', '--no-build', '--pull', 'never')
    long_running = [name for name in cfg['services'] if name not in ('db-init', 'phorge-migrate')]
    wait_healthy(root, long_running, timeout=240)
    marker['phase'] = 'started'; marker['startedAt'] = now()
    write_json(root/MARKER, marker)
    print('Restored services are healthy.', flush=True)


def check_target(root):
    root = Path(root).resolve(); marker, cfg = load_marker(root)
    before = json.loads((root/'state/migration-source-snapshot.json').read_text())
    after = probe(root, files=True)
    result = {'checkedAt': now(), 'project': marker['project'], 'origin': marker['origin'],
              'fullSQLSnapshotMatchesBeforeStartup': marker['fullSQLSnapshotMatches'],
              'businessSnapshotMatches': before['businessDigest'] == after['businessDigest'],
              'accessMatrixMatches': before['authorization'] == after['authorization'],
              'counts': after['counts'],
              'authorization': after['authorization'],
              'volumes': json.loads((root/'state/migration-volume-check.json').read_text()),
              'fileVerification': after.get('files')}
    if marker['rehearsal']:
        result['publicTLS'] = {'tested': False, 'reason': 'Isolated self-signed rehearsal; browser HTTPS checked separately.'}
    else:
        try:
            with urllib.request.urlopen(marker['origin']+'/_login', timeout=20) as response:
                body = response.read(2*1024*1024)
                result['publicTLS'] = {'tested': True, 'passed': response.status == 200 and
                                      b'personalPasswordForm' in body,
                                      'systemTrustValidated': True}
        except Exception:
            result['publicTLS'] = {'tested': True, 'passed': False,
                                  'reason': 'Public HTTPS/login is not ready; check routing and ACME issuance.'}
    result['passed'] = (result['fullSQLSnapshotMatchesBeforeStartup'] and
                        result['businessSnapshotMatches'] and result['accessMatrixMatches'] and
                        bool(after.get('files', {}).get('passed')) and
                        (marker['rehearsal'] or result['publicTLS'].get('passed')))
    write_json(root/'state/migration-check.json', result)
    if not result['passed']:
        raise RuntimeError('Restored business/access/file checks failed.')
    marker['phase'] = 'checked'; write_json(root/MARKER, marker)
    return result


class Relay(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with socket.create_connection(self.server.upstream, timeout=10) as upstream:
                upstream.settimeout(None)
                while True:
                    ready, _, _ = select.select([self.request, upstream], [], [], 30)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is self.request else self.request).sendall(data)
        except OSError:
            return


class RelayServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False
    # Repeated rehearsals may leave TIME_WAIT sockets after the listener closes.
    allow_reuse_address = True


def cleanup_target(root):
    root = Path(root).resolve(); marker, cfg = load_marker(root)
    if not marker['rehearsal'] or not marker['project'].startswith('tm-migrate-test-'):
        raise ValueError('Automatic cleanup is restricted to marked rehearsal targets.')
    compose(root, 'down', '--volumes', '--remove-orphans', '--timeout', '30')
    for kind in ('container', 'volume', 'network'):
        if run(['docker', kind, 'ls', '-q', '--filter', 'label=com.docker.compose.project='+marker['project']]).strip():
            raise RuntimeError('Rehearsal resources remain after cleanup.')
    shutil.rmtree(root)


def rehearse(bundle, target, report_dir, port, keep=False):
    if not (ROOT/'tests/browser/migration-smoke.mjs').is_file():
        raise ValueError('Browser rehearsal requires the carried tests/browser files.')
    run(['node', '--input-type=module', '-e',
         "import fs from 'node:fs'; import {chromium} from 'playwright'; fs.accessSync(chromium.executablePath());"],
        cwd=ROOT/'tests/browser')
    report_dir = new_directory(report_dir)
    result = {'startedAt': now(), 'passed': False, 'scope': 'Isolated full deployment restored from real backup; loopback HTTPS only.'}
    relay = None; thread = None; restored = None
    try:
        restored = restore_bundle(bundle, target, 'https://127.0.0.1:'+str(port), rehearsal=True, port=port)
        start_target(restored)
        marker, cfg = load_marker(restored)
        result['project'] = marker['project']
        result['restore'] = check_target(restored)
        gateway = compose(restored, 'ps', '-q', 'traefik').decode().strip()
        details = json.loads(run(['docker', 'inspect', gateway]))[0]
        addresses = list(details['NetworkSettings']['Networks'].values())
        address = next(n['IPAddress'] for n in addresses if n['IPAddress'])
        relay = RelayServer(('127.0.0.1', port), Relay)
        relay.upstream = (address, 443)
        thread = threading.Thread(target=relay.serve_forever, daemon=True); thread.start()
        print('Verifying restored login, project history, permissions and attachments over HTTPS.', flush=True)
        with (report_dir/'browser.log').open('wb') as log:
            run(['node', ROOT/'tests/browser/migration-smoke.mjs', restored,
                 report_dir/'browser'], stdout=log)
        browser = json.loads((report_dir/'browser/report.json').read_text())
        if not browser['passed']:
            raise RuntimeError('Restored browser verification failed.')
        result['browser'] = browser
        result['passed'] = True
        for name in ['migration-check.json', 'migration-restored-snapshot.json', 'migration-volume-check.json']:
            shutil.copy2(restored/'state'/name, report_dir/name)
    except Exception as error:
        result['error'] = str(error)
        candidate = Path(target).resolve()
        if (candidate/MARKER).exists() and (candidate/'compose.migration.json').exists():
            try:
                mark, _ = load_marker(candidate)
                if mark['rehearsal']:
                    compose(candidate, 'stop', '--timeout', '30')
                    result['failedCloneStopped'] = True
                    result['project'] = mark['project']
            except Exception:
                result['failedCloneStopped'] = False
    finally:
        if relay:
            relay.shutdown(); relay.server_close()
        if thread:
            thread.join(timeout=5)
        if restored and not keep and result['passed']:
            cleanup_target(restored); result['cleanedUp'] = True
        else:
            result['cleanedUp'] = False
            result['retainedTarget'] = str(Path(target).absolute())
        result['completedAt'] = now()
        write_json(report_dir/'report.json', result)
    if not result['passed']:
        raise RuntimeError('Rehearsal failed. Evidence: '+str(report_dir/'report.json'))
    print('Full migration rehearsal passed: '+str(report_dir/'report.json'), flush=True)
    return result


def passphrase_file(path):
    path = Path(path).absolute()
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size < 24:
        raise ValueError('Use a private regular passphrase file (0600, at least 24 bytes).')
    return path


def seal(bundle, output, key):
    bundle = Path(bundle).resolve(); verify_bundle(bundle)
    key = passphrase_file(key); output = Path(output).absolute()
    if key.is_relative_to(bundle):
        raise ValueError('Store the encryption key outside the migration bundle.')
    if output.exists() or output.is_symlink() or output.is_relative_to(bundle):
        raise ValueError('Encrypted output must be a new file outside the bundle.')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output.parent, suffix='.tar') as temp:
        with tarfile.open(fileobj=temp, mode='w') as archive:
            for path in sorted(bundle.iterdir()):
                archive.add(path, arcname=path.name)
        temp.flush()
        run(['gpg', '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase-file', key,
             '--symmetric', '--cipher-algo', 'AES256', '--s2k-digest-algo', 'SHA256',
             '--s2k-count', '65011712', '--output', output, temp.name])
    output.chmod(0o600)
    print('Encrypted portable archive ready: '+str(output), flush=True)


def unseal(archive, output, key):
    key = passphrase_file(key); output = new_directory(output)
    with tempfile.NamedTemporaryFile(dir=output.parent, suffix='.tar') as temp:
        # GPG must finish integrity verification before any member is extracted.
        run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase-file', key,
             '--decrypt', Path(archive).resolve()], stdout=temp)
        temp.flush(); extract(temp.name, output)
    verify_bundle(output)
    print('Decrypted bundle verified: '+str(output), flush=True)


def keygen(output):
    output = Path(output).absolute()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(secrets.token_urlsafe(48)+'\n')
    print('Encryption passphrase created; store separately from the archive: '+str(output))


def resume_source(bundle):
    manifest = verify_bundle(bundle)
    if manifest['sourceRoot'] != str(ROOT) or config(ROOT)['name'] != manifest['sourceProject']:
        raise ValueError('Resume must run from the original source deployment.')
    snapshot = json.loads((Path(bundle)/'snapshot/manifest.json').read_text())
    if not manifest['leaveSourceStopped']:
        raise ValueError('This export did not request that the source remain stopped.')
    compose(ROOT, 'start', *snapshot['runningServices'])
    print('Original source services resumed. Do not allow both deployments to accept writes.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('export', help='Save exact images and a consistent portable snapshot.')
    p.add_argument('--output', required=True, type=Path); p.add_argument('--leave-stopped', action='store_true')
    p = commands.add_parser('verify', help='Check every bundle checksum and archive path.')
    p.add_argument('bundle', type=Path)
    p = commands.add_parser('restore', help='Restore into a NEW directory and unique Docker project; do not start applications.')
    p.add_argument('bundle', type=Path); p.add_argument('--target', type=Path, required=True)
    p.add_argument('--origin', required=True); p.add_argument('--project')
    for name in ['start', 'check', 'cleanup']:
        p = commands.add_parser(name); p.add_argument('--target', type=Path, required=True)
    p = commands.add_parser('rehearse', help='Restore, check, browser-test and clean an isolated loopback clone.')
    p.add_argument('bundle', type=Path); p.add_argument('--target', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True); p.add_argument('--port', type=int, default=18443)
    p.add_argument('--keep', action='store_true')
    for name in ['seal', 'unseal']:
        p = commands.add_parser(name); p.add_argument('input', type=Path)
        p.add_argument('--output', type=Path, required=True); p.add_argument('--passphrase-file', type=Path, required=True)
    p = commands.add_parser('keygen'); p.add_argument('--output', type=Path, required=True)
    p = commands.add_parser('resume-source'); p.add_argument('bundle', type=Path)
    args = parser.parse_args(); os.umask(0o077)
    if args.command == 'export': export_bundle(args.output, args.leave_stopped)
    elif args.command == 'verify': verify_bundle(args.bundle); print('Bundle checksums and archive paths verified.')
    elif args.command == 'restore': restore_bundle(args.bundle, args.target, args.origin, project=args.project)
    elif args.command == 'start': start_target(args.target)
    elif args.command == 'check': print(json.dumps(check_target(args.target), ensure_ascii=False))
    elif args.command == 'cleanup': cleanup_target(args.target)
    elif args.command == 'rehearse': rehearse(args.bundle, args.target, args.report, args.port, args.keep)
    elif args.command == 'seal': seal(args.input, args.output, args.passphrase_file)
    elif args.command == 'unseal': unseal(args.input, args.output, args.passphrase_file)
    elif args.command == 'keygen': keygen(args.output)
    elif args.command == 'resume-source': resume_source(args.bundle)


if __name__ == '__main__':
    previous_term_handler = signal.signal(signal.SIGTERM, cancel_migration)
    try:
        main()
    except KeyboardInterrupt as error:
        print('Migration cancelled; inspect the private status report for source recovery.', file=sys.stderr)
        sys.exit(128 + getattr(error, 'signum', signal.SIGINT))
    except (ValueError, RuntimeError, OSError, KeyError) as error:
        print('Migration stopped: '+str(error), file=sys.stderr)
        sys.exit(1)
    finally:
        signal.signal(signal.SIGTERM, previous_term_handler)
