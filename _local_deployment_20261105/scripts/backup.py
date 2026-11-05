#!/usr/bin/env python3
"""Back up a quiesced deployment; optionally retain its source stop for migration.

Without arguments this retains the historical backup layout and restart behavior.
--portable also captures the current runnable deployment and verifies every
persistent Compose mount. Images are exported separately by migrate.py.
"""
import argparse
import base64
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = [str(ROOT / 'scripts/compose.sh')]
VOLUMES = ('phorge-conf', 'phorge-files', 'phorge-repo',
           'stargate-redis-data', 'herald-redis-data')
EXCLUDED_PARTS = {'.git', 'node_modules', '__pycache__', '.pytest_cache',
                  '.mypy_cache', '.ruff_cache'}


def command(args, **kwargs):
    # Captured diagnostics must not be reprinted: Compose can interpolate keys.
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read_env(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if line and not line.startswith('#') and '=' in line)


def compose_rows(all_containers=False):
    args = COMPOSE + ['ps'] + (['--all'] if all_containers else [])
    result = command(args + ['--format', 'json'], capture_output=True, text=True)
    # Compose versions emit either one JSON object per line or a JSON array.
    output = result.stdout.strip()
    if not output:
        return []
    if output.startswith('['):
        return json.loads(output)
    return [json.loads(line) for line in output.splitlines()]


def utility_image(root):
    marker = root / '.migration-target.json'
    if marker.exists():
        target = json.loads(marker.read_text())
        image = target.get('utilityImageID')
        if image is not None:
            if not isinstance(image, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
                raise ValueError('Invalid migrated utility image ID.')
            return image
    return json.loads((root / 'vendor/phorge/deploy/acceptance/build-lock.json').read_text())['images']['alpine']


def relative_bind(source, root):
    """Only deployment-owned regular files/directories can become portable."""
    path = Path(source)
    if not path.is_absolute():
        path = root / path
    if path.is_symlink():
        raise ValueError('A persistent bind source cannot itself be a symlink.')
    path = path.resolve(strict=True)
    try:
        relative = path.relative_to(root.resolve())
    except ValueError:
        raise ValueError('A persistent bind source lies outside the deployment.') from None
    if not relative.parts or not (path.is_file() or path.is_dir()):
        raise ValueError('Unsupported persistent bind source.')
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        raise ValueError('A persistent bind source is excluded from portable archives.')
    # Arbitrary historical state can contain raw passwords or session captures.
    if relative.parts[0] == 'state' and not (
            len(relative.parts) >= 2 and relative.parts[1] in {
                'registration', 'maintenance', 'testing-mail', 'mysql-accounts.sql'}):
        raise ValueError('Unreviewed persistent state bind; add an explicit migration policy.')
    if relative.parts[0] in {'backups', 'migrations', 'migration-bundles'}:
        raise ValueError('Backup artifacts cannot be recursively packaged as live state.')
    return relative.as_posix()


def mount_inventory(config, root):
    """Fail before stopping writers if a new persistence type is not covered."""
    project = config.get('name')
    if not isinstance(project, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', project):
        raise ValueError('Invalid Compose project name.')
    volume_definitions = config.get('volumes', {})
    volume_map = {}
    bindings = {}
    socket_services = []
    for service, definition in config['services'].items():
        for mount in definition.get('volumes', []):
            kind = mount.get('type')
            if kind == 'tmpfs':
                continue
            if kind == 'volume':
                logical = mount.get('source')
                if logical not in (*VOLUMES, 'phorge-db'):
                    raise ValueError('Unreviewed persistent volume; add an explicit migration policy.')
                spec = volume_definitions.get(logical, {})
                if spec.get('external') or spec.get('driver_opts') or spec.get('driver', 'local') != 'local':
                    raise ValueError('External or custom-driver volumes need a separate migration policy.')
                name = spec.get('name', project + '_' + logical)
                if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', name):
                    raise ValueError('Invalid Docker volume name.')
                row = volume_map.setdefault(logical, {
                    'logicalName': logical, 'sourceName': name,
                    'archive': 'application.sql' if logical == 'phorge-db' else logical + '.tar.gz',
                    'method': 'sql' if logical == 'phorge-db' else 'tar', 'services': []})
                row['services'].append(service)
            elif kind == 'bind':
                source = mount.get('source', '')
                if source == '/var/run/docker.sock' and service == 'traefik':
                    socket_services.append(service)
                    continue
                relative = relative_bind(source, root)
                row = bindings.setdefault(relative, {
                    'source': relative, 'archive': 'deployment-private.tar.gz', 'mounts': []})
                row['mounts'].append({'service': service, 'target': mount['target'],
                                      'readOnly': bool(mount.get('read_only'))})
            else:
                raise ValueError('Unsupported Compose mount type.')
    if set(volume_map) != {*VOLUMES, 'phorge-db'}:
        raise ValueError('The expected persistent deployment volumes are incomplete.')
    return {
        'sourceProject': project,
        'volumeMap': [volume_map[name] for name in sorted(volume_map)],
        'bindMounts': [bindings[name] for name in sorted(bindings)],
        'excludedHostResources': ([{'source': '/var/run/docker.sock',
                                   'reason': 'Host Docker API socket; recreate on the target.'}]
                                  if socket_services else []),
    }


def source_services(config, rows):
    images = {}
    services = []
    for name, definition in sorted(config['services'].items()):
        reference = definition.get('image')
        if not isinstance(reference, str) or not reference:
            raise ValueError('Every service must have an explicit local image.')
        if reference not in images:
            result = command(['docker', 'image', 'inspect', reference], capture_output=True, text=True)
            image = json.loads(result.stdout)[0]
            images[reference] = {'imageID': image['Id'], 'architecture': image['Architecture'],
                                 'os': image['Os'], 'variant': image.get('Variant', '')}
        image = images[reference]
        for row in rows:
            if row['Service'] == name:
                actual = command(['docker', 'inspect', '--format', '{{.Image}}', row['ID']],
                                 capture_output=True, text=True).stdout.strip()
                if actual != image['imageID']:
                    raise ValueError('A deployed container differs from its configured local image.')
        services.append({'service': name, 'configuredImage': reference, **image})
    return services


def portable_paths(root, inventory):
    paths = set()
    for name in ('.env', '.env.identity', '.env.dingtalk', '.env.registration',
                 '.public-enabled', '.dingtalk-enabled', '.registration-enabled',
                 '.maintenance-enabled', '.gitignore', '.migration-target.json',
                 'compose.migration.json', 'README.md', 'DEPLOYMENT.md',
                 'team-management-target-architecture.md', 'pyproject.toml',
                 'config', 'scripts', 'docker', 'vendor', 'docs', 'tests',
                 'state/release-manifest.json', 'state/acceptance/release-manifest.json',
                 'state/acceptance/maintenance-build.json'):
        if (root / name).exists():
            paths.add(name)
    paths.update(p.relative_to(root).as_posix() for pattern in ('compose.*.yaml', 'requirements*.txt')
                 for p in root.glob(pattern))
    paths.update(row['source'] for row in inventory['bindMounts'])
    # Do not add a nested member twice when its parent is already included.
    selected = []
    for name in sorted(paths, key=lambda item: (len(PurePosixPath(item).parts), item)):
        if not any(name == old or name.startswith(old + '/') for old in selected):
            selected.append(name)
    return selected


def legacy_paths(root):
    return [p.relative_to(root).as_posix() for p in [
        root / '.env', root / '.env.identity', root / '.env.dingtalk', root / '.env.registration',
        root / '.public-enabled', root / '.dingtalk-enabled', root / '.registration-enabled',
        root / '.maintenance-enabled', root / 'state/registration', root / 'state/maintenance',
        *root.glob('compose.*.yaml'), root / 'config', root / 'scripts', root / 'docker',
        root / 'state/release-manifest.json', root / 'state/acceptance/release-manifest.json',
        root / 'state/acceptance/maintenance-build.json',
        *[root / 'state/acceptance' / name for name in (
            'test-account-cleanup/plan.json', 'test-account-cleanup/result.json',
            'test-account-cleanup/postcheck.json', 'test-account-cleanup/revocation-check.json',
            'private-defaults-configuration.json', 'private-defaults-native.json',
            'real-user-access-smoke.json', 'public-ip-tls.json', 'host-ssh-hardening.json')]]
        if p.exists()]


def archive_deployment(destination, root, paths, portable):
    """Keep ownership/modes; refuse links which would escape a restored tree."""
    def select(member):
        relative = PurePosixPath(member.name)
        if portable and any(part in EXCLUDED_PARTS for part in relative.parts):
            return None
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise ValueError('Special files cannot be packaged as deployment data.')
        if member.issym() or member.islnk():
            source = root / member.name
            target = ((source.parent / member.linkname) if member.issym()
                      else (root / member.linkname)).resolve()
            try:
                target_relative = target.relative_to(root.resolve())
            except ValueError:
                raise ValueError('A deployment link escapes its archive root.') from None
            if portable and any(part in EXCLUDED_PARTS for part in target_relative.parts):
                raise ValueError('A deployment link points into excluded material.')
        return member
    with tarfile.open(destination, 'w:gz', dereference=False) as archive:
        for relative in paths:
            archive.add(root / relative, arcname=relative, filter=select)


def archive_inventory(path):
    rows = []
    with tarfile.open(path, 'r:gz') as archive:
        seen = set()
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/') or '.'
            if name in seen or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts:
                raise ValueError('Unsafe or duplicate volume archive member.')
            seen.add(name)
            row = {'path': name, 'uid': member.uid, 'gid': member.gid,
                   'mode': member.mode & 0o7777}
            if member.isfile():
                digest = hashlib.sha256()
                with archive.extractfile(member) as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(chunk)
                row.update(type='file', size=member.size, sha256=digest.hexdigest())
            elif member.isdir():
                row['type'] = 'directory'
            elif member.issym() or member.islnk():
                target = PurePosixPath(member.linkname)
                if target.is_absolute():
                    raise ValueError('A volume link uses an absolute target.')
                # Resolve lexically relative to its archive location.
                parts = list(PurePosixPath(name).parent.parts) if member.issym() else []
                for part in target.parts:
                    if part == '..':
                        if not parts:
                            raise ValueError('A volume link escapes its archive root.')
                        parts.pop()
                    elif part != '.':
                        parts.append(part)
                row.update(type='symlink' if member.issym() else 'hardlink', target=member.linkname)
            else:
                raise ValueError('A volume contains an unsupported special file.')
            rows.append(row)
    rows.sort(key=lambda row: row['path'])
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'entries': rows, 'entryCount': len(rows), 'digest': digest}


def sqlite_snapshot(root):
    result = {}
    for name in ('state/registration/registrations.sqlite3', 'state/maintenance/maintenance.sqlite3'):
        source = root / name
        if not source.exists():
            continue
        with tempfile.TemporaryDirectory(prefix='migration-sqlite-') as temporary:
            copy = Path(temporary) / source.name
            for suffix in ('', '-wal', '-shm'):
                original = Path(str(source) + suffix)
                if original.exists():
                    shutil.copyfile(original, Path(str(copy) + suffix))
            connection = sqlite3.connect('file:' + str(copy) + '?mode=ro', uri=True)
            try:
                connection.execute('PRAGMA query_only=ON')
                if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                    raise ValueError('A required SQLite database failed its integrity check.')
                tables = {}
                names = [row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                for table in names:
                    quoted = '"' + table.replace('"', '""') + '"'
                    hashes = []
                    for row in connection.execute('SELECT * FROM ' + quoted):
                        encoded = json.dumps(row, separators=(',', ':'), ensure_ascii=True,
                            default=lambda value: {'blob': base64.b64encode(value).decode()}).encode()
                        hashes.append(hashlib.sha256(encoded).hexdigest())
                    hashes.sort()
                    tables[table] = {'count': len(hashes),
                                     'digest': hashlib.sha256(('\n'.join(hashes)).encode()).hexdigest()}
                result[name] = {'integrity': 'ok', 'tables': tables}
            finally:
                connection.close()
    return result


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def interrupted(signum, frame):
    raise KeyboardInterrupt('Backup interrupted')


def backup(args):
    root = ROOT
    settings = read_env(root / '.env')
    namespace = settings.get('PHORGE_DB_NAMESPACE', 'phabricator')
    if not re.fullmatch(r'[A-Za-z0-9_]{1,44}', namespace):
        raise ValueError('Invalid database namespace.')
    config = json.loads(command(COMPOSE + ['config', '--format', 'json'],
                                capture_output=True, text=True).stdout)
    inventory = mount_inventory(config, root)
    services = []
    rows = compose_rows(all_containers=True)
    running = sorted({row['Service'] for row in rows
                      if row['State'] == 'running' and row['Service'] != 'mysql'})
    if not any(row['Service'] == 'mysql' and row['State'] == 'running' for row in rows):
        raise ValueError('MySQL must already be running; no service was changed.')
    if args.portable:
        services = source_services(config, rows)
        if not (root / 'scripts/migration_probe.php').is_file():
            raise ValueError('The portable read-only database probe is missing.')
    for row in inventory['volumeMap']:
        command(['docker', 'volume', 'inspect', row['sourceName']], stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE)
    alpine = utility_image(root)
    command(['docker', 'image', 'inspect', alpine], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    destination = args.output_dir if args.output_dir is not None else (
        root / 'backups' / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError('The output directory must not exist.')
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.mkdir(mode=0o700)
    paths = portable_paths(root, inventory) if args.portable else legacy_paths(root)
    if args.portable:
        for name in paths:
            if destination == (root / name) or (root / name).is_dir() and destination.is_relative_to(root / name):
                raise ValueError('The output directory overlaps archived deployment material.')
    status = {'passed': False, 'phase': 'locking', 'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'portable': args.portable, 'requestedLeaveStopped': args.leave_stopped,
              'runningServices': running, 'sourceServicesLeftStopped': False}
    lock_fd = None
    stop_attempted = False
    completed = False
    manifest = None
    handlers = {signum: signal.signal(signum, interrupted) for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        registration_store = root / 'state/registration'
        registration_store.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_fd = os.open(registration_store / 'approval.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        status['phase'] = 'stopping'
        write_json(destination / 'backup-status.json', status)
        print('Stopping application and identity writers for a consistent backup.', flush=True)
        stop_attempted = bool(running)
        if running:
            command(COMPOSE + ['stop', '--timeout', '60', *running])
        if any(row['State'] == 'running' and row['Service'] in running for row in compose_rows()):
            raise ValueError('Not every source writer stopped; refusing a partial snapshot.')
        status['phase'] = 'capturing'
        write_json(destination / 'backup-status.json', status)
        prefix = namespace + '_'
        query = (f"SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE LEFT(SCHEMA_NAME,{len(prefix)})='{prefix}' "
                 "OR SCHEMA_NAME='phorge' ORDER BY SCHEMA_NAME")
        databases = command(COMPOSE + ['exec', '-T', 'mysql', 'sh', '-ec',
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -NBe "$1"', 'sh', query],
            capture_output=True, text=True).stdout.splitlines()
        if not databases:
            raise ValueError('No application databases found.')
        query = f"SELECT COUNT(*) FROM information_schema.TABLES WHERE LEFT(TABLE_SCHEMA,{len(prefix)})='{prefix}'"
        table_count = int(command(COMPOSE + ['exec', '-T', 'mysql', 'sh', '-ec',
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -NBe "$1"', 'sh', query],
            capture_output=True, text=True).stdout.strip())
        if not table_count:
            raise ValueError('No initialized application tables found.')
        if args.portable:
            with (root / 'scripts/migration_probe.php').open('rb') as source:
                probe = command(COMPOSE + ['run', '--rm', '--no-deps', '-T', '--entrypoint', 'php', 'phorge'],
                                stdin=source, capture_output=True)
            snapshot = json.loads(probe.stdout)
            if snapshot.get('readOnly') is not True or snapshot.get('passed') is False:
                raise ValueError('The portable database probe did not certify a read-only snapshot.')
            write_json(destination / 'source-snapshot.json', snapshot)
        with (destination / 'application.sql').open('wb') as output:
            command(COMPOSE + ['exec', '-T', 'mysql', 'sh', '-ec',
                'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump -uroot --single-transaction --routines --triggers --events --hex-blob --set-gtid-purged=OFF --databases "$@"',
                'sh', *databases], stdout=output, stderr=subprocess.PIPE)
        volume_inventories = {}
        for row in inventory['volumeMap']:
            if row['method'] == 'sql':
                continue
            with (destination / row['archive']).open('wb') as output:
                command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--pull=never',
                         '--mount', 'type=volume,src=' + row['sourceName'] + ',dst=/data,readonly',
                         alpine, 'tar', '-C', '/data', '-czf', '-', '.'], stdout=output, stderr=subprocess.PIPE)
            if args.portable:
                volume_inventories[row['logicalName']] = archive_inventory(destination / row['archive'])
        archive_deployment(destination / 'deployment-private.tar.gz', root, paths, args.portable)
        if args.portable:
            write_json(destination / 'volume-inventories.json', volume_inventories)
            write_json(destination / 'sqlite-snapshot.json', sqlite_snapshot(root))
        hashes = {path.name: sha256(path) for path in destination.iterdir()
                  if path.is_file() and path.name != 'backup-status.json'}
        manifest = {'databases': databases, 'sha256': hashes, 'databaseNamespace': namespace,
                    'applicationTables': table_count, 'mysqlImage': settings['MYSQL_IMAGE'],
                    'volumes': [row['sourceName'] for row in inventory['volumeMap'] if row['method'] == 'tar'],
                    'runningServices': running, 'sourceServicesLeftStopped': bool(args.leave_stopped),
                    'createdAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        if args.portable:
            manifest.update(formatVersion=2, portable=True,
                            sourceOrigin=settings.get('PHORGE_BASE_URI'), sourceRoot=str(root),
                            sourceServices=services, **inventory)
        completed = True
    finally:
        # A second interrupt must not prevent service recovery after failure.
        for signum in handlers:
            signal.signal(signum, signal.SIG_IGN)
        try:
            if stop_attempted and not (completed and args.leave_stopped):
                status['phase'] = 'restarting'
                write_json(destination / 'backup-status.json', status)
                print('Restarting previously running services.', flush=True)
                command(COMPOSE + ['start', *running])
            status.update(passed=completed, phase='complete' if completed else 'failed',
                          sourceServicesLeftStopped=bool(completed and args.leave_stopped),
                          completedAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
            write_json(destination / 'backup-status.json', status)
        finally:
            if lock_fd is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
    if manifest is not None:
        write_json(destination / 'manifest.json', manifest)
    print('Backup complete: ' + str(destination), flush=True)
    if args.leave_stopped:
        print('Source writers remain stopped; resume only after cancelling or completing the cutover.', flush=True)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, help='New private backup directory; must not already exist.')
    parser.add_argument('--leave-stopped', action='store_true', help='Keep source writers stopped after a successful snapshot; failures still restart them.')
    parser.add_argument('--portable', action='store_true', help='Include current runnable sources/vendor, persistent binds, inventories and a read-only database probe.')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        backup(args)
    except KeyboardInterrupt:
        raise SystemExit('Backup interrupted; inspect the private backup-status.json for source recovery state.') from None
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, tarfile.TarError, subprocess.CalledProcessError):
        raise SystemExit('Backup failed; inspect the private backup-status.json and service state. No credential diagnostics were printed.') from None


if __name__ == '__main__':
    main()
