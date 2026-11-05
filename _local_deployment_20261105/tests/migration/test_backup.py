#!/usr/bin/env python3
"""Portable backup safety and failure recovery; never contacts Docker or live data."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('migration_backup', ROOT / 'scripts/backup.py')
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


def configuration(root, project='copied-deployment'):
    mounts = [{'type': 'volume', 'source': name, 'target': '/data/' + name}
              for name in (*backup.VOLUMES, 'phorge-db')]
    mounts += [{'type': 'bind', 'source': str(root / 'scripts'), 'target': '/work/scripts'},
               {'type': 'bind', 'source': str(root / 'state/registration'), 'target': '/data/registration'}]
    return {'name': project, 'services': {'phorge': {'image': 'fixture', 'volumes': mounts},
                                        'mysql': {'image': 'mysql-fixture'}},
            'volumes': {name: {'name': project + '_' + name}
                        for name in (*backup.VOLUMES, 'phorge-db')}}


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='migration-backup-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'deployment'
        self.root.mkdir()
        for path in ['scripts', 'state/registration', 'state/maintenance', 'config',
                     'vendor/phorge/deploy/acceptance', 'tests/browser/node_modules', 'vendor/example/.git']:
            (self.root / path).mkdir(parents=True, exist_ok=True)
        (self.root / '.env').write_text('MYSQL_IMAGE=mysql-fixture\nPHORGE_BASE_URI=https://fixture.invalid/\n')
        (self.root / 'scripts/migration_probe.php').write_text('<?php echo "probe";')
        (self.root / 'vendor/phorge/deploy/acceptance/build-lock.json').write_text(
            json.dumps({'images': {'alpine': 'alpine-fixture'}}))
        (self.root / 'README.md').write_text('Current deployment documentation')

    def test_migrated_copy_uses_saved_utility_image_id_without_original_tag(self):
        self.assertEqual('alpine-fixture', backup.utility_image(self.root))
        marker = self.root / '.migration-target.json'
        image = 'sha256:' + 'a' * 64
        marker.write_text(json.dumps({'utilityImageID': image}))
        self.assertEqual(image, backup.utility_image(self.root))
        marker.write_text(json.dumps({'utilityImageID': 'unexpected:latest'}))
        with self.assertRaises(ValueError):
            backup.utility_image(self.root)

    def test_mounts_resolve_new_project_names_and_sql_volume(self):
        inventory = backup.mount_inventory(configuration(self.root), self.root)
        self.assertEqual('copied-deployment', inventory['sourceProject'])
        volumes = {row['logicalName']: row for row in inventory['volumeMap']}
        self.assertEqual('copied-deployment_phorge-files', volumes['phorge-files']['sourceName'])
        self.assertEqual('application.sql', volumes['phorge-db']['archive'])
        self.assertEqual('sql', volumes['phorge-db']['method'])
        self.assertEqual({'scripts', 'state/registration'},
                         {row['source'] for row in inventory['bindMounts']})

    def test_unreviewed_or_external_volumes_are_rejected(self):
        for modify in ('external', 'driver_opts', 'driver', 'unknown'):
            with self.subTest(modify=modify):
                config = configuration(self.root)
                if modify == 'unknown':
                    config['services']['phorge']['volumes'].append(
                        {'type': 'volume', 'source': 'forgotten-uploads', 'target': '/uploads'})
                else:
                    config['volumes']['phorge-files'][modify] = 'nfs' if modify == 'driver' else True
                with self.assertRaises(ValueError):
                    backup.mount_inventory(config, self.root)

    def test_external_and_sensitive_unreviewed_state_binds_fail(self):
        for path in [self.root.parent, self.root / 'tests/browser/node_modules', self.root / 'state/acceptance']:
            path.mkdir(exist_ok=True)
            with self.subTest(path=str(path)):
                with self.assertRaises(ValueError):
                    backup.relative_bind(path, self.root)
        link = self.root / 'config/outside'
        link.symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            backup.relative_bind(link, self.root)

    def test_only_traefik_docker_socket_is_exempt(self):
        config = configuration(self.root)
        socket = {'type': 'bind', 'source': '/var/run/docker.sock', 'target': '/var/run/docker.sock'}
        config['services']['traefik'] = {'image': 'fixture', 'volumes': [socket]}
        self.assertEqual(1, len(backup.mount_inventory(config, self.root)['excludedHostResources']))
        config['services']['phorge']['volumes'].append(socket)
        with self.assertRaises((ValueError, FileNotFoundError)):
            backup.mount_inventory(config, self.root)

    def test_portable_capture_has_sources_markers_and_private_modes(self):
        (self.root / 'config/private.key').write_text('not-a-real-key')
        (self.root / 'config/private.key').chmod(0o400)
        (self.root / 'tests/browser/node_modules/excluded').write_text('cache')
        (self.root / 'vendor/example/.git/excluded').write_text('git objects')
        (self.root / 'scripts/internal-link').symlink_to('migration_probe.php')
        (self.root / '.migration-target.json').write_text('{}')
        (self.root / 'compose.migration.json').write_text('{}')
        (self.root / 'state/registration/registrations.sqlite3').write_text('archive fixture only')
        (self.root / 'state/old-password.txt').write_text('must not travel')
        inventory = backup.mount_inventory(configuration(self.root), self.root)
        output = self.root.parent / 'capture.tar.gz'
        backup.archive_deployment(output, self.root, backup.portable_paths(self.root, inventory), True)
        with tarfile.open(output) as archive:
            names = set(archive.getnames())
            for required in ['README.md', 'vendor/phorge/deploy/acceptance/build-lock.json',
                             'scripts/migration_probe.php', 'state/registration/registrations.sqlite3',
                             '.migration-target.json', 'compose.migration.json']:
                self.assertIn(required, names)
            self.assertFalse(any('node_modules' in name or '/.git' in name for name in names))
            self.assertNotIn('state/old-password.txt', names)
            self.assertEqual(0o400, archive.getmember('config/private.key').mode)
            self.assertTrue(archive.getmember('scripts/internal-link').issym())

    def test_deployment_symlinks_cannot_escape(self):
        (self.root / 'config/unsafe').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            backup.archive_deployment(self.root.parent / 'bad.tar.gz', self.root, ['config'], True)

    def test_volume_inventory_verifies_bytes_and_ownership(self):
        path = self.root.parent / 'volume.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            entry = tarfile.TarInfo('./file')
            entry.uid = 10001
            entry.gid = 33
            entry.mode = 0o600
            entry.size = 3
            archive.addfile(entry, io.BytesIO(b'abc'))
        inventory = backup.archive_inventory(path)
        self.assertEqual(1, inventory['entryCount'])
        row = inventory['entries'][0]
        self.assertEqual(('file', 10001, 33, 0o600), (row['path'], row['uid'], row['gid'], row['mode']))
        self.assertEqual('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', row['sha256'])

    def test_volume_archive_rejects_traversal_and_escaping_symlink(self):
        for name, link in [('../escape', None), ('file', '../../escape')]:
            path = self.root.parent / 'unsafe-volume.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                entry = tarfile.TarInfo(name)
                if link:
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = link
                archive.addfile(entry)
            with self.assertRaises(ValueError):
                backup.archive_inventory(path)

    def test_sqlite_snapshot_includes_committed_wal_without_exposing_values(self):
        path = self.root / 'state/registration/registrations.sqlite3'
        db = sqlite3.connect(path)
        self.addCleanup(db.close)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE registrations (id INTEGER, secret BLOB)')
        db.execute('INSERT INTO registrations VALUES (?, ?)', (1, b'private-test-value'))
        db.commit()
        result = backup.sqlite_snapshot(self.root)
        entry = result['state/registration/registrations.sqlite3']
        self.assertEqual('ok', entry['integrity'])
        self.assertEqual(1, entry['tables']['registrations']['count'])
        self.assertNotIn('private-test-value', json.dumps(result))
        self.assertEqual(backup.sqlite_snapshot(self.root), result)

    def run_backup(self, leave_stopped=False, failure=None):
        config = configuration(self.root)
        output = self.root.parent / 'output'
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            if 'config' in args:
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps(config))
            if 'stop' in args and failure == 'stop':
                raise subprocess.CalledProcessError(1, args)
            if args[:1] == ['fixture-compose'] and 'run' in args:
                if failure == 'probe':
                    raise subprocess.CalledProcessError(1, args)
                if failure == 'interrupt':
                    raise KeyboardInterrupt()
                return subprocess.CompletedProcess(args, 0, stdout=b'{"readOnly":true,"passed":true}')
            if any('SELECT SCHEMA_NAME' in str(a) for a in args):
                return subprocess.CompletedProcess(args, 0, stdout='phabricator_user\nphorge\n')
            if any('SELECT COUNT(*)' in str(a) for a in args):
                return subprocess.CompletedProcess(args, 0, stdout='522\n')
            if any('mysqldump' in str(a) for a in args):
                if failure == 'dump':
                    raise subprocess.CalledProcessError(1, args)
                kwargs['stdout'].write(b'-- isolated fake dump\n')
            if args[:2] == ['docker', 'run']:
                with tarfile.open(fileobj=kwargs['stdout'], mode='w:gz') as archive:
                    member = tarfile.TarInfo('.')
                    member.type = tarfile.DIRTYPE
                    archive.addfile(member)
            return subprocess.CompletedProcess(args, 0, stdout='')
        rows = [{'Service': 'mysql', 'State': 'running'}, {'Service': 'phorge', 'State': 'running'}]
        with mock.patch.object(backup, 'ROOT', self.root), mock.patch.object(backup, 'COMPOSE', ['fixture-compose']), \
             mock.patch.object(backup, 'compose_rows', side_effect=[rows, []]), \
             mock.patch.object(backup, 'source_services', return_value=[]), \
             mock.patch.object(backup, 'command', side_effect=command), contextlib.redirect_stdout(io.StringIO()):
            args = argparse.Namespace(output_dir=output, portable=True, leave_stopped=leave_stopped)
            if failure:
                with self.assertRaises((subprocess.CalledProcessError, KeyboardInterrupt)):
                    backup.backup(args)
            else:
                backup.backup(args)
        return calls, output

    def test_success_restarts_source_by_default_and_seals_manifest(self):
        calls, output = self.run_backup()
        self.assertIn(['fixture-compose', 'start', 'phorge'], calls)
        manifest = json.loads((output / 'manifest.json').read_text())
        self.assertTrue(manifest['portable'])
        self.assertFalse(manifest['sourceServicesLeftStopped'])
        self.assertEqual(str(self.root), manifest['sourceRoot'])
        self.assertEqual('copied-deployment', manifest['sourceProject'])
        self.assertTrue(all(backup.sha256(output / name) == digest
                            for name, digest in manifest['sha256'].items()))
        self.assertEqual(0o700, output.stat().st_mode & 0o777)

    def test_success_can_keep_original_writers_stopped(self):
        calls, output = self.run_backup(leave_stopped=True)
        self.assertFalse(any('start' in args for args in calls))
        status = json.loads((output / 'backup-status.json').read_text())
        self.assertTrue(status['passed'])
        self.assertTrue(status['sourceServicesLeftStopped'])
        self.assertEqual(['phorge'], status['runningServices'])

    def test_failed_dump_recovers_even_with_leave_stopped(self):
        calls, output = self.run_backup(leave_stopped=True, failure='dump')
        self.assertIn(['fixture-compose', 'start', 'phorge'], calls)
        self.assertFalse((output / 'manifest.json').exists())
        self.assertFalse(json.loads((output / 'backup-status.json').read_text())['passed'])

    def test_partial_stop_failure_recovers_all_original_services(self):
        calls, output = self.run_backup(leave_stopped=True, failure='stop')
        self.assertIn(['fixture-compose', 'start', 'phorge'], calls)
        self.assertFalse((output / 'manifest.json').exists())

    def test_interrupt_recovers_source_and_does_not_seal_partial_backup(self):
        calls, output = self.run_backup(leave_stopped=True, failure='interrupt')
        self.assertIn(['fixture-compose', 'start', 'phorge'], calls)
        self.assertFalse((output / 'manifest.json').exists())


if __name__ == '__main__':
    unittest.main()
