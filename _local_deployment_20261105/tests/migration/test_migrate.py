import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import shutil
import signal
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('migrate', ROOT/'scripts/migrate.py')
migrate = importlib.util.module_from_spec(spec); spec.loader.exec_module(migrate)


def archive_with(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w') as archive:
        for name, kind, link in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.linkname = link
            archive.addfile(member)
    data.seek(0)
    return tarfile.open(fileobj=data, mode='r:')


class MigrationTests(unittest.TestCase):
    def test_regular_files_and_internal_bin_links_are_supported(self):
        with archive_with([('scripts/run.php', tarfile.REGTYPE, ''),
                           ('bin/run', tarfile.SYMTYPE, '../scripts/run.php')]) as archive:
            migrate.validate_archive(archive)

    def test_traversal_and_external_links_are_rejected(self):
        for name, kind, link in [('../escape', tarfile.REGTYPE, ''),
                                 ('/escape', tarfile.REGTYPE, ''),
                                 ('a', tarfile.SYMTYPE, '../outside'),
                                 ('a', tarfile.LNKTYPE, '/outside'),
                                 ('socket', tarfile.CHRTYPE, '')]:
            with self.subTest(name=name, link=link), archive_with([(name, kind, link)]) as archive:
                with self.assertRaises(ValueError): migrate.validate_archive(archive)

    def test_link_chain_escape_is_rejected_before_extraction(self):
        entries = [('a', tarfile.SYMTYPE, '.'), ('a/b', tarfile.SYMTYPE, '../outside'),
                   ('a/b/payload', tarfile.REGTYPE, '')]
        for ordered in [entries, list(reversed(entries))]:
            with archive_with(ordered) as archive:
                with self.assertRaises(ValueError): migrate.validate_archive(archive)

    def test_duplicate_normalized_archive_members_are_rejected(self):
        with archive_with([('a', tarfile.REGTYPE, ''), ('./a', tarfile.REGTYPE, '')]) as archive:
            with self.assertRaises(ValueError): migrate.validate_archive(archive)

    def test_parent_component_cannot_hide_link_traversal(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE]:
            with archive_with([('a', tarfile.SYMTYPE, '.'),
                               ('b', kind, 'a/../outside')]) as archive:
                with self.assertRaises(ValueError): migrate.validate_archive(archive)

    def test_snapshot_detects_rows_schema_and_permissions_not_only_names(self):
        before = {'tables': {'project.project': {'rows': 1, 'dataSHA256': 'a', 'schemaSHA256': 's'}},
                  'authorization': {'projectSHA256': 'x'}}
        self.assertTrue(migrate.snapshot_equal(before, before))
        for mutated in [
                {**before, 'tables': {'project.project': {'rows': 1, 'dataSHA256': 'b', 'schemaSHA256': 's'}}},
                {**before, 'authorization': {'projectSHA256': 'y'}}]:
            self.assertFalse(migrate.snapshot_equal(before, mutated))

    def test_existing_target_and_symlink_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'existing'; target.mkdir()
            (target/'keep').write_text('original')
            with self.assertRaises(ValueError): migrate.new_directory(target)
            link = Path(directory)/'link'; link.symlink_to(target)
            with self.assertRaises(ValueError): migrate.new_directory(link)
            self.assertEqual((target/'keep').read_text(), 'original')

    def test_encryption_requires_private_non_symlink_key(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory)/'key'; key.write_bytes(b'x'*32); key.chmod(0o600)
            self.assertEqual(migrate.passphrase_file(key), key)
            key.chmod(0o644)
            with self.assertRaises(ValueError): migrate.passphrase_file(key)
            key.chmod(0o600)
            link = Path(directory)/'link'; link.symlink_to(key)
            with self.assertRaises(ValueError): migrate.passphrase_file(link)

    def fake_export(self, directory, *, outcome=None, backup_status=None,
                    final_error=None, leave_stopped=False):
        dest = Path(directory)/'bundle'
        inventory = {'images': [{'id': 'sha256:test'}],
                     'serviceImages': {'phorge': 'sha256:test', 'mysql': 'sha256:mysql'},
                     'sourceProject': 'source-project'}
        def fake_run(argv, **kwargs):
            if argv[:3] == ['docker', 'image', 'save']:
                Path(argv[4]).write_bytes(b'images')
            return b''
        def fake_backup(argv, **kwargs):
            if backup_status is not None:
                snapshot = dest/'snapshot'; snapshot.mkdir()
                (snapshot/'backup-status.json').write_text(json.dumps(backup_status))
            return outcome or {'returncode': 0, 'cancelled': False, 'signal': None, 'exitCode': 0}
        with patch.object(migrate,'require_root'), \
                patch.object(migrate,'image_inventory',return_value=inventory), \
                patch.object(migrate,'source_running_services',return_value=['phorge']), \
                patch.object(migrate,'run',side_effect=fake_run), \
                patch.object(migrate,'run_backup',side_effect=fake_backup), \
                patch.object(migrate,'finalize_export',side_effect=final_error,return_value=dest) as finalize, \
                patch.object(migrate,'compose') as compose:
            error = None
            try:
                result = migrate.export_bundle(dest, leave_stopped=leave_stopped)
            except BaseException as caught:
                error = caught
                result = None
            return dest, error, result, compose.call_args_list, finalize.call_count

    def test_final_bundle_failure_resumes_leave_stopped_source(self):
        with tempfile.TemporaryDirectory() as directory:
            dest, error, _, calls, _ = self.fake_export(directory, leave_stopped=True,
                backup_status={'runningServices': ['phorge'], 'sourceServicesLeftStopped': True},
                final_error=ValueError('bad package'))
            self.assertIsInstance(error, ValueError)
            self.assertEqual([(migrate.ROOT, 'start', 'phorge')], [item.args for item in calls])
            self.assertTrue(json.loads((dest/'export-failure.json').read_text())['sourceResumed'])

    def test_cancelled_backup_recovers_status_services_before_propagating_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            dest, error, _, calls, finalized = self.fake_export(directory, leave_stopped=True,
                backup_status={'runningServices': ['phorge'], 'phase': 'restarting'},
                outcome={'returncode': 1, 'cancelled': True, 'signal': signal.SIGINT, 'exitCode': 130})
            self.assertIsInstance(error, migrate.MigrationCancelled)
            self.assertEqual(signal.SIGINT, error.signum)
            self.assertEqual([(migrate.ROOT, 'start', 'phorge')], [item.args for item in calls])
            self.assertEqual(0, finalized)
            status = json.loads((dest/'export-failure.json').read_text())
            self.assertTrue(status['sourceResumed'])
            self.assertTrue(status['cancelled'])

    def test_late_backup_cancellation_recovers_successful_leave_stopped_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            _, error, _, calls, finalized = self.fake_export(directory, leave_stopped=True,
                backup_status={'runningServices': ['phorge'], 'sourceServicesLeftStopped': True},
                outcome={'returncode': 0, 'cancelled': True, 'signal': signal.SIGTERM, 'exitCode': 143})
            self.assertIsInstance(error, migrate.MigrationCancelled)
            self.assertEqual(signal.SIGTERM, error.signum)
            self.assertEqual([(migrate.ROOT, 'start', 'phorge')], [item.args for item in calls])
            self.assertEqual(0, finalized)

    def test_failed_backup_without_manifest_uses_recorded_parent_running_set(self):
        with tempfile.TemporaryDirectory() as directory:
            dest, error, _, calls, _ = self.fake_export(directory,
                outcome={'returncode': 7, 'cancelled': False, 'signal': None, 'exitCode': 7})
            self.assertIsInstance(error, RuntimeError)
            self.assertEqual([(migrate.ROOT, 'start', 'phorge')], [item.args for item in calls])
            status = json.loads((dest/'export-failure.json').read_text())
            self.assertEqual('export-source-state.json', status['sourceStateEvidence'])
            self.assertEqual(['phorge'], status['sourceServices'])

    def test_unrecognized_backup_service_cannot_expand_recovery_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            dest, error, _, calls, _ = self.fake_export(directory,
                backup_status={'runningServices': ['foreign-service', 'mysql']},
                outcome={'returncode': 1, 'cancelled': False, 'signal': None, 'exitCode': 1})
            self.assertIsInstance(error, RuntimeError)
            self.assertEqual([(migrate.ROOT, 'start', 'phorge')], [item.args for item in calls])
            self.assertEqual(['phorge'], json.loads((dest/'export-failure.json').read_text())['sourceServices'])

    def test_successful_leave_stopped_does_not_restart_source(self):
        with tempfile.TemporaryDirectory() as directory:
            dest, error, result, calls, finalized = self.fake_export(directory, leave_stopped=True,
                backup_status={'runningServices': ['phorge'], 'sourceServicesLeftStopped': True})
            self.assertIsNone(error)
            self.assertEqual(dest, result)
            self.assertEqual([], calls)
            self.assertEqual(1, finalized)

    def test_sigterm_while_finalizing_unwinds_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            _, error, _, calls, _ = self.fake_export(directory, leave_stopped=True,
                backup_status={'runningServices': ['phorge'], 'sourceServicesLeftStopped': True},
                final_error=migrate.MigrationCancelled(signal.SIGTERM))
            self.assertIsInstance(error, migrate.MigrationCancelled)
            self.assertEqual([(migrate.ROOT, 'start', 'phorge')], [item.args for item in calls])

    def test_recovery_ignores_further_signals_and_restores_caller_handlers(self):
        before = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
        with tempfile.TemporaryDirectory() as directory:
            def recover(*args):
                self.assertEqual(signal.SIG_IGN, signal.getsignal(signal.SIGINT))
                self.assertEqual(signal.SIG_IGN, signal.getsignal(signal.SIGTERM))
            with patch.object(migrate, 'compose', side_effect=recover):
                migrate.recover_export_source(Path(directory), {'serviceImages': {'phorge': 'fixture'}}, ['phorge'])
        self.assertEqual(before, {signum: signal.getsignal(signum) for signum in before})

    def test_source_capture_does_not_include_previously_stopped_or_mysql_services(self):
        rows = [ {'Service': 'phorge', 'State': 'running'},
                 {'Service': 'mysql', 'State': 'running'},
                 {'Service': 'maintenance', 'State': 'exited'}]
        with patch.object(migrate, 'compose', return_value=json.dumps(rows).encode()):
            names = migrate.source_running_services({'serviceImages': {'phorge': 'x', 'mysql': 'y', 'maintenance': 'z'}})
            self.assertEqual(['phorge'], names)
        rows.append({'Service': 'foreign-service', 'State': 'running'})
        with patch.object(migrate, 'compose', return_value=json.dumps(rows).encode()):
            with self.assertRaises(ValueError):
                migrate.source_running_services({'serviceImages': {'phorge': 'x', 'mysql': 'y'}})

    @unittest.skipUnless(shutil.which('gpg'), 'GnuPG is required for encrypted bundle tests')
    def test_encryption_roundtrip_and_corruption_never_extracts_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory/'source'; source.mkdir()
            (source/'payload').write_bytes(b'isolated migration fixture\0\xff')
            key = directory/'key'; migrate.keygen(key)
            with self.assertRaises(FileExistsError): migrate.keygen(key)
            encrypted = directory/'bundle.gpg'
            with patch.object(migrate, 'verify_bundle', return_value={}):
                migrate.seal(source, encrypted, key)
                recovered = directory/'recovered'
                migrate.unseal(encrypted, recovered, key)
                self.assertEqual((source/'payload').read_bytes(), (recovered/'payload').read_bytes())
                corrupted = directory/'corrupted.gpg'
                data = bytearray(encrypted.read_bytes()); data[-10] ^= 1
                corrupted.write_bytes(data)
                rejected = directory/'rejected'
                with self.assertRaises(RuntimeError): migrate.unseal(corrupted, rejected, key)
                self.assertEqual(list(rejected.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
