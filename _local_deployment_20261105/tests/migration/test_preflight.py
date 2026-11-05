#!/usr/bin/env python3
"""Readiness must not confuse missing target details with a usable destination."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('migration_preflight', ROOT/'scripts/migration_preflight.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class PreflightTests(unittest.TestCase):
    @contextlib.contextmanager
    def host(self, *, overrides=None):
        calls = []

        def fake(argv, input_text=None):
            calls.append((argv, input_text))
            key = tuple(argv)
            if overrides and key in overrides:
                return overrides[key]
            if argv[:3] == ['docker', 'context', 'inspect']:
                return 'unix:///var/run/docker.sock\n'
            if argv[:2] == ['docker', 'info']:
                return json.dumps({'OSType': 'linux', 'Architecture': 'amd64',
                                   'DockerRootDir': tempfile.gettempdir(), 'SecurityOptions': ['name=seccomp']})
            if argv[:3] == ['docker', 'compose', 'version']:
                return '2.40.3\n'
            if argv[:2] == ['docker', 'compose'] and 'config' in argv:
                self.assertIn('ports: !override []', input_text)
                return '{"services":{"probe":{"image":"busybox:latest"}}}'
            if argv[:2] == ['docker', 'ps']:
                return ''
            if argv[0] in ('bash', 'gpg') and argv[1] == '--version':
                return 'version available'
            raise AssertionError('Unexpected or mutating command: '+repr(argv))

        with patch.object(m, 'command', side_effect=fake), \
             patch.object(m.platform, 'system', return_value='Linux'), \
             patch.object(m.platform, 'machine', return_value='x86_64'), \
             patch.object(m.os, 'geteuid', return_value=0), \
             patch.object(m.shutil, 'which', side_effect=lambda name: '/usr/bin/'+name), \
             patch.dict(os.environ, {}, clear=True):
            yield calls

    def bundle(self, root, arch='amd64', size=1000):
        root.mkdir()
        (root/'bundle.json').write_text(json.dumps({'kind': 'team-management-portable',
            'formatVersion': 1, 'images': [{'architecture': arch, 'os': 'linux'}],
            'files': {'images.tar.gz': {'bytes': size}}}))
        return root

    def test_missing_parameters_are_pending_without_port_queries(self):
        with self.host() as calls, patch.object(m, 'listening_ports', side_effect=AssertionError('Port probe')):
            report = m.check_host()
        self.assertTrue(report['hostChecksPassed'])
        self.assertTrue(report['checksPassed'])
        self.assertFalse(report['readyForRestore'])
        self.assertFalse(report['readyForPublicCutover'])
        self.assertEqual(report['missingParameters'], ['bundle', 'target', 'origin'])
        self.assertFalse(any(argv[:2] == ['docker', 'ps'] for argv, _ in calls))

    def test_known_target_can_pass_only_local_prerequisites_without_creating_directory(self):
        with tempfile.TemporaryDirectory() as tmp, self.host(), patch.object(m, 'listening_ports', return_value=set()):
            root = Path(tmp); bundle = self.bundle(root/'bundle'); target = root/'new'/'deployment'
            report = m.check_host(bundle=bundle, target=target, origin='https://new.example.invalid:9443')
            self.assertTrue(report['readyForRestore'])
            self.assertFalse(report['readyForPublicCutover'])
            self.assertFalse((root/'new').exists())
            self.assertIn('No bundle payload verification', report['scope'])

    def test_cpu_mismatch_or_invalid_size_inventory_blocks_readiness(self):
        with tempfile.TemporaryDirectory() as tmp, self.host():
            bundle = self.bundle(Path(tmp)/'bundle', arch='arm64')
            report = m.check_host(bundle=bundle)
            self.assertFalse(report['checksPassed'])
            self.assertEqual(m.architecture('aarch64'), 'arm64')
            data = json.loads((bundle/'bundle.json').read_text())
            data['files']['images.tar.gz']['bytes'] = -1
            (bundle/'bundle.json').write_text(json.dumps(data))
            self.assertFalse(m.check_host(bundle=bundle)['checksPassed'])

    def test_existing_directory_file_and_dangling_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, self.host():
            root = Path(tmp); file = root/'occupied'; file.write_text('retained')
            link = root/'link'; link.symlink_to(root/'absent')
            for path in (root, file, link):
                report = m.check_host(target=path)
                self.assertFalse(report['checksPassed'])
            self.assertEqual(file.read_text(), 'retained')
            self.assertTrue(link.is_symlink())

    def test_full_disk_and_file_ancestor_are_rejected_without_writes(self):
        with tempfile.TemporaryDirectory() as tmp, self.host():
            root = Path(tmp); bundle = self.bundle(root/'bundle', size=1000)
            class Disk:
                free = 1999
            with patch.object(m.shutil, 'disk_usage', return_value=Disk()):
                report = m.check_host(bundle=bundle, target=root/'new')
            self.assertFalse(report['checksPassed'])
            self.assertIn('floor only', next(c for c in report['checks'] if c['name']=='target_disk')['detail'])
            block = root/'file'; block.write_text('retained')
            self.assertFalse(m.check_host(target=block/'new')['checksPassed'])
            self.assertFalse((root/'new').exists())

    def test_origin_rejects_credentials_non_https_paths_and_conflicting_ports(self):
        invalid = ['http://example.com', 'https://example.com/path', 'https://user:secret@example.com',
                   'https://@example.com', 'https://example.com:80', 'https://example.com:0',
                   'https://example.com:65536', 'https://example.com?query=secret',
                   'https://127.0.0.1:18443', 'https://[::1]', 'https://example.com\n']
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.origin_port(value)
        self.assertEqual(m.origin_port('https://example.com/'), 443)
        self.assertEqual(m.origin_port('https://192.0.2.10:9443'), 9443)

    def test_occupied_port_fails_without_binding_or_network_lookup(self):
        with self.host(), patch.object(m, 'listening_ports', return_value={80, 8080}):
            report = m.check_host(origin='https://example.invalid:9443')
        self.assertFalse(report['checksPassed'])
        self.assertEqual(next(c for c in report['checks'] if c['name']=='ports')['occupiedPorts'], [80])

    def test_remote_docker_does_not_query_daemon_or_publish_credentials(self):
        with self.host() as calls, patch.dict(os.environ, {'DOCKER_HOST': 'tcp://name:PRIVATE@remote.invalid:2376'}):
            report = m.check_host(origin='https://example.invalid')
        self.assertFalse(report['hostChecksPassed'])
        self.assertFalse(any(argv[:2] == ['docker', 'info'] for argv, _ in calls))
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_compose_v2_without_override_support_is_rejected(self):
        key = ('docker', 'compose', '--project-directory', '/', '-f', '-', 'config', '--format', 'json')
        with self.host(overrides={key: None}):
            report = m.check_host()
        self.assertTrue(next(c for c in report['checks'] if c['name']=='compose_v2')['status']=='pass')
        self.assertFalse(report['hostChecksPassed'])

    def test_rootless_and_user_namespace_remapping_are_rejected(self):
        key = ('docker', 'info', '--format', '{{json .}}')
        for option in ('name=rootless', 'name=userns'):
            info = {'OSType':'linux', 'Architecture':'amd64','SecurityOptions':[option]}
            with self.subTest(option=option), self.host(overrides={key: json.dumps(info)}):
                self.assertFalse(m.check_host()['hostChecksPassed'])

    def test_kernel_and_docker_nat_port_inventory_is_combined(self):
        text = 'header\n 0: 00000000:01BB 00000000:0000 0A\n 1: 00000000:0016 00000000:0000 01\n'
        with patch.object(m.Path, 'read_text', return_value=text), \
             patch.object(m, 'command', return_value=json.dumps('0.0.0.0:8080-8082->80-82/tcp, [::]:80->80/tcp')):
            self.assertEqual(m.listening_ports(), {443, 80, 8080, 8081, 8082})

    def test_report_refuses_overwrite_and_symlink_and_is_private(self):
        with tempfile.TemporaryDirectory() as tmp, self.host(), contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            root=Path(tmp); report=root/'report.json'
            with patch.object(m.sys, 'argv', ['migration_preflight.py','--report',str(report)]):
                self.assertEqual(m.main(), 0)
                original=report.read_bytes()
                self.assertEqual(report.stat().st_mode & 0o777, 0o600)
                self.assertEqual(m.main(), 2)
                self.assertEqual(report.read_bytes(), original)
            link=root/'link.json'; link.symlink_to(report)
            with patch.object(m.sys, 'argv', ['migration_preflight.py','--report',str(link)]):
                self.assertEqual(m.main(), 2)
                self.assertEqual(report.read_bytes(), original)

    def test_command_errors_and_timeouts_never_return_private_diagnostics(self):
        result=subprocess.CompletedProcess(['docker'], 1, stdout='PRIVATE', stderr='PRIVATE')
        with patch.object(m.subprocess, 'run', return_value=result):
            self.assertIsNone(m.command(['docker','info']))
        with patch.object(m.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['docker'],15)):
            self.assertIsNone(m.command(['docker','info']))


if __name__ == '__main__':
    unittest.main()
