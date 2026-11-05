#!/usr/bin/env python3
"""Regression tests for restored deployment routing and isolation."""
import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('migration_endpoint', ROOT/'scripts/migration_endpoint.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MigrationEndpointTest(unittest.TestCase):
    def fixture(self, root, project):
        files = {
            '.migration-target.json': json.dumps({'project': project, 'sourceRoot': '/old/deployment'}),
            '.env': 'PHORGE_BASE_URI=https://192.0.2.10/\nMYSQL_PASSWORD=test-secret-preserve\n',
            '.env.registration': 'REGISTRATION_ORIGIN=https://192.0.2.10\nREGISTRATION_TRUSTED_PROXY=172.30.10.2\n',
            'scripts/compose.sh': '#!/bin/sh\nexit 0\n',
            'config/phorge-apache.conf': 'trusted 172.29.240.2\n',
            'config/phorge-trusted-proxy.php': "<?php $trusted='172.29.240.2';\n",
            'config/phorge/extensions/TeamEntrySessionGuard.php': "<?php const TRUSTED_PROXY='172.29.240.2';\n",
            'config/phorge/extensions/TeamMaintenanceApplication.php': "<?php const ENDPOINT='http://172.30.20.3:8086/rpc';\n",
            'config/maintenance/service.py': "bind='172.30.20.3'; client='172.30.20.2'\n",
            'config/registration/server.py': "trusted='172.30.10.2'\n",
            'config/notification.json': json.dumps({'servers': [{'listen': '172.29.241.10'}]}),
        }
        for name, text in files.items():
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        (root/'config/traefik').mkdir(parents=True)
        (root/'config/traefik/dynamic.yaml').write_text(yaml.safe_dump({'http': {'middlewares': {
            'strip-identity': {'headers': {'customRequestHeaders': {'X-Auth-User': ''}}},
            'personal-auth': {'forwardAuth': {'address': 'http://stargate:8080/_auth'}},
            'file-private-cache': {'headers': {'customResponseHeaders': {'Cache-Control': 'private'}}},
            'notification-path': {'stripPrefix': {'prefixes': ['/ws']}}}}}))
        (root/'config/traefik/public-static.yaml').write_text(yaml.safe_dump({
            'providers': {'docker': {'exposedByDefault': False}},
            'certificatesResolvers': {'public-ip': {'acme': {
                'caServer': 'https://acme-v02.api.letsencrypt.org/directory',
                'email': 'test@example.invalid', 'storage': '/etc/traefik/acme/production.json'}}}}))
        networks = {'ingress': '172.30.10.0/24', 'web': '172.29.240.0/24',
                    'notify_admin': '172.29.241.0/24', 'notify_client': '172.29.242.0/24',
                    'maintenance': '172.30.20.0/24'}
        config = {'name': 'team-management', 'networks': {
            key: {'name': 'team-management-'+key, 'internal': True, 'ipam': {'config': [{'subnet': value}]}}
            for key, value in networks.items()}, 'volumes': {
                'phorge-conf': {'name': 'team-management_phorge-conf'},
                'phorge-db': {'name': 'team-management_phorge-db'}}, 'services': {}}
        config['networks']['egress'] = {'internal': False}
        for name in ('traefik', 'stargate', 'phorge', 'phorge-migrate', 'registration', 'gorge-notification', 'maintenance'):
            config['services'][name] = {'image': 'example:fixed', 'restart': 'unless-stopped',
                'build': {'context': str(root/'vendor')}, 'environment': {}, 'networks': {}, 'volumes': [],
                'labels': {'traefik.enable': 'true'}}
        config['services']['traefik'].update({'ports': [{'target': 443, 'published': '443', 'host_ip': '0.0.0.0'}],
            'volumes': [{'type': 'bind', 'source': '/var/run/docker.sock', 'target': '/var/run/docker.sock'}],
            'networks': {'web': {'ipv4_address': '172.29.240.2'}, 'ingress': {'ipv4_address': '172.30.10.2'}}})
        config['services']['phorge']['environment'] = {'PHORGE_BASE_URI': 'https://192.0.2.10/',
            'MYSQL_PASS': 'test-secret-preserve'}
        config['services']['phorge-migrate']['restart'] = 'no'
        config['services']['phorge-migrate']['environment'] = {'GORGE_NOTIFICATION_ADMIN_HOST': '172.29.241.10',
            'GORGE_NOTIFICATION_ADMIN_PORT': '22281', 'GORGE_NOTIFICATION_CLIENT_HOST': '192.0.2.10',
            'GORGE_NOTIFICATION_CLIENT_PORT': '443'}
        config['services']['phorge']['volumes'] = [{'type': 'volume', 'source': 'phorge-conf', 'target': '/conf'},
            {'type': 'bind', 'source': '/old/deployment/config/phorge-trusted-proxy.php', 'target': '/proxy.php'}]
        config['services']['stargate']['environment'] = {'TRUSTED_PROXIES': '172.30.10.2/32'}
        config['services']['maintenance']['environment'] = {'MAINTENANCE_BIND_HOST': '172.30.20.3', 'MAINTENANCE_CLIENT_IP': '172.30.20.2'}
        return config

    def prepare(self, root, config, rehearsal=True):
        project = 'tm-migrate-test-aabbccdd' if rehearsal else 'tm-migrate-aabbccdd'
        with patch.object(m, '_source_compose', return_value=copy.deepcopy(config)), \
             patch.object(m, '_docker_networks', return_value=[ipaddress.ip_network('10.192.0.0/16')]):
            return m.prepare_target(root, 'https://127.0.0.1:18443' if rehearsal else 'https://new.example.com',
                                    project, rehearsal, 18443 if rehearsal else None)

    def test_rehearsal_has_private_topology_and_no_docker_socket_or_public_ports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.fixture(root, 'tm-migrate-test-aabbccdd')
            result = self.prepare(root, config)
            actual = json.loads((root/'compose.migration.json').read_text())
            self.assertTrue(all(n['internal'] for n in actual['networks'].values()))
            self.assertTrue(all('ports' not in s for s in actual['services'].values()))
            self.assertNotIn('/var/run/docker.sock', json.dumps(actual))
            self.assertTrue(all('build' not in s for s in actual['services'].values()))
            self.assertEqual(result['relayBindHost'], '127.0.0.1')
            self.assertEqual(result['relayBindPort'], 18443)
            new_proxy = actual['services']['traefik']['networks']['web']['ipv4_address']
            self.assertIn(new_proxy, (root/'config/phorge/extensions/TeamEntrySessionGuard.php').read_text())
            self.assertIn(new_proxy, (root/'config/phorge-apache.conf').read_text())
            self.assertEqual(actual['services']['phorge']['environment']['MYSQL_PASS'], 'test-secret-preserve')
            self.assertEqual(actual['services']['phorge']['volumes'][1]['source'], str(root/'config/phorge-trusted-proxy.php'))
            self.assertIn('MYSQL_PASSWORD=test-secret-preserve', (root/'.env').read_text())
            self.assertEqual((root/'compose.migration.json').stat().st_mode & 0o777, 0o600)
            self.assertIn('compose.migration.json', (root/'scripts/compose.sh').read_text())
            static = yaml.safe_load((root/'config/traefik/public-static.yaml').read_text())
            self.assertEqual(set(static['providers']), {'file'})
            self.assertNotIn('certificatesResolvers', static)
            dynamic = yaml.safe_load((root/'config/traefik/dynamic.yaml').read_text())
            self.assertEqual(set(dynamic['http']['routers']), {'public-http', 'auth', 'exchange', 'phorge', 'phorge-files', 'notification', 'registration'})
            self.assertEqual(dynamic['http']['routers']['phorge']['middlewares'], ['strip-identity@file', 'personal-auth@file'])
            self.assertTrue((root/'config/tls/migration-tm-migrate-test-aabbccdd.crt').is_file())

    def test_real_compose_notification_configuration_belongs_to_migration_role(self):
        # Read the actual reviewed Compose file, whose web/daemon roles consume
        # persisted deployment.json instead of defining notification settings.
        source = yaml.safe_load((ROOT/'compose.core.yaml').read_text())['services']
        self.assertNotIn('GORGE_NOTIFICATION_ADMIN_HOST', source['phorge']['environment'])
        self.assertNotIn('GORGE_NOTIFICATION_ADMIN_HOST', source['phorge-daemon']['environment'])
        self.assertIn('GORGE_NOTIFICATION_ADMIN_HOST', source['phorge-migrate']['environment'])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.fixture(root, 'tm-migrate-test-aabbccdd')
            for role in ('phorge', 'phorge-migrate'):
                config['services'][role]['environment'] = {
                    key: value for key, value in source[role]['environment'].items()
                    if key.startswith('GORGE_NOTIFICATION_')}
            result = self.prepare(root, config)
            generated = json.loads((root/'compose.migration.json').read_text())
            administrator = generated['services']['phorge-migrate']['environment']['GORGE_NOTIFICATION_ADMIN_HOST']
            self.assertEqual(result['notificationServers'][0]['host'], administrator)
            self.assertNotEqual(administrator, source['phorge-migrate']['environment']['GORGE_NOTIFICATION_ADMIN_HOST'])
            self.assertEqual(result['notificationServers'][1]['host'], '127.0.0.1')
            self.assertEqual(result['notificationServers'][1]['port'], 18443)

    def test_production_has_public_gateway_and_new_acme_name(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.fixture(root, 'tm-migrate-aabbccdd')
            result = self.prepare(root, config, rehearsal=False)
            actual = json.loads((root/'compose.migration.json').read_text())
            self.assertFalse(actual['networks']['egress']['internal'])
            self.assertEqual([p['published'] for p in actual['services']['traefik']['ports']], ['80', '443'])
            self.assertEqual(actual['services']['stargate']['environment']['AUTH_HOST'], 'new.example.com')
            self.assertEqual(actual['services']['registration']['environment']['REGISTRATION_ORIGIN'], 'https://new.example.com')
            dynamic = yaml.safe_load((root/'config/traefik/dynamic.yaml').read_text())
            self.assertEqual(dynamic['tls']['stores']['default']['defaultGeneratedCert']['domain']['main'], 'new.example.com')
            self.assertEqual(result['phorgeConfigUpdates']['phabricator.base-uri'], 'https://new.example.com/')

    def test_rehearsal_export_can_be_restored_to_another_rehearsal_or_production(self):
        import shutil
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'first'
            root.mkdir()
            config = self.fixture(root, 'tm-migrate-test-aabbccdd')
            first = self.prepare(root, config)
            template = root/'config/traefik/migration-production-static.yaml'
            self.assertTrue(template.is_file())
            self.assertEqual(template.stat().st_mode & 0o777, 0o600)
            for rehearsal, project, origin in (
                    (True, 'tm-migrate-test-11223344', 'https://127.0.0.1:19443'),
                    (False, 'tm-migrate-55667788', 'https://moved.example.com')):
                destination = Path(temp)/project
                shutil.copytree(root, destination)
                (destination/'.migration-target.json').write_text(json.dumps({
                    'project': project, 'sourceRoot': str(root)}))
                previous = json.loads((destination/'compose.migration.json').read_text())
                with patch.object(m, '_source_compose', return_value=previous), \
                     patch.object(m, '_docker_networks', return_value=[
                         ipaddress.ip_network(value) for value in first['networkSubnets'].values()]):
                    result = m.prepare_target(destination, origin, project, rehearsal)
                dynamic = yaml.safe_load((destination/'config/traefik/dynamic.yaml').read_text())
                static = yaml.safe_load((destination/'config/traefik/public-static.yaml').read_text())
                restored = json.loads((destination/'compose.migration.json').read_text())
                self.assertNotEqual(result['networkSubnets'], first['networkSubnets'])
                self.assertTrue((destination/'config/tls/migration-tm-migrate-test-aabbccdd.crt').is_file())
                if rehearsal:
                    self.assertTrue((destination/('config/tls/migration-'+project+'.crt')).is_file())
                    self.assertIn(project, dynamic['tls']['stores']['default']['defaultCertificate']['certFile'])
                    self.assertNotIn('certificatesResolvers', static)
                    self.assertTrue(all(n['internal'] for n in restored['networks'].values()))
                    self.assertTrue(all(v['restart'] == 'no' for v in restored['services'].values()))
                else:
                    self.assertFalse(restored['networks']['egress']['internal'])
                    self.assertTrue(restored['networks']['web']['internal'])
                    self.assertEqual(restored['services']['phorge']['restart'], 'unless-stopped')
                    self.assertEqual(restored['services']['phorge-migrate']['restart'], 'no')
                    self.assertNotIn('defaultCertificate', dynamic['tls']['stores']['default'])
                    self.assertEqual(dynamic['tls']['stores']['default']['defaultGeneratedCert']['domain']['main'],
                                     'moved.example.com')
                    self.assertEqual(static['certificatesResolvers']['public-ip']['acme']['caServer'],
                                     'https://acme-v02.api.letsencrypt.org/directory')

    def test_legacy_rehearsal_recovers_defaults_from_original_compose_wrapper(self):
        import shutil
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'first'
            root.mkdir()
            original = self.fixture(root, 'tm-migrate-test-aabbccdd')
            self.prepare(root, original)
            destination = Path(temp)/'restored'
            shutil.copytree(root, destination)
            (destination/'config/migration-runtime-defaults.json').unlink()
            (destination/'.migration-target.json').write_text(json.dumps({
                'project': 'tm-migrate-11223344', 'sourceRoot': str(root)}))
            old_rehearsal = json.loads((destination/'compose.migration.json').read_text())
            # The copied .env still overrides the original YAML project name.
            original['name'] = old_rehearsal['name']
            with patch.object(m, '_source_compose', side_effect=[old_rehearsal, original]) as resolve, \
                 patch.object(m, '_docker_networks', return_value=[]):
                prepared = m.prepare_target(destination, 'https://moved.example.com:9443', 'tm-migrate-11223344')
            self.assertEqual(resolve.call_args_list[-1].args, (destination, 'compose.before-migration.sh'))
            restored = json.loads((destination/'compose.migration.json').read_text())
            self.assertFalse(restored['networks']['egress']['internal'])
            self.assertTrue(restored['networks']['web']['internal'])
            self.assertEqual(restored['services']['phorge']['restart'], 'unless-stopped')
            self.assertEqual(restored['services']['phorge-migrate']['restart'], 'no')
            self.assertEqual(prepared['runtimeDefaultsCapturedFrom'], 'original-compose-wrapper')
            self.assertEqual([p['published'] for p in restored['services']['traefik']['ports']], ['80', '9443'])
            self.assertEqual(restored['services']['stargate']['environment']['AUTH_HOST'], 'moved.example.com:9443')
            dynamic = yaml.safe_load((destination/'config/traefik/dynamic.yaml').read_text())
            self.assertEqual(dynamic['http']['middlewares']['public-https']['redirectScheme']['port'], '9443')
            self.assertEqual(prepared['notificationServers'][1]['port'], 9443)
            self.assertEqual((destination/'config/migration-runtime-defaults.json').stat().st_mode & 0o777, 0o600)

    def test_production_reexport_preserves_new_operator_runtime_choices(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original = self.fixture(root, 'tm-migrate-aabbccdd')
            self.prepare(root, original, rehearsal=False)
            changed = json.loads((root/'compose.migration.json').read_text())
            changed['services']['phorge']['restart'] = 'on-failure:3'
            changed['networks']['egress']['internal'] = True
            defaults = m._runtime_defaults(root, changed)
            self.assertEqual(defaults['services']['phorge']['restart'], 'on-failure:3')
            self.assertTrue(defaults['networks']['egress']['internal'])

    def test_https_port_80_is_rejected_before_preparation(self):
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            m._origin('https://new.example.com:80', False, None)

    def test_restored_phorge_configuration_changes_addresses_and_preserves_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.fixture(root, 'tm-migrate-test-aabbccdd')
            prepared = self.prepare(root, config)
            conf = root/'restored-conf'
            conf.mkdir()
            (conf/'local.json').write_text(json.dumps({'mysql.pass': 'preserved-private-secret',
                'phabricator.base-uri': 'https://192.0.2.10/', 'phabricator.allowed-uris': ['https://old.invalid/']}))
            (conf/'local.json').chmod(0o640)
            (conf/'deployment.json').write_text(json.dumps({'gorge.file.token': 'preserved-service-secret',
                'notification.servers': [{'type': 'admin', 'host': '172.29.241.10'}]}))
            m.rewrite_phorge_config(conf, prepared)
            local = json.loads((conf/'local.json').read_text())
            deployment = json.loads((conf/'deployment.json').read_text())
            self.assertEqual(local['mysql.pass'], 'preserved-private-secret')
            self.assertEqual(local['phabricator.base-uri'], 'https://127.0.0.1:18443/')
            self.assertEqual(local['phabricator.allowed-uris'], ['http://phorge/'])
            self.assertEqual(deployment['gorge.file.token'], 'preserved-service-secret')
            self.assertEqual(deployment['notification.servers'][1]['port'], 18443)
            self.assertEqual((conf/'local.json').stat().st_mode & 0o777, 0o640)

    def test_target_markers_and_origins_are_strict(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ValueError):
                m.prepare_target(root, 'https://new.example.com', 'team-management')
            config = self.fixture(root, 'tm-migrate-test-aabbccdd')
            for origin in ('http://127.0.0.1:18443', 'https://user@127.0.0.1:18443',
                           'https://127.0.0.1:18443/path', 'https://127.0.0.1:18443?x=y',
                           'https://new.example.com:18443', 'https://127.0.0.1:443'):
                with self.subTest(origin=origin), self.assertRaises(ValueError):
                    m.prepare_target(root, origin, 'tm-migrate-test-aabbccdd', True)

    def test_external_mounts_and_networks_are_not_silently_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.fixture(root, 'tm-migrate-test-aabbccdd')
            config['networks']['egress']['external'] = True
            with self.assertRaises(ValueError):
                self.prepare(root, config)
            config['networks']['egress'].pop('external')
            config['services']['phorge']['volumes'].append({'type': 'bind', 'source': '/production/data', 'target': '/unsafe'})
            with self.assertRaises(ValueError):
                self.prepare(root, config)

    def test_network_allocator_avoids_occupied_subnets(self):
        occupied = [ipaddress.ip_network('10.192.0.0/11')]
        result = m._allocate_subnets('tm-migrate-test-aabbccdd', ['one', 'two', 'three'], occupied)
        self.assertEqual(len(set(result.values())), 3)
        for subnet in result.values():
            self.assertFalse(ipaddress.ip_network(subnet).overlaps(occupied[0]))


if __name__ == '__main__':
    unittest.main()
