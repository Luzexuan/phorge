#!/usr/bin/env python3
"""Prepare a restored deployment's address and isolated Docker topology.

This module never starts services. It only changes a restore directory carrying
an explicit .migration-target.json marker. Resolved Compose contains credentials
and is deliberately mode 0600. Production and rehearsal use the same file-only
Traefik configuration; neither receives access to the Docker socket.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit

import yaml

PROJECT_RE = re.compile(r'tm-migrate-(?:test-)?[a-f0-9]{8,32}\Z')


def _atomic(path: Path, data: str | bytes, mode: int | None = None) -> None:
    if path.is_symlink():
        raise ValueError('Refusing symlink destination: '+str(path))
    if mode is None:
        mode = (path.stat().st_mode & 0o777) if path.exists() else 0o644
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data.encode() if isinstance(data, str) else data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if line and not line.startswith('#') and '=' in line)


def _update_env(path: Path, values: dict[str, str]) -> None:
    lines = path.read_text().splitlines() if path.exists() else []
    left = dict(values)
    result = []
    for line in lines:
        key = line.split('=', 1)[0] if '=' in line and not line.startswith('#') else None
        if key in values:
            result.append(key+'='+values[key])
            left.pop(key, None)
        else:
            result.append(line)
    result.extend(key+'='+value for key, value in left.items())
    _atomic(path, '\n'.join(result)+'\n', 0o600)


def _origin(value: str, rehearsal: bool, port: int | None) -> tuple[str, str, str, int]:
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.username or parsed.password or
            parsed.query or parsed.fragment or parsed.path not in ('', '/') or
            not parsed.hostname):
        raise ValueError('Use an HTTPS origin without credentials, path, query or fragment.')
    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host)
        if address.version != 4:
            raise ValueError('This deployment currently supports IPv4 or DNS origins.')
    except ValueError:
        if not re.fullmatch(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', host):
            raise ValueError('Invalid origin hostname.') from None
    actual_port = parsed.port or 443
    if port is not None and actual_port != port:
        raise ValueError('The rehearsal port must match the origin port.')
    if not 1 <= actual_port <= 65535:
        raise ValueError('Invalid HTTPS port.')
    if rehearsal and (host != '127.0.0.1' or actual_port < 1024):
        raise ValueError('A rehearsal requires https://127.0.0.1:<unprivileged-port>.')
    if not rehearsal and actual_port == 80:
        raise ValueError('HTTPS port 80 conflicts with the required HTTP/ACME listener.')
    if not rehearsal and host in ('localhost', '127.0.0.1'):
        raise ValueError('Use --rehearsal for a loopback origin.')
    authority = host+((':'+str(actual_port)) if actual_port != 443 else '')
    return 'https://'+authority, host, authority, actual_port


def _docker_networks() -> list[ipaddress.IPv4Network]:
    rows = subprocess.run(['docker', 'network', 'ls', '--format', '{{.ID}}'],
                          text=True, capture_output=True, check=True).stdout.split()
    if not rows:
        return []
    result = subprocess.run(['docker', 'network', 'inspect', *rows],
                            text=True, capture_output=True, check=True)
    occupied = []
    for network in json.loads(result.stdout):
        for item in network.get('IPAM', {}).get('Config', []) or []:
            if item.get('Subnet'):
                subnet = ipaddress.ip_network(item['Subnet'])
                if subnet.version == 4:
                    occupied.append(subnet)
    # Avoid private host routes too, when iproute2 is available. Ignore the
    # default route: all usable subnets overlap 0.0.0.0/0 by definition.
    try:
        routes = subprocess.run(['ip', '-j', '-4', 'route', 'show'],
                                text=True, capture_output=True, check=True)
        for route in json.loads(routes.stdout):
            destination = route.get('dst', 'default')
            if destination != 'default':
                occupied.append(ipaddress.ip_network(destination, strict=False))
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass
    return occupied


def _allocate_subnets(project: str, names: list[str], occupied=None) -> dict[str, str]:
    used = list(_docker_networks() if occupied is None else occupied)
    # Search /24s in 10.192.0.0/10, starting at a deterministic project offset.
    candidates = list(ipaddress.ip_network('10.192.0.0/10').subnets(new_prefix=24))
    offset = int(hashlib.sha256(project.encode()).hexdigest()[:8], 16) % len(candidates)
    result = {}
    for name in names:
        for distance in range(len(candidates)):
            candidate = candidates[(offset+distance) % len(candidates)]
            if all(not candidate.overlaps(existing) for existing in used):
                result[name] = str(candidate)
                used.append(candidate)
                offset = (offset+distance+1) % len(candidates)
                break
        else:
            raise ValueError('No non-overlapping private subnet is available.')
    return result


def _replace_text(value: str, replacements: dict[str, str]) -> str:
    if not replacements:
        return value
    pattern = re.compile(r'(?<![0-9.])('+ '|'.join(re.escape(k) for k in
                         sorted(replacements, key=len, reverse=True))+r')(?![0-9.])')
    return pattern.sub(lambda match: replacements[match.group(1)], value)


def rewrite_addresses(value, replacements: dict[str, str]):
    if isinstance(value, str):
        return _replace_text(value, replacements)
    if isinstance(value, list):
        return [rewrite_addresses(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: rewrite_addresses(item, replacements) for key, item in value.items()}
    return value


def _source_compose(root: Path, script: str = 'compose.sh') -> dict:
    result = subprocess.run(['bash', str(root/'scripts'/script), 'config', '--format', 'json'],
                            cwd=root, capture_output=True, text=True)
    if result.returncode:
        # Compose may include expanded credentials in its errors. Do not echo.
        raise ValueError('Unable to resolve the restored Compose configuration.')
    return json.loads(result.stdout)



def _runtime_defaults(root: Path, config: dict) -> dict:
    """Retain production restart/egress semantics across an isolated rehearsal."""
    path = root/'config/migration-runtime-defaults.json'
    source_is_rehearsal = config.get('name', '').startswith('tm-migrate-test-')
    if path.is_symlink():
        raise ValueError('Refusing a symlink runtime-defaults file.')
    if source_is_rehearsal and path.is_file():
        defaults = json.loads(path.read_text())
    else:
        source = config
        capture = 'source-compose'
        if source_is_rehearsal:
            # Compatibility with rehearsals exported before this metadata was
            # introduced: the untouched original wrapper and YAML overlays are
            # carried in the same archive. Resolve them read-only, never start.
            original = root/'scripts/compose.before-migration.sh'
            if not original.is_file() or original.is_symlink():
                raise ValueError('A rehearsal export lacks its original runtime defaults.')
            if 'compose.migration.json' in original.read_text():
                raise ValueError('The original wrapper does not contain production runtime defaults.')
            # COMPOSE_PROJECT_NAME in the copied .env may still name the
            # rehearsal even though this wrapper resolves original YAML.
            source = _source_compose(root, 'compose.before-migration.sh')
            capture = 'original-compose-wrapper'
        defaults = {'formatVersion': 1, 'capturedFrom': capture,
                    'networks': {name: {'internal': item.get('internal', False)}
                                 for name, item in source.get('networks', {}).items()},
                    'services': {name: {'restart': item.get('restart', 'no')}
                                 for name, item in source.get('services', {}).items()}}
    if (defaults.get('formatVersion') != 1 or
            set(defaults.get('networks', {})) != set(config.get('networks', {})) or
            set(defaults.get('services', {})) != set(config.get('services', {}))):
        raise ValueError('Runtime defaults do not match the restored service/network inventory.')
    if any(not isinstance(item.get('internal'), bool) for item in defaults['networks'].values()):
        raise ValueError('Invalid original network isolation setting.')
    for item in defaults['services'].values():
        value = item.get('restart')
        if not isinstance(value, str) or not re.fullmatch(r'no|always|unless-stopped|on-failure(?::[1-9][0-9]*)?', value):
            raise ValueError('Invalid original service restart policy.')
    _atomic(path, json.dumps(defaults, indent=2)+'\n', 0o600)
    return defaults


def _write_certificate(root: Path, host: str, project: str) -> tuple[str, str]:
    directory = root/'config/tls'
    directory.mkdir(parents=True, exist_ok=True)
    key_name, cert_name = 'migration-'+project+'.key', 'migration-'+project+'.crt'
    key, cert = directory/key_name, directory/cert_name
    if key.exists() or cert.exists():
        raise ValueError('Refusing to overwrite a rehearsal certificate.')
    san = ('IP:' if re.fullmatch(r'[0-9.]+', host) else 'DNS:')+host
    result = subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048',
                             '-sha256', '-days', '7', '-keyout', str(key), '-out', str(cert),
                             '-subj', '/CN='+host, '-addext', 'subjectAltName='+san],
                            capture_output=True)
    if result.returncode:
        raise ValueError('Unable to generate the isolated HTTPS certificate.')
    key.chmod(0o600)
    cert.chmod(0o644)
    return key_name, cert_name


def _gateway_config(root: Path, services: dict, origin: str, host: str,
                    https_port: int, rehearsal: bool, project: str) -> tuple[dict, dict]:
    dynamic = yaml.safe_load((root/'config/traefik/dynamic.yaml').read_text()) or {}
    http = dynamic.setdefault('http', {})
    # Keep the reviewed identity stripping, ForwardAuth and file cache rules.
    middlewares = http.setdefault('middlewares', {})
    for required in ('strip-identity', 'personal-auth', 'file-private-cache', 'notification-path'):
        if required not in middlewares:
            raise ValueError('Required gateway middleware is missing: '+required)
    middlewares['public-https'] = {'redirectScheme': {
        'scheme': 'https', 'port': str(https_port), 'permanent': True}}
    host_rule = 'Host(`'+host+'`)'
    auth = ['strip-identity@file']
    protected = ['strip-identity@file', 'personal-auth@file']
    routers = {
        'public-http': {'rule': host_rule, 'entryPoints': ['web'],
                        'middlewares': ['public-https@file'], 'service': 'noop@internal'},
        'auth': {'rule': host_rule+' && (Path(`/_login`) || Path(`/_send_verify_code`) || '
                 'Path(`/_logout`) || PathPrefix(`/assets`) || Path(`/favicon.ico`))',
                 'priority': 350, 'service': 'stargate', 'middlewares': auth},
        'exchange': {'rule': host_rule+' && Path(`/_session_exchange`) && Method(`GET`)',
                     'priority': 400, 'service': 'stargate', 'middlewares': auth},
        'phorge': {'rule': host_rule, 'priority': 10, 'service': 'phorge', 'middlewares': protected},
        'phorge-files': {'rule': host_rule+' && PathPrefix(`/file/`)', 'priority': 200,
                         'service': 'phorge', 'middlewares': protected+['file-private-cache@file']},
        'notification': {'rule': host_rule+' && PathPrefix(`/ws/`)', 'priority': 100,
                         'service': 'notification', 'middlewares': protected+['notification-path@file']},
    }
    upstreams = {'stargate': 'http://stargate:8080', 'phorge': 'http://phorge:80',
                 'notification': 'http://gorge-notification:22280'}
    if 'registration' in services:
        routers['registration'] = {'rule': host_rule+' && Path(`/_register`)', 'priority': 450,
                                    'service': 'registration', 'middlewares': auth}
        upstreams['registration'] = 'http://registration:8085'
    for name, router in routers.items():
        if name != 'public-http':
            router.update({'entryPoints': ['websecure'], 'tls': {}})
    http['routers'] = routers
    http['services'] = {name: {'loadBalancer': {'servers': [{'url': url}]}}
                        for name, url in upstreams.items()}
    tls = dynamic.setdefault('tls', {})
    tls['options'] = {'default': {'minVersion': 'VersionTLS12'}}
    tls.pop('certificates', None)
    static_path = root/'config/traefik/public-static.yaml'
    static = yaml.safe_load(static_path.read_text()) if static_path.exists() else {}
    static['providers'] = {'file': {'filename': '/etc/traefik/dynamic.yaml', 'watch': True}}
    static['entryPoints'] = {name: {'address': ':'+str(port), 'http': {'aliasHeadersStrategy': 'reject'}}
                             for name, port in (('web', 80), ('websecure', 443), ('ping', 8082))}
    static.update({'ping': {'entryPoint': 'ping'}, 'api': {'dashboard': False},
                   'log': {'level': 'INFO'}, 'accessLog': {'fields': {
                       'headers': {'defaultMode': 'drop'}, 'names': {'RequestPath': 'drop'}}}})
    production_template = root/'config/traefik/migration-production-static.yaml'
    if rehearsal:
        # A rehearsal may itself be exported and carried to another server.
        # Preserve the production resolver outside the active gateway config;
        # it is never mounted or activated by a rehearsal.
        if static.get('certificatesResolvers'):
            _atomic(production_template, yaml.safe_dump(static, sort_keys=False), 0o600)
        key_name, cert_name = _write_certificate(root, host, project)
        tls['stores'] = {'default': {'defaultCertificate': {
            'certFile': '/etc/traefik/tls/'+cert_name, 'keyFile': '/etc/traefik/tls/'+key_name}}}
        static.pop('certificatesResolvers', None)
    else:
        if not static.get('certificatesResolvers') and production_template.is_file():
            if production_template.is_symlink():
                raise ValueError('Refusing a symlink production ACME template.')
            template = yaml.safe_load(production_template.read_text()) or {}
            static['certificatesResolvers'] = template.get('certificatesResolvers', {})
        resolvers = static.get('certificatesResolvers', {})
        if 'public-ip' not in resolvers:
            raise ValueError('The source must contain a configured production ACME resolver.')
        acme = resolvers['public-ip'].get('acme', {})
        if acme.get('caServer') != 'https://acme-v02.api.letsencrypt.org/directory':
            raise ValueError('A production target requires the production ACME resolver.')
        tls['stores'] = {'default': {'defaultGeneratedCert': {
            'resolver': 'public-ip', 'domain': {'main': host}}}}
    return dynamic, static


def prepare_target(root: Path, origin: str, project: str,
                   rehearsal: bool = False, port: int | None = None) -> dict:
    root = Path(root).resolve()
    marker = root/'.migration-target.json'
    if not marker.is_file() or marker.is_symlink():
        raise ValueError('The restored deployment marker is required.')
    marked = json.loads(marker.read_text())
    if (not PROJECT_RE.fullmatch(project) or marked.get('project') != project or
            project.startswith('tm-migrate-test-') != rehearsal):
        raise ValueError('Refusing a non-migration or mismatched target project.')
    origin, host, authority, https_port = _origin(origin, rehearsal, port)
    previous_env = _read_env(root/'.env')
    old_origin = previous_env.get('PHORGE_BASE_URI', '').rstrip('/')
    config = _source_compose(root)
    if not config.get('services') or 'traefik' not in config['services']:
        raise ValueError('No complete gateway deployment was found.')
    services = config['services']
    runtime_defaults = _runtime_defaults(root, config)
    networks = config.get('networks', {})
    if any(item.get('external') for item in networks.values()):
        raise ValueError('External source networks need an explicit migration adapter.')
    subnets = _allocate_subnets(project, sorted(networks))
    replacements = {}
    for name, network in networks.items():
        old_subnets = network.get('ipam', {}).get('config', [])
        for item in old_subnets:
            old_subnet = item.get('subnet')
            if not old_subnet:
                continue
            old = ipaddress.ip_network(old_subnet)
            if old.version != 4 or old.prefixlen != 24:
                raise ValueError('Only IPv4 /24 static source networks are supported.')
            new = ipaddress.ip_network(subnets[name])
            replacements[str(old.network_address)] = str(new.network_address)
            for index in range(1, 255):
                replacements[str(old.network_address+index)] = str(new.network_address+index)
    # Do not rewrite passwords, user directories, SQL or application content.
    changed = []
    eligible = [root/'config/phorge-apache.conf', root/'config/phorge-trusted-proxy.php',
                root/'config/notification.json', *list((root/'config/phorge/extensions').glob('*.php')),
                *list((root/'config/phorge/organization-staging').glob('*.php')),
                root/'config/maintenance/service.py', root/'config/registration/server.py']
    for path in eligible:
        if not path.is_file() or path.is_symlink():
            continue
        original = path.read_text()
        new = _replace_text(original, replacements)
        if new != original:
            _atomic(path, new)
            changed.append(path.relative_to(root).as_posix())
    config = rewrite_addresses(config, replacements)
    services = config['services']
    source_root = Path(marked.get('sourceRoot') or root).resolve()
    for name, service in services.items():
        if service.get('network_mode') or service.get('privileged'):
            raise ValueError('Unsupported host network or privileged service.')
        service.pop('build', None)
        service.pop('container_name', None)
        service['pull_policy'] = 'never'
        service.pop('ports', None)
        service['restart'] = 'no' if rehearsal else runtime_defaults['services'][name]['restart']
        labels = service.setdefault('labels', {})
        for label in list(labels):
            if label.startswith('traefik.'):
                del labels[label]
        labels['org.team-management.migration-project'] = project
        mounts = []
        for mount in service.get('volumes', []):
            if not isinstance(mount, dict):
                raise ValueError('Expected normalized Compose volume definitions.')
            if mount.get('type') == 'bind':
                if mount.get('target') == '/var/run/docker.sock':
                    continue
                source = Path(mount['source']).resolve()
                if source.is_relative_to(root):
                    pass
                elif source.is_relative_to(source_root):
                    source = root/source.relative_to(source_root)
                else:
                    raise ValueError('External bind source is outside the deployment directory.')
                mount['source'] = str(source)
                mount.setdefault('bind', {})['create_host_path'] = False
            elif mount.get('type') != 'volume':
                raise ValueError('Unsupported persistent mount type.')
            mounts.append(mount)
        service['volumes'] = mounts
        env = service.setdefault('environment', {})
        if 'PHORGE_BASE_URI' in env:
            env['PHORGE_BASE_URI'] = origin+'/'
        for key, value in {'GORGE_NOTIFICATION_CLIENT_HOST': host,
                            'GORGE_NOTIFICATION_CLIENT_PORT': str(https_port),
                            'GORGE_NOTIFICATION_CLIENT_PROTOCOL': 'https',
                            'GORGE_NOTIFICATION_CLIENT_PATH': '/ws/'}.items():
            if key in env:
                env[key] = value
    services['stargate']['environment'].update({'AUTH_HOST': authority, 'CALLBACK_ALLOWED_HOSTS': ''})
    if 'registration' in services:
        services['registration']['environment']['REGISTRATION_ORIGIN'] = origin
    for name, network in config.get('networks', {}).items():
        network['name'] = project+'-'+name
        network['ipam'] = {'config': [{'subnet': subnets[name]}]}
        network['internal'] = True if rehearsal else runtime_defaults['networks'][name]['internal']
        network.setdefault('labels', {})['org.team-management.migration-project'] = project
    for name, volume in config.get('volumes', {}).items():
        if volume.get('external'):
            raise ValueError('External source volumes need an explicit migration adapter.')
        volume['name'] = project+'_'+name
        volume.setdefault('labels', {})['org.team-management.migration-project'] = project
    config['name'] = project
    dynamic, static = _gateway_config(root, services, origin, host, https_port, rehearsal, project)
    _atomic(root/'config/traefik/dynamic.yaml', yaml.safe_dump(dynamic, sort_keys=False), 0o644)
    _atomic(root/'config/traefik/public-static.yaml', yaml.safe_dump(static, sort_keys=False), 0o644)
    gateway = services['traefik']
    gateway['command'] = ['--configFile=/etc/traefik/public-static.yaml']
    # File-only routing needs exactly these mounts, independent of old overlays.
    gateway['volumes'] = [
        {'type': 'bind', 'source': str(root/'config/traefik/dynamic.yaml'),
         'target': '/etc/traefik/dynamic.yaml', 'read_only': True},
        {'type': 'bind', 'source': str(root/'config/traefik/public-static.yaml'),
         'target': '/etc/traefik/public-static.yaml', 'read_only': True},
        {'type': 'bind', 'source': str(root/'config/tls'),
         'target': '/etc/traefik/tls', 'read_only': True},
    ]
    if not rehearsal:
        gateway['volumes'].append({'type': 'bind', 'source': str(root/'config/traefik/acme'),
                                   'target': '/etc/traefik/acme'})
        gateway['ports'] = [{'target': 80, 'published': '80', 'host_ip': '0.0.0.0', 'protocol': 'tcp'},
                            {'target': 443, 'published': str(https_port), 'host_ip': '0.0.0.0', 'protocol': 'tcp'}]
    _update_env(root/'.env', {'COMPOSE_PROJECT_NAME': project, 'PHORGE_BASE_URI': origin+'/',
                             'PHORGE_HOST': host, 'AUTH_HOST': authority,
                             'AUTH_ROUTER_HOST': host, 'CALLBACK_ALLOWED_HOSTS': '',
                             'PUBLIC_HTTPS_PORT': str(https_port)})
    if (root/'.env.registration').exists():
        _update_env(root/'.env.registration', {'REGISTRATION_ORIGIN': origin})
    compose_path = root/'compose.migration.json'
    _atomic(compose_path, json.dumps(config, indent=2)+'\n', 0o600)
    wrapper = root/'scripts/compose.sh'
    if not (root/'scripts/compose.before-migration.sh').exists():
        _atomic(root/'scripts/compose.before-migration.sh', wrapper.read_bytes(), 0o700)
    _atomic(wrapper, '#!/usr/bin/env bash\nset -euo pipefail\ncd "$(dirname "$0")/.."\n'
                    'exec docker compose --project-name '+project+' --file compose.migration.json "$@"\n', 0o700)
    notification_env = services.get('phorge-migrate', {}).get('environment', {})
    admin_host = notification_env.get('GORGE_NOTIFICATION_ADMIN_HOST')
    if not admin_host:
        raise ValueError('The migration role must define the notification administrator endpoint.')
    notification = [{'type': 'admin', 'host': admin_host,
                     'port': int(notification_env.get('GORGE_NOTIFICATION_ADMIN_PORT', 22281)), 'protocol': 'http'},
                    {'type': 'client', 'host': host, 'port': https_port, 'protocol': 'https', 'path': '/ws/'}]
    result = {'formatVersion': 1, 'project': project, 'origin': origin, 'oldOrigin': old_origin,
              'rehearsal': rehearsal, 'composeFile': str(compose_path), 'composeWrapper': str(wrapper),
              'networkSubnets': subnets, 'networkNames': {name: item['name'] for name, item in config['networks'].items()},
              'volumeNames': {name: item['name'] for name, item in config.get('volumes', {}).items()},
              'ipReplacements': replacements, 'modifiedRuntimeFiles': changed,
              'runtimeDefaultsFile': 'config/migration-runtime-defaults.json',
              'runtimeDefaultsCapturedFrom': runtime_defaults['capturedFrom'],
              'phorgeConfigUpdates': {'phabricator.base-uri': origin+'/',
                                      'phabricator.allowed-uris': ['http://phorge/']},
              'notificationServers': notification, 'dockerSocketMounted': False,
              'relayTargetService': 'traefik' if rehearsal else None,
              'relayTargetPort': 443 if rehearsal else None,
              'relayBindHost': '127.0.0.1' if rehearsal else None,
              'relayBindPort': https_port if rehearsal else None}
    _atomic(root/'migration-endpoint.json', json.dumps(result, indent=2)+'\n', 0o600)
    return result


def rewrite_phorge_config(directory: Path, prepared: dict) -> list[str]:
    """Update only restored Phorge configuration files before importing the volume."""
    directory = Path(directory)
    if not (directory/'local.json').is_file() or not (directory/'deployment.json').is_file():
        raise ValueError('A complete restored Phorge configuration volume is required.')
    changed = []
    for path in directory.glob('*.json'):
        if path.is_symlink():
            raise ValueError('Refusing a symlink in the restored configuration volume.')
        original = path.read_text()
        value = rewrite_addresses(json.loads(original), prepared['ipReplacements'])
        if path.name == 'local.json':
            value.update(prepared['phorgeConfigUpdates'])
            if 'notification.servers' in value:
                value['notification.servers'] = prepared['notificationServers']
        if path.name == 'deployment.json':
            value['notification.servers'] = prepared['notificationServers']
        data = json.dumps(value, indent=2, ensure_ascii=False)+'\n'
        if data != original:
            owner = path.stat()
            _atomic(path, data, owner.st_mode & 0o777)
            os.chown(path, owner.st_uid, owner.st_gid)
            changed.append(path.name)
    return changed
