#!/usr/bin/env python3
"""Read-only local prerequisites for a future migration target.

No installation, Docker mutation, port binding, DNS lookup or public request is
performed. Only an explicitly requested, new --report file is written. Exit 0
means no checked prerequisite failed; consult readyForRestore because omitted
target parameters remain pending. Bundle checksums are verified by migrate.py.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit


def command(argv, input_text=None):
    """Return captured stdout; never expose command diagnostics or environment."""
    try:
        result = subprocess.run(argv, input=input_text, text=True,
                                capture_output=True, timeout=15, check=False)
        return result.stdout if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def architecture(value):
    return {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(value.lower(), value.lower())


def origin_port(value):
    if any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError('Whitespace is not allowed in an origin.')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path not in ('', '/')
            or parsed.query or parsed.fragment):
        raise ValueError('Use an HTTPS origin without credentials, path, query or fragment.')
    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if (len(host) > 253 or not re.fullmatch(
                r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
                r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', host)):
            raise ValueError('Use a valid IPv4 address or DNS hostname.') from None
        if host.lower() == 'localhost':
            raise ValueError('A formal target must not use localhost.')
    else:
        if address.version != 4 or address.is_loopback or address.is_unspecified:
            raise ValueError('Use a non-loopback IPv4 address or DNS hostname.')
    port = parsed.port if parsed.port is not None else 443
    if not 1 <= port <= 65535 or port == 80:
        raise ValueError('HTTPS must use a valid port other than the HTTP/ACME port 80.')
    return port


def bundle_metadata(bundle):
    path = Path(bundle).expanduser().resolve()/'bundle.json'
    if not path.is_file() or path.stat().st_size > 8*1024*1024:
        raise ValueError('Missing or oversized bundle manifest.')
    data = json.loads(path.read_text())
    if (data.get('kind') != 'team-management-portable' or data.get('formatVersion') != 1
            or not isinstance(data.get('images'), list) or not data['images']
            or not isinstance(data.get('files'), dict) or not data['files']):
        raise ValueError('Unsupported or incomplete bundle manifest.')
    images = data['images']
    if any(not isinstance(x, dict) or not isinstance(x.get('architecture'), str)
           or not x['architecture'] or x.get('os') != 'linux' for x in images):
        raise ValueError('Bundle must describe Linux image architectures.')
    sizes = [item.get('bytes') if isinstance(item, dict) else None
             for item in data['files'].values()]
    if any(type(size) is not int or size < 0 for size in sizes) or sum(sizes) <= 0:
        raise ValueError('Invalid bundle size inventory.')
    return {'architectures': sorted({architecture(x['architecture']) for x in images}),
            'bundleBytes': sum(sizes), 'minimumFreeBytes': sum(sizes)*2}


def local_docker_endpoint():
    # DOCKER_CONTEXT takes precedence over DOCKER_HOST in the Docker CLI.
    if os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'):
        endpoint = os.environ['DOCKER_HOST']
    else:
        endpoint = command(['docker', 'context', 'inspect', '--format',
                            '{{.Endpoints.docker.Host}}'])
    return bool(endpoint and endpoint.strip().startswith('unix:///'))


def listening_ports():
    """Inspect kernel sockets and running Docker publications without binding."""
    ports = set()
    observed = False
    for path in (Path('/proc/net/tcp'), Path('/proc/net/tcp6')):
        try:
            rows = path.read_text().splitlines()[1:]
        except FileNotFoundError:
            continue
        observed = True
        for row in rows:
            fields = row.split()
            if len(fields) >= 4 and fields[3] == '0A':
                ports.add(int(fields[1].rsplit(':', 1)[1], 16))
    if not observed:
        raise ValueError('Kernel listening sockets could not be inspected.')
    # Docker may publish ports through NAT without a host listening socket.
    output = command(['docker', 'ps', '--format', '{{json .Ports}}'])
    if output is None:
        raise ValueError('Running Docker port publications could not be inspected.')
    for line in output.splitlines():
        published = json.loads(line)
        for start, end in re.findall(r':(\d+)(?:-(\d+))?->', published):
            ports.update(range(int(start), int(end or start)+1))
    return ports


def check_host(*, bundle=None, target=None, origin=None):
    checks = []

    def add(name, status, detail, *, host=False, **extra):
        checks.append({'name': name, 'status': status, 'detail': detail,
                       'hostCheck': host, **extra})

    add('linux', 'pass' if platform.system() == 'Linux' else 'fail',
        'The migration runtime requires Linux.', host=True)
    add('python', 'pass' if sys.version_info >= (3, 12) else 'fail',
        'Python 3.12 or later is required.', host=True,
        version='.'.join(str(n) for n in sys.version_info[:3]))
    add('root', 'pass' if hasattr(os, 'geteuid') and os.geteuid() == 0 else 'fail',
        'Restore requires root to preserve ownership and private files.', host=True)
    try:
        yaml_available = callable(getattr(importlib.import_module('yaml'), 'safe_load', None))
    except (ImportError, OSError):
        yaml_available = False
    add('pyyaml', 'pass' if yaml_available else 'fail', 'PyYAML must be importable.', host=True)
    for name in ('bash', 'gpg'):
        available = shutil.which(name) is not None
        if available:
            available = command([name, '--version']) is not None
        add(name, 'pass' if available else 'fail',
            'Bash is required by the Compose wrapper.' if name == 'bash'
            else 'GnuPG is required to decrypt the portable archive.', host=True)

    docker_local = local_docker_endpoint()
    add('local_docker', 'pass' if docker_local else 'fail',
        'Run on the target host with a local Unix-socket Docker daemon; remote contexts are unsupported.', host=True)
    info = None
    if docker_local:
        raw = command(['docker', 'info', '--format', '{{json .}}'])
        try:
            info = json.loads(raw) if raw else None
            if not isinstance(info, dict):
                info = None
        except ValueError:
            info = None
    daemon_ok = bool(info and info.get('OSType') == 'linux'
                     and architecture(str(info.get('Architecture', ''))) == architecture(platform.machine())
                     and not any('rootless' in x or 'userns' in x
                                 for x in info.get('SecurityOptions', []) or []))
    add('docker_daemon', 'pass' if daemon_ok else 'fail',
        'A reachable local Linux Docker daemon with matching architecture and standard UID mapping is required.', host=True)
    version = command(['docker', 'compose', 'version', '--short'])
    compose_v2 = bool(version and re.fullmatch(r'v?2\.\d+\.\d+(?:[-+][\w.-]+)?\s*', version))
    add('compose_v2', 'pass' if compose_v2 else 'fail', 'Docker Compose v2 is required.', host=True)
    capability = None
    if compose_v2:
        capability = command(['docker', 'compose', '--project-directory', '/', '-f', '-',
                              'config', '--format', 'json'],
                             'name: migration-preflight\nservices:\n  probe:\n'
                             '    image: busybox:latest\n    ports: !override []\n')
    try:
        override_ok = bool(capability and 'probe' in json.loads(capability).get('services', {}))
    except (ValueError, TypeError, AttributeError):
        override_ok = False
    add('compose_override', 'pass' if override_ok else 'fail',
        'Compose must parse the !override tag used by the carried deployment; no image is pulled.', host=True)

    metadata = None
    if bundle is None:
        add('bundle', 'pending', 'Supply a decrypted bundle directory with --bundle.')
    else:
        try:
            metadata = bundle_metadata(bundle)
            arch_ok = metadata['architectures'] == [architecture(platform.machine())]
            add('bundle_architecture', 'pass' if arch_ok else 'fail',
                'All carried images must match the target CPU architecture.', **metadata)
        except (OSError, ValueError, TypeError, AttributeError):
            add('bundle', 'fail', 'The bundle manifest could not be validated; private contents omitted.')

    if target is None:
        add('target', 'pending', 'Supply a new deployment directory with --target.')
    else:
        path = Path(os.path.abspath(Path(target).expanduser()))
        if path.exists() or path.is_symlink():
            add('target', 'fail', 'The target directory must not already exist, including symlinks.')
        else:
            ancestor = path.parent
            while not ancestor.exists() and not ancestor.is_symlink():
                ancestor = ancestor.parent
            writable = ancestor.is_dir() and os.access(ancestor, os.W_OK | os.X_OK)
            add('target', 'pass' if writable else 'fail',
                'The nearest existing parent must be a writable directory; no directory was created.')
            if writable and metadata:
                disks = [('target_disk', ancestor)]
                if daemon_ok and isinstance(info.get('DockerRootDir'), str):
                    disks.append(('docker_disk', Path(info['DockerRootDir'])))
                for name, disk_path in disks:
                    try:
                        free = shutil.disk_usage(disk_path).free
                        add(name, 'pass' if free >= metadata['minimumFreeBytes'] else 'fail',
                            'Free-space floor only: compressed bundle bytes x 2. Expanded images, database, '
                            'temporary files and future growth need additional capacity.',
                            availableBytes=free, minimumFreeBytes=metadata['minimumFreeBytes'])
                    except OSError:
                        add(name, 'fail', 'The relevant local filesystem could not be inspected.')
            elif writable:
                add('target_disk', 'pending', 'A bundle is needed to estimate the free-space floor.')

    if origin is None:
        add('origin', 'pending', 'Supply the eventual HTTPS origin with --origin; ports were not inspected.')
    else:
        try:
            port = origin_port(origin)
            add('origin', 'pass', 'HTTPS origin syntax accepted; DNS and certificate issuance are not tested.')
            if docker_local and daemon_ok:
                try:
                    occupied = listening_ports() & {80, port}
                    add('ports', 'fail' if occupied else 'pass',
                        'Read-only kernel/Docker inspection of required HTTP and HTTPS ports; no socket was bound.',
                        requiredPorts=sorted({80, port}), occupiedPorts=sorted(occupied))
                except (OSError, ValueError, TypeError):
                    add('ports', 'fail', 'Could not inspect required local ports; no port was bound.')
            else:
                add('ports', 'pending', 'Local Docker prerequisites must pass before inspecting publications.')
        except ValueError:
            add('origin', 'fail', 'Use a valid formal HTTPS IPv4/DNS origin without credentials or paths, and a port other than 80.')

    missing = [name for name, value in [('bundle', bundle), ('target', target), ('origin', origin)] if value is None]
    host_passed = all(c['status'] == 'pass' for c in checks if c['hostCheck'])
    passed = not any(c['status'] == 'fail' for c in checks)
    return {'formatVersion': 1, 'checkedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
            'readOnly': True, 'hostChecksPassed': host_passed, 'checksPassed': passed,
            'readyForRestore': passed and not missing and all(c['status'] == 'pass' for c in checks),
            'readyForPublicCutover': False, 'missingParameters': missing,
            'scope': 'Local restore prerequisites only. No bundle payload verification, DNS, public routing, '
                     'ACME issuance, browser login or restore is performed.',
            'nextRequiredChecks': ['migrate.py verify validates the full bundle before restore.',
                                   'Provision disk and RAM for expanded data and service operation.',
                                   'Validate destination DNS, firewall, HTTPS and real login before opening writes.'],
            'checks': checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, help='Decrypted portable bundle directory.')
    parser.add_argument('--target', type=Path, help='Future deployment directory; must not exist.')
    parser.add_argument('--origin', help='Future formal HTTPS origin (IPv4 or DNS).')
    parser.add_argument('--report', type=Path, help='Write a NEW private JSON report; parent must exist.')
    args = parser.parse_args()
    report = check_host(bundle=args.bundle, target=args.target, origin=args.origin)
    encoded = json.dumps(report, ensure_ascii=False, indent=2)+'\n'
    if args.report:
        try:
            fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(encoded)
        except OSError:
            print('Preflight report was not written: use a new file in an existing writable directory.', file=sys.stderr)
            return 2
    print(encoded, end='')
    return 0 if report['checksPassed'] else 1


if __name__ == '__main__':
    sys.exit(main())
