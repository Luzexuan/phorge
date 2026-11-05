#!/usr/bin/env python3
"""Verify Apache peer trust and live RPC header rejection without creating users."""
import datetime
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = [str(ROOT / 'scripts/compose.sh')]
TRUSTED = '172.29.240.2'
NETWORK = 'team-management-web'
checks = []


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                          check=True, timeout=30, **kwargs)


def check(name, passed):
    checks.append({'name': name, 'passed': bool(passed)})
    print(('PASS ' if passed else 'FAIL ') + name, flush=True)
    if not passed:
        raise RuntimeError(name)


def container(service):
    return run(COMPOSE + ['ps', '-q', service]).stdout.strip()


traefik = container('traefik')
phorge = container('phorge')
conduit = container('gorge-conduit')
edge = json.loads(run(['docker', 'inspect', traefik]).stdout)[0]
if edge['NetworkSettings']['Networks'][NETWORK]['IPAddress'] != TRUSTED:
    raise SystemExit('Recreate the gateway on its fixed web address before verification.')

fixture = 'team-management-proxy-check-' + secrets.token_hex(4)
try:
    cli = run(['docker', 'exec', phorge, 'php', '-r',
               '$_SERVER = array("REMOTE_ADDR"=>"127.0.0.1",'
               '"HTTP_X_AUTH_USER"=>"cli-context");'
               'require "/etc/phorge/trusted-proxy.php";'
               'echo json_encode($_SERVER);'])
    check('CLI context unchanged', json.loads(cli.stdout)['HTTP_X_AUTH_USER'] == 'cli-context')

    # A disposable Apache endpoint exercises the actual SAPI and socket peer,
    # including a positive request made by the real trusted Traefik container.
    # It has no database, application configuration, accounts or public ports.
    with tempfile.TemporaryDirectory(prefix='proxy-trust-') as directory:
        directory = Path(directory)
        apache_settings = '\n'.join(line for line in (ROOT / 'config/phorge-apache.conf').read_text().splitlines()
                                    if 'SetEnvIfExpr ' in line or 'php_admin_value auto_prepend_file ' in line)
        (directory / 'apache.conf').write_text(
            '<VirtualHost *:80>\nDocumentRoot /var/www/html\n' + apache_settings +
            '\n<Directory /var/www/html>\nRequire all granted\n</Directory>\n</VirtualHost>\n')
        (directory / 'index.php').write_text(
            '<?php header("Content-Type: application/json");'
            'echo json_encode(array_intersect_key($_SERVER, array_flip(array('
            '"REMOTE_ADDR","HTTPS","HTTP_X_AUTH_USER","HTTP_X_AUTH_EMAIL",'
            '"HTTP_X_AUTH_SCOPES","HTTP_X_FORWARDED_USER","HTTP_X_SERVICE_TOKEN"))));')
        (directory / 'index.php').chmod(0o644)
        image = json.loads(run(['docker', 'inspect', phorge]).stdout)[0]['Config']['Image']
        run(['docker', 'run', '-d', '--name', fixture, '--network', NETWORK,
             '--memory', '128m', '--cpus', '0.5', '--pids-limit', '64',
             '--security-opt', 'no-new-privileges:true',
             '--mount', f'type=bind,src={directory}/apache.conf,dst=/etc/apache2/sites-available/000-default.conf,readonly',
             '--mount', f'type=bind,src={directory}/index.php,dst=/var/www/html/index.php,readonly',
             '--mount', f'type=bind,src={ROOT}/config/phorge-trusted-proxy.php,dst=/etc/phorge/trusted-proxy.php,readonly',
             '--entrypoint', 'apache2-foreground', image])
        for attempt in range(20):
            ready = subprocess.run(['docker', 'exec', fixture, 'curl', '-fsS', '--max-time', '2',
                                    'http://127.0.0.1/'], capture_output=True, text=True)
            if ready.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError('Disposable Apache endpoint did not become ready')

        for separator, label in (('-', 'canonical'), ('_', 'underscore'), ('.', 'dot')):
            headers = [separator.join(parts.split('-')) + ':review-value' for parts in
                       ('X-Auth-User', 'X-Auth-Email', 'X-Auth-Scopes', 'X-Forwarded-User')]
            headers += ['X-Forwarded-For:' + TRUSTED, 'X-Forwarded-Proto:https',
                        'X-Service-Token:unrelated-rpc-token']
            args = ['docker', 'exec', fixture, 'curl', '-fsS', '--max-time', '5']
            for header in headers:
                args += ['-H', header]
            data = json.loads(run(args + ['http://127.0.0.1/']).stdout)
            check('untrusted Apache ' + label + ' identity and TLS rejected',
                  not any(key.startswith('HTTP_X_AUTH_') or key == 'HTTP_X_FORWARDED_USER'
                          for key in data) and data.get('HTTPS', 'off') != 'on'
                  and data.get('HTTP_X_SERVICE_TOKEN') == 'unrelated-rpc-token')

        test_ip = json.loads(run(['docker', 'inspect', fixture]).stdout)[0]['NetworkSettings']['Networks'][NETWORK]['IPAddress']
        positive = json.loads(run(['docker', 'exec', traefik, 'wget', '-qO-', '-T', '5',
                                  '--header=X-Auth-User:trusted-context', '--header=X-Forwarded-Proto:https',
                                  'http://' + test_ip + '/']).stdout)
        check('trusted Apache socket peer retains identity and TLS',
              positive.get('REMOTE_ADDR') == TRUSTED and positive.get('HTTP_X_AUTH_USER') == 'trusted-context'
              and positive.get('HTTPS') == 'on')

    for header, label in (('X-Auth-User', 'canonical'), ('X_Auth_User', 'underscore'), ('X.Auth.User', 'dot')):
        response = run(['docker', 'exec', conduit, 'wget', '-qO-', '-T', '5',
                        '--header=' + header + ':proxy-trust-must-not-become-a-user',
                        '--header=X-Forwarded-Proto:https',
                        'http://phorge/auth/login/traefik:traefik/']).stdout
        check('live RPC ' + label + ' identity denied', 'No Traefik Auth identity was found' in response)
finally:
    subprocess.run(['docker', 'rm', '-f', fixture], capture_output=True, text=True, timeout=30)
    os.umask(0o077)
    (ROOT / 'state/proxy-trust-check.json').write_text(json.dumps({
        'verified_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'trusted_peer': TRUSTED, 'checks': checks,
        'scope': 'Apache peer/header boundary and unchanged CLI context; no accounts created',
    }, indent=2) + '\n')
