#!/usr/bin/env python3
"""Check running initialization, access boundaries and exact image inventory."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = [str(ROOT/'scripts/compose.sh')]
checks = []

def run(args):
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=40)

def check(name, success, detail=''):
    checks.append(dict(name=name, passed=bool(success), detail=detail))
    print(('PASS ' if success else 'FAIL ') + name + (': '+detail if detail else ''))

result = run(COMPOSE + ['config', '--quiet'])
check('compose configuration', result.returncode == 0)
ids = run(COMPOSE + ['ps', '-aq']).stdout.split()
containers = json.loads(run(['docker', 'inspect', *ids]).stdout) if ids else []
inventory = []
for c in containers:
    svc = c['Config']['Labels']['com.docker.compose.service']
    state = c['State']
    if svc in ('db-init', 'phorge-migrate'):
        ok = state['Status'] == 'exited' and state['ExitCode'] == 0
        detail = f"{state['Status']} exit={state['ExitCode']}"
    else:
        health = state.get('Health', {}).get('Status', 'missing')
        ok = state['Status'] == 'running' and health == 'healthy'
        detail = f"{state['Status']} / {health}"
    check(svc, ok, detail)
    ports = c['HostConfig'].get('PortBindings') or {}
    expected = svc == 'traefik'
    check(svc+' published-port boundary', bool(ports) == expected and all(
        binding['HostIp'] == '127.0.0.1' for port in ports.values() for binding in port))
    inventory.append(dict(service=svc, image_ref=c['Config']['Image'], image_id=c['Image'],
                          state=state['Status'], health=state.get('Health', {}).get('Status'),
                          restart_count=c['RestartCount']))
expected_services = {'mysql', 'db-init', 'phorge-migrate', 'phorge', 'phorge-daemon',
                     'gorge-render', 'gorge-conduit', 'gorge-notification',
                     'gorge-file-storage', 'gorge-webhook', 'gorge-taskqueue',
                     'gorge-worker', 'gorge-db-api', 'traefik', 'stargate',
                     'warden', 'herald', 'herald-smtp', 'stargate-redis', 'herald-redis'}
actual_services = {entry['service'] for entry in inventory}
check('expected service count', len(containers) == 20 and actual_services == expected_services,
      f'{len(containers)}/20')

def request(host, path, headers=(), port=8443):
    args = ['curl', '--silent', '--show-error', '--max-time', '10', '--noproxy', '*',
            '--cacert', str(ROOT/'config/tls/localhost.crt'),
            '--resolve', f'{host}:{port}:127.0.0.1', '-o', '/dev/null', '-D', '-',
            '-w', '\n%{http_code}', f'{"https" if port==8443 else "http"}://{host}:{port}{path}']
    for header in headers:
        args += ['-H', header]
    result = run(args)
    code = int(result.stdout.rsplit('\n', 1)[-1]) if result.returncode == 0 else 0
    return code, result.stdout

code, headers = request('pm.localhost', '/', port=8080)
check('HTTP redirects to local HTTPS', code in (301, 302, 307, 308) and ':8443/' in headers)
code, _ = request('auth.localhost', '/_login')
check('login page and TLS certificate', code == 200, str(code))
for hs in ((), ('X-Auth-User: spoofed-admin', 'X-Auth-Email: admin@example.invalid',),
           ('X-Forwarded-User: authenticated', 'X-Forwarded-Host: auth.localhost')):
    code, response = request('pm.localhost', '/', headers=hs)
    check('anonymous/spoofed identity denied '+str(len(hs)),
          code in (302, 303, 307) and 'auth.localhost:8443/_login' in response, str(code))
for alias in ('X_Auth_User: spoofed-admin', 'X.Auth.User: spoofed-admin'):
    code, _ = request('pm.localhost', '/', headers=(alias,))
    check('PHP header alias rejected '+alias.split(':')[0], code == 400, str(code))
for path in ('/metrics', '/healthz', '/_auth'):
    code, _ = request('auth.localhost', path)
    check('identity private endpoint '+path, code == 404, str(code))
code, _ = request('pm.localhost', '/_session_exchange?ticket=invalid')
check('invalid ticket rejected without auth loop', code in (400, 401, 403), str(code))
code, _ = request('pm.localhost', '/ws/')
check('WebSocket route requires entry authentication', code in (302, 303, 307), str(code))
for name, url, success in (
    ('notification client reachable from edge', 'http://172.29.242.10:22280/healthz', True),
    ('notification admin not on client interface', 'http://172.29.242.10:22281/healthz', False),
    ('notification admin network isolated from edge', 'http://172.29.241.10:22281/healthz', False),
):
    r = run(COMPOSE + ['exec', '-T', 'traefik', 'wget', '-q', '-T', '3', '-O', '/dev/null', url])
    check(name, (r.returncode == 0) == success)

report = dict(verified_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
              scope='local initialization; no real users, SMTP or full business acceptance',
              checks=checks, services=inventory)
(ROOT/'state/verification.json').write_text(json.dumps(report, indent=2)+'\n')
sources = [dict(repository='soulteary/phorge', commit='e5141c768b37eeb9a114198cc8df9664173be638'),
           dict(repository='soulteary/gorge', commit='f1130b74f072c1d1d5ad7ad11b626be3d6a5d3ad')]
sources += json.loads((ROOT/'config/identity-sources.json').read_text())
paths = (list(ROOT.glob('compose.*.yaml')) + list((ROOT/'config/traefik').glob('*.yaml'))
         + list((ROOT/'config/build').glob('*.Dockerfile'))
         + [ROOT/'config/notification.json', ROOT/'config/phorge-apache.conf',
            ROOT/'config/phorge-trusted-proxy.php',
            ROOT/'config/mysql/grants.sql.template', ROOT/'config/identity-sources.json',
            ROOT/'docker/identity.Dockerfile']
         + list((ROOT/'scripts').glob('*.py')) + list((ROOT/'scripts').glob('*.sh'))
         + list((ROOT/'scripts').glob('*.php')))
manifest = dict(recorded_at=report['verified_at'], sources=sources, services=inventory,
                configuration_sha256={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
(ROOT/'state/release-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
sys.exit(0 if all(c['passed'] for c in checks) else 1)
