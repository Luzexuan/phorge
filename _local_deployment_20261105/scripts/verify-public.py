#!/usr/bin/env python3
"""Inspect the real public-IP gateway and private service boundaries."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
IP = '45.77.36.106'
checks = []
os.umask(0o077)
static_path = ROOT/'config/traefik/public-static.yaml'
static = yaml.safe_load(static_path.read_text()) if static_path.exists() else {}
acme = static.get('certificatesResolvers', {}).get('public-ip', {}).get('acme', {})
tls_mode = 'self-signed'
if acme:
    if acme.get('caServer') == 'https://acme-staging-v02.api.letsencrypt.org/directory':
        raise SystemExit('Staging TLS is not a public release. Switch to production and issue its certificate before running this verification.')
    if acme.get('caServer') != 'https://acme-v02.api.letsencrypt.org/directory':
        raise SystemExit('Unknown public ACME authority; review the TLS configuration before verification.')
    tls_mode = 'production'
ca_file = Path('/etc/ssl/certs/ca-certificates.crt') if tls_mode == 'production' else ROOT/'config/tls/public-ip.crt'
certificate_details = None

def check(name, passed, detail=None):
    checks.append(dict(name=name, passed=bool(passed), detail=detail))
    print(('PASS ' if passed else 'FAIL ') + name)

def request(path, headers=(), http=False, loopback=False):
    command = ['curl', '--silent', '--show-error', '--path-as-is', '--max-time', '15',
               '--cacert', str(ca_file), '-D', '-', '-o', '/dev/null']
    if loopback:
        command += ['--connect-to', IP+(':80:127.0.0.1:8080' if http else ':443:127.0.0.1:8443')]
    for header in headers:
        command += ['-H', header]
    result = subprocess.run(command + [('http' if http else 'https')+'://'+IP+path],
                            capture_output=True, text=True)
    if result.returncode:
        return 0, {}
    lines = result.stdout.splitlines()
    status = int(lines[0].split()[1])
    fields = dict(line.split(': ', 1) for line in lines[1:] if ': ' in line)
    return status, {k.lower(): v for k, v in fields.items()}

check('public overlay explicitly enabled', (ROOT/'.public-enabled').is_file())
if tls_mode == 'production':
    dynamic = yaml.safe_load((ROOT/'config/traefik/dynamic.yaml').read_text())
    default_store = dynamic.get('tls', {}).get('stores', {}).get('default', {})
    check('native public IP certificate and renewal configuration',
          acme.get('profile') == 'shortlived' and acme.get('disableCommonName') is True
          and acme.get('certificatesDuration') == 160 and acme.get('httpChallenge', {}).get('entryPoint') == 'web'
          and acme.get('storage') == '/etc/traefik/acme/production.json'
          and default_store.get('defaultGeneratedCert') == {'resolver': 'public-ip', 'domain': {'main': IP}}
          and 'defaultCertificate' not in default_store)
    private_store = ROOT/'config/traefik/acme/production.json'
    private_dir = private_store.parent
    check('ACME account and certificate store remains private', private_store.is_file()
          and not private_store.is_symlink() and private_store.stat().st_uid == 0
          and stat.S_IMODE(private_store.stat().st_mode) == 0o600
          and private_dir.stat().st_uid == 0 and stat.S_IMODE(private_dir.stat().st_mode) == 0o700)
    try:
        context = ssl.create_default_context(cafile=str(ca_file))
        with socket.create_connection((IP,443), timeout=15) as connection:
            # Python verifies the IP SAN, and does not send an IP literal as SNI.
            with context.wrap_socket(connection, server_hostname=IP) as secure:
                certificate = secure.getpeercert()
        start = ssl.cert_time_to_seconds(certificate['notBefore'])
        end = ssl.cert_time_to_seconds(certificate['notAfter'])
        certificate_details = {'ipSAN': ('IP Address',IP) in certificate.get('subjectAltName',()),
            'validFrom': certificate['notBefore'], 'validUntil': certificate['notAfter'],
            'durationHours': round((end-start)/3600,2), 'systemTrustVerified': True,
            'withoutDNSNameSNI': True}
        check('system trust validates short-lived IP certificate without a DNS-name SNI',
              certificate_details['ipSAN'] and 0 < end-start <= 7*24*3600)
    except (OSError, ValueError):
        check('system trust validates short-lived IP certificate without a DNS-name SNI', False)
code, headers = request('/', http=True)
check('HTTP redirects to HTTPS public IP', code in (301, 302, 307, 308)
      and headers.get('location', '').startswith('https://'+IP+'/'))
for host in ('pm.localhost', 'auth.localhost', 'localhost', 'untrusted.invalid', IP+'.untrusted.invalid'):
    for http in (False, True):
        code, headers = request('/_login', ['Host: '+host], http=http)
        check('unknown Host rejected on '+('HTTP ' if http else 'HTTPS ')+host,
              code == 404 and not headers.get('location'))
code, headers = request('/', http=True, loopback=True)
check('loopback HTTP retains canonical IP redirect', code in (301,302,307,308)
      and headers.get('location', '').startswith('https://'+IP+'/'))
code, _ = request('/_login', loopback=True)
check('loopback HTTPS accepts canonical IP Host and certificate', code == 200)
code, _ = request('/_login')
check('public login page available with matching IP certificate', code == 200)
login = subprocess.run(['curl', '--silent', '--show-error', '--max-time', '15',
    '--cacert', str(ca_file), 'https://'+IP+'/_login'], capture_output=True, text=True)
check('login page describes real-user registration and approval', login.returncode == 0
      and '团队管理登录' in login.stdout and '管理员批准后' in login.stdout
      and '仅限已获准的测试成员' not in login.stdout)
if (ROOT/'.registration-enabled').exists():
    code, headers = request('/_register')
    check('public pending-registration page available before authentication', code == 200)
    cookie = headers.get('set-cookie', '')
    check('registration sets only a CSRF cookie, no login session',
          cookie.startswith('__Host-registration_csrf=') and 'stargate_session_id=' not in cookie
          and 'phsid=' not in cookie and 'Secure' in cookie and 'HttpOnly' in cookie)
for route in ('/', '/project/', '/api/user.whoami', '/ws/'):
    code, headers = request(route)
    check('anonymous entry requires login '+route, code in (302, 303, 307)
          and '/_login' in headers.get('location', ''))
if (ROOT/'.maintenance-enabled').exists():
    code, headers = request('/maintenance/')
    check('maintenance pages require an authenticated user', code in (302,303,307)
          and '/_login' in headers.get('location', ''))
    for route in ('//maintenance/users/', '/%6daintenance/users/', '/maintenance%2fusers/',
                  '/assets/%2e%2e/maintenance/users/', '/?__path__=/maintenance/users/'):
        code, headers = request(route)
        check('encoded or rewritten maintenance entry requires login '+route,
              code in (302,303,307,308) and '/_login' in headers.get('location',''))
for header in ('X-Auth-User', 'X_Auth_User', 'X.Auth.User'):
    code, headers = request('/settings/', [header+': linkerbot-site-admin',
        'X-Auth-Email: 177000177@qq.com', 'X-Forwarded-User: siteadmin'])
    check('forged public identity rejected '+header,
          code == 400 or (code in (302, 303, 307) and '/_login' in headers.get('location', '')))
for route in ('/_auth', '/healthz', '/readyz', '/metrics', '/user', '/v1/send'):
    code, _ = request(route)
    check('internal endpoint unavailable on public gateway '+route,
          code in (302, 303, 307, 404))
code, _ = request('/_session_exchange?ticket=invalid')
check('invalid exchange ticket rejected without redirect loop', code in (400, 401, 403))
ids = subprocess.check_output([str(ROOT/'scripts/compose.sh'), 'ps', '-aq'], text=True).split()
containers = json.loads(subprocess.check_output(['docker', 'inspect', *ids], text=True))
expectedServices = {'mysql','db-init','phorge-migrate','phorge','phorge-daemon',
    'gorge-render','gorge-conduit','gorge-notification','gorge-file-storage',
    'gorge-webhook','gorge-taskqueue','gorge-worker','gorge-db-api',
    'traefik','stargate','warden','herald','herald-smtp','stargate-redis','herald-redis','identity-test-mail'}
if (ROOT/'.dingtalk-enabled').exists():
    expectedServices.update({'herald-dingtalk','dingtalk-tls'})
if (ROOT/'.registration-enabled').exists():
    expectedServices.add('registration')
if (ROOT/'.maintenance-enabled').exists():
    expectedServices.add('maintenance')
check('complete expected service inventory', expectedServices == {
    c['Config']['Labels']['com.docker.compose.service'] for c in containers})
inventory = []
fixed_addresses = {
    'traefik': {'team-management-ingress': '172.30.10.2',
                'team-management-web': '172.29.240.2'},
    'stargate': {'team-management-ingress': '172.30.10.3'},
    'registration': {'team-management-ingress': '172.30.10.4'},
    'phorge': {'team-management-web': '172.29.240.3'},
}
if (ROOT/'.maintenance-enabled').exists():
    fixed_addresses['maintenance'] = {'team-management_maintenance': '172.30.20.3'}
    fixed_addresses['phorge']['team-management_maintenance'] = '172.30.20.2'
for c in containers:
    service = c['Config']['Labels']['com.docker.compose.service']
    state = c['State']
    healthy = (state['Status'] == 'exited' and state['ExitCode'] == 0) if service in ('db-init', 'phorge-migrate') else (
        state['Status'] == 'running' and state.get('Health', {}).get('Status') == 'healthy')
    check('service healthy '+service, healthy)
    if service in fixed_addresses:
        networks = c['NetworkSettings']['Networks']
        check('fixed address prevents trusted proxy collision '+service,
              all(networks.get(name, {}).get('IPAddress') == address
                  and (networks.get(name, {}).get('IPAMConfig') or {}).get('IPv4Address') == address
                  for name, address in fixed_addresses[service].items()))
    ports = c['HostConfig'].get('PortBindings') or {}
    if service == 'stargate':
        # Inspect only these non-secret values, never emit the environment.
        environment = dict(item.split('=',1) for item in c['Config']['Env'] if '=' in item)
        check('Stargate canonical host has no legacy callback allowlist',
              environment.get('AUTH_HOST') == IP and environment.get('CALLBACK_ALLOWED_HOSTS','') == '')
    rules = [value for key,value in c['Config']['Labels'].items()
             if key.startswith('traefik.http.routers.') and key.endswith('.rule')]
    if rules:
        check('public router rules exclude legacy localhost hosts '+service,
              all('localhost' not in rule and 'Host(`'+IP+'`)' in rule for rule in rules))
    if service == 'traefik':
        bindings = {(p, b['HostIp'], b['HostPort']) for p, items in ports.items() for b in items}
        expected = {('80/tcp', '0.0.0.0', '80'), ('443/tcp', '0.0.0.0', '443'),
                    ('80/tcp', '127.0.0.1', '8080'), ('443/tcp', '127.0.0.1', '8443')}
        check('only intended public and loopback gateway ports', bindings == expected)
    else:
        check('service has no published ports '+service, not ports)
    if service == 'maintenance':
        mounts = c.get('Mounts', [])
        check('maintenance has no Docker socket or host-root mount',
              all(m.get('Source') not in ('/', '/var/run/docker.sock', '/run/docker.sock')
                  and 'docker.sock' not in m.get('Destination','') for m in mounts))
        check('maintenance runs as unprivileged service user', c['Config']['User']=='10001:10001'
              and not c['HostConfig']['Privileged'] and 'ALL' in c['HostConfig'].get('CapDrop',[]))
        check('maintenance has no public router and only private networks',
              not any(k.startswith('traefik.http.routers.') for k in c['Config']['Labels'])
              and set(c['NetworkSettings']['Networks'])=={'team-management_core','team-management_maintenance'})
    inventory.append(dict(service=service, image=c['Config']['Image'], imageID=c['Image'],
        state=state['Status'], health=state.get('Health', {}).get('Status')))
report = dict(verifiedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    url='https://'+IP+'/', passed=all(x['passed'] for x in checks), checks=checks, services=inventory,
    certificate=('publicly trusted short-lived IP certificate with native automatic renewal' if tls_mode == 'production'
                 else 'self-signed test certificate; public browser requires trust/import'),
    publicTLSMode=tls_mode, certificateDetails=certificate_details,
    networkVantage='requests made from the server to its public IP; not an independent external network')
(ROOT/'state/acceptance/public-gateway.json').write_text(json.dumps(report, indent=2)+'\n')
paths = list(ROOT.glob('compose.*.yaml')) + list((ROOT/'scripts').glob('*.py')) \
    + list((ROOT/'scripts').glob('*.sh')) + list((ROOT/'scripts').glob('*.php')) \
    + list((ROOT/'scripts').glob('*.mjs')) + list((ROOT/'tests/browser').glob('*.mjs')) \
    + list((ROOT/'config/phorge/extensions').glob('*.php')) \
    + list((ROOT/'config/phorge/overrides').glob('*')) \
    + list((ROOT/'config/registration').glob('*.py')) \
    + list((ROOT/'config/maintenance').glob('*.py')) \
    + list((ROOT/'config/maintenance').glob('*.php')) \
    + [ROOT/'docker/maintenance.Dockerfile'] \
    + list((ROOT/'config/stargate').glob('*')) \
    + list((ROOT/'config/traefik').glob('*.yaml')) \
    + list((ROOT/'config/dingtalk').glob('*.patch')) \
    + [ROOT/'config/dingtalk/source.json']
manifest = dict(recordedAt=report['verifiedAt'], services=inventory,
    publicEnabled=(ROOT/'.public-enabled').exists(), dingtalkEnabled=(ROOT/'.dingtalk-enabled').exists(),
    registrationEnabled=(ROOT/'.registration-enabled').exists(),
    maintenanceEnabled=(ROOT/'.maintenance-enabled').exists(),
    publicTLSMode=tls_mode,
    configurationSHA256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in paths if p.is_file()})
(ROOT/'state/acceptance/release-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
sys.exit(0 if all(x['passed'] for x in checks) else 1)
