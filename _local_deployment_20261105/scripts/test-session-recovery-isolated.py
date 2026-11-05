#!/usr/bin/env python3
"""Exercise entry/Phorge session recovery over real, isolated native HTTP.

Uses only a kept disposable project-regression database and its exact sources.
No production configuration, authentication service, identity or cookie is read.
The test-only Apache RemoteIP header represents the existing trusted proxy;
the real production trusted-proxy prepend and unchanged guard enforce trust.
"""
import argparse
import datetime
import hashlib
import html.parser
import http.cookiejar
import importlib.util
import json
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('report', type=Path)
parser.add_argument('--guard', type=Path, default=ROOT/'config/phorge/session-staging/TeamEntrySessionGuard.php')
args = parser.parse_args()
baseline = json.loads(args.report.read_text())
run = baseline['run']
assert baseline['passed'] and re.fullmatch(r'team-project-regression-[a-f0-9]{8}', run)
network, database = baseline['network'], baseline['databaseContainer']
assert (network, database) == (run+'-net', run+'-db')
private = Path(baseline['privateConfigurationDirectory'])
config = json.loads((private/'conf/local.json').read_text())
assert config['mysql.host'] == database and config['storage.default-namespace'] == 'project_regression_base'
guard = args.guard.resolve()
assert guard.is_file() and guard.is_relative_to(ROOT/'config/phorge')
output = args.report.resolve().parent/'session-recovery'
output.mkdir(mode=0o700, exist_ok=True)
if (output/'report.json').exists():
    attempt = output/'attempts'/str(time.time_ns()); attempt.mkdir(mode=0o700, parents=True)
    for item in output.iterdir():
        if item.is_file(): shutil.move(item, attempt/item.name)
temporary = Path(tempfile.mkdtemp(prefix=run+'-session-', dir='/tmp'))
webconf = temporary/'conf'; webconf.mkdir(mode=0o755)


class Forwarder(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with socket.create_connection((self.server.target, 80), timeout=10) as upstream:
                upstream.settimeout(None)
                while True:
                    readable, _, _ = select.select([self.request, upstream], [], [], 30)
                    if not readable: return
                    for source in readable:
                        data = source.recv(65536)
                        if not data: return
                        (upstream if source is self.request else self.request).sendall(data)
        except OSError:
            return


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False


proxy = Server(('127.0.0.1', 0), Forwarder)
origin = 'http://127.0.0.1:'+str(proxy.server_address[1])
config.update({'phabricator.base-uri': origin+'/', 'phabricator.allowed-uris': [origin+'/'],
               'security.require-https': False, 'auth.require-email-verification': False,
               'phabricator.show-prototypes': True, 'phabricator.silent': True,
               'notification.servers': [], 'gorge.integrations': {}})
(webconf/'local.json').write_text(json.dumps(config)); (webconf/'local.json').chmod(0o644)
(temporary/'remoteip.conf').write_text('RemoteIPHeader X-Session-Test-Remote-IP\nRemoteIPInternalProxy 172.16.0.0/12\nRemoteIPInternalProxy 10.0.0.0/8\nRemoteIPInternalProxy 192.168.0.0/16\n')
(temporary/'remoteip.conf').chmod(0o644)
(temporary/'prepend.ini').write_text('auto_prepend_file=/etc/phorge/trusted-proxy.php\n')
(temporary/'prepend.ini').chmod(0o644)
web = run+'-session-ui'
created = started = False
report = {'run': run, 'scope': 'Synthetic native HTTP identities on the disposable internal network only.',
          'passed': False, 'checks': [], 'sourceFiles': [],
          'testFiles': [{'source': name, 'sha256': hashlib.sha256((ROOT/name).read_bytes()).hexdigest()}
              for name in ('scripts/test-session-recovery-isolated.py', 'tests/session-recovery-fixture.php')]}
revoked = []
fixture = None
phase = 'prepare isolated application'


def call(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, **kwargs)


def require(argv, **kwargs):
    result = call(argv, **kwargs)
    if result.returncode:
        diagnostic = result.stderr.decode(errors='replace').replace(config['mysql.pass'], '[REDACTED]')
        diagnostic = re.sub(r'[A-Za-z0-9_-]{24,}', '[REDACTED]', diagnostic)
        (output/'process-error.log').write_text(diagnostic)
        (output/'process-error.log').chmod(0o600)
        raise RuntimeError('Isolated process failed; private diagnostic withheld.')
    return result


def check(name, passed, status=None):
    row = {'name': name, 'passed': bool(passed)}
    if status is not None: row['httpStatus'] = status
    report['checks'].append(row)
    print(('PASS ' if passed else 'FAIL ')+name, flush=True)
    if not passed: raise RuntimeError(name)


class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow): self.allow, self.seen = allow, []
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.seen.append((code, urllib.parse.urlsplit(newurl).path))
        if not self.allow: return None
        assert newurl.startswith(origin+'/'), 'A login redirect left the isolated origin.'
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Client:
    def __init__(self, spec):
        self.spec = spec
        self.jar = http.cookiejar.CookieJar()
        self.headers = {'X-Session-Test-Remote-IP': '172.29.240.2',
                        'X-Auth-User': spec['principal'], 'X-Auth-Email': spec['email'],
                        'X-Auth-Name': spec['realName'], 'Accept': 'text/html'}
        self.entry()
    def cookie(self, name):
        return next((c.value for c in self.jar if c.name == name), None)
    def entry(self, value=None):
        self.jar.set_cookie(http.cookiejar.Cookie(0, 'stargate_session_id', value or secrets.token_hex(16),
            None, False, '127.0.0.1', False, False, '/', True, False, None, True, None, None, {}))
    def request(self, path, method='GET', fields=None, follow=True, headers=None):
        redirects = Redirects(follow)
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), redirects)
        req = urllib.request.Request(origin+path,
              data=urllib.parse.urlencode(fields or {}).encode() if method == 'POST' else None,
              method=method, headers={**self.headers, **(headers or {})})
        try: response = opener.open(req, timeout=25)
        except urllib.error.HTTPError as error: response = error
        with response:
            result = (response.status, response.headers, response.read().decode(errors='replace'),
                      urllib.parse.urlsplit(response.url), redirects.seen)
        return result
    def login(self):
        status, _, body, _, _ = self.request('/auth/login/traefik:traefik/')
        check('native provider authenticates '+self.spec['role'],
              status == 200 and self.cookie('phusr') == self.spec['username'] and bool(self.cookie('phsid')), status)
        return self
    def stale(self):
        token = self.cookie('phsid'); assert token; revoked.append(token); self.entry(); return token


class Inputs(html.parser.HTMLParser):
    def __init__(self): super().__init__(); self.values = {}
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('name'): self.values[attrs['name']] = attrs.get('value', '')


def interrupt(signum, frame): raise RuntimeError('Interrupted isolated session test.')
signal.signal(signal.SIGTERM, interrupt)

try:
    details = json.loads(require(['docker', 'network', 'inspect', network]).stdout)[0]
    assert details['Internal']
    sources = baseline['sourceFiles']
    for source in sources:
        assert hashlib.sha256((ROOT/source['source']).read_bytes()).hexdigest() == source['sha256']
    report['sourceFiles'] = sources + [{'source': str(guard.relative_to(ROOT)),
        'path': 'src/extensions/TeamEntrySessionGuard.php', 'sha256': hashlib.sha256(guard.read_bytes()).hexdigest()},
        {'source': 'config/phorge-trusted-proxy.php', 'path': '/etc/phorge/trusted-proxy.php',
         'sha256': hashlib.sha256((ROOT/'config/phorge-trusted-proxy.php').read_bytes()).hexdigest()}]
    mounts = ['--mount', f'type=bind,src={webconf},dst=/opt/phorge/phorge/conf/local,readonly',
              '--mount', f'type=bind,src={ROOT/"tests"},dst=/work/tests,readonly',
              '--mount', f'type=bind,src={guard},dst=/opt/phorge/phorge/src/extensions/TeamEntrySessionGuard.php,readonly',
              '--mount', f'type=bind,src={ROOT/"config/phorge-trusted-proxy.php"},dst=/etc/phorge/trusted-proxy.php,readonly',
              '--mount', f'type=bind,src={temporary/"remoteip.conf"},dst=/etc/apache2/conf-enabled/session-test-remoteip.conf,readonly',
              '--mount', f'type=bind,src={temporary/"prepend.ini"},dst=/usr/local/etc/php/conf.d/session-test-prepend.ini,readonly']
    for item in sources:
        mounts += ['--mount', 'type=bind,src='+str(ROOT/item['source'])+',dst=/opt/phorge/phorge/'+item['path']+',readonly']
    require(['docker', 'run', '-d', '--pull=never', '--name', web, '--network', network,
             '--memory', '768m', '--cpus', '1', '--entrypoint', 'sh', *mounts,
             baseline['phorgeImageID'], '-c', 'a2enmod remoteip >/dev/null && exec apache2-foreground'])
    created = True
    fixture = json.loads(require(['docker', 'exec', '-e', 'TEAM_ENTRY_SESSION_ISOLATED=1', web,
                         'php', '/work/tests/session-recovery-fixture.php']).stdout)
    proxy.target = json.loads(require(['docker', 'inspect', web]).stdout)[0]['NetworkSettings']['Networks'][network]['IPAddress']
    thread = threading.Thread(target=proxy.serve_forever, daemon=True); thread.start(); started = True
    phase = 'native provider and matching session'
    a = Client(fixture['users']['a']).login()
    healthy = Client(fixture['users']['b']).login()
    status, _, _, _, _ = a.request('/settings/user/'+a.spec['username']+'/')
    check('matching entry and native session remain usable', status == 200, status)
    old = a.stale()
    phase = 'same-person entry rotation'
    destination = '/settings/user/'+a.spec['username']+'/?tab=session-recovery'
    status, headers, body, _, _ = a.request(destination, follow=False)
    check('rotated entry document GET returns a 303 native login redirect',
          status == 303 and urllib.parse.urlsplit(headers.get('Location', '')).path == '/auth/login/traefik:traefik/', status)
    check('GET recovery clears the stale application cookie', a.cookie('phsid') is None)
    check('GET recovery retains a local destination and no-store',
          urllib.parse.unquote(a.cookie('next_uri') or '').endswith(','+destination) and 'no-store' in headers.get('Cache-Control', ''))
    status, _, body, location, native_chain = a.request('/auth/login/traefik:traefik/')
    report['recoveryChains'] = [{'case': 'same person with rotated entry session',
        'initialStatus': 303, 'initialLocation': '/auth/login/traefik:traefik/',
        'nativeRedirects': native_chain, 'finalPath': location.path,
        'localQueryPreserved': location.query == 'tab=session-recovery'}]
    check('automatic native login restores the original local destination',
          status == 200 and location.path == urllib.parse.urlsplit(destination).path and location.query == 'tab=session-recovery', status)
    check('reauthentication creates a new phsid for the actual current user',
          a.cookie('phsid') != old and a.cookie('phusr') == a.spec['username'])
    phase = 'cross-user document navigation'
    cross = Client(fixture['users']['a']).login(); cross.stale()
    cross.spec = fixture['users']['b']
    cross.headers.update({'X-Auth-User': cross.spec['principal'], 'X-Auth-Email': cross.spec['email'], 'X-Auth-Name': cross.spec['realName']})
    status, _, body, _, chain = cross.request('/settings/user/'+cross.spec['username']+'/')
    report['recoveryChains'].append({'case': 'current entry user changed', 'nativeRedirects': chain,
        'finalUserIsCurrentEntryUser': cross.cookie('phusr') == cross.spec['username']})
    check('cross-user navigation automatically authenticates only the current entry user',
          status == 200 and cross.cookie('phusr') == cross.spec['username'] and (303, '/auth/login/traefik:traefik/') in chain, status)
    phase = 'stale write and CSRF rejection'
    write = Client(fixture['users']['a']).login()
    status, _, body, _, _ = write.request('/maniphest/task/edit/')
    inputs = Inputs(); inputs.feed(body)
    check('native task form supplies a real CSRF token', status == 200 and bool(inputs.values.get('__csrf__')), status)
    fields = {**inputs.values, '__form__': '1', 'title': 'Rejected stale session card', 'status': 'open', 'priority': '50'}
    write.stale()
    status, headers, body, _, _ = write.request('/maniphest/task/edit/', 'POST', fields, follow=False)
    check('same-person stale POST with a genuine CSRF token is rejected without replay',
          status == 409 and 'ENTRY_SESSION_MISMATCH' in body and not headers.get('Location'), status)
    check('rejected POST clears phsid and retains an actionable login link',
          write.cookie('phsid') is None and '/auth/login/traefik:traefik/' in body)
    other = Client(fixture['users']['a']).login(); other.stale()
    other.headers['X-Auth-User'] = fixture['users']['b']['principal']
    status, headers, body, _, _ = other.request('/api/user.whoami', 'POST', {'params': '{}', 'output': 'json'}, follow=False)
    check('cross-user stale POST remains fail-closed', status == 409 and 'ENTRY_SESSION_MISMATCH' in body and not headers.get('Location'), status)
    csrf = Client(fixture['users']['a']).login()
    status, _, body, _, _ = csrf.request('/maniphest/task/edit/', 'POST',
       {'__form__': '1', 'title': 'Rejected missing CSRF card', 'status': 'open', 'priority': '50'}, follow=False)
    csrf_error = bool(re.search('incorrect token', body, re.I)) and bool(
        re.search(r'AphrontMalformedRequestException|Invalid Request \(CSRF\)', body))
    report['nativeCSRFRejection'] = {'httpStatus': status, 'explicitNativeCSRFError': csrf_error}
    # The pinned fork maps the native malformed-request CSRF exception to 500.
    # Require the exact rejection plus zero persisted tasks, never a generic 500.
    check('matching sessions still require native CSRF validation', status in (400, 403, 500) and csrf_error, status)
    phase = 'non-document and untrusted sources'
    cases = [
        ('AJAX GET', '/settings/', {'__ajax__': '1'}, {}),
        ('workflow GET', '/settings/', {'__wflow__': '1'}, {}),
        ('quicksand GET', '/settings/', {'__quicksand__': '1'}, {}),
        ('API GET', '/api/user.whoami', {}, {}),
        ('file GET', '/file/data/test/PHID-FILE-aaaaaaaaaaaaaaaaaaaa/secret.txt', {}, {}),
        ('non-HTML GET', '/settings/', {}, {'Accept': 'application/json'}),
        ('subresource GET', '/settings/', {}, {'Sec-Fetch-Dest': 'image'}),
    ]
    for label, path, query, extra in cases:
        client = Client(fixture['users']['a']).login(); client.stale()
        if query: path += '?'+urllib.parse.urlencode(query)
        status, headers, body, _, _ = client.request(path, follow=False, headers=extra)
        check(label+' never silently redirects or replays authentication', status == 409 and 'ENTRY_SESSION_MISMATCH' in body and not headers.get('Location'), status)
    for label in ('missing entry cookie', 'missing trusted principal', 'untrusted source with forged identity'):
        client = Client(fixture['users']['a']).login(); revoked.append(client.cookie('phsid'))
        if label == 'missing entry cookie':
            for cookie in list(client.jar):
                if cookie.name == 'stargate_session_id': client.jar.clear(cookie.domain, cookie.path, cookie.name)
        elif label == 'missing trusted principal': client.headers.pop('X-Auth-User')
        else: client.headers['X-Session-Test-Remote-IP'] = '192.0.2.51'
        status, headers, body, _, _ = client.request('/settings/', follow=False)
        check(label+' is rejected without a login redirect loop', status == 409 and 'ENTRY_SESSION_MISMATCH' in body and not headers.get('Location'), status)
    phase = 'local-only continuation'
    local = Client(fixture['users']['a']).login(); local.stale()
    status, _, _, location, chain = local.request('/auth/login/traefik:traefik/?next=https://outside.invalid/')
    report['recoveryChains'].append({'case': 'external next URL discarded on auth path',
        'nativeRedirects': chain, 'finalPath': location.path})
    check('authentication recovery never follows an external next URL or loops to auth',
          status == 200 and location.path == '/' and (303, '/auth/login/traefik:traefik/') in chain, status)
    status, _, _, _, _ = healthy.request('/settings/user/'+healthy.spec['username']+'/')
    check('independent valid browser session remains usable', status == 200, status)
    phase = 'read-only persistence verification'
    verification_input = {**fixture, 'revokedTokens': list(set(revoked))}
    report['nativeVerification'] = json.loads(require(['docker', 'exec', '-i', '-e', 'TEAM_ENTRY_SESSION_ISOLATED=1', web,
        'php', '/work/tests/session-recovery-fixture.php', '--verify'], input=json.dumps(verification_input).encode()).stdout)
    report['passed'] = report['nativeVerification']['passed'] and all(c['passed'] for c in report['checks'])
except Exception as error:
    report['error'] = 'Session recovery check failed at '+phase+': '+type(error).__name__
finally:
    if started: proxy.shutdown(); thread.join(timeout=5)
    proxy.server_close()
    if created:
        logs = call(['docker', 'logs', '--tail', '100', web])
        safe = (logs.stdout+logs.stderr).decode(errors='replace').replace(config['mysql.pass'], '[REDACTED]')
        (output/'apache.log').write_text(safe); (output/'apache.log').chmod(0o600)
        report['webContainerRemoved'] = call(['docker', 'rm', '-f', '-v', web]).returncode == 0
    shutil.rmtree(temporary)
    report['testFilesUnchanged'] = all(hashlib.sha256((ROOT/item['source']).read_bytes()).hexdigest() == item['sha256']
                                       for item in report['testFiles'])
    report['sourceFilesUnchanged'] = bool(report['sourceFiles']) and all(
        hashlib.sha256((ROOT/item['source']).read_bytes()).hexdigest() == item['sha256']
        for item in report['sourceFiles'])
    report['passed'] = report['passed'] and report['testFilesUnchanged'] and report['sourceFilesUnchanged']
    report['verifiedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output/'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
    (output/'report.json').chmod(0o600)
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks']),
                     'error': report.get('error'), 'report': str(output/'report.json')}, ensure_ascii=False))
raise SystemExit(0 if report['passed'] else 1)
