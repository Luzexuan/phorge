#!/usr/bin/env python3
"""Run real HTTP project organization tests against a kept disposable regression database.

Usage: python3 scripts/test-project-organization-ui-isolated.py path/to/isolated/report.json
Requires scripts/test-project-isolated.py --keep to have prepared the database.
Only a loopback high port is exposed; no production state is mounted or read.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import select
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('report', type=Path)
parser.add_argument('--staging', action='store_true', help='Use the progress-staging replacements tested by the native run.')
parser.add_argument('--diagnostic', action='store_true', help='Permit source drift only for compatibility diagnosis; never report a passed acceptance run.')
args = parser.parse_args()
baseline = json.loads(args.report.read_text())
if not baseline.get('passed'):
    raise SystemExit('The isolated native regression must pass before browser checks.')
if args.staging != baseline.get('staging', False):
    raise SystemExit('The UI staging mode must match the kept native regression (--staging).')
run = baseline['run']
if not re.fullmatch(r'team-project-regression-[a-f0-9]{8}', run):
    raise SystemExit('Refusing a non-test report.')
network = baseline['network']
database = baseline['databaseContainer']
application = baseline['applicationContainer']
if (network, database, application) != (run+'-net', run+'-db', run+'-php'):
    raise SystemExit('Unexpected isolated container names.')
private = Path(baseline['privateConfigurationDirectory'])
config = json.loads((private/'conf/local.json').read_text())
if config.get('mysql.host') != database or config.get('storage.default-namespace') != 'project_regression_base':
    raise SystemExit('Refusing non-test database configuration.')
output = args.report.resolve().parent/'organization-ui'
output.mkdir(mode=0o700, exist_ok=True)
if (output/'report.json').exists():
    attempt = output/'attempts'/str(time.time_ns())
    attempt.mkdir(mode=0o700, parents=True)
    for artifact in output.iterdir():
        if artifact.is_file():
            shutil.move(artifact, attempt/artifact.name)
temporary = Path(tempfile.mkdtemp(prefix=run+'-organization-ui-', dir='/tmp'))
webconf = temporary/'conf'
webconf.mkdir(mode=0o755)


class LoopbackForwarder(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with socket.create_connection((self.server.target, 80), timeout=10) as upstream:
                upstream.settimeout(None)
                while True:
                    readable, _, _ = select.select([self.request, upstream], [], [], 60)
                    if not readable:
                        return
                    for source in readable:
                        data = source.recv(65536)
                        if not data:
                            return
                        destination = upstream if source is self.request else self.request
                        destination.sendall(data)
        except OSError:
            return


class LoopbackServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False


# Docker intentionally does not publish ports on an --internal network. Keep
# that isolation intact and relay only this loopback listener to the test IP.
proxy = LoopbackServer(('127.0.0.1', 0), LoopbackForwarder)
proxy_started = False
port = proxy.server_address[1]
origin = f'http://127.0.0.1:{port}'
config.update({'phabricator.base-uri': origin+'/', 'phabricator.allowed-uris': [origin+'/'],
               'security.require-https': False, 'auth.require-email-verification': False,
               'phabricator.show-prototypes': True, 'phabricator.silent': True,
               'notification.servers': [], 'gorge.integrations': {}})
(webconf/'local.json').write_text(json.dumps(config))
(webconf/'local.json').chmod(0o644)  # Host parent remains 0700; Apache can read the bind mount.
web = run+'-organization-ui'
created = False
report = {'run': run, 'origin': origin, 'scope': 'Disposable HTTP application and synthetic users only.',
          'staging': args.staging, 'diagnostic': args.diagnostic,
          'nativeBaselineVerified': False, 'passed': False}

def call(argv, **kwargs):
    return subprocess.run(argv, text=True, capture_output=True, **kwargs)

def require(argv, **kwargs):
    result = call(argv, **kwargs)
    if result.returncode:
        # Do not copy raw fixture stdout (it contains synthetic session tokens).
        raise RuntimeError(result.stderr.replace(config['mysql.pass'], '[REDACTED]').strip()
                           or 'Isolated command failed; see its private log.')
    return result

try:
    details = json.loads(require(['docker', 'network', 'inspect', network]).stdout)[0]
    if not details.get('Internal'):
        raise RuntimeError('Expected an internal test network.')
    fixture = require(['docker', 'exec', '-e', 'TEAM_PROJECT_ISOLATED_UI=1', application,
                       'php', '/work/tests/project-organization-ui-fixture.php']).stdout
    # Ensure the command returned exactly a structured fixture, never PHP warnings.
    fixture_data = json.loads(fixture)
    fixture_path = temporary/'fixture.json'
    fixture_path.write_text(json.dumps(fixture_data))
    fixture_path.chmod(0o600)
    spec = importlib.util.spec_from_file_location('generate_core', ROOT/'scripts/generate-core.py')
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    sources = generator.project_runtime_sources(staging=args.staging)
    source_files = [{'source': row['source'].as_posix(), 'path': row['path'],
                     'sha256': hashlib.sha256((ROOT/row['source']).read_bytes()).hexdigest()} for row in sources]
    source_match = source_files == baseline.get('sourceFiles')
    report['nativeBaselineVerified'] = source_match and not args.diagnostic
    if not source_match:
        previous = {row['path']: row for row in baseline.get('sourceFiles', [])}
        report['sourceDiff'] = [{'path': row['path'], 'baselineSHA256': previous.get(row['path'], {}).get('sha256'),
                                'currentSHA256': row['sha256']} for row in source_files
                               if row != previous.get(row['path'])]
    if not source_match and not args.diagnostic:
        raise RuntimeError('Application sources changed after native tests; rerun the isolated native suite before browser checks.')
    report['sourceFiles'] = source_files
    mounts = ['--mount', f'type=bind,src={webconf},dst=/opt/phorge/phorge/conf/local,readonly']
    for item in sources:
        mounts += ['--mount', 'type=bind,src='+str(ROOT/item['source'])+
                   ',dst=/opt/phorge/phorge/'+item['path']+',readonly']
    require(['docker', 'run', '-d', '--pull=never', '--name', web, '--network', network,
             '--memory', '768m', '--cpus', '1',
             '--entrypoint', 'apache2-foreground', *mounts, baseline['phorgeImageID']])
    created = True
    web_details = json.loads(require(['docker', 'inspect', web]).stdout)[0]
    proxy.target = web_details['NetworkSettings']['Networks'][network]['IPAddress']
    if not proxy.target:
        raise RuntimeError('The isolated application has no test-network address.')
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    proxy_started = True
    deadline = time.monotonic()+45
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(origin+'/project/', timeout=3).close()
            break
        except urllib.error.HTTPError:
            break  # The browser reports the actual application status.
        except (OSError, urllib.error.URLError):
            time.sleep(1)
    else:
        raise RuntimeError('Isolated Apache did not become reachable.')
    result = call(['node', str(ROOT/'tests/browser/project-organization-native.mjs'),
                   origin, str(fixture_path), str(output)])
    (output/'browser.log').write_text(result.stdout+result.stderr)
    (output/'browser.log').chmod(0o600)
    if result.returncode:
        raise RuntimeError('Browser checks failed; inspect organization-ui/browser-report.json and organization-ui/browser.log.')
    report['browserChecksPassed'] = True
    result = require(['docker', 'exec', '-i', '-e', 'TEAM_PROJECT_ISOLATED_UI=1', application,
                      'php', '/work/tests/project-organization-ui-fixture.php', '--verify'], input=fixture)
    report['nativeVerification'] = json.loads(result.stdout)
    report['browserReport'] = str(output/'browser-report.json')
    if args.diagnostic:
        report['diagnosticChecksPassed'] = report['nativeVerification']['passed']
    else:
        report['passed'] = report['nativeVerification']['passed']
except Exception as error:
    report['error'] = str(error)
finally:
    if proxy_started:
        proxy.shutdown()
        proxy_thread.join(timeout=5)
    proxy.server_close()
    if created:
        # Logs are private and secrets are redacted before saving.
        logs = call(['docker', 'logs', '--tail', '120', web])
        (output/'apache.log').write_text((logs.stdout+logs.stderr).replace(config['mysql.pass'], '[REDACTED]'))
        (output/'apache.log').chmod(0o600)
        report['webContainerRemoved'] = call(['docker', 'rm', '-f', web]).returncode == 0
    shutil.rmtree(temporary)
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    (output/'report.json').chmod(0o600)
    print(json.dumps(report, indent=2))
raise SystemExit(0 if report['passed'] or report.get('diagnosticChecksPassed') else 1)
