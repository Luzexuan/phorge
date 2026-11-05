#!/usr/bin/env python3
"""Recheck all native permissions after PHP-only fixes in a kept test runtime.

Original evidence is immutable. Migration evidence may be reused only when the
organization DAO/patch source and SQL are unchanged. No production runtime,
credentials, database, or network may be supplied.
An explicitly recovered native failure keeps the original failed report and
requires its successful restricted-account schema probes before rerunning all suites.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('report', type=Path)
parser.add_argument('--output', default='report-ui-recheck.json', help='New evidence filename in the original report directory.')
parser.add_argument('--staging', action='store_true')
suite_choices = ('subproject-permissions', 'project-progress', 'project-organization',
                 'project-access', 'project-membership', 'project-member-import',
                 'project-team-policy', 'policy-display', 'policy-options')
parser.add_argument('--suite', action='append', choices=suite_choices,
                    help='Recheck only the selected suites; defaults to all suites.')
parser.add_argument('--recover-native-failure', action='store_true',
                    help='Rerun every native suite after a failed retained baseline whose unchanged schema probes succeeded.')
args = parser.parse_args()
native_suites = tuple(dict.fromkeys(args.suite)) if args.suite else suite_choices
test_files = []
for name in native_suites:
    path = Path('tests/permissions')/(name+'.php')
    if not (ROOT/path).is_file():
        raise SystemExit('Missing native regression suite: '+str(path))
    test_files.append({'source': str(path),
                       'sha256': hashlib.sha256((ROOT/path).read_bytes()).hexdigest()})
original_path = args.report.resolve()
baseline = json.loads(original_path.read_text())
run = baseline['run']
if not re.fullmatch(r'team-project-regression-[a-f0-9]{8}', run):
    raise SystemExit('Refusing a non-test run.')
if not baseline.get('keptForDebugging'):
    raise SystemExit('A retained isolated runtime is required.')
recovering = not baseline.get('passed')
if recovering and not args.recover_native_failure:
    raise SystemExit('A passed baseline is required unless --recover-native-failure is explicit.')
if recovering:
    checks = {row['name']: row for row in baseline.get('tests', [])}
    schema_steps = ('schema-bootstrap', 'organization-schema-before-recheck',
                    'schema-recheck', 'organization-schema-after-recheck')
    if (not baseline.get('organizationSchemaUpgradeRepeatSafe') or
            any(name not in checks for name in schema_steps) or
            any(checks[name]['exitCode'] not in (0, 2)
                for name in ('schema-bootstrap', 'schema-recheck')) or
            any(checks[name]['exitCode'] != 0
                for name in ('organization-schema-before-recheck', 'organization-schema-after-recheck')) or
            not any(name in checks for name in native_suites)):
        raise SystemExit('Recovery requires completed first/repeated schema probes and a native suite attempt.')
    snapshots = []
    for name in ('organization-schema-before-recheck', 'organization-schema-after-recheck'):
        snapshot_path = Path(checks[name]['log']).resolve()
        if snapshot_path != original_path.parent/(name+'.log'):
            raise SystemExit('Refusing schema evidence outside the original report directory.')
        snapshots.append(json.loads(snapshot_path.read_text()))
    if (snapshots[0] != snapshots[1] or
            not snapshots[0].get('readOnly') or
            set(snapshots[0].get('tables', {})) != {
                'user_organizationteam', 'user_organizationmember',
                'user_organizationaudit', 'user_organizationlock'} or
            snapshots[0].get('databaseUser') != 'phorge_probe@%' or
            baseline.get('schemaPermissionProbe', {}).get('user') != 'phorge_probe'):
        raise SystemExit('The original restricted-account schema snapshots do not match.')
if not re.fullmatch(r'report-[a-z0-9-]+\.json', args.output):
    raise SystemExit('Use a new report-NAME.json filename.')
output = original_path.parent/args.output
if output.exists():
    raise SystemExit('Refusing to overwrite existing evidence: '+str(output))
private = Path(baseline['privateConfigurationDirectory']).resolve()
if private.parent != Path('/tmp') or not private.name.startswith(run+'-'):
    raise SystemExit('Refusing a non-test private configuration directory.')
config = json.loads((private/'conf/local.json').read_text())
application = baseline['applicationContainer']
database = baseline['databaseContainer']
network = baseline['network']
if (application != run+'-php' or database != run+'-db' or network != run+'-net' or
        config.get('mysql.host') != database or
        config.get('storage.default-namespace') != 'project_regression_base'):
    raise SystemExit('Refusing non-test runtime configuration.')

spec = importlib.util.spec_from_file_location('generate_core', ROOT/'scripts/generate-core.py')
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
sources = generator.project_runtime_sources(staging=args.staging)
source_files = [{'source': row['source'].as_posix(), 'path': row['path'],
                 'sha256': hashlib.sha256((ROOT/row['source']).read_bytes()).hexdigest()}
                for row in sources]
expected = {row['path']: row['sha256'] for row in source_files}
previous = {row['path']: row['sha256'] for row in baseline['sourceFiles']}
previous_tests = {row['source']: row['sha256'] for row in baseline.get('testFiles', [])}
for path in ('src/extensions/TeamOrganization.php',
             'resources/sql/team-organization/20261027.organization.sql'):
    if expected.get(path) != previous.get(path):
        raise SystemExit('Schema/DAO source changed; run a fresh isolated installation.')

report = dict(baseline)
report.update({'passed': False, 'staging': args.staging,
               'derivedFrom': str(original_path), 'schemaProbeEvidence': str(original_path),
               'unchangedMigrationSources': True, 'sourceFiles': source_files,
               'recoveredFromFailedNativeBaseline': recovering,
               'sourceDiff': [path for path, digest in expected.items() if previous.get(path) != digest],
               'testFiles': test_files,
               'testSourceDiff': [row['source'] for row in test_files
                                  if previous_tests.get(row['source']) != row['sha256']],
               'tests': [], 'runtimeSourcesMatchBaseline': False})
report.pop('runtimeSourceHashes', None)
report.pop('error', None)
if recovering:
    report['failedBaselineError'] = baseline.get('error')
log_suffix = output.stem.removeprefix('report-')
secrets = [config.get('mysql.pass'), config.get('gorge.file.token')]

def call(command):
    return subprocess.run(command, text=True, capture_output=True)

def require(command):
    result = call(command)
    if result.returncode:
        raise RuntimeError('Isolated runtime inspection failed.')
    return result

def hashes_in_runtime():
    result = require(['docker', 'exec', application, 'sha256sum',
                      *('/opt/phorge/phorge/'+row['path'] for row in sources)])
    return {path.removeprefix('/opt/phorge/phorge/'): digest
            for digest, path in (line.split(None, 1) for line in result.stdout.splitlines())}

try:
    details = json.loads(require(['docker', 'network', 'inspect', network]).stdout)[0]
    if not details.get('Internal'):
        raise RuntimeError('The test network must remain internal.')
    runtime_before = hashes_in_runtime()
    if runtime_before != expected:
        report['runtimeSourceDiff'] = [path for path, digest in expected.items()
                                       if runtime_before.get(path) != digest]
        raise RuntimeError('Runtime sources differ from the captured baseline: '+
                           ', '.join(report['runtimeSourceDiff'])+
                           '. Freeze sources and inspect bind mounts before rechecking.')
    for name in native_suites:
        print('Rechecking '+name+' in '+application, flush=True)
        result = call(['docker', 'exec', application, 'php', '/work/tests/permissions/'+name+'.php'])
        log_text = result.stdout+result.stderr
        for secret in secrets:
            if secret:
                log_text = log_text.replace(secret, '[REDACTED]')
        log = output.parent/(name+'-'+log_suffix+'.log')
        if log.exists():
            raise RuntimeError('Refusing to overwrite an existing native log.')
        log.write_text(log_text)
        log.chmod(0o600)
        report['tests'].append({'name': name, 'exitCode': result.returncode, 'log': str(log)})
        print(name+': exit '+str(result.returncode), flush=True)
        if result.returncode:
            raise RuntimeError(name+' failed; inspect '+str(log))
    current = {row['path']: hashlib.sha256((ROOT/row['source']).read_bytes()).hexdigest()
               for row in sources}
    runtime = hashes_in_runtime()
    if current != expected or runtime != expected:
        raise RuntimeError('Application sources changed during native tests; rerun from a frozen source baseline.')
    if any(hashlib.sha256((ROOT/row['source']).read_bytes()).hexdigest() != row['sha256']
           for row in test_files):
        raise RuntimeError('Native regression suites changed during execution; rerun from frozen tests.')
    report.update({'runtimeSourceHashes': runtime, 'runtimeSourcesMatchBaseline': True,
                   'passed': True})
except Exception as error:
    report['error'] = str(error)
finally:
    output.write_text(json.dumps(report, indent=2)+'\n')
    output.chmod(0o600)
    print('Report: '+str(output), flush=True)
raise SystemExit(0 if report['passed'] else 1)
