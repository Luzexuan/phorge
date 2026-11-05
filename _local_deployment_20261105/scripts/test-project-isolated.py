#!/usr/bin/env python3
"""Run project PHP regressions against disposable, isolated Docker databases.

No production configuration, credentials, data volumes, or networks are used.
The only mounted application files are the deployment overrides and tests.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mysql-image', default=os.environ.get('TEAM_TEST_MYSQL_IMAGE', 'mysql:8.0.46'))
parser.add_argument('--phorge-image', default=os.environ.get('TEAM_TEST_PHORGE_IMAGE', 'team-management/phorge:e5141c7'))
parser.add_argument('--gorge-image', default=os.environ.get('TEAM_TEST_GORGE_IMAGE', 'team-management/gorge-file-storage:f1130b7'))
parser.add_argument('--keep', action='store_true', help='Keep only the isolated test containers and private configuration for debugging.')
parser.add_argument('--staging', action='store_true', help='Use project/organization staging replacements without changing production bind mounts.')
suite_choices = ('subproject-permissions', 'project-progress', 'project-organization',
                 'project-access', 'project-membership', 'project-member-import',
                 'project-team-policy', 'policy-display', 'policy-options')
parser.add_argument('--suite', action='append', choices=suite_choices,
                    help='Run only these native suites; repeat to select more than one. Default: all suites.')
args = parser.parse_args()
native_suites = tuple(dict.fromkeys(args.suite)) if args.suite else suite_choices
test_files = []
for name in native_suites:
    path = Path('tests/permissions')/(name+'.php')
    if not (ROOT/path).is_file():
        raise SystemExit('Missing native regression suite: '+str(path))
    test_files.append({'source': str(path),
                       'sha256': hashlib.sha256((ROOT/path).read_bytes()).hexdigest()})
run = 'team-project-regression-' + secrets.token_hex(4)
private = Path(tempfile.mkdtemp(prefix=run+'-', dir='/tmp'))
private.chmod(0o700)
report_dir = ROOT/'state'/'acceptance'/run
report_dir.mkdir(mode=0o700, parents=True)
network = run+'-net'
database = run+'-db'
application = run+'-php'
file_storage = run+'-files'
password = secrets.token_hex(32)
schema_password = secrets.token_hex(32)
file_token = secrets.token_hex(32)
(private/'gorge.env').write_text('GORGE_LISTEN_ADDR=:8100\nGORGE_SERVICE_TOKEN='+file_token+
    '\nGORGE_FILE_LOCAL_DISK_PATH=/var/lib/gorge/files\n')
(private/'gorge.env').chmod(0o600)
(private/'mysql.env').write_text('MYSQL_ROOT_PASSWORD='+password+'\nMYSQL_ROOT_HOST=%\n')
(private/'mysql.env').chmod(0o600)
conf = private/'conf'
conf.mkdir(mode=0o700)
(conf/'local.json').write_text(json.dumps({
    'mysql.host': database,
    'mysql.port': 3306,
    'mysql.user': 'root',
    'mysql.pass': password,
    'storage.default-namespace': 'project_regression_base',
    'phabricator.base-uri': 'http://project-regression.invalid/',
    'phabricator.silent': True,
    'notification.servers': [],
    'gorge.integrations': {},
    'gorge.file.uri': 'http://'+file_storage+':8100',
    'gorge.file.token': file_token,
}))
(conf/'local.json').chmod(0o600)
schema_conf = private/'schema-conf'
schema_conf.mkdir(mode=0o700)
schema_config = json.loads((conf/'local.json').read_text())
schema_config.update({'mysql.user': 'phorge_probe', 'mysql.pass': schema_password})
(schema_conf/'local.json').write_text(json.dumps(schema_config))
(schema_conf/'local.json').chmod(0o600)
manifest = json.loads((ROOT/'config/phorge/overrides/project-hierarchy-overrides.json').read_text())
spec = importlib.util.spec_from_file_location('generate_core', ROOT/'scripts/generate-core.py')
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
sources = generator.project_runtime_sources(staging=args.staging)
mounts = [
    '--mount', f'type=bind,src={conf},dst=/opt/phorge/phorge/conf/local,readonly',
    '--mount', f'type=bind,src={ROOT / "tests"},dst=/work/tests,readonly',
]
for item in sources:
    source = ROOT/item['source']
    if not source.is_file():
        raise SystemExit('Missing reviewed runtime source: '+str(item['source']))
    mounts += ['--mount', 'type=bind,src='+str(source)+
               ',dst=/opt/phorge/phorge/'+item['path']+',readonly']
schema_mounts = list(mounts)
schema_mounts[1] = f'type=bind,src={schema_conf},dst=/opt/phorge/phorge/conf/local,readonly'
report = {'run': run, 'scope': 'Disposable test database and network; no production data or credentials.',
          'network': network, 'databaseContainer': database, 'applicationContainer': application, 'fileStorageContainer': file_storage,
          'staging': args.staging,
          'sourceFiles': [{'source': row['source'].as_posix(), 'path': row['path'],
                           'sha256': hashlib.sha256((ROOT/row['source']).read_bytes()).hexdigest()} for row in sources],
          'testFiles': test_files,
          'tests': [], 'passed': False}
created = []
def call(argv, **kwargs):
    return subprocess.run(argv, text=True, capture_output=True, **kwargs)
def require(argv):
    result = call(argv)
    if result.returncode:
        # These commands contain paths/image names only; no secret arguments.
        raise RuntimeError(result.stderr.strip() or 'Docker command failed.')
    return result
try:
    # Verify images exist locally. Never implicitly pull an image.
    report['mysqlImageID'] = require(['docker', 'image', 'inspect', '--format', '{{.Id}}', args.mysql_image]).stdout.strip()
    report['phorgeImageID'] = require(['docker', 'image', 'inspect', '--format', '{{.Id}}', args.phorge_image]).stdout.strip()
    report['gorgeImageID'] = require(['docker', 'image', 'inspect', '--format', '{{.Id}}', args.gorge_image]).stdout.strip()
    require(['docker', 'network', 'create', '--internal', network])
    created.append(('network', network))
    require(['docker', 'run', '-d', '--pull=never', '--name', database,
             '--network', network, '--memory', '1g', '--cpus', '1',
             '--tmpfs', '/var/lib/mysql:rw,size=1g',
             '--env-file', str(private/'mysql.env'), args.mysql_image,
             '--innodb-buffer-pool-size=128M', '--max-allowed-packet=134217728',
             '--sql-mode=STRICT_ALL_TABLES', '--local-infile=0', '--partial-revokes=ON'])
    created.append(('container', database))
    print('Waiting for isolated test MySQL: '+database, flush=True)
    deadline = time.monotonic()+180
    while time.monotonic() < deadline:
        result = call(['docker', 'exec', database, 'sh', '-ec',
                       'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql --protocol=TCP -h 127.0.0.1 -uroot -NBe "SELECT 1"'])
        if result.returncode == 0:
            break
        time.sleep(2)
    else:
        raise RuntimeError('Isolated test MySQL did not become ready.')
    # Use the production generator's exact database grants for migration. The
    # native test harness still needs root to create its random fixture schemas.
    # This separate credential catches migrations which need unreviewed grants.
    grants = re.findall(r"GRANT ALL PRIVILEGES ON (`[^`]+`)\.\* TO 'phorge'@'%';",
                        generator.generate_sql(ROOT/'vendor/phorge', 'project_regression_base'))
    if not grants:
        raise RuntimeError('No production-equivalent database grants were generated.')
    sql = "CREATE USER 'phorge_probe'@'%' IDENTIFIED BY '"+schema_password+"';\n"
    sql += ''.join("GRANT ALL PRIVILEGES ON "+database_name+".* TO 'phorge_probe'@'%';\n"
                   for database_name in grants)
    grant_result = call(['docker', 'exec', '-i', database, 'sh', '-ec',
                         'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot'], input=sql)
    if grant_result.returncode:
        raise RuntimeError('Could not provision the isolated schema permission probe.')
    report['schemaPermissionProbe'] = {
        'user': 'phorge_probe', 'databaseCount': len(grants),
        'grantSource': 'generate-core.py exact production database grants',
        'nativeFixtureUser': 'root (random disposable fixture databases only)',
    }
    require(['docker', 'run', '-d', '--pull=never', '--name', file_storage,
             '--network', network, '--memory', '128m', '--cpus', '0.5',
             '--tmpfs', '/var/lib/gorge/files:rw,size=64m,mode=1777',
             '--env-file', str(private/'gorge.env'), args.gorge_image])
    created.append(('container', file_storage))
    deadline = time.monotonic()+30
    while time.monotonic() < deadline:
        result = call(['docker', 'exec', file_storage, 'wget', '-qO-', 'http://127.0.0.1:8100/readyz'])
        if result.returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('Isolated Gorge file storage did not become ready.')
    require(['docker', 'run', '-d', '--pull=never', '--name', application,
             '--network', network, '--memory', '768m', '--cpus', '1',
             '--entrypoint', '/bin/sleep', *mounts, args.phorge_image, 'infinity'])
    created.append(('container', application))
    commands = [
        ('schema-bootstrap', ['php', '/opt/phorge/phorge/bin/storage', 'upgrade', '--force']),
        ('organization-schema-before-recheck', ['php', '/work/tests/permissions/snapshot-organization-schema.php']),
        ('schema-recheck', ['php', '/opt/phorge/phorge/bin/storage', 'upgrade', '--force']),
        ('organization-schema-after-recheck', ['php', '/work/tests/permissions/snapshot-organization-schema.php']),
    ] + [(name, ['php', '/work/tests/permissions/'+name+'.php'])
         for name in native_suites]
    schema_before = None
    for label, command in commands:
        print('Running '+label+' in isolated containers.', flush=True)
        if label in ('schema-bootstrap', 'schema-recheck') or label.startswith('organization-schema-'):
            result = call(['docker', 'run', '--rm', '--pull=never',
                           '--name', application+'-schema', '--network', network,
                           '--memory', '768m', '--cpus', '1', '--entrypoint', '/usr/local/bin/php',
                           *schema_mounts, args.phorge_image, *command[1:]])
        else:
            result = call(['docker', 'exec', application, *command])
        # No generated credentials are printed or retained in logs.
        output = (result.stdout+result.stderr).replace(password, '[REDACTED]').replace(schema_password, '[REDACTED]').replace(file_token, '[REDACTED]')
        log = report_dir/(label+'.log')
        log.write_text(output)
        log.chmod(0o600)
        report['tests'].append({'name': label, 'exitCode': result.returncode, 'log': str(log)})
        print(label+': exit '+str(result.returncode)+'; log '+str(log), flush=True)
        if result.returncode and not (label in ('schema-bootstrap', 'schema-recheck') and result.returncode == 2):
            raise RuntimeError(label+' failed; inspect the private log.')
        if label == 'organization-schema-before-recheck':
            schema_before = json.loads(result.stdout)
            if schema_before.get('databaseUser') != 'phorge_probe@%':
                raise RuntimeError('Schema permission probe used the wrong database account.')
        if label == 'organization-schema-after-recheck':
            if json.loads(result.stdout) != schema_before:
                raise RuntimeError('Repeating storage upgrade changed organization schema or data.')
            report['organizationSchemaUpgradeRepeatSafe'] = True
    expected_hashes = {row['path']: row['sha256'] for row in report['sourceFiles']}
    current_hashes = {row['path']: hashlib.sha256((ROOT/row['source']).read_bytes()).hexdigest()
                      for row in sources}
    runtime_output = require(['docker', 'exec', application, 'sha256sum',
                              *('/opt/phorge/phorge/'+row['path'] for row in sources)]).stdout
    runtime_hashes = {}
    for line in runtime_output.splitlines():
        digest, path = line.split(None, 1)
        runtime_hashes[path.removeprefix('/opt/phorge/phorge/')] = digest
    if current_hashes != expected_hashes or runtime_hashes != expected_hashes:
        raise RuntimeError('Application sources changed during tests; rerun with a frozen source baseline.')
    if any(hashlib.sha256((ROOT/row['source']).read_bytes()).hexdigest() != row['sha256']
           for row in test_files):
        raise RuntimeError('Native regression suites changed during execution; rerun from frozen tests.')
    report['runtimeSourceHashes'] = runtime_hashes
    report['runtimeSourcesMatchBaseline'] = True
    report['passed'] = True
except Exception as error:
    report['error'] = str(error)
    print('Isolated regression failed: '+str(error), flush=True)
finally:
    if args.keep:
        report['privateConfigurationDirectory'] = str(private)
        report['keptForDebugging'] = True
        print('Isolated debug containers kept; private configuration: '+str(private), flush=True)
    else:
        cleanup = []
        for kind, name in reversed(created):
            command = ['docker', 'rm', '-f', name] if kind == 'container' else ['docker', 'network', 'rm', name]
            result = call(command)
            cleanup.append({'kind': kind, 'name': name, 'passed': result.returncode == 0})
        shutil.rmtree(private)
        report['cleanup'] = cleanup
        report['passed'] = report['passed'] and all(row['passed'] for row in cleanup)
    report_file = report_dir/'report.json'
    report_file.write_text(json.dumps(report, indent=2)+'\n')
    report_file.chmod(0o600)
    print('Report: '+str(report_file), flush=True)
raise SystemExit(0 if report['passed'] else 1)
