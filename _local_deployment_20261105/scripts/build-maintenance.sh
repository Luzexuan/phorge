#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p state
exec 9>state/build-maintenance.lock
flock 9
python3 - <<'PY'
import json,subprocess
expected='sha256:68e534371988bc2a580e47f8c5de20b203bb670d76793a1fbd7f85786fc8d4ee'
image=json.loads(subprocess.check_output(['docker','image','inspect','team-management/phorge:e5141c7']))[0]
if image['Id'] != expected:
    raise SystemExit('Phorge base image differs from the reviewed maintenance baseline; review before rebuilding.')
PY
docker build --progress=plain --file docker/maintenance.Dockerfile \
  --tag team-management/maintenance:e5141c7-v1 docker > state/build-maintenance.log 2>&1
python3 - <<'PY'
import datetime,hashlib,json,pathlib,subprocess
root=pathlib.Path.cwd()
image=json.loads(subprocess.check_output(['docker','image','inspect','team-management/maintenance:e5141c7-v1']))[0]
packages=subprocess.check_output(['docker','run','--rm','--network','none','--entrypoint','dpkg-query',image['Id'],'-W','python3','python3.13'],text=True).strip().splitlines()
out={'builtAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
     'image':'team-management/maintenance:e5141c7-v1','imageID':image['Id'],
     'phorgeBaseImageID':'sha256:68e534371988bc2a580e47f8c5de20b203bb670d76793a1fbd7f85786fc8d4ee',
     'packages':packages,'files':{p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in ['docker/maintenance.Dockerfile','scripts/build-maintenance.sh']}}
(root/'state/acceptance/maintenance-build.json').write_text(json.dumps(out,indent=2)+'\n')
print('Private maintenance runtime built; provenance recorded without credentials.')
PY
