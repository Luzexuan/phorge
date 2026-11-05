#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
umask 077
mkdir -p state config/build
exec 9>state/build-images.lock
flock 9
LOCK=vendor/phorge/deploy/acceptance/build-lock.json
read_lock() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); print(v[sys.argv[2]][sys.argv[3]] if len(sys.argv)>3 else v[sys.argv[2]])' "$LOCK" "$@"; }
PHP_BASE_IMAGE=$(read_lock images php)
GO_BASE_IMAGE=$(read_lock images go)
RUNTIME_BASE_IMAGE=$(read_lock images alpine)
PHORGE_TAG=team-management/phorge:e5141c7
GORGE_TAG=f1130b7
GORGE_REVISION=f1130b74f072c1d1d5ad7ad11b626be3d6a5d3ad
BUILD_TARGET=${1:-all}
if [[ "$BUILD_TARGET" != all && "$BUILD_TARGET" != phorge && "$BUILD_TARGET" != gorge ]]; then
  printf 'Usage: %s [all|phorge|gorge]\n' "$0" >&2
  exit 2
fi
if [[ "$BUILD_TARGET" == all || "$BUILD_TARGET" == phorge ]]; then
  if [[ "${FORCE_BUILD:-0}" != 1 ]] && docker image inspect "$PHORGE_TAG" >/dev/null 2>&1; then
    printf 'Reusing %s (FORCE_BUILD=1 rebuilds pinned sources).\n' "$PHORGE_TAG"
  else
  docker build --progress=plain \
    --file config/build/Phorge.Dockerfile \
    --build-arg "PHP_BASE_IMAGE=$PHP_BASE_IMAGE" \
    --build-arg "DEBIAN_SNAPSHOT=$(read_lock debianSnapshot)" \
    --build-arg "APCU_VERSION=$(read_lock apcu)" \
    --build-arg "APCU_SHA256=$(read_lock apcuSHA256)" \
    --label org.opencontainers.image.source=https://github.com/soulteary/phorge \
    --label org.opencontainers.image.revision=e5141c768b37eeb9a114198cc8df9664173be638 \
    --tag "$PHORGE_TAG" vendor/phorge 2>&1 | tee state/build-phorge.log
  fi
fi
if [[ "$BUILD_TARGET" == all || "$BUILD_TARGET" == gorge ]]; then
  GORGE_BUILDER_IMAGE="team-management/gorge-builder:$GORGE_TAG"
  if [[ "${FORCE_BUILD:-0}" == 1 ]] || ! docker image inspect "$GORGE_BUILDER_IMAGE" >/dev/null 2>&1; then
    docker build --progress=plain \
      --file config/build/Gorge-builder.Dockerfile \
      --build-arg "GO_BASE_IMAGE=$GO_BASE_IMAGE" \
      --build-arg "SOURCE_REVISION=$GORGE_REVISION" \
      --tag "$GORGE_BUILDER_IMAGE" vendor/gorge/go \
      2>&1 | tee state/build-gorge-builder.log
  fi
  while read -r service port; do
    if [[ "${FORCE_BUILD:-0}" != 1 ]] && docker image inspect "team-management/gorge-$service:$GORGE_TAG" >/dev/null 2>&1; then
      printf 'Reusing team-management/gorge-%s:%s.\n' "$service" "$GORGE_TAG"
      continue
    fi
    docker build --progress=plain \
      --file config/build/Gorge.Dockerfile \
      --build-arg "BINARY_IMAGE=$GORGE_BUILDER_IMAGE" \
      --build-arg "RUNTIME_BASE_IMAGE=$RUNTIME_BASE_IMAGE" \
      --build-arg "SERVICE=gorge-$service" \
      --build-arg "PORT=$port" \
      --build-arg "SOURCE_REVISION=$GORGE_REVISION" \
      --tag "team-management/gorge-$service:$GORGE_TAG" vendor/gorge/go \
      2>&1 | tee "state/build-gorge-$service.log"
  done <<'SERVICES'
render 8140
conduit 8150
notification 22281
file-storage 8100
webhook 8160
taskqueue 8090
worker 8170
db-api 8080
SERVICES
fi
python3 - <<'PY'
import datetime, hashlib, json, pathlib, subprocess
root=pathlib.Path.cwd()
tags=['team-management/phorge:e5141c7']+['team-management/gorge-'+s+':f1130b7' for s in ['render','conduit','notification','file-storage','webhook','taskqueue','worker','db-api']]
images=[]
for tag in tags:
    p=subprocess.run(['docker','image','inspect',tag],capture_output=True,text=True)
    if p.returncode==0:
        i=json.loads(p.stdout)[0]
        images.append({'tag':tag,'id':i['Id'],'created':i['Created'],'architecture':i['Architecture'],'sourceRevisionLabel':i['Config'].get('Labels',{}).get('org.opencontainers.image.revision')})
files=['scripts/build-images.sh','config/build/Phorge.Dockerfile','config/build/Gorge-builder.Dockerfile','config/build/Gorge.Dockerfile','vendor/phorge/deploy/acceptance/build-lock.json','vendor/gorge/go/go.mod','vendor/gorge/go/go.sum']
binary_build={}
builder='team-management/gorge-builder:f1130b7'
p=subprocess.run(['docker','image','inspect',builder],capture_output=True,text=True)
if p.returncode==0:
    compiler=subprocess.run(['docker','run','--rm','--network','none','--entrypoint','go',builder,'version'],capture_output=True,text=True,check=True).stdout.strip()
    assert compiler.startswith('go version go1.27.2 '),compiler
    sums=subprocess.run(['docker','run','--rm','--network','none','--entrypoint','sh',builder,'-c','sha256sum /out/gorge-*'],capture_output=True,text=True,check=True).stdout
    hashes={line.split()[1]:line.split()[0] for line in sums.splitlines()}
    assert len(hashes)==8,hashes
    binary_build={'image':builder,'id':json.loads(p.stdout)[0]['Id'],'compiler':compiler,'binarySHA256':hashes}
out={'generatedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
     'sourceRevisions':{'phorge':'e5141c768b37eeb9a114198cc8df9664173be638','gorge':'f1130b74f072c1d1d5ad7ad11b626be3d6a5d3ad'},
     'sourceRepositories':{'phorge':'https://github.com/soulteary/phorge','gorge':'https://github.com/soulteary/gorge'},
     'buildLock':json.loads((root/'vendor/phorge/deploy/acceptance/build-lock.json').read_text()),
     'binaryBuild':binary_build,
     'images':images,'files':{f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in files}}
temporary=root/'state/build-provenance.json.tmp'
temporary.write_text(json.dumps(out,indent=2)+'\n')
temporary.replace(root/'state/build-provenance.json')
PY
