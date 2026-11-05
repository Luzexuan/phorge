#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
umask 077
mkdir -p state
while read -r service version commit toolchain main_package; do
  image_tag="team-management/$service:${commit:0:8}"
  if [[ "$service" == "stargate" ]]; then
    python3 scripts/prepare-stargate-password.py
    image_tag="team-management/stargate:${commit:0:8}-personal-password"
    version="v1.2.0-personal-password"
  fi
  if [[ "${SKIP_EXISTING_IMAGES:-0}" == "1" ]] && docker image inspect "$image_tag" >/dev/null 2>&1; then
    printf 'Using existing local image %s (%s).\n' "$service" "${commit:0:8}"
    continue
  fi
  docker build --progress=plain \
    --file docker/identity.Dockerfile \
    --build-arg "GOTOOLCHAIN=$toolchain" \
    --build-arg "MAIN_PACKAGE=$main_package" \
    --build-arg "VERSION=$version" \
    --build-arg "COMMIT=$commit" \
    --label "org.opencontainers.image.source=https://github.com/soulteary/$service" \
    --label "org.opencontainers.image.revision=$commit" \
    --tag "$image_tag" "vendor/$service" \
    > "state/build-$service.log" 2>&1 || {
      tail -80 "state/build-$service.log" >&2
      exit 1
    }
  printf 'Built %s (%s).\n' "$service" "${commit:0:8}"
done <<'SERVICES'
stargate v1.2.0 3fd1784efa03df53005912b78fa2b7202c1dbba1 go1.27.1 ./src/cmd/stargate
warden v1.4.0 3cc5ee7cb5bcf1e02b7f2b8cbf721de16a3773f4 go1.27.1 .
herald v1.3.0 4deb444fafa056ca2e84e8bb0757cde7f9af7b17 go1.27.1 .
herald-smtp 1a63bb89 1a63bb89d3fb27629e3c50915626d98d1bb6fde2 go1.27.3 .
SERVICES
python3 - <<'PY'
import datetime, hashlib, json, pathlib, subprocess
root = pathlib.Path.cwd()
sources = json.loads((root / 'config/identity-sources.json').read_text())
images = []
for source in sources:
    service = source['repository'].split('/')[1]
    tag = f"team-management/{service}:{source['commit'][:8]}"
    if service == 'stargate':
        tag += '-personal-password'
    image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag]))[0]
    images.append({'tag': tag, 'id': image['Id'], 'architecture': image['Architecture'],
                   'created': image['Created'], 'source': source})
files = ['docker/identity.Dockerfile', 'config/identity-sources.json',
         'config/stargate/personal-password.patch', 'config/stargate/personal-password-source.json',
         'scripts/prepare-stargate-password.py']
for image in images:
    service = image['source']['repository'].split('/')[1]
    files += [f'vendor/{service}/go.mod', f'vendor/{service}/go.sum']
manifest = {'generatedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'images': images,
            'files': {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                      for name in files}}
(root / 'state/build-provenance-identity.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
