#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
files=(-f compose.core.yaml -f compose.identity.yaml -f compose.gateway.yaml)
envfiles=(--env-file .env --env-file .env.identity)
[[ ! -f compose.testing.yaml ]] || files+=(-f compose.testing.yaml)
[[ ! -f .public-enabled ]] || files+=(-f compose.public.yaml)
if [[ -f .registration-enabled ]]; then
  files+=(-f compose.registration.yaml)
  envfiles+=(--env-file .env.registration)
fi
[[ ! -f .maintenance-enabled ]] || files+=(-f compose.maintenance.yaml)
files+=(-f compose.dingtalk.yaml)
envfiles+=(--env-file .env.dingtalk)
exec docker compose "${envfiles[@]}" "${files[@]}" "$@"
