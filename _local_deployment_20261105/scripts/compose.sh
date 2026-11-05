#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
files=(-f compose.core.yaml -f compose.identity.yaml -f compose.gateway.yaml)
envfiles=(--env-file .env --env-file .env.identity)
if [[ -f compose.testing.yaml ]]; then
  files+=(-f compose.testing.yaml)
fi
if [[ -f .public-enabled ]]; then
  files+=(-f compose.public.yaml)
fi
if [[ -f .registration-enabled ]]; then
  files+=(-f compose.registration.yaml)
  envfiles+=(--env-file .env.registration)
fi
if [[ -f .maintenance-enabled ]]; then
  files+=(-f compose.maintenance.yaml)
fi
if [[ -f .dingtalk-enabled ]]; then
  files+=(-f compose.dingtalk.yaml)
  envfiles+=(--env-file .env.dingtalk)
fi
exec docker compose "${envfiles[@]}" "${files[@]}" "$@"
