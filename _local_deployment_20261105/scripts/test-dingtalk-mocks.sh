#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# All provider calls in these tests use httptest/local transports. No real
# DingTalk credentials are passed to this container.
exec docker run --rm --network bridge \
  -e GOTOOLCHAIN=go1.27.3 -e GOMAXPROCS=2 -e GOFLAGS=-p=2 \
  -v "$PWD/vendor/herald-dingtalk:/src" -w /src \
  golang@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 \
  go test ./...
