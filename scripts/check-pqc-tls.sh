#!/usr/bin/env bash
# Refuse classical TLS curve overrides in non-test Go code and tlsmlkem overrides
# anywhere in code, workflows, scripts, Dockerfiles, or deployment configs, then
# verify PQ TLS handshake tests pass under GODEBUG=fips140=on.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

curve_hits=$(git grep -n 'CurvePreferences' -- '*.go' ':!*_test.go' || true)
if [ -n "$curve_hits" ]; then
  echo "CurvePreferences is forbidden in non-test Go code; use Go defaults or pqtls.HybridOnly:" >&2
  echo "$curve_hits" >&2
  exit 1
fi

mlkem_hits=$(git grep -in 'tlsmlkem' -- . ':!scripts/check-pqc-tls.sh' ':!*.md' || true)
if [ -n "$mlkem_hits" ]; then
  echo "tlsmlkem overrides are forbidden:" >&2
  echo "$mlkem_hits" >&2
  exit 1
fi

GODEBUG=fips140=on go test -count=1 ./internal/brokerproto/... ./internal/connectors/adldaps/... ./internal/sso/...
