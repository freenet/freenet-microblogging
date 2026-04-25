#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
CONTRACT_ID=$(cat "$ROOT/published-contract/contract-id.txt")

GATEWAY="${GATEWAY:-http://127.0.0.1:50509}"
URL="$GATEWAY/v1/contract/web/$CONTRACT_ID/"

echo "smoke-testing $URL"

cd "$ROOT/web/tests"
BASE_URL="$URL" npx playwright test production-liveness.spec.ts
