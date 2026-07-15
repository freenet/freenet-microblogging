#!/usr/bin/env bash
#
# Multi-node end-to-end harness: realistic usage journeys across a REAL local
# Freenet network (1 gateway + 2 peers) with two browser users on different
# nodes. Complements scripts/node-e2e.sh (single `freenet local` node): this
# tier is the only one that exercises cross-node propagation — contract
# replication, the global-index public timeline across nodes, live update
# notifications to remote subscribers, and cross-node thread reads.
#
# Requires:
#   * `fdev` on PATH (publishing).
#   * a checkout of https://github.com/freenet/freenet-test-network at
#     FREENET_TEST_NETWORK_DIR (default: ../freenet-test-network next to this
#     repo). The runner example (scripts/test-network-runner.rs) is copied in
#     and built there, so the checkout's target/ cache is reused.
#   * `freenet` on PATH, or FREENET_TEST_BINARY pointing at a specific build.
#
# NOTE (macOS): freenet-test-network assigns per-node loopback IPs that stock
# macOS cannot bind; it needs the fix from freenet-test-network#4 (use
# 127.0.0.1 on macOS) in the checkout until that PR is released.
#
# Env overrides:
#   FREENET_TEST_NETWORK_DIR  test-network checkout (see above)
#   FREENET_TEST_BINARY       freenet binary for the nodes (default: PATH)
#   E2E_KEEP                  if set, keep the network + logs running on exit
#   PLAYWRIGHT_GREP           limit journeys by title substring

set -euo pipefail

ROOT="${CARGO_MAKE_WORKING_DIRECTORY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TN_DIR="${FREENET_TEST_NETWORK_DIR:-$ROOT/../freenet-test-network}"

command -v fdev >/dev/null 2>&1 || { echo "ERROR: 'fdev' not on PATH" >&2; exit 1; }
[ -d "$TN_DIR" ] || {
    echo "ERROR: freenet-test-network checkout not found at $TN_DIR" >&2
    echo "       clone https://github.com/freenet/freenet-test-network or set FREENET_TEST_NETWORK_DIR" >&2
    exit 1
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/raven-multinode.XXXXXX")"
NET_LOG="$WORK/network.log"
NET_PID=""

# The publish steps rewrite the committed release snapshot (published-contract/
# + the signed web/dist/index.html) — snapshot and restore, same contract as
# node-e2e.sh.
SNAP="$WORK/_committed_snapshot"
mkdir -p "$SNAP"
[ -d "$ROOT/published-contract" ] && cp -R "$ROOT/published-contract" "$SNAP/published-contract"
[ -f "$ROOT/web/dist/index.html" ] && { mkdir -p "$SNAP/dist"; cp "$ROOT/web/dist/index.html" "$SNAP/dist/index.html"; }

cleanup() {
    if [ -n "${E2E_KEEP:-}" ]; then
        echo "E2E_KEEP set — leaving network running (pid $NET_PID, log $NET_LOG)"
    else
        [ -n "$NET_PID" ] && kill "$NET_PID" 2>/dev/null || true
        # The runner's Drop kills the nodes; belt-and-braces for orphans:
        pkill -f "freenet-test-networks" 2>/dev/null || true
    fi
    [ -d "$SNAP/published-contract" ] && { rm -rf "$ROOT/published-contract"; cp -R "$SNAP/published-contract" "$ROOT/published-contract"; }
    [ -f "$SNAP/dist/index.html" ] && cp "$SNAP/dist/index.html" "$ROOT/web/dist/index.html"
    [ -n "${E2E_KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

echo "── booting test network (1 gateway + 2 peers) via $TN_DIR ──"
cp "$ROOT/scripts/test-network-runner.rs" "$TN_DIR/examples/raven_net.rs"
(
    cd "$TN_DIR"
    exec cargo run --release --example raven_net
) > "$NET_LOG" 2>&1 &
NET_PID=$!

ready=false
for _ in $(seq 1 120); do
    grep -q "RAVEN_NET_READY" "$NET_LOG" 2>/dev/null && { ready=true; break; }
    grep -q "connectivity check failed" "$NET_LOG" 2>/dev/null && break
    kill -0 "$NET_PID" 2>/dev/null || break
    sleep 3
done
[ "$ready" = true ] || { echo "ERROR: network failed to boot" >&2; tail -40 "$NET_LOG" >&2; exit 1; }

GW_PORT="$(grep -o 'GATEWAY_WS=ws://127.0.0.1:[0-9]*' "$NET_LOG" | grep -o '[0-9]*$')"
PEER_PORT="$(grep -o 'PEER0_WS=ws://127.0.0.1:[0-9]*' "$NET_LOG" | grep -o '[0-9]*$')"
[ -n "$GW_PORT" ] && [ -n "$PEER_PORT" ] || { echo "ERROR: could not parse node ports" >&2; exit 1; }
echo "network up: gateway ws :$GW_PORT, peer0 ws :$PEER_PORT"

echo "── building + publishing raven (delegate + webapp on gateway AND peer0) ──"
cargo make update-published-contract
for port in "$GW_PORT" "$PEER_PORT"; do
    WS_API_PORT="$port" cargo make publish-identity
    WS_API_PORT="$port" cargo make publish-webapp-test
done

CID="$(cat "$ROOT/published-contract/contract-id.txt")"
GW_APP_URL="http://127.0.0.1:$GW_PORT/v1/contract/web/$CID/"
PEER_APP_URL="http://127.0.0.1:$PEER_PORT/v1/contract/web/$CID/"

for url in "$GW_APP_URL" "$PEER_APP_URL"; do
    served=false
    for _ in $(seq 1 30); do
        code="$(curl -sS -m10 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
        [ "$code" = "200" ] && { served=true; break; }
        sleep 2
    done
    [ "$served" = true ] || { echo "ERROR: webapp not served at $url (last http=$code)" >&2; exit 1; }
done
echo "── webapp served on both nodes ──"

echo "── running multi-node journeys ──"
cd "$ROOT/web/tests"
grep_args=()
[ -n "${PLAYWRIGHT_GREP:-}" ] && grep_args=(--grep="$PLAYWRIGHT_GREP")
GW_APP_URL="$GW_APP_URL" PEER_APP_URL="$PEER_APP_URL" \
    npx playwright test --config=playwright.multinode.config.ts "${grep_args[@]}"
