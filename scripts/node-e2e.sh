#!/usr/bin/env bash
#
# Node-backed end-to-end test harness.
#
# Boots a FRESH, ISOLATED Freenet node (its own --config-dir / --data-dir, on a
# non-default port so it never touches a developer's running dev node), publishes
# the identity delegate + the packaged web container + the shard contracts to it,
# then runs the Playwright specs under web/tests/node-e2e/ against the node-SERVED
# webapp URL (http://127.0.0.1:<port>/v1/contract/web/<CID>/).
#
# This is the only tier that exercises the real browser -> live node -> delegate
# -> contract stack: WS connect, delegate identity flow, shard PUT/GET/UPDATE
# against compiled WASM in a node. The offline Playwright job (test-ui-playwright)
# only renders mock data and never touches a node. See issue #34 + docs/adr.
#
# Requires: the `freenet` node binary AND `fdev` on PATH (the offline tier needs
# only fdev). Heavier than per-PR CI — intended as a separate, non-blocking job.
#
# Env overrides:
#   E2E_WS_PORT   websocket api port for the throwaway node (default 7609)
#   E2E_KEEP      if set, do not delete the temp node dir on exit (for debugging)
#   PLAYWRIGHT_PROJECT  limit to one browser, e.g. "chromium" (default: all)

set -euo pipefail

ROOT="${CARGO_MAKE_WORKING_DIRECTORY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PORT="${E2E_WS_PORT:-7609}"

command -v freenet >/dev/null 2>&1 || { echo "ERROR: 'freenet' node binary not on PATH" >&2; exit 1; }
command -v fdev    >/dev/null 2>&1 || { echo "ERROR: 'fdev' not on PATH" >&2; exit 1; }

E2E_DIR="$(mktemp -d "${TMPDIR:-/tmp}/raven-node-e2e.XXXXXX")"
mkdir -p "$E2E_DIR/config" "$E2E_DIR/data"

NODE_PID=""

# The publish steps (update-published-contract / sign-webapp-test) REWRITE the
# committed release snapshot under published-contract/ and web/dist/. Those are
# tracked artifacts that must not change as a side effect of running tests, so we
# snapshot them up front and restore on exit. (The throwaway node's own state
# lives entirely under $E2E_DIR and is just deleted.)
SNAP_DIR="$E2E_DIR/_committed_snapshot"
mkdir -p "$SNAP_DIR"
[ -d "$ROOT/published-contract" ] && cp -R "$ROOT/published-contract" "$SNAP_DIR/published-contract"
[ -f "$ROOT/web/dist/index.html" ] && { mkdir -p "$SNAP_DIR/dist"; cp "$ROOT/web/dist/index.html" "$SNAP_DIR/dist/index.html"; }

cleanup() {
    [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
    # Restore the committed release snapshot the publish steps mutated.
    [ -d "$SNAP_DIR/published-contract" ] && { rm -rf "$ROOT/published-contract"; cp -R "$SNAP_DIR/published-contract" "$ROOT/published-contract"; }
    [ -f "$SNAP_DIR/dist/index.html" ] && cp "$SNAP_DIR/dist/index.html" "$ROOT/web/dist/index.html"
    if [ -n "${E2E_KEEP:-}" ]; then
        echo "E2E_KEEP set — leaving node dir: $E2E_DIR"
    else
        rm -rf "$E2E_DIR"
    fi
}
trap cleanup EXIT

echo "── booting throwaway Freenet node on 127.0.0.1:$PORT (dir: $E2E_DIR) ──"
# IPv4 bind (--ws-api-address 127.0.0.1): fdev publish dials 127.0.0.1, and the
# default dual-stack bind comes up IPv6-only on some hosts -> connection refused.
RUST_LOG="${RUST_LOG:-freenet=warn,info}" freenet local \
    --ws-api-address 127.0.0.1 --ws-api-port "$PORT" \
    --config-dir "$E2E_DIR/config" --data-dir "$E2E_DIR/data" \
    > "$E2E_DIR/node.log" 2>&1 &
NODE_PID=$!

# Wait for the WS API to accept connections.
ready=false
for _ in $(seq 1 60); do
    if curl -sS -m1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then ready=true; break; fi
    if ! kill -0 "$NODE_PID" 2>/dev/null; then
        echo "ERROR: node process exited during startup" >&2
        tail -30 "$E2E_DIR/node.log" >&2; exit 1
    fi
    sleep 1
done
[ "$ready" = true ] || { echo "ERROR: node WS api not ready within 60s" >&2; tail -30 "$E2E_DIR/node.log" >&2; exit 1; }
echo "node listening."

# Publish to THIS node. fdev resolves the node port from WS_API_PORT.
export WS_API_PORT="$PORT"

echo "── snapshotting + publishing identity delegate ──"
# update-published-contract records the test-signed web container + contract id.
cargo make update-published-contract
cargo make publish-identity

echo "── publishing packaged web container ──"
cargo make publish-webapp-test

CID="$(cat "$ROOT/published-contract/contract-id.txt")"
APP_URL="http://127.0.0.1:$PORT/v1/contract/web/$CID/"
echo "── webapp published. served at: $APP_URL ──"

# Wait for the served webapp GET to return the packaged HTML (not the node's
# "FN Peer" status page on /).
served=false
for _ in $(seq 1 30); do
    code="$(curl -sS -m5 -o /dev/null -w '%{http_code}' "$APP_URL" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then served=true; break; fi
    sleep 2
done
[ "$served" = true ] || { echo "ERROR: served webapp not reachable (last http=$code)" >&2; exit 1; }

echo "── running node-e2e Playwright specs ──"
cd "$ROOT/web/tests"
proj_args=()
[ -n "${PLAYWRIGHT_PROJECT:-}" ] && proj_args=(--project="$PLAYWRIGHT_PROJECT")
# PLAYWRIGHT_GREP limits to specs/titles matching a substring (default: all).
grep_args=()
[ -n "${PLAYWRIGHT_GREP:-}" ] && grep_args=(--grep="$PLAYWRIGHT_GREP")
BASE_URL="$APP_URL" npx playwright test --config=playwright.node.config.ts "${proj_args[@]}" "${grep_args[@]}"
