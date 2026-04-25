#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
ASSUME_YES=false
if [ "${2:-}" = "--yes" ] || [ "${1:-}" = "--yes" ]; then
    ASSUME_YES=true
    [ "${1:-}" = "--yes" ] && VERSION="${2:-}"
fi

if [ -z "$VERSION" ]; then
    echo "usage: scripts/release.sh <version> [--yes]" >&2
    echo "example: scripts/release.sh 0.1.0" >&2
    exit 2
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]; then
    echo "error: version must be semver (e.g. 0.1.0 or 0.1.0-rc.1)" >&2
    exit 2
fi

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

confirm() {
    $ASSUME_YES && return 0
    read -r -p "$1 [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

# ─── 1. Preflight ──────────────────────────────────────────────────────────────
echo "── preflight ─────────────────────────────────────────────────────────────"

[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || {
    echo "error: not on main" >&2; exit 1; }

git diff --quiet && git diff --cached --quiet || {
    echo "error: working tree dirty" >&2; exit 1; }

git fetch origin --tags
if git rev-parse "v$VERSION" >/dev/null 2>&1; then
    echo "error: tag v$VERSION already exists locally" >&2; exit 1
fi
if git ls-remote --tags origin "v$VERSION" | grep -q "v$VERSION"; then
    echo "error: tag v$VERSION already exists on origin" >&2; exit 1
fi

KEY_FILE="${WEB_CONTAINER_KEY_FILE:-$HOME/.config/freenet-microblogging/web-container-keys.toml}"
[ -f "$KEY_FILE" ] || { echo "error: production key missing at $KEY_FILE" >&2; exit 1; }

for cmd in fdev cargo-make gh; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "error: $cmd not on PATH" >&2; exit 1; }
done

if ! command -v gtar >/dev/null 2>&1 && ! tar --version 2>/dev/null | grep -qi 'gnu tar'; then
    echo "error: GNU tar required (macOS: brew install gnu-tar)" >&2; exit 1
fi

if ! curl -fsS --max-time 3 "http://127.0.0.1:50509/v1/contract/info" >/dev/null 2>&1 \
   && ! nc -z 127.0.0.1 50509 2>/dev/null; then
    echo "error: local Freenet node unreachable on 127.0.0.1:50509" >&2; exit 1
fi
echo "preflight ✓"

# ─── 2. Test gate ──────────────────────────────────────────────────────────────
echo "── tests ─────────────────────────────────────────────────────────────────"
cargo make test
cargo make clippy
echo "tests ✓"

# ─── 3. First confirmation ─────────────────────────────────────────────────────
cat <<EOF

This will perform 6 IRREVERSIBLE steps for v$VERSION:
  1. Build + sign webapp with PRODUCTION key
  2. Update published-contract/ with new contract ID
  3. Publish webapp to the live Freenet network
  4. Commit published-contract/ on main
  5. Create annotated tag v$VERSION with auto-generated notes
  6. Push commit + tag to origin

EOF
confirm "Proceed?" || { echo "aborted"; exit 0; }

# ─── 4. Build, sign, publish ───────────────────────────────────────────────────
echo "── publish-production ────────────────────────────────────────────────────"
cargo make publish-production

# ─── 5. Verify snapshot changed ────────────────────────────────────────────────
if git diff --quiet -- published-contract/; then
    echo "error: published-contract/ did not change — nothing to release" >&2
    exit 1
fi

NEW_ID=$(cat published-contract/contract-id.txt)
echo
echo "── new contract id: $NEW_ID ────────────────────────────────"
git --no-pager diff --stat -- published-contract/

# ─── 6. Second confirmation ────────────────────────────────────────────────────
confirm "Commit published-contract/ and proceed to tag?" || {
    echo "aborted — published-contract/ left modified for inspection"; exit 0; }

# ─── 7. Commit ─────────────────────────────────────────────────────────────────
git add published-contract/
git commit -m "release: v$VERSION

Contract ID: $NEW_ID
"

# ─── 8. Tag ────────────────────────────────────────────────────────────────────
PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [ -n "$PREV_TAG" ]; then
    NOTES=$(git log --pretty=format:"- %s (%h)" "$PREV_TAG"..HEAD)
else
    NOTES=$(git log --pretty=format:"- %s (%h)" HEAD)
fi

git tag -a "v$VERSION" -m "v$VERSION

Contract ID: $NEW_ID

Changes since $PREV_TAG:
$NOTES
"

# ─── 9. Third confirmation ─────────────────────────────────────────────────────
echo
echo "── ready to push ────────────────────────────────────────────────────────"
echo "  git push origin main"
echo "  git push origin v$VERSION"
confirm "Push?" || {
    echo "stopped before push — run \`git push origin main && git push origin v$VERSION\` when ready"
    exit 0
}

git push origin main
git push origin "v$VERSION"

echo
echo "── released v$VERSION ────────────────────────────────────────────────────"
echo "  contract id: $NEW_ID"
