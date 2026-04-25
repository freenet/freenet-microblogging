#!/usr/bin/env bash
set -euo pipefail

KEY_DIR="${HOME}/.config/freenet-microblogging"
KEY_FILE="${WEB_CONTAINER_KEY_FILE:-${KEY_DIR}/web-container-keys.toml}"

if [ -f "$KEY_FILE" ]; then
    echo "error: $KEY_FILE already exists" >&2
    echo "       refusing to overwrite — back it up and remove it first if you really want to rotate" >&2
    exit 1
fi

mkdir -p "$(dirname "$KEY_FILE")"
chmod 700 "$(dirname "$KEY_FILE")"

cargo run --quiet -p web-container-sign -- generate --output "$KEY_FILE"
chmod 600 "$KEY_FILE"

cat <<EOF

╔══════════════════════════════════════════════════════════════════════════════╗
║  PRODUCTION KEY GENERATED                                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Location: $KEY_FILE
║                                                                              ║
║  THIS KEY CANNOT BE RECOVERED. Back it up NOW:                               ║
║    cp "$KEY_FILE" /path/to/secure/offline/backup
║                                                                              ║
║  Anyone with this key can publish updates that the network will accept as   ║
║  authentic. Treat it like an SSH private key.                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
