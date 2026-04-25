# Freenet Microblogging – Agent Guide

## Overview

Decentralized Twitter/X-like microblogging application built on Freenet. Uses a
TypeScript web UI with Vite, Rust WASM contracts for post storage and social
graph, an Ed25519 identity delegate for signing, and the `@freenetorg/freenet-stdlib`
TypeScript SDK for WebSocket communication with a Freenet node.

## Quick Reference

### Commands

```bash
# Build
cargo make build                # Full build: contracts + UI + web container
cargo make build-contracts      # Posts + follows + likes + identity (WASM + code hashes)
cargo make build-ui             # Vite/TypeScript build (depends on build-contracts)
cargo make build-web-container  # web/container Rust → WASM
cargo make build-ui-offline     # Vite build with mock data (no Freenet node) — for CI

# Publish (local node)
cargo make publish-posts        # Publish posts contract
cargo make publish-follows      # Publish follows contract
cargo make publish-likes        # Publish likes contract
cargo make publish-identity     # Publish identity delegate
cargo make publish-webapp-test  # Publish test-signed webapp from published-contract/
cargo make publish-all          # End-to-end: build → sign-test → snapshot → publish all

# Publish (PRODUCTION — use scripts/release.sh, not directly)
cargo make publish-production   # Build → sign with prod key → snapshot → publish to live network

# Release
scripts/release.sh 0.1.0        # End-to-end release driver (preflight + 3 confirmation gates)

# Development
cd web && npm run dev           # Vite dev server on :8080
cargo make dev-offline          # Vite dev server with mock data (no node required)

# Quality
cargo make test                 # Rust tests + Vitest
cargo make clippy               # Workspace clippy, deny warnings
cargo make fmt-check            # cargo fmt --check
cargo make check                # cargo check + tsc --noEmit

# Playwright
cargo make test-ui-playwright-setup  # One-time browser install
cargo make test-ui-playwright        # Run E2E suite

# Node
cargo make run-node             # Local Freenet node
```

### Repository Structure

```
freenet-microblogging/
├── contracts/
│   ├── posts/                  # Posts contract (Rust → WASM)
│   │   ├── src/lib.rs          # PostsFeed: store, validate, merge posts
│   │   ├── Cargo.toml
│   │   ├── freenet.toml
│   │   └── initial_state.json  # {"posts": []}
│   └── follows/                # Follows contract (Rust → WASM)
│       ├── src/lib.rs          # FollowGraph: follow/unfollow actions
│       ├── Cargo.toml
│       ├── freenet.toml
│       └── initial_state.json  # {"follows": {}}
├── delegates/
│   └── identity/               # Identity delegate (Rust → WASM)
│       ├── src/lib.rs          # Ed25519 keypair, signing
│       ├── Cargo.toml
│       └── freenet.toml
├── web/                        # TypeScript web frontend
│   ├── index.html              # App entry point (Vite serves this)
│   ├── vite.config.ts          # Vite bundler config
│   ├── src/
│   │   ├── index.ts            # Entry: mounts app shell
│   │   ├── app.ts              # App shell: assembles 3-column layout
│   │   ├── types.ts            # Post, User, TrendingTopic interfaces
│   │   ├── mock-data.ts        # Mock posts/users for development
│   │   ├── theme.ts            # Dark/light mode toggle
│   │   ├── utils.ts            # formatRelativeTime helper
│   │   ├── vite-env.d.ts       # Vite type declarations
│   │   ├── components/
│   │   │   ├── sidebar.ts      # Logo, nav, theme toggle, post CTA
│   │   │   ├── feed.ts         # Tab bar, compose, post list, filtering
│   │   │   ├── compose-box.ts  # Textarea, char counter, post button
│   │   │   ├── post-card.ts    # Post card with actions, timestamps
│   │   │   ├── right-panel.ts  # Search, trending, who-to-follow
│   │   │   └── bottom-nav.ts   # Mobile bottom navigation
│   │   └── scss/
│   │       ├── styles.scss     # Main entry (imports all partials)
│   │       ├── _variables.scss # CSS custom properties (design tokens)
│   │       ├── _reset.scss     # Minimal reset
│   │       ├── _layout.scss    # 3-column grid
│   │       ├── _sidebar.scss   # Sidebar styles
│   │       ├── _feed.scss      # Feed, compose, post cards
│   │       ├── _right-panel.scss # Trending, follow cards
│   │       ├── _buttons.scss   # Button variants
│   │       ├── _dark-mode.scss # Dark mode overrides
│   │       └── _responsive.scss # Mobile/tablet breakpoints
│   ├── container/              # Web contract container (Rust → WASM)
│   │   └── src/lib.rs
│   ├── package.json
│   ├── tsconfig.json
│   └── freenet.toml
├── Cargo.toml                  # Workspace root
├── Makefile.toml               # Build orchestration (cargo-make)
├── DESIGN.md                   # Visual design system specification
├── CLAUDE.md                   # → points to this file
└── AGENTS.md                   # This file (single source of truth)
```

### Key Dependencies

| Dependency | Purpose |
|-----------|---------|
| `@freenetorg/freenet-stdlib` | Freenet TypeScript SDK — WebSocket API, FlatBuffers types |
| `vite` | Build tool and dev server |
| `vitest` | Test runner |
| `typescript` | Language |
| `sass` | SCSS compilation |
| `freenet-stdlib` (Rust) | Contract/delegate traits, WASM macros |
| `ed25519-dalek` (Rust) | Ed25519 signing for identity delegate |
| `freenet` (cargo) | Freenet node binary |
| `fdev` (cargo) | Freenet developer tools (build, publish, inspect) |

### Architecture

- **Posts Contract** (`contracts/posts/`): Rust WASM contract storing microblog
  posts as JSON. Each post has id, author_pubkey, author_name, author_handle,
  content (max 280 chars), timestamp, and optional signature. Merge is
  commutative: dedup by post hash (Blake3 of id).

- **Follows Contract** (`contracts/follows/`): Rust WASM contract storing the
  social graph as `HashMap<pubkey, HashSet<pubkey>>`. Supports Follow/Unfollow
  actions. Merge is commutative for follows (set union).

- **Identity Delegate** (`delegates/identity/`): Runs locally on user's device.
  Generates/stores Ed25519 keypairs via Freenet's encrypted secret storage.
  Signs post content on request. Communicates with web UI via ApplicationMessage.

- **Web Container** (`web/container/`): Minimal Rust WASM contract serving the
  compiled web app as a Freenet webapp.

- **Web App** (`web/src/`): TypeScript SPA with Vite. Twitter/X-like 3-column
  layout (sidebar / feed / right panel). Components: sidebar nav, compose box
  with 280-char limit, post cards with like/repost/reply actions, trending
  topics, who-to-follow suggestions, dark mode toggle, responsive design with
  mobile bottom nav and FAB.

### Build Flow

```
contracts/{posts,follows,likes}/src/lib.rs
    → fdev build → WASM
    → fdev inspect → code hash → build/<name>_code_hash
    (posts hash also mirrored to web/model_code_hash.txt for vite.config.ts)

delegates/identity/src/lib.rs
    → fdev build --package-type delegate → WASM
    → b3sum-derived delegate key → web/delegate_key{,_bytes,_code_hash_bytes}.{txt,json}

web/src/index.ts
    → vite build (defines: __MODEL_CONTRACT__, __DELEGATE_KEY__, __OFFLINE_MODE__)
    → web/dist/

web/dist
    → cargo make compress-webapp → target/webapp/webapp.tar.xz (GNU tar, fixed mtime)
    → cargo make sign-webapp{,-test} → webapp.metadata + webapp.parameters
    → cargo make update-published-contract{,-prod} → published-contract/{wasm,parameters,contract-id.txt}
    → cargo make publish-webapp{,-test} → fdev publish (against committed snapshot)
```

The `published-contract/` directory is committed. CI verifies it matches HEAD.
Production releases bump the snapshot via `scripts/release.sh`.

### Releasing

See `RELEASING.md` for the production release runbook. TL;DR:

```bash
scripts/release.sh 0.1.0
```

Three confirmation gates. Idempotent up to the commit step. The committed
`published-contract/` snapshot is what CI and downstream consumers verify
against, not freshly built artifacts.

### Testing

```bash
cargo make test                                # All tests
cargo test -p freenet-microblogging-posts       # Posts contract (5 tests)
cargo test -p freenet-microblogging-follows     # Follows contract (4 tests)
cd web && npm test                              # Web app (Vitest)
```

### Environment Requirements

- `CARGO_TARGET_DIR` must be set (required by Makefile.toml)
- Node.js and npm for web app
- Rust toolchain with `wasm32-unknown-unknown` target
- `freenet` and `fdev` CLI tools (`cargo install freenet fdev`)

## Conventions

- All Freenet protocol messages use FlatBuffers types from the stdlib
- Contract state is JSON-encoded, transported as `Uint8Array`
- Delta updates are JSON arrays of post/action objects
- WebSocket URL pattern: `ws://{host}/contract/command`
- Contract keys derived from instance ID via `ContractKey.fromInstanceId()`
- CSS follows BEM naming: `block__element--modifier`
- SCSS uses CSS custom properties (design tokens) defined in `_variables.scss`
- Dark mode via `[data-theme="dark"]` attribute on `<html>`
- UI components are pure TypeScript DOM functions (no framework)
- Posts limited to 280 characters (validated in contract + UI)
- Ed25519 signatures for post authenticity (via identity delegate)
