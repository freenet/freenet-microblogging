# published-contract/

Committed snapshot of the most recently released web container contract.

- `web_container_contract.wasm` — compiled web container (Rust → WASM)
- `webapp.parameters` — signed parameters (ed25519 pubkey + version)
- `contract-id.txt` — derived contract ID (`hash(wasm, parameters)`)

**Updated by:** `cargo make update-published-contract` (test) or
`cargo make update-published-contract-prod` (production).

**Bumped on release** by `scripts/release.sh` and committed alongside an
annotated `vX.Y.Z` tag. CI verifies HEAD's contract ID matches this snapshot
(`.github/workflows/check-contract-wasm.yml`).
