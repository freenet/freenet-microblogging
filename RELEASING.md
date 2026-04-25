# Releasing freenet-microblogging

## One-time setup (per release operator)

1. Generate the production signing key:

   ```bash
   scripts/generate-production-key.sh
   ```

   Writes `~/.config/freenet-microblogging/web-container-keys.toml` with `chmod 600`.

2. Back it up immediately (offline, encrypted). The key cannot be recovered.

3. Install prerequisites:

   ```bash
   cargo install cargo-make fdev
   brew install gnu-tar gh    # macOS — Linux ships GNU tar
   ```

4. Confirm local Freenet node reaches the network:

   ```bash
   freenet local --ws-api-address 127.0.0.1
   ```

## Cutting a release

```bash
scripts/release.sh 0.1.0
```

The script enforces:
- clean tree on `main`
- tag does not already exist
- production key + tools present
- node reachable at `127.0.0.1:50509`
- `cargo make test` and `cargo make clippy` pass

It then prompts 3 times before destructive steps:
1. Before publishing to the live network
2. Before committing `published-contract/`
3. Before pushing to `origin`

## Recovery

If `release.sh` fails or you abort partway:

| Stage reached            | What's safe                                  | What to clean up                                                    |
|--------------------------|----------------------------------------------|---------------------------------------------------------------------|
| Preflight or tests       | nothing changed                              | nothing                                                             |
| `publish-production` ran | webapp is live on network with new contract ID | re-run release.sh with the same version — `update-published-contract-prod` is idempotent |
| Commit created           | repo state captures the release              | if not pushed: `git reset --hard HEAD~1` to back out                 |
| Tag created              | tag is local-only until push                 | `git tag -d v0.1.0` to remove local tag                              |
| Push completed           | release is final                             | follow `RELEASING.md` §Hotfix to publish a corrected version         |

## Hotfix (republish at a new contract ID)

A published contract ID is permanent. To replace it:
1. Bump version (e.g. 0.1.0 → 0.1.1)
2. Make the fix on a branch, merge to main
3. Run `scripts/release.sh 0.1.1`

The new contract ID supersedes the old one in `published-contract/`. Users
following the published gateway URL get the new version automatically.

## Production key backup

The key in `~/.config/freenet-microblogging/web-container-keys.toml` is the
ONLY way to publish updates that this contract's clients will accept as
authentic. Treat it like a domain-name registrar password:

- Store one offline copy on encrypted media
- Store one copy in a password manager with 2FA
- Document recovery steps in your team's secrets-management playbook
- Rotate by generating a new key, publishing under a new contract ID,
  and announcing the migration to users
