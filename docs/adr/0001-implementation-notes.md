# ADR-0001 implementation notes

Working notes for the staged implementation of
[ADR-0001](0001-contract-sharding-architecture.md). The ADR is the design;
this file records the concrete engineering decisions and sequencing so the
work can land in reviewable slices instead of one monolithic change.

## Scope and sequencing

The ADR spans #11 (profiles), #12 (threads), #13 (per-user feeds), and #19
(fanout, still open). It is built **one shard type at a time**, and the
migration from today's global contracts is **not wired until all shard types
exist**. Order:

0. **Crypto + id foundation** (this slice) — prerequisites shared by every shard.
1. **User shard** — per-user, owner-writes-only (profile + recent posts + follows).
2. **Thread shard** — per-root, public-write (replies + likes + quote refs).
3. **Inbox shard** — per-user, public-write notifications; owner prunes.
4. **Migration** — cut existing global state over to the shards.

## Phase 0 decisions

### Signature scheme: ML-DSA-65 (post-quantum)

Raven moves from Ed25519 to **ML-DSA-65** (FIPS 204, NIST level 3), matching
`freenet/freenet-email`. Pin `ml-dsa = =0.1.0-rc.8` (build-isolation rule:
exact version, see AGENTS.md → "Build isolation").

Size changes that ripple through the code:

| | Ed25519 | ML-DSA-65 |
|---|---|---|
| secret (stored seed) | 32 B | **32 B** (unchanged — a seed) |
| verifying key (VK) | 32 B | **1952 B** |
| signature | 64 B | **3309 B** |

Consequences:
- The stored secret is still a 32-byte seed, so export/import stays a 64-hex
  string. The signing key is reconstructed with `MlDsa65::from_seed(seed)`.
- **The VK is no longer derivable from the seed by string-slicing.** The web UI
  (`web/src/identity.ts`) currently does `publicKey = secretKey.slice(0,64)`;
  that assumption is removed — the delegate is the sole source of the VK, and
  the UI waits for the delegate's `Identity` response on import.
- In the WASM delegate the seed comes from `freenet_stdlib::rand::rand_bytes(32)`
  (no `getrandom` in WASM), reconstructed via `MlDsa65::from_seed`.

### Post id: content hash of the signed record

Post id moves from the string `"{author_pubkey}-{timestamp_ms}"` (collides
within a millisecond, forgeable, not self-describing) to

    id = blake3(canonical_signed_post_bytes)   // 32-byte content address

This satisfies the ADR's Atlas constraint: posts are "self-contained signed
records with stable, externally-referenceable IDs." The id is derived from the
signed bytes, so it is collision-resistant and tamper-evident, and any external
indexer can reference a post without rehydrating internal state.

### Shard key derivation (lands with the user shard, Phase 1)

A shard contract is parameterized by its owner's **ML-DSA-65 VK bytes**:

    parameters     = owner_vk_bytes
    contract_key   = ContractKey::from_params(shard_wasm_hash, parameters)
                   = blake3(wasm_code || parameters)   // native freenet derivation

No custom hash primitive is introduced. Domain separation between shard types
(`"user"` / `"thread"` / `"inbox"` in the ADR table) comes for free from the
distinct WASM code hash of each shard binary — two shard types never share a
binary, so the same owner VK yields three different contract keys.

### Posts contract now self-verifies (and what that means for old data)

The existing global `posts` contract is updated in this phase to use
`common::post::Post`: `update_state` / `validate_state` now **reject any post
that does not self-verify** (content-addressed id + valid ML-DSA-65 signature
for `author_pubkey`) or exceeds the length bound. A bad post in a delta batch is
skipped, not fatal to the whole update.

This is a **non-byte-compatible schema change** (`signature` moves from a byte
array to a hex string; `id` moves from a `{pubkey}-{ms}` string to a content
address), so per AGENTS.md → "Contract migration" it cannot ride a plain
hash-bump legacy append. It does not need a re-shape pass either: the only
pre-existing posts are **unsigned** prototype data (`signature: null`), which by
definition can never satisfy the new signed invariant and are intentionally not
carried across. The posts WASM hash rotates on the next `cargo make
build-contracts`; no entry is added to `LEGACY_POSTS_CODE_HASHES` because there
is no migratable prior state. Signed-feed migration proper arrives with the
shard cutover (Phase 4).

## Phase 1 decisions (user shard)

The user shard (`contracts/user-shard`) lands **posts-only** first; profile and
follows are deferred to follow-up slices (they share the owner-writes / low-churn
/ read-by-followers axis, so they belong in this same contract — they are not
new contract types). The contract reuses the merge/summary machinery proven on
the `posts` contract, adding two shard-specific rules:

### Write authority — VK-param match

The shard is parameterized by the **raw encoded owner ML-DSA-65 VK bytes**
(`parameters = vk.encode()`). `update_state` / `validate_state` accept a post
iff it self-verifies (`common::post::Post::verify`) **and** its `author_pubkey`
hex equals `hex(parameters)`. A post signed by a *different* valid key
self-verifies but is not the owner's, so it is rejected — this is what makes the
shard owner-writes without a separate signed-envelope type (the `Post` already
carries the ML-DSA-65 signature). Empty parameters yield an empty owner key that
no real post can match, so an un-parameterized shard accepts nothing.

This realizes the deferred key-derivation primitive: `contract_key =
blake3(user_shard_wasm || owner_vk_bytes)` via native freenet derivation. No
custom hash; domain separation between shard types comes from the distinct WASM
code hash per shard binary (Phase 0 note).

### Bounded state — post-merge count window

`MAX_POSTS = 200` (ADR starting policy). Truncation is **post-merge**, not a
pre-write check, and **count-based with a deterministic total order** — a
contract has no clock (see windowing caveat below). The survival order is
`(timestamp, id)` descending: timestamp is the author-supplied recency hint
(safe to trust here — the shard is single-author owner-writes, so a lying owner
only reorders their own feed), and the content-addressed `id` is a stable total
tie-break so every replica truncates to the identical set regardless of the
order deltas arrived in (covered by `truncation_is_deterministic_across_orderings`).
`validate_state` deliberately does **not** enforce the window — a transiently
over-bound merged state is normal and rejecting it would break convergence;
authority + self-verification are the only validity invariants.

No instance id is committed for this contract (unlike `posts`/`follows`/`likes`,
which use empty parameters): per-owner parameterization means each owner derives
a distinct key at runtime from the one build-stable `user_shard_code_hash`. UI
wiring + migration of the existing global feed into per-user shards is Phase 4.

### Phase 1b — profile + follows (completes the user shard)

The user shard now carries all three owner-writes surfaces. State is
`{ posts, profile: Option<ProfileRegister>, follows: BTreeMap<vk, FollowState> }`.

**Non-post owner mutations use a signed envelope** (`common::signed_op::SignedOp`):
profile and follow edits are not `Post`s, so they carry no intrinsic signature.
`SignedOp` is an ML-DSA-65 signature by the owner over a domain-tagged
(`raven:signed-op:v1`, distinct from the post tag), length-prefixed payload of
`(op_type, payload, seq, signer_pubkey)`. `op.verify(owner)` checks the signer is
the owner *and* the signature is valid — the same VK-param match as posts. The
generic envelope is reused for all three op types (`Profile` / `Follow` /
`Unfollow`); `op_type` and `seq` are inside the signed bytes so an op cannot be
replayed against another surface or have its `seq` bumped to win a race.

**Convergence per surface** (all order-independent — required because deltas
arrive in any order across replicas):
- *profile* — last-write-wins by monotonic `seq`, tie-broken by serialized bytes
  (no clock in a contract; the delegate supplies a monotonic counter).
- *follows* — each target key stores the `seq` of the op that last touched it and
  whether it was a Follow; merge keeps the higher `seq` per key, and on **equal
  seq an Unfollow wins** (a deterministic tie-break). This is convergent under
  reordering, unlike the bare add/remove set in the legacy global `follows`
  contract (whose own NOTE admits Follow/Unfollow is not commutative). The
  equal-seq tie-break is load-bearing: without it, concurrent Follow/Unfollow at
  the same seq splits replicas permanently (review C-1).

The envelope is **bound to a shard context** (`USER_SHARD_CONTEXT =
"raven:user-shard:v1"`) mixed into `signing_payload`, so a future thread/inbox
shard reusing `SignedOp` cannot have a user-shard op replayed into it (review
M-2). Follows are also bounded — `MAX_FOLLOWS` map entries, `MAX_FOLLOW_TARGETS_
PER_OP` per op, and a target-key length cap — so an owner cannot self-bloat the
shard (review M-1). The cap is applied **post-merge by `truncate_follows` as a
function of the key set** (tombstones evicted first, then largest key), never by
arrival order: an earlier draft skipped new keys at insert time, which made the
retained set order-dependent and split replicas permanently at the cap (review
MAJOR-1, fourth round — the same convergence class as C-1). Over-cap eviction is
best-effort lossy, the same trade-off as the recent-N post window. Evicting
tombstones first also bounds tombstone accumulation (review NIT).

**Delta format is now a tagged `ShardDelta` enum** (`Posts(Vec<Post>)` |
`Op(SignedOp)`), forced by review finding MAJOR-2: the Phase-1 bare-`Vec<Post>`
delta could not host a second surface, and changing it later (after non-test
state exists) would need a migration. `update_state` now iterates **every**
`UpdateData` item (not just `delta[0]`) and the `State`/`StateAndDelta` arms do a
real full-`UserShard` merge (so a peer syncing state reconciles profile + follows,
not only posts). `apply_delta_bytes` still accepts a bare `Vec<Post>` for
backward tolerance. `summarize_state` folds profile + follows into one hash each
so a register difference triggers a delta; `get_state_delta` ships the full state
when a register differs (a `Posts` delta cannot convey registers) and just the
missing posts otherwise.

**Review fixes folded in** (from the post-merge re-review of #25): `validate_state`
now also rejects duplicate post ids (MAJOR-1 — the invariant `update_state`'s
dedup guarantees, so the two halves agree) and oversized profile fields;
`summarize_state`/`get_state_delta` use `?` instead of `unwrap()` (MINOR-3,
panic-in-WASM footgun); `MAX_CONTENT_LEN` doc corrected to say bytes, not chars
(NIT). The window is still deliberately not enforced in `validate_state`.

This rotates the user-shard WASM hash again; still no migration entry (no
migratable prior state — Phase 1 shipped no real user-shard data). UI wiring is
still Phase 4.

## Phase 2 decisions (thread shard)

The thread shard (`contracts/thread-shard`) is the first **public-write** shard:
one contract per root post, created lazily on the first reply, collecting the
**replies, likes, and quote references** that target that root. It is
parameterized by the root post's content-addressed id (`parameters =
root_post_id`), so `contract_key = blake3(thread_shard_wasm || root_post_id)` —
distinct per thread and, because the WASM hash differs, distinct from a user
shard parameterized by the same bytes.

### Write authority — anyone-writes, self-verifying, credential seam

Unlike the owner-writes user shard, a thread shard accepts writes from **any**
party. Each entry still self-verifies:

- a **reply** is a full `common::post::Post` whose `reply_to` equals this
  thread's root id. `reply_to` is **conditionally mixed into the post signing
  payload** (only when non-empty — see below), so a reply's thread membership is
  signed and cannot be replayed into another thread; a top-level post (empty
  `reply_to`) hashes/signs exactly as before, leaving existing post ids/sigs
  byte-stable.
- a **like** is a `common::thread::LikeRecord` and a **quote ref** a
  `common::thread::QuoteRef`, each an ML-DSA-65 signature over a domain-tagged
  (`raven:thread-like:v1` / `raven:thread-quote:v1`), length-prefixed payload
  **including the root post id**, so neither can be replayed into another thread.

Verification proves *who* signed, not that the signer is *allowed* — the ADR's
abuse model leaves "who may be a writer" to a credential mechanism (GhostKey is
the candidate, not fixed). Per the Phase 2 decision, the wire slot is reserved
now: every record carries an optional `WriterCert`, and the contract gates writes
through a `verify_writer_cert` seam that **accepts everything today**. When a real
credential lands, only that seam changes — an additive schema step, not a format
break. (The user shard does not reuse `signed_op::SignedOp` here: `SignedOp` is
owner-bound — its `verify` rejects any signer ≠ owner — which is exactly wrong
for an anyone-writes surface, so thread records carry their own self-sig.)

### Convergence per surface (order-independent — AGENTS.md → "Contract correctness invariants")

- *replies* — grow-set deduped by content-address id, truncated post-merge to the
  newest `MAX_REPLIES` (500) by `(timestamp, id)` desc (a total order; no clock).
- *likes* — per-liker join semilattice keyed by liker VK: keep the higher `seq`,
  and on equal `seq` an **unlike wins** (the same deterministic tie-break as the
  user-shard follows, for the same reason — equal-seq concurrent like/unlike must
  not split replicas). Capped post-merge by `truncate_likes` as a function of the
  key set (tombstones evicted first, then largest key).
- *quotes* — grow-set deduped by `quote_post_id`, capped post-merge by a total
  order over the key.

All caps are enforced **only post-merge** (`normalize`), never at insert time;
`validate_state` deliberately does not enforce them (a transiently over-bound
merged state is normal). `validate_state` *does* reject any reply/quote that
fails self-verification, is not thread-bound, or is mis-keyed (id ≠ map key), and
any liker key that is not a valid-length ML-DSA-65 VK — the invariants
`update_state` guarantees, so the two halves agree.

### Delta format and sync

Deltas are a tagged `ThreadDelta` enum (`Replies` | `Likes` | `Quotes`).
`update_state` iterates **every** `UpdateData` item and the `State` /
`StateAndDelta` arms do a full-`ThreadShard` merge, so a peer syncing state
reconciles all three surfaces. `summarize_state` returns the per-surface key sets
(plus each like's `(seq, liked)` for diffing), and `get_state_delta` ships a
`ThreadStateDelta` carrying exactly what the requester lacks: full self-verifying
records for **all three** surfaces, including likes. `apply_delta_bytes` decodes
`ThreadStateDelta` too, so the sync delta round-trips (regression:
`get_state_delta_output_is_applyable`).

**Likes store the full signed `LikeRecord`, re-verified on every path.** A
public-write contract must assume adversarial `UpdateData`, so a like is re-checked
by `merge_like` (→ `LikeRecord::verify`) on *every* write path — `ThreadDelta::Likes`,
full-state `merge_state`, and the sync `apply_state_delta` — and `validate_state`
re-proves every stored like's signature. There is no "the sender already verified
it" shortcut: an earlier draft stored likes as unsigned `(seq, liked)` and trusted
the full-state / sync paths, which let *any* peer forge, suppress, or overwrite any
user's like with no private key (review **CRITICAL**, fifth round — a signature
bypass, the same "every write path must verify, not just the primary one" lesson as
the convergence rounds). Retaining the signature (~3.3 KB/like) is the price of an
unforgeable per-liker counter on a public surface. Replies and quotes always worked
this way; likes were the lone exception and now match. `merge_state` likewise
re-verifies replies/quotes (it had trusted them) so a full-state sync cannot inject
anything a delta could not (review M-1).

This adds the `thread_shard_code_hash` build artifact (parameterized, so no single
instance id — like the user shard). No migration entry (no prior thread-shard
state). UI wiring + cross-contract quote/notification delivery are Phase 4 / the
inbox shard (Phase 3).

## Phase 3 decisions (inbox shard)

The inbox shard (`contracts/inbox-shard`) is the **last shard type**: one contract
per user, parameterized by the owner's ML-DSA-65 VK bytes (`parameters =
owner_vk_bytes`, exactly like the user shard), so `contract_key =
blake3(inbox_shard_wasm || owner_vk)` — distinct per user and, because the WASM
hash differs, distinct from that user's user shard with the same parameters. It
holds incoming **notifications** (reply / mention / follow / quote) targeting the
owner.

### Write authority — anyone-writes deliveries, owner-prunes

The inbox is the second public-write surface, but with a twist absent from the
thread shard: it is **anyone-writes for delivery, owner-only for pruning**.

- A **notification** (`common::inbox::Notification`, kind
  `Reply`/`Mention`/`Follow`/`Quote`) is signed by its **sender** and bound to
  the **recipient owner VK** (domain tag `raven:inbox-notif:v1`, recipient +
  kind mixed into the length-prefixed payload), so it self-verifies and cannot
  be replayed into another user's inbox or presented as a different kind. Its
  `id` is the content address `blake3(signing_payload)`, the map key and the
  handle the owner names when pruning one. As on the thread shard, *who* may be a
  sender is the abuse question left to a credential mechanism — the `WriterCert`
  slot is reserved and gated by `verify_writer_cert` (accepts everything today).
- A **prune** reuses the owner-bound `signed_op::SignedOp` envelope (the same
  type the user shard uses for profile/follows) under a new
  `INBOX_SHARD_CONTEXT = "raven:inbox-shard:v1"`, so an inbox prune cannot be
  replayed into the user shard or vice versa. Two new `OpType`s were added:
  `PruneIds` (drop explicit ids in the payload — selective) and `PruneBefore`
  (advance a high-water to `op.seq` — bulk). `SignedOp::verify` already requires
  `signer == owner`, so only the owner can prune.

### The owner-prune convergence invariant (the hard part)

On an anyone-writes surface, the new failure mode is **resurrection**: a stale
replica still holding a notification the owner pruned must not re-add it when it
merges with a pruned replica. A prune therefore leaves **durable, convergent
evidence** — but because *removal is the owner's exclusive right*, that evidence
must itself carry the owner's signature on every path. State retains the
**owner-signed prune ops**, never a sig-stripped projection of their effect:
`{ notifs, prune_before_op: Option<SignedOp>, prune_ids_ops: Map<op_seq,SignedOp> }`.

- *prune_before_op* — the single highest-`seq` owner-signed `PruneBefore` op. The
  high-water *is* that op's `seq`; because `seq` is inside the signed payload, a
  peer cannot claim `pruned_before = u64::MAX` without the owner key. Merged by
  keeping the higher-`seq` **verified** op.
- *prune_ids_ops* — owner-signed `PruneIds` ops (keyed by op `seq`), each naming
  the ids it prunes. The live tombstone set is *derived* from these verified ops;
  a tombstone exists only while backed by an owner signature.
- *notifs* — a grow-set keyed by content address, admitted only if it
  self-verifies for this owner **and** is neither tombstoned nor below the
  high-water (`notif_admissible`, the single predicate every write path and
  `validate_state` agree on).

`PruneBefore` is the bulk-cleanup tool: a single max-wins op, no GC needed.
Selective `PruneIds` tombstones are a **pure grow-set**, bounded only by the
`MAX_PRUNE_IDS_OPS` backstop (oldest op `seq`s evicted, best-effort lossy — the
same trade as the notif window). A second draft tried to GC a `PruneIds` op once
an owner-attested per-id `notif_seq` fell below the high-water, but that seq was
never tied to the notif's *real* seq: an understated value (a delegate bug or a
careless owner) let GC drop a live tombstone and resurrect the notif, with no
`validate_state` backstop — owner-self-harm, not attacker-reachable, but it
silently re-opened the exact resurrection class the prune machinery exists to
prevent (review **MAJOR**, seventh round). There is no sound high-water GC for a
bare id, so `notif_seq` was dropped entirely and `gc_prune_ids_ops` keeps only the
count backstop. `normalize` re-applies prune suppression **post-merge** (the same
discipline as the caps), so a notif that arrived before the prune op that
suppresses it — i.e. the prune merged in second — is still removed. Notifs are
capped post-merge to the newest `MAX_NOTIFS` by `(seq, id)` desc (a total order;
no clock).

### Sync delta carries the **signed prune ops** — there is no removal-only shortcut (review CRITICAL, sixth round)

The first cut of this contract stored a bare `{ tombstones, pruned_before }` and
shipped it un-re-signed over sync, on the argument that "trusting prune evidence
can only *remove* notifications, never forge one, so it is safe." **That argument
was wrong, and review caught it as a CRITICAL.** On an inbox, *removal is itself
the owner's exclusive privilege* — an unsigned removal claim is a forgeable
authority claim. Any peer (no key, no relationship to the victim) could ship a
state with `pruned_before = u64::MAX`; an honest replica merging it would
`max`-adopt the high-water, `retain` would wipe **every** notification, and
because the poisoned high-water is then durable state it would re-propagate
network-wide via that replica's own `get_state_delta`/`merge_state`, with
`max`-wins guaranteeing it never heals. A single push wipes an honest user's inbox
everywhere, permanently. This is the same class as the thread-shard CRITICAL — a
sig-stripped projection trusted from an upstream peer — applied to *suppression*
instead of injection.

The fix is the same discipline: **retain and re-verify the owner-signed prune
ops on every path.** `summarize_state` ships the notif id set + which prune ops
the holder has (the `PruneBefore` seq, the `PruneIds` op seqs); `get_state_delta`
ships the missing **signed ops** (not their effect); `apply_state_delta` /
`merge_state` route every op through `merge_prune_ops`, which calls
`op.verify(INBOX_SHARD_CONTEXT, owner)` before it may raise the high-water or add
a tombstone. A forged `PruneBefore { seq: u64::MAX, signature: None }` simply
fails verification and is dropped, so the honest replica's high-water stays put
and its notifications survive (regression
`forged_unsigned_prune_evidence_cannot_suppress`). Notifications continue to be
re-verified by `merge_notif` on every path, exactly as before. The cost is real —
prune ops accumulate — but a `PruneBefore` collapses to one op (highest seq) and
`PruneIds` ops are capped by the `MAX_PRUNE_IDS_OPS` backstop, so it stays bounded.

`validate_state` re-proves **every retained prune op** (genuine owner signature,
correct op type, keyed under its own seq) *and* every stored notification's
admissibility, so a forged prune op or a resurrected notification in a state
object fails validation (the two halves agree).

This adds the `inbox_shard_code_hash` build artifact (parameterized, so no single
instance id — like the user and thread shards). No migration entry (no prior
inbox-shard state). With this slice **all three shard types now exist**, so the
migration + UI wiring (Phase 4) is unblocked.

## Phase 4 decisions (UI cutover — user shard, slice 1)

Phase 4 cuts the web app from the legacy global posts contract to the per-user
shards. It is sliced: this first slice wires only the **user shard**
(posts/profile/follows surface) for read + write; thread/inbox UI and migration
of legacy global-feed data into shards are later slices.

### Client-side key derivation must match the node byte-for-byte

A parameterized shard's contract instance id is
`blake3(code_hash_bytes || parameters_bytes)` — the raw 32-byte code hash
concatenated with the raw parameter blob, **no length prefix, no separator, no
domain tag**, taking the 32-byte digest (freenet-stdlib
`ContractKey::generate_id` / `from_params`). The web app reproduces this in
`web/src/shard-key.ts` with `@noble/hashes/blake3` + `bs58`. If the JS derivation
drifts from the node, every GET/PUT/subscribe silently addresses a different
(empty) contract, so the match is pinned by a **ground-truth vector** in
`shard-key.test.ts` taken from `fdev get-contract-id --code … --parameters …`
(code hash `7iSNUfGW…`, 32×`0x01` params → instance id `2q69AnoP…`). The vector
depends only on the algorithm (code hash + params), so it survives rebuilds.

The shard parameters are the **raw owner ML-DSA-65 VK bytes** (1952 B), matching
the contract's `owner_vk_hex(params) = hex(params)`. (Note: freenet-email
JSON-encodes its inbox params; raven does not — the contract dictates the wire
form, and raven's expects raw VK bytes.)

### The browser PUTs the parameterized container itself

The node has no pre-published per-owner instance, so the app instantiates each
owner's shard by PUTting a `ContractContainer` (raw WASM `data` + owner-VK
`parameters` + derived key) with an empty initial state `{"posts":[]}`, then
GET/subscribes by the derived key. `setUser` (fired when the delegate reports the
identity) is the trigger; `initUserShard` derives the key, GETs to check for an
existing instance, PUTs to instantiate if absent, then loads + subscribes. A real
VK is 3904 hex chars — the 64-char offline fake is not treated as a shard owner.

**The shipped WASM must be the raw compiled artifact, not the packaged
container.** `fdev`'s code hash is `blake3` of the raw `target/…/*.wasm`; the
packaged `build/freenet/…` file has extra framing and hashes differently. On PUT
the node re-hashes the `data` bytes to derive the key, so shipping the packaged
file would derive a key that never matches the GET key. `Makefile.toml`
`build-user-shard` copies the **raw** wasm to `web/public/user_shard.wasm` and
injects its base58 code hash as `__USER_SHARD_CODE_HASH__`. The task then fails
the build unless `b3sum web/public/user_shard.wasm` (hex) equals the
base58-decoded injected code hash (hex) — the one assertion that catches a
raw-vs-packaged mix-up, which would otherwise be a silent network-wide no-op.

### Delta form differs from the legacy feed

The user shard takes the externally-tagged `ShardDelta` enum, so a post is
written as `{"Posts":[post]}` (vs. the legacy global feed's bare `[post]` array),
and an incoming shard delta is parsed by the `Posts` tag (an `Op` delta carries
profile/follow changes, no feed posts). State reads route by the response key:
the shard returns a `UserShard` (`{posts,profile,follows}`), the legacy feed a
`{posts}`. Until a real VK is known the app stays on the legacy contract, so the
slice is additive and reversible.

### Not exercised by per-PR CI

The PUT-container / GET-by-derived-key round-trip is only exercised against a live
node (deferred WASM-in-node tier), not vitest. The load-bearing invariant that
*is* unit-tested is the key derivation match — the one thing that, if wrong,
makes everything silently no-op.

## Phase 4 decisions (thread shard — likes, slice 2)

Slice 2 wires the **thread shard** for one operation end-to-end — **likes** —
to prove the delegate→sign→thread-shard→UI loop for a non-post record. Quotes
and replies followed in later slices (replies via `SignReply`, see below); the
inbox shard, the notifications UI, and the legacy global-contract teardown are
each their own later slice.

### Delegate signs non-post records via the same single trusted encoder

The identity delegate gained a `SignLike{nonce, root_post_id, seq, liked}` →
`SignedLike{…, signature}` message. Like `SignPost`, it builds the canonical
payload in Rust with the common crate's encoder
(`common::thread::LikeRecord::signing_payload(root_post_id)`) and signs *that*
— the exact bytes the thread shard verifies. The byte layout never leaves the
one audited place; the browser only assembles the returned fields into a
`LikeRecord` and sends it. (The rejected alternative — a generic
`SignPayload{bytes}` with the payload built in TS — would have moved a subtle,
unaudited correctness surface into JavaScript.) Quotes/replies/notifications/
prunes follow this same per-record-message pattern in later slices.

Replies use the same pattern via a `SignReply{nonce, content, author_name,
author_handle, timestamp, reply_to, quoted_post}` → `SignedReply{…, post_id,
signature}` message (#12). A reply is structurally a `Post` with a non-empty
`reply_to`, so the delegate reuses the post encoder
(`common::Post::signing_payload`, which appends `reply_to`/`quoted_post` only
when non-empty). That keeps top-level `SignPost` output **byte-identical** —
existing post signatures are unaffected — while the thread shard's
`reply_is_acceptable` gate (`post.reply_to == root && post.verify()`) binds a
reply to its thread and makes rebinding to another root fail verification.

### Thread-shard key derivation: parameter is the UTF-8 id string

A thread shard is parameterized by its **root post id**, and the contract reads
that parameter as `String::from_utf8_lossy(parameters)`. So the browser derives
the key as `blake3(thread_code_hash || utf8(post_id))` — the parameter bytes are
the UTF-8 encoding of the hex id *string*, NOT the hex-*decoded* bytes (contrast
the user shard, whose parameter is the raw VK bytes). Getting this wrong is the
familiar silent-no-op. Thread shards are lazy: a per-thread key is derived (and
the contract PUT-instantiated) only the first time a post is liked, not eagerly
for every feed post.

### Likes are optimistic, then reconciled from authoritative state

The like button toggles locally for instant feedback, then the signed
`LikeRecord` is folded into the thread shard via `ThreadDelta::Likes`
(`{"Likes":[record]}`). After the update lands — and on any thread update
notification — the app re-GETs the thread shard and recomputes the aggregate
(count of `liked==true` records; `liked-by-me` if the owner's VK is among them)
rather than reconciling deltas by hand, then emits it via `onLikeUpdated` so the
feed re-renders with the real count. `seq` is the liker's monotonic counter
(ms-precision time), which the contract uses to resolve concurrent like/unlike of
the same post.

### Build wiring factored to a shared helper

The user-shard's raw-wasm mirror + `b3sum == code_hash` build check (slice 1) is
now `scripts/mirror-shard-wasm.sh`, called by both `build-user-shard` and
`build-thread-shard`, so the load-bearing safety check is defined once. Note this
*adds* behavior to `build-thread-shard` (it previously only wrote the code hash;
it now also mirrors the raw wasm to `web/public/` and runs the b3sum check).

### Known limitations / follow-ups (slice 2)

- **`seq = Date.now()` is not robust to clock regressions.** The contract resolves
  a liker's concurrent like/unlike by higher `seq` (unlike wins an equal-seq tie).
  A backward clock step (NTP correction, VM resume) can give a later toggle a
  lower seq, so the older action wins until the next action with a higher clock.
  Per-device and self-correcting; a persisted monotonic per-liker counter would
  remove it. Acceptable for a slice-2 proof.
- **Optimistic-toggle revert.** The like button toggles locally first; if the like
  cannot be sent (no delegate / no thread code hash / delegate `Error` for the
  nonce) the UI re-renders from `localPosts` to discard the toggle, rather than
  leaving a stuck heart.
- **Like-refresh is debounced** (500 ms per thread) so a burst of remote-like
  notifications on a hot post collapses to one full-state GET per window; the
  user's own like still refreshes immediately.
- **Unverified without a live node (WASM-in-node tier):** `ensureThreadShard`
  treats a successful GET as "already instantiated" and PUTs only on
  reject/timeout. This assumes a GET against a never-instantiated parameterized
  contract *rejects* (→ we PUT). If instead it resolves with empty state we would
  skip the PUT and the first like's UPDATE would no-op. This is the key thing the
  deferred real-node test must confirm.

## Post-cutover holistic review (fixes)

A whole-system review after the teardown (#33) — reading all three shards + the
delegate + the web client together, rather than one PR diff — surfaced fixes the
per-slice reviews could not see:

- **GET-response serialization (regression introduced by the teardown).** The
  stdlib resolves GET promises from a single uncorrelated FIFO queue: the Nth
  response settles the Nth pending `get()`, regardless of contract. The slice-1
  `startupDone` barrier covered only startup-time traffic, which #33 removed — so
  post-cutover the barrier serialized nothing while *multiple* shard flows
  (user-shard probe/load, per-thread probe/like-refresh) were live at once. Two
  in-flight GETs could swap responses: a thread GET resolving the user-shard probe
  (feed never instantiates) or a like-refresh popping a thread probe (that thread
  never PUT → the like is silently lost). Replaced the barrier with
  `serializedGet` (`web/src/freenet-api.ts`): every `api.get()` chains behind the
  previous one's settle, so at most one GET is outstanding and each response
  matches its own promise. Pinned by `web/src/freenet-api.test.ts`.
  - **Subtlety (caught in review):** the chain must advance on the UNDERLYING
    `api.get()` settle, NOT on the app's soft timeout. The stdlib keeps a GET in
    its `pendingGets` FIFO until a real response/NotFound or its own 30 s
    `REQUEST_TIMEOUT_MS`. A shorter (8 s) app timeout that advanced the chain
    would issue the next GET while the stale entry is still queued → two entries
    → a late response pops the wrong promise (the same misroute). So
    `serializedGet` chains on the raw stdlib promise and exposes the 8 s only as
    a soft caller-facing view that does not release the next GET. Regression
    guard: `does NOT advance the chain on the soft timeout`.
- **Lost-like revert (M-3).** `ensureThreadShard` now awaits its PUT before the
  caller sends the like UPDATE (an UPDATE to a never-instantiated contract is
  dropped by the node), and `completeLike` re-GETs the authoritative aggregate on
  UPDATE *failure* too, so the optimistic toggle is always reconciled away rather
  than left stuck.
- **Fabricated-engagement / dangling threads (H-3) — accepted + mitigated.** A
  thread shard is keyed by a post id but the contract never checks the root post
  is real, and a post evicted from the user-shard window (`MAX_POSTS`) leaves its
  thread shard's likes orphaned. The client mitigation is already in place:
  `onLikeUpdated` ignores aggregates for any post not in the live feed
  (`index.ts`), and a post id is the blake3 of its own signed content, so an
  attacker cannot pre-seed a *real* future post's thread. Residual: a like
  aggregate trusts only the records present in the addressed thread shard; treat a
  thread aggregate as authoritative only while its root post is in view.

## Testing tiers

- **Unit** — per-function `#[test]`s inside each contract crate's `test` module:
  one `validate_state` / `update_state` / merge / truncation rule at a time, with
  real ML-DSA-65 keys. The convergence and forgery regressions live here.
- **Integration** — an `integration` module inside the user-shard and thread-shard
  crates that drives the **full `ContractInterface` through the real sync
  protocol**: a `sync_into` helper does `dst.summarize_state` →
  `src.get_state_delta(summary)` → `dst.update_state(delta)` and asserts `dst`
  stays valid, and `reconcile` runs it both directions and asserts the two
  replicas reach byte-identical state. This covers what unit tests skip — the
  summarize/delta wire path and the validate-after-merge invariant — across
  multi-replica convergence (incl. equal-seq follow/unfollow and like/unlike
  fixed points in both reconcile orders), adversarial-replica rejection (a forged
  like / non-owner post in a peer's state must not propagate to an honest
  replica), and cross-shard key consistency (a user-shard post's content id is the
  thread-shard param, and a reply bound to it lands only on that thread).
- **Node-backed browser E2E (first slice landed).** `scripts/node-e2e.sh` +
  `cargo make test-ui-node-e2e` boot a fresh, isolated Freenet node, publish the
  identity delegate + packaged web container + shards to it, and run the
  Playwright specs under `web/tests/node-e2e/` against the node-SERVED webapp
  (`/v1/contract/web/<CID>/`). This is the only tier that exercises the real
  browser → live node → delegate → contract path: the served loader mounts the
  app in a sandboxed iframe, opens a live WS to `/v1/contract/command`, wires the
  identity delegate, and drives onboarding → identity → app-shell. Live-delegate
  console signals (`Connected to Freenet node`, `Delegate connection wired`,
  `No identity in delegate — show onboarding`) are asserted so a spec cannot pass
  in offline/mock mode. Runs as a **non-blocking** CI job (`node-e2e`,
  `continue-on-error`) since it needs an external node binary and is heavier than
  per-PR gating. Does **not yet** confirm delegate identity *persistence* across
  reload, the GET-rejects-on-uninstantiated assumption, WASM-trap, or node-vs-JS
  key-derivation drift — those stay in the contract tier below.
- **Deferred — WASM-in-node contract e2e**: the contract `integration` tests drive
  the contract as a Rust library, not the compiled WASM inside a running node, so
  they do not catch WASM-compilation or transport differences. A contract-level
  real-node tier (via the `freenet:linux-test` / `freenet:local-dev` skills —
  publish the shards, drive reply/like/quote + two-peer sync over the live WS) is
  the next slice beneath the browser E2E above. It is the only tier that can
  confirm the load-bearing `ensureThreadShard` / `ensureGlobalIndex`
  GET-rejects-on-uninstantiated assumption and catch WASM-trap / node-vs-JS
  key-derivation drift. **Tracked as issue #34** (not only this note).
- **Delegate unit coverage (added in the holistic-review pass).** The identity
  delegate now has unit tests (`delegates/identity/src/lib.rs`): export→import seed
  round-trip, and the delegate's `SignPost`/`SignLike` outputs verify under the
  same `common` code the contracts run (thread-context binding, vk_hex == owner
  param). The end-to-end `process()` request path stays uncovered on the host
  target (its secret store is a WASM-only host import) — exercised only by the
  WASM-in-node tier above.

`cargo make test` now runs `cargo test --workspace` (was a hand-maintained subset
that omitted the user/thread shards and the delegate) so every crate — and these
integration tests — run in CI.

## Caveat: ADR vs. mail on windowing

The ADR states the bounded-state window mirrors "how `freenet/mail` windows its
inbox contracts." On inspection, the mail **inbox contract does no
contract-level truncation** — it bounds nothing in `update_state`; mail enforces
message age sender-side in the anti-flood-token delegate, because there is no
clock inside the contract WASM. So Raven's post-merge truncation is **new code**,
not a port, and it must be **count-based with a deterministic ordering** (by post
id) rather than time-based — a contract cannot read a wall clock. This is the
only material place the implementation diverges from the ADR's stated rationale.
