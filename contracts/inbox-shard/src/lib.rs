//! Inbox shard contract (ADR-0001, Phase 3).
//!
//! One contract **per user**, parameterized by the owner's ML-DSA-65 verifying
//! key bytes (`parameters = owner_vk_bytes`, exactly like the user shard), so the
//! contract key is `blake3(inbox_shard_wasm || owner_vk)` — distinct per user and
//! distinct from that user's user shard because the WASM hash differs (ADR-0001 →
//! "Shard key derivation").
//!
//! ## Write authority — anyone-writes notifications, owner-prunes
//!
//! The inbox is **anyone-writes** for *delivery*: any party may append a
//! [`Notification`] (a reply / mention / follow / quote targeting the owner).
//! Each notification **self-verifies** — it is signed by its *sender* and bound
//! to the owner's VK (the recipient), so it cannot be replayed into another
//! user's inbox. Who may be a sender is the abuse question ADR-0001 leaves to a
//! credential mechanism (GhostKey is the candidate); the [`WriterCert`] wire slot
//! is reserved and checked by [`verify_writer_cert`], which accepts everything
//! today.
//!
//! Only the **owner** may *prune*. A prune is an owner-signed
//! [`SignedOp`](freenet_microblogging_common::signed_op::SignedOp) bound to
//! [`INBOX_SHARD_CONTEXT`], in two forms:
//! * `OpType::PruneIds` — drop the explicit notification ids in the payload
//!   (selective: kill one spam notification).
//! * `OpType::PruneBefore` — advance a monotonic high-water `pruned_before` to
//!   `op.seq`, dropping every notification whose own `seq` is below it (bulk:
//!   "clear everything older than N").
//!
//! ## Convergence (every rule order-independent — AGENTS.md → "Contract
//! correctness invariants")
//!
//! The hard part of an owner-prune on an anyone-writes surface is that a *stale
//! replica* still holding a pruned notification must not **resurrect** it when it
//! merges with a pruned replica. So a prune leaves durable, convergent evidence —
//! but because *removal is the owner's exclusive right*, that evidence must itself
//! carry the owner's signature on **every** path, exactly like a notification
//! carries its sender's. State therefore retains the **owner-signed prune ops**,
//! not a sig-stripped projection of their effect:
//!
//! * **`prune_before_op`** — the single highest-`seq` owner-signed `PruneBefore`
//!   op. The high-water is that op's `seq`; because `seq` is inside the signed
//!   payload, a peer cannot forge `pruned_before = u64::MAX` without the owner
//!   key. Merged by keeping the higher-`seq` *verified* op.
//! * **`prune_ids_ops`** — owner-signed `PruneIds` ops (keyed by op `seq`), each
//!   naming the ids it prunes. A tombstone for `id` exists only while backed by
//!   such a verified op. Merged as a verified-op union.
//! * **`notifs`** — a grow-set keyed by content-addressed id, admitted only if it
//!   self-verifies, is **not** tombstoned, and is **not** below the high-water.
//!
//! Selective tombstones are a **pure grow-set**, bounded only by the
//! `MAX_PRUNE_IDS_OPS` backstop. An earlier draft tried to GC a tombstone once an
//! owner-attested per-id `notif_seq` fell below the high-water, but that seq was
//! never tied to the notif's real seq — an understated value let GC drop a live
//! tombstone and resurrect the notif (review MAJOR, seventh round). There is no
//! sound high-water GC for a bare id, so the bulk-cleanup tool is `PruneBefore`
//! (a single max-wins op needing no GC); selective `PruneIds` accumulate until
//! the rare backstop eviction (best-effort lossy, like the notif window).
//!
//! **Every prune op is re-verified against the owner on *every* path** (delta,
//! full-state merge, sync delta) before it can raise the high-water or add a
//! tombstone — there is no "the peer already pruned it" shortcut, because trusting
//! an unsigned removal claim lets any peer wipe an honest inbox network-wide
//! (`max`-wins never heals — review CRITICAL, sixth round). `validate_state`
//! re-proves every retained prune op *and* every stored notification, and rejects
//! a notification that the retained prune state should have removed — the same
//! "every write path verifies, the two halves agree" discipline as the thread
//! shard (AGENTS.md → "Every write path verifies").

use freenet_microblogging_common::inbox::{Notification, WriterCert};
use freenet_microblogging_common::signed_op::{
    INBOX_SHARD_CONTEXT, OpType, SignedOp, decode_id_list, encode_id_list,
    id_list_count_within_bounds,
};
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Cap on distinct retained notifications. Public-write (delivery), so this
/// bounds flood blast radius alongside the (future) writer-credential gate and
/// the owner's own pruning.
const MAX_NOTIFS: usize = 10_000;

/// Cap on retained `PruneIds` ops (selective tombstones are a pure grow-set).
/// When exceeded, the oldest op `seq`s are evicted — best-effort lossy, the only
/// bound on tombstone growth. An owner who bulk-prunes with `PruneBefore` keeps
/// selective ops few, so this rarely bites.
const MAX_PRUNE_IDS_OPS: usize = 1_000;

/// Max length of a notification id (hex of a 32-byte blake3 hash = 64 chars);
/// a small margin guards against a malformed oversized key.
///
/// Re-exported from `common::signed_op` rather than restated: the shared id-list
/// decoder enforces the same bound while parsing a prune payload, and two
/// definitions that drift would let an id pass one check and fail the other.
/// (`MAX_PRUNE_IDS_PER_OP` moved there too, as `MAX_IDS_PER_OP`.)
use freenet_microblogging_common::signed_op::MAX_ID_LEN;

/// Inbox shard state for one owner.
///
/// Both surfaces retain **owner-/sender-signed records**, never a sig-stripped
/// projection: the inbox is public-write *and* owner-pruned, so the contract must
/// assume adversarial `UpdateData` and re-verify, on *every* path, both who sent
/// a notification (its sender) and who authorized a removal (the owner). A
/// notification keeps its signature; a prune keeps its owner-signed `SignedOp`.
/// This is what lets `validate_state` re-prove the whole state and makes both a
/// forged delivery and a forged *removal* impossible (the thread-shard CRITICAL
/// lesson and its sixth-round suppression variant; AGENTS.md → "Every write path
/// verifies").
#[derive(Serialize, Deserialize, Default)]
struct InboxShard {
    // Schema-tolerance: defaults so older/newer wire shapes still decode
    // (AGENTS.md → "Contract migration").
    /// Notifications keyed by their content-addressed id.
    #[serde(default)]
    notifs: BTreeMap<String, Notification>,
    /// The highest-`seq` owner-signed `PruneBefore` op, if any. Its `seq` is the
    /// monotonic high-water; retaining the signed op is what makes the high-water
    /// unforgeable (a peer cannot claim `u64::MAX` without the owner key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prune_before_op: Option<SignedOp>,
    /// Owner-signed `PruneIds` ops keyed by their op `seq`. Each names the ids it
    /// prunes; the union of those ids is the tombstone set. A pure grow-set
    /// (no sound high-water GC for a bare id), bounded only by the
    /// [`MAX_PRUNE_IDS_OPS`] backstop.
    #[serde(default)]
    prune_ids_ops: BTreeMap<u64, SignedOp>,
}

impl<'a> TryFrom<State<'a>> for InboxShard {
    type Error = ContractError;

    fn try_from(value: State<'a>) -> Result<Self, Self::Error> {
        serde_json::from_slice(value.as_ref()).map_err(|_| ContractError::InvalidState)
    }
}

/// A single inbox-shard delta operation. Externally tagged so the wire form is
/// unambiguous and new surfaces can be added without colliding.
#[derive(Serialize, Deserialize)]
enum InboxDelta {
    /// One or more incoming notifications (each self-signed by its sender).
    Notifs(Vec<Notification>),
    /// One owner-signed prune op (`PruneIds` or `PruneBefore`).
    Prune(SignedOp),
}

/// The inbox owner's VK as hex — the contract parameters interpreted as raw
/// encoded ML-DSA-65 VK bytes. This is both the recipient a notification must be
/// bound to and the only key whose prune ops are honored. Empty parameters yield
/// an empty owner hex that no real notification (bound to a 3904-hex VK) can
/// match and that no real signature can satisfy, so an un-parameterized inbox
/// accepts nothing.
fn owner_vk_hex(parameters: &Parameters<'_>) -> String {
    hex::encode(parameters.as_ref())
}

/// The writer-credential seam (ADR-0001 abuse model). Today it accepts every
/// sender — `WriterCert` is a reserved wire slot, not yet a policy — but does
/// bound the cert's size: `cert` is excluded from the notification's signing
/// payload (see `common::inbox`), so it is unauthenticated as well as
/// unbounded, and an unbounded field on an anyone-writes surface is a storage
/// amplification primitive regardless of whether its *content* is checked.
/// When a real credential (GhostKey) lands, gate deliveries here; the cert
/// already rides on each notification so doing so is an additive change, not a
/// format break.
fn verify_writer_cert(cert: Option<&WriterCert>) -> bool {
    cert.is_none_or(WriterCert::within_bounds)
}

/// The current high-water: the `seq` of the retained `PruneBefore` op, or 0 if
/// none. Every notification with `seq < pruned_before` is suppressed.
fn pruned_before(shard: &InboxShard) -> u64 {
    shard.prune_before_op.as_ref().map(|op| op.seq).unwrap_or(0)
}

/// The live tombstone id set: every id named by a retained `PruneIds` op.
/// Recomputed from the verified ops (never stored as a bare projection), so a
/// tombstone exists only while backed by an owner signature.
fn tombstone_ids(shard: &InboxShard) -> std::collections::HashSet<String> {
    let mut ids = std::collections::HashSet::new();
    for op in shard.prune_ids_ops.values() {
        for id in decode_prune_ids(&op.payload) {
            ids.insert(id);
        }
    }
    ids
}

/// Whether a notification is, on its own merits, a well-formed delivery for this
/// inbox: bound to the owner, self-verifying, keyed under its own content
/// address, and carrying an acceptable writer credential. Does **not** consider
/// prune state — that is layered on by [`notif_admissible`].
fn notif_is_acceptable(id: &str, notif: &Notification, owner: &str) -> bool {
    !owner.is_empty()
        && id.len() <= MAX_ID_LEN
        && notif.within_bounds()
        && id == notif.id(owner)
        && notif.verify(owner).is_ok()
        && verify_writer_cert(notif.writer_cert.as_ref())
}

/// Whether a notification may currently live in the inbox: acceptable on its own
/// merits **and** not suppressed by a prune (tombstoned, or below the
/// high-water). This is the single admission predicate every write path and
/// `validate_state` agree on. `tombstones` is the derived live set; `hw` the
/// high-water — both computed once per merge by the caller.
fn notif_admissible(
    id: &str,
    notif: &Notification,
    owner: &str,
    tombstones: &std::collections::HashSet<String>,
    hw: u64,
) -> bool {
    notif_is_acceptable(id, notif, owner) && !tombstones.contains(id) && notif.seq >= hw
}

/// Admit one notification if currently admissible. Every path into `notifs` goes
/// through here, so a notification that does not verify for this owner — or that
/// the owner has pruned — is never stored, no matter which peer sent it.
fn merge_notif(shard: &mut InboxShard, notif: Notification, owner: &str) {
    let id = notif.id(owner);
    let tombstones = tombstone_ids(shard);
    let hw = pruned_before(shard);
    if notif_admissible(&id, &notif, owner, &tombstones, hw) {
        // Content address is stable, so re-inserting the same notification is
        // idempotent (grow-set dedup).
        shard.notifs.entry(id).or_insert(notif);
    }
}

/// Merge one owner-signed prune op into the shard's retained-op set. **The caller
/// must have already verified `op` against the owner** for `INBOX_SHARD_CONTEXT`;
/// this only sequences the convergent retention. Suppression of now-pruned notifs
/// is applied in [`normalize`], so this is purely additive (order-independent).
fn merge_prune_op(shard: &mut InboxShard, op: SignedOp) {
    match op.op_type {
        OpType::PruneBefore => {
            // Keep the higher-seq op (max-wins, but on the *signed* op so the
            // high-water cannot be forged past what the owner actually signed).
            let replace = match &shard.prune_before_op {
                None => true,
                Some(cur) => op.seq > cur.seq,
            };
            if replace {
                shard.prune_before_op = Some(op);
            }
        }
        OpType::PruneIds => {
            if !prune_op_is_acceptable(&op) {
                return;
            }
            // Union by op seq; identical ops dedupe. A peer cannot fabricate a new
            // op (it would not verify), so this is a grow-set of genuine ops.
            shard.prune_ids_ops.entry(op.seq).or_insert(op);
        }
        // A non-prune op type is not a valid inbox mutation; ignore it.
        // Not inbox surfaces. They are bound to a different shard context so
        // they would not verify here anyway, but stay exhaustive so a new
        // OpType can never fall through into an inbox mutation by default.
        OpType::Profile | OpType::Follow | OpType::Unfollow | OpType::RetractPost => {}
    }
}

/// Decode a `PruneIds` payload into the ids it names.
///
/// The wire format lives in `common::signed_op` because the same
/// length-prefixed id list is also the payload of `OpType::RetractPost`, and
/// those bytes ride inside the signature — two encoders that drift by a byte
/// produce ops that verify on one side and not the other, failing silently.
///
/// Note: ids only — no per-id `notif_seq`. An earlier draft carried an
/// owner-attested `notif_seq` per id to let the high-water GC tombstones, but
/// that seq was untied to the notif's real seq: an understated value let GC drop
/// a tombstone while the real notif was still above the high-water, resurrecting
/// it (review MAJOR, seventh round — owner-self-harm, no validate backstop).
/// There is no sound high-water GC for a bare id, so tombstones are a pure
/// grow-set bounded only by [`MAX_PRUNE_IDS_OPS`].
fn decode_prune_ids(payload: &[u8]) -> Vec<String> {
    decode_id_list(payload)
}

/// Encode a `PruneIds` payload from a list of ids. Thin alias over the shared
/// encoder, kept so existing call sites and tests read in inbox terms.
pub fn encode_prune_ids(ids: &[String]) -> Vec<u8> {
    encode_id_list(ids)
}

/// Bound the retained `PruneIds` op set. Tombstones are a pure grow-set — there
/// is no sound high-water GC for a bare id (see [`decode_prune_ids`]) — so the
/// only bound is this cap. When exceeded, evict the lowest op `seq`s
/// (oldest prunes) deterministically; the `BTreeMap` is already seq-ordered, so
/// every replica evicts the identical set regardless of arrival order. Eviction
/// is best-effort lossy (it can re-open resurrection for the evicted ids, the
/// same trade as the notif window), but only an owner who issues
/// `MAX_PRUNE_IDS_OPS` selective prunes without ever bulk-pruning hits it — a
/// `PruneBefore` is the unbounded-cleanup tool and needs no GC (single max-wins
/// op).
fn gc_prune_ids_ops(shard: &mut InboxShard) {
    if shard.prune_ids_ops.len() > MAX_PRUNE_IDS_OPS {
        let drop: Vec<u64> = shard
            .prune_ids_ops
            .keys()
            .take(shard.prune_ids_ops.len() - MAX_PRUNE_IDS_OPS)
            .cloned()
            .collect();
        for seq in drop {
            shard.prune_ids_ops.remove(&seq);
        }
    }
}

/// Truncate notifications to the newest `MAX_NOTIFS` by `(seq, id)` desc — a
/// total order, so every replica retains the identical set regardless of arrival
/// order. Post-merge only. Best-effort lossy, like the user-shard post window.
fn truncate_notifs(notifs: &mut BTreeMap<String, Notification>) {
    if notifs.len() <= MAX_NOTIFS {
        return;
    }
    let mut order: Vec<(u64, String)> = notifs.iter().map(|(id, n)| (n.seq, id.clone())).collect();
    // Newest first: seq desc, then id desc as a stable total tie-break.
    order.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    for (_, id) in order.into_iter().skip(MAX_NOTIFS) {
        notifs.remove(&id);
    }
}

/// Normalize a merged state: GC redundant prune ops, drop any notification the
/// prune state now suppresses, then enforce the notif cap — all post-merge. Pure
/// function of the accumulated sets, so it is order-independent. Run after every
/// merge so a notification that arrived before the prune that suppresses it is
/// still removed (the prune may merge in second).
fn normalize(shard: &mut InboxShard) {
    gc_prune_ids_ops(shard);
    let hw = pruned_before(shard);
    let tombstones = tombstone_ids(shard);
    shard
        .notifs
        .retain(|id, n| !tombstones.contains(id) && n.seq >= hw);
    truncate_notifs(&mut shard.notifs);
}

/// Apply one decoded `InboxDelta` to the shard, verifying as it goes. Unverified
/// notifications and prune ops not signed by the owner are skipped (not fatal),
/// the same tolerance the other shards use for a bad entry in a batch.
fn apply_inbox_delta(shard: &mut InboxShard, delta: InboxDelta, owner: &str) {
    match delta {
        InboxDelta::Notifs(notifs) => {
            for notif in notifs {
                merge_notif(shard, notif, owner);
            }
        }
        InboxDelta::Prune(op) => {
            // Single-op convenience path; verification is centralized in
            // merge_prune_ops so every path enforces the owner check identically.
            merge_prune_ops(shard, vec![op], owner);
        }
    }
}

/// Try the tagged `InboxDelta` form first, then an `InboxStateDelta` (what
/// `get_state_delta` ships — notifs + prune evidence in one message), then a bare
/// `Vec<Notification>` (notifs-only backward tolerance), then a full `InboxShard`
/// (state-as-delta).
///
/// Order matters: `InboxStateDelta`'s fields are all `#[serde(default)]`, so it
/// would also accept a bare `{}`; `InboxDelta` (externally tagged, no defaults)
/// is tried first so a real tagged delta is never mis-decoded.
fn apply_delta_bytes(
    shard: &mut InboxShard,
    bytes: &[u8],
    owner: &str,
) -> Result<(), ContractError> {
    if let Ok(delta) = serde_json::from_slice::<InboxDelta>(bytes) {
        apply_inbox_delta(shard, delta, owner);
        return Ok(());
    }
    if let Ok(sd) = serde_json::from_slice::<InboxStateDelta>(bytes) {
        apply_state_delta(shard, sd, owner);
        return Ok(());
    }
    if let Ok(notifs) = serde_json::from_slice::<Vec<Notification>>(bytes) {
        apply_inbox_delta(shard, InboxDelta::Notifs(notifs), owner);
        return Ok(());
    }
    let other =
        serde_json::from_slice::<InboxShard>(bytes).map_err(|_| ContractError::InvalidDelta)?;
    merge_state(shard, other, owner);
    Ok(())
}

/// Re-verify and merge a batch of owner-signed prune ops. **Every op is checked
/// against the owner for `INBOX_SHARD_CONTEXT` here** — a prune is the owner's
/// exclusive right, so an unverified prune op from any peer (delta, sync, or
/// full-state) is dropped, not trusted. This is the suppression-side of "every
/// write path verifies": without it, a peer could ship `pruned_before = u64::MAX`
/// and wipe an honest inbox network-wide (review CRITICAL, sixth round).
fn merge_prune_ops(shard: &mut InboxShard, ops: Vec<SignedOp>, owner: &str) {
    if owner.is_empty() {
        return;
    }
    for op in ops {
        if prune_op_is_acceptable(&op) && op.verify(INBOX_SHARD_CONTEXT, owner).is_ok() {
            merge_prune_op(shard, op);
        }
    }
}

/// Whether a prune op is within its size bounds.
///
/// `PruneIds` shares `encode_id_list` with the user shard's and global index's
/// `RetractPost`, and inherits the same two independent ceilings: `payload`
/// bytes, and the number of ids named. `decode_id_list` bounds neither — it is
/// tolerant, stopping at `MAX_IDS_PER_OP` and returning what it parsed, so an
/// over-long list is silently TRUNCATED into a legal-looking op rather than
/// refused.
///
/// Owner-writes bounds the blast radius to a malicious owner bloating their own
/// inbox, which is the same reason the profile register is bounded — so the
/// bound belongs here too, by the same argument.
///
/// Deliberately enforced at ACCEPTANCE only, NOT in `validate_state`. Unlike
/// retraction, prune ops already exist in deployed inbox state; adding a
/// ceiling to `validate_state` could declare an already-stored op invalid and
/// strand a live inbox. Rejecting new oversized ops while continuing to accept
/// existing states is the safe direction: `update_state` never produces a state
/// `validate_state` would refuse.
fn prune_op_is_acceptable(op: &SignedOp) -> bool {
    op.within_bounds() && id_list_count_within_bounds(&op.payload)
}

/// Apply an `InboxStateDelta` (the sync delta from `get_state_delta`). It carries
/// the owner-signed prune ops and the full self-verifying notifications the
/// requester lacks. Prune ops are re-verified and merged first (so a notification
/// the requester is about to receive is correctly suppressed); notifications are
/// re-verified by `merge_notif`. Nothing here is trusted on the sender's say-so.
fn apply_state_delta(shard: &mut InboxShard, sd: InboxStateDelta, owner: &str) {
    merge_prune_ops(shard, sd.prune_before_op.into_iter().collect(), owner);
    merge_prune_ops(shard, sd.prune_ids_ops, owner);
    for notif in sd.notifs {
        merge_notif(shard, notif, owner);
    }
}

/// Full-state merge: fold `other` into `shard` under the same acceptance +
/// convergence rules as a delta. Prune ops re-verify and merge first; then every
/// notification of `other` is re-verified — `other` came over the wire from a
/// possibly-adversarial peer, so neither its notifications nor its prune ops may
/// be trusted as "already validated upstream" (the thread-shard CRITICAL / M-1
/// lesson, plus its suppression variant — review CRITICAL, sixth round).
fn merge_state(shard: &mut InboxShard, other: InboxShard, owner: &str) {
    merge_prune_ops(shard, other.prune_before_op.into_iter().collect(), owner);
    merge_prune_ops(shard, other.prune_ids_ops.into_values().collect(), owner);
    for (_id, notif) in other.notifs {
        merge_notif(shard, notif, owner);
    }
}

#[contract]
impl ContractInterface for InboxShard {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts,
    ) -> Result<ValidateResult, ContractError> {
        let shard = InboxShard::try_from(state)?;
        let owner = owner_vk_hex(&parameters);

        // Every retained prune op must be a genuine owner signature for this inbox
        // context, and keyed under its own seq — update_state only ever stores
        // verified ops, so a state carrying an unverifiable (forged) prune op, or
        // a PruneBefore op of the wrong type, is invalid. This is what makes the
        // high-water / tombstones unforgeable: a peer cannot smuggle a removal
        // claim past validate (review CRITICAL, sixth round).
        if let Some(op) = &shard.prune_before_op {
            if op.op_type != OpType::PruneBefore || op.verify(INBOX_SHARD_CONTEXT, &owner).is_err()
            {
                return Err(ContractError::InvalidState);
            }
        }
        // Deliberately does NOT check `prune_op_is_acceptable` here, and that
        // asymmetry with the acceptance paths is the point — do NOT "fix" it by
        // adding the bound. Prune ops already exist in DEPLOYED inbox state, so
        // a ceiling enforced here could declare an already-stored op invalid and
        // strand a live inbox. Refusing new oversized ops while continuing to
        // accept existing states is the safe direction; the invariant that must
        // hold is only that `update_state` never PRODUCES a state this would
        // reject, which stays true when update is the stricter of the two.
        //
        // Keying by `seq` here is a known convergence defect (raven#66), left in
        // place for the same reason: re-keying is a breaking wire change that
        // needs a migration. Retraction could be re-keyed freely because it had
        // never shipped; this had.
        for (seq, op) in &shard.prune_ids_ops {
            if op.op_type != OpType::PruneIds
                || op.seq != *seq
                || op.verify(INBOX_SHARD_CONTEXT, &owner).is_err()
            {
                return Err(ContractError::InvalidState);
            }
        }

        // Every stored notification must be admissible: self-verifying, bound to
        // this owner, keyed under its own content address, AND not suppressed by
        // the (now-proven) prune state it is stored alongside. update_state
        // guarantees all of these, so validate_state must reject any state
        // violating them (AGENTS.md → "validate agrees with update"). In
        // particular a notification that is tombstoned or below the high-water
        // would have been dropped by update_state, so its presence is invalid (a
        // forged resurrection).
        let hw = pruned_before(&shard);
        let tombstones = tombstone_ids(&shard);
        for (id, notif) in &shard.notifs {
            if !notif_admissible(id, notif, &owner, &tombstones, hw) {
                return Err(ContractError::InvalidState);
            }
        }
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        delta: Vec<UpdateData>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let mut shard = InboxShard::try_from(state)?;
        let owner = owner_vk_hex(&parameters);

        // Iterate EVERY update item (not just the first), dispatching per kind.
        for item in &delta {
            match item {
                UpdateData::Delta(d) => apply_delta_bytes(&mut shard, d.as_ref(), &owner)?,
                UpdateData::State(s) => {
                    let other = InboxShard::try_from(State::from(s.to_vec()))?;
                    merge_state(&mut shard, other, &owner);
                }
                UpdateData::StateAndDelta { state: s, delta: d } => {
                    let other = InboxShard::try_from(State::from(s.to_vec()))?;
                    merge_state(&mut shard, other, &owner);
                    apply_delta_bytes(&mut shard, d.as_ref(), &owner)?;
                }
                _ => {}
            }
        }

        normalize(&mut shard);
        let bytes = serde_json::to_vec(&shard).map_err(|e| ContractError::Other(format!("{e}")))?;
        Ok(UpdateModification::valid(State::from(bytes)))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let shard = InboxShard::try_from(state)?;
        // Summary = the notif id set + which prune ops the holder has (the
        // PruneBefore seq, and the PruneIds op seqs), so get_state_delta can ship
        // only the notifs and prune ops the requester lacks.
        let summary = InboxSummary {
            notifs: shard.notifs.keys().cloned().collect(),
            prune_before_seq: shard.prune_before_op.as_ref().map(|op| op.seq),
            prune_ids_seqs: shard.prune_ids_ops.keys().cloned().collect(),
        };
        let bytes =
            serde_json::to_vec(&summary).map_err(|e| ContractError::Other(format!("{e}")))?;
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let shard = InboxShard::try_from(state)?;
        let _ = owner_vk_hex(&parameters);
        let have: InboxSummary = serde_json::from_slice(summary.as_ref()).unwrap_or_default();

        let have_notifs: std::collections::HashSet<&String> = have.notifs.iter().collect();
        let have_prune_ids: std::collections::HashSet<u64> =
            have.prune_ids_seqs.iter().cloned().collect();

        // Notifications the requester lacks — full signed records, re-verified on
        // the receiving side (a sync delta is no more trusted than any other).
        let missing_notifs: Vec<Notification> = shard
            .notifs
            .iter()
            .filter(|(id, _)| !have_notifs.contains(id))
            .map(|(_, n)| n.clone())
            .collect();

        // Ship our PruneBefore op if it is newer than the requester's high-water,
        // and any PruneIds ops the requester lacks — the **signed ops**, so the
        // receiver re-verifies them (a prune is owner-authority; the receiver
        // never trusts our claimed effect, only a proven op). This is what keeps
        // suppression unforgeable across sync (review CRITICAL, sixth round).
        let prune_before_op = match (&shard.prune_before_op, have.prune_before_seq) {
            (Some(op), Some(have_seq)) if op.seq <= have_seq => None,
            (Some(op), _) => Some(op.clone()),
            (None, _) => None,
        };
        let prune_ids_ops: Vec<SignedOp> = shard
            .prune_ids_ops
            .iter()
            .filter(|(seq, _)| !have_prune_ids.contains(seq))
            .map(|(_, op)| op.clone())
            .collect();

        let delta = InboxStateDelta {
            notifs: missing_notifs,
            prune_before_op,
            prune_ids_ops,
        };
        let bytes = serde_json::to_vec(&delta).map_err(|e| ContractError::Other(format!("{e}")))?;
        Ok(StateDelta::from(bytes))
    }
}

/// Summary shape: the notif id set the requester already holds plus which prune
/// ops it has (the PruneBefore seq, the PruneIds op seqs), so `get_state_delta`
/// can ship only what is missing.
#[derive(Serialize, Deserialize, Default)]
struct InboxSummary {
    #[serde(default)]
    notifs: Vec<String>,
    #[serde(default)]
    prune_before_seq: Option<u64>,
    #[serde(default)]
    prune_ids_seqs: Vec<u64>,
}

/// The delta `get_state_delta` ships: full self-verifying notifications the
/// requester lacks, plus the **owner-signed prune ops** it lacks (not their
/// stripped effect). It is intentionally NOT an `InboxDelta` so it can convey
/// notifs and prune ops at once; `apply_delta_bytes` decodes it via
/// `apply_state_delta`, which re-verifies every notification AND every prune op.
#[derive(Serialize, Deserialize, Default)]
struct InboxStateDelta {
    #[serde(default)]
    notifs: Vec<Notification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prune_before_op: Option<SignedOp>,
    #[serde(default)]
    prune_ids_ops: Vec<SignedOp>,
}

#[cfg(test)]
mod test {
    use super::*;
    use freenet_microblogging_common::inbox::NotifKind;
    use ml_dsa::KeyGen;
    use ml_dsa::signature::{Keypair, Signer};
    use ml_dsa::{MlDsa65, Signature};

    /// Owner identity for the inbox under test (seed 1).
    fn owner_seed() -> [u8; 32] {
        [1u8; 32]
    }

    fn owner_vk() -> String {
        let sk = MlDsa65::from_seed(&owner_seed().into());
        hex::encode(sk.verifying_key().encode())
    }

    fn params() -> Parameters<'static> {
        let sk = MlDsa65::from_seed(&owner_seed().into());
        Parameters::from(sk.verifying_key().encode().to_vec())
    }

    /// A signed notification to this inbox's owner from sender `seed`.
    fn signed_notif(seed: [u8; 32], kind: NotifKind, ref_id: &str, seq: u64) -> Notification {
        let sk = MlDsa65::from_seed(&seed.into());
        let owner = owner_vk();
        let mut n = Notification {
            kind,
            sender_pubkey: hex::encode(sk.verifying_key().encode()),
            ref_id: ref_id.into(),
            seq,
            writer_cert: None,
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&n.signing_payload(&owner));
        n.signature = Some(hex::encode(sig.encode()));
        n
    }

    /// An owner-signed prune op for this inbox.
    fn prune_op(op_type: OpType, payload: Vec<u8>, seq: u64) -> SignedOp {
        let sk = MlDsa65::from_seed(&owner_seed().into());
        let mut op = SignedOp {
            op_type,
            payload,
            seq,
            signer_pubkey: owner_vk(),
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&op.signing_payload(INBOX_SHARD_CONTEXT));
        op.signature = Some(hex::encode(sig.encode()));
        op
    }

    fn state_of(shard: &InboxShard) -> State<'static> {
        State::from(serde_json::to_vec(shard).unwrap())
    }

    fn delta_item(d: &InboxDelta) -> UpdateData<'static> {
        UpdateData::Delta(StateDelta::from(serde_json::to_vec(d).unwrap()))
    }

    fn run_update(shard: InboxShard, items: Vec<UpdateData<'static>>) -> InboxShard {
        let res = InboxShard::update_state(params(), state_of(&shard), items).unwrap();
        serde_json::from_slice(res.unwrap_valid().as_ref()).unwrap()
    }

    #[test]
    fn notif_accepted_only_when_bound_to_this_owner() {
        let good = signed_notif([2u8; 32], NotifKind::Reply, "post_a", 1);
        // A notif signed for a different recipient must be rejected here. Build one
        // bound to a bogus recipient.
        let sk = MlDsa65::from_seed(&[2u8; 32].into());
        let mut wrong = Notification {
            kind: NotifKind::Reply,
            sender_pubkey: hex::encode(sk.verifying_key().encode()),
            ref_id: "post_a".into(),
            seq: 1,
            writer_cert: None,
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&wrong.signing_payload("a_different_owner"));
        wrong.signature = Some(hex::encode(sig.encode()));

        let out = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Notifs(vec![good.clone(), wrong]))],
        );
        assert_eq!(out.notifs.len(), 1);
        assert!(out.notifs.contains_key(&good.id(&owner_vk())));
    }

    #[test]
    fn notifs_dedup_by_content_address() {
        let n = signed_notif([2u8; 32], NotifKind::Quote, "post_x", 3);
        let out = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Notifs(vec![n.clone(), n.clone()]))],
        );
        assert_eq!(out.notifs.len(), 1);
    }

    #[test]
    fn oversized_ref_id_rejected() {
        // ref_id is sender-chosen and self-verifying, so a signature alone
        // does not bound it — only `within_bounds()` does. An inbox is
        // anyone-writes, so an unbounded ref_id is an unbounded write
        // primitive available to anyone.
        let big = "x".repeat(freenet_microblogging_common::inbox::MAX_REF_ID_LEN + 1);
        let n = signed_notif([2u8; 32], NotifKind::Reply, &big, 1);
        assert_eq!(n.verify(&owner_vk()), Ok(()));
        let out = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Notifs(vec![n]))],
        );
        assert!(out.notifs.is_empty());
    }

    #[test]
    fn oversized_writer_cert_rejected() {
        // writer_cert is excluded from the signing payload (it is not yet a
        // verified credential), so it can be attached AFTER signing without
        // invalidating the signature — no keypair of one's own is needed, only
        // a valid notification to relay with a new cert bolted on. Only
        // `verify_writer_cert`'s size bound stops this from being an
        // unbounded write primitive on an anyone-writes inbox.
        let mut n = signed_notif([2u8; 32], NotifKind::Reply, "p", 1);
        assert_eq!(n.verify(&owner_vk()), Ok(()));
        n.writer_cert = Some(WriterCert {
            cert: vec![0u8; freenet_microblogging_common::thread::MAX_WRITER_CERT_LEN + 1],
        });
        // Tampering writer_cert after signing must NOT break the signature.
        assert_eq!(n.verify(&owner_vk()), Ok(()));

        let out = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Notifs(vec![n]))],
        );
        assert!(out.notifs.is_empty());
    }

    #[test]
    fn tampered_notif_signature_rejected() {
        let mut bad = signed_notif([2u8; 32], NotifKind::Reply, "p", 1);
        bad.seq = 99; // breaks signature
        let out = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Notifs(vec![bad]))],
        );
        assert!(out.notifs.is_empty());
    }

    #[test]
    fn owner_prune_ids_removes_and_tombstones() {
        let n = signed_notif([2u8; 32], NotifKind::Reply, "p", 5);
        let id = n.id(&owner_vk());
        let base = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Notifs(vec![n]))],
        );
        assert_eq!(base.notifs.len(), 1);

        // PruneIds carries (id, notif_seq) pairs; the owner attests both.
        let op = prune_op(
            OpType::PruneIds,
            encode_prune_ids(std::slice::from_ref(&id)),
            1,
        );
        let out = run_update(base, vec![delta_item(&InboxDelta::Prune(op))]);
        assert!(out.notifs.is_empty(), "pruned notif removed");
        assert!(tombstone_ids(&out).contains(&id), "tombstone recorded");
    }

    #[test]
    fn an_oversized_prune_payload_is_rejected() {
        // `PruneIds` shares `encode_id_list` with RetractPost and inherits the
        // same two ceilings. `decode_id_list` bounds neither — it truncates.
        use freenet_microblogging_common::signed_op::MAX_OP_PAYLOAD_LEN;

        let ids: Vec<String> = (0..40_000).map(|i| format!("id-{i:0>100}")).collect();
        let op = prune_op(OpType::PruneIds, encode_prune_ids(&ids), 1);
        assert!(op.payload.len() > MAX_OP_PAYLOAD_LEN);
        // Cryptographically valid — only the explicit bound refuses it.
        assert!(op.verify(INBOX_SHARD_CONTEXT, &owner_vk()).is_ok());

        let out = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Prune(op))],
        );
        assert!(
            out.prune_ids_ops.is_empty(),
            "an unbounded prune payload was stored"
        );
    }

    #[test]
    fn an_overlong_prune_id_list_is_refused_not_truncated() {
        use freenet_microblogging_common::signed_op::MAX_IDS_PER_OP;

        let ids: Vec<String> = (0..MAX_IDS_PER_OP + 1).map(|i| format!("id-{i}")).collect();
        let op = prune_op(OpType::PruneIds, encode_prune_ids(&ids), 1);
        // Legal under the BYTE bound, so only the count bound can refuse it.
        assert!(op.within_bounds(), "fixture must be under the byte ceiling");
        assert_eq!(
            decode_prune_ids(&op.payload).len(),
            MAX_IDS_PER_OP,
            "decode must be silently truncating, or this proves nothing"
        );

        let out = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Prune(op))],
        );
        assert!(
            out.prune_ids_ops.is_empty(),
            "a truncated prefix of the signed list was stored"
        );
    }

    #[test]
    fn tombstone_blocks_resurrection() {
        // Owner prunes a notif by id; a stale replica then re-delivers the same
        // notif. The tombstone must keep it out (no resurrection).
        let n = signed_notif([2u8; 32], NotifKind::Reply, "p", 5);
        let id = n.id(&owner_vk());
        let op = prune_op(
            OpType::PruneIds,
            encode_prune_ids(std::slice::from_ref(&id)),
            1,
        );

        // Prune first, then the (late) re-delivery arrives.
        let pruned = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Prune(op))],
        );
        let out = run_update(pruned, vec![delta_item(&InboxDelta::Notifs(vec![n]))]);
        assert!(out.notifs.is_empty(), "tombstoned notif must not resurrect");
    }

    #[test]
    fn prune_before_drops_below_high_water_and_blocks_old() {
        let old = signed_notif([2u8; 32], NotifKind::Reply, "old", 3);
        let new = signed_notif([3u8; 32], NotifKind::Reply, "new", 10);
        let base = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Notifs(vec![old, new.clone()]))],
        );
        assert_eq!(base.notifs.len(), 2);

        // Prune everything with seq < 5.
        let op = prune_op(OpType::PruneBefore, Vec::new(), 5);
        let out = run_update(base, vec![delta_item(&InboxDelta::Prune(op))]);
        assert_eq!(out.notifs.len(), 1, "old dropped, new kept");
        assert_eq!(pruned_before(&out), 5);

        // A late old notif (seq 4) cannot be admitted below the high-water.
        let late = signed_notif([4u8; 32], NotifKind::Reply, "late", 4);
        let out2 = run_update(out, vec![delta_item(&InboxDelta::Notifs(vec![late]))]);
        assert_eq!(out2.notifs.len(), 1, "below-high-water notif rejected");
    }

    #[test]
    fn prune_before_is_monotonic() {
        let op_hi = prune_op(OpType::PruneBefore, Vec::new(), 10);
        let op_lo = prune_op(OpType::PruneBefore, Vec::new(), 3);
        // Apply high then low: the low must not lower the high-water (we keep the
        // higher-seq signed op).
        let out = run_update(
            InboxShard::default(),
            vec![
                delta_item(&InboxDelta::Prune(op_hi)),
                delta_item(&InboxDelta::Prune(op_lo)),
            ],
        );
        assert_eq!(pruned_before(&out), 10);
    }

    #[test]
    fn non_owner_prune_rejected() {
        // A prune op signed by someone other than the owner must be ignored — the
        // signer != owner check in SignedOp::verify (owner-writes for prunes).
        let n = signed_notif([2u8; 32], NotifKind::Reply, "p", 5);
        let id = n.id(&owner_vk());
        let base = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Notifs(vec![n]))],
        );

        // Forge a prune signed by a NON-owner key (seed 2) but claiming to prune.
        let attacker = MlDsa65::from_seed(&[2u8; 32].into());
        let mut op = SignedOp {
            op_type: OpType::PruneIds,
            payload: encode_prune_ids(std::slice::from_ref(&id)),
            seq: 1,
            signer_pubkey: hex::encode(attacker.verifying_key().encode()),
            signature: None,
        };
        let sig: Signature<MlDsa65> = attacker.sign(&op.signing_payload(INBOX_SHARD_CONTEXT));
        op.signature = Some(hex::encode(sig.encode()));

        let out = run_update(base, vec![delta_item(&InboxDelta::Prune(op))]);
        assert_eq!(out.notifs.len(), 1, "non-owner prune must be ignored");
        assert!(out.prune_ids_ops.is_empty());
    }

    #[test]
    fn prune_op_replayed_from_user_shard_context_rejected() {
        // A prune op is bound to INBOX_SHARD_CONTEXT. An op the owner signed for
        // the USER_SHARD_CONTEXT (or any other context) must not verify here.
        use freenet_microblogging_common::signed_op::USER_SHARD_CONTEXT;
        let n = signed_notif([2u8; 32], NotifKind::Reply, "p", 5);
        let id = n.id(&owner_vk());
        let base = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Notifs(vec![n]))],
        );

        let sk = MlDsa65::from_seed(&owner_seed().into());
        let mut op = SignedOp {
            op_type: OpType::PruneIds,
            payload: encode_prune_ids(std::slice::from_ref(&id)),
            seq: 1,
            signer_pubkey: owner_vk(),
            signature: None,
        };
        // Signed for the WRONG context.
        let sig: Signature<MlDsa65> = sk.sign(&op.signing_payload(USER_SHARD_CONTEXT));
        op.signature = Some(hex::encode(sig.encode()));

        let out = run_update(base, vec![delta_item(&InboxDelta::Prune(op))]);
        assert_eq!(out.notifs.len(), 1, "cross-context prune must be ignored");
    }

    #[test]
    fn notif_arriving_before_prune_is_normalized_out() {
        // A prune op may merge in AFTER the notif (reordering). normalize must drop
        // a notif the high-water now suppresses even though it was admissible when
        // first inserted. Drive via a full-state merge of a peer holding the signed
        // PruneBefore op.
        let old = signed_notif([2u8; 32], NotifKind::Reply, "old", 3);
        let with_notif = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Notifs(vec![old]))],
        );

        // A peer state that holds the owner-signed high-water op (seq 5), no notifs.
        let pruned_peer = InboxShard {
            prune_before_op: Some(prune_op(OpType::PruneBefore, Vec::new(), 5)),
            ..Default::default()
        };

        let out = run_update(with_notif, vec![UpdateData::State(state_of(&pruned_peer))]);
        assert!(
            out.notifs.is_empty(),
            "notif below merged-in high-water normalized out"
        );
        assert_eq!(pruned_before(&out), 5);
    }

    #[test]
    fn forged_unsigned_prune_evidence_cannot_suppress() {
        // CRITICAL regression (sixth round): a peer crafts a state whose
        // prune_before_op is unsigned (or signed by a non-owner) claiming
        // u64::MAX, shipped as UpdateData::State, trying to wipe an honest inbox.
        // merge_state must re-verify the op against the owner and DROP it, so the
        // honest replica's high-water stays 0 and its notif survives.
        let n = signed_notif([2u8; 32], NotifKind::Reply, "keep", 5);
        let honest = run_update(
            InboxShard::default(),
            vec![delta_item(&InboxDelta::Notifs(vec![n]))],
        );
        assert_eq!(honest.notifs.len(), 1);

        // Forged: a PruneBefore op with seq=u64::MAX but NO valid owner signature,
        // plus a forged tombstone op naming the honest notif's id.
        let id = honest.notifs.keys().next().unwrap().clone();
        let mut prune_ids_ops = BTreeMap::new();
        prune_ids_ops.insert(
            7,
            SignedOp {
                op_type: OpType::PruneIds,
                payload: encode_prune_ids(std::slice::from_ref(&id)),
                seq: 7,
                signer_pubkey: owner_vk(),
                signature: None, // forged
            },
        );
        let malicious = InboxShard {
            prune_before_op: Some(SignedOp {
                op_type: OpType::PruneBefore,
                payload: Vec::new(),
                seq: u64::MAX,
                signer_pubkey: owner_vk(),
                signature: None, // forged: not signed
            }),
            prune_ids_ops,
            ..Default::default()
        };

        let out = run_update(honest, vec![UpdateData::State(state_of(&malicious))]);
        assert_eq!(
            pruned_before(&out),
            0,
            "forged high-water must not be adopted"
        );
        assert_eq!(
            out.notifs.len(),
            1,
            "honest notif must survive a forged suppression attempt"
        );
        assert!(out.prune_ids_ops.is_empty(), "forged tombstone op dropped");
    }

    #[test]
    fn validate_rejects_forged_prune_before_op() {
        // A state carrying an unsigned/forged PruneBefore op must fail validate —
        // update_state only ever stores verified ops, so the two halves agree.
        let shard = InboxShard {
            prune_before_op: Some(SignedOp {
                op_type: OpType::PruneBefore,
                payload: Vec::new(),
                seq: 99,
                signer_pubkey: owner_vk(),
                signature: None,
            }),
            ..Default::default()
        };
        let res = InboxShard::validate_state(params(), state_of(&shard), RelatedContracts::new());
        assert!(!matches!(res, Ok(ValidateResult::Valid)));
    }

    #[test]
    fn validate_rejects_misfiled_notif_id() {
        let mut shard = InboxShard::default();
        let n = signed_notif([2u8; 32], NotifKind::Reply, "x", 1);
        shard.notifs.insert("wrong_key".into(), n);
        let res = InboxShard::validate_state(params(), state_of(&shard), RelatedContracts::new());
        assert!(!matches!(res, Ok(ValidateResult::Valid)));
    }

    #[test]
    fn validate_rejects_forged_unsigned_notif() {
        // A state carrying an unsigned notif (no key) must fail validate — the two
        // halves agree, update_state would never store it (the thread CRITICAL
        // lesson applied to the inbox).
        let owner = owner_vk();
        let sk = MlDsa65::from_seed(&[2u8; 32].into());
        let forged = Notification {
            kind: NotifKind::Reply,
            sender_pubkey: hex::encode(sk.verifying_key().encode()),
            ref_id: "x".into(),
            seq: 1,
            writer_cert: None,
            signature: None, // forged: no signature
        };
        let id = forged.id(&owner);
        let mut shard = InboxShard::default();
        shard.notifs.insert(id, forged);
        let res = InboxShard::validate_state(params(), state_of(&shard), RelatedContracts::new());
        assert!(!matches!(res, Ok(ValidateResult::Valid)));
    }

    #[test]
    fn validate_rejects_tombstoned_notif_present() {
        // A notif present alongside an owner-signed PruneIds op that names it would
        // have been removed by update_state, so its presence is invalid (a
        // resurrection forgery). The tombstone op must itself be genuine, else
        // validate would reject on the op instead — we want to prove the notif
        // check fires.
        let n = signed_notif([2u8; 32], NotifKind::Reply, "p", 5);
        let id = n.id(&owner_vk());
        let mut shard = InboxShard::default();
        shard.notifs.insert(id.clone(), n);
        // Genuine owner-signed PruneIds op tombstoning that id (notif_seq 5, at or
        // above the high-water of 0, so the tombstone is live).
        let op = prune_op(
            OpType::PruneIds,
            encode_prune_ids(std::slice::from_ref(&id)),
            1,
        );
        shard.prune_ids_ops.insert(1, op);
        let res = InboxShard::validate_state(params(), state_of(&shard), RelatedContracts::new());
        assert!(!matches!(res, Ok(ValidateResult::Valid)));
    }

    #[test]
    fn validate_accepts_well_formed_state() {
        let n = signed_notif([2u8; 32], NotifKind::Follow, "", 1);
        let mut shard = InboxShard::default();
        shard.notifs.insert(n.id(&owner_vk()), n);
        let res = InboxShard::validate_state(params(), state_of(&shard), RelatedContracts::new())
            .unwrap();
        assert!(matches!(res, ValidateResult::Valid));
    }

    #[test]
    fn notifs_truncate_deterministically() {
        // Exercise the post-merge cap directly on `truncate_notifs` rather than
        // signing MAX_NOTIFS+ real notifications (ML-DSA signing 10k records is
        // minutes, not a CI fit). The cap is a pure function of the (seq, id) key
        // set and ignores signatures, so unsigned fixtures prove the same
        // order-independence property: both arrival orders retain the identical
        // newest-by-(seq,id) set.
        fn fake(id: &str, seq: u64) -> Notification {
            Notification {
                kind: NotifKind::Reply,
                sender_pubkey: "00".into(),
                ref_id: id.into(),
                seq,
                writer_cert: None,
                signature: None,
            }
        }
        let n = MAX_NOTIFS + 25;
        let mut a: BTreeMap<String, Notification> = BTreeMap::new();
        let mut b: BTreeMap<String, Notification> = BTreeMap::new();
        // Insert in opposite orders; the retained set must match.
        for i in 0..n {
            let id = format!("{i:08}");
            a.insert(id.clone(), fake(&id, 1000 + i as u64));
        }
        for i in (0..n).rev() {
            let id = format!("{i:08}");
            b.insert(id.clone(), fake(&id, 1000 + i as u64));
        }
        truncate_notifs(&mut a);
        truncate_notifs(&mut b);
        assert_eq!(a.len(), MAX_NOTIFS);
        assert_eq!(
            a.keys().collect::<Vec<_>>(),
            b.keys().collect::<Vec<_>>(),
            "cap must retain the same set regardless of insertion order"
        );
    }

    #[test]
    fn empty_owner_param_accepts_nothing() {
        let n = signed_notif([2u8; 32], NotifKind::Reply, "p", 1);
        let res = InboxShard::update_state(
            Parameters::from(Vec::new()),
            state_of(&InboxShard::default()),
            vec![delta_item(&InboxDelta::Notifs(vec![n]))],
        )
        .unwrap();
        let out: InboxShard = serde_json::from_slice(res.unwrap_valid().as_ref()).unwrap();
        assert!(out.notifs.is_empty());
    }

    #[test]
    fn get_state_delta_output_is_applyable() {
        // Regression: get_state_delta ships an InboxStateDelta; apply_delta_bytes
        // must decode and apply it (round-trip), or peers never sync.
        let mut src = InboxShard::default();
        let n = signed_notif([2u8; 32], NotifKind::Reply, "r", 5);
        src.notifs.insert(n.id(&owner_vk()), n);
        // Genuine owner-signed prune ops on the source.
        src.prune_before_op = Some(prune_op(OpType::PruneBefore, Vec::new(), 2));
        let pruned_id = signed_notif([6u8; 32], NotifKind::Reply, "gone", 9).id(&owner_vk());
        src.prune_ids_ops.insert(
            3,
            prune_op(
                OpType::PruneIds,
                encode_prune_ids(std::slice::from_ref(&pruned_id)),
                3,
            ),
        );

        let empty_summary =
            StateSummary::from(serde_json::to_vec(&InboxSummary::default()).unwrap());
        let delta = InboxShard::get_state_delta(params(), state_of(&src), empty_summary).unwrap();

        let out = run_update(
            InboxShard::default(),
            vec![UpdateData::Delta(StateDelta::from(
                delta.into_bytes().to_vec(),
            ))],
        );
        assert_eq!(out.notifs.len(), 1);
        assert_eq!(pruned_before(&out), 2);
        assert!(tombstone_ids(&out).contains(&pruned_id));
    }

    #[test]
    fn forged_notif_via_full_state_merge_rejected() {
        // CRITICAL-class regression: an adversary crafts an InboxShard whose notifs
        // map carries an unsigned notif, shipped as UpdateData::State. merge_state
        // must re-verify and drop it.
        let owner = owner_vk();
        let sk = MlDsa65::from_seed(&[2u8; 32].into());
        let forged = Notification {
            kind: NotifKind::Reply,
            sender_pubkey: hex::encode(sk.verifying_key().encode()),
            ref_id: "x".into(),
            seq: 1,
            writer_cert: None,
            signature: None,
        };
        let mut malicious = InboxShard::default();
        malicious.notifs.insert(forged.id(&owner), forged);
        let out = run_update(
            InboxShard::default(),
            vec![UpdateData::State(state_of(&malicious))],
        );
        assert!(
            out.notifs.is_empty(),
            "forged unsigned notif must not be stored"
        );
    }

    #[test]
    fn decodes_old_shape_state() {
        let empty: InboxShard = serde_json::from_slice(b"{}").unwrap();
        assert!(
            empty.notifs.is_empty()
                && empty.prune_before_op.is_none()
                && empty.prune_ids_ops.is_empty()
        );
        let forward: InboxShard = serde_json::from_slice(
            br#"{"notifs":{},"prune_ids_ops":{},"pruned_before":0,"version":2}"#,
        )
        .unwrap();
        assert!(forward.notifs.is_empty());
    }

    #[test]
    fn high_water_does_not_drop_selective_tombstone() {
        // MAJOR regression (seventh round): a selective PruneIds tombstone must NOT
        // be GC'd by the high-water — there is no sound per-id seq to compare, so
        // tombstones are a pure grow-set. Prune a high-seq notif selectively, then
        // advance the high-water far past low values; the tombstone (and the notif
        // suppression) must persist, with no resurrection.
        let n = signed_notif([2u8; 32], NotifKind::Reply, "p", 999);
        let id = n.id(&owner_vk());
        let base = run_update(
            InboxShard::default(),
            vec![
                delta_item(&InboxDelta::Notifs(vec![n.clone()])),
                delta_item(&InboxDelta::Prune(prune_op(
                    OpType::PruneIds,
                    encode_prune_ids(std::slice::from_ref(&id)),
                    1,
                ))),
            ],
        );
        assert!(base.notifs.is_empty());
        assert!(tombstone_ids(&base).contains(&id));

        // Advance the high-water to 50 — far below the pruned notif's seq (999),
        // so it must NOT make the tombstone redundant or drop it.
        let out = run_update(
            base,
            vec![delta_item(&InboxDelta::Prune(prune_op(
                OpType::PruneBefore,
                Vec::new(),
                50,
            )))],
        );
        assert!(
            tombstone_ids(&out).contains(&id),
            "selective tombstone must survive an unrelated high-water advance"
        );
        // And a re-delivery of the seq-999 notif (above the high-water) is still
        // blocked by the surviving tombstone — no resurrection.
        let after = run_update(out, vec![delta_item(&InboxDelta::Notifs(vec![n]))]);
        assert!(
            after.notifs.is_empty(),
            "tombstoned notif must not resurrect"
        );
    }

    #[test]
    fn state_and_delta_merges_both() {
        // The StateAndDelta update arm: one update item carrying a full state AND
        // a delta. update_state must merge_state the state THEN apply the delta,
        // so a record from each is present and post-merge invariants hold.
        // Full state: a notif (seq 5) + a genuine owner-signed PruneBefore (seq 2).
        let from_state = signed_notif([2u8; 32], NotifKind::Reply, "from-state", 5);
        let mut src = InboxShard::default();
        src.notifs
            .insert(from_state.id(&owner_vk()), from_state.clone());
        src.prune_before_op = Some(prune_op(OpType::PruneBefore, Vec::new(), 2));
        // Delta: a second notif (seq 6, above the high-water) on the notif surface.
        let from_delta = signed_notif([3u8; 32], NotifKind::Quote, "from-delta", 6);
        let delta = serde_json::to_vec(&InboxDelta::Notifs(vec![from_delta.clone()])).unwrap();

        let out = run_update(
            InboxShard::default(),
            vec![UpdateData::StateAndDelta {
                state: state_of(&src),
                delta: StateDelta::from(delta),
            }],
        );
        // Both notifs present (state's + delta's), each above the high-water.
        assert_eq!(out.notifs.len(), 2, "state notif + delta notif both merged");
        assert!(out.notifs.contains_key(&from_state.id(&owner_vk())));
        assert!(out.notifs.contains_key(&from_delta.id(&owner_vk())));
        // State's owner-signed high-water survived the merge.
        assert_eq!(pruned_before(&out), 2);
        // Invariants: every notif keyed under its own content address and at or
        // above the high-water (the admission rule normalize enforces post-merge).
        let hw = pruned_before(&out);
        for (id, n) in &out.notifs {
            assert_eq!(id, &n.id(&owner_vk()));
            assert!(n.seq >= hw);
        }
    }

    #[test]
    fn prune_ids_payload_round_trips() {
        let ids = vec!["aaa".to_string(), "bbb".to_string(), "ccc".to_string()];
        let encoded = encode_prune_ids(&ids);
        assert_eq!(decode_prune_ids(&encoded), ids);
        // Truncated/garbage trailing bytes are tolerated (no panic).
        let mut trunc = encoded.clone();
        trunc.truncate(encoded.len() - 1);
        let _ = decode_prune_ids(&trunc); // must not panic
    }
}

/// Integration tests: drive the full `ContractInterface` (validate / update /
/// summarize / get_state_delta) through multi-replica scenarios — the layer above
/// the per-function unit tests. The key scenarios are **two replicas reconciling
/// via the real sync protocol** and the **owner-prune convergence invariant** (a
/// pruned notification must not resurrect through a stale replica).
///
/// These still call the contract as a Rust library (not compiled WASM in a node);
/// true WASM-in-node e2e is a separate, heavier tier (see the `freenet:linux-test`
/// skill).
#[cfg(test)]
mod integration {
    use super::*;
    use freenet_microblogging_common::inbox::NotifKind;
    use ml_dsa::signature::{Keypair, Signer};
    use ml_dsa::{KeyGen, MlDsa65, Signature};

    fn owner_seed() -> [u8; 32] {
        [1u8; 32]
    }
    fn owner_vk() -> String {
        let sk = MlDsa65::from_seed(&owner_seed().into());
        hex::encode(sk.verifying_key().encode())
    }
    fn params() -> Parameters<'static> {
        let sk = MlDsa65::from_seed(&owner_seed().into());
        Parameters::from(sk.verifying_key().encode().to_vec())
    }
    fn state_of(shard: &InboxShard) -> State<'static> {
        State::from(serde_json::to_vec(shard).unwrap())
    }
    fn decode(state: State<'static>) -> InboxShard {
        serde_json::from_slice(state.as_ref()).unwrap()
    }

    fn notif(seed: [u8; 32], kind: NotifKind, ref_id: &str, seq: u64) -> Notification {
        let sk = MlDsa65::from_seed(&seed.into());
        let owner = owner_vk();
        let mut n = Notification {
            kind,
            sender_pubkey: hex::encode(sk.verifying_key().encode()),
            ref_id: ref_id.into(),
            seq,
            writer_cert: None,
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&n.signing_payload(&owner));
        n.signature = Some(hex::encode(sig.encode()));
        n
    }

    fn prune_op(op_type: OpType, payload: Vec<u8>, seq: u64) -> SignedOp {
        let sk = MlDsa65::from_seed(&owner_seed().into());
        let mut op = SignedOp {
            op_type,
            payload,
            seq,
            signer_pubkey: owner_vk(),
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&op.signing_payload(INBOX_SHARD_CONTEXT));
        op.signature = Some(hex::encode(sig.encode()));
        op
    }

    fn apply(shard: &InboxShard, items: Vec<UpdateData<'static>>) -> InboxShard {
        let res = InboxShard::update_state(params(), state_of(shard), items).unwrap();
        decode(res.unwrap_valid())
    }

    fn delta(d: &InboxDelta) -> UpdateData<'static> {
        UpdateData::Delta(StateDelta::from(serde_json::to_vec(d).unwrap()))
    }

    /// One directional sync step, faithful to the node protocol.
    fn sync_into(dst: &InboxShard, src: &InboxShard) -> InboxShard {
        assert!(matches!(
            InboxShard::validate_state(params(), state_of(dst), RelatedContracts::new()).unwrap(),
            ValidateResult::Valid
        ));
        let summary = InboxShard::summarize_state(params(), state_of(dst)).unwrap();
        let d = InboxShard::get_state_delta(params(), state_of(src), summary).unwrap();
        let merged = apply(
            dst,
            vec![UpdateData::Delta(StateDelta::from(d.into_bytes().to_vec()))],
        );
        assert!(matches!(
            InboxShard::validate_state(params(), state_of(&merged), RelatedContracts::new())
                .unwrap(),
            ValidateResult::Valid
        ));
        merged
    }

    fn reconcile(a: &InboxShard, b: &InboxShard) -> (InboxShard, InboxShard) {
        let a2 = sync_into(a, b);
        let b2 = sync_into(b, a);
        (a2, b2)
    }

    fn canonical(shard: &InboxShard) -> Vec<u8> {
        serde_json::to_vec(shard).unwrap()
    }

    #[test]
    fn two_replicas_converge_over_sync_protocol() {
        let empty = InboxShard::default();
        let a = apply(
            &empty,
            vec![delta(&InboxDelta::Notifs(vec![
                notif([2; 32], NotifKind::Reply, "ra", 1),
                notif([3; 32], NotifKind::Follow, "", 2),
            ]))],
        );
        let b = apply(
            &empty,
            vec![delta(&InboxDelta::Notifs(vec![notif(
                [4; 32],
                NotifKind::Quote,
                "qb",
                3,
            )]))],
        );

        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(canonical(&a2), canonical(&b2), "replicas must converge");
        assert_eq!(a2.notifs.len(), 3);
    }

    #[test]
    fn pruned_notif_does_not_resurrect_through_stale_replica() {
        // THE inbox convergence invariant. Replica A delivers a notif, then the
        // owner prunes it on A. Replica B still holds the original (un-pruned)
        // notif. After reconcile, both must agree the notif is GONE — B's stale
        // copy must not resurrect it on A.
        let n = notif([2; 32], NotifKind::Reply, "p", 5);
        let id = n.id(&owner_vk());

        let a_delivered = apply(
            &InboxShard::default(),
            vec![delta(&InboxDelta::Notifs(vec![n.clone()]))],
        );
        // B is the stale replica: it has the notif and never saw the prune.
        let b_stale = apply(
            &InboxShard::default(),
            vec![delta(&InboxDelta::Notifs(vec![n]))],
        );
        // Owner prunes on A.
        let a_pruned = apply(
            &a_delivered,
            vec![delta(&InboxDelta::Prune(prune_op(
                OpType::PruneIds,
                encode_prune_ids(std::slice::from_ref(&id)),
                1,
            )))],
        );
        assert!(a_pruned.notifs.is_empty());

        let (a2, b2) = reconcile(&a_pruned, &b_stale);
        assert_eq!(canonical(&a2), canonical(&b2), "replicas must converge");
        assert!(
            a2.notifs.is_empty() && b2.notifs.is_empty(),
            "pruned notif must stay pruned on both replicas (no resurrection)"
        );
        assert!(tombstone_ids(&a2).contains(&id));
    }

    #[test]
    fn high_water_prune_converges_over_sync() {
        // A advances the high-water past some notifs; B is behind. After sync both
        // hold the same high-water and the same (post-prune) notif set.
        let old = notif([2; 32], NotifKind::Reply, "old", 3);
        let new = notif([3; 32], NotifKind::Reply, "new", 10);
        let a = apply(
            &InboxShard::default(),
            vec![
                delta(&InboxDelta::Notifs(vec![old.clone(), new.clone()])),
                delta(&InboxDelta::Prune(prune_op(
                    OpType::PruneBefore,
                    Vec::new(),
                    5,
                ))),
            ],
        );
        // B still has the old notif and a zero high-water.
        let b = apply(
            &InboxShard::default(),
            vec![delta(&InboxDelta::Notifs(vec![old, new]))],
        );

        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(canonical(&a2), canonical(&b2));
        assert_eq!(pruned_before(&a2), 5);
        assert_eq!(
            a2.notifs.len(),
            1,
            "only the above-high-water notif survives"
        );
    }

    #[test]
    fn forged_notif_does_not_propagate_over_sync() {
        // A malicious replica holds a forged (unsigned) notif. An honest replica
        // syncing from it re-verifies and drops it.
        let owner = owner_vk();
        let sk = MlDsa65::from_seed(&[9u8; 32].into());
        let forged = Notification {
            kind: NotifKind::Reply,
            sender_pubkey: hex::encode(sk.verifying_key().encode()),
            ref_id: "x".into(),
            seq: 1,
            writer_cert: None,
            signature: None,
        };
        let mut malicious = InboxShard::default();
        malicious.notifs.insert(forged.id(&owner), forged);

        let honest = InboxShard::default();
        let synced = sync_into(&honest, &malicious);
        assert!(
            synced.notifs.is_empty(),
            "honest replica must reject forged notif over sync"
        );
    }

    #[test]
    fn prune_before_ops_converge_over_sync() {
        // A on high-water seq 5, B on seq 3 — over the sync protocol each adopts
        // the other's op; both land on the single seq-5 op (highest-wins, byte
        // identical), no split.
        let a = apply(
            &InboxShard::default(),
            vec![delta(&InboxDelta::Prune(prune_op(
                OpType::PruneBefore,
                Vec::new(),
                5,
            )))],
        );
        let b = apply(
            &InboxShard::default(),
            vec![delta(&InboxDelta::Prune(prune_op(
                OpType::PruneBefore,
                Vec::new(),
                3,
            )))],
        );
        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(canonical(&a2), canonical(&b2));
        assert_eq!(pruned_before(&a2), 5);
    }

    #[test]
    fn cross_shard_recipient_binding_is_consistent() {
        // A notification's recipient binding is exactly the inbox shard's owner VK
        // (its parameters). A notif addressed to owner-1 must land on owner-1's
        // inbox and be rejected by owner-2's inbox — the cross-shard contract that
        // makes inboxes non-fungible.
        let owner1_vk = owner_vk(); // seed 1
        let owner2_sk = MlDsa65::from_seed(&[20u8; 32].into());
        let owner2_params = Parameters::from(owner2_sk.verifying_key().encode().to_vec());

        // A notif addressed to owner-1.
        let n = notif([2; 32], NotifKind::Reply, "p", 1);

        // Accepted on owner-1's inbox.
        let on_1 = apply(
            &InboxShard::default(),
            vec![delta(&InboxDelta::Notifs(vec![n.clone()]))],
        );
        assert_eq!(on_1.notifs.len(), 1);
        assert!(on_1.notifs.contains_key(&n.id(&owner1_vk)));

        // Rejected on owner-2's inbox (its signed recipient is owner-1, not 2).
        let res = InboxShard::update_state(
            owner2_params,
            State::from(serde_json::to_vec(&InboxShard::default()).unwrap()),
            vec![UpdateData::Delta(StateDelta::from(
                serde_json::to_vec(&InboxDelta::Notifs(vec![n])).unwrap(),
            ))],
        )
        .unwrap();
        let on_2: InboxShard = serde_json::from_slice(res.unwrap_valid().as_ref()).unwrap();
        assert!(
            on_2.notifs.is_empty(),
            "notif must not land on the wrong inbox"
        );
    }
}
