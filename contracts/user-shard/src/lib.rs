//! User shard contract (ADR-0001, Phase 1).
//!
//! One contract per user, **owner-writes only**, parameterized by the owner's
//! raw encoded ML-DSA-65 verifying key. It bundles the three owner-writes /
//! low-churn / read-by-followers surfaces the ADR assigns to the user shard:
//!
//!   * **posts** — a windowed feed of the owner's recent posts;
//!   * **profile** — a single last-write-wins register (display name, handle,
//!     bio, avatar);
//!   * **follows** — the set of pubkeys the owner follows.
//!
//! ## Write authority
//!
//! Posts are self-signed and content-addressed, so a post proves owner-authorship
//! directly (`common::post::Post::verify` + `author_pubkey == owner`). Profile and
//! follow mutations are not posts, so they arrive as `common::signed_op::SignedOp`
//! envelopes: an ML-DSA-65 signature by the owner over a domain-tagged payload.
//! Both gates reduce to the same VK-param match — only the owner's key is accepted.
//!
//! ## Delta format
//!
//! Updates are a `ShardDelta` (an externally-tagged enum), so a single contract
//! can host more than one surface in one delta stream. `update_state` iterates
//! **every** `UpdateData` item (not just the first) and dispatches per variant.
//! Full-state (`UpdateData::State`) merges deserialize a whole `UserShard` and
//! fold each surface, so a peer syncing its latest state reconciles all three
//! surfaces — not only posts.
//!
//! ## Convergence
//!
//! * **posts** — grow-set deduped by content-address id, then truncated to the
//!   newest `MAX_POSTS` by `(timestamp, id)` desc (a total order; no clock in a
//!   contract). Order-independent.
//! * **profile** — last-write-wins by a monotonic `seq` (tie-break by serialized
//!   bytes for determinism). Order-independent.
//! * **follows** — each followed key records the `seq` of the op that last
//!   touched it and whether that op was Follow; merge keeps the higher seq per
//!   key, and an Unfollow wins on equal seq. This per-key rule is a join
//!   semilattice, so it is convergent under reordering, unlike a bare add/remove
//!   set. The `MAX_FOLLOWS` cap is enforced post-merge by `truncate_follows` as
//!   a function of the key set (tombstones evicted first, then largest key) —
//!   never by arrival order, which would diverge. Over-cap eviction is
//!   best-effort lossy, the same trade-off as the post window.

use freenet_microblogging_common::post::Post;
use freenet_microblogging_common::signed_op::{
    MAX_FOLLOW_TARGETS_PER_OP, MAX_TARGET_KEY_LEN, OpType, Profile, SignedOp, USER_SHARD_CONTEXT,
    decode_id_list, id_list_count_within_bounds,
};
use freenet_stdlib::prelude::{
    blake3::{Hasher as Blake3, traits::digest::Digest},
    *,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Recent-post retention window. ADR-0001 starting policy: ~200.
const MAX_POSTS: usize = 200;

/// Cap on retained retraction ops. Retractions are a pure grow-set: there is no
/// sound way to GC one, because dropping it lets a replica that still holds the
/// post re-introduce it on the next merge — the tombstone IS the memory. When
/// the cap is hit the LOWEST op seqs are evicted (oldest retractions first),
/// deterministically, so every replica evicts the same set.
const MAX_RETRACT_OPS: usize = 1_000;

/// Cap on the number of distinct followed keys retained. Like the profile field
/// bounds, this caps an owner's self-bloat (the only blast radius for an
/// owner-writes surface). Enforced post-merge in `validate_state` (transient
/// over-bound during merge is tolerated, mirroring the post window).
const MAX_FOLLOWS: usize = 5_000;

/// Per-key follow record: the `seq` of the op that last touched this key and
/// whether that op was a Follow (`true`) or an Unfollow (`false`). Merge keeps
/// the entry with the higher `seq`, so concurrent follow/unfollow of the same
/// key converges deterministically regardless of arrival order.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct FollowState {
    seq: u64,
    following: bool,
}

#[derive(Serialize, Deserialize, Default)]
struct UserShard {
    // Schema-tolerance: defaults so older/newer wire shapes still decode.
    // See AGENTS.md → "Contract migration".
    #[serde(default)]
    posts: Vec<Post>,
    /// Latest profile register, with the `seq` that set it (for LWW merge).
    /// `None` until the owner first sets a profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<ProfileRegister>,
    /// Followed pubkeys keyed by target VK hex (`BTreeMap` for deterministic
    /// serialization order).
    #[serde(default)]
    follows: BTreeMap<String, FollowState>,
    /// Owner-signed `RetractPost` ops keyed by op `seq`. The union of the ids
    /// they name is the retraction tombstone set.
    ///
    /// The signed OP is retained, never a bare id list, for the same reason the
    /// inbox retains its prune ops: state arrives from the network and
    /// `validate_state` has to re-prove it. A bare list would let any peer ship
    /// a state naming every one of the owner's posts as retracted and erase
    /// them. Keeping the op means a retraction is only ever as good as the owner's
    /// signature over it.
    ///
    /// Keyed by CONTENT ADDRESS ([`SignedOp::content_id`]), never by `seq`.
    /// `seq` is client-chosen (`Date.now()`), and some browsers clamp timer
    /// resolution, so an owner retracting two different posts in quick
    /// succession can sign two ops sharing one `seq`. Keyed by `seq`, the
    /// second silently displaces the first, and the post the first one named
    /// comes BACK on the next merge with a replica that still holds it — the
    /// tombstone is the memory, so losing it un-retracts the post.
    #[serde(default)]
    retract_ops: BTreeMap<String, SignedOp>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct ProfileRegister {
    profile: Profile,
    seq: u64,
}

impl<'a> TryFrom<State<'a>> for UserShard {
    type Error = ContractError;

    fn try_from(value: State<'a>) -> Result<Self, Self::Error> {
        serde_json::from_slice(value.as_ref()).map_err(|_| ContractError::InvalidState)
    }
}

/// A single delta operation. Externally tagged so the wire form is unambiguous
/// and new surfaces can be added without colliding with the post array.
#[derive(Serialize, Deserialize)]
enum ShardDelta {
    /// One or more of the owner's posts (each self-signed + content-addressed).
    Posts(Vec<Post>),
    /// An owner-signed profile / follow / unfollow op.
    Op(SignedOp),
}

/// The owner VK for this shard as hex, to compare against a post's
/// `author_pubkey` / a `SignedOp`'s `signer_pubkey`. Parameters are the raw
/// encoded ML-DSA-65 VK bytes; empty parameters yield an empty owner key that no
/// real signed record can match (an un-parameterized shard accepts nothing).
fn owner_vk_hex(parameters: &Parameters<'_>) -> String {
    hex::encode(parameters.as_ref())
}

/// Dedup/summary key for a post: blake3 over its content-addressed id.
fn post_hash(post: &Post) -> [u8; 32] {
    let mut hasher = Blake3::new();
    hasher.update(post.id.as_bytes());
    let hash_val = hasher.finalize();
    let mut key = [0; 32];
    key.copy_from_slice(&hash_val[..]);
    key
}

/// Whether a retraction op may be retained, for EVERY path that can store one.
///
/// One predicate on purpose. The three entry points — `apply_op`,
/// `merge_state`, and `validate_state` — previously each spelled the check out
/// by hand, and they drifted: only `apply_op` rejected an op whose id list
/// decodes to empty, so the same owner-signed vacuous op was dropped when it
/// arrived as a delta and stored when it arrived inside a full state. That is
/// the same order-dependent divergence the content-address key exists to
/// prevent, reintroduced one level up. The global index already routes every
/// path through a single gate; this matches it.
fn retract_op_is_acceptable(op: &SignedOp, owner_vk_hex: &str) -> bool {
    op.op_type == OpType::RetractPost
        && op.within_bounds()
        && id_list_count_within_bounds(&op.payload)
        && !decode_id_list(&op.payload).is_empty()
        && op.verify(USER_SHARD_CONTEXT, owner_vk_hex).is_ok()
}

/// A post is acceptable iff within the length bound, self-verifying, and authored
/// by this shard's owner (owner-writes — ADR-0001).
fn post_is_acceptable(post: &Post, owner_vk_hex: &str) -> bool {
    // `within_bounds` covers content AND the author name/handle. Those two are
    // author-chosen and ride inside the signature, so a signature alone does not
    // bound them — an owner could otherwise bloat their own shard without limit.
    post.within_bounds() && post.author_pubkey == owner_vk_hex && post.verify().is_ok()
}

/// Deterministic "newest-first" ordering for the retention window: timestamp
/// desc, then content-addressed id desc as a stable, total tie-break.
fn newest_first(a: &Post, b: &Post) -> std::cmp::Ordering {
    b.timestamp.cmp(&a.timestamp).then_with(|| b.id.cmp(&a.id))
}

/// Keep only the newest `MAX_POSTS` after a merge, then restore canonical merge
/// order (sorted by `post_hash`). Deterministic across replicas.
fn truncate_window(posts: &mut Vec<Post>) {
    if posts.len() > MAX_POSTS {
        posts.sort_by(newest_first);
        posts.truncate(MAX_POSTS);
    }
    posts.sort_by_cached_key(post_hash);
}

/// Whether a slice of posts is a valid stored set: every post acceptable AND no
/// two posts share a content-address id. (Uniqueness is what `update_state`
/// guarantees via dedup; `validate_state` enforces the same invariant so the two
/// halves of the contract agree on what a valid state is.)
fn posts_are_valid_state(posts: &[Post], owner: &str) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(posts.len());
    for post in posts {
        if !post_is_acceptable(post, owner) {
            return false;
        }
        if !seen.insert(post_hash(post)) {
            return false; // duplicate id
        }
    }
    true
}

/// Whether an incoming follow entry `(seq, following)` should replace the
/// current one for a key. Higher seq always wins. On EQUAL seq the states must
/// still converge regardless of arrival order, so a deterministic tie-break is
/// required: an Unfollow (`following == false`) beats a Follow. Without this,
/// concurrent Follow/Unfollow at the same seq diverges permanently (one replica
/// keeps `true`, the other `false`, and neither heals on gossip).
fn follow_replaces(new_seq: u64, new_following: bool, cur: &FollowState) -> bool {
    if new_seq != cur.seq {
        return new_seq > cur.seq;
    }
    // Equal seq: Unfollow (false) wins. Only a state actually changing matters,
    // so replace iff the incoming differs and is the tie-break winner.
    !new_following && cur.following
}

/// Apply an owner-signed op to the shard. Returns whether anything changed.
/// Rejected (non-owner / bad signature / out-of-bounds) ops are silently
/// skipped — a bad op in a batch is dropped, not fatal.
fn apply_op(shard: &mut UserShard, op: &SignedOp, owner: &str) -> bool {
    if op.verify(USER_SHARD_CONTEXT, owner).is_err() {
        return false;
    }
    match op.op_type {
        OpType::Profile => {
            let Ok(profile) = serde_json::from_slice::<Profile>(&op.payload) else {
                return false;
            };
            if !profile.within_bounds() {
                return false;
            }
            // Last-write-wins by seq; tie-break by serialized bytes so two
            // replicas applying different same-seq profiles still converge.
            let replace = match &shard.profile {
                None => true,
                Some(cur) => {
                    op.seq > cur.seq
                        || (op.seq == cur.seq
                            && serde_json::to_vec(&profile).unwrap_or_default()
                                > serde_json::to_vec(&cur.profile).unwrap_or_default())
                }
            };
            if replace {
                shard.profile = Some(ProfileRegister {
                    profile,
                    seq: op.seq,
                });
                return true;
            }
            false
        }
        OpType::Follow | OpType::Unfollow => {
            // Payload is a JSON array of target pubkey hex strings.
            let Ok(targets) = serde_json::from_slice::<Vec<String>>(&op.payload) else {
                return false;
            };
            // Reject an over-large batch outright (fail closed, don't truncate).
            if targets.len() > MAX_FOLLOW_TARGETS_PER_OP {
                return false;
            }
            let following = matches!(op.op_type, OpType::Follow);
            let mut changed = false;
            for target in targets {
                if target.len() > MAX_TARGET_KEY_LEN {
                    continue; // skip malformed/oversized key, don't fail the batch
                }
                // Insert freely; the cap is enforced deterministically post-merge
                // in `truncate_follows` (a function of the key set, not arrival
                // order — see MAJOR-1 in review). Per-key convergence below the
                // cap is exact via `follow_replaces`.
                let apply = match shard.follows.get(&target) {
                    None => true,
                    Some(cur) => follow_replaces(op.seq, following, cur),
                };
                if apply {
                    shard.follows.insert(
                        target,
                        FollowState {
                            seq: op.seq,
                            following,
                        },
                    );
                    changed = true;
                }
            }
            changed
        }
        OpType::RetractPost => {
            // Union by op seq; an identical op dedupes. A peer cannot fabricate
            // one (it would not verify against the owner), so this is a grow-set
            // of genuine owner-signed retractions.
            // `op` is already verified against the owner by the caller, but
            // go through the shared predicate anyway so this path cannot drift
            // from the other two.
            if !retract_op_is_acceptable(op, &op.signer_pubkey.clone()) {
                return false;
            }
            // `or_insert` on a content-address key, matching the merge path
            // exactly. Two distinct ops can no longer collide, and an identical
            // op is idempotent, so both paths converge on the same set — the
            // asymmetry between `insert` here and `or_insert` in `merge_state`
            // was itself order-dependence.
            shard
                .retract_ops
                .entry(op.content_id(USER_SHARD_CONTEXT))
                .or_insert_with(|| op.clone());
            // Apply immediately so the post disappears on this write, not only
            // after the next merge.
            apply_retractions(shard);
            true
        }
        // Inbox-shard prune ops are not valid user-shard mutations. They are
        // bound to INBOX_SHARD_CONTEXT (so they would not even verify here under
        // USER_SHARD_CONTEXT), but reject them explicitly so the match stays
        // exhaustive and an inbox op can never mutate user-shard state.
        OpType::PruneIds | OpType::PruneBefore => false,
    }
}

/// Merge another whole `UserShard` (from a full-state update) into `shard`,
/// honoring each surface's convergence rule.
fn merge_state(shard: &mut UserShard, other: UserShard, owner: &str) {
    for post in other.posts {
        if post_is_acceptable(&post, owner) {
            shard.posts.push(post);
        }
    }
    // Profile: LWW by seq, same rule as apply_op (bytes tie-break).
    if let Some(other_p) = other.profile {
        let replace = match &shard.profile {
            None => true,
            Some(cur) => {
                other_p.seq > cur.seq
                    || (other_p.seq == cur.seq
                        && serde_json::to_vec(&other_p.profile).unwrap_or_default()
                            > serde_json::to_vec(&cur.profile).unwrap_or_default())
            }
        };
        if replace {
            shard.profile = Some(other_p);
        }
    }
    // Follows: higher seq wins per key, with the same equal-seq tie-break as
    // apply_op so a delta-applied state and a full-state merge converge. The cap
    // is applied deterministically post-merge in `truncate_follows`, not here.
    // Retractions union by content address. Each is owner-signed, so a peer
    // cannot inject one; merging them BEFORE the post window is normalized
    // means a post that arrives in the same merge as its own retraction never
    // survives it.
    //
    // The `op_type` check is not redundant with the signature. A peer sees the
    // owner's OTHER signed ops (a Profile, a Follow) on this very shard, and
    // nothing stops it filing one of them into `retract_ops` in a full-state
    // merge — it verifies, because it genuinely is owner-signed. Accepting it
    // would build a state that this contract's own `validate_state` rejects,
    // which is the one disagreement a contract must never produce.
    //
    // The key is re-derived rather than taken from `other`, for the same
    // reason: a peer could otherwise file a valid op under a key that is not
    // its content address, and `validate_state` would reject that too.
    for (_, op) in other.retract_ops {
        if retract_op_is_acceptable(&op, owner) {
            let key = op.content_id(USER_SHARD_CONTEXT);
            shard.retract_ops.entry(key).or_insert(op);
        }
    }
    for (target, other_fs) in other.follows {
        if target.len() > MAX_TARGET_KEY_LEN {
            continue;
        }
        let keep = match shard.follows.get(&target) {
            None => true,
            Some(cur) => follow_replaces(other_fs.seq, other_fs.following, cur),
        };
        if keep {
            shard.follows.insert(target, other_fs);
        }
    }
}

/// The set of post ids named by every retained retraction op.
fn retracted_ids(shard: &UserShard) -> std::collections::BTreeSet<String> {
    let mut ids = std::collections::BTreeSet::new();
    for op in shard.retract_ops.values() {
        for id in decode_id_list(&op.payload) {
            ids.insert(id);
        }
    }
    ids
}

/// Drop every post named by a retraction.
///
/// On this shard the check is simple because the surface is owner-writes: the
/// op verified against the owner, and a post only got in if its `author_pubkey`
/// is the owner, so signer and author necessarily agree. The conditional-author
/// rule that matters on public-write surfaces (global index) is enforced there.
fn apply_retractions(shard: &mut UserShard) {
    if shard.retract_ops.is_empty() {
        return;
    }
    let ids = retracted_ids(shard);
    shard.posts.retain(|p| !ids.contains(&p.id));
}

/// Bound the retained retraction ops. Pure grow-set — dropping a tombstone lets
/// a replica that still holds the post re-introduce it on the next merge, so
/// there is no sound GC, only this backstop. Evict the LOWEST seqs (oldest
/// retractions) first, breaking same-seq ties on the content address. Keys are
/// content addresses, so map order is hash order rather than seq order — hence
/// the explicit sort on `(seq, key)`. What convergence actually needs is only
/// that the order be TOTAL and agreed on by every replica holding the same set;
/// oldest-first is the intent layered on top of that, and it is exact except
/// between ops that share a `seq`, where the tie-break is arbitrary but
/// identical everywhere.
fn gc_retract_ops(shard: &mut UserShard) {
    if shard.retract_ops.len() <= MAX_RETRACT_OPS {
        return;
    }
    let excess = shard.retract_ops.len() - MAX_RETRACT_OPS;
    let mut by_age: Vec<(u64, String)> = shard
        .retract_ops
        .iter()
        .map(|(k, op)| (op.seq, k.clone()))
        .collect();
    by_age.sort();
    for (_, key) in by_age.into_iter().take(excess) {
        shard.retract_ops.remove(&key);
    }
}

/// Enforce `MAX_FOLLOWS` deterministically as a function of the key SET (never
/// arrival order — that was review MAJOR-1: arrival-order admission diverges
/// permanently across replicas at the cap). When over the cap, drop entries by
/// (tombstones first, then largest key) until at the cap. Dropping tombstoned
/// (unfollowed) entries first also bounds tombstone accumulation (review NIT).
fn truncate_follows(follows: &mut BTreeMap<String, FollowState>) {
    if follows.len() <= MAX_FOLLOWS {
        return;
    }
    // Eviction order: a tombstone (following == false) is dropped before any
    // active follow; within the same class, the lexicographically larger key is
    // dropped first. This is a total order over the keys, so every replica with
    // the same map evicts the identical set.
    let mut keys: Vec<(bool, String)> = follows
        .iter()
        .map(|(k, v)| (v.following, k.clone()))
        .collect();
    // Sort so the entries we KEEP come first: active before tombstone, then key
    // ascending. (active=true should sort before false → reverse the bool.)
    keys.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (_, key) in keys.into_iter().skip(MAX_FOLLOWS) {
        follows.remove(&key);
    }
}

/// Restore canonical order + enforce both bounded surfaces after any merge.
/// Like the post window, follow eviction over the cap is best-effort lossy
/// (same trade-off as recent-N posts): deterministic given an identical merged
/// map, but an over-cap shard does not retain everything across partial syncs.
fn normalize(shard: &mut UserShard) {
    shard.posts.sort_by_cached_key(post_hash);
    shard.posts.dedup_by_key(|p| post_hash(p));
    // Retractions apply BEFORE the window truncates, so a retracted post cannot
    // occupy a slot that a live post should have had.
    apply_retractions(shard);
    truncate_window(&mut shard.posts);
    truncate_follows(&mut shard.follows);
    gc_retract_ops(shard);
}

// ---------------------------------------------------------------------------
// Summary: one fixed-width entry per surface so every surface reconciles via
// the delta path. Post entries are per-post content hashes; profile + follows
// fold to a single hash each (their full reconciliation rides the state path,
// but the summary must still *differ* when they differ so a delta is requested).
// ---------------------------------------------------------------------------
#[derive(Serialize, Deserialize)]
struct ShardSummary {
    posts: Vec<MessageSummary>,
    /// blake3 over the serialized profile register (zeroed if none).
    profile: [u8; 32],
    /// blake3 over the serialized follows map.
    follows: [u8; 32],
    /// blake3 over the serialized retraction ops. Without this a peer holding a
    /// retraction we lack would summarize identically and never send it, so a
    /// retracted post would linger on replicas that missed the op.
    retractions: [u8; 32],
}

fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3::new();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_ref());
    out
}

impl ShardSummary {
    fn of(shard: &UserShard) -> Self {
        let posts = shard
            .posts
            .iter()
            .map(|p| MessageSummary(post_hash(p)))
            .collect();
        let profile = match &shard.profile {
            Some(p) => hash_bytes(&serde_json::to_vec(p).unwrap_or_default()),
            None => [0u8; 32],
        };
        let follows = hash_bytes(&serde_json::to_vec(&shard.follows).unwrap_or_default());
        let retractions = hash_bytes(&serde_json::to_vec(&shard.retract_ops).unwrap_or_default());
        ShardSummary {
            posts,
            profile,
            follows,
            retractions,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct MessageSummary([u8; 32]);

#[contract]
impl ContractInterface for UserShard {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts,
    ) -> Result<ValidateResult, ContractError> {
        let owner = owner_vk_hex(&parameters);
        let shard = UserShard::try_from(state)?;
        // Posts: every post acceptable AND ids unique (the invariant update_state
        // guarantees). The retention *window* is deliberately NOT enforced here —
        // a transiently over-bound merged state is normal and rejecting it would
        // break convergence.
        if !posts_are_valid_state(&shard.posts, &owner) {
            return Ok(ValidateResult::Invalid);
        }
        // Profile: if present, must be within field bounds.
        if let Some(reg) = &shard.profile {
            if !reg.profile.within_bounds() {
                return Ok(ValidateResult::Invalid);
            }
        }
        // Follows: cap the map size (owner self-bloat ceiling) and reject any
        // malformed/oversized target key. The count of *actively followed* keys
        // is what the cap bounds; tombstoned (unfollowed) entries are retained
        // for convergence but also counted, so the cap is on total entries.
        if shard.follows.len() > MAX_FOLLOWS {
            return Ok(ValidateResult::Invalid);
        }
        if shard.follows.keys().any(|k| k.len() > MAX_TARGET_KEY_LEN) {
            return Ok(ValidateResult::Invalid);
        }
        // Retractions: every retained op must be a genuine owner signature over
        // a RetractPost, and its `seq` must be the key it is filed under —
        // otherwise a peer could file an op under a seq that collides with a real
        // one and displace it. This is the check that makes a retraction
        // only ever as strong as the owner's key.
        for (key, op) in &shard.retract_ops {
            if !retract_op_is_acceptable(op, &owner) || *key != op.content_id(USER_SHARD_CONTEXT) {
                return Ok(ValidateResult::Invalid);
            }
        }
        if shard.retract_ops.len() > MAX_RETRACT_OPS {
            return Ok(ValidateResult::Invalid);
        }
        // No retracted post may survive in the state. Without this a peer could
        // ship a state that carries the owner's own retraction AND the post it
        // retracts, and the post would be treated as live.
        let retracted = retracted_ids(&shard);
        if shard.posts.iter().any(|p| retracted.contains(&p.id)) {
            return Ok(ValidateResult::Invalid);
        }
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        delta: Vec<UpdateData>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        if delta.is_empty() {
            return Ok(UpdateModification::valid(state));
        }
        let owner = owner_vk_hex(&parameters);
        let mut shard = UserShard::try_from(state)?;

        // Process EVERY update item (not just the first).
        for item in &delta {
            match item {
                UpdateData::Delta(d) => apply_delta_bytes(&mut shard, d.as_ref(), &owner)?,
                UpdateData::State(s) => {
                    let other = UserShard::try_from(State::from(s.to_vec()))?;
                    merge_state(&mut shard, other, &owner);
                }
                UpdateData::StateAndDelta { state, delta } => {
                    let other = UserShard::try_from(State::from(state.to_vec()))?;
                    merge_state(&mut shard, other, &owner);
                    apply_delta_bytes(&mut shard, delta.as_ref(), &owner)?;
                }
                _ => {}
            }
        }

        normalize(&mut shard);
        let shard_bytes =
            serde_json::to_vec(&shard).map_err(|err| ContractError::Other(format!("{err}")))?;
        Ok(UpdateModification::valid(State::from(shard_bytes)))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let _ = parameters;
        let shard = UserShard::try_from(state)?;
        let summary = ShardSummary::of(&shard);
        Ok(StateSummary::from(
            serde_json::to_vec(&summary).map_err(|err| ContractError::Other(format!("{err}")))?,
        ))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let _ = parameters;
        let shard = UserShard::try_from(state)?;
        let remote = serde_json::from_slice::<ShardSummary>(&summary).unwrap_or(ShardSummary {
            posts: vec![],
            profile: [0u8; 32],
            follows: [0u8; 32],
            retractions: [0u8; 32],
        });

        // Posts the remote lacks → emit as a Posts delta.
        let mut remote_posts: Vec<[u8; 32]> = remote.posts.iter().map(|m| m.0).collect();
        remote_posts.sort();
        let mut missing_posts = vec![];
        for post in &shard.posts {
            let hash = post_hash(post);
            if remote_posts.binary_search(&hash).is_err() {
                missing_posts.push(post.clone());
            }
        }

        // A `Posts` delta cannot convey the profile/follows registers. So if
        // either register differs, ship the full serialized shard as the delta
        // payload — `apply_delta_bytes` recognises a whole `UserShard` and
        // `merge_state`s it, reconciling every surface (posts ride along). When
        // only posts differ, the smaller `Posts` delta suffices.
        let local = ShardSummary::of(&shard);
        // Retractions ride the same full-state path as the registers: a
        // `Posts` delta has no slot for them, and shipping posts WITHOUT the
        // retractions that withdraw them would hand the remote a state where a
        // withdrawn post looks live.
        let registers_differ = local.profile != remote.profile
            || local.follows != remote.follows
            || local.retractions != remote.retractions;

        let payload = if registers_differ {
            serde_json::to_vec(&shard)
        } else {
            serde_json::to_vec(&ShardDelta::Posts(missing_posts))
        };
        Ok(StateDelta::from(
            payload.map_err(|err| ContractError::Other(format!("{err}")))?,
        ))
    }
}

/// Parse a `ShardDelta` from raw delta bytes and apply it to the shard.
fn apply_delta_bytes(
    shard: &mut UserShard,
    bytes: &[u8],
    owner: &str,
) -> Result<(), ContractError> {
    // A delta is a `ShardDelta`. For backward tolerance also accept a bare
    // `Vec<Post>` (the Phase-1 posts-only wire form) and a full `UserShard`
    // object (a state shipped as a delta — see get_state_delta register path).
    if let Ok(d) = serde_json::from_slice::<ShardDelta>(bytes) {
        match d {
            ShardDelta::Posts(posts) => {
                for post in posts {
                    if post_is_acceptable(&post, owner) {
                        shard.posts.push(post);
                    }
                }
            }
            ShardDelta::Op(op) => {
                apply_op(shard, &op, owner);
            }
        }
        return Ok(());
    }
    if let Ok(posts) = serde_json::from_slice::<Vec<Post>>(bytes) {
        for post in posts {
            if post_is_acceptable(&post, owner) {
                shard.posts.push(post);
            }
        }
        return Ok(());
    }
    if let Ok(other) = serde_json::from_slice::<UserShard>(bytes) {
        merge_state(shard, other, owner);
        return Ok(());
    }
    Err(ContractError::InvalidDelta)
}

#[cfg(test)]
mod test {
    use super::*;
    use freenet_microblogging_common::signed_op::Profile;
    use ml_dsa::signature::{Keypair, Signer};
    use ml_dsa::{KeyGen, MlDsa65};

    fn owner_params(seed: [u8; 32]) -> Vec<u8> {
        let sk = MlDsa65::from_seed(&seed.into());
        sk.verifying_key().encode().to_vec()
    }

    fn params_of(seed: [u8; 32]) -> Parameters<'static> {
        Parameters::from(owner_params(seed))
    }

    fn vk_hex(seed: [u8; 32]) -> String {
        let sk = MlDsa65::from_seed(&seed.into());
        hex::encode(sk.verifying_key().encode())
    }

    fn signed_post(seed: [u8; 32], content: &str, timestamp: u64) -> Post {
        let sk = MlDsa65::from_seed(&seed.into());
        let author_pubkey = hex::encode(sk.verifying_key().encode());
        let mut p = Post {
            id: String::new(),
            author_pubkey,
            author_name: "Test User".to_string(),
            author_handle: "@testuser".to_string(),
            content: content.to_string(),
            timestamp,
            reply_to: String::new(),
            quoted_post: String::new(),
            signature: None,
        };
        p.id = p.compute_id();
        let sig: ml_dsa::Signature<MlDsa65> = sk.sign(&p.signing_payload());
        p.signature = Some(hex::encode(sig.encode()));
        p
    }

    fn signed_op(seed: [u8; 32], op_type: OpType, payload: Vec<u8>, seq: u64) -> SignedOp {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut op = SignedOp {
            op_type,
            payload,
            seq,
            signer_pubkey: hex::encode(sk.verifying_key().encode()),
            signature: None,
        };
        let sig: ml_dsa::Signature<MlDsa65> = sk.sign(&op.signing_payload(USER_SHARD_CONTEXT));
        op.signature = Some(hex::encode(sig.encode()));
        op
    }

    fn profile_op(seed: [u8; 32], p: &Profile, seq: u64) -> SignedOp {
        signed_op(seed, OpType::Profile, serde_json::to_vec(p).unwrap(), seq)
    }

    fn follow_op(seed: [u8; 32], targets: &[&str], follow: bool, seq: u64) -> SignedOp {
        let targets: Vec<String> = targets.iter().map(|s| s.to_string()).collect();
        signed_op(
            seed,
            if follow {
                OpType::Follow
            } else {
                OpType::Unfollow
            },
            serde_json::to_vec(&targets).unwrap(),
            seq,
        )
    }

    fn apply(owner: [u8; 32], state: Vec<u8>, items: Vec<ShardDelta>) -> Vec<u8> {
        let deltas: Vec<UpdateData> = items
            .into_iter()
            .map(|d| UpdateData::Delta(StateDelta::from(serde_json::to_vec(&d).unwrap())))
            .collect();
        UserShard::update_state(params_of(owner), State::from(state), deltas)
            .unwrap()
            .unwrap_valid()
            .into_bytes()
    }

    fn empty_state() -> Vec<u8> {
        b"{}".to_vec()
    }

    fn sample_profile() -> Profile {
        Profile {
            display_name: "Alice".into(),
            handle: "@alice".into(),
            bio: "hi".into(),
            avatar: "blue".into(),
        }
    }

    #[test]
    fn posts_merge_dedup_and_owner_only() {
        let owner = [1u8; 32];
        let other = [2u8; 32];
        let p = signed_post(owner, "first", 1);
        let bytes = apply(
            owner,
            empty_state(),
            vec![ShardDelta::Posts(vec![
                p.clone(),
                p.clone(), // intra-batch duplicate
                signed_post(other, "foreign", 2),
            ])],
        );
        let shard: UserShard = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(shard.posts.len(), 1);
    }

    #[test]
    fn oversized_author_name_rejected_even_from_owner() {
        // author_name/author_handle are author-chosen and self-verifying, so a
        // signature alone does not bound them — only `within_bounds()` does.
        // Owner-writes doesn't help: the owner can still sign an oversized name.
        let owner = [1u8; 32];
        let mut p = signed_post(owner, "hi", 1);
        p.author_name = "x".repeat(freenet_microblogging_common::post::MAX_AUTHOR_NAME_LEN + 1);
        p.id = p.compute_id();
        let sk = MlDsa65::from_seed(&owner.into());
        let sig: ml_dsa::Signature<MlDsa65> = sk.sign(&p.signing_payload());
        p.signature = Some(hex::encode(sig.encode()));
        assert_eq!(p.verify(), Ok(()));

        let bytes = apply(owner, empty_state(), vec![ShardDelta::Posts(vec![p])]);
        let shard: UserShard = serde_json::from_slice(&bytes).unwrap();
        assert!(shard.posts.is_empty());
    }

    #[test]
    fn profile_lww_by_seq() {
        let owner = [1u8; 32];
        let mut p1 = sample_profile();
        p1.display_name = "v1".into();
        let mut p2 = sample_profile();
        p2.display_name = "v2".into();

        // Apply seq=2 then seq=1; higher seq must win regardless of order.
        let bytes = apply(
            owner,
            empty_state(),
            vec![
                ShardDelta::Op(profile_op(owner, &p2, 2)),
                ShardDelta::Op(profile_op(owner, &p1, 1)),
            ],
        );
        let shard: UserShard = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(shard.profile.unwrap().profile.display_name, "v2");
    }

    #[test]
    fn profile_rejects_oversized_and_foreign() {
        let owner = [1u8; 32];
        let other = [2u8; 32];

        // Oversized bio rejected.
        let mut big = sample_profile();
        big.bio = "x".repeat(10_000);
        let bytes = apply(
            owner,
            empty_state(),
            vec![ShardDelta::Op(profile_op(owner, &big, 1))],
        );
        let shard: UserShard = serde_json::from_slice(&bytes).unwrap();
        assert!(shard.profile.is_none());

        // Foreign signer rejected (signed by `other`, shard owned by `owner`).
        let bytes2 = apply(
            owner,
            empty_state(),
            vec![ShardDelta::Op(profile_op(other, &sample_profile(), 1))],
        );
        let shard2: UserShard = serde_json::from_slice(&bytes2).unwrap();
        assert!(shard2.profile.is_none());
    }

    #[test]
    fn follows_add_remove_converge() {
        let owner = [1u8; 32];
        let a = vk_hex([10u8; 32]);
        let b = vk_hex([11u8; 32]);

        // Follow a,b (seq1); unfollow a (seq2). a gone, b present.
        let bytes = apply(
            owner,
            empty_state(),
            vec![
                ShardDelta::Op(follow_op(owner, &[&a, &b], true, 1)),
                ShardDelta::Op(follow_op(owner, &[&a], false, 2)),
            ],
        );
        let shard: UserShard = serde_json::from_slice(&bytes).unwrap();
        assert!(!shard.follows.get(&a).unwrap().following);
        assert!(shard.follows.get(&b).unwrap().following);

        // Reorder: apply unfollow-a(seq2) BEFORE follow-a,b(seq1). Same result —
        // higher seq wins per key.
        let bytes2 = apply(
            owner,
            empty_state(),
            vec![
                ShardDelta::Op(follow_op(owner, &[&a], false, 2)),
                ShardDelta::Op(follow_op(owner, &[&a, &b], true, 1)),
            ],
        );
        let shard2: UserShard = serde_json::from_slice(&bytes2).unwrap();
        assert!(!shard2.follows.get(&a).unwrap().following);
        assert!(shard2.follows.get(&b).unwrap().following);
    }

    #[test]
    fn follows_equal_seq_converges() {
        // Regression for review C-1: Follow(k) and Unfollow(k) at the SAME seq
        // must converge regardless of order (was a permanent split-brain — one
        // replica kept following=true, the other false, neither healed). The
        // deterministic tie-break is "Unfollow wins on equal seq".
        let owner = [1u8; 32];
        let k = vk_hex([10u8; 32]);

        // Follow(seq=5) then Unfollow(seq=5).
        let s1: UserShard = serde_json::from_slice(&apply(
            owner,
            empty_state(),
            vec![
                ShardDelta::Op(follow_op(owner, &[&k], true, 5)),
                ShardDelta::Op(follow_op(owner, &[&k], false, 5)),
            ],
        ))
        .unwrap();

        // Unfollow(seq=5) then Follow(seq=5) — reverse order.
        let s2: UserShard = serde_json::from_slice(&apply(
            owner,
            empty_state(),
            vec![
                ShardDelta::Op(follow_op(owner, &[&k], false, 5)),
                ShardDelta::Op(follow_op(owner, &[&k], true, 5)),
            ],
        ))
        .unwrap();

        // Both converge to the same result (Unfollow wins on tie).
        assert_eq!(s1.follows.get(&k), s2.follows.get(&k));
        assert!(!s1.follows.get(&k).unwrap().following);

        // And a full-state merge of one into the other also converges.
        let s1_bytes = serde_json::to_vec(&s1).unwrap();
        let merged = UserShard::update_state(
            params_of(owner),
            State::from(serde_json::to_vec(&s2).unwrap()),
            vec![UpdateData::State(State::from(s1_bytes))],
        )
        .unwrap()
        .unwrap_valid();
        let sm: UserShard = serde_json::from_slice(merged.as_ref()).unwrap();
        assert!(!sm.follows.get(&k).unwrap().following);
    }

    #[test]
    fn follows_rejects_oversized_op_and_caps_map() {
        let owner = [1u8; 32];
        // An op carrying more than MAX_FOLLOW_TARGETS_PER_OP targets is dropped.
        let many: Vec<String> = (0..MAX_FOLLOW_TARGETS_PER_OP + 1)
            .map(|i| format!("{i:0>8}"))
            .collect();
        let refs: Vec<&str> = many.iter().map(|s| s.as_str()).collect();
        let bytes = apply(
            owner,
            empty_state(),
            vec![ShardDelta::Op(follow_op(owner, &refs, true, 1))],
        );
        let shard: UserShard = serde_json::from_slice(&bytes).unwrap();
        assert!(shard.follows.is_empty());

        // validate_state rejects a state whose follows map exceeds MAX_FOLLOWS.
        let mut over = UserShard::default();
        for i in 0..=MAX_FOLLOWS {
            over.follows.insert(
                format!("{i:0>8}"),
                FollowState {
                    seq: 1,
                    following: true,
                },
            );
        }
        assert!(matches!(
            UserShard::validate_state(
                params_of(owner),
                State::from(serde_json::to_vec(&over).unwrap()),
                RelatedContracts::new(),
            )
            .unwrap(),
            ValidateResult::Invalid
        ));
    }

    #[test]
    fn follows_cap_eviction_is_order_independent() {
        // Regression for review MAJOR-1: building an over-cap follow set in two
        // different op orders must yield the SAME retained key set (eviction is
        // a function of the key set, not arrival order). truncate_follows keeps
        // the lexicographically-smallest active keys.
        let keys: Vec<String> = (0..MAX_FOLLOWS + 200)
            .map(|i| format!("{i:0>10}"))
            .collect();
        assert!(keys.len() > MAX_FOLLOWS);

        let mut f1 = BTreeMap::new();
        for k in &keys {
            f1.insert(
                k.clone(),
                FollowState {
                    seq: 1,
                    following: true,
                },
            );
        }
        let mut f2 = BTreeMap::new();
        for k in keys.iter().rev() {
            f2.insert(
                k.clone(),
                FollowState {
                    seq: 1,
                    following: true,
                },
            );
        }
        truncate_follows(&mut f1);
        truncate_follows(&mut f2);
        assert_eq!(f1.len(), MAX_FOLLOWS);
        assert_eq!(f1.keys().collect::<Vec<_>>(), f2.keys().collect::<Vec<_>>());
        // Smallest keys retained: "0000000000" present, the largest absent.
        assert!(f1.contains_key(&keys[0]));
        assert!(!f1.contains_key(keys.last().unwrap()));
    }

    #[test]
    fn follows_cap_evicts_tombstones_first() {
        // Review NIT: tombstones (unfollowed) are dropped before active follows
        // when over the cap, so churn can't wedge the map full of tombstones.
        let mut f = BTreeMap::new();
        // MAX_FOLLOWS active + 10 tombstones = over cap by 10.
        for i in 0..MAX_FOLLOWS {
            f.insert(
                format!("a{i:0>10}"),
                FollowState {
                    seq: 1,
                    following: true,
                },
            );
        }
        for i in 0..10 {
            f.insert(
                format!("z{i:0>10}"),
                FollowState {
                    seq: 2,
                    following: false,
                },
            );
        }
        truncate_follows(&mut f);
        assert_eq!(f.len(), MAX_FOLLOWS);
        // All tombstones evicted; all actives retained.
        assert!(f.values().all(|v| v.following));
    }

    #[test]
    fn mixed_surfaces_in_one_update() {
        let owner = [1u8; 32];
        let a = vk_hex([10u8; 32]);
        let bytes = apply(
            owner,
            empty_state(),
            vec![
                ShardDelta::Posts(vec![signed_post(owner, "hello", 1)]),
                ShardDelta::Op(profile_op(owner, &sample_profile(), 1)),
                ShardDelta::Op(follow_op(owner, &[&a], true, 1)),
            ],
        );
        let shard: UserShard = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(shard.posts.len(), 1);
        assert_eq!(shard.profile.unwrap().profile.display_name, "Alice");
        assert!(shard.follows.get(&a).unwrap().following);
    }

    #[test]
    fn full_state_merge_reconciles_all_surfaces() {
        let owner = [1u8; 32];
        // Build a populated shard, serialize, feed it back as UpdateData::State
        // into an empty shard — all surfaces must transfer.
        let src = apply(
            owner,
            empty_state(),
            vec![
                ShardDelta::Posts(vec![signed_post(owner, "p", 1)]),
                ShardDelta::Op(profile_op(owner, &sample_profile(), 3)),
                ShardDelta::Op(follow_op(owner, &[&vk_hex([10u8; 32])], true, 1)),
            ],
        );
        let merged = UserShard::update_state(
            params_of(owner),
            State::from(empty_state()),
            vec![UpdateData::State(State::from(src))],
        )
        .unwrap()
        .unwrap_valid();
        let shard: UserShard = serde_json::from_slice(merged.as_ref()).unwrap();
        assert_eq!(shard.posts.len(), 1);
        assert_eq!(shard.profile.unwrap().seq, 3);
        assert_eq!(shard.follows.len(), 1);
    }

    #[test]
    fn state_and_delta_merges_both() {
        // The StateAndDelta update arm: a peer ships a full state AND a delta in
        // one item. update_state must merge_state the state THEN apply the delta,
        // so a record from each is present and post-merge invariants hold.
        let owner = [1u8; 32];
        let a = vk_hex([10u8; 32]);
        // Full state: a post + a profile (seq 1) the peer already holds.
        let src = apply(
            owner,
            empty_state(),
            vec![
                ShardDelta::Posts(vec![signed_post(owner, "from-state", 1)]),
                ShardDelta::Op(profile_op(owner, &sample_profile(), 1)),
            ],
        );
        // Delta: a follow op (a distinct second record on a distinct surface).
        let delta = serde_json::to_vec(&ShardDelta::Op(follow_op(owner, &[&a], true, 1))).unwrap();

        let res = UserShard::update_state(
            params_of(owner),
            State::from(empty_state()),
            vec![UpdateData::StateAndDelta {
                state: State::from(src),
                delta: StateDelta::from(delta),
            }],
        )
        .unwrap()
        .unwrap_valid();
        let shard: UserShard = serde_json::from_slice(res.as_ref()).unwrap();
        // State's post merged in.
        assert_eq!(shard.posts.len(), 1, "state post merged");
        assert_eq!(shard.posts[0].content, "from-state");
        // State's profile merged in.
        assert_eq!(shard.profile.unwrap().profile.display_name, "Alice");
        // Delta's follow merged in.
        assert!(
            shard.follows.get(&a).unwrap().following,
            "delta follow merged"
        );
        // Canonical post order invariant: stored sorted by post_hash.
        let mut sorted = shard.posts.clone();
        sorted.sort_by_cached_key(post_hash);
        assert_eq!(
            shard.posts.iter().map(post_hash).collect::<Vec<_>>(),
            sorted.iter().map(post_hash).collect::<Vec<_>>(),
            "posts remain in canonical merge order"
        );
    }

    #[test]
    fn validate_rejects_duplicate_ids() {
        let owner = [1u8; 32];
        let p = signed_post(owner, "dup", 1);
        let shard = UserShard {
            posts: vec![p.clone(), p],
            ..Default::default()
        };
        let res = UserShard::validate_state(
            params_of(owner),
            State::from(serde_json::to_vec(&shard).unwrap()),
            RelatedContracts::new(),
        )
        .unwrap();
        assert!(matches!(res, ValidateResult::Invalid));
    }

    #[test]
    fn validate_rejects_foreign_and_oversized_profile() {
        let owner = [1u8; 32];
        // Foreign-author post.
        let shard = UserShard {
            posts: vec![signed_post([2u8; 32], "x", 1)],
            ..Default::default()
        };
        assert!(matches!(
            UserShard::validate_state(
                params_of(owner),
                State::from(serde_json::to_vec(&shard).unwrap()),
                RelatedContracts::new(),
            )
            .unwrap(),
            ValidateResult::Invalid
        ));

        // Oversized profile register.
        let mut big = sample_profile();
        big.bio = "x".repeat(10_000);
        let shard2 = UserShard {
            profile: Some(ProfileRegister {
                profile: big,
                seq: 1,
            }),
            ..Default::default()
        };
        assert!(matches!(
            UserShard::validate_state(
                params_of(owner),
                State::from(serde_json::to_vec(&shard2).unwrap()),
                RelatedContracts::new(),
            )
            .unwrap(),
            ValidateResult::Invalid
        ));
    }

    #[test]
    fn validate_accepts_well_formed() {
        let owner = [1u8; 32];
        let bytes = apply(
            owner,
            empty_state(),
            vec![
                ShardDelta::Posts(vec![signed_post(owner, "ok", 1)]),
                ShardDelta::Op(profile_op(owner, &sample_profile(), 1)),
            ],
        );
        assert!(matches!(
            UserShard::validate_state(
                params_of(owner),
                State::from(bytes),
                RelatedContracts::new()
            )
            .unwrap(),
            ValidateResult::Valid
        ));
    }

    #[test]
    fn truncates_to_window() {
        let owner = [1u8; 32];
        let total = MAX_POSTS + 50;
        let mut all = Vec::with_capacity(total);
        for i in 0..total {
            all.push(signed_post(owner, &format!("post {i}"), i as u64));
        }
        let bytes = apply(owner, empty_state(), vec![ShardDelta::Posts(all)]);
        let shard: UserShard = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(shard.posts.len(), MAX_POSTS);
        let ts: Vec<u64> = shard.posts.iter().map(|p| p.timestamp).collect();
        assert!(ts.contains(&((total - 1) as u64)));
        assert!(!ts.contains(&0));
    }

    #[test]
    fn summary_changes_when_registers_change() {
        let owner = [1u8; 32];
        let base = apply(
            owner,
            empty_state(),
            vec![ShardDelta::Posts(vec![signed_post(owner, "p", 1)])],
        );
        let with_profile = apply(
            owner,
            base.clone(),
            vec![ShardDelta::Op(profile_op(owner, &sample_profile(), 1))],
        );
        let s1 = ShardSummary::of(&serde_json::from_slice::<UserShard>(&base).unwrap());
        let s2 = ShardSummary::of(&serde_json::from_slice::<UserShard>(&with_profile).unwrap());
        assert_ne!(s1.profile, s2.profile);
    }

    #[test]
    fn get_delta_ships_state_when_registers_differ() {
        let owner = [1u8; 32];
        // Local has a profile; remote summary has none → delta must carry the
        // full state so the profile reconciles. Feeding it back must restore it.
        let local = apply(
            owner,
            empty_state(),
            vec![ShardDelta::Op(profile_op(owner, &sample_profile(), 1))],
        );
        let remote_summary = ShardSummary {
            posts: vec![],
            profile: [0u8; 32],
            follows: [0u8; 32],
            retractions: [0u8; 32],
        };
        let delta = UserShard::get_state_delta(
            params_of(owner),
            State::from(local),
            StateSummary::from(serde_json::to_vec(&remote_summary).unwrap()),
        )
        .unwrap();
        // Apply the delta to an empty shard; profile must appear.
        let merged = UserShard::update_state(
            params_of(owner),
            State::from(empty_state()),
            vec![UpdateData::Delta(StateDelta::from(delta.to_vec()))],
        )
        .unwrap()
        .unwrap_valid();
        let shard: UserShard = serde_json::from_slice(merged.as_ref()).unwrap();
        assert!(shard.profile.is_some());
    }

    #[test]
    fn backward_compat_bare_post_array_delta() {
        // The Phase-1 posts-only wire form (a bare Vec<Post>) must still apply.
        let owner = [1u8; 32];
        let posts = vec![signed_post(owner, "legacy", 1)];
        let merged = UserShard::update_state(
            params_of(owner),
            State::from(empty_state()),
            vec![UpdateData::Delta(StateDelta::from(
                serde_json::to_vec(&posts).unwrap(),
            ))],
        )
        .unwrap()
        .unwrap_valid();
        let shard: UserShard = serde_json::from_slice(merged.as_ref()).unwrap();
        assert_eq!(shard.posts.len(), 1);
    }

    #[test]
    fn decodes_empty_and_old_shape() {
        let empty = UserShard::try_from(State::from(b"{}".as_ref())).unwrap();
        assert!(empty.posts.is_empty());
        assert!(empty.profile.is_none());
        assert!(empty.follows.is_empty());
    }
}

/// Integration tests: drive the full `ContractInterface` through multi-replica
/// reconciliation via the real sync protocol (`summarize_state` →
/// `get_state_delta` → `update_state`) across all three owner-writes surfaces
/// (posts, profile, follows). This is the layer above the per-function unit
/// tests; what is new is the summarize/delta sync path and the validate-after-
/// merge invariant, with real ML-DSA-65 owner keys.
///
/// Still a Rust-library drive of the contract, not compiled WASM in a node
/// (that e2e tier is separate — see the `freenet:linux-test` skill).
#[cfg(test)]
mod integration {
    use super::*;
    use freenet_microblogging_common::signed_op::Profile;
    use ml_dsa::signature::{Keypair, Signer};
    use ml_dsa::{KeyGen, MlDsa65};

    // The owner of the shard under test. Posts/ops the owner signs are accepted;
    // a different key is rejected (owner-writes). One owner per shard instance.
    const OWNER: [u8; 32] = [42u8; 32];

    fn params() -> Parameters<'static> {
        let sk = MlDsa65::from_seed(&OWNER.into());
        Parameters::from(sk.verifying_key().encode().to_vec())
    }

    fn signed_post(content: &str, ts: u64) -> Post {
        let sk = MlDsa65::from_seed(&OWNER.into());
        let mut p = Post {
            id: String::new(),
            author_pubkey: hex::encode(sk.verifying_key().encode()),
            author_name: "Owner".into(),
            author_handle: "@owner".into(),
            content: content.into(),
            timestamp: ts,
            reply_to: String::new(),
            quoted_post: String::new(),
            signature: None,
        };
        p.id = p.compute_id();
        let sig: ml_dsa::Signature<MlDsa65> = sk.sign(&p.signing_payload());
        p.signature = Some(hex::encode(sig.encode()));
        p
    }

    fn op(op_type: OpType, payload: Vec<u8>, seq: u64) -> SignedOp {
        let sk = MlDsa65::from_seed(&OWNER.into());
        let mut o = SignedOp {
            op_type,
            payload,
            seq,
            signer_pubkey: hex::encode(sk.verifying_key().encode()),
            signature: None,
        };
        let sig: ml_dsa::Signature<MlDsa65> = sk.sign(&o.signing_payload(USER_SHARD_CONTEXT));
        o.signature = Some(hex::encode(sig.encode()));
        o
    }

    fn profile_op(p: &Profile, seq: u64) -> SignedOp {
        op(OpType::Profile, serde_json::to_vec(p).unwrap(), seq)
    }

    fn follow_op(targets: &[&str], follow: bool, seq: u64) -> SignedOp {
        let targets: Vec<String> = targets.iter().map(|s| s.to_string()).collect();
        op(
            if follow {
                OpType::Follow
            } else {
                OpType::Unfollow
            },
            serde_json::to_vec(&targets).unwrap(),
            seq,
        )
    }

    fn state_of(shard: &UserShard) -> State<'static> {
        State::from(serde_json::to_vec(shard).unwrap())
    }

    fn decode(state: State<'static>) -> UserShard {
        serde_json::from_slice(state.as_ref()).unwrap()
    }

    fn apply(shard: &UserShard, items: Vec<ShardDelta>) -> UserShard {
        let deltas: Vec<UpdateData> = items
            .into_iter()
            .map(|d| UpdateData::Delta(StateDelta::from(serde_json::to_vec(&d).unwrap())))
            .collect();
        let res = UserShard::update_state(params(), state_of(shard), deltas).unwrap();
        decode(res.unwrap_valid())
    }

    fn validate(shard: &UserShard) -> bool {
        matches!(
            UserShard::validate_state(params(), state_of(shard), RelatedContracts::new()).unwrap(),
            ValidateResult::Valid
        )
    }

    /// One directional sync step, faithful to the node protocol: `dst` summarizes,
    /// `src` computes the delta of what `dst` lacks, `dst` applies it. Both states
    /// must stay valid.
    fn sync_into(dst: &UserShard, src: &UserShard) -> UserShard {
        assert!(validate(dst));
        let summary = UserShard::summarize_state(params(), state_of(dst)).unwrap();
        let d = UserShard::get_state_delta(params(), state_of(src), summary).unwrap();
        let res = UserShard::update_state(
            params(),
            state_of(dst),
            vec![UpdateData::Delta(StateDelta::from(d.into_bytes().to_vec()))],
        )
        .unwrap();
        let merged = decode(res.unwrap_valid());
        assert!(validate(&merged));
        merged
    }

    /// Bidirectional reconcile (one round each way). For these state sizes a
    /// single round each direction converges. Returns `(a', b')`, must be equal.
    fn reconcile(a: &UserShard, b: &UserShard) -> (UserShard, UserShard) {
        let a2 = sync_into(a, b);
        let b2 = sync_into(b, a);
        (a2, b2)
    }

    fn canonical(shard: &UserShard) -> Vec<u8> {
        serde_json::to_vec(shard).unwrap()
    }

    #[test]
    fn two_replicas_converge_all_surfaces_over_sync() {
        // A and B each see disjoint owner writes across posts, profile, and
        // follows, then reconcile via the sync protocol. They must converge.
        let empty = UserShard::default();
        let prof_a = Profile {
            display_name: "A".into(),
            handle: "@a".into(),
            bio: "".into(),
            avatar: "".into(),
        };
        let prof_b = Profile {
            display_name: "B".into(),
            handle: "@b".into(),
            bio: "bio".into(),
            avatar: "red".into(),
        };

        let a = apply(
            &empty,
            vec![
                ShardDelta::Posts(vec![signed_post("post-1", 100)]),
                ShardDelta::Op(profile_op(&prof_a, 1)),
                ShardDelta::Op(follow_op(&["aa", "bb"], true, 1)),
            ],
        );
        // B has a newer profile (seq 2 wins) and a different post + follow edit.
        let b = apply(
            &empty,
            vec![
                ShardDelta::Posts(vec![signed_post("post-2", 200)]),
                ShardDelta::Op(profile_op(&prof_b, 2)),
                ShardDelta::Op(follow_op(&["cc"], true, 1)),
            ],
        );

        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(canonical(&a2), canonical(&b2), "replicas must converge");
        assert_eq!(a2.posts.len(), 2, "both posts present");
        // Profile LWW: seq 2 (B's) wins on both.
        assert_eq!(a2.profile.as_ref().unwrap().seq, 2);
        assert_eq!(a2.profile.as_ref().unwrap().profile.display_name, "B");
        // Follows union of the followed keys.
        assert!(a2.follows.get("aa").map(|f| f.following).unwrap_or(false));
        assert!(a2.follows.get("cc").map(|f| f.following).unwrap_or(false));
    }

    #[test]
    fn concurrent_follow_unfollow_equal_seq_converges_over_sync() {
        // Same target, equal seq, follow on A and unfollow on B — the split-brain
        // case C-1 guards. Over the sync protocol both must settle on unfollow,
        // in either reconcile direction.
        let empty = UserShard::default();
        let a = apply(
            &empty,
            vec![ShardDelta::Op(follow_op(&["target"], true, 5))],
        );
        let b = apply(
            &empty,
            vec![ShardDelta::Op(follow_op(&["target"], false, 5))],
        );

        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(canonical(&a2), canonical(&b2));
        assert!(
            !a2.follows
                .get("target")
                .map(|f| f.following)
                .unwrap_or(false),
            "equal-seq unfollow wins after sync"
        );

        let (b3, a3) = reconcile(&b, &a);
        assert_eq!(canonical(&a3), canonical(&b3));
        assert!(
            !a3.follows
                .get("target")
                .map(|f| f.following)
                .unwrap_or(false)
        );
    }

    #[test]
    fn profile_lww_resolves_over_sync_regardless_of_replica() {
        // A holds seq 3, B holds seq 1 for the profile register. After sync both
        // hold seq 3 — the summary folds the profile so a register difference
        // triggers shipping the newer state.
        let empty = UserShard::default();
        let old = Profile {
            display_name: "Old".into(),
            handle: "@o".into(),
            bio: "".into(),
            avatar: "".into(),
        };
        let new = Profile {
            display_name: "New".into(),
            handle: "@n".into(),
            bio: "".into(),
            avatar: "".into(),
        };
        let a = apply(&empty, vec![ShardDelta::Op(profile_op(&new, 3))]);
        let b = apply(&empty, vec![ShardDelta::Op(profile_op(&old, 1))]);

        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(canonical(&a2), canonical(&b2));
        assert_eq!(a2.profile.as_ref().unwrap().seq, 3);
        assert_eq!(a2.profile.as_ref().unwrap().profile.display_name, "New");
    }

    #[test]
    fn non_owner_post_never_propagates_over_sync() {
        // A malicious replica holds a post signed by a NON-owner key in its state.
        // When an honest replica syncs from it, update_state re-checks owner
        // authorship and drops it — owner-writes holds across the sync path.
        let other = [7u8; 32];
        let osk = MlDsa65::from_seed(&other.into());
        let mut foreign = Post {
            id: String::new(),
            author_pubkey: hex::encode(osk.verifying_key().encode()),
            author_name: "Intruder".into(),
            author_handle: "@intruder".into(),
            content: "not the owner".into(),
            timestamp: 50,
            reply_to: String::new(),
            quoted_post: String::new(),
            signature: None,
        };
        foreign.id = foreign.compute_id();
        let sig: ml_dsa::Signature<MlDsa65> = osk.sign(&foreign.signing_payload());
        foreign.signature = Some(hex::encode(sig.encode()));
        // foreign self-verifies as a valid post, just not by the owner.
        assert_eq!(foreign.verify(), Ok(()));

        let mut malicious = UserShard::default();
        malicious.posts.push(foreign);

        let honest = UserShard::default();
        let synced = sync_into(&honest, &malicious);
        assert!(
            synced.posts.is_empty(),
            "non-owner post must not propagate to an honest replica"
        );
    }

    // -- retraction --
    //
    // A retraction is a withdrawal, not a delete: it stops this shard serving
    // the post and stops the post being re-accepted on merge. It cannot reach an
    // offline replica or an archive, and the op is named RetractPost so nobody
    // reads a guarantee into it that the network cannot give.

    fn retract_op(ids: &[&str], seq: u64) -> SignedOp {
        use freenet_microblogging_common::signed_op::encode_id_list;
        let owned: Vec<String> = ids.iter().map(|s| (*s).to_string()).collect();
        op(OpType::RetractPost, encode_id_list(&owned), seq)
    }

    /// A retraction signed by a key that is NOT the shard owner.
    fn foreign_retract_op(ids: &[&str], seq: u64) -> SignedOp {
        use freenet_microblogging_common::signed_op::encode_id_list;
        let sk = MlDsa65::from_seed(&[7u8; 32].into());
        let owned: Vec<String> = ids.iter().map(|s| (*s).to_string()).collect();
        let mut o = SignedOp {
            op_type: OpType::RetractPost,
            payload: encode_id_list(&owned),
            seq,
            signer_pubkey: hex::encode(sk.verifying_key().encode()),
            signature: None,
        };
        let sig: ml_dsa::Signature<MlDsa65> = sk.sign(&o.signing_payload(USER_SHARD_CONTEXT));
        o.signature = Some(hex::encode(sig.encode()));
        o
    }

    #[test]
    fn retracting_a_post_removes_it_and_keeps_the_proof() {
        let post = signed_post("regrettable", 1_000);
        let id = post.id.clone();
        let shard = apply(&UserShard::default(), vec![ShardDelta::Posts(vec![post])]);
        assert_eq!(shard.posts.len(), 1);

        let shard = apply(&shard, vec![ShardDelta::Op(retract_op(&[&id], 1))]);
        assert!(shard.posts.is_empty());
        // The signed op is retained: it is what makes the removal re-provable by
        // validate_state and unproduceable by a peer.
        assert_eq!(shard.retract_ops.len(), 1);
        assert!(validate(&shard));
    }

    #[test]
    fn a_retracted_post_cannot_be_resurrected_by_a_peer() {
        // The tombstone IS the memory. A replica that still holds the post will
        // offer it again; without the retained op it would be re-accepted.
        let post = signed_post("regrettable", 1_000);
        let id = post.id.clone();
        let shard = apply(
            &UserShard::default(),
            vec![
                ShardDelta::Posts(vec![post.clone()]),
                ShardDelta::Op(retract_op(&[&id], 1)),
            ],
        );
        let shard = apply(&shard, vec![ShardDelta::Posts(vec![post])]);
        assert!(shard.posts.is_empty(), "retracted post came back");
    }

    #[test]
    fn a_retraction_signed_by_another_key_does_nothing() {
        // Only the owner may withdraw the owner's posts.
        let post = signed_post("keep me", 1_000);
        let id = post.id.clone();
        let shard = apply(
            &UserShard::default(),
            vec![
                ShardDelta::Posts(vec![post]),
                ShardDelta::Op(foreign_retract_op(&[&id], 1)),
            ],
        );
        assert_eq!(shard.posts.len(), 1, "a foreign retraction withdrew a post");
        assert!(shard.retract_ops.is_empty());
    }

    #[test]
    fn validate_rejects_a_state_holding_a_post_it_also_retracts() {
        let post = signed_post("regrettable", 1_000);
        let id = post.id.clone();
        let mut shard = UserShard::default();
        shard.posts.push(post);
        let op = retract_op(&[&id], 1);
        shard
            .retract_ops
            .insert(op.content_id(USER_SHARD_CONTEXT), op);
        assert!(!validate(&shard), "live post survived its own retraction");
    }

    #[test]
    fn validate_rejects_a_retraction_filed_under_a_key_that_is_not_its_content_address() {
        // Filing a genuine op under some other key is how a peer would try to
        // collide with, and displace, another retraction. Keying by content
        // address is what makes that impossible, and this pins that the key is
        // actually CHECKED rather than merely computed on the write path.
        let mut shard = UserShard::default();
        shard.retract_ops.insert(
            "not-a-content-address".to_string(),
            retract_op(&["some-id"], 1),
        );
        assert!(!validate(&shard));
    }

    // -- retraction ops are keyed by CONTENT ADDRESS, not by `seq` --
    //
    // This shard is owner-writes, so the collision here is same-owner: `seq` is
    // `Date.now()` chosen per call with no persisted counter, and browsers that
    // clamp timer resolution (Tor Browser clamps to 100ms) make two retractions
    // seconds apart share one `seq` routinely. Keyed by `seq`, the second op
    // displaces the first and the post the FIRST one named comes back on the
    // next merge with a replica that still holds it — the tombstone IS the
    // memory, so losing it un-retracts the post.

    #[test]
    fn two_retractions_at_the_same_seq_both_keep_their_tombstones() {
        let p1 = signed_post("first regret", 1_000);
        let p2 = signed_post("second regret", 1_001);
        let (id1, id2) = (p1.id.clone(), p2.id.clone());

        let shard = apply(
            &UserShard::default(),
            vec![
                ShardDelta::Posts(vec![p1, p2]),
                // Same seq for both — the clamped-clock case.
                ShardDelta::Op(retract_op(&[&id1], 5)),
                ShardDelta::Op(retract_op(&[&id2], 5)),
            ],
        );

        assert_eq!(
            shard.retract_ops.len(),
            2,
            "the second retraction displaced the first one's tombstone"
        );
        assert!(shard.posts.is_empty(), "a retracted post survived");
    }

    #[test]
    fn a_post_retracted_at_a_colliding_seq_does_not_come_back_on_merge() {
        // The consequence that actually hurts. The local replica retracts two
        // posts at one seq; a peer never heard of either retraction and still
        // holds both posts. On merge, any tombstone that was displaced no
        // longer names its post, so the peer's copy is unioned back in and the
        // withdrawn post is live again.
        let p1 = signed_post("first regret", 1_000);
        let p2 = signed_post("second regret", 1_001);
        let (id1, id2) = (p1.id.clone(), p2.id.clone());

        let peer = apply(
            &UserShard::default(),
            vec![ShardDelta::Posts(vec![p1.clone(), p2.clone()])],
        );
        assert_eq!(peer.posts.len(), 2);

        let local = apply(
            &UserShard::default(),
            vec![
                ShardDelta::Posts(vec![p1, p2]),
                ShardDelta::Op(retract_op(&[&id1], 5)),
                ShardDelta::Op(retract_op(&[&id2], 5)),
            ],
        );
        assert!(local.posts.is_empty());

        let merged = sync_into(&local, &peer);
        assert!(
            merged.posts.is_empty(),
            "a withdrawn post was resurrected by a peer that still held it"
        );
    }

    #[test]
    fn colliding_seq_retractions_converge_regardless_of_arrival_order() {
        // Both orders must produce byte-identical state. Under `seq` keying the
        // direct-apply path used `insert` (last wins) while the merge path used
        // `or_insert` (first wins), so the two paths disagreed with each other
        // as well as with themselves.
        let a = retract_op(&["id-a"], 5);
        let b = retract_op(&["id-b"], 5);

        let ab = apply(
            &UserShard::default(),
            vec![ShardDelta::Op(a.clone()), ShardDelta::Op(b.clone())],
        );
        let ba = apply(
            &UserShard::default(),
            vec![ShardDelta::Op(b), ShardDelta::Op(a)],
        );

        assert_eq!(
            serde_json::to_vec(&ab).unwrap(),
            serde_json::to_vec(&ba).unwrap(),
            "arrival order changed the retained retraction set"
        );
    }

    #[test]
    fn a_non_retraction_op_cannot_be_filed_into_retract_ops_by_a_full_state_merge() {
        // A peer sees the owner's OTHER signed ops on this very shard — a
        // Profile, a Follow — and nothing about them says "not a retraction"
        // except `op_type`. Filing one into `retract_ops` and shipping the
        // whole state is free: it is genuinely owner-signed, so the signature
        // check passes, and it is filed under its own content address, so the
        // key check passes too.
        //
        // Accepting it would make `update_state` emit a state that this
        // contract's own `validate_state` calls Invalid — the one disagreement
        // a contract must never produce, because honest peers would then
        // reject a state an honest peer just built.
        let smuggled = profile_op(
            &Profile {
                display_name: "A".into(),
                handle: "@a".into(),
                bio: "".into(),
                avatar: "".into(),
            },
            1,
        );
        assert_eq!(smuggled.op_type, OpType::Profile);
        assert!(
            smuggled
                .verify(USER_SHARD_CONTEXT, &smuggled.signer_pubkey.clone())
                .is_ok(),
            "fixture must be genuinely owner-signed, or this proves nothing"
        );

        let mut malicious = UserShard::default();
        malicious
            .retract_ops
            .insert(smuggled.content_id(USER_SHARD_CONTEXT), smuggled);

        let res = UserShard::update_state(
            params(),
            state_of(&UserShard::default()),
            vec![UpdateData::State(State::from(
                serde_json::to_vec(&malicious).unwrap(),
            ))],
        )
        .unwrap();
        let merged = decode(res.unwrap_valid());

        assert!(
            merged.retract_ops.is_empty(),
            "a non-retraction op was smuggled into retract_ops"
        );
        assert!(
            validate(&merged),
            "update_state produced a state its own validate_state rejects"
        );
    }

    #[test]
    fn a_vacuous_retraction_is_refused_on_every_path_alike() {
        // An owner-signed RetractPost naming NO ids. `apply_op` always rejected
        // it; `merge_state` and `validate_state` did not, so the same op was
        // dropped when it arrived as a delta and stored when it arrived inside
        // a full state. Two replicas that received it by different routes then
        // hold different `retract_ops` — the same order-dependent divergence
        // the content-address key exists to prevent, one level up.
        let vacuous = op(OpType::RetractPost, Vec::new(), 5);
        assert!(
            vacuous
                .verify(USER_SHARD_CONTEXT, &vacuous.signer_pubkey.clone())
                .is_ok(),
            "fixture must be genuinely owner-signed, or this proves nothing"
        );
        assert!(decode_id_list(&vacuous.payload).is_empty());

        // Path 1: as a delta.
        let via_delta = apply(&UserShard::default(), vec![ShardDelta::Op(vacuous.clone())]);
        assert!(via_delta.retract_ops.is_empty(), "delta path stored it");

        // Path 2: inside a full state, which is where it used to get through.
        let mut smuggled = UserShard::default();
        smuggled
            .retract_ops
            .insert(vacuous.content_id(USER_SHARD_CONTEXT), vacuous);

        let res = UserShard::update_state(
            params(),
            state_of(&UserShard::default()),
            vec![UpdateData::State(State::from(
                serde_json::to_vec(&smuggled).unwrap(),
            ))],
        )
        .unwrap();
        let via_state = decode(res.unwrap_valid());

        assert!(via_state.retract_ops.is_empty(), "merge path stored it");
        assert_eq!(
            serde_json::to_vec(&via_delta).unwrap(),
            serde_json::to_vec(&via_state).unwrap(),
            "the two routes disagree about the same op"
        );
        // Path 3: and the state that DOES contain it must be refused outright.
        assert!(!validate(&smuggled), "validate_state accepted a vacuous op");
    }

    #[test]
    fn an_oversized_retraction_payload_is_rejected() {
        // `decode_id_list` caps what it INTERPRETS at MAX_IDS_PER_OP; it says
        // nothing about how many BYTES get stored. Owner-writes bounds the
        // blast radius to self-harm, but the bound belongs here too — the same
        // helper guards the anyone-writes global index. Same class as
        // GHSA-qxwp-8hqx-4wrj.
        use freenet_microblogging_common::signed_op::{MAX_OP_PAYLOAD_LEN, encode_id_list};

        let ids: Vec<String> = (0..40_000).map(|i| format!("id-{i:0>100}")).collect();
        let o = op(OpType::RetractPost, encode_id_list(&ids), 5);

        assert!(o.payload.len() > MAX_OP_PAYLOAD_LEN);
        // Cryptographically valid and decodes to a non-empty list: only the
        // explicit bound stops it.
        assert!(
            o.verify(USER_SHARD_CONTEXT, &o.signer_pubkey.clone())
                .is_ok()
        );
        assert!(!decode_id_list(&o.payload).is_empty());

        let shard = apply(&UserShard::default(), vec![ShardDelta::Op(o)]);
        assert!(
            shard.retract_ops.is_empty(),
            "an unbounded payload was stored in replicated state"
        );
    }

    // -- the merge laws, asserted directly --
    //
    // Same laws as the global index, on the owner-writes surface where the
    // collision is same-signer. See freenet-core#5320.

    #[test]
    fn retraction_merge_is_commutative_over_every_permutation() {
        // Three retractions of DIFFERENT posts all sharing one seq — what a
        // clamped `Date.now()` produces when an owner withdraws three posts in
        // one tick.
        let ops = vec![
            retract_op(&["id-a"], 5),
            retract_op(&["id-b"], 5),
            retract_op(&["id-c"], 5),
        ];

        fn permute(ops: &[SignedOp]) -> Vec<Vec<SignedOp>> {
            if ops.len() <= 1 {
                return vec![ops.to_vec()];
            }
            let mut out = Vec::new();
            for i in 0..ops.len() {
                let mut rest = ops.to_vec();
                let head = rest.remove(i);
                for mut tail in permute(&rest) {
                    let mut one = vec![head.clone()];
                    one.append(&mut tail);
                    out.push(one);
                }
            }
            out
        }

        let orders = permute(&ops);
        assert_eq!(orders.len(), 6);

        let mut canonical: Option<Vec<u8>> = None;
        for order in orders {
            let shard = apply(
                &UserShard::default(),
                order.into_iter().map(ShardDelta::Op).collect(),
            );
            assert_eq!(
                shard.retract_ops.len(),
                3,
                "a same-seq retraction displaced another"
            );
            let bytes = serde_json::to_vec(&shard).unwrap();
            match &canonical {
                None => canonical = Some(bytes),
                Some(first) => assert_eq!(
                    *first, bytes,
                    "a permutation of the same op set produced different state"
                ),
            }
        }
    }

    #[test]
    fn retraction_merge_is_idempotent() {
        let op = retract_op(&["id-a"], 5);

        let once = apply(&UserShard::default(), vec![ShardDelta::Op(op.clone())]);
        let twice = apply(
            &UserShard::default(),
            vec![ShardDelta::Op(op.clone()), ShardDelta::Op(op.clone())],
        );
        let c = serde_json::to_vec(&once).unwrap();
        // Re-applying onto the already-merged state is the shape a re-gossip
        // takes, and is the one the direct-apply path used to get wrong: it
        // called `insert` rather than `or_insert`.
        let again = apply(&once, vec![ShardDelta::Op(op)]);

        assert_eq!(c, serde_json::to_vec(&twice).unwrap(), "f(x,x) != f(x)");
        assert_eq!(
            c,
            serde_json::to_vec(&again).unwrap(),
            "re-gossip changed state"
        );
    }

    #[test]
    fn retraction_merge_is_associative() {
        // Distinct from commutativity: this varies how the ops are GROUPED
        // into deltas, which is what differs between a batched sync delta and
        // a stream of single-op deltas.
        let a = retract_op(&["id-a"], 5);
        let b = retract_op(&["id-b"], 5);
        let c = retract_op(&["id-c"], 5);

        let ab = apply(
            &UserShard::default(),
            vec![ShardDelta::Op(a.clone()), ShardDelta::Op(b.clone())],
        );
        let ab_c = apply(&ab, vec![ShardDelta::Op(c.clone())]);

        let bc = apply(
            &UserShard::default(),
            vec![ShardDelta::Op(b), ShardDelta::Op(c)],
        );
        let a_bc = apply(&bc, vec![ShardDelta::Op(a)]);

        assert_eq!(
            serde_json::to_vec(&ab_c).unwrap(),
            serde_json::to_vec(&a_bc).unwrap(),
            "grouping changed the result"
        );
    }

    #[test]
    fn an_overlong_id_list_is_refused_not_truncated() {
        // `decode_id_list` stops at MAX_IDS_PER_OP and returns what it parsed,
        // so a count check leaning on it would see a legal-looking 1000-id list
        // and store a PREFIX of what the owner actually signed.
        use freenet_microblogging_common::signed_op::{MAX_IDS_PER_OP, encode_id_list};

        let ids: Vec<String> = (0..MAX_IDS_PER_OP + 1).map(|i| format!("id-{i}")).collect();
        let o = op(OpType::RetractPost, encode_id_list(&ids), 5);

        // Legal under the BYTE bound, so only the count bound can refuse it.
        assert!(o.within_bounds(), "fixture must be under the byte ceiling");
        assert_eq!(
            decode_id_list(&o.payload).len(),
            MAX_IDS_PER_OP,
            "decode must be silently truncating, or this proves nothing"
        );

        let shard = apply(&UserShard::default(), vec![ShardDelta::Op(o)]);
        assert!(
            shard.retract_ops.is_empty(),
            "a truncated prefix of the signed list was stored"
        );
    }

    #[test]
    fn validate_rejects_a_retraction_signed_by_another_key() {
        let mut shard = UserShard::default();
        let op = foreign_retract_op(&["some-id"], 1);
        shard
            .retract_ops
            .insert(op.content_id(USER_SHARD_CONTEXT), op);
        assert!(!validate(&shard));
    }

    #[test]
    fn retractions_replicate_through_the_sync_path() {
        // If the summary ignored retractions a peer holding one we lack would
        // summarize identically and never send it, so the withdrawn post would
        // linger here forever.
        let post = signed_post("regrettable", 1_000);
        let id = post.id.clone();

        // A retracted; B still holds the post.
        let a = apply(
            &UserShard::default(),
            vec![
                ShardDelta::Posts(vec![post.clone()]),
                ShardDelta::Op(retract_op(&[&id], 1)),
            ],
        );
        let b = apply(&UserShard::default(), vec![ShardDelta::Posts(vec![post])]);
        assert_eq!(b.posts.len(), 1);

        let (a2, b2) = reconcile(&a, &b);
        assert!(a2.posts.is_empty());
        assert!(b2.posts.is_empty(), "peer kept a post the author withdrew");
        assert_eq!(a2.retract_ops.len(), 1);
        assert_eq!(b2.retract_ops.len(), 1);
    }

    #[test]
    fn retraction_is_order_independent() {
        // The retraction may arrive BEFORE the post it names — a pre-emptive
        // tombstone from the owner must still withdraw the post on arrival.
        let post = signed_post("regrettable", 1_000);
        let id = post.id.clone();
        let shard = apply(
            &UserShard::default(),
            vec![
                ShardDelta::Op(retract_op(&[&id], 1)),
                ShardDelta::Posts(vec![post]),
            ],
        );
        assert!(shard.posts.is_empty());
    }
}
