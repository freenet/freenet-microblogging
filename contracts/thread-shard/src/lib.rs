//! Thread shard contract (ADR-0001, Phase 2).
//!
//! One contract **per root post**, created lazily on the first reply, and
//! **anyone-writes**: it collects the replies, likes, and quote references that
//! target one root post. The contract is parameterized by the root post's
//! content-addressed id (`parameters = root_post_id` bytes), so the contract key
//! is `blake3(thread_shard_wasm || root_post_id)` — distinct per thread, and
//! distinct from a user shard with the same parameters because the WASM hash
//! differs (ADR-0001 → "Shard key derivation").
//!
//! ## Write authority (anyone-writes)
//!
//! Unlike the owner-writes user shard, a thread shard accepts writes from any
//! party. Each entry still **self-verifies** — a reply is a self-signed
//! [`Post`](freenet_microblogging_common::post::Post) whose `reply_to` equals
//! this thread's root; a like / quote is a signed
//! [`LikeRecord`] / [`QuoteRef`] bound to the root id. Verification proves *who*
//! signed, not that the signer is *allowed*. Constraining who may write is the
//! abuse question ADR-0001 leaves to a credential mechanism (GhostKey is the
//! candidate); the [`WriterCert`] wire slot is reserved and checked by the
//! [`verify_writer_cert`] seam, which accepts everything today.
//!
//! ## Convergence (every rule order-independent — AGENTS.md → "Contract
//! correctness invariants")
//!
//! * **replies** — grow-set deduped by content-address id, truncated post-merge
//!   to the newest `MAX_REPLIES` by `(timestamp, id)` desc (a total order; no
//!   clock in a contract).
//! * **likes** — per-liker join semilattice: keep the higher `seq` per liker,
//!   and on equal `seq` an **unlike wins** (deterministic tie-break, mirroring
//!   the user-shard follow rule). Capped post-merge by `truncate_likes`
//!   (tombstones first, then a total order over keys).
//! * **quotes** — grow-set deduped by `quote_post_id`, capped post-merge.
//! * **reposts** — per-reposter join semilattice identical to **likes**: keep
//!   the higher `seq` per reposter, un-repost wins an equal-`seq` tie. Capped
//!   post-merge by `truncate_reposts`.
//!
//! `validate_state` checks authority + self-verification + thread-binding + no
//! duplicates, but deliberately does **not** enforce the caps: a transiently
//! over-bound merged state is normal, and rejecting it would break convergence.

use freenet_microblogging_common::post::Post;
use freenet_microblogging_common::thread::{LikeRecord, QuoteRef, RepostRecord, WriterCert};
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Retention window for replies (ADR-0001 starting policy, matching the user
/// shard's post window).
const MAX_REPLIES: usize = 500;

/// Cap on distinct likers retained. Public-write, so this bounds flood blast
/// radius alongside the (future) writer-credential gate.
const MAX_LIKES: usize = 50_000;

/// Cap on distinct quote references retained.
const MAX_QUOTES: usize = 5_000;

/// Cap on distinct reposters retained. Public-write, so this bounds flood blast
/// radius alongside the (future) writer-credential gate. Mirrors `MAX_LIKES`.
const MAX_REPOSTS: usize = 50_000;

/// Thread shard state: replies, likes, and quote references for one root post.
///
/// Likes store the **full signed `LikeRecord`**, not a stripped `(seq, liked)`
/// view: a thread shard is public-write, so the contract must assume adversarial
/// `UpdateData` and re-verify a like's signature on *every* path it can enter
/// state (delta, full-state merge, sync delta) — exactly as replies and quotes
/// do. Retaining the signature is what lets `validate_state` re-prove a like and
/// makes a forged/overwritten like (any peer, no key) impossible (review
/// CRITICAL). The ~3.3 KB/like is the cost of an unforgeable per-liker counter.
#[derive(Serialize, Deserialize, Default)]
struct ThreadShard {
    // Schema-tolerance: defaults so older/newer wire shapes still decode
    // (AGENTS.md → "Contract migration").
    /// Replies keyed by content-addressed post id (`BTreeMap` for deterministic
    /// serialization).
    #[serde(default)]
    replies: BTreeMap<String, Post>,
    /// Likes keyed by liker VK hex; the value is the full signed record, kept so
    /// every merge path can re-verify it.
    #[serde(default)]
    likes: BTreeMap<String, LikeRecord>,
    /// Quote references keyed by the quoting post's content-addressed id.
    #[serde(default)]
    quotes: BTreeMap<String, QuoteRef>,
    /// Reposts keyed by reposter VK hex; the value is the full signed record,
    /// kept so every merge path can re-verify it (same rationale as `likes`).
    #[serde(default)]
    reposts: BTreeMap<String, RepostRecord>,
}

impl<'a> TryFrom<State<'a>> for ThreadShard {
    type Error = ContractError;

    fn try_from(value: State<'a>) -> Result<Self, Self::Error> {
        serde_json::from_slice(value.as_ref()).map_err(|_| ContractError::InvalidState)
    }
}

/// A single thread-shard delta operation. Externally tagged so the wire form is
/// unambiguous and new surfaces can be added without colliding.
#[derive(Serialize, Deserialize)]
enum ThreadDelta {
    /// One or more replies (each a self-signed `Post` with `reply_to == root`).
    Replies(Vec<Post>),
    /// One or more like/unlike records.
    Likes(Vec<LikeRecord>),
    /// One or more quote references.
    Quotes(Vec<QuoteRef>),
    /// One or more repost/un-repost records.
    Reposts(Vec<RepostRecord>),
}

/// This thread's root post id, as the UTF-8 string carried in the contract
/// parameters. Empty parameters yield an empty root id that no real reply (whose
/// signed `reply_to` is a 64-hex content address) can match, so an
/// un-parameterized thread accepts no replies.
fn root_post_id(parameters: &Parameters<'_>) -> String {
    String::from_utf8_lossy(parameters.as_ref()).into_owned()
}

/// The writer-credential seam (ADR-0001 abuse model). Today it accepts every
/// writer — `WriterCert` is a reserved wire slot, not yet a policy. When a real
/// credential (GhostKey) lands, gate writes here; the cert already rides on each
/// record so doing so is an additive change, not a format break.
fn verify_writer_cert(_cert: Option<&WriterCert>) -> bool {
    true
}

/// Whether a reply is acceptable on this thread: within the length bound, bound
/// to this thread (`reply_to == root`), self-verifying, and (vacuously today)
/// carrying an acceptable writer credential.
fn reply_is_acceptable(post: &Post, root: &str) -> bool {
    !root.is_empty()
        && post.reply_to == root
        // Bounds author name/handle too, not just content: this is an
        // anyone-writes surface, so an unbounded author field is a write
        // primitive for anybody with a keypair, not just self-harm.
        && post.within_bounds()
        && post.verify().is_ok()
        && verify_writer_cert(None)
}

/// Whether a like record is acceptable: thread-bound self-verifying signature
/// and an acceptable writer credential.
fn like_is_acceptable(like: &LikeRecord, root: &str) -> bool {
    !root.is_empty() && like.verify(root).is_ok() && verify_writer_cert(like.writer_cert.as_ref())
}

/// Whether a quote ref is acceptable: thread-bound self-verifying signature and
/// an acceptable writer credential.
fn quote_is_acceptable(quote: &QuoteRef, root: &str) -> bool {
    !root.is_empty() && quote.verify(root).is_ok() && verify_writer_cert(quote.writer_cert.as_ref())
}

/// Whether a repost record is acceptable: thread-bound self-verifying signature
/// and an acceptable writer credential. Mirrors `like_is_acceptable`.
fn repost_is_acceptable(repost: &RepostRecord, root: &str) -> bool {
    !root.is_empty()
        && repost.verify(root).is_ok()
        && verify_writer_cert(repost.writer_cert.as_ref())
}

/// Per-key like merge: does the incoming `(new_seq, new_liked)` replace the
/// current record for a liker? Higher `seq` wins; on equal `seq` an **unlike**
/// (`!liked`) wins. Identical to the user-shard follow rule — a deterministic,
/// order-independent join.
fn like_replaces(new_seq: u64, new_liked: bool, cur: &LikeRecord) -> bool {
    if new_seq != cur.seq {
        new_seq > cur.seq
    } else {
        // Equal seq: unlike wins. Only replaces if current is a like.
        !new_liked && cur.liked
    }
}

/// Re-verify one like for `root` and merge it by the per-liker join rule. Every
/// path into `shard.likes` goes through here, so a like that does not carry a
/// valid signature for its named signer + this thread is never stored — no
/// caller may assume an upstream peer already checked it (public-write surface).
fn merge_like(likes: &mut BTreeMap<String, LikeRecord>, like: LikeRecord, root: &str) {
    if !like_is_acceptable(&like, root) {
        return;
    }
    match likes.get(&like.signer_pubkey) {
        Some(cur) if !like_replaces(like.seq, like.liked, cur) => {}
        _ => {
            likes.insert(like.signer_pubkey.clone(), like);
        }
    }
}

/// Per-key repost merge — identical join to `like_replaces`: higher `seq` wins;
/// on equal `seq` an **un-repost** (`!reposted`) wins. Deterministic and
/// order-independent.
fn repost_replaces(new_seq: u64, new_reposted: bool, cur: &RepostRecord) -> bool {
    if new_seq != cur.seq {
        new_seq > cur.seq
    } else {
        !new_reposted && cur.reposted
    }
}

/// Re-verify one repost for `root` and merge it by the per-reposter join rule.
/// Every path into `shard.reposts` goes through here (public-write surface), so a
/// repost without a valid signature for its named signer + this thread is never
/// stored. Mirrors `merge_like`.
fn merge_repost(reposts: &mut BTreeMap<String, RepostRecord>, repost: RepostRecord, root: &str) {
    if !repost_is_acceptable(&repost, root) {
        return;
    }
    match reposts.get(&repost.signer_pubkey) {
        Some(cur) if !repost_replaces(repost.seq, repost.reposted, cur) => {}
        _ => {
            reposts.insert(repost.signer_pubkey.clone(), repost);
        }
    }
}

/// Truncate replies to the newest `MAX_REPLIES` by `(timestamp, id)` desc — a
/// total order, so every replica retains the identical set regardless of arrival
/// order. Post-merge only (AGENTS.md → "bounded surfaces must truncate
/// post-merge"). Best-effort lossy, like the user-shard post window.
fn truncate_replies(replies: &mut BTreeMap<String, Post>) {
    if replies.len() <= MAX_REPLIES {
        return;
    }
    let mut keys: Vec<(u64, String)> = replies
        .iter()
        .map(|(id, p)| (p.timestamp, id.clone()))
        .collect();
    // Newest first: timestamp desc, then id desc as a stable total tie-break.
    keys.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    for (_, id) in keys.into_iter().skip(MAX_REPLIES) {
        replies.remove(&id);
    }
}

/// Truncate likes to `MAX_LIKES` as a function of the key set: evict tombstones
/// (unlikes) first, then the largest liker key. Deterministic and order-
/// independent, and bounds tombstone growth (AGENTS.md → "bounded surfaces").
fn truncate_likes(likes: &mut BTreeMap<String, LikeRecord>) {
    if likes.len() <= MAX_LIKES {
        return;
    }
    let mut order: Vec<(bool, String)> = likes.iter().map(|(k, v)| (v.liked, k.clone())).collect();
    // Keep active likes (liked = true) before tombstones; within a class, keep
    // smaller keys. Sort so survivors come first: liked desc, key asc.
    order.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (_, key) in order.into_iter().skip(MAX_LIKES) {
        likes.remove(&key);
    }
}

/// Truncate quotes to `MAX_QUOTES` by a total order over the quote-post-id key.
/// Deterministic and order-independent.
fn truncate_quotes(quotes: &mut BTreeMap<String, QuoteRef>) {
    if quotes.len() <= MAX_QUOTES {
        return;
    }
    let mut keys: Vec<String> = quotes.keys().cloned().collect();
    keys.sort();
    for key in keys.into_iter().skip(MAX_QUOTES) {
        quotes.remove(&key);
    }
}

/// Truncate reposts to `MAX_REPOSTS` as a function of the key set: evict
/// tombstones (un-reposts) first, then the largest reposter key. Deterministic
/// and order-independent. Mirrors `truncate_likes`.
fn truncate_reposts(reposts: &mut BTreeMap<String, RepostRecord>) {
    if reposts.len() <= MAX_REPOSTS {
        return;
    }
    let mut order: Vec<(bool, String)> = reposts
        .iter()
        .map(|(k, v)| (v.reposted, k.clone()))
        .collect();
    // Keep active reposts (reposted = true) before tombstones; within a class,
    // keep smaller keys. Sort so survivors come first: reposted desc, key asc.
    order.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (_, key) in order.into_iter().skip(MAX_REPOSTS) {
        reposts.remove(&key);
    }
}

/// Normalize a merged state: enforce all caps post-merge. Pure function of the
/// accumulated sets.
fn normalize(shard: &mut ThreadShard) {
    truncate_replies(&mut shard.replies);
    truncate_likes(&mut shard.likes);
    truncate_quotes(&mut shard.quotes);
    truncate_reposts(&mut shard.reposts);
}

/// Apply one decoded `ThreadDelta` to the shard. Unacceptable entries are
/// skipped (not fatal), the same tolerance the posts contract uses for a bad
/// post in a batch.
fn apply_thread_delta(shard: &mut ThreadShard, delta: ThreadDelta, root: &str) {
    match delta {
        ThreadDelta::Replies(replies) => {
            for reply in replies {
                if reply_is_acceptable(&reply, root) {
                    // Dedup by content-addressed id: a content address is stable,
                    // so re-inserting the same reply is idempotent.
                    shard.replies.entry(reply.id.clone()).or_insert(reply);
                }
            }
        }
        ThreadDelta::Likes(likes) => {
            for like in likes {
                merge_like(&mut shard.likes, like, root);
            }
        }
        ThreadDelta::Quotes(quotes) => {
            for quote in quotes {
                if quote_is_acceptable(&quote, root) {
                    shard
                        .quotes
                        .entry(quote.quote_post_id.clone())
                        .or_insert(quote);
                }
            }
        }
        ThreadDelta::Reposts(reposts) => {
            for repost in reposts {
                merge_repost(&mut shard.reposts, repost, root);
            }
        }
    }
}

/// Try the tagged `ThreadDelta` form first, then a `ThreadStateDelta` (what
/// `get_state_delta` ships — all three surfaces in one message), then a bare
/// `Vec<Post>` (replies-only backward tolerance), then a full `ThreadShard`
/// (state-as-delta).
///
/// Order matters: `ThreadStateDelta`'s fields are all `#[serde(default)]`, so it
/// would also accept a bare `{}`; `ThreadDelta` (externally tagged, no defaults)
/// is tried first so a real tagged delta is never mis-decoded as an empty
/// state-delta.
fn apply_delta_bytes(
    shard: &mut ThreadShard,
    bytes: &[u8],
    root: &str,
) -> Result<(), ContractError> {
    if let Ok(delta) = serde_json::from_slice::<ThreadDelta>(bytes) {
        apply_thread_delta(shard, delta, root);
        return Ok(());
    }
    if let Ok(sd) = serde_json::from_slice::<ThreadStateDelta>(bytes) {
        apply_state_delta(shard, sd, root);
        return Ok(());
    }
    if let Ok(replies) = serde_json::from_slice::<Vec<Post>>(bytes) {
        apply_thread_delta(shard, ThreadDelta::Replies(replies), root);
        return Ok(());
    }
    let other =
        serde_json::from_slice::<ThreadShard>(bytes).map_err(|_| ContractError::InvalidDelta)?;
    merge_state(shard, other, root);
    Ok(())
}

/// Apply a `ThreadStateDelta` (the sync delta from `get_state_delta`). Every
/// surface carries full self-verifying records — replies, quotes, **and likes**
/// — each re-checked here. A like is never trusted on the sender's say-so (the
/// sender may be adversarial); `merge_like` re-verifies its signature.
fn apply_state_delta(shard: &mut ThreadShard, sd: ThreadStateDelta, root: &str) {
    for reply in sd.replies {
        if reply_is_acceptable(&reply, root) {
            shard.replies.entry(reply.id.clone()).or_insert(reply);
        }
    }
    for quote in sd.quotes {
        if quote_is_acceptable(&quote, root) {
            shard
                .quotes
                .entry(quote.quote_post_id.clone())
                .or_insert(quote);
        }
    }
    for like in sd.likes {
        merge_like(&mut shard.likes, like, root);
    }
    for repost in sd.reposts {
        merge_repost(&mut shard.reposts, repost, root);
    }
}

/// Full-state merge: fold every surface of `other` into `shard` under the same
/// acceptance + convergence rules as a delta, so a peer syncing its latest state
/// reconciles replies + likes + quotes (not only replies). Every entry is
/// re-verified — `other` came over the wire from a possibly-adversarial peer, so
/// "it was already validated upstream" is not an assumption the contract may make
/// (review CRITICAL / M-1).
fn merge_state(shard: &mut ThreadShard, other: ThreadShard, root: &str) {
    for (id, reply) in other.replies {
        if reply_is_acceptable(&reply, root) {
            shard.replies.entry(id).or_insert(reply);
        }
    }
    for (_signer, like) in other.likes {
        merge_like(&mut shard.likes, like, root);
    }
    for (qid, quote) in other.quotes {
        if quote_is_acceptable(&quote, root) {
            shard.quotes.entry(qid).or_insert(quote);
        }
    }
    for (_signer, repost) in other.reposts {
        merge_repost(&mut shard.reposts, repost, root);
    }
}

#[contract]
impl ContractInterface for ThreadShard {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts,
    ) -> Result<ValidateResult, ContractError> {
        let shard = ThreadShard::try_from(state)?;
        let root = root_post_id(&parameters);

        // Every reply must self-verify, be bound to this thread, fit the length
        // bound, and key under its own content address (no duplicates / no
        // misfiled id). update_state guarantees these, so validate_state must
        // reject any state violating them (AGENTS.md → "validate agrees with
        // update").
        for (id, reply) in &shard.replies {
            if id != &reply.id || !reply_is_acceptable(reply, &root) {
                return Err(ContractError::InvalidState);
            }
        }
        // Every like must self-verify for this thread and key under its own
        // signer — the same full re-proof update_state performs, so the two
        // halves agree and a forged like cannot validate (review CRITICAL).
        for (signer, like) in &shard.likes {
            if signer != &like.signer_pubkey || !like_is_acceptable(like, &root) {
                return Err(ContractError::InvalidState);
            }
        }
        // Every quote must self-verify, be bound to this thread, and key under
        // its quote_post_id.
        for (qid, quote) in &shard.quotes {
            if qid != &quote.quote_post_id || !quote_is_acceptable(quote, &root) {
                return Err(ContractError::InvalidState);
            }
        }
        // Every repost must self-verify for this thread and key under its own
        // signer — the same full re-proof update_state performs (mirrors likes).
        for (signer, repost) in &shard.reposts {
            if signer != &repost.signer_pubkey || !repost_is_acceptable(repost, &root) {
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
        let mut shard = ThreadShard::try_from(state)?;
        let root = root_post_id(&parameters);

        // Iterate EVERY update item (not just the first), dispatching per kind.
        for item in &delta {
            match item {
                UpdateData::Delta(d) => apply_delta_bytes(&mut shard, d.as_ref(), &root)?,
                UpdateData::State(s) => {
                    let other = ThreadShard::try_from(State::from(s.to_vec()))?;
                    merge_state(&mut shard, other, &root);
                }
                UpdateData::StateAndDelta { state: s, delta: d } => {
                    let other = ThreadShard::try_from(State::from(s.to_vec()))?;
                    merge_state(&mut shard, other, &root);
                    apply_delta_bytes(&mut shard, d.as_ref(), &root)?;
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
        let shard = ThreadShard::try_from(state)?;
        // Summary = the key sets per surface, so get_state_delta can compute what
        // the requester is missing. Keys are deterministic (BTreeMap order).
        let summary = ThreadSummary {
            replies: shard.replies.keys().cloned().collect(),
            // (signer, seq, liked) is enough to diff which likers the requester
            // is stale on; the full signed record is shipped in the delta, not
            // the summary.
            likes: shard
                .likes
                .iter()
                .map(|(k, v)| (k.clone(), v.seq, v.liked))
                .collect(),
            quotes: shard.quotes.keys().cloned().collect(),
            // (signer, seq, reposted) — enough to diff which reposters the
            // requester is stale on; the full signed record ships in the delta.
            reposts: shard
                .reposts
                .iter()
                .map(|(k, v)| (k.clone(), v.seq, v.reposted))
                .collect(),
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
        let shard = ThreadShard::try_from(state)?;
        let _ = root_post_id(&parameters);
        let have: ThreadSummary = serde_json::from_slice(summary.as_ref()).unwrap_or_default();

        let have_replies: std::collections::HashSet<&String> = have.replies.iter().collect();
        let have_quotes: std::collections::HashSet<&String> = have.quotes.iter().collect();
        let have_likes: BTreeMap<&String, (u64, bool)> = have
            .likes
            .iter()
            .map(|(k, seq, liked)| (k, (*seq, *liked)))
            .collect();
        let have_reposts: BTreeMap<&String, (u64, bool)> = have
            .reposts
            .iter()
            .map(|(k, seq, reposted)| (k, (*seq, *reposted)))
            .collect();

        // Replies the requester lacks.
        let missing_replies: Vec<Post> = shard
            .replies
            .iter()
            .filter(|(id, _)| !have_replies.contains(id))
            .map(|(_, p)| p.clone())
            .collect();
        // Quotes the requester lacks.
        let missing_quotes: Vec<QuoteRef> = shard
            .quotes
            .iter()
            .filter(|(qid, _)| !have_quotes.contains(qid))
            .map(|(_, q)| q.clone())
            .collect();
        // Likes the requester lacks or has at a lower (seq, liked-rank). Ship the
        // **full signed record** so the receiver re-verifies it (a sync delta is
        // no more trusted than any other delta — review CRITICAL / MIN-1).
        let likes_delta: Vec<LikeRecord> = shard
            .likes
            .iter()
            .filter(|(k, v)| match have_likes.get(*k) {
                Some((seq, liked)) => v.seq > *seq || (v.seq == *seq && *liked && !v.liked),
                None => true,
            })
            .map(|(_, v)| v.clone())
            .collect();

        // Reposts the requester lacks or has at a lower (seq, reposted-rank).
        // Ship the full signed record so the receiver re-verifies it.
        let reposts_delta: Vec<RepostRecord> = shard
            .reposts
            .iter()
            .filter(|(k, v)| match have_reposts.get(*k) {
                Some((seq, reposted)) => {
                    v.seq > *seq || (v.seq == *seq && *reposted && !v.reposted)
                }
                None => true,
            })
            .map(|(_, v)| v.clone())
            .collect();

        let delta = ThreadStateDelta {
            replies: missing_replies,
            quotes: missing_quotes,
            likes: likes_delta,
            reposts: reposts_delta,
        };
        let bytes = serde_json::to_vec(&delta).map_err(|e| ContractError::Other(format!("{e}")))?;
        Ok(StateDelta::from(bytes))
    }
}

/// Summary shape: the key sets the requester already holds, so `get_state_delta`
/// can ship only what is missing.
#[derive(Serialize, Deserialize, Default)]
struct ThreadSummary {
    #[serde(default)]
    replies: Vec<String>,
    /// (signer, seq, liked) so a stale like can be refreshed.
    #[serde(default)]
    likes: Vec<(String, u64, bool)>,
    #[serde(default)]
    quotes: Vec<String>,
    /// (signer, seq, reposted) so a stale repost can be refreshed.
    #[serde(default)]
    reposts: Vec<(String, u64, bool)>,
}

/// The delta `get_state_delta` ships: all three surfaces in one message, each a
/// full self-verifying record (replies, likes, quotes). It is intentionally NOT
/// a `ThreadDelta` so it can convey every surface at once; `apply_delta_bytes`
/// decodes it via `apply_state_delta`, which re-verifies each entry — a sync
/// delta is no more trusted than any other.
#[derive(Serialize, Deserialize, Default)]
struct ThreadStateDelta {
    #[serde(default)]
    replies: Vec<Post>,
    #[serde(default)]
    likes: Vec<LikeRecord>,
    #[serde(default)]
    quotes: Vec<QuoteRef>,
    #[serde(default)]
    reposts: Vec<RepostRecord>,
}

#[cfg(test)]
mod test {
    use super::*;
    use freenet_microblogging_common::thread::{LikeRecord, QuoteRef, RepostRecord};
    use ml_dsa::KeyGen;
    use ml_dsa::signature::{Keypair, Signer};
    use ml_dsa::{MlDsa65, Signature};

    const ROOT: &str = "root_post_content_address_0001";

    fn params() -> Parameters<'static> {
        Parameters::from(ROOT.as_bytes().to_vec())
    }

    fn vk_hex(seed: [u8; 32]) -> String {
        let sk = MlDsa65::from_seed(&seed.into());
        hex::encode(sk.verifying_key().encode())
    }

    /// A signed reply to ROOT.
    fn signed_reply(seed: [u8; 32], content: &str, ts: u64) -> Post {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut p = Post {
            id: String::new(),
            author_pubkey: hex::encode(sk.verifying_key().encode()),
            author_name: "Bob".into(),
            author_handle: "@bob".into(),
            content: content.into(),
            timestamp: ts,
            reply_to: ROOT.into(),
            quoted_post: String::new(),
            signature: None,
        };
        p.id = p.compute_id();
        let sig: Signature<MlDsa65> = sk.sign(&p.signing_payload());
        p.signature = Some(hex::encode(sig.encode()));
        p
    }

    fn signed_like(seed: [u8; 32], seq: u64, liked: bool) -> LikeRecord {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut r = LikeRecord {
            signer_pubkey: hex::encode(sk.verifying_key().encode()),
            seq,
            liked,
            writer_cert: None,
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&r.signing_payload(ROOT));
        r.signature = Some(hex::encode(sig.encode()));
        r
    }

    fn signed_quote(seed: [u8; 32], qid: &str) -> QuoteRef {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut q = QuoteRef {
            signer_pubkey: hex::encode(sk.verifying_key().encode()),
            quote_post_id: qid.into(),
            writer_cert: None,
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&q.signing_payload(ROOT));
        q.signature = Some(hex::encode(sig.encode()));
        q
    }

    fn signed_repost(seed: [u8; 32], seq: u64, reposted: bool) -> RepostRecord {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut r = RepostRecord {
            signer_pubkey: hex::encode(sk.verifying_key().encode()),
            seq,
            reposted,
            writer_cert: None,
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&r.signing_payload(ROOT));
        r.signature = Some(hex::encode(sig.encode()));
        r
    }

    fn state_of(shard: &ThreadShard) -> State<'static> {
        State::from(serde_json::to_vec(shard).unwrap())
    }

    fn delta_item(d: &ThreadDelta) -> UpdateData<'static> {
        UpdateData::Delta(StateDelta::from(serde_json::to_vec(d).unwrap()))
    }

    fn run_update(shard: ThreadShard, items: Vec<UpdateData<'static>>) -> ThreadShard {
        let res = ThreadShard::update_state(params(), state_of(&shard), items).unwrap();
        serde_json::from_slice(res.unwrap_valid().as_ref()).unwrap()
    }

    #[test]
    fn reply_accepted_only_when_bound_to_this_thread() {
        let good = signed_reply([1u8; 32], "hi", 100);
        // A reply whose reply_to is a different thread must be rejected.
        let sk = MlDsa65::from_seed(&[1u8; 32].into());
        let mut wrong = Post {
            id: String::new(),
            author_pubkey: hex::encode(sk.verifying_key().encode()),
            author_name: "Bob".into(),
            author_handle: "@bob".into(),
            content: "hi".into(),
            timestamp: 100,
            reply_to: "some_other_thread".into(),
            quoted_post: String::new(),
            signature: None,
        };
        wrong.id = wrong.compute_id();
        let sig: Signature<MlDsa65> = sk.sign(&wrong.signing_payload());
        wrong.signature = Some(hex::encode(sig.encode()));

        let out = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Replies(vec![good.clone(), wrong]))],
        );
        assert_eq!(out.replies.len(), 1);
        assert!(out.replies.contains_key(&good.id));
    }

    #[test]
    fn replies_dedup_by_content_address() {
        let r = signed_reply([1u8; 32], "dup", 100);
        let out = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Replies(vec![
                r.clone(),
                r.clone(),
            ]))],
        );
        assert_eq!(out.replies.len(), 1);
    }

    #[test]
    fn likes_converge_equal_seq_unlike_wins() {
        // Same liker, same seq, Like vs Unlike → unlike wins regardless of order
        // (the equal-seq tie-break; AGENTS.md → "Convergence").
        let like = signed_like([2u8; 32], 5, true);
        let unlike = signed_like([2u8; 32], 5, false);

        let a = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Likes(vec![
                like.clone(),
                unlike.clone(),
            ]))],
        );
        let b = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Likes(vec![unlike, like]))],
        );
        let signer = vk_hex([2u8; 32]);
        assert!(!a.likes[&signer].liked);
        assert_eq!(a.likes[&signer], b.likes[&signer]);
    }

    #[test]
    fn likes_higher_seq_wins() {
        let l1 = signed_like([2u8; 32], 1, true);
        let l2 = signed_like([2u8; 32], 2, false);
        let out = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Likes(vec![l2, l1]))],
        );
        let signer = vk_hex([2u8; 32]);
        assert_eq!(out.likes[&signer].seq, 2);
        assert!(!out.likes[&signer].liked);
    }

    #[test]
    fn quotes_dedup_by_quote_post_id() {
        let q = signed_quote([3u8; 32], "quote_aaa");
        let out = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Quotes(vec![q.clone(), q.clone()]))],
        );
        assert_eq!(out.quotes.len(), 1);
        assert!(out.quotes.contains_key("quote_aaa"));
    }

    #[test]
    fn tampered_like_signature_rejected() {
        let mut bad = signed_like([2u8; 32], 1, true);
        bad.seq = 99; // breaks signature
        let out = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Likes(vec![bad]))],
        );
        assert!(out.likes.is_empty());
    }

    #[test]
    fn reposts_converge_equal_seq_unrepost_wins() {
        // Same reposter, same seq, Repost vs Un-repost → un-repost wins
        // regardless of order (equal-seq tie-break, mirroring likes).
        let repost = signed_repost([2u8; 32], 5, true);
        let unrepost = signed_repost([2u8; 32], 5, false);

        let a = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Reposts(vec![
                repost.clone(),
                unrepost.clone(),
            ]))],
        );
        let b = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Reposts(vec![unrepost, repost]))],
        );
        let signer = vk_hex([2u8; 32]);
        assert!(!a.reposts[&signer].reposted);
        assert_eq!(a.reposts[&signer], b.reposts[&signer]);
    }

    #[test]
    fn reposts_higher_seq_wins() {
        let r1 = signed_repost([2u8; 32], 1, true);
        let r2 = signed_repost([2u8; 32], 2, false);
        let out = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Reposts(vec![r2, r1]))],
        );
        let signer = vk_hex([2u8; 32]);
        assert_eq!(out.reposts[&signer].seq, 2);
        assert!(!out.reposts[&signer].reposted);
    }

    #[test]
    fn tampered_repost_signature_rejected() {
        let mut bad = signed_repost([2u8; 32], 1, true);
        bad.seq = 99; // breaks signature
        let out = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Reposts(vec![bad]))],
        );
        assert!(out.reposts.is_empty());
    }

    #[test]
    fn forged_repost_via_full_state_merge_rejected() {
        // A peer ships a full ThreadShard with a repost whose signature does not
        // verify; merge_state must re-verify and drop it (public-write surface).
        let mut forged = signed_repost([2u8; 32], 1, true);
        forged.reposted = false; // flip after signing → bad signature
        let mut malicious = ThreadShard::default();
        malicious
            .reposts
            .insert(forged.signer_pubkey.clone(), forged);
        let out = run_update(
            ThreadShard::default(),
            vec![UpdateData::State(State::from(
                serde_json::to_vec(&malicious).unwrap(),
            ))],
        );
        assert!(out.reposts.is_empty());
    }

    #[test]
    fn validate_rejects_forged_repost_state() {
        // validate_state must reject a state carrying a repost that does not
        // self-verify, so it agrees with update_state (AGENTS.md → "validate
        // agrees with update").
        let mut forged = signed_repost([2u8; 32], 1, true);
        forged.reposted = false; // break signature
        let mut shard = ThreadShard::default();
        shard.reposts.insert(forged.signer_pubkey.clone(), forged);
        let res =
            ThreadShard::validate_state(params(), state_of(&shard), RelatedContracts::default());
        // validate_state signals a forged repost via Err(InvalidState) (same as
        // the forged-like path), not Ok(Invalid).
        assert!(res.is_err());
    }

    #[test]
    fn full_state_merge_reconciles_all_surfaces() {
        let mut a = ThreadShard::default();
        let r = signed_reply([1u8; 32], "r", 100);
        a.replies.insert(r.id.clone(), r);
        let lk = signed_like([2u8; 32], 1, true);
        a.likes.insert(lk.signer_pubkey.clone(), lk);

        // Merge a's full state into an empty shard via UpdateData::State.
        let out = run_update(
            ThreadShard::default(),
            vec![UpdateData::State(state_of(&a))],
        );
        assert_eq!(out.replies.len(), 1);
        assert_eq!(out.likes.len(), 1);
    }

    #[test]
    fn state_and_delta_merges_both() {
        // The StateAndDelta update arm: one update item carrying a full state AND
        // a delta. update_state must merge_state the state THEN apply the delta,
        // so a record from each is present and post-merge invariants hold.
        // Full state: a reply + a like the peer already holds.
        let mut src = ThreadShard::default();
        let r = signed_reply([1u8; 32], "from-state", 100);
        src.replies.insert(r.id.clone(), r.clone());
        let lk = signed_like([2u8; 32], 1, true);
        src.likes.insert(lk.signer_pubkey.clone(), lk);
        // Delta: a quote (a distinct second record on a distinct surface).
        let q = signed_quote([3u8; 32], "from-delta");
        let delta = serde_json::to_vec(&ThreadDelta::Quotes(vec![q.clone()])).unwrap();

        let out = run_update(
            ThreadShard::default(),
            vec![UpdateData::StateAndDelta {
                state: state_of(&src),
                delta: StateDelta::from(delta),
            }],
        );
        // State's reply + like merged in.
        assert_eq!(out.replies.len(), 1, "state reply merged");
        assert!(out.replies.contains_key(&r.id));
        assert_eq!(out.likes.len(), 1, "state like merged");
        // Delta's quote merged in.
        assert_eq!(out.quotes.len(), 1, "delta quote merged");
        assert!(out.quotes.contains_key("from-delta"));
        // Invariant: every reply still keyed under its own content address.
        for (id, reply) in &out.replies {
            assert_eq!(id, &reply.id);
        }
    }

    #[test]
    fn validate_rejects_misfiled_reply_id() {
        let mut shard = ThreadShard::default();
        let r = signed_reply([1u8; 32], "x", 100);
        // File it under the wrong key.
        shard.replies.insert("wrong_key".into(), r);
        let res = ThreadShard::validate_state(params(), state_of(&shard), RelatedContracts::new());
        assert!(!matches!(res, Ok(ValidateResult::Valid)));
    }

    #[test]
    fn validate_accepts_well_formed_state() {
        let mut shard = ThreadShard::default();
        let r = signed_reply([1u8; 32], "x", 100);
        shard.replies.insert(r.id.clone(), r);
        let q = signed_quote([3u8; 32], "qa");
        shard.quotes.insert(q.quote_post_id.clone(), q);
        let res = ThreadShard::validate_state(params(), state_of(&shard), RelatedContracts::new())
            .unwrap();
        assert!(matches!(res, ValidateResult::Valid));
    }

    #[test]
    fn replies_truncate_deterministically() {
        // Build > MAX_REPLIES replies across two orderings; both retain the same
        // newest-by-(timestamp,id) set.
        let mut items_fwd = Vec::new();
        let mut items_rev = Vec::new();
        let n = MAX_REPLIES + 25;
        let mut replies: Vec<Post> = (0..n)
            .map(|i| signed_reply([1u8; 32], &format!("c{i}"), 1000 + i as u64))
            .collect();
        for r in &replies {
            items_fwd.push(r.clone());
        }
        replies.reverse();
        for r in &replies {
            items_rev.push(r.clone());
        }
        let a = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Replies(items_fwd))],
        );
        let b = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Replies(items_rev))],
        );
        assert_eq!(a.replies.len(), MAX_REPLIES);
        assert_eq!(
            a.replies.keys().collect::<Vec<_>>(),
            b.replies.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn empty_root_param_accepts_nothing() {
        let r = signed_reply([1u8; 32], "hi", 100);
        let res = ThreadShard::update_state(
            Parameters::from(Vec::new()),
            state_of(&ThreadShard::default()),
            vec![delta_item(&ThreadDelta::Replies(vec![r]))],
        )
        .unwrap();
        let out: ThreadShard = serde_json::from_slice(res.unwrap_valid().as_ref()).unwrap();
        assert!(out.replies.is_empty());
    }

    #[test]
    fn get_state_delta_output_is_applyable() {
        // Regression: get_state_delta ships a ThreadStateDelta; apply_delta_bytes
        // must be able to decode and apply it (round-trip), or peers never sync.
        // Build a source with all three surfaces.
        let mut src = ThreadShard::default();
        let r = signed_reply([1u8; 32], "r", 100);
        src.replies.insert(r.id.clone(), r);
        let lk = signed_like([2u8; 32], 3, true);
        src.likes.insert(lk.signer_pubkey.clone(), lk);
        let q = signed_quote([3u8; 32], "qa");
        src.quotes.insert(q.quote_post_id.clone(), q);

        // Empty requester summary → delta carries everything.
        let empty_summary =
            StateSummary::from(serde_json::to_vec(&ThreadSummary::default()).unwrap());
        let delta = ThreadShard::get_state_delta(params(), state_of(&src), empty_summary).unwrap();

        // Apply that delta to a fresh shard.
        let out = run_update(
            ThreadShard::default(),
            vec![UpdateData::Delta(StateDelta::from(
                delta.into_bytes().to_vec(),
            ))],
        );
        assert_eq!(out.replies.len(), 1);
        assert_eq!(out.likes.len(), 1);
        assert_eq!(out.quotes.len(), 1);
    }

    #[test]
    fn forged_like_via_full_state_merge_rejected() {
        // CRITICAL regression: an adversary crafts a ThreadShard whose `likes`
        // map carries an unsigned (or mis-signed) like attributed to a victim VK,
        // and ships it as UpdateData::State. merge_state must re-verify and drop
        // it — no key, no like.
        let victim = vk_hex([2u8; 32]);
        let mut forged = ThreadShard::default();
        forged.likes.insert(
            victim.clone(),
            LikeRecord {
                signer_pubkey: victim.clone(),
                seq: 9,
                liked: true,
                writer_cert: None,
                signature: None, // forged: no valid signature
            },
        );
        let out = run_update(
            ThreadShard::default(),
            vec![UpdateData::State(state_of(&forged))],
        );
        assert!(
            out.likes.is_empty(),
            "forged unsigned like must not be stored"
        );
    }

    #[test]
    fn forged_like_cannot_suppress_genuine_like() {
        // A genuine like exists; an attacker tries to overwrite it with a forged
        // higher-seq unlike attributed to the same victim, via full-state merge.
        let genuine = signed_like([2u8; 32], 1, true);
        let victim = genuine.signer_pubkey.clone();
        let base = run_update(
            ThreadShard::default(),
            vec![delta_item(&ThreadDelta::Likes(vec![genuine]))],
        );
        assert!(base.likes[&victim].liked);

        let mut forged = ThreadShard::default();
        forged.likes.insert(
            victim.clone(),
            LikeRecord {
                signer_pubkey: victim.clone(),
                seq: 99,
                liked: false,
                writer_cert: None,
                signature: None, // forged unlike
            },
        );
        let out = run_update(base, vec![UpdateData::State(state_of(&forged))]);
        // Genuine like survives; forged suppression is dropped.
        assert!(out.likes[&victim].liked);
        assert_eq!(out.likes[&victim].seq, 1);
    }

    #[test]
    fn validate_rejects_forged_like_state() {
        // The two halves must agree: a state update_state would never produce
        // (an unsigned like) must fail validate_state.
        let victim = vk_hex([2u8; 32]);
        let mut shard = ThreadShard::default();
        shard.likes.insert(
            victim.clone(),
            LikeRecord {
                signer_pubkey: victim,
                seq: 1,
                liked: true,
                writer_cert: None,
                signature: None,
            },
        );
        let res = ThreadShard::validate_state(params(), state_of(&shard), RelatedContracts::new());
        assert!(!matches!(res, Ok(ValidateResult::Valid)));
    }

    #[test]
    fn decodes_old_shape_state() {
        let empty: ThreadShard = serde_json::from_slice(b"{}").unwrap();
        assert!(empty.replies.is_empty() && empty.likes.is_empty() && empty.quotes.is_empty());
        let forward: ThreadShard =
            serde_json::from_slice(br#"{"replies":{},"likes":{},"quotes":{},"version":2}"#)
                .unwrap();
        assert!(forward.replies.is_empty());
    }
}

/// Integration tests: drive the full `ContractInterface` (validate / update /
/// summarize / get_state_delta) through multi-replica and multi-author scenarios
/// — the layer above the per-function unit tests. The key scenario is **two
/// replicas reconciling via the real sync protocol** (`summarize_state` →
/// `get_state_delta` → `update_state`), which the unit tests do not exercise.
///
/// These still call the contract as a Rust library (not compiled WASM in a
/// node); true WASM-in-node e2e is a separate, heavier tier (see the
/// `freenet:linux-test` skill). What is new here vs. the unit tests: real
/// multi-party ML-DSA-65 keys, the summarize/delta sync path, and cross-shard
/// consistency between a post and its thread.
#[cfg(test)]
mod integration {
    use super::*;
    use freenet_microblogging_common::thread::{LikeRecord, QuoteRef};
    use ml_dsa::signature::{Keypair, Signer};
    use ml_dsa::{KeyGen, MlDsa65, Signature};

    const ROOT: &str = "integration_root_post_address";

    fn params() -> Parameters<'static> {
        Parameters::from(ROOT.as_bytes().to_vec())
    }

    fn state_of(shard: &ThreadShard) -> State<'static> {
        State::from(serde_json::to_vec(shard).unwrap())
    }

    fn decode(state: State<'static>) -> ThreadShard {
        serde_json::from_slice(state.as_ref()).unwrap()
    }

    /// A reply to ROOT by the author with `seed`.
    fn reply(seed: [u8; 32], content: &str, ts: u64) -> Post {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut p = Post {
            id: String::new(),
            author_pubkey: hex::encode(sk.verifying_key().encode()),
            author_name: "Author".into(),
            author_handle: "@author".into(),
            content: content.into(),
            timestamp: ts,
            reply_to: ROOT.into(),
            quoted_post: String::new(),
            signature: None,
        };
        p.id = p.compute_id();
        let sig: Signature<MlDsa65> = sk.sign(&p.signing_payload());
        p.signature = Some(hex::encode(sig.encode()));
        p
    }

    fn like(seed: [u8; 32], seq: u64, liked: bool) -> LikeRecord {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut r = LikeRecord {
            signer_pubkey: hex::encode(sk.verifying_key().encode()),
            seq,
            liked,
            writer_cert: None,
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&r.signing_payload(ROOT));
        r.signature = Some(hex::encode(sig.encode()));
        r
    }

    fn quote(seed: [u8; 32], qid: &str) -> QuoteRef {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut q = QuoteRef {
            signer_pubkey: hex::encode(sk.verifying_key().encode()),
            quote_post_id: qid.into(),
            writer_cert: None,
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&q.signing_payload(ROOT));
        q.signature = Some(hex::encode(sig.encode()));
        q
    }

    fn repost(seed: [u8; 32], seq: u64, reposted: bool) -> RepostRecord {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut r = RepostRecord {
            signer_pubkey: hex::encode(sk.verifying_key().encode()),
            seq,
            reposted,
            writer_cert: None,
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&r.signing_payload(ROOT));
        r.signature = Some(hex::encode(sig.encode()));
        r
    }

    /// Apply a batch of deltas to a replica, returning its new state — the
    /// contract's own `update_state`, exactly as a node would call it.
    fn apply(shard: &ThreadShard, items: Vec<UpdateData<'static>>) -> ThreadShard {
        let res = ThreadShard::update_state(params(), state_of(shard), items).unwrap();
        decode(res.unwrap_valid())
    }

    fn delta(d: &ThreadDelta) -> UpdateData<'static> {
        UpdateData::Delta(StateDelta::from(serde_json::to_vec(d).unwrap()))
    }

    /// One directional sync step, faithful to the node protocol: `dst` summarizes
    /// what it has, `src` computes the delta of what `dst` is missing, `dst`
    /// applies it. Returns `dst`'s new state. Every state must stay valid.
    fn sync_into(dst: &ThreadShard, src: &ThreadShard) -> ThreadShard {
        // dst is valid before syncing.
        assert!(matches!(
            ThreadShard::validate_state(params(), state_of(dst), RelatedContracts::new()).unwrap(),
            ValidateResult::Valid
        ));
        let summary = ThreadShard::summarize_state(params(), state_of(dst)).unwrap();
        let d = ThreadShard::get_state_delta(params(), state_of(src), summary).unwrap();
        let merged = apply(
            dst,
            vec![UpdateData::Delta(StateDelta::from(d.into_bytes().to_vec()))],
        );
        // dst stays valid after syncing.
        assert!(matches!(
            ThreadShard::validate_state(params(), state_of(&merged), RelatedContracts::new())
                .unwrap(),
            ValidateResult::Valid
        ));
        merged
    }

    /// Full bidirectional reconcile: sync each way once. For these state sizes a
    /// single round each direction converges (the delta carries everything the
    /// peer lacks). Returns `(a', b')`, which must be equal.
    fn reconcile(a: &ThreadShard, b: &ThreadShard) -> (ThreadShard, ThreadShard) {
        let a2 = sync_into(a, b);
        let b2 = sync_into(b, a);
        (a2, b2)
    }

    fn canonical(shard: &ThreadShard) -> Vec<u8> {
        serde_json::to_vec(shard).unwrap()
    }

    #[test]
    fn two_replicas_converge_over_sync_protocol() {
        // A and B each see a disjoint set of writes from different authors, then
        // reconcile via summarize/get_state_delta/update_state. They must reach
        // byte-identical state — exercising the real sync path, not direct merge.
        let empty = ThreadShard::default();

        let a = apply(
            &empty,
            vec![
                delta(&ThreadDelta::Replies(vec![reply([1; 32], "a-reply", 100)])),
                delta(&ThreadDelta::Likes(vec![like([2; 32], 1, true)])),
                delta(&ThreadDelta::Quotes(vec![quote([3; 32], "qa")])),
                delta(&ThreadDelta::Reposts(vec![repost([6; 32], 1, true)])),
            ],
        );
        let b = apply(
            &empty,
            vec![
                delta(&ThreadDelta::Replies(vec![reply([4; 32], "b-reply", 200)])),
                delta(&ThreadDelta::Likes(vec![like([5; 32], 1, true)])),
                delta(&ThreadDelta::Reposts(vec![repost([8; 32], 1, true)])),
            ],
        );

        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(canonical(&a2), canonical(&b2), "replicas must converge");
        // Union of all writes present on both.
        assert_eq!(a2.replies.len(), 2);
        assert_eq!(a2.likes.len(), 2);
        assert_eq!(a2.quotes.len(), 1);
        assert_eq!(a2.reposts.len(), 2);
    }

    #[test]
    fn concurrent_repost_unrepost_converges_over_sync() {
        // Same reposter, equal seq, opposite intents on the two replicas — must
        // settle on the un-repost (equal-seq tie-break) over the sync protocol,
        // in either reconcile direction. Mirrors the like case.
        let empty = ThreadShard::default();
        let a = apply(
            &empty,
            vec![delta(&ThreadDelta::Reposts(vec![repost([9; 32], 5, true)]))],
        );
        let b = apply(
            &empty,
            vec![delta(&ThreadDelta::Reposts(vec![repost(
                [9; 32], 5, false,
            )]))],
        );

        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(canonical(&a2), canonical(&b2));
        let signer = hex::encode(
            MlDsa65::from_seed(&[9u8; 32].into())
                .verifying_key()
                .encode(),
        );
        assert!(
            !a2.reposts[&signer].reposted,
            "equal-seq un-repost wins after sync"
        );

        let (b3, a3) = reconcile(&b, &a);
        assert_eq!(canonical(&a3), canonical(&b3));
    }

    #[test]
    fn concurrent_like_unlike_converges_over_sync() {
        // Same liker, equal seq, opposite intents on the two replicas — the
        // hardest convergence case. Over the sync protocol both must settle on
        // the unlike (equal-seq tie-break), in either reconcile direction.
        let empty = ThreadShard::default();
        let a = apply(
            &empty,
            vec![delta(&ThreadDelta::Likes(vec![like([7; 32], 5, true)]))],
        );
        let b = apply(
            &empty,
            vec![delta(&ThreadDelta::Likes(vec![like([7; 32], 5, false)]))],
        );

        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(canonical(&a2), canonical(&b2));
        let signer = hex::encode(
            MlDsa65::from_seed(&[7u8; 32].into())
                .verifying_key()
                .encode(),
        );
        assert!(!a2.likes[&signer].liked, "equal-seq unlike wins after sync");

        // And the reverse reconcile order yields the same fixed point.
        let (b3, a3) = reconcile(&b, &a);
        assert_eq!(canonical(&a3), canonical(&b3));
        assert!(!a3.likes[&signer].liked);
    }

    #[test]
    fn higher_seq_like_propagates_over_sync() {
        // A has an old like (seq 1, liked); B has the same liker's newer unlike
        // (seq 2). After sync both hold the unlike — the summary carries (seq,
        // liked) so get_state_delta ships the newer record.
        let empty = ThreadShard::default();
        let a = apply(
            &empty,
            vec![delta(&ThreadDelta::Likes(vec![like([8; 32], 1, true)]))],
        );
        let b = apply(
            &empty,
            vec![delta(&ThreadDelta::Likes(vec![like([8; 32], 2, false)]))],
        );
        let signer = hex::encode(
            MlDsa65::from_seed(&[8u8; 32].into())
                .verifying_key()
                .encode(),
        );

        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(canonical(&a2), canonical(&b2));
        assert_eq!(a2.likes[&signer].seq, 2);
        assert!(!a2.likes[&signer].liked);
    }

    #[test]
    fn forged_like_does_not_propagate_over_sync() {
        // A holds a forged (unsigned) like in its state. When B syncs from A, the
        // forged like rides in the delta but B's update_state re-verifies and
        // drops it — a malicious replica cannot inject a like into an honest one.
        let victim = hex::encode(
            MlDsa65::from_seed(&[9u8; 32].into())
                .verifying_key()
                .encode(),
        );
        let mut malicious = ThreadShard::default();
        malicious.likes.insert(
            victim.clone(),
            LikeRecord {
                signer_pubkey: victim.clone(),
                seq: 1,
                liked: true,
                writer_cert: None,
                signature: None, // forged
            },
        );
        // (A malicious peer's own state need not be valid; we only care what an
        // honest peer accepts from it.)
        let honest = ThreadShard::default();
        let synced = sync_into(&honest, &malicious);
        assert!(
            synced.likes.is_empty(),
            "honest replica must reject forged like over sync"
        );
    }

    #[test]
    fn cross_shard_post_and_reply_use_consistent_keys() {
        // A post authored on a user shard and a reply to it on the thread shard
        // are both `common::post::Post`s signed by their authors with the single
        // trusted encoder. The thread is keyed by the root post's content id, and
        // a reply's reply_to must equal that id. This checks the cross-shard
        // contract: the thread param is exactly the user-shard post's id, and a
        // reply bound to it is accepted while one bound to a different id is not.
        let author = [10u8; 32];
        let sk = MlDsa65::from_seed(&author.into());
        // The "root" post as it would live on the author's user shard.
        let mut root_post = Post {
            id: String::new(),
            author_pubkey: hex::encode(sk.verifying_key().encode()),
            author_name: "Root".into(),
            author_handle: "@root".into(),
            content: "the original post".into(),
            timestamp: 1_000,
            reply_to: String::new(),
            quoted_post: String::new(),
            signature: None,
        };
        root_post.id = root_post.compute_id();
        let sig: Signature<MlDsa65> = sk.sign(&root_post.signing_payload());
        root_post.signature = Some(hex::encode(sig.encode()));
        assert_eq!(root_post.verify(), Ok(()));

        // The thread shard for this post is parameterized by its content id.
        let thread_params = Parameters::from(root_post.id.as_bytes().to_vec());

        // A reply bound to that id (by a different author) is accepted.
        let replier = [11u8; 32];
        let rsk = MlDsa65::from_seed(&replier.into());
        let mut good_reply = Post {
            id: String::new(),
            author_pubkey: hex::encode(rsk.verifying_key().encode()),
            author_name: "Replier".into(),
            author_handle: "@replier".into(),
            content: "good reply".into(),
            timestamp: 1_001,
            reply_to: root_post.id.clone(),
            quoted_post: String::new(),
            signature: None,
        };
        good_reply.id = good_reply.compute_id();
        let rsig: Signature<MlDsa65> = rsk.sign(&good_reply.signing_payload());
        good_reply.signature = Some(hex::encode(rsig.encode()));

        let res = ThreadShard::update_state(
            thread_params.clone(),
            State::from(serde_json::to_vec(&ThreadShard::default()).unwrap()),
            vec![UpdateData::Delta(StateDelta::from(
                serde_json::to_vec(&ThreadDelta::Replies(vec![good_reply.clone()])).unwrap(),
            ))],
        )
        .unwrap();
        let out: ThreadShard = serde_json::from_slice(res.unwrap_valid().as_ref()).unwrap();
        assert_eq!(
            out.replies.len(),
            1,
            "reply bound to the root id is accepted"
        );
        assert!(out.replies.contains_key(&good_reply.id));

        // The same reply offered to the WRONG thread (different root param) is
        // rejected — its signed reply_to no longer matches that thread's root.
        let wrong_params = Parameters::from(b"some_other_root_id".to_vec());
        let res2 = ThreadShard::update_state(
            wrong_params,
            State::from(serde_json::to_vec(&ThreadShard::default()).unwrap()),
            vec![UpdateData::Delta(StateDelta::from(
                serde_json::to_vec(&ThreadDelta::Replies(vec![good_reply])).unwrap(),
            ))],
        )
        .unwrap();
        let out2: ThreadShard = serde_json::from_slice(res2.unwrap_valid().as_ref()).unwrap();
        assert!(
            out2.replies.is_empty(),
            "reply must not land on the wrong thread"
        );
    }

    #[test]
    fn truncate_reposts_evicts_tombstones_first_under_cap() {
        // The repost cap (`MAX_REPOSTS`) is enforced post-merge by
        // `truncate_reposts` — a function of the key set, so it must be
        // deterministic and order-independent. The tombstone-first rule keeps
        // the active-repost set intact under pressure: un-reposts (tombstones)
        // and the largest reposter keys are dropped before any active repost.
        //
        // Test plan: build a synthetic shard with MAX_REPOSTS active reposts +
        // K tombstones, run normalize, assert (1) size == MAX_REPOSTS, (2) every
        // surviving record is active (`reposted == true`).
        let mut shard = ThreadShard::default();

        // MAX_REPOSTS active records.
        for i in 0..MAX_REPOSTS {
            let key = format!("active_{i:08}");
            shard.reposts.insert(
                key.clone(),
                RepostRecord {
                    signer_pubkey: key,
                    seq: 1,
                    reposted: true,
                    writer_cert: None,
                    signature: None,
                },
            );
        }
        // Add 32 tombstones on top, pushing total to MAX_REPOSTS + 32.
        for i in 0..32 {
            let key = format!("tombstone_{i:08}");
            shard.reposts.insert(
                key.clone(),
                RepostRecord {
                    signer_pubkey: key,
                    seq: 1,
                    reposted: false,
                    writer_cert: None,
                    signature: None,
                },
            );
        }
        assert_eq!(shard.reposts.len(), MAX_REPOSTS + 32);

        truncate_reposts(&mut shard.reposts);

        assert_eq!(
            shard.reposts.len(),
            MAX_REPOSTS,
            "cap enforced exactly at MAX_REPOSTS"
        );
        for r in shard.reposts.values() {
            assert!(
                r.reposted,
                "tombstones must be evicted before any active repost survives"
            );
        }
    }
}
