//! Global index shard contract (interim public-timeline infra).
//!
//! A **single, well-known, anyone-writes** contract that collects full signed
//! [`Post`](freenet_microblogging_common::post::Post)s so a client can render a
//! network-wide "recent posts" home (e.g. for an unregistered user) from one
//! GET. Unlike the per-owner user shard and the per-root thread shard, this is a
//! **fixed-key singleton**: its parameters are empty, so its key is
//! `blake3(global_index_shard_wasm || <empty>)` — one instance for the whole
//! network. Writes are opt-in on the client (a post enters here only when the
//! author ticks "share to public timeline"); the contract itself enforces no
//! such policy — it accepts any self-verifying post.
//!
//! ## Write authority (anyone-writes, UNSCOPED)
//!
//! Like the thread shard, any party may write, and each entry **self-verifies**
//! — a [`Post`] carries a content-addressed id and an ML-DSA-65 signature over
//! its canonical payload, re-checked via [`Post::verify`] on every path that can
//! enter state. Verification proves *who* signed, not that the signer is
//! *allowed*. **Unlike** the thread shard there is no root/thread binding to
//! scope writes: the global index is a flat firehose, so the only thing that
//! distinguishes an acceptable post is that it self-verifies. Constraining *who*
//! may write is the abuse question ADR-0001 leaves to a credential mechanism
//! (GhostKey is the candidate); the [`WriterCert`] wire slot is reserved and
//! checked by [`verify_writer_cert`], which accepts everything today.
//!
//! ## Convergence (every rule order-independent — AGENTS.md → "Contract
//! correctness invariants")
//!
//! * **posts** — grow-set deduped by content-address id, truncated post-merge to
//!   the newest [`MAX_INDEX_POSTS`] by `(timestamp, id)` desc (a total order; no
//!   clock in a contract). Identical to the thread shard's `replies` surface.
//!
//! `validate_state` checks self-verification + content-address keying, but
//! deliberately does **not** enforce the cap: a transiently over-bound merged
//! state is normal, and rejecting it would break convergence.
//!
//! ## What the index may contain (note for the read/render PR)
//!
//! Acceptance is self-verification ONLY — there is no `reply_to`/`quoted_post`
//! check (see [`post_is_acceptable`]). So a *reply* or *quote* `Post` that
//! self-verifies is a valid index entry as far as the contract is concerned.
//! Today the only writer (the web client's opt-in "share to public timeline")
//! shares **top-level** posts only — the quote path never opts in and the toggle
//! is plain-compose-only — so in practice the index holds top-level posts. But
//! the contract does not enforce that, so a future "Today on Freenet" home that
//! wants a strictly top-level timeline must filter on `reply_to.is_empty()` at
//! render time rather than assume the index is reply-free.

use freenet_microblogging_common::post::Post;
use freenet_microblogging_common::thread::WriterCert;
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Cap on retained global-index posts. This is the public network-wide firehose
/// — anyone-writes with **no** per-thread scoping — so a flood's blast radius is
/// larger than a per-thread reply set (thread `MAX_REPLIES` = 500). Deliberately
/// bounded: interim infra for a recent-N home, not durable history (ADR-0001 →
/// "Durable history is not Raven's job").
///
/// SPAM/ABUSE: anyone-writes + UNSCOPED. Only (a) this cap (a flood evicts older
/// genuine posts — lossy, like the user-shard post window) and (b) the future
/// writer-credential gate ([`verify_writer_cert`], vacuous today) bound abuse.
/// `verify()` proves WHO signed, not that the signer is ALLOWED — the same
/// posture the thread shard documents; the global index simply has no root to
/// scope it.
///
/// Under `cfg(test)` the cap is shrunk to a small value so the truncation tests
/// exercise the *order-independence* property (the thing under test) without
/// signing thousands of ML-DSA-65 posts — each signature is ~ms, so a 2000-cap
/// truncation test signs >4000 posts and dominates wall-time. The truncation
/// logic is independent of the cap's magnitude, so a small cap proves the same
/// invariant; `cap_matches_production_value` pins the real value separately.
#[cfg(not(test))]
const MAX_INDEX_POSTS: usize = 2000;
#[cfg(test)]
const MAX_INDEX_POSTS: usize = 64;

/// Global index state: the recent network-wide posts.
///
/// Each post is stored as the **full signed `Post`**, not a stripped view: this
/// is a public-write surface, so the contract must assume adversarial
/// `UpdateData` and re-verify a post's signature on *every* path it can enter
/// state (delta, full-state merge, sync delta) — exactly as the thread shard
/// does for replies. Retaining the signature is what lets `validate_state`
/// re-prove a post and makes a forged/overwritten post (any peer, no key)
/// impossible.
#[derive(Serialize, Deserialize, Default)]
struct GlobalIndexShard {
    // Schema-tolerance: default so older/newer wire shapes still decode
    // (AGENTS.md → "Contract migration").
    /// Posts keyed by content-addressed id (`BTreeMap` for deterministic
    /// serialization).
    #[serde(default)]
    posts: BTreeMap<String, Post>,
}

impl<'a> TryFrom<State<'a>> for GlobalIndexShard {
    type Error = ContractError;

    fn try_from(value: State<'a>) -> Result<Self, Self::Error> {
        serde_json::from_slice(value.as_ref()).map_err(|_| ContractError::InvalidState)
    }
}

/// A single global-index delta operation. Externally tagged so the wire form is
/// unambiguous and new surfaces can be added without colliding.
#[derive(Serialize, Deserialize)]
enum GlobalIndexDelta {
    /// One or more self-signed top-level `Post`s to index.
    Posts(Vec<Post>),
}

/// The writer-credential seam (ADR-0001 abuse model). Today it accepts every
/// writer — `WriterCert` is a reserved wire slot, not yet a policy. When a real
/// credential (GhostKey) lands, gate writes here. Mirrors the thread shard.
fn verify_writer_cert(_cert: Option<&WriterCert>) -> bool {
    true
}

/// Whether a post is acceptable in the global index: within the length bound,
/// self-verifying (content-address id + ML-DSA-65 signature), and (vacuously
/// today) carrying an acceptable writer credential.
///
/// **Unlike** the thread shard there is intentionally **no** thread/root binding
/// check — the global index is a flat firehose, so any self-verifying post is
/// eligible regardless of whether it is a reply, quote, or top-level post.
fn post_is_acceptable(post: &Post) -> bool {
    post.within_bounds() && post.verify().is_ok() && verify_writer_cert(None)
}

/// Truncate posts to the newest `MAX_INDEX_POSTS` by `(timestamp, id)` desc — a
/// total order, so every replica retains the identical set regardless of arrival
/// order. Post-merge only (AGENTS.md → "bounded surfaces must truncate
/// post-merge"). Best-effort lossy, like the thread shard's reply window.
fn truncate_posts(posts: &mut BTreeMap<String, Post>) {
    if posts.len() <= MAX_INDEX_POSTS {
        return;
    }
    let mut keys: Vec<(u64, String)> = posts
        .iter()
        .map(|(id, p)| (p.timestamp, id.clone()))
        .collect();
    // Newest first: timestamp desc, then id desc as a stable total tie-break.
    keys.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    for (_, id) in keys.into_iter().skip(MAX_INDEX_POSTS) {
        posts.remove(&id);
    }
}

/// Normalize a merged state: enforce the cap post-merge. Pure function of the
/// accumulated set.
fn normalize(shard: &mut GlobalIndexShard) {
    truncate_posts(&mut shard.posts);
}

/// Apply one decoded `GlobalIndexDelta` to the shard. Unacceptable entries are
/// skipped (not fatal), the same tolerance the other shards use for a bad post
/// in a batch.
fn apply_index_delta(shard: &mut GlobalIndexShard, delta: GlobalIndexDelta) {
    match delta {
        GlobalIndexDelta::Posts(posts) => {
            for post in posts {
                if post_is_acceptable(&post) {
                    // Dedup by content-addressed id: a content address is stable,
                    // so re-inserting the same post is idempotent.
                    shard.posts.entry(post.id.clone()).or_insert(post);
                }
            }
        }
    }
}

/// Try the tagged `GlobalIndexDelta` form first, then a `GlobalIndexStateDelta`
/// (what `get_state_delta` ships), then a bare `Vec<Post>` (backward tolerance),
/// then a full `GlobalIndexShard` (state-as-delta).
///
/// Order matters: `GlobalIndexStateDelta`'s field is `#[serde(default)]`, so it
/// would also accept a bare `{}`; `GlobalIndexDelta` (externally tagged, no
/// defaults) is tried first so a real tagged delta is never mis-decoded as an
/// empty state-delta. Mirrors the thread shard's decode discipline.
fn apply_delta_bytes(shard: &mut GlobalIndexShard, bytes: &[u8]) -> Result<(), ContractError> {
    if let Ok(delta) = serde_json::from_slice::<GlobalIndexDelta>(bytes) {
        apply_index_delta(shard, delta);
        return Ok(());
    }
    if let Ok(sd) = serde_json::from_slice::<GlobalIndexStateDelta>(bytes) {
        apply_state_delta(shard, sd);
        return Ok(());
    }
    if let Ok(posts) = serde_json::from_slice::<Vec<Post>>(bytes) {
        apply_index_delta(shard, GlobalIndexDelta::Posts(posts));
        return Ok(());
    }
    let other = serde_json::from_slice::<GlobalIndexShard>(bytes)
        .map_err(|_| ContractError::InvalidDelta)?;
    merge_state(shard, other);
    Ok(())
}

/// Apply a `GlobalIndexStateDelta` (the sync delta from `get_state_delta`). Each
/// post is a full self-verifying record, re-checked here — a post is never
/// trusted on the sender's say-so (the sender may be adversarial).
fn apply_state_delta(shard: &mut GlobalIndexShard, sd: GlobalIndexStateDelta) {
    for post in sd.posts {
        if post_is_acceptable(&post) {
            shard.posts.entry(post.id.clone()).or_insert(post);
        }
    }
}

/// Full-state merge: fold every post of `other` into `shard` under the same
/// acceptance rule as a delta, so a peer syncing its latest state reconciles the
/// posts surface. Every entry is re-verified — `other` came over the wire from a
/// possibly-adversarial peer, so "it was already validated upstream" is not an
/// assumption the contract may make (review CRITICAL / M-1).
fn merge_state(shard: &mut GlobalIndexShard, other: GlobalIndexShard) {
    for (id, post) in other.posts {
        if post_is_acceptable(&post) {
            shard.posts.entry(id).or_insert(post);
        }
    }
}

#[contract]
impl ContractInterface for GlobalIndexShard {
    fn validate_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts,
    ) -> Result<ValidateResult, ContractError> {
        let shard = GlobalIndexShard::try_from(state)?;

        // Every post must self-verify, fit the length bound, and key under its
        // own content address (no duplicates / no misfiled id). update_state
        // guarantees these, so validate_state must reject any state violating
        // them (AGENTS.md → "validate agrees with update"). The singleton's
        // empty parameters are deliberately ignored — there is no root binding.
        for (id, post) in &shard.posts {
            if id != &post.id || !post_is_acceptable(post) {
                return Err(ContractError::InvalidState);
            }
        }
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        delta: Vec<UpdateData>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let mut shard = GlobalIndexShard::try_from(state)?;

        // Iterate EVERY update item (not just the first), dispatching per kind.
        for item in &delta {
            match item {
                UpdateData::Delta(d) => apply_delta_bytes(&mut shard, d.as_ref())?,
                UpdateData::State(s) => {
                    let other = GlobalIndexShard::try_from(State::from(s.to_vec()))?;
                    merge_state(&mut shard, other);
                }
                UpdateData::StateAndDelta { state: s, delta: d } => {
                    let other = GlobalIndexShard::try_from(State::from(s.to_vec()))?;
                    merge_state(&mut shard, other);
                    apply_delta_bytes(&mut shard, d.as_ref())?;
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
        let shard = GlobalIndexShard::try_from(state)?;
        // Summary = the post key set, so get_state_delta can compute what the
        // requester is missing. Keys are deterministic (BTreeMap order).
        let summary = GlobalIndexSummary {
            posts: shard.posts.keys().cloned().collect(),
        };
        let bytes =
            serde_json::to_vec(&summary).map_err(|e| ContractError::Other(format!("{e}")))?;
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let shard = GlobalIndexShard::try_from(state)?;
        let have: GlobalIndexSummary = serde_json::from_slice(summary.as_ref()).unwrap_or_default();
        let have_posts: std::collections::HashSet<&String> = have.posts.iter().collect();

        // Posts the requester lacks. Ship the **full signed record** so the
        // receiver re-verifies it (a sync delta is no more trusted than any other
        // delta — review CRITICAL / MIN-1).
        let missing_posts: Vec<Post> = shard
            .posts
            .iter()
            .filter(|(id, _)| !have_posts.contains(id))
            .map(|(_, p)| p.clone())
            .collect();

        let delta = GlobalIndexStateDelta {
            posts: missing_posts,
        };
        let bytes = serde_json::to_vec(&delta).map_err(|e| ContractError::Other(format!("{e}")))?;
        Ok(StateDelta::from(bytes))
    }
}

/// Summary shape: the key set the requester already holds, so `get_state_delta`
/// can ship only what is missing.
#[derive(Serialize, Deserialize, Default)]
struct GlobalIndexSummary {
    #[serde(default)]
    posts: Vec<String>,
}

/// The delta `get_state_delta` ships: the missing posts, each a full
/// self-verifying record. It is intentionally NOT a `GlobalIndexDelta` so the
/// sync surface can evolve independently of the externally-tagged write delta;
/// `apply_delta_bytes` decodes it via `apply_state_delta`, which re-verifies each
/// entry — a sync delta is no more trusted than any other.
#[derive(Serialize, Deserialize, Default)]
struct GlobalIndexStateDelta {
    #[serde(default)]
    posts: Vec<Post>,
}

#[cfg(test)]
mod test {
    use super::*;
    use freenet_microblogging_common::post::MAX_CONTENT_LEN;
    use ml_dsa::KeyGen;
    use ml_dsa::signature::{Keypair, Signer};
    use ml_dsa::{MlDsa65, Signature};

    /// Empty parameters — the singleton instance.
    fn params() -> Parameters<'static> {
        Parameters::from(Vec::new())
    }

    /// A signed top-level post (no reply_to / quoted_post).
    fn signed_post(seed: [u8; 32], content: &str, ts: u64) -> Post {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut p = Post {
            id: String::new(),
            author_pubkey: hex::encode(sk.verifying_key().encode()),
            author_name: "Alice".into(),
            author_handle: "@alice".into(),
            content: content.into(),
            timestamp: ts,
            reply_to: String::new(),
            quoted_post: String::new(),
            signature: None,
        };
        p.id = p.compute_id();
        let sig: Signature<MlDsa65> = sk.sign(&p.signing_payload());
        p.signature = Some(hex::encode(sig.encode()));
        p
    }

    fn state_of(shard: &GlobalIndexShard) -> State<'static> {
        State::from(serde_json::to_vec(shard).unwrap())
    }

    fn delta_item(d: &GlobalIndexDelta) -> UpdateData<'static> {
        UpdateData::Delta(StateDelta::from(serde_json::to_vec(d).unwrap()))
    }

    fn run_update(shard: GlobalIndexShard, items: Vec<UpdateData<'static>>) -> GlobalIndexShard {
        let res = GlobalIndexShard::update_state(params(), state_of(&shard), items).unwrap();
        serde_json::from_slice(res.unwrap_valid().as_ref()).unwrap()
    }

    #[test]
    fn test_cap_does_not_exceed_production() {
        // The cap is shrunk under cfg(test) (see MAX_INDEX_POSTS) so truncation
        // tests stay cheap. Guard that the test override never silently exceeds
        // the production value — keep in sync with the `#[cfg(not(test))]` const
        // above. `std::hint::black_box` keeps both sides out of const-folding so
        // this is a real runtime check (clippy::assertions_on_constants).
        let production = std::hint::black_box(2000usize);
        let test_cap = std::hint::black_box(MAX_INDEX_POSTS);
        assert!(
            test_cap <= production,
            "test cap {test_cap} must not exceed the production cap {production}"
        );
    }

    #[test]
    fn post_accepted_when_self_verifying() {
        let p = signed_post([1u8; 32], "hello network", 100);
        let out = run_update(
            GlobalIndexShard::default(),
            vec![delta_item(&GlobalIndexDelta::Posts(vec![p.clone()]))],
        );
        assert_eq!(out.posts.len(), 1);
        assert!(out.posts.contains_key(&p.id));
    }

    #[test]
    fn post_rejected_when_not_self_verifying() {
        // Tamper with content after signing → id no longer matches → rejected.
        let mut bad = signed_post([1u8; 32], "hello", 100);
        bad.content = "tampered".into();
        let out = run_update(
            GlobalIndexShard::default(),
            vec![delta_item(&GlobalIndexDelta::Posts(vec![bad]))],
        );
        assert!(out.posts.is_empty());
    }

    #[test]
    fn posts_dedup_by_content_address() {
        let p = signed_post([1u8; 32], "dup", 100);
        let out = run_update(
            GlobalIndexShard::default(),
            vec![delta_item(&GlobalIndexDelta::Posts(vec![
                p.clone(),
                p.clone(),
            ]))],
        );
        assert_eq!(out.posts.len(), 1);
    }

    #[test]
    fn oversized_content_rejected() {
        // A post over MAX_CONTENT_LEN must be rejected even if otherwise signed.
        // Sign it honestly so only the length bound can reject it.
        let big = "x".repeat(MAX_CONTENT_LEN + 1);
        let p = signed_post([1u8; 32], &big, 100);
        assert_eq!(p.verify(), Ok(()));
        let out = run_update(
            GlobalIndexShard::default(),
            vec![delta_item(&GlobalIndexDelta::Posts(vec![p]))],
        );
        assert!(out.posts.is_empty());
    }

    #[test]
    fn oversized_author_name_rejected() {
        // author_name/author_handle are author-chosen and self-verifying, so a
        // signature alone does not bound them — only `within_bounds()` does.
        // The global index is the most widely replicated state in the system,
        // so an unbounded write here is an unbounded write primitive.
        let mut p = signed_post([1u8; 32], "hi", 100);
        p.author_name = "x".repeat(freenet_microblogging_common::post::MAX_AUTHOR_NAME_LEN + 1);
        p.id = p.compute_id();
        let sk = MlDsa65::from_seed(&[1u8; 32].into());
        let sig: Signature<MlDsa65> = sk.sign(&p.signing_payload());
        p.signature = Some(hex::encode(sig.encode()));
        assert_eq!(p.verify(), Ok(()));
        let out = run_update(
            GlobalIndexShard::default(),
            vec![delta_item(&GlobalIndexDelta::Posts(vec![p]))],
        );
        assert!(out.posts.is_empty());
    }

    #[test]
    fn oversized_quoted_post_ref_rejected() {
        // reply_to/quoted_post are just as author-chosen as author_name — a
        // signature alone does not bound them either.
        let mut p = signed_post([1u8; 32], "hi", 100);
        p.quoted_post = "x".repeat(freenet_microblogging_common::post::MAX_POST_REF_LEN + 1);
        p.id = p.compute_id();
        let sk = MlDsa65::from_seed(&[1u8; 32].into());
        let sig: Signature<MlDsa65> = sk.sign(&p.signing_payload());
        p.signature = Some(hex::encode(sig.encode()));
        assert_eq!(p.verify(), Ok(()));
        let out = run_update(
            GlobalIndexShard::default(),
            vec![delta_item(&GlobalIndexDelta::Posts(vec![p]))],
        );
        assert!(out.posts.is_empty());
    }

    #[test]
    fn empty_params_singleton_accepts_posts() {
        // INVERSE of the thread shard's `empty_root_param_accepts_nothing`: the
        // global index is a singleton with empty parameters BY DESIGN, and it
        // DOES accept self-verifying posts (no root binding to fail).
        let p = signed_post([2u8; 32], "from the singleton", 100);
        let res = GlobalIndexShard::update_state(
            Parameters::from(Vec::new()),
            state_of(&GlobalIndexShard::default()),
            vec![delta_item(&GlobalIndexDelta::Posts(vec![p]))],
        )
        .unwrap();
        let out: GlobalIndexShard = serde_json::from_slice(res.unwrap_valid().as_ref()).unwrap();
        assert_eq!(out.posts.len(), 1);
    }

    #[test]
    fn posts_truncate_deterministically() {
        // Build > MAX_INDEX_POSTS posts across two orderings; both retain the same
        // newest-by-(timestamp,id) set. (Distinct content+timestamp → distinct
        // content-address ids.)
        let n = MAX_INDEX_POSTS + 25;
        let mut posts: Vec<Post> = (0..n)
            .map(|i| signed_post([1u8; 32], &format!("c{i}"), 1000 + i as u64))
            .collect();
        let items_fwd: Vec<Post> = posts.clone();
        posts.reverse();
        let items_rev: Vec<Post> = posts;

        let a = run_update(
            GlobalIndexShard::default(),
            vec![delta_item(&GlobalIndexDelta::Posts(items_fwd))],
        );
        let b = run_update(
            GlobalIndexShard::default(),
            vec![delta_item(&GlobalIndexDelta::Posts(items_rev))],
        );
        assert_eq!(a.posts.len(), MAX_INDEX_POSTS);
        assert_eq!(
            a.posts.keys().collect::<Vec<_>>(),
            b.posts.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn forged_post_via_full_state_merge_rejected() {
        // A peer ships a full GlobalIndexShard whose post does not verify (content
        // flipped after signing); merge_state must re-verify and drop it
        // (public-write surface).
        let mut forged = signed_post([2u8; 32], "real", 100);
        forged.content = "forged".into(); // breaks the id/signature
        let mut malicious = GlobalIndexShard::default();
        malicious.posts.insert(forged.id.clone(), forged);
        let out = run_update(
            GlobalIndexShard::default(),
            vec![UpdateData::State(State::from(
                serde_json::to_vec(&malicious).unwrap(),
            ))],
        );
        assert!(out.posts.is_empty());
    }

    #[test]
    fn validate_rejects_forged_post_state() {
        // validate_state must reject a state carrying a post that does not
        // self-verify, so it agrees with update_state.
        let mut forged = signed_post([2u8; 32], "real", 100);
        let key = forged.id.clone();
        forged.content = "forged".into(); // break signature, keep the (now stale) key
        let mut shard = GlobalIndexShard::default();
        shard.posts.insert(key, forged);
        let res = GlobalIndexShard::validate_state(
            params(),
            state_of(&shard),
            RelatedContracts::default(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn validate_rejects_misfiled_post_id() {
        let mut shard = GlobalIndexShard::default();
        let p = signed_post([1u8; 32], "x", 100);
        // File it under the wrong key.
        shard.posts.insert("wrong_key".into(), p);
        let res =
            GlobalIndexShard::validate_state(params(), state_of(&shard), RelatedContracts::new());
        assert!(!matches!(res, Ok(ValidateResult::Valid)));
    }

    #[test]
    fn validate_accepts_well_formed_state() {
        let mut shard = GlobalIndexShard::default();
        let p = signed_post([1u8; 32], "x", 100);
        shard.posts.insert(p.id.clone(), p);
        let res =
            GlobalIndexShard::validate_state(params(), state_of(&shard), RelatedContracts::new())
                .unwrap();
        assert!(matches!(res, ValidateResult::Valid));
    }

    #[test]
    fn state_and_delta_merges_both() {
        // One update item carrying a full state AND a delta: update_state must
        // merge_state THEN apply the delta, so a post from each is present.
        let mut src = GlobalIndexShard::default();
        let from_state = signed_post([1u8; 32], "from-state", 100);
        src.posts.insert(from_state.id.clone(), from_state.clone());
        let from_delta = signed_post([3u8; 32], "from-delta", 200);
        let delta = serde_json::to_vec(&GlobalIndexDelta::Posts(vec![from_delta.clone()])).unwrap();

        let out = run_update(
            GlobalIndexShard::default(),
            vec![UpdateData::StateAndDelta {
                state: state_of(&src),
                delta: StateDelta::from(delta),
            }],
        );
        assert_eq!(out.posts.len(), 2);
        assert!(out.posts.contains_key(&from_state.id));
        assert!(out.posts.contains_key(&from_delta.id));
        // Invariant: every post keyed under its own content address.
        for (id, post) in &out.posts {
            assert_eq!(id, &post.id);
        }
    }

    #[test]
    fn get_state_delta_output_is_applyable() {
        // Regression: get_state_delta ships a GlobalIndexStateDelta;
        // apply_delta_bytes must decode and apply it (round-trip), or peers never
        // sync.
        let mut src = GlobalIndexShard::default();
        let p = signed_post([1u8; 32], "p", 100);
        src.posts.insert(p.id.clone(), p);

        let empty_summary =
            StateSummary::from(serde_json::to_vec(&GlobalIndexSummary::default()).unwrap());
        let delta =
            GlobalIndexShard::get_state_delta(params(), state_of(&src), empty_summary).unwrap();

        let out = run_update(
            GlobalIndexShard::default(),
            vec![UpdateData::Delta(StateDelta::from(
                delta.into_bytes().to_vec(),
            ))],
        );
        assert_eq!(out.posts.len(), 1);
    }

    #[test]
    fn decodes_old_shape_state() {
        let empty: GlobalIndexShard = serde_json::from_slice(b"{}").unwrap();
        assert!(empty.posts.is_empty());
        let forward: GlobalIndexShard =
            serde_json::from_slice(br#"{"posts":{},"version":2}"#).unwrap();
        assert!(forward.posts.is_empty());
    }
}

/// Integration tests: drive the full `ContractInterface` (validate / update /
/// summarize / get_state_delta) through multi-replica, multi-author scenarios —
/// the layer above the per-function unit tests. The key scenario is **two
/// replicas reconciling via the real sync protocol** (`summarize_state` →
/// `get_state_delta` → `update_state`).
///
/// These still call the contract as a Rust library (not compiled WASM in a
/// node); true WASM-in-node e2e is a separate, heavier tier (see the
/// `freenet:linux-test` skill and issue #34).
#[cfg(test)]
mod integration {
    use super::*;
    use ml_dsa::signature::{Keypair, Signer};
    use ml_dsa::{KeyGen, MlDsa65, Signature};

    fn params() -> Parameters<'static> {
        Parameters::from(Vec::new())
    }

    fn state_of(shard: &GlobalIndexShard) -> State<'static> {
        State::from(serde_json::to_vec(shard).unwrap())
    }

    fn decode(state: State<'static>) -> GlobalIndexShard {
        serde_json::from_slice(state.as_ref()).unwrap()
    }

    /// A signed top-level post by the author with `seed`.
    fn post(seed: [u8; 32], content: &str, ts: u64) -> Post {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut p = Post {
            id: String::new(),
            author_pubkey: hex::encode(sk.verifying_key().encode()),
            author_name: "Author".into(),
            author_handle: "@author".into(),
            content: content.into(),
            timestamp: ts,
            reply_to: String::new(),
            quoted_post: String::new(),
            signature: None,
        };
        p.id = p.compute_id();
        let sig: Signature<MlDsa65> = sk.sign(&p.signing_payload());
        p.signature = Some(hex::encode(sig.encode()));
        p
    }

    fn apply(shard: &GlobalIndexShard, items: Vec<UpdateData<'static>>) -> GlobalIndexShard {
        let res = GlobalIndexShard::update_state(params(), state_of(shard), items).unwrap();
        decode(res.unwrap_valid())
    }

    fn delta(d: &GlobalIndexDelta) -> UpdateData<'static> {
        UpdateData::Delta(StateDelta::from(serde_json::to_vec(d).unwrap()))
    }

    /// One directional sync step, faithful to the node protocol: `dst` summarizes
    /// what it has, `src` computes the delta of what `dst` is missing, `dst`
    /// applies it. Every state must stay valid before and after.
    fn sync_into(dst: &GlobalIndexShard, src: &GlobalIndexShard) -> GlobalIndexShard {
        assert!(matches!(
            GlobalIndexShard::validate_state(params(), state_of(dst), RelatedContracts::new())
                .unwrap(),
            ValidateResult::Valid
        ));
        let summary = GlobalIndexShard::summarize_state(params(), state_of(dst)).unwrap();
        let d = GlobalIndexShard::get_state_delta(params(), state_of(src), summary).unwrap();
        let merged = apply(
            dst,
            vec![UpdateData::Delta(StateDelta::from(d.into_bytes().to_vec()))],
        );
        assert!(matches!(
            GlobalIndexShard::validate_state(params(), state_of(&merged), RelatedContracts::new())
                .unwrap(),
            ValidateResult::Valid
        ));
        merged
    }

    /// Full bidirectional reconcile: sync each way once. For these state sizes a
    /// single round each direction converges. Returns `(a', b')`, which must be
    /// equal.
    fn reconcile(
        a: &GlobalIndexShard,
        b: &GlobalIndexShard,
    ) -> (GlobalIndexShard, GlobalIndexShard) {
        let a2 = sync_into(a, b);
        let b2 = sync_into(b, a);
        (a2, b2)
    }

    fn canonical(shard: &GlobalIndexShard) -> Vec<u8> {
        serde_json::to_vec(shard).unwrap()
    }

    #[test]
    fn two_replicas_converge_over_sync_protocol() {
        // A and B each see a disjoint set of posts from different authors, then
        // reconcile via summarize/get_state_delta/update_state. They must reach
        // byte-identical state.
        let empty = GlobalIndexShard::default();
        let a = apply(
            &empty,
            vec![delta(&GlobalIndexDelta::Posts(vec![
                post([1; 32], "a-post", 100),
                post([2; 32], "a-post-2", 110),
            ]))],
        );
        let b = apply(
            &empty,
            vec![delta(&GlobalIndexDelta::Posts(vec![post(
                [4; 32], "b-post", 200,
            )]))],
        );

        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(canonical(&a2), canonical(&b2), "replicas must converge");
        assert_eq!(a2.posts.len(), 3, "union of all posts present on both");
    }

    #[test]
    fn forged_post_does_not_propagate_over_sync() {
        // A holds a forged (tampered) post in its state. When an honest replica
        // syncs from A, the forged post rides in the delta but update_state
        // re-verifies and drops it — a malicious replica cannot inject a post.
        let mut tampered = post([9; 32], "real", 100);
        tampered.content = "forged".into(); // breaks id/signature
        let mut malicious = GlobalIndexShard::default();
        malicious.posts.insert(tampered.id.clone(), tampered);

        let honest = GlobalIndexShard::default();
        let synced = sync_into(&honest, &malicious);
        assert!(
            synced.posts.is_empty(),
            "honest replica must reject forged post over sync"
        );
    }

    #[test]
    fn truncation_is_order_independent_over_sync() {
        // Both replicas push > MAX_INDEX_POSTS posts (overlapping ranges from the
        // same author, distinct by content+timestamp). After reconcile both hold
        // the identical newest-N set.
        let empty = GlobalIndexShard::default();
        let half = MAX_INDEX_POSTS;
        let a_posts: Vec<Post> = (0..half + 30)
            .map(|i| post([1; 32], &format!("a{i}"), 1000 + i as u64))
            .collect();
        let b_posts: Vec<Post> = (0..half + 30)
            .map(|i| post([1; 32], &format!("b{i}"), 5000 + i as u64))
            .collect();
        let a = apply(&empty, vec![delta(&GlobalIndexDelta::Posts(a_posts))]);
        let b = apply(&empty, vec![delta(&GlobalIndexDelta::Posts(b_posts))]);

        let (a2, b2) = reconcile(&a, &b);
        assert_eq!(
            canonical(&a2),
            canonical(&b2),
            "converge under cap pressure"
        );
        assert_eq!(a2.posts.len(), MAX_INDEX_POSTS, "cap enforced exactly");
    }
}
