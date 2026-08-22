//! Generic owner-signed operation envelope for non-`Post` user-shard mutations
//! (ADR-0001 → "User shard", owner-writes).
//!
//! A [`Post`](crate::post::Post) is self-signed and content-addressed, so the
//! contract proves owner-authorship directly from the post. Profile updates and
//! follow-set edits are **not** posts — they carry no intrinsic signature — so
//! the owner wraps each such mutation in a [`SignedOp`]: an ML-DSA-65 signature
//! over a deterministic, length-prefixed payload (the same encoding discipline
//! as `Post::signing_payload`, never `serde_json`).
//!
//! `update_state` verifies the signature **and** that `signer_pubkey` equals the
//! shard's owner VK — exactly the VK-param match that makes posts owner-writes.
//! The `seq` field carries a monotonic counter so register-style surfaces
//! (profile) can resolve concurrent writes last-write-wins without a clock,
//! which a contract does not have.

use ml_dsa::signature::Verifier;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Domain-separation tag mixed into every `SignedOp` payload, distinct from
/// `POST_DOMAIN_TAG`, so an op signature can never be replayed as a post
/// signature (or vice versa) even if the inner bytes coincide.
pub const SIGNED_OP_DOMAIN_TAG: &[u8] = b"raven:signed-op:v1";

/// Why a [`SignedOp`] failed verification.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// `signer_pubkey` was not valid hex or not a valid ML-DSA-65 VK.
    BadPublicKey,
    /// `signature` was not valid hex or not a valid ML-DSA-65 signature.
    BadSignature,
    /// `signer_pubkey` did not equal the expected owner VK.
    NotOwner,
    /// Signature did not verify against `signer_pubkey`.
    SignatureInvalid,
}

/// What surface an op mutates. Part of the signed payload, so an op signed for
/// one surface cannot be replayed against another.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpType {
    /// Replace the shard's profile register (last-write-wins by `seq`).
    Profile,
    /// Add one or more pubkeys to the follow set.
    Follow,
    /// Remove one or more pubkeys from the follow set.
    Unfollow,
    /// Inbox shard: prune the explicit notification ids carried in `payload`
    /// (a length-prefixed list of hex notif ids). Owner-only.
    PruneIds,
    /// Inbox shard: advance the inbox high-water mark to `seq`, dropping every
    /// notification whose own `seq` is strictly below it. `payload` is empty.
    /// Owner-only.
    PruneBefore,
    /// Retract one or more posts the signer authored. `payload` is a
    /// length-prefixed list of content-addressed post ids (see
    /// [`encode_id_list`]).
    ///
    /// A retraction is not a delete and the type is named so it cannot be
    /// mistaken for one. On a P2P network no contract can reach an offline
    /// replica or an archive; what it can do is stop serving the post and
    /// refuse to re-accept it on merge. The honest claim is "the author
    /// withdrew this", not "this never existed".
    ///
    /// The tombstone is CONDITIONAL, which is what makes it safe on a
    /// shared surface: it applies to a post only when the retracting signer is
    /// that post's own author. Retracting somebody else's id — or
    /// pre-emptively retracting an id before the post arrives — is inert.
    RetractPost,
}

impl OpType {
    /// Stable byte tag for the signing payload. Explicit (not the serde repr)
    /// so the signed bytes never shift if the enum is reordered/extended.
    fn tag(self) -> &'static [u8] {
        match self {
            OpType::Profile => b"profile",
            OpType::Follow => b"follow",
            OpType::Unfollow => b"unfollow",
            OpType::PruneIds => b"prune-ids",
            OpType::PruneBefore => b"prune-before",
            OpType::RetractPost => b"retract-post",
        }
    }
}

/// An owner-signed mutation envelope.
///
/// Schema-tolerance: additive fields must carry `#[serde(default, …)]` so older
/// wire shapes still decode (AGENTS.md → "Contract migration").
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedOp {
    /// Which surface this op mutates.
    pub op_type: OpType,
    /// Opaque application payload (e.g. a serialized `Profile`, or the set of
    /// pubkeys to add/remove). Interpreted by the contract per `op_type`; signed
    /// verbatim here so the contract can trust it.
    pub payload: Vec<u8>,
    /// Monotonic per-owner counter. Register surfaces (profile) keep the op with
    /// the highest `seq`; set surfaces (follow/unfollow) ignore it. Part of the
    /// signed payload so it cannot be forged to win a last-write-wins race.
    pub seq: u64,
    /// Hex-encoded ML-DSA-65 verifying key of the signer (must be the owner).
    pub signer_pubkey: String,
    /// Hex-encoded ML-DSA-65 signature over [`SignedOp::signing_payload`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl SignedOp {
    /// The exact bytes signed and verified: a length-prefixed concatenation of
    /// the domain tag, the shard `context`, op-type tag, payload, seq, and signer
    /// key. Deterministic across builds; `signature` is excluded (it is derived
    /// from this).
    ///
    /// `context` binds the op to a specific shard *type* (e.g. the user shard),
    /// so an op signed for one shard cannot be replayed into a different shard
    /// that also uses `SignedOp`. Each shard contract passes its own constant
    /// (e.g. [`USER_SHARD_CONTEXT`]); the same `context` must be passed to
    /// [`SignedOp::verify`].
    pub fn signing_payload(&self, context: &[u8]) -> Vec<u8> {
        fn put(buf: &mut Vec<u8>, field: &[u8]) {
            buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
            buf.extend_from_slice(field);
        }
        let mut buf = Vec::new();
        put(&mut buf, SIGNED_OP_DOMAIN_TAG);
        put(&mut buf, context);
        put(&mut buf, self.op_type.tag());
        put(&mut buf, &self.payload);
        put(&mut buf, &self.seq.to_le_bytes());
        put(&mut buf, self.signer_pubkey.as_bytes());
        buf
    }

    /// Verify the op is well-formed, bound to `context`, and signed by
    /// `expected_owner_vk_hex`. This is what a shard `update_state` calls before
    /// applying a profile or follow mutation, passing its own shard context.
    pub fn verify(&self, context: &[u8], expected_owner_vk_hex: &str) -> Result<(), VerifyError> {
        // Owner-writes: the signer must be exactly this shard's owner.
        if self.signer_pubkey != expected_owner_vk_hex {
            return Err(VerifyError::NotOwner);
        }
        let sig_hex = self.signature.as_deref().ok_or(VerifyError::BadSignature)?;

        let vk_bytes = hex::decode(&self.signer_pubkey).map_err(|_| VerifyError::BadPublicKey)?;
        let vk_encoded: EncodedVerifyingKey<MlDsa65> = vk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::BadPublicKey)?;
        let vk = VerifyingKey::<MlDsa65>::decode(&vk_encoded);

        let sig_bytes = hex::decode(sig_hex).map_err(|_| VerifyError::BadSignature)?;
        let sig_encoded: EncodedSignature<MlDsa65> = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::BadSignature)?;
        let sig = Signature::<MlDsa65>::decode(&sig_encoded).ok_or(VerifyError::BadSignature)?;

        vk.verify(&self.signing_payload(context), &sig)
            .map_err(|_| VerifyError::SignatureInvalid)
    }

    /// Whether `payload` is within its bound.
    ///
    /// [`MAX_IDS_PER_OP`] and [`MAX_ID_LEN`] bound what [`decode_id_list`] will
    /// *interpret*, not what the op *carries*: a payload of a million
    /// well-formed entries decodes to 1000 ids while the whole blob is still
    /// stored verbatim in replicated contract state. A signature does not bound
    /// it either — ML-DSA-65 signs a message of any length, so an oversized
    /// payload is perfectly valid and perfectly storable. Only this does.
    ///
    /// Same class as [`Post::within_bounds`](crate::post::Post::within_bounds),
    /// and it matters most on the global index, where retraction ops are
    /// accepted from *any* signer: there is no owner check to fall back on, so
    /// an unbounded payload there is an unbounded write primitive available to
    /// anyone with a freshly generated keypair.
    pub fn within_bounds(&self) -> bool {
        self.payload.len() <= MAX_OP_PAYLOAD_LEN
    }

    /// Content address of this op: BLAKE3 over the exact bytes the signature
    /// covers, hex-encoded.
    ///
    /// This is what retraction maps are keyed by, and the reason is
    /// convergence, not tidiness. Keying by `seq` alone does not work: `seq` is
    /// chosen client-side and is not scoped to the signer, so two *different*
    /// ops can land on the same key. Whichever reached a replica first would
    /// win there, so replicas that saw them in different orders would keep
    /// different ops — a state that no `validate_state` can detect, because
    /// each replica is internally self-consistent. On the global index, where
    /// any key may sign a retraction, that also hands an attacker a censorship
    /// primitive: file a throwaway op at the seq a victim is about to use and
    /// their real retraction is dropped everywhere it arrives second.
    ///
    /// A content address cannot collide across distinct ops and is necessarily
    /// identical for identical ones, which is exactly the union-by-key
    /// behaviour a grow-only set needs. `context` is included because it is
    /// part of the signed bytes: the same op is a different op on a different
    /// shard type.
    pub fn content_id(&self, context: &[u8]) -> String {
        hex::encode(blake3::hash(&self.signing_payload(context)).as_bytes())
    }
}

/// Maximum byte length of [`SignedOp::payload`].
///
/// Sized as the largest legitimate [`encode_id_list`] payload: [`MAX_IDS_PER_OP`]
/// entries, each a `u32` length prefix plus at most [`MAX_ID_LEN`] bytes. An op
/// larger than that cannot decode to anything the contracts will act on, so
/// there is no honest reason to carry it — and every dishonest one.
pub const MAX_OP_PAYLOAD_LEN: usize = MAX_IDS_PER_OP * (4 + MAX_ID_LEN);

/// Maximum length of a single id in an [`encode_id_list`] payload.
pub const MAX_ID_LEN: usize = 128;

/// Maximum number of ids a single op payload may carry.
pub const MAX_IDS_PER_OP: usize = 1_000;

/// Encode a list of ids as a length-prefixed (u32 LE) sequence.
///
/// Shared by every op whose payload is "a set of ids the signer names": the
/// inbox's `PruneIds` and the user shard's / global index's [`OpType::RetractPost`].
/// One encoder, because the bytes go INSIDE the signature — two implementations
/// that drift by a byte produce ops that verify on one side and not the other,
/// and the failure mode is a silent drop, not an error.
pub fn encode_id_list(ids: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    for id in ids {
        buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
        buf.extend_from_slice(id.as_bytes());
    }
    buf
}

/// Whether an [`encode_id_list`] payload carries at most [`MAX_IDS_PER_OP`] ids.
///
/// [`decode_id_list`] is deliberately TOLERANT — it stops at
/// [`MAX_IDS_PER_OP`] and returns what it parsed — so on its own it silently
/// TRUNCATES an over-long list rather than refusing it. Truncation is the wrong
/// answer at an acceptance boundary: the signer signed a list, and storing a
/// prefix of it applies part of an op the author never authorized in that form.
/// Acceptance therefore fails CLOSED on the count, using this, while
/// `decode_id_list` keeps its tolerant contract for read paths.
///
/// This is the COUNT half of the bound; [`SignedOp::within_bounds`] is the BYTE
/// half. Both are needed: a payload can be under the byte ceiling while naming
/// far too many ids, and under the id ceiling while carrying junk bytes.
pub fn id_list_count_within_bounds(payload: &[u8]) -> bool {
    let mut count = 0usize;
    let mut i = 0;
    while i + 4 <= payload.len() {
        let len = u32::from_le_bytes([payload[i], payload[i + 1], payload[i + 2], payload[i + 3]])
            as usize;
        i += 4;
        if len > MAX_ID_LEN || i + len > payload.len() {
            break;
        }
        count += 1;
        if count > MAX_IDS_PER_OP {
            return false;
        }
        i += len;
    }
    true
}

/// Decode an [`encode_id_list`] payload, capped at [`MAX_IDS_PER_OP`].
///
/// Tolerant by design: malformed input yields the ids parsed so far rather than
/// failing or panicking (AGENTS.md → "No unwrap/panic"). A truncated payload is
/// a partial list, never a crash. Acceptance paths must ALSO call
/// [`id_list_count_within_bounds`], or an over-long list is silently truncated
/// into a valid-looking op.
pub fn decode_id_list(payload: &[u8]) -> Vec<String> {
    let mut ids = Vec::new();
    let mut i = 0;
    while i + 4 <= payload.len() && ids.len() < MAX_IDS_PER_OP {
        let len = u32::from_le_bytes([payload[i], payload[i + 1], payload[i + 2], payload[i + 3]])
            as usize;
        i += 4;
        if len > MAX_ID_LEN || i + len > payload.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&payload[i..i + len]) {
            ids.push(s.to_owned());
        }
        i += len;
    }
    ids
}

/// Shard-context tag for the **user shard**, mixed into every user-shard
/// `SignedOp` signature. A future thread/inbox shard reusing `SignedOp` must
/// pass its own distinct context, so an op signed for one shard type can never
/// verify against another.
pub const USER_SHARD_CONTEXT: &[u8] = b"raven:user-shard:v1";

/// Shard-context tag for the **global index**, mixed into every retraction
/// signed against the public timeline. Distinct from the user-shard context so
/// a retraction meant for one cannot be replayed into the other — the two have
/// different authorization rules (owner-writes vs. author-conditional), so a
/// signature valid for one must not carry into the other.
pub const GLOBAL_INDEX_CONTEXT: &[u8] = b"raven:global-index:v1";

/// Shard-context tag for the **inbox shard**, mixed into every inbox-shard
/// owner-prune `SignedOp` signature. Distinct from [`USER_SHARD_CONTEXT`] so an
/// owner-prune op cannot be replayed into the user shard (or vice versa).
pub const INBOX_SHARD_CONTEXT: &[u8] = b"raven:inbox-shard:v1";

/// The profile register carried in a [`OpType::Profile`] op's payload. Bounded
/// so a malicious owner cannot bloat their own shard without limit (the only
/// blast radius for owner-writes is self-harm, but the contract still caps it).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub handle: String,
    #[serde(default)]
    pub bio: String,
    /// Avatar color or short descriptor (the UI's `avatarColor`); kept small.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub avatar: String,
}

/// Field length bounds for a [`Profile`], enforced in the contract.
pub const MAX_DISPLAY_NAME_LEN: usize = 64;
pub const MAX_HANDLE_LEN: usize = 32;
pub const MAX_BIO_LEN: usize = 280;
pub const MAX_AVATAR_LEN: usize = 64;

/// Cap on how many targets a single [`OpType::Follow`] / [`OpType::Unfollow`] op
/// may carry, so one op cannot blow the follow set in a single write. The user
/// shard rejects an over-cap op outright (fail closed, never truncate), so a
/// signer that exceeds this produces a signature the contract silently drops —
/// which is why it lives here, shared by the contract and the delegate that
/// builds the op, rather than being restated on each side.
pub const MAX_FOLLOW_TARGETS_PER_OP: usize = 1_000;

/// Maximum length of a followed-key hex string. An ML-DSA-65 verifying key is
/// 1952 bytes → 3904 hex chars. Over-long targets are skipped per-key (the op
/// itself still applies), so this is a per-target filter, not a fail-closed cap.
pub const MAX_TARGET_KEY_LEN: usize = 3904;

impl Profile {
    /// Whether every field is within its bound.
    pub fn within_bounds(&self) -> bool {
        self.display_name.len() <= MAX_DISPLAY_NAME_LEN
            && self.handle.len() <= MAX_HANDLE_LEN
            && self.bio.len() <= MAX_BIO_LEN
            && self.avatar.len() <= MAX_AVATAR_LEN
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ml_dsa::KeyGen;
    use ml_dsa::signature::{Keypair, Signer};

    const CTX: &[u8] = USER_SHARD_CONTEXT;

    fn owner_vk_hex(seed: [u8; 32]) -> String {
        let sk = MlDsa65::from_seed(&seed.into());
        hex::encode(sk.verifying_key().encode())
    }

    /// Build a fully-signed op (for context `CTX`) the way the delegate would.
    fn signed(seed: [u8; 32], op_type: OpType, payload: Vec<u8>, seq: u64) -> SignedOp {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut op = SignedOp {
            op_type,
            payload,
            seq,
            signer_pubkey: hex::encode(sk.verifying_key().encode()),
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&op.signing_payload(CTX));
        op.signature = Some(hex::encode(sig.encode()));
        op
    }

    #[test]
    fn verify_accepts_owner_signed_op() {
        let owner = owner_vk_hex([1u8; 32]);
        let op = signed([1u8; 32], OpType::Profile, b"hello".to_vec(), 1);
        assert_eq!(op.verify(CTX, &owner), Ok(()));
    }

    #[test]
    fn verify_rejects_non_owner_signer() {
        // A DIFFERENT valid key signs a well-formed op; against the owner VK it
        // is NotOwner (checked before the crypto).
        let owner = owner_vk_hex([1u8; 32]);
        let op = signed([2u8; 32], OpType::Profile, b"hello".to_vec(), 1);
        assert_eq!(op.verify(CTX, &owner), Err(VerifyError::NotOwner));
    }

    #[test]
    fn verify_rejects_wrong_context() {
        // An op signed for the user shard must not verify under another shard's
        // context — cross-shard replay defense.
        let owner = owner_vk_hex([1u8; 32]);
        let op = signed([1u8; 32], OpType::Profile, b"hello".to_vec(), 1);
        assert_eq!(op.verify(CTX, &owner), Ok(()));
        assert_eq!(
            op.verify(b"raven:thread-shard:v1", &owner),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let owner = owner_vk_hex([1u8; 32]);
        let mut op = signed([1u8; 32], OpType::Profile, b"hello".to_vec(), 1);
        op.payload = b"tampered".to_vec();
        assert_eq!(op.verify(CTX, &owner), Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_tampered_seq() {
        // seq is in the signed payload — bumping it to win a LWW race fails.
        let owner = owner_vk_hex([1u8; 32]);
        let mut op = signed([1u8; 32], OpType::Profile, b"hello".to_vec(), 1);
        op.seq = 9999;
        assert_eq!(op.verify(CTX, &owner), Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_optype_replay() {
        // An op signed as Follow cannot be replayed as Unfollow: op_type is in
        // the signed payload.
        let owner = owner_vk_hex([1u8; 32]);
        let mut op = signed([1u8; 32], OpType::Follow, b"key".to_vec(), 1);
        op.op_type = OpType::Unfollow;
        assert_eq!(op.verify(CTX, &owner), Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_missing_signature() {
        let owner = owner_vk_hex([1u8; 32]);
        let mut op = signed([1u8; 32], OpType::Profile, b"x".to_vec(), 1);
        op.signature = None;
        assert_eq!(op.verify(CTX, &owner), Err(VerifyError::BadSignature));
    }

    #[test]
    fn payload_is_length_prefixed_unambiguous() {
        let a = signed([1u8; 32], OpType::Follow, b"ab".to_vec(), 1);
        let mut b = a.clone();
        b.payload = b"a".to_vec();
        assert_ne!(a.signing_payload(CTX), b.signing_payload(CTX));
    }

    #[test]
    fn profile_bounds() {
        let mut p = Profile {
            display_name: "Alice".into(),
            handle: "@alice".into(),
            bio: "hi".into(),
            avatar: "blue".into(),
        };
        assert!(p.within_bounds());
        p.bio = "x".repeat(MAX_BIO_LEN + 1);
        assert!(!p.within_bounds());
    }

    #[test]
    fn golden_signing_payload() {
        // GOLDEN VECTOR — a change here means the signing format changed and ALL
        // deployed SignedOp signatures break. Do not "fix" by updating the literal
        // unless that break is intended and versioned (bump SIGNED_OP_DOMAIN_TAG
        // and/or the affected shard context tag).
        //
        // Pins the exact bytes for a fixed op (Profile, payload "hi", seq 7,
        // signer "aabbcc") under USER_SHARD_CONTEXT — the injectivity tests do
        // not catch a consistent format shift across sign+verify.
        let op = SignedOp {
            op_type: OpType::Profile,
            payload: b"hi".to_vec(),
            seq: 7,
            signer_pubkey: "aabbcc".into(),
            signature: None,
        };
        let expected = "12000000726176656e3a7369676e65642d6f703a763113000000726176656e3a7573\
            65722d73686172643a76310700000070726f66696c65020000006869080000000700000000000000\
            06000000616162626363";
        let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(
            hex::encode(op.signing_payload(USER_SHARD_CONTEXT)),
            expected
        );
    }

    #[test]
    fn decodes_old_shape_op() {
        // Missing signature + unknown forward field must decode.
        let json = r#"{
            "op_type": "Profile",
            "payload": [1,2,3],
            "seq": 5,
            "signer_pubkey": "ab",
            "future_field": true
        }"#;
        let op: SignedOp = serde_json::from_str(json).unwrap();
        assert!(op.signature.is_none());
        assert_eq!(op.seq, 5);
    }
}
