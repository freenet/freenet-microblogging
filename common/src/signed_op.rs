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
}

/// Shard-context tag for the **user shard**, mixed into every user-shard
/// `SignedOp` signature. A future thread/inbox shard reusing `SignedOp` must
/// pass its own distinct context, so an op signed for one shard type can never
/// verify against another.
pub const USER_SHARD_CONTEXT: &[u8] = b"raven:user-shard:v1";

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
