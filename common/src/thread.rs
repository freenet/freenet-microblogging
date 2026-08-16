//! Signed thread-entry records for the thread shard (ADR-0001 → "Thread shard").
//!
//! A thread shard is **anyone-writes**: replies, likes, and quote references
//! targeting one root post. A *reply* is a full [`Post`](crate::post::Post)
//! whose `reply_to` is the root id (already self-signed + content-addressed). A
//! *like* and a *quote reference* carry no post body, so each is its own signed
//! record here.
//!
//! Unlike the user shard's [`SignedOp`](crate::signed_op::SignedOp) — which is
//! **owner-bound** (the signer must equal the shard owner) — these records are
//! signed by *any* writer: verification proves the record was signed by the key
//! it names, not that the signer is privileged. Who may be a writer is the
//! abuse question the ADR leaves to a later credential mechanism
//! ([`WriterCert`]); see the thread contract's `verify_writer_cert` seam.
//!
//! Every payload is a deterministic, length-prefixed concatenation (never
//! `serde_json`) tagged with a per-kind domain string **and the root post id**,
//! so a like/quote signed for one thread can never be replayed into another.

use ml_dsa::signature::Verifier;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Domain tag for a like record's signing payload.
pub const LIKE_DOMAIN_TAG: &[u8] = b"raven:thread-like:v1";
/// Domain tag for a quote-reference record's signing payload.
pub const QUOTE_DOMAIN_TAG: &[u8] = b"raven:thread-quote:v1";
/// Domain tag for a repost record's signing payload.
pub const REPOST_DOMAIN_TAG: &[u8] = b"raven:thread-repost:v1";

/// Why a thread record failed verification.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// `signer_pubkey` was not valid hex or not a valid ML-DSA-65 VK.
    BadPublicKey,
    /// `signature` was absent, not valid hex, or not a valid ML-DSA-65 signature.
    BadSignature,
    /// Signature did not verify against `signer_pubkey`.
    SignatureInvalid,
}

/// An opaque, currently-unverified writer credential (ADR-0001 abuse model).
///
/// The ADR names [GhostKey](https://freenet.org/ghostkey/) — donation-backed,
/// blind-signed certificates verifiable inside `update_state` — as the candidate
/// defense for public-write surfaces, but does **not** fix the mechanism. This
/// type reserves the wire slot so adding real verification later is an additive
/// schema change, not a format break. Today the thread contract's
/// `verify_writer_cert` accepts any (or no) cert; when GhostKey lands, the cert
/// bytes are checked there. Keep this `#[serde(default, …)]` everywhere it is
/// embedded so older/newer records still decode.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct WriterCert {
    /// Opaque certificate bytes (e.g. a serialized GhostKey certificate).
    /// Interpreted by the future credential verifier; ignored today.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cert: Vec<u8>,
}

/// Maximum length of `WriterCert.cert`, in bytes. `cert` is excluded from
/// every record's signing payload (it is not yet a verified credential), so
/// it is also not authenticated — a record can be relayed with its cert bytes
/// swapped out without invalidating the signature. That makes it strictly
/// easier to abuse than a signed-but-unbounded field: no keypair is needed at
/// all, just a valid record to relay with a new `cert` attached. Every record
/// type that embeds a `WriterCert` (`LikeRecord`, `RepostRecord`, `QuoteRef`,
/// `Notification`) is anyone-writes, so an unbounded cert is an unbounded
/// write primitive available to anyone who can observe one valid record.
pub const MAX_WRITER_CERT_LEN: usize = 4096;

impl WriterCert {
    /// Whether `cert` is within its bound. Deliberately independent of
    /// whether the credential itself is considered valid — bounding size is a
    /// storage-amplification guard, not a step toward the GhostKey
    /// verification `verify_writer_cert` still reserves the slot for.
    pub fn within_bounds(&self) -> bool {
        self.cert.len() <= MAX_WRITER_CERT_LEN
    }
}

/// A signed "like" of the thread's root post by `signer_pubkey`.
///
/// Convergence on the thread shard is per-liker: `seq` carries a monotonic
/// counter and `liked` whether this is a like (`true`) or unlike (`false`); the
/// merge keeps the higher `seq` per liker and an **unlike wins an equal-`seq`
/// tie** (a deterministic tie-break, mirroring the user shard's follow rule).
///
/// Schema-tolerance: additive fields carry `#[serde(default, …)]`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LikeRecord {
    /// Hex-encoded ML-DSA-65 verifying key of the liker.
    pub signer_pubkey: String,
    /// Monotonic per-liker counter; resolves concurrent like/unlike without a
    /// clock. Part of the signed payload so it cannot be forged to win a race.
    pub seq: u64,
    /// `true` = like, `false` = unlike (a tombstone).
    pub liked: bool,
    /// Optional writer credential (see [`WriterCert`]); unused today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_cert: Option<WriterCert>,
    /// Hex-encoded ML-DSA-65 signature over [`LikeRecord::signing_payload`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A signed reference recording that `signer_pubkey` quoted the root post in a
/// post of their own (`quote_post_id`, a content address on the quoter's user
/// shard). Append-only; deduped by `quote_post_id`.
///
/// Schema-tolerance: additive fields carry `#[serde(default, …)]`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct QuoteRef {
    /// Hex-encoded ML-DSA-65 verifying key of the quoting author.
    pub signer_pubkey: String,
    /// Content-addressed id of the quoting post (on the quoter's user shard).
    pub quote_post_id: String,
    /// Optional writer credential (see [`WriterCert`]); unused today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_cert: Option<WriterCert>,
    /// Hex-encoded ML-DSA-65 signature over [`QuoteRef::signing_payload`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A signed "repost" (retweet/boost) of the thread's root post by
/// `signer_pubkey` — an amplification with no body of its own, the plain-repost
/// half of the engagement surface (the quote half is [`QuoteRef`] + a real
/// post). Convergence is per-reposter and identical to [`LikeRecord`]: `seq` is
/// a monotonic counter and `reposted` whether this is a repost (`true`) or an
/// un-repost tombstone (`false`); the merge keeps the higher `seq` and an
/// **un-repost wins an equal-`seq` tie**.
///
/// Schema-tolerance: additive fields carry `#[serde(default, …)]`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RepostRecord {
    /// Hex-encoded ML-DSA-65 verifying key of the reposter.
    pub signer_pubkey: String,
    /// Monotonic per-reposter counter; resolves concurrent repost/un-repost
    /// without a clock. Part of the signed payload so it cannot be forged to win
    /// a race.
    pub seq: u64,
    /// `true` = repost, `false` = un-repost (a tombstone).
    pub reposted: bool,
    /// Optional writer credential (see [`WriterCert`]); unused today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_cert: Option<WriterCert>,
    /// Hex-encoded ML-DSA-65 signature over [`RepostRecord::signing_payload`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Length-prefixed `put` shared by both record payloads.
fn put(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
    buf.extend_from_slice(field);
}

/// Decode a hex VK + hex signature and verify `sig` over `payload`. Shared by
/// both record kinds.
fn verify_sig(
    signer_pubkey: &str,
    signature: Option<&str>,
    payload: &[u8],
) -> Result<(), VerifyError> {
    let sig_hex = signature.ok_or(VerifyError::BadSignature)?;

    let vk_bytes = hex::decode(signer_pubkey).map_err(|_| VerifyError::BadPublicKey)?;
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

    vk.verify(payload, &sig)
        .map_err(|_| VerifyError::SignatureInvalid)
}

impl LikeRecord {
    /// Bytes signed/verified: domain tag, **root post id** (binds to thread),
    /// signer, seq, liked. `signature` excluded (derived from this).
    pub fn signing_payload(&self, root_post_id: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        put(&mut buf, LIKE_DOMAIN_TAG);
        put(&mut buf, root_post_id.as_bytes());
        put(&mut buf, self.signer_pubkey.as_bytes());
        put(&mut buf, &self.seq.to_le_bytes());
        put(&mut buf, &[self.liked as u8]);
        buf
    }

    /// Verify the like is well-formed and signed by `signer_pubkey` for the
    /// given thread root. Does **not** check writer authority — that is the
    /// contract's `verify_writer_cert` seam.
    pub fn verify(&self, root_post_id: &str) -> Result<(), VerifyError> {
        verify_sig(
            &self.signer_pubkey,
            self.signature.as_deref(),
            &self.signing_payload(root_post_id),
        )
    }
}

impl QuoteRef {
    /// Whether `quote_post_id` is within its bound. It is signer-chosen and
    /// signed (see `signing_payload`), so the signature does not bound it —
    /// only this does. `quote_post_id` is also the map key the thread shard
    /// stores quotes under, so an oversized value is both a storage-blowup
    /// primitive and an oversized key. Same class as `Post::reply_to` /
    /// `Post::quoted_post`; reuses their bound since both hold a
    /// content-addressed post id.
    pub fn within_bounds(&self) -> bool {
        self.quote_post_id.len() <= crate::post::MAX_POST_REF_LEN
    }

    /// Bytes signed/verified: domain tag, **root post id** (binds to thread),
    /// signer, quote_post_id. `signature` excluded (derived from this).
    pub fn signing_payload(&self, root_post_id: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        put(&mut buf, QUOTE_DOMAIN_TAG);
        put(&mut buf, root_post_id.as_bytes());
        put(&mut buf, self.signer_pubkey.as_bytes());
        put(&mut buf, self.quote_post_id.as_bytes());
        buf
    }

    /// Verify the quote ref is well-formed and signed by `signer_pubkey` for the
    /// given thread root. Does **not** check writer authority.
    pub fn verify(&self, root_post_id: &str) -> Result<(), VerifyError> {
        verify_sig(
            &self.signer_pubkey,
            self.signature.as_deref(),
            &self.signing_payload(root_post_id),
        )
    }
}

impl RepostRecord {
    /// Bytes signed/verified: domain tag, **root post id** (binds to thread),
    /// signer, seq, reposted. `signature` excluded (derived from this). Mirrors
    /// [`LikeRecord::signing_payload`] under a distinct domain tag, so a repost
    /// can never be replayed as a like (or vice versa).
    pub fn signing_payload(&self, root_post_id: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        put(&mut buf, REPOST_DOMAIN_TAG);
        put(&mut buf, root_post_id.as_bytes());
        put(&mut buf, self.signer_pubkey.as_bytes());
        put(&mut buf, &self.seq.to_le_bytes());
        put(&mut buf, &[self.reposted as u8]);
        buf
    }

    /// Verify the repost is well-formed and signed by `signer_pubkey` for the
    /// given thread root. Does **not** check writer authority — that is the
    /// contract's `verify_writer_cert` seam.
    pub fn verify(&self, root_post_id: &str) -> Result<(), VerifyError> {
        verify_sig(
            &self.signer_pubkey,
            self.signature.as_deref(),
            &self.signing_payload(root_post_id),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ml_dsa::KeyGen;
    use ml_dsa::signature::{Keypair, Signer};

    const ROOT: &str = "root_post_content_address";

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

    fn signed_quote(seed: [u8; 32], quote_post_id: &str) -> QuoteRef {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut q = QuoteRef {
            signer_pubkey: hex::encode(sk.verifying_key().encode()),
            quote_post_id: quote_post_id.into(),
            writer_cert: None,
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&q.signing_payload(ROOT));
        q.signature = Some(hex::encode(sig.encode()));
        q
    }

    #[test]
    fn like_verifies_for_its_thread() {
        let r = signed_like([1u8; 32], 1, true);
        assert_eq!(r.verify(ROOT), Ok(()));
    }

    #[test]
    fn like_rejected_in_another_thread() {
        // Thread binding: a like signed for ROOT must not verify under a
        // different root id (cross-thread replay defense).
        let r = signed_like([1u8; 32], 1, true);
        assert_eq!(
            r.verify("a_different_root"),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn like_rejects_tampered_seq_or_flag() {
        let mut r = signed_like([1u8; 32], 1, true);
        let bumped = LikeRecord {
            seq: 99,
            ..r.clone()
        };
        assert_eq!(bumped.verify(ROOT), Err(VerifyError::SignatureInvalid));
        r.liked = false; // flip like→unlike without re-signing
        assert_eq!(r.verify(ROOT), Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn like_rejects_missing_signature() {
        let mut r = signed_like([1u8; 32], 1, true);
        r.signature = None;
        assert_eq!(r.verify(ROOT), Err(VerifyError::BadSignature));
    }

    #[test]
    fn quote_verifies_and_is_thread_bound() {
        let q = signed_quote([2u8; 32], "quote_post_aaa");
        assert_eq!(q.verify(ROOT), Ok(()));
        assert_eq!(q.verify("other_root"), Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn quote_rejects_tampered_target() {
        let mut q = signed_quote([2u8; 32], "quote_post_aaa");
        q.quote_post_id = "quote_post_bbb".into();
        assert_eq!(q.verify(ROOT), Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn like_and_quote_payloads_are_domain_separated() {
        // Same root + signer, but a like payload and a quote payload must never
        // collide (distinct domain tags), so neither can be replayed as the other.
        let like = signed_like([3u8; 32], 0, true);
        let quote = QuoteRef {
            signer_pubkey: like.signer_pubkey.clone(),
            quote_post_id: String::new(),
            writer_cert: None,
            signature: None,
        };
        assert_ne!(like.signing_payload(ROOT), quote.signing_payload(ROOT));
    }

    #[test]
    fn golden_like_signing_payload() {
        // GOLDEN VECTOR — a change here means the signing format changed and ALL
        // deployed like signatures break. Do not "fix" by updating the literal
        // unless that break is intended and versioned (bump LIKE_DOMAIN_TAG).
        // Injectivity tests do not catch a consistent sign+verify format shift.
        let r = LikeRecord {
            signer_pubkey: "aabbcc".into(),
            seq: 3,
            liked: true,
            writer_cert: None,
            signature: None,
        };
        let expected = "14000000726176656e3a7468726561642d6c696b653a76310b000000726f6f745f74\
            6872656164060000006161626263630800000003000000000000000100000001";
        let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(hex::encode(r.signing_payload("root_thread")), expected);
    }

    #[test]
    fn golden_quote_signing_payload() {
        // GOLDEN VECTOR — a change here means the signing format changed and ALL
        // deployed quote-ref signatures break. Do not "fix" by updating the literal
        // unless that break is intended and versioned (bump QUOTE_DOMAIN_TAG).
        let q = QuoteRef {
            signer_pubkey: "aabbcc".into(),
            quote_post_id: "qid".into(),
            writer_cert: None,
            signature: None,
        };
        let expected = "15000000726176656e3a7468726561642d71756f74653a76310b000000726f6f745f\
            7468726561640600000061616262636303000000716964";
        let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(hex::encode(q.signing_payload("root_thread")), expected);
    }

    #[test]
    fn repost_verifies_for_its_thread() {
        let r = signed_repost([1u8; 32], 1, true);
        assert_eq!(r.verify(ROOT), Ok(()));
    }

    #[test]
    fn repost_rejected_in_another_thread() {
        // Thread binding: a repost signed for ROOT must not verify under a
        // different root id (cross-thread replay defense).
        let r = signed_repost([1u8; 32], 1, true);
        assert_eq!(
            r.verify("a_different_root"),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn repost_rejects_tampered_seq_or_flag() {
        let mut r = signed_repost([1u8; 32], 1, true);
        let bumped = RepostRecord {
            seq: 99,
            ..r.clone()
        };
        assert_eq!(bumped.verify(ROOT), Err(VerifyError::SignatureInvalid));
        r.reposted = false; // flip repost→un-repost without re-signing
        assert_eq!(r.verify(ROOT), Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn repost_rejects_missing_signature() {
        let mut r = signed_repost([1u8; 32], 1, true);
        r.signature = None;
        assert_eq!(r.verify(ROOT), Err(VerifyError::BadSignature));
    }

    #[test]
    fn repost_is_domain_separated_from_like() {
        // Same root + signer + seq + flag, but a like payload and a repost
        // payload must never collide (distinct domain tags), so neither can be
        // replayed as the other.
        let like = signed_like([3u8; 32], 0, true);
        let repost = RepostRecord {
            signer_pubkey: like.signer_pubkey.clone(),
            seq: like.seq,
            reposted: like.liked,
            writer_cert: None,
            signature: None,
        };
        assert_ne!(like.signing_payload(ROOT), repost.signing_payload(ROOT));
    }

    #[test]
    fn golden_repost_signing_payload() {
        // GOLDEN VECTOR — a change here means the signing format changed and ALL
        // deployed repost signatures break. Do not "fix" by updating the literal
        // unless that break is intended and versioned (bump REPOST_DOMAIN_TAG).
        let r = RepostRecord {
            signer_pubkey: "aabbcc".into(),
            seq: 3,
            reposted: true,
            writer_cert: None,
            signature: None,
        };
        let expected = "16000000726176656e3a7468726561642d7265706f73743a76310b000000726f6f745f\
            746872656164060000006161626263630800000003000000000000000100000001";
        let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(hex::encode(r.signing_payload("root_thread")), expected);
    }

    #[test]
    fn decodes_old_shape_records() {
        // Missing signature/writer_cert + unknown forward field must decode.
        let like: LikeRecord =
            serde_json::from_str(r#"{"signer_pubkey":"ab","seq":3,"liked":true,"future":1}"#)
                .unwrap();
        assert!(like.signature.is_none() && like.writer_cert.is_none());
        let quote: QuoteRef =
            serde_json::from_str(r#"{"signer_pubkey":"ab","quote_post_id":"x","future":1}"#)
                .unwrap();
        assert!(quote.signature.is_none());
        let repost: RepostRecord =
            serde_json::from_str(r#"{"signer_pubkey":"ab","seq":3,"reposted":true,"future":1}"#)
                .unwrap();
        assert!(repost.signature.is_none() && repost.writer_cert.is_none());
    }
}
