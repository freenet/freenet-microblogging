//! Signed notification records for the inbox shard (ADR-0001 → "Inbox shard").
//!
//! An inbox shard is **anyone-writes** (like the thread shard) but
//! **owner-prunes**: any party may deliver a [`Notification`] to a user's inbox
//! (a reply, mention, follow, or quote targeting that user), and only the inbox
//! owner may remove notifications. A notification is signed by its **sender**
//! and bound to the **recipient owner VK**, so it self-verifies and cannot be
//! replayed into a different user's inbox.
//!
//! Pruning is not expressed here — it is an owner-signed
//! [`SignedOp`](crate::signed_op::SignedOp) (`OpType::PruneIds` /
//! `OpType::PruneBefore`, bound to [`INBOX_SHARD_CONTEXT`](crate::signed_op::INBOX_SHARD_CONTEXT)),
//! interpreted by the inbox contract. This module only defines the inbound,
//! sender-signed record.
//!
//! Like the thread records, the payload is a deterministic, length-prefixed
//! concatenation (never `serde_json`) tagged with a domain string **and the
//! recipient VK and kind**, so a notification signed for one recipient/kind can
//! never be replayed as another.

use ml_dsa::signature::Verifier;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub use crate::thread::{VerifyError, WriterCert};

/// Domain tag for a notification record's signing payload.
pub const NOTIF_DOMAIN_TAG: &[u8] = b"raven:inbox-notif:v1";

/// What a notification is about. Part of the signed payload (via its byte
/// [`tag`](NotifKind::tag)) so a notification signed as one kind cannot be
/// presented as another.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifKind {
    /// Someone replied to one of the recipient's posts. `ref_id` = reply post id.
    Reply,
    /// Someone mentioned the recipient in a post. `ref_id` = mentioning post id.
    Mention,
    /// Someone followed the recipient. `ref_id` = empty (the sender *is* the
    /// follower; their VK is `sender_pubkey`).
    Follow,
    /// Someone quoted one of the recipient's posts. `ref_id` = quoting post id.
    Quote,
}

impl NotifKind {
    /// Stable byte tag for the signing payload. Explicit (not the serde repr) so
    /// the signed bytes never shift if the enum is reordered/extended.
    fn tag(self) -> &'static [u8] {
        match self {
            NotifKind::Reply => b"reply",
            NotifKind::Mention => b"mention",
            NotifKind::Follow => b"follow",
            NotifKind::Quote => b"quote",
        }
    }
}

/// A signed notification delivered to the recipient's inbox by `sender_pubkey`.
///
/// Self-verifying: the signature proves the sender authored it for this exact
/// `(recipient, kind, ref_id, seq)`. Who may be a sender is the abuse question
/// the ADR leaves to a later credential mechanism ([`WriterCert`]); see the
/// inbox contract's `verify_writer_cert` seam.
///
/// The content-addressed [`id`](Notification::id) (blake3 of the signing
/// payload) is the map key in the contract and the handle the owner names when
/// pruning a single notification.
///
/// Schema-tolerance: additive fields carry `#[serde(default, …)]`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    /// What this notification is about.
    pub kind: NotifKind,
    /// Hex-encoded ML-DSA-65 verifying key of the sender (the notifying party).
    pub sender_pubkey: String,
    /// The referenced content-addressed id (post id), or empty for `Follow`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ref_id: String,
    /// Sender-supplied monotonic counter / recency hint. The inbox owner's
    /// high-water prune (`OpType::PruneBefore`) drops notifications whose `seq`
    /// is below the mark. Part of the signed payload so it cannot be tampered.
    pub seq: u64,
    /// Optional writer credential (see [`WriterCert`]); unused today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_cert: Option<WriterCert>,
    /// Hex-encoded ML-DSA-65 signature over [`Notification::signing_payload`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Length-prefixed `put` (same encoding discipline as the other record types).
fn put(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
    buf.extend_from_slice(field);
}

/// Maximum length of `ref_id`, in UTF-8 bytes. Meant to hold a content-addressed
/// post id (hex of a 32-byte blake3 hash = 64 chars); this is double that as a
/// margin, matching [`crate::post::MAX_POST_REF_LEN`].
pub const MAX_REF_ID_LEN: usize = 128;

impl Notification {
    /// Whether `ref_id` is within its bound.
    ///
    /// A signature proves who sent this notification, not that it is benign —
    /// the sender picks `ref_id` freely and signs whatever they picked. An
    /// inbox is anyone-writes (any party may deliver a notification to a
    /// user's inbox), so an unbounded `ref_id` is an unbounded write primitive
    /// available to anyone, same as an unbounded `Post::author_name` would be.
    pub fn within_bounds(&self) -> bool {
        self.ref_id.len() <= MAX_REF_ID_LEN
    }

    /// Bytes signed/verified: domain tag, **recipient VK** (binds to one inbox),
    /// kind tag, sender, ref_id, seq. `signature` and `writer_cert` are excluded
    /// (the signature is derived from this; the cert is a separate credential).
    ///
    /// `recipient_vk_hex` is the inbox owner's VK — i.e. the inbox shard's
    /// parameters as hex. Binding it here means a notification can only ever be
    /// admitted to the one inbox it was addressed to.
    pub fn signing_payload(&self, recipient_vk_hex: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        put(&mut buf, NOTIF_DOMAIN_TAG);
        put(&mut buf, recipient_vk_hex.as_bytes());
        put(&mut buf, self.kind.tag());
        put(&mut buf, self.sender_pubkey.as_bytes());
        put(&mut buf, self.ref_id.as_bytes());
        put(&mut buf, &self.seq.to_le_bytes());
        buf
    }

    /// Content address of this notification: `blake3(signing_payload)`, hex.
    /// Stable per `(recipient, kind, sender, ref_id, seq)`, so the same
    /// notification delivered twice dedupes to one map entry, and the owner can
    /// reference it by id when pruning. Independent of the (excluded) signature.
    pub fn id(&self, recipient_vk_hex: &str) -> String {
        let hash = blake3::hash(&self.signing_payload(recipient_vk_hex));
        hex::encode(hash.as_bytes())
    }

    /// Verify the notification is well-formed and signed by `sender_pubkey` for
    /// the given recipient. Does **not** check sender authority — that is the
    /// inbox contract's `verify_writer_cert` seam.
    pub fn verify(&self, recipient_vk_hex: &str) -> Result<(), VerifyError> {
        let sig_hex = self.signature.as_deref().ok_or(VerifyError::BadSignature)?;

        let vk_bytes = hex::decode(&self.sender_pubkey).map_err(|_| VerifyError::BadPublicKey)?;
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

        vk.verify(&self.signing_payload(recipient_vk_hex), &sig)
            .map_err(|_| VerifyError::SignatureInvalid)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ml_dsa::KeyGen;
    use ml_dsa::signature::{Keypair, Signer};

    const RECIPIENT: &str = "recipient_owner_vk_hex";

    fn signed(seed: [u8; 32], kind: NotifKind, ref_id: &str, seq: u64) -> Notification {
        let sk = MlDsa65::from_seed(&seed.into());
        let mut n = Notification {
            kind,
            sender_pubkey: hex::encode(sk.verifying_key().encode()),
            ref_id: ref_id.into(),
            seq,
            writer_cert: None,
            signature: None,
        };
        let sig: Signature<MlDsa65> = sk.sign(&n.signing_payload(RECIPIENT));
        n.signature = Some(hex::encode(sig.encode()));
        n
    }

    #[test]
    fn notif_verifies_for_its_recipient() {
        let n = signed([1u8; 32], NotifKind::Reply, "post_aaa", 1);
        assert_eq!(n.verify(RECIPIENT), Ok(()));
    }

    #[test]
    fn notif_rejected_for_another_recipient() {
        // Recipient binding: a notif signed for RECIPIENT must not verify under a
        // different inbox owner (cross-inbox replay defense).
        let n = signed([1u8; 32], NotifKind::Reply, "post_aaa", 1);
        assert_eq!(
            n.verify("a_different_recipient"),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn notif_rejects_tampered_kind_ref_or_seq() {
        let n = signed([1u8; 32], NotifKind::Reply, "post_aaa", 1);
        let wrong_kind = Notification {
            kind: NotifKind::Quote,
            ..n.clone()
        };
        assert_eq!(
            wrong_kind.verify(RECIPIENT),
            Err(VerifyError::SignatureInvalid)
        );
        let wrong_ref = Notification {
            ref_id: "post_bbb".into(),
            ..n.clone()
        };
        assert_eq!(
            wrong_ref.verify(RECIPIENT),
            Err(VerifyError::SignatureInvalid)
        );
        let bumped = Notification { seq: 99, ..n };
        assert_eq!(bumped.verify(RECIPIENT), Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn notif_rejects_missing_signature() {
        let mut n = signed([1u8; 32], NotifKind::Follow, "", 0);
        n.signature = None;
        assert_eq!(n.verify(RECIPIENT), Err(VerifyError::BadSignature));
    }

    #[test]
    fn id_is_stable_and_recipient_bound() {
        let n = signed([2u8; 32], NotifKind::Quote, "post_ccc", 5);
        // Stable across calls.
        assert_eq!(n.id(RECIPIENT), n.id(RECIPIENT));
        // Independent of the signature (content address of the signing payload).
        let mut n2 = n.clone();
        n2.signature = Some("deadbeef".into());
        assert_eq!(n.id(RECIPIENT), n2.id(RECIPIENT));
        // Bound to the recipient: the same notif addressed elsewhere has a
        // different id (and would not verify there anyway).
        assert_ne!(n.id(RECIPIENT), n.id("other_recipient"));
    }

    #[test]
    fn distinct_kinds_have_distinct_payloads() {
        // Same sender/ref/seq, different kind → different signed bytes, so a
        // Reply notification can never be presented as a Follow.
        let reply = signed([3u8; 32], NotifKind::Reply, "p", 0);
        let follow = Notification {
            kind: NotifKind::Follow,
            ..reply.clone()
        };
        assert_ne!(
            reply.signing_payload(RECIPIENT),
            follow.signing_payload(RECIPIENT)
        );
    }

    #[test]
    fn golden_notif_signing_payload() {
        // GOLDEN VECTOR — a change here means the signing format changed and ALL
        // deployed notification signatures (and their content-addressed ids)
        // break. Do not "fix" by updating the literal unless that break is
        // intended and versioned (bump NOTIF_DOMAIN_TAG). Injectivity tests do
        // not catch a consistent sign+verify format shift.
        let n = Notification {
            kind: NotifKind::Reply,
            sender_pubkey: "aabbcc".into(),
            ref_id: "post1".into(),
            seq: 9,
            writer_cert: None,
            signature: None,
        };
        let expected = "14000000726176656e3a696e626f782d6e6f7469663a763109000000726563697069\
            656e74050000007265706c790600000061616262636305000000706f737431080000000900000000\
            000000";
        let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(hex::encode(n.signing_payload("recipient")), expected);
    }

    #[test]
    fn decodes_old_shape_records() {
        // Missing ref_id/signature/writer_cert + an unknown forward field must decode.
        let n: Notification =
            serde_json::from_str(r#"{"kind":"Follow","sender_pubkey":"ab","seq":2,"future":1}"#)
                .unwrap();
        assert!(n.ref_id.is_empty() && n.signature.is_none() && n.writer_cert.is_none());
    }
}
