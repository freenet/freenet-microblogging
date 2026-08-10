//! Canonical signed post record shared by the identity delegate, the shard
//! contracts (ADR-0001), and any external indexer (Atlas).
//!
//! A post is a **self-contained signed record with a stable, content-addressed
//! ID** (ADR-0001 → "Durable history is not Raven's job"). The ID is
//! `blake3(canonical_signing_payload)`, so it is collision-resistant and
//! tamper-evident: changing any signed field changes the ID, and the ID can be
//! referenced externally without rehydrating internal state.
//!
//! Signatures are ML-DSA-65 (FIPS 204). The signing payload is a deterministic,
//! length-prefixed concatenation of the signed fields — NOT `serde_json`, whose
//! field order and whitespace are not guaranteed stable across versions. The
//! same payload is hashed for the ID and verified for the signature.

use ml_dsa::signature::Verifier;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Why a post failed verification. Carried back so callers can log/reject
/// precisely rather than treating every failure as "invalid signature".
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// `signature` field was absent.
    MissingSignature,
    /// `author_pubkey` was not valid hex or not a valid ML-DSA-65 VK.
    BadPublicKey,
    /// `signature` was not valid hex or not a valid ML-DSA-65 signature.
    BadSignature,
    /// `id` did not match `blake3(signing_payload)`.
    IdMismatch,
    /// Signature did not verify against the author's key.
    SignatureInvalid,
}

/// Domain-separation tag mixed into every post signing payload, so a post
/// signature can never be replayed as a signature over some other Raven
/// structure (profile delta, follow op, …) that happens to share bytes.
pub const POST_DOMAIN_TAG: &[u8] = b"raven:post:v1";

/// A signed post record.
///
/// Schema-tolerance: additive fields must carry `#[serde(default, …)]` so older
/// wire shapes still decode under newer code (AGENTS.md → "Contract migration").
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Post {
    /// Content-addressed ID: hex of `blake3(signing_payload)`. Derived, not
    /// author-chosen — recompute with [`Post::compute_id`] and reject a
    /// mismatch.
    pub id: String,
    /// Hex-encoded ML-DSA-65 verifying key of the author (1952 bytes → 3904 hex).
    pub author_pubkey: String,
    /// Display name.
    pub author_name: String,
    /// `@handle`.
    pub author_handle: String,
    /// Post text (max [`MAX_CONTENT_LEN`] UTF-8 bytes — contracts bound
    /// `content.len()`, which is the byte length).
    pub content: String,
    /// Unix timestamp, milliseconds. Part of the signed payload, so it cannot
    /// be altered without invalidating the signature; it is not read as a clock
    /// by any contract.
    pub timestamp: u64,
    /// Content-addressed id of the post this is a reply to, if any (ADR-0001
    /// thread shard). Empty/absent for a top-level post. When non-empty it is
    /// **mixed into the signing payload** (so a reply's thread membership is
    /// signed and cannot be replayed into another thread); when empty the
    /// payload is byte-identical to a pre-`reply_to` top-level post, so existing
    /// post ids/signatures are unaffected.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    /// Content-addressed id of the post this one **quotes** (ADR-0001 quote
    /// repost), if any. Empty/absent for a non-quote post. When non-empty it is
    /// **mixed into the signing payload** (so the quote target is signed and a
    /// quote cannot be retargeted without invalidating the id/signature); when
    /// empty the payload is byte-identical to a pre-`quoted_post` post, so
    /// existing post ids/signatures are unaffected. Appended **after**
    /// `reply_to` so the two optional fields compose deterministically — a post
    /// can be both a reply and a quote.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub quoted_post: String,
    /// Hex-encoded ML-DSA-65 signature over the signing payload (3309 bytes).
    /// Optional only for forward/backward wire tolerance; an unsigned post is
    /// rejected by [`Post::verify`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Maximum post length, in UTF-8 bytes (`content.len()`). Enforced in
/// `validate_state` and the UI.
pub const MAX_CONTENT_LEN: usize = 280;

/// Maximum author display name, in UTF-8 bytes. Mirrors the profile register's
/// [`MAX_DISPLAY_NAME_LEN`](crate::signed_op::MAX_DISPLAY_NAME_LEN): the same
/// value shown in the same place in the UI should be bounded the same way, or
/// the looser surface silently becomes the one that gets used.
pub const MAX_AUTHOR_NAME_LEN: usize = 64;

/// Maximum author handle, in UTF-8 bytes. Mirrors
/// [`MAX_HANDLE_LEN`](crate::signed_op::MAX_HANDLE_LEN).
pub const MAX_AUTHOR_HANDLE_LEN: usize = 32;

impl Post {
    /// Whether every author-controlled field is within its bound.
    ///
    /// A signature proves who wrote a record, not that the record is benign —
    /// the author picks `author_name` / `author_handle` freely and signs
    /// whatever they picked. Unbounded, those two fields have no ceiling at
    /// all: a valid post could carry megabytes of "name" into every replica of
    /// a shard whose only other bound is 280 bytes of content.
    ///
    /// Kept separate from `verify()` so the split stays legible: `verify()`
    /// answers "did this key sign these bytes", `within_bounds()` answers "may
    /// these bytes be stored at all".
    pub fn within_bounds(&self) -> bool {
        self.content.len() <= MAX_CONTENT_LEN
            && self.author_name.len() <= MAX_AUTHOR_NAME_LEN
            && self.author_handle.len() <= MAX_AUTHOR_HANDLE_LEN
    }

    /// The exact bytes that are hashed for the ID and signed/verified.
    ///
    /// Length-prefixed concatenation (`u32` LE length + bytes per field) so no
    /// field-boundary ambiguity exists and the encoding is deterministic across
    /// builds. `id` and `signature` are intentionally excluded — they are
    /// *derived from* this payload.
    ///
    /// `reply_to` then `quoted_post` are each appended **only when non-empty**: a
    /// post with both empty produces the exact pre-`reply_to` byte sequence, so
    /// its id and signature are unchanged; a reply binds its target thread and a
    /// quote binds its quoted post into the signed bytes, so neither can be
    /// retargeted. The fixed order (reply_to before quoted_post) keeps a
    /// reply-and-quote post deterministic.
    pub fn signing_payload(&self) -> Vec<u8> {
        fn put(buf: &mut Vec<u8>, field: &[u8]) {
            buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
            buf.extend_from_slice(field);
        }
        let mut buf = Vec::new();
        put(&mut buf, POST_DOMAIN_TAG);
        put(&mut buf, self.author_pubkey.as_bytes());
        put(&mut buf, self.author_name.as_bytes());
        put(&mut buf, self.author_handle.as_bytes());
        put(&mut buf, self.content.as_bytes());
        put(&mut buf, &self.timestamp.to_le_bytes());
        if !self.reply_to.is_empty() {
            put(&mut buf, self.reply_to.as_bytes());
        }
        if !self.quoted_post.is_empty() {
            put(&mut buf, self.quoted_post.as_bytes());
        }
        buf
    }

    /// Content-addressed ID for this post: hex of `blake3(signing_payload)`.
    pub fn compute_id(&self) -> String {
        let payload = self.signing_payload();
        let hash = blake3::hash(&payload);
        hex::encode(hash.as_bytes())
    }

    /// Whether `self.id` matches the recomputed content address.
    pub fn id_is_valid(&self) -> bool {
        self.id == self.compute_id()
    }

    /// Full verification of a self-contained post: the ID is the correct
    /// content address, and the signature verifies against `author_pubkey`
    /// over the signing payload. This is what a contract's `update_state`
    /// calls before accepting a post.
    pub fn verify(&self) -> Result<(), VerifyError> {
        let sig_hex = self
            .signature
            .as_deref()
            .ok_or(VerifyError::MissingSignature)?;

        // ID must be the content address of the signed fields.
        if !self.id_is_valid() {
            return Err(VerifyError::IdMismatch);
        }

        // Decode the author's verifying key.
        let vk_bytes = hex::decode(&self.author_pubkey).map_err(|_| VerifyError::BadPublicKey)?;
        let vk_encoded: EncodedVerifyingKey<MlDsa65> = vk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::BadPublicKey)?;
        let vk = VerifyingKey::<MlDsa65>::decode(&vk_encoded);

        // Decode the signature.
        let sig_bytes = hex::decode(sig_hex).map_err(|_| VerifyError::BadSignature)?;
        let sig_encoded: EncodedSignature<MlDsa65> = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::BadSignature)?;
        let sig = Signature::<MlDsa65>::decode(&sig_encoded).ok_or(VerifyError::BadSignature)?;

        vk.verify(&self.signing_payload(), &sig)
            .map_err(|_| VerifyError::SignatureInvalid)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ml_dsa::KeyGen;
    use ml_dsa::signature::{Keypair, Signer};

    fn sample() -> Post {
        Post {
            id: String::new(),
            author_pubkey: "ab".repeat(1952),
            author_name: "Alice".into(),
            author_handle: "@alice".into(),
            content: "Hello world".into(),
            timestamp: 1_700_000_000_000,
            reply_to: String::new(),
            quoted_post: String::new(),
            signature: None,
        }
    }

    /// Build a fully-signed post the way the delegate + UI would.
    fn signed(seed: [u8; 32], content: &str) -> Post {
        let sk = MlDsa65::from_seed(&seed.into());
        let vk_hex = hex::encode(sk.verifying_key().encode());
        let mut p = Post {
            id: String::new(),
            author_pubkey: vk_hex,
            author_name: "Alice".into(),
            author_handle: "@alice".into(),
            content: content.into(),
            timestamp: 1_700_000_000_000,
            reply_to: String::new(),
            quoted_post: String::new(),
            signature: None,
        };
        p.id = p.compute_id();
        let sig: Signature<MlDsa65> = sk.sign(&p.signing_payload());
        p.signature = Some(hex::encode(sig.encode()));
        p
    }

    #[test]
    fn verify_accepts_well_formed_post() {
        let p = signed([3u8; 32], "hello raven");
        assert_eq!(p.verify(), Ok(()));
    }

    #[test]
    fn verify_rejects_tampering() {
        // Tamper with content after signing → id mismatch (id is recomputed first).
        let mut p = signed([3u8; 32], "hello raven");
        p.content = "tampered".into();
        assert_eq!(p.verify(), Err(VerifyError::IdMismatch));

        // Keep id consistent with tampered content but signature now stale.
        p.id = p.compute_id();
        assert_eq!(p.verify(), Err(VerifyError::SignatureInvalid));

        // Wrong author key.
        let mut q = signed([3u8; 32], "hello raven");
        let other = MlDsa65::from_seed(&[9u8; 32].into());
        q.author_pubkey = hex::encode(other.verifying_key().encode());
        // id is over author_pubkey too, so this is an id mismatch.
        assert_eq!(q.verify(), Err(VerifyError::IdMismatch));
    }

    #[test]
    fn verify_rejects_missing_signature() {
        let mut p = signed([3u8; 32], "x");
        p.signature = None;
        assert_eq!(p.verify(), Err(VerifyError::MissingSignature));
    }

    #[test]
    fn id_is_deterministic_and_content_addressed() {
        let mut p = sample();
        let id = p.compute_id();
        // Stable across calls.
        assert_eq!(id, p.compute_id());
        // 32-byte blake3 → 64 hex chars.
        assert_eq!(id.len(), 64);
        // Changing a signed field changes the id.
        p.content.push('!');
        assert_ne!(id, p.compute_id());
    }

    #[test]
    fn id_validation_roundtrip() {
        let mut p = sample();
        assert!(!p.id_is_valid()); // empty id
        p.id = p.compute_id();
        assert!(p.id_is_valid());
        // id excludes the signature/id fields themselves.
        p.signature = Some("ff".into());
        assert!(p.id_is_valid());
    }

    #[test]
    fn payload_is_length_prefixed_unambiguous() {
        // "ab"+"c" vs "a"+"bc" must not collide.
        let mut p1 = sample();
        p1.author_name = "ab".into();
        p1.author_handle = "c".into();
        let mut p2 = sample();
        p2.author_name = "a".into();
        p2.author_handle = "bc".into();
        assert_ne!(p1.signing_payload(), p2.signing_payload());
    }

    #[test]
    fn empty_reply_to_is_payload_compatible() {
        // A top-level post (empty reply_to) must hash/sign exactly as it did
        // before the field existed: reply_to is appended only when non-empty,
        // so the byte sequence is unchanged and ids/signatures are stable.
        let p = sample();
        assert!(p.reply_to.is_empty());

        // Reconstruct the pre-reply_to payload by hand and compare.
        let mut expected = Vec::new();
        for field in [
            POST_DOMAIN_TAG,
            p.author_pubkey.as_bytes(),
            p.author_name.as_bytes(),
            p.author_handle.as_bytes(),
            p.content.as_bytes(),
            &p.timestamp.to_le_bytes(),
        ] {
            expected.extend_from_slice(&(field.len() as u32).to_le_bytes());
            expected.extend_from_slice(field);
        }
        assert_eq!(p.signing_payload(), expected);
    }

    #[test]
    fn reply_to_is_signed_and_thread_bound() {
        // A reply binds its target thread into the signature: it verifies in its
        // own thread, but moving it to another thread (changing reply_to) breaks
        // the id (id is over the payload) — a reply cannot be replayed elsewhere.
        let sk = MlDsa65::from_seed(&[7u8; 32].into());
        let mut reply = Post {
            id: String::new(),
            author_pubkey: hex::encode(sk.verifying_key().encode()),
            author_name: "Bob".into(),
            author_handle: "@bob".into(),
            content: "nice post".into(),
            timestamp: 1_700_000_000_001,
            reply_to: "root_post_id_aaaa".into(),
            quoted_post: String::new(),
            signature: None,
        };
        reply.id = reply.compute_id();
        let sig: Signature<MlDsa65> = sk.sign(&reply.signing_payload());
        reply.signature = Some(hex::encode(sig.encode()));
        assert_eq!(reply.verify(), Ok(()));

        // Same author/content, different thread → different signed bytes → the
        // id no longer matches, so a thread can detect a misfiled reply.
        let mut moved = reply.clone();
        moved.reply_to = "root_post_id_bbbb".into();
        assert_eq!(moved.verify(), Err(VerifyError::IdMismatch));
    }

    #[test]
    fn golden_signing_payload_top_level() {
        // GOLDEN VECTOR — a change here means the signing format changed and ALL
        // deployed signatures/records break. Do not "fix" by updating the literal
        // unless that break is intended and versioned (bump POST_DOMAIN_TAG).
        //
        // Existing tests only prove injectivity (length-prefix unambiguity); a
        // serde/encoding change that shifts the payload CONSISTENTLY across
        // sign+verify passes them yet silently invalidates already-deployed
        // signatures. This pins the exact bytes as a tripwire.
        let p = Post {
            id: String::new(),
            author_pubkey: "00112233".into(),
            author_name: "Alice".into(),
            author_handle: "@alice".into(),
            content: "hello".into(),
            timestamp: 1_700_000_000_000,
            reply_to: String::new(),
            quoted_post: String::new(),
            signature: None,
        };
        let expected = "0d000000726176656e3a706f73743a763108000000303031313232333305000000\
            416c6963650600000040616c6963650500000068656c6c6f080000000068e5cf8b010000";
        let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(hex::encode(p.signing_payload()), expected);
    }

    #[test]
    fn golden_signing_payload_reply() {
        // GOLDEN VECTOR — see golden_signing_payload_top_level. This pins the
        // reply variant (non-empty reply_to appended). Do not update the literal
        // unless the format break is intended and POST_DOMAIN_TAG is bumped.
        let p = Post {
            id: String::new(),
            author_pubkey: "00112233".into(),
            author_name: "Alice".into(),
            author_handle: "@alice".into(),
            content: "hello".into(),
            timestamp: 1_700_000_000_000,
            reply_to: "rootid".into(),
            quoted_post: String::new(),
            signature: None,
        };
        let expected = "0d000000726176656e3a706f73743a763108000000303031313232333305000000\
            416c6963650600000040616c6963650500000068656c6c6f080000000068e5cf8b010000\
            06000000726f6f746964";
        let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(hex::encode(p.signing_payload()), expected);
    }

    #[test]
    fn golden_signing_payload_quote() {
        // GOLDEN VECTOR — pins the quote variant (empty reply_to, non-empty
        // quoted_post appended). Do not update the literal unless the format
        // break is intended and POST_DOMAIN_TAG is bumped.
        let p = Post {
            id: String::new(),
            author_pubkey: "00112233".into(),
            author_name: "Alice".into(),
            author_handle: "@alice".into(),
            content: "hello".into(),
            timestamp: 1_700_000_000_000,
            reply_to: String::new(),
            quoted_post: "qid".into(),
            signature: None,
        };
        let expected = "0d000000726176656e3a706f73743a763108000000303031313232333305000000\
            416c6963650600000040616c6963650500000068656c6c6f080000000068e5cf8b010000\
            03000000716964";
        let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(hex::encode(p.signing_payload()), expected);
    }

    #[test]
    fn golden_signing_payload_reply_and_quote() {
        // GOLDEN VECTOR — a post that is BOTH a reply and a quote. Fixed field
        // order: reply_to THEN quoted_post. Pins that composition so it can never
        // silently reorder (which would break every reply-quote signature).
        let p = Post {
            id: String::new(),
            author_pubkey: "00112233".into(),
            author_name: "Alice".into(),
            author_handle: "@alice".into(),
            content: "hello".into(),
            timestamp: 1_700_000_000_000,
            reply_to: "rootid".into(),
            quoted_post: "qid".into(),
            signature: None,
        };
        let expected = "0d000000726176656e3a706f73743a763108000000303031313232333305000000\
            416c6963650600000040616c6963650500000068656c6c6f080000000068e5cf8b010000\
            06000000726f6f74696403000000716964";
        let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(hex::encode(p.signing_payload()), expected);
    }

    #[test]
    fn quoted_post_is_signed_and_bound() {
        // A quote binds its target into the signature: changing quoted_post after
        // signing breaks the id (id is over the payload), so a quote cannot be
        // retargeted to a different post.
        let sk = MlDsa65::from_seed(&[5u8; 32].into());
        let mut q = Post {
            id: String::new(),
            author_pubkey: hex::encode(sk.verifying_key().encode()),
            author_name: "Carol".into(),
            author_handle: "@carol".into(),
            content: "great point".into(),
            timestamp: 1_700_000_000_002,
            reply_to: String::new(),
            quoted_post: "quoted_aaaa".into(),
            signature: None,
        };
        q.id = q.compute_id();
        let sig: Signature<MlDsa65> = sk.sign(&q.signing_payload());
        q.signature = Some(hex::encode(sig.encode()));
        assert_eq!(q.verify(), Ok(()));

        // Retarget to a different quoted post → id no longer matches.
        let mut moved = q.clone();
        moved.quoted_post = "quoted_bbbb".into();
        assert_eq!(moved.verify(), Err(VerifyError::IdMismatch));
    }

    #[test]
    fn empty_quoted_post_is_payload_compatible() {
        // A post with empty quoted_post (and empty reply_to) must hash/sign
        // exactly as a pre-quoted_post post: quoted_post is appended only when
        // non-empty, so ids/signatures of existing posts are unaffected.
        let p = sample();
        assert!(p.quoted_post.is_empty() && p.reply_to.is_empty());
        let mut expected = Vec::new();
        for field in [
            POST_DOMAIN_TAG,
            p.author_pubkey.as_bytes(),
            p.author_name.as_bytes(),
            p.author_handle.as_bytes(),
            p.content.as_bytes(),
            &p.timestamp.to_le_bytes(),
        ] {
            expected.extend_from_slice(&(field.len() as u32).to_le_bytes());
            expected.extend_from_slice(field);
        }
        assert_eq!(p.signing_payload(), expected);
    }

    #[test]
    fn decodes_old_shape_without_signature() {
        // A post missing `signature` (older shape) and carrying an unknown
        // forward-compat field must decode.
        let json = r#"{
            "id": "deadbeef",
            "author_pubkey": "ab",
            "author_name": "Alice",
            "author_handle": "@alice",
            "content": "hi",
            "timestamp": 1700000000000,
            "reply_to": "future-field"
        }"#;
        let p: Post = serde_json::from_str(json).unwrap();
        assert!(p.signature.is_none());
    }

    // -- author-field bounds --
    //
    // A signature proves authorship, not innocence. These fields are chosen by
    // the author and signed by them, so only an explicit bound stops a
    // perfectly valid record from carrying an arbitrary payload into every
    // replica.

    #[test]
    fn within_bounds_accepts_ordinary_fields() {
        assert!(sample().within_bounds());
    }

    #[test]
    fn within_bounds_rejects_oversized_author_name() {
        let mut p = sample();
        p.author_name = "x".repeat(MAX_AUTHOR_NAME_LEN + 1);
        assert!(!p.within_bounds());
    }

    #[test]
    fn within_bounds_rejects_oversized_author_handle() {
        let mut p = sample();
        p.author_handle = "x".repeat(MAX_AUTHOR_HANDLE_LEN + 1);
        assert!(!p.within_bounds());
    }

    #[test]
    fn within_bounds_still_rejects_oversized_content() {
        let mut p = sample();
        p.content = "x".repeat(MAX_CONTENT_LEN + 1);
        assert!(!p.within_bounds());
    }

    #[test]
    fn bounds_are_counted_in_utf8_bytes_not_chars() {
        // `len()` is the BYTE length. A field of MAX/2 + 1 two-byte characters
        // is over the bound even though it is well under it in `chars()`.
        let mut p = sample();
        p.author_handle = "ą".repeat(MAX_AUTHOR_HANDLE_LEN / 2 + 1);
        assert!(p.author_handle.chars().count() <= MAX_AUTHOR_HANDLE_LEN);
        assert!(!p.within_bounds());
    }

    #[test]
    fn an_oversized_field_still_verifies_which_is_the_point() {
        // The bound is NOT redundant with the signature: an over-bound post is
        // cryptographically valid. If acceptance only checked `verify()`, this
        // record would be stored and replicated.
        let sk = MlDsa65::from_seed(&[3u8; 32].into());
        let mut p = sample();
        p.author_pubkey = hex::encode(sk.verifying_key().encode());
        p.author_name = "x".repeat(MAX_AUTHOR_NAME_LEN + 1);
        p.id = p.compute_id();
        let sig: Signature<MlDsa65> = sk.sign(&p.signing_payload());
        p.signature = Some(hex::encode(sig.encode()));

        assert_eq!(p.verify(), Ok(()));
        assert!(!p.within_bounds());
    }
}
