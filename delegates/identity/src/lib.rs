#![allow(unexpected_cfgs)]
use freenet_microblogging_common::post::Post;
use freenet_microblogging_common::thread::{LikeRecord, QuoteRef, RepostRecord};
use freenet_stdlib::prelude::*;
use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{KeyGen, MlDsa65, SigningKey as MlDsaSigningKey};
use serde::{Deserialize, Serialize};

struct IdentityDelegate;

/// ML-DSA-65 secret seed length. The 32-byte seed is the storable secret;
/// `MlDsa65::from_seed` reconstructs the signing key (and hence the 1952-byte
/// verifying key) deterministically. Exported/imported as 64 hex chars.
const MLDSA_SEED_LEN: usize = 32;

/// Messages the web UI sends to the delegate.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
enum Request {
    /// Generate a new keypair and store it. Returns the public key.
    CreateIdentity {
        handle: String,
        display_name: String,
    },
    /// Get the current public key and identity info.
    GetIdentity,
    /// Sign a post. The delegate builds the canonical signing payload from
    /// these fields (the single trusted encoder, `common::post`), derives the
    /// content-addressed id, and returns id + signature + public key. `nonce`
    /// is echoed back so the UI can match the response to its pending draft.
    SignPost {
        nonce: String,
        content: String,
        author_name: String,
        author_handle: String,
        timestamp: u64,
        /// Content address of the quoted post for a quote repost; empty/absent
        /// for an ordinary post (kept optional so older UIs still decode).
        #[serde(default)]
        quoted_post: String,
    },
    /// Sign a like (or unlike) for a thread. The delegate builds the canonical
    /// `LikeRecord` payload via the single trusted encoder (`common::thread`)
    /// and signs it, returning the assembled signed record. `root_post_id` is
    /// the thread root (the thread-shard parameter); `seq` is the liker's
    /// monotonic counter; `liked` is true to like, false to unlike (tombstone).
    /// `nonce` is echoed so the UI can match the response to its pending action.
    SignLike {
        nonce: String,
        root_post_id: String,
        seq: u64,
        liked: bool,
    },
    /// Sign a repost (or un-repost) for a thread. Mirrors `SignLike`: the
    /// delegate builds the canonical `RepostRecord` payload via the single
    /// trusted encoder (`common::thread`) and signs it. `root_post_id` is the
    /// thread root; `seq` is the reposter's monotonic counter; `reposted` is
    /// true to repost, false to un-repost (tombstone). `nonce` is echoed.
    SignRepost {
        nonce: String,
        root_post_id: String,
        seq: u64,
        reposted: bool,
    },
    /// Sign a quote reference for a thread. The delegate builds the canonical
    /// `QuoteRef` payload via the single trusted encoder (`common::thread`) and
    /// signs it, recording that the signer quoted `root_post_id` in their own
    /// post `quote_post_id` (a content address on the quoter's user shard).
    /// `nonce` is echoed so the UI can match the response.
    SignQuoteRef {
        nonce: String,
        root_post_id: String,
        quote_post_id: String,
    },
    /// Sign a reply post for a thread. The delegate builds a canonical [`Post`]
    /// with `reply_to` populated (binding the reply to its parent thread root),
    /// derives the content-addressed id, and signs the payload. `reply_to` is
    /// the content-addressed id of the root post (the thread shard key);
    /// `quoted_post` is the content-addressed id of an additionally quoted post
    /// (empty for a plain reply). `nonce` is echoed so the UI can match the
    /// response to its pending draft. SignPost is kept byte-identical (empty
    /// `reply_to`) so existing top-level post signatures are unaffected.
    SignReply {
        nonce: String,
        content: String,
        author_name: String,
        author_handle: String,
        timestamp: u64,
        /// Content-addressed id of the root post this is a reply to (required,
        /// non-empty — the contract's `reply_is_acceptable` rejects empty).
        reply_to: String,
        /// Content-addressed id of the quoted post, if this reply also quotes
        /// another post; empty/absent for a plain reply.
        #[serde(default)]
        quoted_post: String,
    },
    /// Export the secret seed for backup/migration.
    ExportIdentity,
    /// Import a secret seed + identity from another device.
    ImportIdentity {
        secret_key: String, // hex-encoded 32-byte ML-DSA-65 secret seed
        display_name: String,
    },
}

/// Messages the delegate sends back to the web UI.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
enum Response {
    Identity {
        public_key: String, // hex-encoded ML-DSA-65 VK (1952 bytes → 3904 hex)
        handle: String,
        display_name: String,
    },
    Signed {
        nonce: String,      // echoed so the UI can match its pending draft
        post_id: String,    // content-addressed id = blake3(signing payload)
        signature: String,  // hex-encoded ML-DSA-65 signature (3309 bytes)
        public_key: String, // hex-encoded VK
    },
    /// A signed `LikeRecord` ready to fold into a thread shard via
    /// `ThreadDelta::Likes`. `nonce` is echoed so the UI matches its pending
    /// action; the other fields reconstruct the exact signed record.
    SignedLike {
        nonce: String,
        root_post_id: String,
        signer_pubkey: String, // hex-encoded VK
        seq: u64,
        liked: bool,
        signature: String, // hex-encoded ML-DSA-65 signature
    },
    /// A signed `RepostRecord` ready to fold into a thread shard via
    /// `ThreadDelta::Reposts`. `nonce` is echoed; the other fields reconstruct
    /// the exact signed record. Mirrors `SignedLike`.
    SignedRepost {
        nonce: String,
        root_post_id: String,
        signer_pubkey: String, // hex-encoded VK
        seq: u64,
        reposted: bool,
        signature: String, // hex-encoded ML-DSA-65 signature
    },
    /// A signed `QuoteRef` ready to fold into a thread shard via
    /// `ThreadDelta::Quotes`. `nonce` is echoed; the other fields reconstruct the
    /// exact signed record.
    SignedQuoteRef {
        nonce: String,
        root_post_id: String,
        signer_pubkey: String, // hex-encoded VK
        quote_post_id: String,
        signature: String, // hex-encoded ML-DSA-65 signature
    },
    /// A signed reply [`Post`] ready to submit to the user shard (and the
    /// thread shard via `ThreadDelta::Replies`). `nonce` is echoed; `post_id`,
    /// `signature`, and `public_key` mirror the `Signed` response so the UI
    /// can assemble and PUT the post without special-casing. Kept as a
    /// distinct variant (rather than reusing `Signed`) so the UI can
    /// distinguish a reply response from a top-level post response.
    SignedReply {
        nonce: String,      // echoed so the UI can match its pending draft
        post_id: String,    // content-addressed id = blake3(signing payload)
        signature: String,  // hex-encoded ML-DSA-65 signature (3309 bytes)
        public_key: String, // hex-encoded VK
    },
    ExportedIdentity {
        secret_key: String, // hex-encoded 32-byte secret seed
        public_key: String, // hex-encoded VK
        display_name: String,
        handle: String,
    },
    Error {
        message: String,
        // Present when the error is for a SignPost, so the UI can drop exactly
        // the stranded draft. Absent for errors not tied to a pending post.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    },
}

// Secret storage keys. The signing key is stored as its 32-byte SEED, not the
// expanded key — `MlDsa65::from_seed` reconstructs the key deterministically.
const SECRET_SEED: &[u8] = b"mldsa_seed";
const SECRET_HANDLE: &[u8] = b"handle";
const SECRET_DISPLAY_NAME: &[u8] = b"display_name";

/// Draw a fresh 32-byte ML-DSA seed from the Freenet kernel RNG.
///
/// `freenet_stdlib::rand::rand_bytes` calls the WASM host import
/// `__frnt__rand__rand_bytes` provided by the kernel, avoiding any dependency
/// on `getrandom` / OS entropy in WASM.
fn random_seed() -> [u8; MLDSA_SEED_LEN] {
    let bytes = freenet_stdlib::rand::rand_bytes(MLDSA_SEED_LEN as u32);
    let mut seed = [0u8; MLDSA_SEED_LEN];
    seed.copy_from_slice(&bytes[..MLDSA_SEED_LEN]);
    seed
}

/// Reconstruct the ML-DSA-65 signing key from a stored 32-byte seed.
fn signing_key_from_seed(seed: &[u8; MLDSA_SEED_LEN]) -> MlDsaSigningKey<MlDsa65> {
    MlDsa65::from_seed(&(*seed).into())
}

/// Hex-encode the verifying key derived from a signing key.
fn vk_hex(signing_key: &MlDsaSigningKey<MlDsa65>) -> String {
    hex::encode(signing_key.verifying_key().encode())
}

/// Assemble the canonical [`Post`] and sign it with `signing_key`.
///
/// This is the trusted producer of the signatures the user-shard contract
/// verifies via [`Post::verify`]: it populates `author_pubkey` with the hex VK,
/// derives the content-addressed id with the single trusted encoder
/// (`common::post`), then signs that exact payload. A top-level post keeps
/// `reply_to` empty so the signing payload is byte-identical to the
/// pre-`reply_to` shape. Pure (no `ctx` / secret store) so it is unit-testable
/// on the host target, where the secret store is unavailable.
fn build_signed_post(
    signing_key: &MlDsaSigningKey<MlDsa65>,
    content: &str,
    author_name: &str,
    author_handle: &str,
    timestamp: u64,
    quoted_post: &str,
) -> Post {
    let public_key = vk_hex(signing_key);
    let mut post = Post {
        id: String::new(),
        author_pubkey: public_key,
        author_name: author_name.to_string(),
        author_handle: author_handle.to_string(),
        content: content.to_string(),
        timestamp,
        // Top-level post: empty reply_to keeps the signing payload byte-identical
        // to the pre-reply_to shape. Reply signing (non-empty reply_to) arrives
        // with thread-shard UI wiring (ADR-0001 Phase 4).
        reply_to: String::new(),
        // A quote repost carries the quoted post's content address here; empty
        // for an ordinary post, keeping the signing payload byte-identical to the
        // pre-quoted_post shape.
        quoted_post: quoted_post.to_string(),
        signature: None,
    };
    post.id = post.compute_id();
    let signature: ml_dsa::Signature<MlDsa65> = signing_key.sign(&post.signing_payload());
    post.signature = Some(hex::encode(signature.encode()));
    post
}

/// Assemble the canonical reply [`Post`] and sign it with `signing_key`.
///
/// Mirrors [`build_signed_post`] but populates `reply_to` (and optionally
/// `quoted_post`) so the signing payload binds the thread root. The reply
/// is structurally identical to a post — it lives on the user shard — but
/// `reply_to` being non-empty means `Post::signing_payload` appends it,
/// making the id/signature different from a same-content top-level post.
/// This keeps `SignPost` byte-identical (empty `reply_to`).
/// Pure (no `ctx` / secret store) so it is unit-testable on the host target.
fn build_signed_reply(
    signing_key: &MlDsaSigningKey<MlDsa65>,
    content: &str,
    author_name: &str,
    author_handle: &str,
    timestamp: u64,
    reply_to: &str,
    quoted_post: &str,
) -> Post {
    let public_key = vk_hex(signing_key);
    let mut post = Post {
        id: String::new(),
        author_pubkey: public_key,
        author_name: author_name.to_string(),
        author_handle: author_handle.to_string(),
        content: content.to_string(),
        timestamp,
        // Non-empty reply_to: mixed into the signing payload so this reply is
        // thread-bound and cannot be retargeted to a different root.
        reply_to: reply_to.to_string(),
        // Optional: non-empty when this reply also quotes another post.
        quoted_post: quoted_post.to_string(),
        signature: None,
    };
    post.id = post.compute_id();
    let signature: ml_dsa::Signature<MlDsa65> = signing_key.sign(&post.signing_payload());
    post.signature = Some(hex::encode(signature.encode()));
    post
}

/// Assemble the canonical [`LikeRecord`] and sign it for `root_post_id`.
///
/// The thread shard verifies these via [`LikeRecord::verify`]. The signing
/// payload (built by the single trusted encoder, `common::thread`) binds the
/// **thread root id**, so a like signed for one thread can never be replayed
/// into another. Pure (no `ctx` / secret store) so it is unit-testable on the
/// host target. Returns the record and its hex-encoded signature.
fn build_signed_like(
    signing_key: &MlDsaSigningKey<MlDsa65>,
    root_post_id: &str,
    seq: u64,
    liked: bool,
) -> (LikeRecord, String) {
    let signer_pubkey = vk_hex(signing_key);
    let record = LikeRecord {
        signer_pubkey,
        seq,
        liked,
        writer_cert: None,
        signature: None,
    };
    let signature: ml_dsa::Signature<MlDsa65> =
        signing_key.sign(&record.signing_payload(root_post_id));
    (record, hex::encode(signature.encode()))
}

/// Assemble the canonical [`RepostRecord`] and sign it for `root_post_id`.
/// Mirror of [`build_signed_like`]; the thread shard verifies these via
/// [`RepostRecord::verify`]. Pure (no `ctx` / secret store) so it is
/// unit-testable on the host target.
fn build_signed_repost(
    signing_key: &MlDsaSigningKey<MlDsa65>,
    root_post_id: &str,
    seq: u64,
    reposted: bool,
) -> (RepostRecord, String) {
    let signer_pubkey = vk_hex(signing_key);
    let record = RepostRecord {
        signer_pubkey,
        seq,
        reposted,
        writer_cert: None,
        signature: None,
    };
    let signature: ml_dsa::Signature<MlDsa65> =
        signing_key.sign(&record.signing_payload(root_post_id));
    (record, hex::encode(signature.encode()))
}

/// Assemble the canonical [`QuoteRef`] and sign it for `root_post_id`. Records
/// that the signer quoted the root post in their own `quote_post_id`. The thread
/// shard verifies these via [`QuoteRef::verify`]; the signing payload binds the
/// thread root id, so a quote ref cannot be replayed into another thread. Pure
/// (no `ctx`) so it is unit-testable on the host target.
fn build_signed_quote_ref(
    signing_key: &MlDsaSigningKey<MlDsa65>,
    root_post_id: &str,
    quote_post_id: &str,
) -> (QuoteRef, String) {
    let signer_pubkey = vk_hex(signing_key);
    let record = QuoteRef {
        signer_pubkey,
        quote_post_id: quote_post_id.to_string(),
        writer_cert: None,
        signature: None,
    };
    let signature: ml_dsa::Signature<MlDsa65> =
        signing_key.sign(&record.signing_payload(root_post_id));
    (record, hex::encode(signature.encode()))
}

#[delegate]
impl DelegateInterface for IdentityDelegate {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        // Verify origin — only accept calls from web apps.
        match &origin {
            Some(MessageOrigin::WebApp(_)) => {}
            _ => return Err(DelegateError::Other("only web app calls accepted".into())),
        }

        match message {
            InboundDelegateMsg::ApplicationMessage(app_msg) => {
                let request: Request = serde_json::from_slice(&app_msg.payload)
                    .map_err(|e| DelegateError::Other(format!("invalid request: {e}")))?;

                let response = match request {
                    Request::CreateIdentity {
                        handle,
                        display_name,
                    } => create_identity(ctx, &handle, &display_name),
                    Request::GetIdentity => get_identity(ctx),
                    Request::SignPost {
                        nonce,
                        content,
                        author_name,
                        author_handle,
                        timestamp,
                        quoted_post,
                    } => sign_post(
                        ctx,
                        &nonce,
                        &content,
                        &author_name,
                        &author_handle,
                        timestamp,
                        &quoted_post,
                    ),
                    Request::SignLike {
                        nonce,
                        root_post_id,
                        seq,
                        liked,
                    } => sign_like(ctx, &nonce, &root_post_id, seq, liked),
                    Request::SignRepost {
                        nonce,
                        root_post_id,
                        seq,
                        reposted,
                    } => sign_repost(ctx, &nonce, &root_post_id, seq, reposted),
                    Request::SignQuoteRef {
                        nonce,
                        root_post_id,
                        quote_post_id,
                    } => sign_quote_ref(ctx, &nonce, &root_post_id, &quote_post_id),
                    Request::SignReply {
                        nonce,
                        content,
                        author_name,
                        author_handle,
                        timestamp,
                        reply_to,
                        quoted_post,
                    } => sign_reply(
                        ctx,
                        &nonce,
                        &content,
                        &author_name,
                        &author_handle,
                        timestamp,
                        &reply_to,
                        &quoted_post,
                    ),
                    Request::ExportIdentity => export_identity(ctx),
                    Request::ImportIdentity {
                        secret_key,
                        display_name,
                    } => import_identity(ctx, &secret_key, &display_name),
                };

                let response_bytes = serde_json::to_vec(&response)
                    .map_err(|e| DelegateError::Other(format!("serialize error: {e}")))?;

                Ok(vec![OutboundDelegateMsg::ApplicationMessage(
                    ApplicationMessage::new(response_bytes),
                )])
            }
            _ => Err(DelegateError::Other("unexpected message type".into())),
        }
    }
}

/// Load and validate the stored seed, returning a reconstructed signing key.
fn load_signing_key(ctx: &DelegateCtx) -> Result<MlDsaSigningKey<MlDsa65>, Response> {
    let Some(seed_bytes) = ctx.get_secret(SECRET_SEED) else {
        return Err(Response::Error {
            message: "no identity found — call CreateIdentity first".to_string(),
            nonce: None,
        });
    };
    let seed: [u8; MLDSA_SEED_LEN] = match seed_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return Err(Response::Error {
                message: "stored seed has unexpected length".to_string(),
                nonce: None,
            });
        }
    };
    Ok(signing_key_from_seed(&seed))
}

fn stored_handle(ctx: &DelegateCtx) -> String {
    ctx.get_secret(SECRET_HANDLE)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn stored_display_name(ctx: &DelegateCtx) -> String {
    ctx.get_secret(SECRET_DISPLAY_NAME)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn create_identity(ctx: &mut DelegateCtx, handle: &str, display_name: &str) -> Response {
    let seed = random_seed();
    let signing_key = signing_key_from_seed(&seed);
    let public_key = vk_hex(&signing_key);
    // An empty handle from the UI means "derive one" — use the VK prefix.
    let handle = if handle.is_empty() {
        public_key[..8].to_string()
    } else {
        handle.to_string()
    };

    ctx.set_secret(SECRET_SEED, &seed);
    ctx.set_secret(SECRET_HANDLE, handle.as_bytes());
    ctx.set_secret(SECRET_DISPLAY_NAME, display_name.as_bytes());

    Response::Identity {
        public_key,
        handle,
        display_name: display_name.to_string(),
    }
}

fn get_identity(ctx: &DelegateCtx) -> Response {
    let signing_key = match load_signing_key(ctx) {
        Ok(k) => k,
        Err(resp) => return resp,
    };
    Response::Identity {
        public_key: vk_hex(&signing_key),
        handle: stored_handle(ctx),
        display_name: stored_display_name(ctx),
    }
}

fn sign_post(
    ctx: &DelegateCtx,
    nonce: &str,
    content: &str,
    author_name: &str,
    author_handle: &str,
    timestamp: u64,
    quoted_post: &str,
) -> Response {
    let signing_key = match load_signing_key(ctx) {
        Ok(k) => k,
        // Re-tag the load error with this request's nonce so the UI can drop
        // exactly the stranded draft.
        Err(Response::Error { message, .. }) => {
            return Response::Error {
                message,
                nonce: Some(nonce.to_string()),
            };
        }
        Err(resp) => return resp,
    };

    // Build + sign the canonical record with the single trusted encoder
    // (`common::post`) — the exact bytes the user-shard contract verifies. A
    // non-empty quoted_post is mixed into the signed id (quote repost).
    let post = build_signed_post(
        &signing_key,
        content,
        author_name,
        author_handle,
        timestamp,
        quoted_post,
    );

    Response::Signed {
        nonce: nonce.to_string(),
        post_id: post.id,
        signature: post.signature.unwrap_or_default(),
        public_key: post.author_pubkey,
    }
}

fn sign_like(
    ctx: &DelegateCtx,
    nonce: &str,
    root_post_id: &str,
    seq: u64,
    liked: bool,
) -> Response {
    let signing_key = match load_signing_key(ctx) {
        Ok(k) => k,
        // Re-tag the load error with this request's nonce so the UI can drop
        // exactly the stranded pending action.
        Err(Response::Error { message, .. }) => {
            return Response::Error {
                message,
                nonce: Some(nonce.to_string()),
            };
        }
        Err(resp) => return resp,
    };

    // Build + sign the canonical record with the single trusted encoder
    // (`common::thread`) — the same bytes the thread shard verifies, bound to
    // the thread root id.
    let (record, signature) = build_signed_like(&signing_key, root_post_id, seq, liked);

    Response::SignedLike {
        nonce: nonce.to_string(),
        root_post_id: root_post_id.to_string(),
        signer_pubkey: record.signer_pubkey,
        seq,
        liked,
        signature,
    }
}

fn sign_repost(
    ctx: &DelegateCtx,
    nonce: &str,
    root_post_id: &str,
    seq: u64,
    reposted: bool,
) -> Response {
    let signing_key = match load_signing_key(ctx) {
        Ok(k) => k,
        // Re-tag the load error with this request's nonce so the UI can drop
        // exactly the stranded pending action.
        Err(Response::Error { message, .. }) => {
            return Response::Error {
                message,
                nonce: Some(nonce.to_string()),
            };
        }
        Err(resp) => return resp,
    };

    // Build + sign the canonical record with the single trusted encoder
    // (`common::thread`) — the same bytes the thread shard verifies, bound to
    // the thread root id.
    let (record, signature) = build_signed_repost(&signing_key, root_post_id, seq, reposted);

    Response::SignedRepost {
        nonce: nonce.to_string(),
        root_post_id: root_post_id.to_string(),
        signer_pubkey: record.signer_pubkey,
        seq,
        reposted,
        signature,
    }
}

fn sign_quote_ref(
    ctx: &DelegateCtx,
    nonce: &str,
    root_post_id: &str,
    quote_post_id: &str,
) -> Response {
    let signing_key = match load_signing_key(ctx) {
        Ok(k) => k,
        Err(Response::Error { message, .. }) => {
            return Response::Error {
                message,
                nonce: Some(nonce.to_string()),
            };
        }
        Err(resp) => return resp,
    };

    let (record, signature) = build_signed_quote_ref(&signing_key, root_post_id, quote_post_id);

    Response::SignedQuoteRef {
        nonce: nonce.to_string(),
        root_post_id: root_post_id.to_string(),
        signer_pubkey: record.signer_pubkey,
        quote_post_id: quote_post_id.to_string(),
        signature,
    }
}

#[allow(clippy::too_many_arguments)]
fn sign_reply(
    ctx: &DelegateCtx,
    nonce: &str,
    content: &str,
    author_name: &str,
    author_handle: &str,
    timestamp: u64,
    reply_to: &str,
    quoted_post: &str,
) -> Response {
    let signing_key = match load_signing_key(ctx) {
        Ok(k) => k,
        // Re-tag the load error with this request's nonce so the UI can drop
        // exactly the stranded pending draft.
        Err(Response::Error { message, .. }) => {
            return Response::Error {
                message,
                nonce: Some(nonce.to_string()),
            };
        }
        Err(resp) => return resp,
    };

    // Build + sign the canonical reply with the single trusted encoder
    // (`common::post`) — the exact bytes the user-shard contract verifies.
    // reply_to (non-empty) is mixed into the signing payload via
    // `Post::signing_payload`, binding this reply to its thread root.
    let post = build_signed_reply(
        &signing_key,
        content,
        author_name,
        author_handle,
        timestamp,
        reply_to,
        quoted_post,
    );

    Response::SignedReply {
        nonce: nonce.to_string(),
        post_id: post.id,
        signature: post.signature.unwrap_or_default(),
        public_key: post.author_pubkey,
    }
}

fn export_identity(ctx: &DelegateCtx) -> Response {
    let Some(seed_bytes) = ctx.get_secret(SECRET_SEED) else {
        return Response::Error {
            message: "no identity to export".to_string(),
            nonce: None,
        };
    };
    let seed: [u8; MLDSA_SEED_LEN] = match seed_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return Response::Error {
                message: "stored seed has unexpected length".to_string(),
                nonce: None,
            };
        }
    };
    let signing_key = signing_key_from_seed(&seed);
    Response::ExportedIdentity {
        secret_key: hex::encode(seed),
        public_key: vk_hex(&signing_key),
        display_name: stored_display_name(ctx),
        handle: stored_handle(ctx),
    }
}

fn import_identity(ctx: &mut DelegateCtx, secret_key_hex: &str, display_name: &str) -> Response {
    let seed: [u8; MLDSA_SEED_LEN] = match hex::decode(secret_key_hex) {
        Ok(bytes) => match bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return Response::Error {
                    message: "invalid secret key: must be 64 hex characters (32 bytes)".to_string(),
                    nonce: None,
                };
            }
        },
        Err(_) => {
            return Response::Error {
                message: "invalid secret key: must be 64 hex characters (32 bytes)".to_string(),
                nonce: None,
            };
        }
    };

    let signing_key = signing_key_from_seed(&seed);
    let public_key = vk_hex(&signing_key);
    let handle = public_key[..8].to_string();

    ctx.set_secret(SECRET_SEED, &seed);
    ctx.set_secret(SECRET_HANDLE, handle.as_bytes());
    ctx.set_secret(SECRET_DISPLAY_NAME, display_name.as_bytes());

    Response::Identity {
        public_key,
        handle,
        display_name: display_name.to_string(),
    }
}

#[cfg(test)]
mod test {
    //! Why these tests live here and not against `process()`:
    //!
    //! `process()` — and therefore the public `sign_post` / `sign_like` /
    //! `export_identity` / `import_identity` entry points — reads and writes the
    //! signer's seed through `DelegateCtx::{get_secret, set_secret}`. Those are
    //! WASM host imports; on the host test target the stdlib stubs them to return
    //! `None` / `false` (see `freenet_stdlib::delegate_host`). So a host-driven
    //! `process()` call can never load a key and always returns the "no identity
    //! found" error — it is genuinely undrivable off-WASM.
    //!
    //! What matters for on-network correctness is that the bytes the delegate
    //! signs are the *same* bytes the contracts verify. That logic — payload
    //! assembly, field population, id derivation, signature encoding — lives in
    //! the pure `build_signed_post` / `build_signed_like` / `signing_key_from_seed`
    //! / `vk_hex` helpers, which `sign_post` / `sign_like` / `export` / `import`
    //! call verbatim. These tests exercise those exact helpers and then verify the
    //! result with the SAME `common` verify code the contracts run, so a
    //! divergence between signer and verifier fails here rather than on-network.
    use super::*;
    use freenet_microblogging_common::post::VerifyError as PostVerifyError;
    use freenet_microblogging_common::thread::VerifyError as ThreadVerifyError;

    const SEED_A: [u8; MLDSA_SEED_LEN] = [7u8; MLDSA_SEED_LEN];
    const SEED_B: [u8; MLDSA_SEED_LEN] = [42u8; MLDSA_SEED_LEN];

    // 1. export → import round-trip of the 64-hex secret seed yields the same
    //    signing key / VK. Mirrors `export_identity` (hex::encode(seed)) feeding
    //    `import_identity` (hex::decode → try_into → signing_key_from_seed).
    #[test]
    fn export_import_seed_roundtrip_preserves_key() {
        let original = signing_key_from_seed(&SEED_A);
        let exported_hex = hex::encode(SEED_A); // what export_identity emits

        // 32-byte seed → 64 hex chars (the documented ImportIdentity contract).
        assert_eq!(exported_hex.len(), MLDSA_SEED_LEN * 2);

        // what import_identity does with the hex string.
        let decoded = hex::decode(&exported_hex).expect("valid hex");
        let reimported_seed: [u8; MLDSA_SEED_LEN] =
            decoded.as_slice().try_into().expect("32 bytes");
        let reimported = signing_key_from_seed(&reimported_seed);

        assert_eq!(reimported_seed, SEED_A);
        // Same VK after the full export→import cycle.
        assert_eq!(vk_hex(&reimported), vk_hex(&original));
    }

    // 2. sign_post: the delegate's assembled Post + signature VERIFIES under
    //    common's `Post::verify` — the same code the user-shard contract runs.
    //    Confirms field population (author_pubkey casing, empty reply_to) matches
    //    what the verifier reconstructs.
    #[test]
    fn signed_post_verifies_under_common() {
        let sk = signing_key_from_seed(&SEED_A);
        let post = build_signed_post(&sk, "hello raven", "Alice", "@alice", 1_700_000_000_000, "");

        // The contract's acceptance check passes on the delegate's output.
        assert_eq!(post.verify(), Ok(()));

        // Field population the verifier depends on.
        assert_eq!(post.author_pubkey, vk_hex(&sk)); // exact hex VK, lowercase
        assert!(post.reply_to.is_empty()); // top-level post
        assert_eq!(post.author_name, "Alice");
        assert_eq!(post.author_handle, "@alice");
        assert_eq!(post.content, "hello raven");
        assert_eq!(post.timestamp, 1_700_000_000_000);
        // id is the content address of the signed payload.
        assert!(post.id_is_valid());
        assert!(post.signature.is_some());
    }

    // 2b. A post signed by one key must NOT verify if the author_pubkey is
    //     swapped to a different key — guards against the delegate emitting a VK
    //     that does not match the signing key.
    #[test]
    fn signed_post_rejects_mismatched_author_key() {
        let sk = signing_key_from_seed(&SEED_A);
        let mut post = build_signed_post(&sk, "hello", "Alice", "@alice", 1, "");
        // Swap in a different author key (recompute id so we isolate the
        // signature check rather than tripping the id-mismatch guard first).
        post.author_pubkey = vk_hex(&signing_key_from_seed(&SEED_B));
        post.id = post.compute_id();
        assert_eq!(post.verify(), Err(PostVerifyError::SignatureInvalid));
    }

    // 3. sign_like: the delegate's LikeRecord signature verifies under common's
    //    thread verify, and is bound to the THREAD root_post_id. A cross-context
    //    mix-up (verifying against a different root) MUST fail.
    #[test]
    fn signed_like_verifies_and_is_thread_bound() {
        let sk = signing_key_from_seed(&SEED_A);
        let root = "root_post_content_address_abc";
        let (record, sig_hex) = build_signed_like(&sk, root, 1, true);

        // Reassemble the on-wire record exactly as the UI folds it into the
        // thread shard (signer_pubkey + seq + liked + the hex signature), then
        // run the contract's verify.
        let wire = LikeRecord {
            signer_pubkey: record.signer_pubkey.clone(),
            seq: record.seq,
            liked: record.liked,
            writer_cert: None,
            signature: Some(sig_hex),
        };
        assert_eq!(wire.verify(root), Ok(()));

        // Field population.
        assert_eq!(wire.signer_pubkey, vk_hex(&sk));
        assert_eq!(wire.seq, 1);
        assert!(wire.liked);

        // Thread binding: the same signed like must NOT verify under a different
        // root id (cross-thread replay defense).
        assert_eq!(
            wire.verify("a_completely_different_root"),
            Err(ThreadVerifyError::SignatureInvalid)
        );
    }

    // 3b. Cross-CONTEXT mix-up: a like is bound to the thread root id via the
    //     LIKE_DOMAIN_TAG'd payload. Signing for the thread root then trying to
    //     verify with the *inbox* identifier (a foreign context value) in the
    //     root slot must fail — the signature does not transplant between the
    //     thread context and any other context that reuses the verify call.
    #[test]
    fn signed_like_does_not_verify_in_foreign_context() {
        let sk = signing_key_from_seed(&SEED_A);
        let thread_root = "thread:root_post_id_123";
        let inbox_context = "inbox:recipient_pubkey_456"; // a non-thread identifier
        let (record, sig_hex) = build_signed_like(&sk, thread_root, 5, true);

        let wire = LikeRecord {
            signer_pubkey: record.signer_pubkey,
            seq: record.seq,
            liked: record.liked,
            writer_cert: None,
            signature: Some(sig_hex),
        };
        // Verifies in its own thread context...
        assert_eq!(wire.verify(thread_root), Ok(()));
        // ...but a like signed for the thread cannot be replayed against any
        // other context value occupying the root slot.
        assert_eq!(
            wire.verify(inbox_context),
            Err(ThreadVerifyError::SignatureInvalid)
        );
    }

    // 3c. seq / liked are signed: flipping either after signing breaks verify
    //     (the delegate must sign exactly what it returns to the UI).
    #[test]
    fn signed_like_seq_and_flag_are_bound() {
        let sk = signing_key_from_seed(&SEED_A);
        let root = "root_xyz";
        let (record, sig_hex) = build_signed_like(&sk, root, 3, true);

        let tampered_seq = LikeRecord {
            signer_pubkey: record.signer_pubkey.clone(),
            seq: 4, // bumped
            liked: record.liked,
            writer_cert: None,
            signature: Some(sig_hex.clone()),
        };
        assert_eq!(
            tampered_seq.verify(root),
            Err(ThreadVerifyError::SignatureInvalid)
        );

        let tampered_flag = LikeRecord {
            signer_pubkey: record.signer_pubkey,
            seq: 3,
            liked: false, // flipped like→unlike
            writer_cert: None,
            signature: Some(sig_hex),
        };
        assert_eq!(
            tampered_flag.verify(root),
            Err(ThreadVerifyError::SignatureInvalid)
        );
    }

    // 3d. sign_repost: the delegate's RepostRecord signature verifies under
    //     common's thread verify, is bound to the THREAD root, and seq/reposted
    //     are signed (flipping either after signing breaks verify). Mirrors the
    //     like tests — the same path the thread shard runs.
    #[test]
    fn signed_repost_verifies_and_is_thread_bound() {
        let sk = signing_key_from_seed(&SEED_A);
        let root = "root_post_content_address_abc";
        let (record, sig_hex) = build_signed_repost(&sk, root, 1, true);

        let wire = RepostRecord {
            signer_pubkey: record.signer_pubkey.clone(),
            seq: record.seq,
            reposted: record.reposted,
            writer_cert: None,
            signature: Some(sig_hex),
        };
        assert_eq!(wire.verify(root), Ok(()));
        assert_eq!(wire.signer_pubkey, vk_hex(&sk));
        assert_eq!(wire.seq, 1);
        assert!(wire.reposted);

        // Thread binding: the same signed repost must NOT verify under a
        // different root id (cross-thread replay defense).
        assert_eq!(
            wire.verify("a_completely_different_root"),
            Err(ThreadVerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn signed_repost_seq_and_flag_are_bound() {
        let sk = signing_key_from_seed(&SEED_A);
        let root = "root_xyz";
        let (record, sig_hex) = build_signed_repost(&sk, root, 3, true);

        let tampered_seq = RepostRecord {
            signer_pubkey: record.signer_pubkey.clone(),
            seq: 4, // bumped
            reposted: record.reposted,
            writer_cert: None,
            signature: Some(sig_hex.clone()),
        };
        assert_eq!(
            tampered_seq.verify(root),
            Err(ThreadVerifyError::SignatureInvalid)
        );

        let tampered_flag = RepostRecord {
            signer_pubkey: record.signer_pubkey,
            seq: 3,
            reposted: false, // flipped repost→un-repost
            writer_cert: None,
            signature: Some(sig_hex),
        };
        assert_eq!(
            tampered_flag.verify(root),
            Err(ThreadVerifyError::SignatureInvalid)
        );
    }

    // 3e. A quote post: build_signed_post with a non-empty quoted_post produces a
    //     post that verifies, carries the quoted_post, and whose id binds it (so
    //     it cannot be retargeted). Confirms the delegate signs the quote target.
    #[test]
    fn signed_quote_post_binds_quoted_post() {
        let sk = signing_key_from_seed(&SEED_A);
        let post = build_signed_post(&sk, "great take", "Alice", "@alice", 1, "quoted_xyz");
        assert_eq!(post.verify(), Ok(()));
        assert_eq!(post.quoted_post, "quoted_xyz");
        assert!(post.reply_to.is_empty());

        // Retargeting the quote breaks the id (id is over the payload).
        let mut moved = post.clone();
        moved.quoted_post = "quoted_other".into();
        assert_eq!(moved.verify(), Err(PostVerifyError::IdMismatch));
    }

    // 3f. sign_quote_ref: the delegate's QuoteRef signature verifies under
    //     common's thread verify, is bound to the THREAD root, and a retargeted
    //     quote_post_id breaks verification.
    #[test]
    fn signed_quote_ref_verifies_and_is_thread_bound() {
        let sk = signing_key_from_seed(&SEED_A);
        let root = "root_post_content_address_abc";
        let (record, sig_hex) = build_signed_quote_ref(&sk, root, "my_quote_post_id");

        let wire = QuoteRef {
            signer_pubkey: record.signer_pubkey.clone(),
            quote_post_id: record.quote_post_id.clone(),
            writer_cert: None,
            signature: Some(sig_hex),
        };
        assert_eq!(wire.verify(root), Ok(()));
        assert_eq!(wire.signer_pubkey, vk_hex(&sk));
        assert_eq!(wire.quote_post_id, "my_quote_post_id");

        // Thread binding: must not verify under a different root.
        assert_eq!(
            wire.verify("a_completely_different_root"),
            Err(ThreadVerifyError::SignatureInvalid)
        );

        // Retargeted quote_post_id (tamper after signing) fails verify.
        let tampered = QuoteRef {
            quote_post_id: "different_post".into(),
            ..wire
        };
        assert_eq!(
            tampered.verify(root),
            Err(ThreadVerifyError::SignatureInvalid)
        );
    }

    // 4. vk_hex encoding equals what the shard owner-param match expects: the
    //    lowercase hex of the raw VK bytes, and it round-trips back to the same
    //    VK bytes the verifier decodes.
    #[test]
    fn vk_hex_is_hex_of_raw_vk_bytes() {
        let sk = signing_key_from_seed(&SEED_A);
        let encoded = sk.verifying_key().encode();
        let expected = hex::encode(encoded.as_slice());

        let got = vk_hex(&sk);
        assert_eq!(got, expected);
        // ML-DSA-65 VK is 1952 bytes → 3904 hex chars (per the Response docs).
        assert_eq!(got.len(), 1952 * 2);
        // Lowercase hex (owner-param matching is byte-for-byte string equality).
        assert_eq!(got, got.to_lowercase());
        // Round-trips back to the same raw bytes the verifier decodes.
        assert_eq!(hex::decode(&got).expect("valid hex"), encoded.as_slice());
    }

    // 5. seed → key determinism: the same seed always yields the same VK, and
    //    two distinct seeds yield distinct VKs. This is the property `export` /
    //    `import` and cross-device restore rely on.
    #[test]
    fn seed_to_key_is_deterministic() {
        let a1 = vk_hex(&signing_key_from_seed(&SEED_A));
        let a2 = vk_hex(&signing_key_from_seed(&SEED_A));
        let b = vk_hex(&signing_key_from_seed(&SEED_B));

        assert_eq!(a1, a2, "same seed must yield the same VK");
        assert_ne!(a1, b, "distinct seeds must yield distinct VKs");
    }

    // Cross-check: a post and a like signed by the SAME key are domain-separated,
    // so neither signature can be replayed as the other structure. (Guards the
    // delegate's two signing paths against payload collision.)
    #[test]
    fn post_and_like_payloads_are_domain_separated() {
        let sk = signing_key_from_seed(&SEED_A);
        let post = build_signed_post(&sk, "x", "n", "h", 0, "");
        let (like, _) = build_signed_like(&sk, "root", 0, true);
        // Distinct domain tags (raven:post:v1 vs raven:thread-like:v1) guarantee
        // the byte payloads differ.
        assert_ne!(post.signing_payload(), like.signing_payload("root"));
    }

    // -- SignReply tests --

    // R1. build_signed_reply output verifies under Post::verify() — the same
    //     code path the user-shard contract runs. Confirms reply_to is present
    //     and the signing payload / id are consistent with what the verifier
    //     expects.
    #[test]
    fn signed_reply_verifies_under_common() {
        let sk = signing_key_from_seed(&SEED_A);
        let reply = build_signed_reply(
            &sk,
            "nice post",
            "Bob",
            "@bob",
            1_700_000_000_001,
            "root_post_id_aaaaaa",
            "",
        );

        assert_eq!(reply.verify(), Ok(()));
        assert_eq!(reply.author_pubkey, vk_hex(&sk));
        assert_eq!(reply.reply_to, "root_post_id_aaaaaa");
        assert!(reply.quoted_post.is_empty());
        assert!(reply.id_is_valid());
        assert!(reply.signature.is_some());
    }

    // R2. A reply signed for root A fails verification when reply_to is swapped
    //     to root B (rebinding guard). Changing reply_to changes the signing
    //     payload, so the id no longer matches — a misfiled reply is detectable.
    #[test]
    fn signed_reply_rebinding_breaks_verification() {
        let sk = signing_key_from_seed(&SEED_A);
        let reply = build_signed_reply(
            &sk,
            "nice post",
            "Bob",
            "@bob",
            1_700_000_000_001,
            "root_post_id_aaaaaa",
            "",
        );
        assert_eq!(reply.verify(), Ok(()));

        // Swap reply_to to a different root — id should no longer match.
        let mut moved = reply.clone();
        moved.reply_to = "root_post_id_bbbbbb".into();
        // id is over the payload which includes reply_to, so id mismatch fires
        // before the signature check.
        assert_eq!(moved.verify(), Err(PostVerifyError::IdMismatch));

        // Fix up the id but keep the original signature — now the signature
        // must fail (the bytes that were signed no longer match).
        moved.id = moved.compute_id();
        assert_eq!(moved.verify(), Err(PostVerifyError::SignatureInvalid));
    }

    // R3a. A reply+quote (both reply_to and quoted_post non-empty) produces the
    //      correct byte order in the signing payload: reply_to is appended first,
    //      then quoted_post (as specified by Post::signing_payload). Verify both
    //      that the assembled post verifies and that the payload bytes match the
    //      hand-constructed expected order.
    #[test]
    fn signed_reply_and_quote_payload_byte_order() {
        let sk = signing_key_from_seed(&SEED_A);
        let reply = build_signed_reply(
            &sk,
            "great and also replying",
            "Alice",
            "@alice",
            1_700_000_000_002,
            "reply_root_id",
            "quoted_post_id",
        );

        // Full verification passes.
        assert_eq!(reply.verify(), Ok(()));
        assert_eq!(reply.reply_to, "reply_root_id");
        assert_eq!(reply.quoted_post, "quoted_post_id");

        // Manually reconstruct the expected payload to pin the field order:
        // domain tag, author_pubkey, author_name, author_handle, content,
        // timestamp (LE u64), reply_to (non-empty → appended), quoted_post
        // (non-empty → appended after reply_to). Use the same length-prefix
        // encoding Post::signing_payload uses.
        fn put(buf: &mut Vec<u8>, field: &[u8]) {
            buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
            buf.extend_from_slice(field);
        }
        let mut expected = Vec::new();
        put(
            &mut expected,
            freenet_microblogging_common::post::POST_DOMAIN_TAG,
        );
        put(&mut expected, reply.author_pubkey.as_bytes());
        put(&mut expected, b"Alice");
        put(&mut expected, b"@alice");
        put(&mut expected, b"great and also replying");
        put(&mut expected, &1_700_000_000_002u64.to_le_bytes());
        put(&mut expected, b"reply_root_id"); // reply_to first
        put(&mut expected, b"quoted_post_id"); // quoted_post second

        assert_eq!(reply.signing_payload(), expected);
    }

    // R3b. SignPost path is byte-identical: a post built with build_signed_post
    //      (empty reply_to) and a reply built with build_signed_reply for the
    //      same content have DIFFERENT signing payloads (reply_to being non-empty
    //      extends the payload). Ensures the two paths do not collide.
    #[test]
    fn top_level_post_and_reply_have_different_payloads() {
        let sk = signing_key_from_seed(&SEED_A);
        let top_post = build_signed_post(&sk, "same content", "Alice", "@alice", 1_000, "");
        let reply = build_signed_reply(
            &sk,
            "same content",
            "Alice",
            "@alice",
            1_000,
            "some_root_id",
            "",
        );

        // Different payloads → different ids and different signatures.
        assert_ne!(top_post.signing_payload(), reply.signing_payload());
        assert_ne!(top_post.id, reply.id);
        // Both still verify independently.
        assert_eq!(top_post.verify(), Ok(()));
        assert_eq!(reply.verify(), Ok(()));
    }
}
