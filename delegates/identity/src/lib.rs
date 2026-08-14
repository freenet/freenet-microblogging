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
// Every secret is namespaced under the calling app's attested origin (see
// `origin_key`) — two apps addressing this delegate never see each other's
// secrets.
const SECRET_SEED: &[u8] = b"mldsa_seed";
const SECRET_HANDLE: &[u8] = b"handle";
const SECRET_DISPLAY_NAME: &[u8] = b"display_name";

/// Separator between the caller namespace and the key. `:` cannot occur in a
/// hex id, so a namespaced key can never be ambiguous.
const ORIGIN_KEY_SEPARATOR: &str = ":";

/// The attested identity of whoever sent the current request.
///
/// `MessageOrigin::WebApp` carries the calling web app's `ContractInstanceId`,
/// which the runtime attests — the delegate does not have to take the caller's
/// word for who it is. Keeping it (rather than matching `WebApp(_)`) is what
/// lets every stored secret be scoped to the app that created it.
struct Origin(Vec<u8>);

impl Origin {
    /// Hex rather than base58 only to avoid adding a dependency to a WASM
    /// build that pins every dep exactly; the encoding just has to be
    /// unambiguous and stable.
    fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

/// Namespace a secret key under the caller.
///
/// This is the whole isolation mechanism, and it is deliberately structural
/// rather than a permission check: a caller cannot reach another caller's
/// secrets because it never names them. There is no rule to remember to apply
/// on a newly added request type — a new handler that stores something gets
/// the same scoping for free.
fn origin_key(origin: &Origin, key: &[u8]) -> Vec<u8> {
    format!(
        "{}{}{}",
        origin.to_hex(),
        ORIGIN_KEY_SEPARATOR,
        String::from_utf8_lossy(key)
    )
    .into_bytes()
}

/// Resolve the attested caller, or refuse to act.
///
/// Only a web app may drive this delegate. An inter-delegate call is refused
/// outright: `MessageOrigin::Delegate` identifies the calling delegate, not the
/// person, so there is nobody whose identity it would be acting for. An unknown
/// variant is refused too, so extending the enum upstream fails closed here
/// instead of silently widening who may call.
fn resolve_origin(origin: &Option<MessageOrigin>) -> Result<Origin, DelegateError> {
    match origin {
        Some(MessageOrigin::WebApp(contract_id)) => Ok(Origin(contract_id.as_bytes().to_vec())),
        Some(MessageOrigin::Delegate(caller)) => Err(DelegateError::Other(format!(
            "identity delegate does not accept inter-delegate calls (caller: {caller})"
        ))),
        None => Err(DelegateError::Other("missing message origin".into())),
        _ => Err(DelegateError::Other(
            "unknown MessageOrigin variant — identity delegate must be rebuilt \
             against a newer freenet-stdlib"
                .into(),
        )),
    }
}

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
        // Resolve the attested caller. Every secret this request touches is
        // scoped to it, so an app can only ever reach the identity it created.
        let origin = resolve_origin(&origin)?;

        match message {
            InboundDelegateMsg::ApplicationMessage(app_msg) => {
                let request: Request = serde_json::from_slice(&app_msg.payload)
                    .map_err(|e| DelegateError::Other(format!("invalid request: {e}")))?;

                let response = match request {
                    Request::CreateIdentity {
                        handle,
                        display_name,
                    } => create_identity(ctx, &origin, &handle, &display_name),
                    Request::GetIdentity => get_identity(ctx, &origin),
                    Request::SignPost {
                        nonce,
                        content,
                        author_name,
                        author_handle,
                        timestamp,
                        quoted_post,
                    } => sign_post(
                        ctx,
                        &origin,
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
                    } => sign_like(ctx, &origin, &nonce, &root_post_id, seq, liked),
                    Request::SignRepost {
                        nonce,
                        root_post_id,
                        seq,
                        reposted,
                    } => sign_repost(ctx, &origin, &nonce, &root_post_id, seq, reposted),
                    Request::SignQuoteRef {
                        nonce,
                        root_post_id,
                        quote_post_id,
                    } => sign_quote_ref(ctx, &origin, &nonce, &root_post_id, &quote_post_id),
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
                        &origin,
                        &nonce,
                        &content,
                        &author_name,
                        &author_handle,
                        timestamp,
                        &reply_to,
                        &quoted_post,
                    ),
                    Request::ExportIdentity => export_identity(ctx, &origin),
                    Request::ImportIdentity {
                        secret_key,
                        display_name,
                    } => import_identity(ctx, &origin, &secret_key, &display_name),
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

// `Response` is the delegate's wire enum, so its size is the size of its
// largest variant. Boxing the Err here to satisfy `result_large_err` would add
// an allocation on the error path of a function whose Ok path runs on every
// signing request, to save moving a value that is immediately serialized
// anyway.
#[allow(clippy::result_large_err)]
/// Load and validate the stored seed, returning a reconstructed signing key.
fn load_signing_key(
    ctx: &DelegateCtx,
    origin: &Origin,
) -> Result<MlDsaSigningKey<MlDsa65>, Response> {
    let Some(seed_bytes) = ctx.get_secret(&origin_key(origin, SECRET_SEED)) else {
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

fn stored_handle(ctx: &DelegateCtx, origin: &Origin) -> String {
    ctx.get_secret(&origin_key(origin, SECRET_HANDLE))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn stored_display_name(ctx: &DelegateCtx, origin: &Origin) -> String {
    ctx.get_secret(&origin_key(origin, SECRET_DISPLAY_NAME))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn create_identity(
    ctx: &mut DelegateCtx,
    origin: &Origin,
    handle: &str,
    display_name: &str,
) -> Response {
    let seed = random_seed();
    let signing_key = signing_key_from_seed(&seed);
    let public_key = vk_hex(&signing_key);
    // An empty handle from the UI means "derive one" — use the VK prefix.
    let handle = if handle.is_empty() {
        public_key[..8].to_string()
    } else {
        handle.to_string()
    };

    ctx.set_secret(&origin_key(origin, SECRET_SEED), &seed);
    ctx.set_secret(&origin_key(origin, SECRET_HANDLE), handle.as_bytes());
    ctx.set_secret(
        &origin_key(origin, SECRET_DISPLAY_NAME),
        display_name.as_bytes(),
    );

    Response::Identity {
        public_key,
        handle,
        display_name: display_name.to_string(),
    }
}

fn get_identity(ctx: &DelegateCtx, origin: &Origin) -> Response {
    let signing_key = match load_signing_key(ctx, origin) {
        Ok(k) => k,
        Err(resp) => return resp,
    };
    Response::Identity {
        public_key: vk_hex(&signing_key),
        handle: stored_handle(ctx, origin),
        display_name: stored_display_name(ctx, origin),
    }
}

#[allow(clippy::too_many_arguments)]
fn sign_post(
    ctx: &DelegateCtx,
    origin: &Origin,
    nonce: &str,
    content: &str,
    author_name: &str,
    author_handle: &str,
    timestamp: u64,
    quoted_post: &str,
) -> Response {
    let signing_key = match load_signing_key(ctx, origin) {
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
    origin: &Origin,
    nonce: &str,
    root_post_id: &str,
    seq: u64,
    liked: bool,
) -> Response {
    let signing_key = match load_signing_key(ctx, origin) {
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
    origin: &Origin,
    nonce: &str,
    root_post_id: &str,
    seq: u64,
    reposted: bool,
) -> Response {
    let signing_key = match load_signing_key(ctx, origin) {
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
    origin: &Origin,
    nonce: &str,
    root_post_id: &str,
    quote_post_id: &str,
) -> Response {
    let signing_key = match load_signing_key(ctx, origin) {
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
    origin: &Origin,
    nonce: &str,
    content: &str,
    author_name: &str,
    author_handle: &str,
    timestamp: u64,
    reply_to: &str,
    quoted_post: &str,
) -> Response {
    let signing_key = match load_signing_key(ctx, origin) {
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

fn export_identity(ctx: &DelegateCtx, origin: &Origin) -> Response {
    let Some(seed_bytes) = ctx.get_secret(&origin_key(origin, SECRET_SEED)) else {
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
        display_name: stored_display_name(ctx, origin),
        handle: stored_handle(ctx, origin),
    }
}

fn import_identity(
    ctx: &mut DelegateCtx,
    origin: &Origin,
    secret_key_hex: &str,
    display_name: &str,
) -> Response {
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

    ctx.set_secret(&origin_key(origin, SECRET_SEED), &seed);
    ctx.set_secret(&origin_key(origin, SECRET_HANDLE), handle.as_bytes());
    ctx.set_secret(
        &origin_key(origin, SECRET_DISPLAY_NAME),
        display_name.as_bytes(),
    );

    Response::Identity {
        public_key,
        handle,
        display_name: display_name.to_string(),
    }
}

#[cfg(test)]
mod test {
    //! Why most of these tests exercise pure helpers rather than `process()`:
    //!
    //! `process()` itself IS callable off-WASM — `#[delegate]` only generates a
    //! separate `extern "C" fn process` wrapper gated behind `cfg(feature =
    //! "freenet-main-delegate")`; `<IdentityDelegate as DelegateInterface>::process`
    //! remains a plain associated function, and `DelegateCtx` derives `Default`.
    //! The "process() dispatch wiring" tests below call it directly to prove
    //! `resolve_origin(&origin)?` is actually threaded through the match arms —
    //! a property no purely-unit-level test of `resolve_origin`/`origin_key`
    //! alone can catch.
    //!
    //! What genuinely CANNOT be driven off-WASM is the secret *storage*
    //! round-trip: `sign_post` / `sign_like` / `export_identity` /
    //! `import_identity` read and write the signer's seed through
    //! `DelegateCtx::{get_secret, set_secret}`, which are WASM host imports
    //! stubbed off-WASM to always return `None` / `false` (see
    //! `freenet_stdlib::delegate_host`). So a host-driven call into one of those
    //! handlers can never load a key and always returns the "no identity found"
    //! error.
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

    // -- caller scoping --
    //
    // The delegate is reachable by any web app on the node, so every stored
    // secret is namespaced by the attested caller. These tests pin the
    // properties that isolation rests on: distinct callers never collide, the
    // same caller is stable across requests, and only an attested web app may
    // drive the delegate at all.

    fn origin_of(bytes: [u8; 32]) -> Origin {
        Origin(bytes.to_vec())
    }

    #[test]
    fn different_callers_get_different_secret_keys() {
        let a = origin_of([1u8; 32]);
        let b = origin_of([2u8; 32]);
        assert_ne!(
            origin_key(&a, SECRET_SEED),
            origin_key(&b, SECRET_SEED),
            "two apps would share a seed slot"
        );
    }

    #[test]
    fn the_same_caller_is_stable_across_calls() {
        // If this were not stable an app would lose its own identity between
        // requests, which is the failure mode that tempts people to widen the
        // scoping until it does nothing.
        let a = origin_of([7u8; 32]);
        assert_eq!(origin_key(&a, SECRET_SEED), origin_key(&a, SECRET_SEED));
    }

    #[test]
    fn each_secret_is_distinct_within_one_caller() {
        let a = origin_of([7u8; 32]);
        let seed = origin_key(&a, SECRET_SEED);
        let handle = origin_key(&a, SECRET_HANDLE);
        let name = origin_key(&a, SECRET_DISPLAY_NAME);
        assert_ne!(seed, handle);
        assert_ne!(handle, name);
        assert_ne!(seed, name);
    }

    #[test]
    fn a_namespaced_key_cannot_be_confused_with_another() {
        // The separator must not be producible from the id encoding, or one
        // caller could craft a key that resolves into another's namespace.
        let a = origin_of([0xABu8; 32]);
        let key = String::from_utf8(origin_key(&a, SECRET_SEED)).unwrap();
        assert!(key.starts_with(&a.to_hex()));
        assert_eq!(key.matches(ORIGIN_KEY_SEPARATOR).count(), 1);
        // hex ids contain no separator, so the split point is unambiguous
        assert!(!a.to_hex().contains(ORIGIN_KEY_SEPARATOR));
    }

    #[test]
    fn every_secret_access_goes_through_origin_key() {
        // `get_secret`/`set_secret` are host-stubbed to always return
        // `None`/`false` off-WASM (see the module doc above), so no test that
        // drives `process()` or a handler can observe whether a namespacing
        // regression (a handler reverted to a bare SECRET_SEED/SECRET_HANDLE/
        // SECRET_DISPLAY_NAME constant) actually happened — the response
        // still assembles and every existing test still passes. This
        // source-scrape is the only thing that can catch it: every
        // `ctx.get_secret(`/`ctx.set_secret(` call site, wherever it falls
        // relative to line breaks, must have `origin_key(` within the next
        // few tokens.
        let source = include_str!("lib.rs");
        let impl_source = source
            .split("#[cfg(test)]")
            .next()
            .expect("this file has a #[cfg(test)] module");
        let bytes = impl_source.as_bytes();

        // Span of THIS call's own argument list, matching parens by depth —
        // not a fixed-width window, which can bleed into the NEXT call site
        // on a short line and spuriously "find" ITS `origin_key(` instead.
        fn call_args_span(bytes: &[u8], open_paren: usize) -> &str {
            let mut depth = 0i32;
            let mut end = open_paren;
            for (i, &b) in bytes.iter().enumerate().skip(open_paren) {
                match b {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            std::str::from_utf8(&bytes[open_paren..=end]).unwrap()
        }

        for needle in ["get_secret(", "set_secret("] {
            let mut search_from = 0;
            while let Some(rel) = impl_source[search_from..].find(needle) {
                let pos = search_from + rel;
                let open_paren = pos + needle.len() - 1;
                let args = call_args_span(bytes, open_paren);
                assert!(
                    args.contains("origin_key("),
                    "found `{needle}` not routed through `origin_key(`: {args:?}"
                );
                search_from = pos + needle.len();
            }
        }
    }

    #[test]
    fn only_a_web_app_may_drive_the_delegate() {
        use freenet_stdlib::prelude::ContractInstanceId;
        let app = ContractInstanceId::new([5u8; 32]);
        assert!(resolve_origin(&Some(MessageOrigin::WebApp(app))).is_ok());
        // No origin at all: nothing to scope to, so nothing may be done.
        assert!(resolve_origin(&None).is_err());
    }

    #[test]
    fn an_inter_delegate_call_is_refused() {
        // A delegate caller identifies the delegate, not a person — there is no
        // identity it would be acting for, so acting at all is wrong.
        let caller = DelegateKey::from_params("x", &Parameters::from(vec![]))
            .expect("build a delegate key for the test");
        assert!(resolve_origin(&Some(MessageOrigin::Delegate(caller))).is_err());
    }

    // -- process() dispatch wiring --
    //
    // The tests above cover `resolve_origin`/`origin_key` as PURE functions.
    // They do not prove `process()` actually calls `resolve_origin(&origin)?`
    // and threads the result into its handlers — a future edit that weakened
    // that `?` (e.g. to `.unwrap_or(Origin(vec![]))`) would leave every test
    // above green. `<IdentityDelegate as DelegateInterface>::process` is a
    // plain associated function; `#[delegate]` only adds a separate
    // `extern "C" fn process` wrapper behind `cfg(feature =
    // "freenet-main-delegate")` (see freenet-macros' `delegate_impl.rs`), so
    // the real `process()` is directly callable here, off-WASM, with no macro
    // involved. `DelegateCtx` derives `Default` (its host-side `get_secret`/
    // `set_secret` are stubbed to always return `None`/`false` off-WASM — see
    // the module doc above), so only the dispatch path is exercised, not the
    // storage round-trip.

    #[test]
    fn process_refuses_missing_origin() {
        let mut ctx = DelegateCtx::default();
        let msg = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(
            serde_json::to_vec(&Request::GetIdentity).unwrap(),
        ));
        let result = <IdentityDelegate as DelegateInterface>::process(
            &mut ctx,
            Parameters::from(vec![]),
            None,
            msg,
        );
        assert!(result.is_err());
    }

    #[test]
    fn process_refuses_delegate_origin() {
        let mut ctx = DelegateCtx::default();
        let msg = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(
            serde_json::to_vec(&Request::GetIdentity).unwrap(),
        ));
        let caller = DelegateKey::from_params("x", &Parameters::from(vec![]))
            .expect("build a delegate key for the test");
        let result = <IdentityDelegate as DelegateInterface>::process(
            &mut ctx,
            Parameters::from(vec![]),
            Some(MessageOrigin::Delegate(caller)),
            msg,
        );
        assert!(result.is_err());
    }

    #[test]
    fn process_threads_webapp_origin_into_create_identity() {
        use freenet_stdlib::prelude::ContractInstanceId;

        let mut ctx = DelegateCtx::default();
        let request = Request::CreateIdentity {
            handle: "alice".to_string(),
            display_name: "Alice".to_string(),
        };
        let msg = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(
            serde_json::to_vec(&request).unwrap(),
        ));
        let app = ContractInstanceId::new([9u8; 32]);

        let mut outbound = <IdentityDelegate as DelegateInterface>::process(
            &mut ctx,
            Parameters::from(vec![]),
            Some(MessageOrigin::WebApp(app)),
            msg,
        )
        .expect("a WebApp-origin CreateIdentity request must be accepted");

        let OutboundDelegateMsg::ApplicationMessage(out) = outbound.remove(0) else {
            panic!("expected an ApplicationMessage response");
        };
        let response: Response = serde_json::from_slice(&out.payload).unwrap();
        match response {
            Response::Identity {
                handle,
                display_name,
                public_key,
            } => {
                assert_eq!(handle, "alice");
                assert_eq!(display_name, "Alice");
                // ML-DSA-65 VK is 1952 bytes -> 3904 hex chars.
                assert_eq!(public_key.len(), 1952 * 2);
            }
            _ => panic!("expected Response::Identity"),
        }
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
