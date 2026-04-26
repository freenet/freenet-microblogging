#![allow(unexpected_cfgs)]
use ed25519_dalek::{Signer, SigningKey};
use freenet_stdlib::prelude::*;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

struct IdentityDelegate;

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
    /// Sign a post's content bytes. Returns the signature.
    SignPost {
        post_content: String,
        post_id: String,
    },
    /// Export the private key for backup/migration.
    ExportIdentity,
    /// Import a private key + identity from another device.
    ImportIdentity {
        secret_key: String, // hex-encoded 32-byte Ed25519 secret key
        display_name: String,
    },
}

/// Messages the delegate sends back to the web UI.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
enum Response {
    Identity {
        public_key: String, // hex-encoded
        handle: String,
        display_name: String,
    },
    Signed {
        post_id: String,
        signature: String,  // hex-encoded
        public_key: String, // hex-encoded
    },
    ExportedIdentity {
        secret_key: String, // hex-encoded 32-byte secret key
        public_key: String, // hex-encoded
        display_name: String,
        handle: String,
    },
    Error {
        message: String,
    },
}

// Secret storage keys
const SECRET_SIGNING_KEY: &[u8] = b"signing_key";
const SECRET_HANDLE: &[u8] = b"handle";
const SECRET_DISPLAY_NAME: &[u8] = b"display_name";

/// A thin RNG wrapper that delegates to the freenet-stdlib host function.
///
/// `freenet_stdlib::rand::rand_bytes` calls the WASM host import
/// `__frnt__rand__rand_bytes` which is provided by the Freenet kernel.
/// This avoids any dependency on `getrandom` / OS entropy in WASM.
struct FreenetRng;

impl RngCore for FreenetRng {
    fn next_u32(&mut self) -> u32 {
        let bytes = freenet_stdlib::rand::rand_bytes(4);
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }

    fn next_u64(&mut self) -> u64 {
        let bytes = freenet_stdlib::rand::rand_bytes(8);
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let bytes = freenet_stdlib::rand::rand_bytes(dest.len() as u32);
        dest.copy_from_slice(&bytes);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// Mark FreenetRng as a cryptographically secure RNG so ed25519-dalek accepts it.
impl rand_core::CryptoRng for FreenetRng {}

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
                        post_content,
                        post_id,
                    } => sign_post(ctx, &post_content, &post_id),
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

fn create_identity(ctx: &mut DelegateCtx, handle: &str, display_name: &str) -> Response {
    let mut rng = FreenetRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    ctx.set_secret(SECRET_SIGNING_KEY, &signing_key.to_bytes());
    ctx.set_secret(SECRET_HANDLE, handle.as_bytes());
    ctx.set_secret(SECRET_DISPLAY_NAME, display_name.as_bytes());

    Response::Identity {
        public_key: hex::encode(verifying_key.to_bytes()),
        handle: handle.to_string(),
        display_name: display_name.to_string(),
    }
}

fn get_identity(ctx: &DelegateCtx) -> Response {
    match ctx.get_secret(SECRET_SIGNING_KEY) {
        Some(key_bytes) => {
            let key_arr: [u8; 32] = match key_bytes.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    return Response::Error {
                        message: "stored signing key has unexpected length".to_string(),
                    };
                }
            };
            let signing_key = SigningKey::from_bytes(&key_arr);
            let verifying_key = signing_key.verifying_key();

            let handle = ctx
                .get_secret(SECRET_HANDLE)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            let display_name = ctx
                .get_secret(SECRET_DISPLAY_NAME)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();

            Response::Identity {
                public_key: hex::encode(verifying_key.to_bytes()),
                handle,
                display_name,
            }
        }
        None => Response::Error {
            message: "no identity found — call CreateIdentity first".to_string(),
        },
    }
}

fn sign_post(ctx: &DelegateCtx, post_content: &str, post_id: &str) -> Response {
    match ctx.get_secret(SECRET_SIGNING_KEY) {
        Some(key_bytes) => {
            let key_arr: [u8; 32] = match key_bytes.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    return Response::Error {
                        message: "stored signing key has unexpected length".to_string(),
                    };
                }
            };
            let signing_key = SigningKey::from_bytes(&key_arr);
            let verifying_key = signing_key.verifying_key();
            let signature = signing_key.sign(post_content.as_bytes());

            Response::Signed {
                post_id: post_id.to_string(),
                signature: hex::encode(signature.to_bytes()),
                public_key: hex::encode(verifying_key.to_bytes()),
            }
        }
        None => Response::Error {
            message: "no identity — cannot sign".to_string(),
        },
    }
}

fn export_identity(ctx: &DelegateCtx) -> Response {
    match ctx.get_secret(SECRET_SIGNING_KEY) {
        Some(key_bytes) => {
            let key_arr: [u8; 32] = match key_bytes.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    return Response::Error {
                        message: "stored signing key has unexpected length".to_string(),
                    };
                }
            };
            let signing_key = SigningKey::from_bytes(&key_arr);
            let verifying_key = signing_key.verifying_key();
            let handle = ctx
                .get_secret(SECRET_HANDLE)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            let display_name = ctx
                .get_secret(SECRET_DISPLAY_NAME)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();

            Response::ExportedIdentity {
                secret_key: hex::encode(signing_key.to_bytes()),
                public_key: hex::encode(verifying_key.to_bytes()),
                display_name,
                handle,
            }
        }
        None => Response::Error {
            message: "no identity to export".to_string(),
        },
    }
}

fn import_identity(ctx: &mut DelegateCtx, secret_key_hex: &str, display_name: &str) -> Response {
    let key_bytes = match hex::decode(secret_key_hex) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => {
            return Response::Error {
                message: "invalid secret key: must be 64 hex characters (32 bytes)".to_string(),
            };
        }
    };

    let key_arr: [u8; 32] = key_bytes.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&key_arr);
    let verifying_key = signing_key.verifying_key();
    let public_key = hex::encode(verifying_key.to_bytes());
    let handle = public_key[..8].to_string();

    ctx.set_secret(SECRET_SIGNING_KEY, &signing_key.to_bytes());
    ctx.set_secret(SECRET_HANDLE, handle.as_bytes());
    ctx.set_secret(SECRET_DISPLAY_NAME, display_name.as_bytes());

    Response::Identity {
        public_key,
        handle,
        display_name: display_name.to_string(),
    }
}
