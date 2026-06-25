/**
 * identity.ts — Identity management
 *
 * Two modes:
 *  1. Delegate mode: sends messages to the identity delegate (persistent)
 *  2. In-memory simulation: fallback when delegate not connected
 */

import { FreenetWsApi } from "@freenetorg/freenet-stdlib";
import { sendIdentityMessage } from "./delegate-api";

export interface Identity {
  publicKey: string;
  displayName: string;
  handle: string;
}

let currentIdentity: Identity | null = null;

let delegateApi: FreenetWsApi | null = null;
let delegateKeyBytes: number[] | null = null;
let delegateCodeHashBytes: number[] | null = null;

type ExportListener = (secretKey: string) => void;
let exportListener: ExportListener | null = null;

export function onIdentityExported(listener: ExportListener): void {
  exportListener = listener;
}

export function connectDelegate(
  api: FreenetWsApi,
  keyBytes: number[],
  codeHashBytes: number[]
): void {
  delegateApi = api;
  delegateKeyBytes = keyBytes;
  delegateCodeHashBytes = codeHashBytes;
  console.log("[identity] Delegate connection wired");
}

export function isDelegateConnected(): boolean {
  return delegateApi !== null && delegateKeyBytes !== null;
}

function generateFakePubkey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function getIdentity(): Identity | null {
  return currentIdentity;
}

export function hasIdentity(): boolean {
  return currentIdentity !== null;
}

export function createIdentity(displayName: string, secretKey?: string): Identity {
  if (isDelegateConnected()) {
    const msg = secretKey
      ? { type: "ImportIdentity", secret_key: secretKey, display_name: displayName }
      : { type: "CreateIdentity", display_name: displayName, handle: "" };

    sendIdentityMessage(delegateApi!, delegateKeyBytes!, delegateCodeHashBytes!, msg)
      .catch((e) => console.warn("[identity] Failed to send to delegate:", e));
  }

  // The ML-DSA-65 verifying key is 1952 bytes and is NOT derivable from the
  // 32-byte secret seed by string-slicing — the delegate is the sole source of
  // the public key and returns it in its `Identity`/`Signed` responses
  // (see applyDelegateIdentity). When connected we use a provisional placeholder
  // here and let the delegate response replace it. Offline we only have a fake.
  const publicKey = isDelegateConnected() ? "" : generateFakePubkey();
  const handle = publicKey ? publicKey.slice(0, 8) : "";
  currentIdentity = { publicKey, displayName, handle };
  return currentIdentity;
}

/**
 * Ask the delegate to sign a post. The delegate builds the canonical signing
 * payload, derives the content-addressed id, and replies with a `Signed`
 * response routed through onDelegateResponse → freenet-api completePublish.
 */
export function signPost(
  nonce: string,
  content: string,
  authorName: string,
  authorHandle: string,
  timestamp: number,
  quotedPost = ""
): boolean {
  if (!isDelegateConnected()) return false;
  sendIdentityMessage(delegateApi!, delegateKeyBytes!, delegateCodeHashBytes!, {
    type: "SignPost",
    nonce,
    content,
    author_name: authorName,
    author_handle: authorHandle,
    timestamp,
    quoted_post: quotedPost,
  }).catch((e) => console.warn("[identity] SignPost failed:", e));
  return true;
}

/**
 * Ask the delegate to sign a like/unlike for a thread. The delegate builds the
 * canonical `LikeRecord` payload (common::thread, the single trusted encoder)
 * and replies with a `SignedLike` routed through onDelegateResponse →
 * freenet-api completeLike. Returns false if no delegate (cannot sign offline).
 */
export function signLike(
  nonce: string,
  rootPostId: string,
  seq: number,
  liked: boolean
): boolean {
  if (!isDelegateConnected()) return false;
  sendIdentityMessage(delegateApi!, delegateKeyBytes!, delegateCodeHashBytes!, {
    type: "SignLike",
    nonce,
    root_post_id: rootPostId,
    seq,
    liked,
  }).catch((e) => console.warn("[identity] SignLike failed:", e));
  return true;
}

/**
 * Ask the delegate to sign a repost/un-repost for a thread. Mirror of
 * {@link signLike}: the delegate builds the canonical `RepostRecord` payload
 * (common::thread) and replies with a `SignedRepost` routed through
 * onDelegateResponse → freenet-api completeRepost. Returns false if no delegate.
 */
export function signRepost(
  nonce: string,
  rootPostId: string,
  seq: number,
  reposted: boolean
): boolean {
  if (!isDelegateConnected()) return false;
  sendIdentityMessage(delegateApi!, delegateKeyBytes!, delegateCodeHashBytes!, {
    type: "SignRepost",
    nonce,
    root_post_id: rootPostId,
    seq,
    reposted,
  }).catch((e) => console.warn("[identity] SignRepost failed:", e));
  return true;
}

/**
 * Ask the delegate to sign a quote reference for a thread: records that the
 * signer quoted `rootPostId` in their own `quotePostId`. The delegate replies
 * with a `SignedQuoteRef` routed through onDelegateResponse → freenet-api
 * completeQuoteRef. Returns false if no delegate.
 */
export function signQuoteRef(
  nonce: string,
  rootPostId: string,
  quotePostId: string
): boolean {
  if (!isDelegateConnected()) return false;
  sendIdentityMessage(delegateApi!, delegateKeyBytes!, delegateCodeHashBytes!, {
    type: "SignQuoteRef",
    nonce,
    root_post_id: rootPostId,
    quote_post_id: quotePostId,
  }).catch((e) => console.warn("[identity] SignQuoteRef failed:", e));
  return true;
}

/**
 * Ask the delegate to sign a reply post. Structurally identical to a regular
 * post but the `reply_to` field is populated (the content-address of the root
 * post being replied to). The delegate sends a `SignReply` request and replies
 * with a `SignedReply` response routed through onDelegateResponse →
 * freenet-api completeReply. Returns false if no delegate (cannot sign offline).
 */
export function signReply(
  nonce: string,
  content: string,
  authorName: string,
  authorHandle: string,
  timestamp: number,
  replyTo: string,
  quotedPost = ""
): boolean {
  if (!isDelegateConnected()) return false;
  sendIdentityMessage(delegateApi!, delegateKeyBytes!, delegateCodeHashBytes!, {
    type: "SignReply",
    nonce,
    content,
    author_name: authorName,
    author_handle: authorHandle,
    timestamp,
    reply_to: replyTo,
    quoted_post: quotedPost,
  }).catch((e) => console.warn("[identity] SignReply failed:", e));
  return true;
}

export function exportIdentity(): void {
  if (!isDelegateConnected()) {
    // Offline / no delegate: synthesize a placeholder so the modal still appears
    // and the user understands export is not available without a node.
    exportListener?.("(offline mode — connect to a Freenet node to export your real key)");
    return;
  }
  sendIdentityMessage(delegateApi!, delegateKeyBytes!, delegateCodeHashBytes!, {
    type: "ExportIdentity",
  }).catch((e) => console.warn("[identity] Export failed:", e));
}

export function requestIdentityFromDelegate(): void {
  if (!isDelegateConnected()) return;
  sendIdentityMessage(delegateApi!, delegateKeyBytes!, delegateCodeHashBytes!, {
    type: "GetIdentity",
  }).catch((e) => console.warn("[identity] GetIdentity failed:", e));
}

export function applyDelegateIdentity(payload: object): boolean {
  const p = payload as {
    type?: string;
    public_key?: string;
    secret_key?: string;
    display_name?: string;
    handle?: string;
  };

  if (p.type === "Identity" && p.public_key && p.display_name) {
    currentIdentity = {
      publicKey: p.public_key,
      displayName: p.display_name,
      handle: p.handle || p.public_key.slice(0, 8),
    };
    console.log(`[identity] Delegate identity: ${currentIdentity.displayName} (@${currentIdentity.handle})`);
    return true;
  }

  if (p.type === "ExportedIdentity" && p.secret_key) {
    exportListener?.(p.secret_key);
    return true;
  }

  return false;
}
