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

  const publicKey = secretKey ? secretKey.slice(0, 64) : generateFakePubkey();
  const handle = publicKey.slice(0, 8);
  currentIdentity = { publicKey, displayName, handle };
  return currentIdentity;
}

export function exportIdentity(): void {
  if (!isDelegateConnected()) return;
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
    alert(`Your secret key (save this to import on another device):\n\n${p.secret_key}`);
    return true;
  }

  return false;
}
