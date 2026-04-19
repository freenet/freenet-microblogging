/**
 * delegate-api.ts — Delegate communication layer
 *
 * Sends delegate requests via the FreenetWsApi private sendRequest method.
 * Uses dynamic imports to access internal stdlib T-types that have pack().
 */

import {
  FreenetWsApi,
  DelegateRequest,
  DelegateResponse,
} from "@freenetorg/freenet-stdlib";

export { DelegateResponse };

/**
 * Send a JSON message to the identity delegate.
 */
export async function sendIdentityMessage(
  api: FreenetWsApi,
  delegateKeyBytes: number[],
  delegateCodeHash: number[],
  message: object
): Promise<void> {
  const payload = Array.from(new TextEncoder().encode(JSON.stringify(message)));

  // Import internal types dynamically — Vite resolves via alias, tsc can't
  // @ts-ignore — resolved by Vite alias at build time
  const { ApplicationMessageT } = await import("@freenetorg/freenet-stdlib/common");
  // @ts-ignore — resolved by Vite alias at build time
  const clientReqModule = await import("@freenetorg/freenet-stdlib/client-request");
  const { ClientRequestT, ClientRequestType, ApplicationMessagesT, DelegateKeyT, DelegateRequestType, InboundDelegateMsgT, InboundDelegateMsgType } = clientReqModule;

  // Build proper instances with pack() methods
  const appMsg = new ApplicationMessageT(payload, [], false);

  const inbound = new InboundDelegateMsgT(
    InboundDelegateMsgType.common_ApplicationMessage,
    appMsg
  );

  const delegateKey = new DelegateKeyT(delegateKeyBytes, delegateCodeHash);

  const appMessages = new ApplicationMessagesT(delegateKey, [], [inbound]);

  const delegateReq = new DelegateRequest(
    DelegateRequestType.ApplicationMessages,
    appMessages
  );

  const clientReq = new ClientRequestT(
    ClientRequestType.DelegateRequest,
    delegateReq
  );

  (api as any).sendRequest(clientReq);
}

/**
 * Parse a DelegateResponse and extract application message payloads.
 */
export function parseDelegateResponse(response: DelegateResponse): object[] {
  const results: object[] = [];
  if (!response.values) return results;

  for (const outbound of response.values) {
    // OutboundDelegateMsgType.common_ApplicationMessage = 1
    if (outbound.inboundType !== 1) continue;

    const msg = outbound.inbound as { payload?: number[] } | null;
    if (!msg?.payload?.length) continue;

    try {
      const bytes = new Uint8Array(msg.payload);
      const json = new TextDecoder().decode(bytes);
      results.push(JSON.parse(json));
    } catch (e) {
      console.warn("[delegate-api] Failed to parse delegate payload:", e);
    }
  }

  return results;
}
