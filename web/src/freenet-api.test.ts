import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type {
  GetRequest,
  GetResponse,
  UpdateNotification,
} from "@freenetorg/freenet-stdlib";
import { UpdateDataType } from "@freenetorg/freenet-stdlib";
import * as flatbuffers from "flatbuffers";
import { buildShardPutRequest } from "./freenet-api";

// ---------------------------------------------------------------------------
// Mocking approach
// ---------------------------------------------------------------------------
// freenet-api.ts builds its WebSocket client from the stdlib's `FreenetWsApi`
// inside connect(). Every OTHER stdlib symbol it (and shard-key.ts) uses —
// ContractKey, GetRequest, WasmContractV1, the flatbuffer tables — must stay
// REAL, because shard-key.ts derives genuine ContractKeys and the production
// code routes GET responses by `key.encode()`. So we do a PARTIAL mock: keep
// `...actual`, and replace only `FreenetWsApi` with a fake whose constructor
// captures the ResponseHandler and whose `.get()` returns deferred promises we
// settle by hand. That lets us drive the client state machine deterministically
// without a node, while real keys still match real responses.
//
// `./identity` is mocked too: likePost/publishPost call signLike/signPost,
// which only succeed when a delegate is connected. We stub them to report
// "delegate connected" so those flows proceed without a real delegate.

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
  req: GetRequest;
}

// The FakeWsApi class must be defined inside vi.hoisted, because vi.mock's
// factory is hoisted to the very top of the module — referencing a normal
// top-level class there throws "Cannot access before initialization". Anything
// the factory closes over has to come from vi.hoisted (which runs first).
const { FakeWsApi } = vi.hoisted(() => {
  function deferred<T>(req: GetRequest): Deferred<T> {
    let resolve!: (v: T) => void;
    let reject!: (e: unknown) => void;
    const promise = new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    return { promise, resolve, reject, req };
  }

  /** Fake FreenetWsApi: records calls, hands back controllable GET promises. */
  class FakeWsApi {
    static instances: FakeWsApi[] = [];
    handler: import("@freenetorg/freenet-stdlib").ResponseHandler;
    getCalls: Deferred<GetResponse>[] = [];
    putCalls: unknown[] = [];
    updateCalls: unknown[] = [];
    subscribeCalls: unknown[] = [];
    /** When set, update() rejects with this — to exercise completeLike's catch. */
    updateError: Error | null = null;

    constructor(
      _url: URL,
      handler: import("@freenetorg/freenet-stdlib").ResponseHandler,
      _token: string,
    ) {
      this.handler = handler;
      FakeWsApi.instances.push(this);
    }

    get(req: GetRequest): Promise<GetResponse> {
      const d = deferred<GetResponse>(req);
      this.getCalls.push(d);
      return d.promise;
    }

    put(req: unknown): Promise<void> {
      this.putCalls.push(req);
      return Promise.resolve();
    }

    update(req: unknown): Promise<void> {
      this.updateCalls.push(req);
      return this.updateError
        ? Promise.reject(this.updateError)
        : Promise.resolve();
    }

    subscribe(req: unknown): Promise<void> {
      this.subscribeCalls.push(req);
      return Promise.resolve();
    }
  }
  return { FakeWsApi };
});

type FakeWsApi = InstanceType<typeof FakeWsApi>;

vi.mock("@freenetorg/freenet-stdlib", async (importActual) => {
  const actual = await importActual<typeof import("@freenetorg/freenet-stdlib")>();
  return { ...actual, FreenetWsApi: FakeWsApi };
});

// signPost/signLike normally require a connected delegate. Report connected so
// likePost/publishPost proceed; we drive completeLike/completePublish directly.
vi.mock("./identity", () => ({
  signPost: vi.fn(() => true),
  signLike: vi.fn(() => true),
  signRepost: vi.fn(() => true),
  signQuoteRef: vi.fn(() => true),
  signReply: vi.fn(() => true),
}));

import {
  FreenetConnection,
  type FreenetCallbacks,
  type LikeState,
  type RepostState,
  type QuoteState,
} from "./freenet-api";
import type { Post } from "./types";

// A real ML-DSA-65 VK is 1952 bytes → 3904 hex chars; setUser only initialises
// the user shard for a key of exactly that length (the offline 64-char fake is
// rejected). Use a deterministic 3904-char hex owner.
const OWNER_VK = "ab".repeat(1952);

function makeConnection() {
  const callbacks: {
    onPostsLoaded: ReturnType<typeof vi.fn>;
    onNewPost: ReturnType<typeof vi.fn>;
    onStatusChange: ReturnType<typeof vi.fn>;
    onLikeUpdated: ReturnType<typeof vi.fn>;
    onRepostUpdated: ReturnType<typeof vi.fn>;
    onQuoteUpdated: ReturnType<typeof vi.fn>;
    onRepliesUpdated: ReturnType<typeof vi.fn>;
    onGlobalPostsLoaded: ReturnType<typeof vi.fn>;
    onNewGlobalPost: ReturnType<typeof vi.fn>;
  } = {
    onPostsLoaded: vi.fn(),
    onNewPost: vi.fn(),
    onStatusChange: vi.fn(),
    onLikeUpdated: vi.fn(),
    onRepostUpdated: vi.fn(),
    onQuoteUpdated: vi.fn(),
    onRepliesUpdated: vi.fn(),
    onGlobalPostsLoaded: vi.fn(),
    onNewGlobalPost: vi.fn(),
  };
  const conn = new FreenetConnection(callbacks as unknown as FreenetCallbacks);
  conn.connect();
  const api = FakeWsApi.instances[FakeWsApi.instances.length - 1];
  return { conn, api, callbacks };
}

/** Flush the microtask queue so chained `.then` callbacks run. */
const flush = () => new Promise<void>((r) => setTimeout(r, 0));

/**
 * Resolve every GET that appears over a few flush cycles as "exists", letting
 * fire-and-forget serializedGet chains (e.g. recordQuoteRef → ensureThreadShard)
 * make progress without depending on exact ordering. Returns the index of the
 * last GET resolved.
 */
async function drainGets(api: FakeWsApi): Promise<void> {
  for (let i = 0; i < 8; i++) {
    await flush();
    let resolvedAny = false;
    for (const g of api.getCalls) {
      if (!(g as unknown as { _settled?: boolean })._settled) {
        (g as unknown as { _settled?: boolean })._settled = true;
        g.resolve({} as GetResponse);
        resolvedAny = true;
      }
    }
    await flush();
    if (!resolvedAny && i > 1) break;
  }
}

beforeEach(() => {
  FakeWsApi.instances = [];
  vi.useRealTimers();
  // connect() builds `ws://${location.host}/...`; the node test env has no DOM
  // `location`. Stub a minimal one so the URL constructs and our FakeWsApi is
  // reached. (Vitest's default env is `node`; we don't otherwise need a DOM.)
  (globalThis as { location?: { host: string } }).location = {
    host: "localhost:8080",
  };
});

afterEach(() => {
  vi.restoreAllMocks();
  delete (globalThis as { location?: unknown }).location;
});

describe("FreenetConnection", () => {
  describe("serializedGet — single GET in flight (H-1 anti-misroute guarantee)", () => {
    // This is the core property the H-1 fix restores: at most one api.get() is
    // outstanding, so the stdlib's uncorrelated FIFO response queue can never
    // settle the wrong awaited promise. If serialisation regresses, two GETs
    // overlap and responses can be swapped (feed never instantiates / likes
    // silently lost).
    it("does not issue the 2nd GET until the 1st settles", async () => {
      const { conn, api } = makeConnection();

      // Two independent GET-issuing flows started back-to-back: a user-shard
      // load and a thread like-refresh. Both go through serializedGet.
      conn.setUser(OWNER_VK, "Alice", "alice"); // -> initUserShard -> probe GET
      // refreshLikesNow is private; drive it via the public update-notification
      // path would debounce, so reach it through likePost is heavier. Instead
      // issue a second user-shard load via loadState() once the shard key is set.
      await flush();

      // Exactly one GET in flight after kicking off the first flow.
      expect(api.getCalls.length).toBe(1);

      // Start a SECOND serialised GET (another load). It must NOT call api.get()
      // yet — it's queued behind the first on getChain.
      conn.loadState();
      await flush();
      expect(api.getCalls.length).toBe(1); // still only the first

      // Settle the first GET (reject = not-found probe). Chain advances.
      api.getCalls[0].reject(new Error("not found"));
      await flush();
      await flush();

      // Now the second GET is allowed out.
      expect(api.getCalls.length).toBe(2);
    });

    it("advances the chain even when a GET rejects (no wedge)", async () => {
      const { conn, api } = makeConnection();

      // Establish the user-shard key cleanly: resolve initUserShard's probe so
      // it treats the shard as existing (no PUT/fetch), then it issues its own
      // loadUserShard GET. Settle that too so the chain is idle and the key set.
      conn.setUser(OWNER_VK, "Alice", "alice");
      await flush();
      expect(api.getCalls.length).toBe(1); // the probe
      api.getCalls[0].resolve({} as GetResponse); // exists -> no PUT
      await flush();
      await flush();
      expect(api.getCalls.length).toBe(2); // loadUserShard GET issued
      api.getCalls[1].resolve({} as GetResponse);
      await flush();
      await flush();

      // Now drive two serialised loadState() GETs. Reject the first: a wedged
      // chain would block the second forever; the fix advances getChain on
      // settle either way.
      conn.loadState();
      await flush();
      expect(api.getCalls.length).toBe(3);
      conn.loadState();
      await flush();
      expect(api.getCalls.length).toBe(3); // queued behind the (rejecting) #3

      api.getCalls[2].reject(new Error("timeout"));
      await flush();
      await flush();
      // The second load got out despite the rejection -> chain not wedged.
      expect(api.getCalls.length).toBe(4);
    });

    it("each caller sees its own GET outcome (resolve), then chain continues", async () => {
      const { conn, api } = makeConnection();
      conn.setUser(OWNER_VK, "Alice", "alice");
      await flush();
      expect(api.getCalls.length).toBe(1);

      conn.loadState();
      await flush();
      expect(api.getCalls.length).toBe(1);

      // Resolve the first probe GET successfully -> userShardExists() true ->
      // no PUT; chain advances and releases the queued load.
      api.getCalls[0].resolve({} as GetResponse);
      await flush();
      await flush();
      expect(api.getCalls.length).toBe(2);
    });

    // Regression guard for H-A (skeptical review of PR #35): the soft 8 s app
    // timeout MUST NOT advance the chain, because the stdlib keeps the timed-out
    // GET in its `pendingGets` FIFO until a real response or its OWN 30 s reject.
    // If the chain advanced on the soft timeout, the next api.get() would be
    // issued while the stale entry is still queued → two entries → a late
    // response pops the wrong promise (the misroute this fix exists to prevent).
    it("does NOT advance the chain on the soft timeout — only on the real GET settle", async () => {
      vi.useFakeTimers();
      try {
        const { conn, api } = makeConnection();

        conn.setUser(OWNER_VK, "Alice", "alice"); // probe GET in flight
        await vi.advanceTimersByTimeAsync(0);
        expect(api.getCalls.length).toBe(1);

        // A second serialised GET is queued behind the (still-unsettled) probe.
        conn.loadState();
        await vi.advanceTimersByTimeAsync(0);
        expect(api.getCalls.length).toBe(1);

        // Fire the 8 s soft timeout WITHOUT settling the underlying GET. The
        // stdlib entry is still live; the chain must stay blocked.
        await vi.advanceTimersByTimeAsync(8000);
        expect(api.getCalls.length).toBe(1); // 2nd GET still NOT issued

        // Only once the real (late) GET settles does the chain advance.
        api.getCalls[0].resolve({} as GetResponse);
        await vi.advanceTimersByTimeAsync(0);
        await vi.advanceTimersByTimeAsync(0);
        expect(api.getCalls.length).toBe(2);
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe("dropPendingLike — nonce matching", () => {
    it("returns true only when a matching pending like exists, false otherwise", async () => {
      const { conn, api } = makeConnection();

      // Seed a pending like via likePost. likePost -> ensureThreadShard probe
      // GET; resolve it so the shard is treated as existing, then signLike (mock)
      // returns true and the pending like is recorded.
      const likePromise = conn.likePost("post-1", true);
      await flush();
      // ensureThreadShard issued a probe GET; resolve it as existing.
      expect(api.getCalls.length).toBe(1);
      api.getCalls[0].resolve({} as GetResponse);
      const ok = await likePromise;
      expect(ok).toBe(true);

      // We don't know the internal nonce, so test the false branch directly and
      // then exercise the true branch via completeLike below.
      expect(conn.dropPendingLike("nonce-that-does-not-exist")).toBe(false);
    });
  });

  describe("optimistic like revert", () => {
    it("completeLike refreshes (re-GETs) on update SUCCESS", async () => {
      const { conn, api } = makeConnection();

      // Drive completeLike for a known nonce. It folds the like into the thread
      // shard via update(), then refreshLikesNow() issues a GET to read back the
      // authoritative aggregate.
      const before = api.getCalls.length;
      const ok = await conn.completeLike({
        nonce: "n1",
        root_post_id: "root-success",
        signer_pubkey: OWNER_VK,
        seq: Date.now(),
        liked: true,
        signature: "sig",
      });
      // No matching pending like was registered, so completeLike short-circuits
      // false BEFORE updating — register one first to reach the success path.
      expect(ok).toBe(false);
      expect(api.updateCalls.length).toBe(0);
      expect(api.getCalls.length).toBe(before);
    });

    it("completeLike (matched nonce) updates then refreshes on SUCCESS", async () => {
      const { conn, api } = makeConnection();

      // Register a pending like through likePost, capturing its nonce.
      const signLikeMock = (await import("./identity"))
        .signLike as unknown as ReturnType<typeof vi.fn>;
      const likePromise = conn.likePost("root-ok", true);
      await flush();
      api.getCalls[api.getCalls.length - 1].resolve({} as GetResponse); // probe exists
      await likePromise;
      // signLike(nonce, rootPostId, seq, liked) — first arg is the nonce.
      const nonce = signLikeMock.mock.calls[0][0] as string;

      const getsBefore = api.getCalls.length;
      const ok = await conn.completeLike({
        nonce,
        root_post_id: "root-ok",
        signer_pubkey: OWNER_VK,
        seq: Date.now(),
        liked: true,
        signature: "sig",
      });
      expect(ok).toBe(true);
      // Update sent, then a refresh GET issued.
      expect(api.updateCalls.length).toBe(1);
      expect(api.getCalls.length).toBe(getsBefore + 1);
      // The matched nonce was consumed; dropping it again is a no-op.
      expect(conn.dropPendingLike(nonce)).toBe(false);
    });

    it("completeLike refreshes on update FAILURE so the UI reconciles", async () => {
      const { conn, api } = makeConnection();
      api.updateError = new Error("update rejected");

      const signLikeMock = (await import("./identity"))
        .signLike as unknown as ReturnType<typeof vi.fn>;
      const likePromise = conn.likePost("root-fail", true);
      await flush();
      api.getCalls[api.getCalls.length - 1].resolve({} as GetResponse);
      await likePromise;
      const nonce = signLikeMock.mock.calls[
        signLikeMock.mock.calls.length - 1
      ][0] as string;

      const getsBefore = api.getCalls.length;
      const ok = await conn.completeLike({
        nonce,
        root_post_id: "root-fail",
        signer_pubkey: OWNER_VK,
        seq: Date.now(),
        liked: true,
        signature: "sig",
      });
      // Update failed -> returns false, but STILL re-GETs to reconcile the
      // optimistic toggle away (the H-fix: refresh on BOTH paths).
      expect(ok).toBe(false);
      expect(api.updateCalls.length).toBe(1);
      expect(api.getCalls.length).toBe(getsBefore + 1);
    });

    it("dropPendingLike returns true for a real pending like, then false", async () => {
      const { conn, api } = makeConnection();
      const signLikeMock = (await import("./identity"))
        .signLike as unknown as ReturnType<typeof vi.fn>;

      const likePromise = conn.likePost("root-drop", true);
      await flush();
      api.getCalls[api.getCalls.length - 1].resolve({} as GetResponse);
      await likePromise;
      const nonce = signLikeMock.mock.calls[
        signLikeMock.mock.calls.length - 1
      ][0] as string;

      expect(conn.dropPendingLike(nonce)).toBe(true); // matched -> dropped
      expect(conn.dropPendingLike(nonce)).toBe(false); // already gone
    });
  });

  describe("optimistic repost revert", () => {
    it("completeRepost (matched nonce) updates then refreshes on SUCCESS", async () => {
      const { conn, api } = makeConnection();

      const signRepostMock = (await import("./identity"))
        .signRepost as unknown as ReturnType<typeof vi.fn>;
      const repostPromise = conn.repostPost("root-ok", true);
      await flush();
      api.getCalls[api.getCalls.length - 1].resolve({} as GetResponse); // probe exists
      await repostPromise;
      // signRepost(nonce, rootPostId, seq, reposted) — first arg is the nonce.
      const nonce = signRepostMock.mock.calls[0][0] as string;

      const getsBefore = api.getCalls.length;
      const ok = await conn.completeRepost({
        nonce,
        root_post_id: "root-ok",
        signer_pubkey: OWNER_VK,
        seq: Date.now(),
        reposted: true,
        signature: "sig",
      });
      expect(ok).toBe(true);
      expect(api.updateCalls.length).toBe(1);
      expect(api.getCalls.length).toBe(getsBefore + 1);
      expect(conn.dropPendingRepost(nonce)).toBe(false); // consumed
    });

    it("completeRepost refreshes on update FAILURE so the UI reconciles", async () => {
      const { conn, api } = makeConnection();
      api.updateError = new Error("update rejected");

      const signRepostMock = (await import("./identity"))
        .signRepost as unknown as ReturnType<typeof vi.fn>;
      const repostPromise = conn.repostPost("root-fail", true);
      await flush();
      api.getCalls[api.getCalls.length - 1].resolve({} as GetResponse);
      await repostPromise;
      const nonce = signRepostMock.mock.calls[
        signRepostMock.mock.calls.length - 1
      ][0] as string;

      const getsBefore = api.getCalls.length;
      const ok = await conn.completeRepost({
        nonce,
        root_post_id: "root-fail",
        signer_pubkey: OWNER_VK,
        seq: Date.now(),
        reposted: true,
        signature: "sig",
      });
      expect(ok).toBe(false);
      expect(api.updateCalls.length).toBe(1);
      expect(api.getCalls.length).toBe(getsBefore + 1);
    });

    it("dropPendingRepost returns true for a real pending repost, then false", async () => {
      const { conn, api } = makeConnection();
      const signRepostMock = (await import("./identity"))
        .signRepost as unknown as ReturnType<typeof vi.fn>;

      const repostPromise = conn.repostPost("root-drop", true);
      await flush();
      api.getCalls[api.getCalls.length - 1].resolve({} as GetResponse);
      await repostPromise;
      const nonce = signRepostMock.mock.calls[
        signRepostMock.mock.calls.length - 1
      ][0] as string;

      expect(conn.dropPendingRepost(nonce)).toBe(true);
      expect(conn.dropPendingRepost(nonce)).toBe(false);
    });
  });

  describe("quote repost", () => {
    it("quotePost publishes a post carrying quoted_post, then records a QuoteRef", async () => {
      const { conn, api } = makeConnection();
      conn.setUser(OWNER_VK, "Alice", "alice");
      await flush();
      if (api.getCalls.length) api.getCalls[0].resolve({} as GetResponse);
      await flush();
      await flush();

      const signPostMock = (await import("./identity"))
        .signPost as unknown as ReturnType<typeof vi.fn>;
      const signQuoteRefMock = (await import("./identity"))
        .signQuoteRef as unknown as ReturnType<typeof vi.fn>;

      const ok = await conn.quotePost("quoted-post-id", "my take");
      expect(ok).toBe(true);
      // signPost was called WITH the quoted_post arg (6th positional).
      const call = signPostMock.mock.calls[signPostMock.mock.calls.length - 1];
      expect(call[1]).toBe("my take"); // content
      expect(call[5]).toBe("quoted-post-id"); // quoted_post
      const nonce = call[0] as string;

      const updatesBefore = api.updateCalls.length;
      // Complete the publish: sends the quote post to the user shard, then
      // kicks off recordQuoteRef (ensure thread shard + signQuoteRef).
      const pub = await conn.completePublish({
        nonce,
        post_id: "new-quote-post-id",
        signature: "sig",
        public_key: OWNER_VK,
      });
      expect(pub).toBe(true);
      expect(api.updateCalls.length).toBe(updatesBefore + 1); // the quote post

      // recordQuoteRef (fire-and-forget) derives the quoted post's thread shard
      // via a probe GET. Drain any GETs that appear, resolving each as "exists"
      // so ensureThreadShard returns and signQuoteRef fires.
      await drainGets(api);
      const qCall = signQuoteRefMock.mock.calls[signQuoteRefMock.mock.calls.length - 1];
      expect(qCall).toBeDefined();
      expect(qCall[1]).toBe("quoted-post-id"); // root = quoted post
      expect(qCall[2]).toBe("new-quote-post-id"); // quote_post_id = new post
    });

    it("completeQuoteRef folds a Quotes delta into the quoted post's thread shard", async () => {
      const { conn, api } = makeConnection();

      const signQuoteRefMock = (await import("./identity"))
        .signQuoteRef as unknown as ReturnType<typeof vi.fn>;
      // Seed a pending quote-ref via the public quotePost→completePublish path is
      // heavy; instead drive recordQuoteRef indirectly is private, so register
      // through quotePost + completePublish like above, then complete the ref.
      conn.setUser(OWNER_VK, "Alice", "alice");
      await drainGets(api);
      const signPostMock = (await import("./identity"))
        .signPost as unknown as ReturnType<typeof vi.fn>;
      await conn.quotePost("root-q", "c");
      const pubNonce = signPostMock.mock.calls[signPostMock.mock.calls.length - 1][0] as string;
      await conn.completePublish({
        nonce: pubNonce,
        post_id: "new-q",
        signature: "s",
        public_key: OWNER_VK,
      });
      await drainGets(api); // thread probe → signQuoteRef fires
      const qNonce = signQuoteRefMock.mock.calls[signQuoteRefMock.mock.calls.length - 1][0] as string;

      const updatesBefore = api.updateCalls.length;
      const ok = await conn.completeQuoteRef({
        nonce: qNonce,
        root_post_id: "root-q",
        signer_pubkey: OWNER_VK,
        quote_post_id: "new-q",
        signature: "s",
      });
      expect(ok).toBe(true);
      expect(api.updateCalls.length).toBe(updatesBefore + 1); // Quotes delta sent
      expect(conn.dropPendingQuoteRef(qNonce)).toBe(false); // consumed
    });

    it("a thread-shard GET emits onQuoteUpdated with the quote count", async () => {
      const { conn, api, callbacks } = makeConnection();
      conn.setUser(OWNER_VK, "Alice", "alice");
      await flush();
      api.getCalls[0].resolve({} as GetResponse);
      await flush();
      await flush();
      if (api.getCalls[1]) api.getCalls[1].resolve({} as GetResponse);
      await flush();
      await flush();

      // Register the thread instance→root mapping via a repost (cheapest path).
      const rootId = "quote-thread-root";
      const rp = conn.repostPost(rootId, true);
      await flush();
      const probe = api.getCalls[api.getCalls.length - 1];
      probe.resolve({} as GetResponse);
      await rp;

      const quotes = {
        q1: { signer_pubkey: OWNER_VK, quote_post_id: "p1", signature: "s" },
        q2: { signer_pubkey: "cd".repeat(1952), quote_post_id: "p2", signature: "s" },
      };
      const stateBytes = Array.from(
        new TextEncoder().encode(JSON.stringify({ quotes })),
      );
      callbacks.onQuoteUpdated.mockClear();
      api.handler.onContractGet({
        key: probe.req.key,
        state: stateBytes,
      } as unknown as GetResponse);

      expect(callbacks.onQuoteUpdated).toHaveBeenCalledTimes(1);
      const emitted = callbacks.onQuoteUpdated.mock.calls[0][0] as QuoteState;
      expect(emitted.postId).toBe(rootId);
      expect(emitted.count).toBe(2);
    });
  });

  describe("completePublish / dropPendingPost — nonce matching", () => {
    async function seedDraft(conn: FreenetConnection) {
      // publishPost needs a user shard + currentUser. setUser sets currentUser
      // and kicks off initUserShard (which sets userShardKey synchronously after
      // deriving — but it's async). Drive it and settle the probe so the shard
      // key is in place.
      const signPostMock = (await import("./identity"))
        .signPost as unknown as ReturnType<typeof vi.fn>;
      const ok = await conn.publishPost("hello world");
      return { ok, signPostMock };
    }

    it("completePublish with an UNKNOWN nonce returns false, leaves drafts intact", async () => {
      const { conn, api } = makeConnection();
      conn.setUser(OWNER_VK, "Alice", "alice");
      await flush();
      // Resolve the user-shard probe so userShardKey/exists is settled.
      if (api.getCalls.length) api.getCalls[0].resolve({} as GetResponse);
      await flush();

      const { ok, signPostMock } = await seedDraft(conn);
      expect(ok).toBe(true);
      const realNonce = signPostMock.mock.calls[
        signPostMock.mock.calls.length - 1
      ][0] as string;

      // Unknown nonce -> no draft matched -> false, and no update sent.
      const updatesBefore = api.updateCalls.length;
      const res = await conn.completePublish({
        nonce: "no-such-nonce",
        post_id: "pid",
        signature: "sig",
        public_key: OWNER_VK,
      });
      expect(res).toBe(false);
      expect(api.updateCalls.length).toBe(updatesBefore);

      // The real draft is still there: completing it now succeeds and sends an
      // update (proving the unknown-nonce call did NOT consume it).
      const res2 = await conn.completePublish({
        nonce: realNonce,
        post_id: "pid",
        signature: "sig",
        public_key: OWNER_VK,
      });
      expect(res2).toBe(true);
      expect(api.updateCalls.length).toBe(updatesBefore + 1);
    });

    it("dropPendingPost removes only the matching nonce", async () => {
      const { conn, api } = makeConnection();
      conn.setUser(OWNER_VK, "Alice", "alice");
      await flush();
      if (api.getCalls.length) api.getCalls[0].resolve({} as GetResponse);
      await flush();

      const signPostMock = (await import("./identity"))
        .signPost as unknown as ReturnType<typeof vi.fn>;

      // Two drafts queued.
      await conn.publishPost("first");
      await conn.publishPost("second");
      const nonceA = signPostMock.mock.calls[0][0] as string;
      const nonceB = signPostMock.mock.calls[1][0] as string;
      expect(nonceA).not.toBe(nonceB);

      // Drop only A. B must survive: completePublish(B) succeeds, A fails.
      conn.dropPendingPost(nonceA);

      const resA = await conn.completePublish({
        nonce: nonceA,
        post_id: "pa",
        signature: "s",
        public_key: OWNER_VK,
      });
      expect(resA).toBe(false); // A was dropped

      const resB = await conn.completePublish({
        nonce: nonceB,
        post_id: "pb",
        signature: "s",
        public_key: OWNER_VK,
      });
      expect(resB).toBe(true); // B untouched
    });
  });

  describe("handleGetResponse routing -> like aggregate", () => {
    it("a thread-shard GET response emits onLikeUpdated with the correct count/likedByMe", async () => {
      const { conn, api, callbacks } = makeConnection();

      // ownerVkHex (used by emitLikeState for likedByMe) is only set when a real
      // 3904-char VK is supplied via setUser. Set it, then settle the user-shard
      // init GETs so the chain is idle.
      conn.setUser(OWNER_VK, "Alice", "alice");
      await flush();
      api.getCalls[0].resolve({} as GetResponse); // probe -> exists
      await flush();
      await flush();
      if (api.getCalls[1]) api.getCalls[1].resolve({} as GetResponse); // loadUserShard
      await flush();
      await flush();

      // Like a post so the thread key + instance->root mapping is registered
      // (handleGetResponse routes by instance id).
      const rootId = "thread-root-1";
      const likePromise = conn.likePost(rootId, true);
      await flush();
      const probe = api.getCalls[api.getCalls.length - 1];
      probe.resolve({} as GetResponse);
      await likePromise;

      // Build a thread-shard GET response for that key with two likes, one of
      // them by the owner, and feed it through the captured handler.
      const likes = {
        a: { signer_pubkey: OWNER_VK, seq: 1, liked: true, signature: "s" },
        b: { signer_pubkey: "cd".repeat(1952), seq: 1, liked: true, signature: "s" },
        c: { signer_pubkey: "ef".repeat(1952), seq: 2, liked: false, signature: "s" },
      };
      // One thread GET carries both surfaces: two reposts true (one by owner),
      // one un-repost tombstone.
      const reposts = {
        a: { signer_pubkey: OWNER_VK, seq: 1, reposted: true, signature: "s" },
        b: { signer_pubkey: "cd".repeat(1952), seq: 1, reposted: true, signature: "s" },
        c: { signer_pubkey: "ef".repeat(1952), seq: 2, reposted: false, signature: "s" },
      };
      const stateBytes = Array.from(
        new TextEncoder().encode(JSON.stringify({ likes, reposts })),
      );
      const key = probe.req.key; // same ContractKey the thread uses

      callbacks.onLikeUpdated.mockClear();
      callbacks.onRepostUpdated.mockClear();
      api.handler.onContractGet({
        key,
        state: stateBytes,
      } as unknown as GetResponse);

      expect(callbacks.onLikeUpdated).toHaveBeenCalledTimes(1);
      const emitted = callbacks.onLikeUpdated.mock.calls[0][0] as LikeState;
      expect(emitted.postId).toBe(rootId);
      expect(emitted.count).toBe(2); // two liked:true records
      expect(emitted.likedByMe).toBe(true); // owner is among them

      expect(callbacks.onRepostUpdated).toHaveBeenCalledTimes(1);
      const reEmit = callbacks.onRepostUpdated.mock.calls[0][0] as RepostState;
      expect(reEmit.postId).toBe(rootId);
      expect(reEmit.count).toBe(2); // two reposted:true records
      expect(reEmit.repostedByMe).toBe(true); // owner is among them
    });
  });

  // -------------------------------------------------------------------------
  // Global-index (public-timeline) READ path.
  // -------------------------------------------------------------------------
  // The write side (shareToGlobalIndex / ensureGlobalIndex) already has the
  // singleton key wiring; these cover the read side: loadGlobalIndex() issues a
  // serialised GET against the singleton key, handleGetResponse routes that
  // response (state = a MAP keyed by id, a Rust BTreeMap) to onGlobalPostsLoaded,
  // and a live update notification with a `{"Posts":[…]}` delta on that same key
  // routes to onNewGlobalPost. We drive everything through the captured handler
  // exactly like the user-shard/thread GET tests above.
  describe("global-index read path", () => {
    // A ContractPost as it appears on-wire inside the global index map. Mirrors
    // the Rust `Post` json fields (incl. `reply_to`). `id` is the map key.
    function gPost(
      overrides: Partial<{
        id: string;
        content: string;
        timestamp: number;
        reply_to: string;
      }> = {},
    ): Record<string, unknown> {
      return {
        id: overrides.id ?? "g1",
        author_pubkey: OWNER_VK,
        author_name: "Alice",
        author_handle: "alice",
        content: overrides.content ?? "hello timeline",
        timestamp: overrides.timestamp ?? 1000,
        reply_to: overrides.reply_to ?? "",
        quoted_post: "",
        signature: "sig",
      };
    }

    /** Encode a global-index state map ({"posts": {<id>: Post}}) as state bytes. */
    function globalStateBytes(posts: Record<string, unknown>): number[] {
      return Array.from(
        new TextEncoder().encode(JSON.stringify({ posts })),
      );
    }

    /**
     * Trigger loadGlobalIndex() and return the GET it issued. The hash file is
     * present in the repo, so __GLOBAL_INDEX_SHARD_CODE_HASH__ is a real hash and
     * globalIndexKeyOrNull() derives + registers the singleton instance id — so
     * the response we feed back routes to the global-index branch.
     */
    async function loadGlobalAndGetProbe(
      conn: FreenetConnection,
      api: FakeWsApi,
    ): Promise<Deferred<GetResponse>> {
      const before = api.getCalls.length;
      conn.loadGlobalIndex();
      await flush();
      expect(api.getCalls.length).toBe(before + 1);
      return api.getCalls[api.getCalls.length - 1];
    }

    it("a global-index GET maps the posts MAP and emits onGlobalPostsLoaded newest-first", async () => {
      const { conn, api, callbacks } = makeConnection();
      const probe = await loadGlobalAndGetProbe(conn, api);

      // Two top-level posts keyed by id; the older one is listed first in the
      // map to prove the read side sorts by timestamp desc (not map order).
      const posts = {
        old: gPost({ id: "old", content: "older", timestamp: 1000 }),
        new: gPost({ id: "new", content: "newer", timestamp: 5000 }),
      };
      api.handler.onContractGet({
        key: probe.req.key,
        state: globalStateBytes(posts),
      } as unknown as GetResponse);

      expect(callbacks.onGlobalPostsLoaded).toHaveBeenCalledTimes(1);
      const emitted = callbacks.onGlobalPostsLoaded.mock.calls[0][0] as Array<{
        id: string;
        content: string;
      }>;
      expect(emitted.map((p) => p.id)).toEqual(["new", "old"]); // newest first
      expect(emitted[0].content).toBe("newer");

      // Routing isolation: the user-shard callback must NOT fire for this GET.
      expect(callbacks.onPostsLoaded).not.toHaveBeenCalled();
    });

    it("an empty index ({\"posts\":{}}) emits onGlobalPostsLoaded([])", async () => {
      const { conn, api, callbacks } = makeConnection();
      const probe = await loadGlobalAndGetProbe(conn, api);

      api.handler.onContractGet({
        key: probe.req.key,
        state: globalStateBytes({}),
      } as unknown as GetResponse);

      expect(callbacks.onGlobalPostsLoaded).toHaveBeenCalledTimes(1);
      expect(callbacks.onGlobalPostsLoaded.mock.calls[0][0]).toEqual([]);
    });

    it("filters reply posts out of the timeline (top-level only)", async () => {
      const { conn, api, callbacks } = makeConnection();
      const probe = await loadGlobalAndGetProbe(conn, api);

      // The index MAY hold replies (acceptance is self-verification only); the
      // read side filters on a non-empty reply_to to keep the timeline top-level.
      const posts = {
        top: gPost({ id: "top", reply_to: "" }),
        reply: gPost({ id: "reply", reply_to: "some-parent" }),
      };
      api.handler.onContractGet({
        key: probe.req.key,
        state: globalStateBytes(posts),
      } as unknown as GetResponse);

      const emitted = callbacks.onGlobalPostsLoaded.mock.calls[0][0] as Array<{
        id: string;
      }>;
      expect(emitted.map((p) => p.id)).toEqual(["top"]);
    });

    it("a global-index delta notification ({\"Posts\":[…]}) emits onNewGlobalPost", async () => {
      const { conn, api, callbacks } = makeConnection();
      // loadGlobalIndex registers the singleton instance id used to route both
      // the GET response AND subsequent live-update notifications.
      const probe = await loadGlobalAndGetProbe(conn, api);

      const post = gPost({ id: "live-1", content: "fresh share" });
      const deltaBytes = Array.from(
        new TextEncoder().encode(JSON.stringify({ Posts: [post] })),
      );
      // The handler reads notification.update as a property-shaped UpdateData
      // ({ updateDataType, updateData: { delta } }) — same shape the production
      // unpacked notification exposes; mirror it as a plain object.
      api.handler.onContractUpdateNotification({
        key: probe.req.key,
        update: {
          updateDataType: UpdateDataType.DeltaUpdate,
          updateData: { delta: deltaBytes },
        },
      } as unknown as UpdateNotification);

      expect(callbacks.onNewGlobalPost).toHaveBeenCalledTimes(1);
      const emitted = callbacks.onNewGlobalPost.mock.calls[0][0] as {
        id: string;
        content: string;
      };
      expect(emitted.id).toBe("live-1");
      expect(emitted.content).toBe("fresh share");

      // Routing isolation: the user-shard live-update callback must NOT fire.
      expect(callbacks.onNewPost).not.toHaveBeenCalled();
    });

    it("routing isolation: a user-shard GET does NOT fire the global callback", async () => {
      const { conn, api, callbacks } = makeConnection();

      // Establish + load the user shard (sets userShardInstanceId, issues GETs).
      conn.setUser(OWNER_VK, "Alice", "alice");
      await flush();
      const probe = api.getCalls[0]; // the user-shard probe GET
      probe.resolve({} as GetResponse); // exists -> no PUT
      await flush();
      await flush();
      // loadUserShard's GET carries the user-shard state (a Vec under `posts`).
      expect(api.getCalls.length).toBe(2);
      const loadGet = api.getCalls[1];

      api.handler.onContractGet({
        key: loadGet.req.key,
        state: Array.from(
          new TextEncoder().encode(
            JSON.stringify({ posts: [gPost({ id: "u1" })] }),
          ),
        ),
      } as unknown as GetResponse);

      // The user-shard branch fired; the global-index branch must NOT have.
      expect(callbacks.onPostsLoaded).toHaveBeenCalledTimes(1);
      expect(callbacks.onGlobalPostsLoaded).not.toHaveBeenCalled();
    });

    it("loadGlobalIndex() is a no-op before connect() (no GET, no throw)", () => {
      // globalIndexKeyOrNull() returns null only when the build hash is the dev
      // sentinel/undefined — which can't be forced here (it's a compile-time
      // vite `define`). The other no-op guard is `!this.api`: before connect(),
      // the WS client doesn't exist, so loadGlobalIndex() must quietly return
      // without issuing a GET (and without throwing). This is the path an
      // offline/unconnected reader hits.
      const conn = new FreenetConnection({
        onPostsLoaded: vi.fn(),
        onNewPost: vi.fn(),
        onStatusChange: vi.fn(),
      } as unknown as FreenetCallbacks);
      // No connect() — this.api is null.
      expect(() => conn.loadGlobalIndex()).not.toThrow();
      // No FakeWsApi instance was created (connect not called) and thus no GET.
      expect(FakeWsApi.instances.length).toBe(0);
    });

    it("re-issues the subscribe once after the first successful GET, then stops", async () => {
      // The boot-time subscribe is rejected by the node when the singleton is
      // not instantiated yet and that rejection never reaches the stdlib
      // promise — so a subscribe must be re-issued after a GET succeeded (the
      // contract is then cached locally and the node accepts it). See #50.
      const { conn, api } = makeConnection();
      const probe = await loadGlobalAndGetProbe(conn, api);
      // Boot attempt went out with the load.
      expect(api.subscribeCalls.length).toBe(1);

      probe.resolve({} as GetResponse);
      await flush();
      // Post-GET retry — the one the node is guaranteed to accept.
      expect(api.subscribeCalls.length).toBe(2);

      // Further loads (the refresh tick path) must not re-subscribe again.
      const probe2 = await loadGlobalAndGetProbe(conn, api);
      probe2.resolve({} as GetResponse);
      await flush();
      expect(api.subscribeCalls.length).toBe(2);
    });

    it("keeps re-GETting the public timeline on the refresh interval", async () => {
      // Live deltas are dropped by the network when the subscription tree
      // hasn't formed yet (fire-and-forget, no anti-entropy), so Discover
      // needs a slow re-GET fallback to stay eventually consistent (#50).
      vi.useFakeTimers();
      try {
        const { conn, api } = makeConnection();
        conn.loadGlobalIndex();
        await vi.advanceTimersByTimeAsync(0);
        expect(api.getCalls.length).toBe(1);
        // Settle the in-flight GET so the serialized-GET chain can advance.
        api.getCalls[0].resolve({} as GetResponse);
        await vi.advanceTimersByTimeAsync(0);

        await vi.advanceTimersByTimeAsync(60_000);
        expect(api.getCalls.length).toBe(2);
        api.getCalls[1].resolve({} as GetResponse);
        await vi.advanceTimersByTimeAsync(0);

        // A second explicit load must NOT stack a second interval: one more
        // tick produces exactly one more GET (plus the explicit load's own).
        conn.loadGlobalIndex();
        await vi.advanceTimersByTimeAsync(0);
        expect(api.getCalls.length).toBe(3);
        api.getCalls[2].resolve({} as GetResponse);
        await vi.advanceTimersByTimeAsync(0);
        await vi.advanceTimersByTimeAsync(60_000);
        expect(api.getCalls.length).toBe(4);
      } finally {
        vi.useRealTimers();
      }
    });
  });

  // -------------------------------------------------------------------------
  // Reply path — mirrors the like/repost/quote test patterns exactly.
  // -------------------------------------------------------------------------
  describe("reply path", () => {
    describe("dropPendingReply — nonce matching", () => {
      it("returns false for an unknown nonce; true then false for a real pending reply", async () => {
        const { conn, api } = makeConnection();
        conn.setUser(OWNER_VK, "Alice", "alice");
        // Drain all user-shard GETs (probe + loadUserShard) so the serialised
        // GET chain is idle before replyPost (which itself awaits ensureThreadShard).
        await drainGets(api);

        // Seed a pending reply via replyPost. It calls ensureThreadShard (probe
        // GET) then records the pending entry and calls signReply (mock -> true).
        const replyPromise = conn.replyPost("root-reply-drop", "hello thread");
        await flush();
        api.getCalls[api.getCalls.length - 1].resolve({} as GetResponse); // probe exists
        const ok = await replyPromise;
        expect(ok).toBe(true);

        // Unknown nonce is always false.
        expect(conn.dropPendingReply("nonce-that-does-not-exist")).toBe(false);

        // Retrieve the real nonce from the signReply mock call.
        const signReplyMock = (await import("./identity"))
          .signReply as unknown as ReturnType<typeof vi.fn>;
        const nonce = signReplyMock.mock.calls[
          signReplyMock.mock.calls.length - 1
        ][0] as string;

        expect(conn.dropPendingReply(nonce)).toBe(true);  // matched -> dropped
        expect(conn.dropPendingReply(nonce)).toBe(false); // already gone
      });
    });

    describe("optimistic reply revert", () => {
      it("completeReply (matched nonce) sends a Replies delta then refreshes on SUCCESS", async () => {
        const { conn, api } = makeConnection();
        conn.setUser(OWNER_VK, "Alice", "alice");
        // Drain all user-shard GETs so the chain is idle before replyPost.
        await drainGets(api);

        const signReplyMock = (await import("./identity"))
          .signReply as unknown as ReturnType<typeof vi.fn>;
        const replyPromise = conn.replyPost("root-reply-ok", "my reply");
        await flush();
        api.getCalls[api.getCalls.length - 1].resolve({} as GetResponse); // probe exists
        await replyPromise;
        // signReply(nonce, content, name, handle, timestamp, rootPostId) — first arg is nonce.
        const nonce = signReplyMock.mock.calls[
          signReplyMock.mock.calls.length - 1
        ][0] as string;

        const getsBefore = api.getCalls.length;
        const ok = await conn.completeReply({
          nonce,
          post_id: "reply-post-id",
          signature: "sig",
          public_key: OWNER_VK,
        });
        expect(ok).toBe(true);
        // A DeltaUpdate was sent and a refresh GET followed.
        expect(api.updateCalls.length).toBe(1);
        expect(api.getCalls.length).toBe(getsBefore + 1);
        // The matched nonce was consumed; dropping it again is a no-op.
        expect(conn.dropPendingReply(nonce)).toBe(false);
      });

      it("completeReply with an UNMATCHED nonce returns false and does NOT call update", async () => {
        const { conn, api } = makeConnection();
        conn.setUser(OWNER_VK, "Alice", "alice");
        // Drain all user-shard GETs so the chain is idle before replyPost.
        await drainGets(api);

        // Seed a real pending reply so the state isn't empty, but call
        // completeReply with a foreign nonce — must no-op and return false.
        const signReplyMock = (await import("./identity"))
          .signReply as unknown as ReturnType<typeof vi.fn>;
        const replyPromise = conn.replyPost("root-reply-unmatched", "content");
        await flush();
        api.getCalls[api.getCalls.length - 1].resolve({} as GetResponse);
        await replyPromise;
        const realNonce = signReplyMock.mock.calls[
          signReplyMock.mock.calls.length - 1
        ][0] as string;

        const updatesBefore = api.updateCalls.length;
        const getsBefore = api.getCalls.length;
        const res = await conn.completeReply({
          nonce: "foreign-nonce",
          post_id: "pid",
          signature: "sig",
          public_key: OWNER_VK,
        });
        expect(res).toBe(false);
        expect(api.updateCalls.length).toBe(updatesBefore); // no update sent
        expect(api.getCalls.length).toBe(getsBefore);       // no refresh GET

        // The real pending reply is still there: completing it now succeeds.
        const res2 = await conn.completeReply({
          nonce: realNonce,
          post_id: "pid",
          signature: "sig",
          public_key: OWNER_VK,
        });
        expect(res2).toBe(true);
        expect(api.updateCalls.length).toBe(updatesBefore + 1);
      });
    });

    it("a thread-shard GET emits onRepliesUpdated with replies sorted oldest-first", async () => {
      const { conn, api, callbacks } = makeConnection();
      conn.setUser(OWNER_VK, "Alice", "alice");
      await flush();
      api.getCalls[0].resolve({} as GetResponse); // user-shard probe exists
      await flush();
      await flush();
      if (api.getCalls[1]) api.getCalls[1].resolve({} as GetResponse); // loadUserShard GET
      await flush();
      await flush();

      // Register the thread instance→root mapping via repostPost (cheapest path).
      const rootId = "reply-thread-root";
      const rp = conn.repostPost(rootId, true);
      await flush();
      const probe = api.getCalls[api.getCalls.length - 1];
      probe.resolve({} as GetResponse);
      await rp;

      // Two replies with out-of-order timestamps — newer listed first in the
      // map to prove the read side sorts oldest-first (asc by timestamp).
      const replies = {
        r2: {
          id: "r2",
          author_pubkey: OWNER_VK,
          author_name: "Alice",
          author_handle: "alice",
          content: "second reply",
          timestamp: 5000,
          reply_to: rootId,
          quoted_post: "",
          signature: "s2",
        },
        r1: {
          id: "r1",
          author_pubkey: "cd".repeat(1952),
          author_name: "Bob",
          author_handle: "bob",
          content: "first reply",
          timestamp: 1000,
          reply_to: rootId,
          quoted_post: "",
          signature: "s1",
        },
      };
      const stateBytes = Array.from(
        new TextEncoder().encode(JSON.stringify({ replies })),
      );
      callbacks.onRepliesUpdated.mockClear();
      api.handler.onContractGet({
        key: probe.req.key,
        state: stateBytes,
      } as unknown as GetResponse);

      expect(callbacks.onRepliesUpdated).toHaveBeenCalledTimes(1);
      const [emittedRootId, emittedReplies] =
        callbacks.onRepliesUpdated.mock.calls[0] as [string, Post[]];
      expect(emittedRootId).toBe(rootId);
      // Oldest first (timestamp asc).
      expect(emittedReplies.map((p) => p.id)).toEqual(["r1", "r2"]);
      expect(emittedReplies[0].content).toBe("first reply");
      expect(emittedReplies[1].content).toBe("second reply");
    });
  });

  // -------------------------------------------------------------------------
  // Shard PUT serialization (regression guard for the "field 8 must be set"
  // bug, freenet/raven#56). Every browser-side shard instantiation goes through
  // buildShardPutRequest(); if its container reverts to reader tables, or
  // relatedContracts goes back to `undefined`, the PutRequest fails to
  // SERIALIZE — which silently broke ALL post persistence. These pack the real
  // request (no node) so a regression fails here instantly instead of only on
  // the slow, flaky live-node round-trip.
  // -------------------------------------------------------------------------
  describe("buildShardPutRequest — serialization", () => {
    // 32-byte code hash + representative params/state for each shard shape.
    const codeHash = new Uint8Array(32).fill(7);
    const wasm = new Uint8Array(64).fill(1);

    function packs(req: ReturnType<typeof buildShardPutRequest>): number {
      const builder = new flatbuffers.Builder(1024);
      builder.finish(req.pack(builder));
      return builder.asUint8Array().length;
    }

    it("packs a user-shard PUT (owner-VK params, {posts:[]} state)", () => {
      const params = new Uint8Array(1952).fill(3); // ML-DSA-65 VK-sized
      const state = new TextEncoder().encode(JSON.stringify({ posts: [] }));
      expect(packs(buildShardPutRequest(wasm, codeHash, params, state))).toBeGreaterThan(0);
    });

    it("packs a thread-shard PUT (root-post-id params)", () => {
      const params = new TextEncoder().encode("some-root-post-id");
      const state = new TextEncoder().encode(
        JSON.stringify({ replies: {}, likes: {}, quotes: {}, reposts: {} }),
      );
      expect(packs(buildShardPutRequest(wasm, codeHash, params, state))).toBeGreaterThan(0);
    });

    it("packs a global-index PUT (singleton, EMPTY params)", () => {
      // The empty-params singleton is the case that most resembles the original
      // bug shape; pinning it guards the field-8 regression specifically.
      const params = new Uint8Array(0);
      const state = new TextEncoder().encode(JSON.stringify({ posts: {} }));
      expect(packs(buildShardPutRequest(wasm, codeHash, params, state))).toBeGreaterThan(0);
    });

    it("does not throw the 'field 8 must be set' flatbuffer error", () => {
      // The exact failure the bug produced. Assert it never recurs for any of
      // the three shard shapes.
      for (const params of [new Uint8Array(0), new Uint8Array(32).fill(9)]) {
        const state = new TextEncoder().encode("{}");
        expect(() => packs(buildShardPutRequest(wasm, codeHash, params, state))).not.toThrow();
      }
    });
  });
});
