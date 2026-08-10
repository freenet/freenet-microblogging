/**
 * stores/freenet.ts — the single home for the FreenetConnection instance and
 * all the application state index.ts used to hold imperatively.
 *
 * Plain `writable`/`derived` from `svelte/store` (NOT runes) so this
 * non-component module stays framework-light and can be imported anywhere.
 * Runes ($state/$derived) are reserved for `.svelte` files.
 *
 * The callback bodies below are ported VERBATIM from index.ts (lines 218-538).
 * The single most important porting rule: index.ts mutated Post objects in place
 * and then re-rendered; Svelte store subscriptions only re-run on a NEW array
 * reference, so every in-place reconcile MUST return a fresh array (`[...cur]`)
 * from `.update()`.
 */

import { writable } from "svelte/store";
import {
  FreenetConnection,
  type ConnectionStatus,
  type LikeState,
  type RepostState,
  type QuoteState,
} from "../freenet-api";
import { Post } from "../types";
import {
  getIdentity,
  createIdentity,
  applyDelegateIdentity,
  connectDelegate,
  requestIdentityFromDelegate,
  onIdentityExported,
  Identity,
} from "../identity";
import { parseDelegateResponse } from "../delegate-api";
import { DelegateResponse } from "@freenetorg/freenet-stdlib";

// ---------------------------------------------------------------------------
// Exported reactive stores
// ---------------------------------------------------------------------------

/** User-shard feed (was index.ts `localPosts`). */
export const posts = writable<Post[]>([]);
/** Public-timeline buffer (was index.ts `globalPosts`). */
export const globalPosts = writable<Post[]>([]);
/** Last onStatusChange value (was the imperative status flow). */
export const status = writable<ConnectionStatus>("connecting");
/**
 * Mirrors identity.ts getIdentity(); written after createIdentity /
 * applyDelegateIdentity so components re-render reactively instead of calling
 * getIdentity() at build time.
 */
export const identity = writable<Identity | null>(null);
/** Gates onboarding/splash vs the app shell (was the `appRendered` latch). */
export const appRendered = writable<boolean>(false);
/**
 * Set true by every index.ts showOnboarding() call site (delegate timeout, no
 * delegate, error/disconnected status, "no identity" delegate error).
 * App.svelte renders OnboardingOverlay + LandingFeed when
 * `$showOnboarding && !$appRendered`.
 */
export const showOnboarding = writable<boolean>(false);
/**
 * Set by the onIdentityExported listener; KeyExportModal shows when non-null,
 * clears to null on close. Replaces the imperative showKeyExportModal() call.
 */
export const keyExportSecret = writable<string | null>(null);
/**
 * Authoritative replies for each thread, keyed by root post id. Written by
 * the onRepliesUpdated callback whenever a thread shard is read. Thread.svelte
 * derives its reply list from this store (not from the feed posts list).
 */
export const threadReplies = writable<Map<string, Post[]>>(new Map());

/**
 * Hex VKs the signed-in owner follows, from their own user shard. Replaced (not
 * merged) on every emit: an unfollow is a tombstone in the contract, so merging
 * would never drop anyone from the UI.
 */
export const follows = writable<Set<string>>(new Set());

/** Aggregated Following feed: posts from every followed user's shard. */
export const followingPosts = writable<Post[]>([]);

// ---------------------------------------------------------------------------
// Module-private latches / dedup sets (plain `let`/`const`, NOT stores) —
// these mirror index.ts exactly.
// ---------------------------------------------------------------------------
const knownPostIds = new Set<string>();
const globalPostIds = new Set<string>();
let globalIndexStarted = false;
let delegateTimeoutId: ReturnType<typeof setTimeout> | null = null;

// Mirror of index.ts `appRendered`. The store above drives Svelte rendering,
// but the callback bodies guard on a plain boolean (cannot synchronously read a
// store value inside the callback otherwise). Kept in lockstep with the store.
let appRenderedFlag = false;
appRendered.subscribe((v) => {
  appRenderedFlag = v;
});

// ---------------------------------------------------------------------------
// refreshFeed: index.ts re-rendered from the authoritative localPosts. In
// Svelte this is "force the posts subscriptions to re-run from current state"
// — return a fresh array reference. (Used by the optimistic-toggle reverts.)
// ---------------------------------------------------------------------------
function refreshFeed(): void {
  posts.update((c) => [...c]);
}

// ---------------------------------------------------------------------------
// Onboarding "show" — every index.ts showOnboarding() call site becomes this.
// Guarded by appRendered exactly like index.ts.
// ---------------------------------------------------------------------------
function triggerOnboarding(): void {
  if (appRenderedFlag) return;
  showOnboarding.set(true);
}

// ---------------------------------------------------------------------------
// renderApp side effects (was index.ts renderApp lines 129-192, minus the DOM
// teardown which App.svelte now does reactively when appRendered flips).
// ---------------------------------------------------------------------------
function renderApp(id: Identity): void {
  if (appRenderedFlag) return;
  appRenderedFlag = true;
  if (delegateTimeoutId) {
    clearTimeout(delegateTimeoutId);
    delegateTimeoutId = null;
  }
  appRendered.set(true);
  showOnboarding.set(false);

  connection.setUser(id.publicKey, id.displayName, id.handle);

  // Load posts now that app is rendered.
  connection.loadState();
  // Any already-buffered public-timeline posts flow to Discover automatically
  // via the globalPosts store; nothing imperative to forward here.
}

// ---------------------------------------------------------------------------
// Connection singleton — owns the WebSocket + contract hub. Offline mode skips
// connect() (see start() below) but still constructs the instance so the action
// wrappers exist.
// ---------------------------------------------------------------------------
export const connection = new FreenetConnection({
  onPostsLoaded: (loaded: Post[]) => {
    console.log(`[freenet] Loaded ${loaded.length} posts from network`);
    knownPostIds.clear();
    for (const post of loaded) knownPostIds.add(post.id);
    posts.set(loaded);
  },
  onNewPost: (post: Post) => {
    if (knownPostIds.has(post.id)) return;
    knownPostIds.add(post.id);
    posts.update((cur) => [post, ...cur]);
  },
  onGlobalPostsLoaded: (loaded: Post[]) => {
    console.log(`[freenet] Loaded ${loaded.length} public-timeline posts`);
    // MERGE, do not replace. The global index is multi-writer, and the
    // subscribe fires right after the GET is queued — so a live delta
    // (onNewGlobalPost) can land BEFORE this snapshot arrives. Keep any
    // buffered post whose id is not in the snapshot, union, re-sort
    // newest-first, and rebuild the dedup set from the union. This is the
    // load-bearing PR#52 invariant — copied verbatim, do not simplify.
    globalPosts.update((cur) => {
      const snapshotIds = new Set(loaded.map((p) => p.id));
      const survivors = cur.filter((p) => !snapshotIds.has(p.id));
      const merged = [...loaded, ...survivors].sort(
        (a, b) => b.timestamp.getTime() - a.timestamp.getTime(),
      );
      globalPostIds.clear();
      for (const p of merged) globalPostIds.add(p.id);
      return merged;
    });
  },
  onNewGlobalPost: (post: Post) => {
    if (globalPostIds.has(post.id)) return;
    globalPostIds.add(post.id);
    // Insert then re-sort newest-first: the global index is multi-writer and
    // deltas can arrive out of timestamp order.
    globalPosts.update((cur) =>
      [post, ...cur].sort(
        (a, b) => b.timestamp.getTime() - a.timestamp.getTime(),
      ),
    );
  },
  onStatusChange: (s: ConnectionStatus) => {
    console.log(`[freenet] Status: ${s}`);
    status.set(s);

    if (s === "connected") {
      // Start the public-timeline read path independent of identity. Guarded to
      // once per page so a reconnect does not re-subscribe to the singleton key.
      if (!globalIndexStarted) {
        globalIndexStarted = true;
        connection.loadGlobalIndex();
      }
      wireDelegateAndRequestIdentity();
    }

    if (s === "disconnected" || s === "error") {
      // No Freenet node — show onboarding with in-memory identity.
      if (!appRenderedFlag) {
        triggerOnboarding();
      }
    }
  },
  onLikeUpdated: (like: LikeState) => {
    // Authoritative like aggregate from the post's thread shard — reconcile the
    // optimistic UI with real state. Mutate in place then return a NEW array
    // reference so the store subscriptions re-run.
    posts.update((cur) => {
      const post = cur.find((p) => p.id === like.postId);
      if (post) {
        post.likes = like.count;
        post.liked = like.likedByMe;
      }
      return [...cur];
    });
  },
  onRepostUpdated: (repost: RepostState) => {
    posts.update((cur) => {
      const post = cur.find((p) => p.id === repost.postId);
      if (post) {
        post.reposts = repost.count;
        post.reposted = repost.repostedByMe;
      }
      return [...cur];
    });
  },
  onQuoteUpdated: (quote: QuoteState) => {
    posts.update((cur) => {
      const post = cur.find((p) => p.id === quote.postId);
      if (post) {
        post.quotes = quote.count;
      }
      return [...cur];
    });
  },
  onRepliesUpdated: (rootPostId: string, replies: Post[]) => {
    threadReplies.update((cur) => {
      const next = new Map(cur);
      next.set(rootPostId, replies);
      return next;
    });
    // Reply count comes from the authoritative thread-shard reply list —
    // same cadence as like/quote aggregates: only refreshes when that post's
    // thread shard is read.
    posts.update((cur) => {
      const post = cur.find((p) => p.id === rootPostId);
      if (post) {
        post.replies = replies.length;
      }
      return [...cur];
    });
  },
  onFollowsUpdated: ({ following }: { following: Set<string> }) => {
    follows.set(following);
  },
  onFollowingPostsLoaded: (list: Post[]) => {
    followingPosts.set(list);
  },
  onDelegateResponse: (response: DelegateResponse) => {
    const payloads = parseDelegateResponse(response);
    for (const payload of payloads) {
      console.log("[delegate] Response:", payload);

      if (applyDelegateIdentity(payload)) {
        const id = getIdentity()!;
        identity.set(id);
        connection.setUser(id.publicKey, id.displayName, id.handle);

        if (!appRenderedFlag) {
          renderApp(id);
        }
        return;
      }

      // A signed post (or reply) came back from the delegate. Route by the
      // delegate-tagged response type: SignedReply → completeReply only;
      // Signed → completePublish only. No fallback probing needed.
      const signed = payload as {
        type?: string;
        nonce?: string;
        post_id?: string;
        signature?: string;
        public_key?: string;
      };
      if (
        (signed.type === "Signed" || signed.type === "SignedReply") &&
        signed.nonce &&
        signed.post_id &&
        signed.signature &&
        signed.public_key
      ) {
        if (signed.type === "SignedReply") {
          connection
            .completeReply({
              nonce: signed.nonce,
              post_id: signed.post_id,
              signature: signed.signature,
              public_key: signed.public_key,
            })
            .catch((e) => console.error("[delegate] completeReply failed:", e));
        } else {
          connection
            .completePublish({
              nonce: signed.nonce,
              post_id: signed.post_id,
              signature: signed.signature,
              public_key: signed.public_key,
            })
            .catch((e) => console.error("[delegate] completePublish failed:", e));
        }
        return;
      }

      // A signed like came back — fold it into the post's thread shard.
      const signedLike = payload as {
        type?: string;
        nonce?: string;
        root_post_id?: string;
        signer_pubkey?: string;
        seq?: number;
        liked?: boolean;
        signature?: string;
      };
      if (
        signedLike.type === "SignedLike" &&
        signedLike.nonce &&
        signedLike.root_post_id &&
        signedLike.signer_pubkey &&
        typeof signedLike.seq === "number" &&
        typeof signedLike.liked === "boolean" &&
        signedLike.signature
      ) {
        connection
          .completeLike({
            nonce: signedLike.nonce,
            root_post_id: signedLike.root_post_id,
            signer_pubkey: signedLike.signer_pubkey,
            seq: signedLike.seq,
            liked: signedLike.liked,
            signature: signedLike.signature,
          })
          .then((ok) => {
            // On a hard false, revert the optimistic toggle from the
            // authoritative state directly so the like never sticks.
            if (!ok) refreshFeed();
          })
          .catch((e) => console.error("[delegate] completeLike failed:", e));
        return;
      }

      // A signed repost came back — fold it into the post's thread shard.
      const signedRepost = payload as {
        type?: string;
        nonce?: string;
        root_post_id?: string;
        signer_pubkey?: string;
        seq?: number;
        reposted?: boolean;
        signature?: string;
      };
      if (
        signedRepost.type === "SignedRepost" &&
        signedRepost.nonce &&
        signedRepost.root_post_id &&
        signedRepost.signer_pubkey &&
        typeof signedRepost.seq === "number" &&
        typeof signedRepost.reposted === "boolean" &&
        signedRepost.signature
      ) {
        connection
          .completeRepost({
            nonce: signedRepost.nonce,
            root_post_id: signedRepost.root_post_id,
            signer_pubkey: signedRepost.signer_pubkey,
            seq: signedRepost.seq,
            reposted: signedRepost.reposted,
            signature: signedRepost.signature,
          })
          .then((ok) => {
            if (!ok) refreshFeed();
          })
          .catch((e) => console.error("[delegate] completeRepost failed:", e));
        return;
      }

      // A signed quote ref came back — fold it into the quoted post's thread shard.
      const signedQuote = payload as {
        type?: string;
        nonce?: string;
        root_post_id?: string;
        signer_pubkey?: string;
        quote_post_id?: string;
        signature?: string;
      };
      if (
        signedQuote.type === "SignedQuoteRef" &&
        signedQuote.nonce &&
        signedQuote.root_post_id &&
        signedQuote.signer_pubkey &&
        signedQuote.quote_post_id &&
        signedQuote.signature
      ) {
        connection
          .completeQuoteRef({
            nonce: signedQuote.nonce,
            root_post_id: signedQuote.root_post_id,
            signer_pubkey: signedQuote.signer_pubkey,
            quote_post_id: signedQuote.quote_post_id,
            signature: signedQuote.signature,
          })
          .catch((e) => console.error("[delegate] completeQuoteRef failed:", e));
        return;
      }

      // A signed profile/follow op: fold it into the owner's user shard. The
      // payload rides back hex-encoded and is relayed verbatim — see
      // completeShardOp for why it is never re-encoded here.
      const signedOp = payload as {
        type?: string;
        nonce?: string;
        op_type?: string;
        payload?: string;
        seq?: number;
        signer_pubkey?: string;
        signature?: string;
      };
      if (
        signedOp.type === "SignedShardOp" &&
        signedOp.nonce &&
        signedOp.op_type &&
        typeof signedOp.payload === "string" &&
        typeof signedOp.seq === "number" &&
        signedOp.signer_pubkey &&
        signedOp.signature
      ) {
        connection
          .completeShardOp({
            nonce: signedOp.nonce,
            op_type: signedOp.op_type,
            payload: signedOp.payload,
            seq: signedOp.seq,
            signer_pubkey: signedOp.signer_pubkey,
            signature: signedOp.signature,
          })
          .catch((e) => console.error("[delegate] completeShardOp failed:", e));
        return;
      }

      // Check for an error from the delegate.
      const p = payload as { type?: string; message?: string; nonce?: string };
      if (p.type === "Error") {
        // If the error carries a nonce it came from a failed SignPost,
        // SignLike, or SignRepost — drop exactly that stranded pending action.
        if (p.nonce) {
          connection.dropPendingPost(p.nonce);
          if (connection.dropPendingLike(p.nonce)) refreshFeed();
          if (connection.dropPendingRepost(p.nonce)) refreshFeed();
          connection.dropPendingQuoteRef(p.nonce);
          connection.dropPendingReply(p.nonce);
          connection.dropPendingShardOp(p.nonce);
        }
        if (p.message?.includes("no identity")) {
          console.log("[identity] No identity in delegate — show onboarding");
          if (!appRenderedFlag) {
            triggerOnboarding();
          }
        } else {
          console.warn("[delegate] Error:", p.message);
        }
        return;
      }
    }
  },
});

// ---------------------------------------------------------------------------
// Delegate wiring (was index.ts lines 499-538, ported verbatim). The
// imperative showOnboarding() call sites become triggerOnboarding().
// ---------------------------------------------------------------------------
export async function wireDelegateAndRequestIdentity(): Promise<void> {
  const api = connection.wsApi;
  if (!api || !__DELEGATE_KEY__) {
    // No delegate configured — fallback to onboarding.
    if (!appRenderedFlag) triggerOnboarding();
    return;
  }

  try {
    // Use pre-decoded bytes injected at build time (avoids base58 decode in sandbox).
    const keyBytes = __DELEGATE_KEY_BYTES__;
    const codeHashBytes = __DELEGATE_CODE_HASH_BYTES__;
    if (!keyBytes || keyBytes.length !== 32) {
      console.warn("[identity] Invalid delegate key bytes, length:", keyBytes?.length);
      if (!appRenderedFlag) triggerOnboarding();
      return;
    }
    if (!codeHashBytes || codeHashBytes.length !== 32) {
      console.warn("[identity] Invalid delegate code_hash bytes, length:", codeHashBytes?.length);
      if (!appRenderedFlag) triggerOnboarding();
      return;
    }

    connectDelegate(api, keyBytes, codeHashBytes);
    console.log(`[identity] Delegate wired (key: ${keyBytes.length}b, code_hash: ${codeHashBytes.length}b)`);

    requestIdentityFromDelegate();

    delegateTimeoutId = setTimeout(() => {
      if (!appRenderedFlag) {
        console.log("[identity] Delegate timeout — showing onboarding");
        triggerOnboarding();
      }
      delegateTimeoutId = null;
    }, 5000);
  } catch (e) {
    console.warn("[identity] Failed to wire delegate:", e);
    if (!appRenderedFlag) triggerOnboarding();
  }
}

// ---------------------------------------------------------------------------
// Action wrappers — the callback closures from index.ts renderApp (lines
// 144-183), moved here so components dispatch to the store.
// ---------------------------------------------------------------------------
export function publish(content: string, shareToGlobal: boolean): void {
  connection.publishPost(content, shareToGlobal).then((ok) => {
    if (ok) {
      console.log("[freenet] Post published");
      setTimeout(() => connection.loadState(), 300);
    }
  });
}

export function like(postId: string, liked: boolean): void {
  connection.likePost(postId, liked).then((ok) => {
    if (!ok) {
      console.warn("[freenet] Like not sent (no delegate / thread shard)");
      // Revert the optimistic toggle from the authoritative state.
      refreshFeed();
    }
  });
}

export function repost(postId: string, reposted: boolean): void {
  connection.repostPost(postId, reposted).then((ok) => {
    if (!ok) {
      console.warn("[freenet] Repost not sent (no delegate / thread shard)");
      refreshFeed();
    }
  });
}

export function quote(postId: string, content: string): void {
  connection.quotePost(postId, content).then((ok) => {
    if (!ok) {
      console.warn("[freenet] Quote not sent (no delegate / shard)");
    } else {
      // The quote post lands on the owner's user shard; refresh so it shows up.
      setTimeout(() => connection.loadState(), 300);
    }
  });
}

export function reply(rootPostId: string, content: string): void {
  connection.replyPost(rootPostId, content).then((ok) => {
    if (!ok) {
      console.warn("[freenet] Reply not sent (no delegate / shard)");
    }
    // On success the reply surfaces via completeReply → thread-shard refresh →
    // onRepliesUpdated (the threadReplies store), not via a user-shard reload —
    // the reply lives in the thread shard, so loadState() would be a no-op here.
  });
}

/**
 * Trigger a thread-shard load for the given root post so the reply list is
 * populated even on a fresh page load (before any engagement action). Mirrors
 * the like/repost pattern: fire-and-forget, errors are logged in the connection.
 */
/**
 * Follow or unfollow a user by their hex ML-DSA-65 verifying key. The write
 * lands on the CALLER'S own shard (the follow set is owner state), so there is
 * no foreign shard to instantiate. The authoritative set comes back via
 * onFollowsUpdated once the op merges — no optimistic toggle here, because a
 * rejected op is silent and the UI would otherwise show a follow that never was.
 */
export function follow(targetVkHex: string, following: boolean): void {
  connection
    .followUser(targetVkHex, following)
    .catch((e) => console.error("[follows] follow failed:", e));
}

/** Update the owner's profile register (display name / handle / bio / avatar). */
export function saveProfile(
  displayName: string,
  handle: string,
  bio = "",
  avatar = "",
): void {
  connection
    .updateProfile(displayName, handle, bio, avatar)
    .catch((e) => console.error("[profile] update failed:", e));
}

export function loadThreadReplies(rootPostId: string): void {
  connection.loadThreadReplies(rootPostId);
}

// ---------------------------------------------------------------------------
// completeOnboarding — was index.ts showOnboarding's onComplete (lines 558-561).
// Creates the identity, mirrors it into the store, and renders the app.
// ---------------------------------------------------------------------------
export function completeOnboarding(displayName: string, secretKey?: string): void {
  const id = createIdentity(displayName, secretKey);
  identity.set(id);
  renderApp(id);
}

// ---------------------------------------------------------------------------
// Key-export listener (was index.ts line 39).
// ---------------------------------------------------------------------------
onIdentityExported((secret) => keyExportSecret.set(secret));

// ---------------------------------------------------------------------------
// Boot — offline-mode aware (was index.ts lines 568-585). main.ts calls
// start() after applying theme + design tokens + document.title.
// ---------------------------------------------------------------------------
export function start(): void {
  if (__OFFLINE_MODE__) {
    // Offline mode: skip WebSocket / delegate, render immediately with mock
    // data. Used for CI / Playwright / no-node previews. The mock posts are
    // pushed into the `posts` store directly (App.svelte reads it reactively),
    // replacing the old imperative feed.updatePosts(MOCK_POSTS) handle.
    console.log("[offline] Booting in offline mode with mock data");
    const id = createIdentity("Offline Demo");
    identity.set(id);
    renderApp(id);
    // renderApp triggers connection.loadState() which is a no-op without a
    // connect(). Push mock posts into the feed store once mounted.
    import("../mock-data").then(({ MOCK_POSTS }) => {
      knownPostIds.clear();
      for (const post of MOCK_POSTS) knownPostIds.add(post.id);
      posts.set(MOCK_POSTS);
    });
  } else {
    // App.svelte renders the splash while status === "connecting" && !appRendered.
    connection.connect();
  }
}
