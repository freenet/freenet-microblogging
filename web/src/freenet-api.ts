import {
  FreenetWsApi,
  ContractKey,
  ContractType as WasmContractType,
  GetRequest,
  GetResponse,
  PutRequest,
  UpdateRequest,
  UpdateResponse,
  UpdateNotification,
  UpdateData,
  UpdateDataType,
  DeltaUpdate,
  SubscribeRequest,
  PutResponse,
  DelegateResponse,
  HostError,
  ResponseHandler,
} from "@freenetorg/freenet-stdlib";
// The constructable (`…T`) flatbuffer tables carry `.pack()`; the reader classes
// (ContractCode/WasmContractV1/ContractContainer) do NOT, so anything nested in
// a PutRequest container must be a `…T` or packing throws "field N must be set".
// These are re-exported only from the /common subpath, not the package root.
import {
  ContractCodeT,
  WasmContractV1T,
  ContractContainerT,
} from "@freenetorg/freenet-stdlib/common";
// A PutRequest's `relatedContracts` (flatbuffer field 8) is REQUIRED, not
// optional — passing `undefined` makes the Put message fail to serialize with
// "FlatBuffers: field 8 must be set". An empty RelatedContractsT satisfies it.
import { RelatedContractsT } from "@freenetorg/freenet-stdlib/client-request";
import { Post } from "./types";
import {
  deriveShardContractKey,
  shardContractKeyTFromParts,
  hexToBytes,
} from "./shard-key";
import { signPost, signLike, signRepost, signQuoteRef, signReply } from "./identity";

/**
 * Assemble the `PutRequest` that instantiates a parameterized shard contract.
 *
 * This is the single place the three shard PUT paths (user / thread /
 * global-index) build their container, so a serialization regression is caught
 * once. It is deliberately easy to get wrong in two ways that BOTH surface as
 * the opaque flatbuffer error "field 8 must be set", and both are guarded here:
 *
 *  - The nested tables MUST be the packable builder (`…T`) variants
 *    (WasmContractV1T / ContractContainerT / ContractKeyT). The reader classes
 *    carry no `.pack()`, so a reader key serializes to nothing and the
 *    WasmContractV1 `key` (its field 8) is reported unset.
 *  - `relatedContracts` (the Put message's field 8) is REQUIRED. Passing
 *    `undefined` fails to serialize; an empty RelatedContractsT([]) satisfies it.
 *
 * `freenet-api.test.ts` packs the result of this function to lock both in.
 */
export function buildShardPutRequest(
  wasm: Uint8Array,
  codeHashBytes: Uint8Array,
  parameters: Uint8Array,
  initialState: Uint8Array,
): PutRequest {
  const code = new ContractCodeT(Array.from(wasm), Array.from(codeHashBytes));
  const keyT = shardContractKeyTFromParts(codeHashBytes, parameters);
  const contract = new WasmContractV1T(code, Array.from(parameters), keyT);
  const container = new ContractContainerT(
    WasmContractType.WasmContractV1,
    contract,
  );
  return new PutRequest(
    container,
    Array.from(initialState),
    // REQUIRED field — never `undefined` (see fn doc).
    new RelatedContractsT([]),
    false,
    false,
  );
}

// Contract post format (matches Rust `common::post::Post`). Signature and
// author_pubkey are hex strings (ML-DSA-65 sig 3309 B, VK 1952 B); the id is
// the content address (hex of blake3 over the canonical signing payload).
interface ContractPost {
  id: string;
  author_pubkey: string;
  author_name: string;
  author_handle: string;
  content: string;
  timestamp: number;
  // Content address of the post this replies to, empty/absent for top-level
  // posts. Matches the Rust `Post.reply_to` field. The global index MAY hold
  // replies (its acceptance is self-verification only — see the contract doc),
  // so a strictly-top-level public timeline filters on this at render time.
  reply_to?: string;
  // Content address of the quoted post (quote repost), empty/absent otherwise.
  // Matches the Rust `Post.quoted_post` additive field.
  quoted_post?: string;
  signature: string | null;
}

interface PendingPostDraft {
  nonce: string;
  author_name: string;
  author_handle: string;
  content: string;
  timestamp: number;
  /** Set for a quote repost: the content address of the quoted post. */
  quoted_post: string;
  /**
   * Whether the author opted to also share this post to the public-timeline
   * global index (opt-in). Carried on the draft so {@link completePublish} —
   * which matches by nonce — knows whether to mirror the signed post into the
   * global index after the primary user-shard publish.
   */
  shareToGlobal: boolean;
}

// User-shard state (matches Rust `UserShard`). Only `posts` is consumed by the
// feed today; profile/follows are deserialized-tolerant (present-or-absent).
interface UserShardState {
  posts?: ContractPost[];
  profile?: unknown;
  follows?: Record<string, unknown>;
}

// Global-index (public-timeline) state (matches Rust `GlobalIndexShard`). Unlike
// the user shard, `posts` is a MAP keyed by content-address id (Rust
// `BTreeMap<String, Post>`), NOT a Vec — so the read side iterates
// `Object.values(posts)`. `#[serde(default)]` on the contract makes `{}` and
// `{"posts":{}}` both decode to an empty timeline.
interface GlobalIndexState {
  posts?: Record<string, ContractPost>;
}

// A like record (matches Rust `common::thread::LikeRecord`). signer_pubkey is
// the liker's VK hex; `liked` true=like / false=unlike (tombstone); signature
// is over the canonical payload the delegate built.
interface LikeRecord {
  signer_pubkey: string;
  seq: number;
  liked: boolean;
  writer_cert?: unknown;
  signature: string | null;
}

// A repost record (matches Rust `common::thread::RepostRecord`). Mirror of
// LikeRecord: signer_pubkey is the reposter's VK hex; `reposted` true=repost /
// false=un-repost (tombstone); signature is over the canonical payload.
interface RepostRecord {
  signer_pubkey: string;
  seq: number;
  reposted: boolean;
  writer_cert?: unknown;
  signature: string | null;
}

// A quote reference (matches Rust `common::thread::QuoteRef`). Records that
// signer_pubkey quoted the thread's root post in their own quote_post_id.
interface QuoteRefRecord {
  signer_pubkey: string;
  quote_post_id: string;
  writer_cert?: unknown;
  signature: string | null;
}

// Thread-shard state (matches Rust `ThreadShard`). `likes`, `reposts`, and
// `quotes` are consumed for engagement aggregates; replies land in a later slice.
interface ThreadShardState {
  replies?: Record<string, ContractPost>;
  likes?: Record<string, LikeRecord>;
  quotes?: Record<string, QuoteRefRecord>;
  reposts?: Record<string, RepostRecord>;
}

/** A pending like awaiting the delegate's `SignedLike`, keyed by nonce. */
interface PendingLike {
  nonce: string;
  rootPostId: string;
  liked: boolean;
}

/** A pending repost awaiting the delegate's `SignedRepost`, keyed by nonce. */
interface PendingRepost {
  nonce: string;
  rootPostId: string;
  reposted: boolean;
}

/** Aggregate like state for one post, derived from its thread shard. */
export interface LikeState {
  postId: string;
  count: number;
  likedByMe: boolean;
}

/** Aggregate repost state for one post, derived from its thread shard. */
export interface RepostState {
  postId: string;
  count: number;
  repostedByMe: boolean;
}

/** A pending quote-ref awaiting the delegate's `SignedQuoteRef`, keyed by nonce. */
interface PendingQuoteRef {
  nonce: string;
  rootPostId: string;
  quotePostId: string;
}

/** A pending reply awaiting the delegate's `Signed` response, keyed by nonce. */
interface PendingReply {
  nonce: string;
  rootPostId: string;
  author_name: string;
  author_handle: string;
  content: string;
  timestamp: number;
}

/** Aggregate quote state for one post, derived from its thread shard. */
export interface QuoteState {
  postId: string;
  count: number;
}

// Convert contract format → UI format
function contractPostToUiPost(cp: ContractPost): Post {
  return {
    id: cp.id,
    author: {
      displayName: cp.author_name,
      handle: cp.author_handle,
      avatarColor: stringToColor(cp.author_pubkey),
      publicKey: cp.author_pubkey,
    },
    content: cp.content,
    timestamp: new Date(cp.timestamp),
    likes: 0,
    reposts: 0,
    replies: 0,
    liked: false,
    reposted: false,
    quotes: 0,
    quotedPostId: cp.quoted_post && cp.quoted_post.length > 0 ? cp.quoted_post : undefined,
    replyToId: cp.reply_to && cp.reply_to.length > 0 ? cp.reply_to : undefined,
  };
}

/**
 * Cadence of the public-timeline re-GET fallback. Slow on purpose: it only
 * exists to backstop the live-delta path (the network drops a delta broadcast
 * when the subscription tree is still forming and never re-sends it — #50),
 * so one singleton GET a minute per session keeps Discover eventually
 * consistent without meaningfully loading the node.
 */
const GLOBAL_INDEX_REFRESH_MS = 60_000;

/**
 * Extract the DELTA payload of an update notification as a JSON string, or
 * null when the notification carries no delta. Deltas arrive on a local
 * client's own UPDATE echo (`DeltaUpdate`) and on `StateAndDeltaUpdate`.
 */
function notificationDelta(notification: UpdateNotification): string | null {
  const updateData = notification.update as UpdateData;
  if (!updateData) return null;
  const t = updateData.updateDataType;
  if (t !== UpdateDataType.DeltaUpdate && t !== UpdateDataType.StateAndDeltaUpdate) {
    return null;
  }
  const payload = updateData.updateData as { delta?: number[] } | null;
  if (!payload?.delta) return null;
  return new TextDecoder("utf8")
    .decode(Uint8Array.from(payload.delta))
    .replace(/\x00/g, "");
}

/**
 * Extract the FULL-STATE payload of an update notification as a JSON string,
 * or null when the notification carries no state. Relayed/broadcast updates
 * from other nodes arrive as `StateUpdate` — the post-merge state, same JSON
 * as a GET response.
 */
function notificationState(notification: UpdateNotification): string | null {
  const updateData = notification.update as UpdateData;
  if (!updateData) return null;
  const t = updateData.updateDataType;
  if (t !== UpdateDataType.StateUpdate && t !== UpdateDataType.StateAndDeltaUpdate) {
    return null;
  }
  const payload = updateData.updateData as { state?: number[] } | null;
  if (!payload?.state) return null;
  return new TextDecoder("utf8")
    .decode(Uint8Array.from(payload.state))
    .replace(/\x00/g, "");
}

// Deterministic color from string
function stringToColor(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  const hue = Math.abs(hash % 360);
  return `hsl(${hue}, 65%, 45%)`;
}

export type ConnectionStatus =
  | "disconnected"
  | "connecting"
  | "connected"
  | "error";

export interface FreenetCallbacks {
  onPostsLoaded: (posts: Post[]) => void;
  onNewPost: (post: Post) => void;
  onStatusChange: (status: ConnectionStatus) => void;
  /** Optional: receives delegate responses forwarded from the node. */
  onDelegateResponse?: (response: DelegateResponse) => void;
  /** Optional: live like count / liked-by-me for a post, from its thread shard. */
  onLikeUpdated?: (like: LikeState) => void;
  /** Optional: live repost count / reposted-by-me for a post, from its thread shard. */
  onRepostUpdated?: (repost: RepostState) => void;
  /** Optional: live quote-repost count for a post, from its thread shard. */
  onQuoteUpdated?: (quote: QuoteState) => void;
  /** Optional: full public-timeline snapshot from the global-index GET. */
  onGlobalPostsLoaded?: (posts: Post[]) => void;
  /** Optional: a single live public-timeline post from a global-index delta. */
  onNewGlobalPost?: (post: Post) => void;
  /**
   * Optional: authoritative reply list for a root post, derived from its
   * thread shard GET. Fires whenever the thread shard is read (like/repost
   * refresh or explicit subscribe delivery). The full reply set is passed so
   * the caller can replace (not merge) its local replica.
   */
  onRepliesUpdated?: (rootPostId: string, replies: Post[]) => void;
}

export class FreenetConnection {
  private api: FreenetWsApi | null = null;
  private callbacks: FreenetCallbacks;
  private currentUser: {
    pubkey: string;
    name: string;
    handle: string;
  } | null = null;
  /** Drafts awaiting a delegate `Signed` response, FIFO. See publishPost. */
  private pendingPosts: PendingPostDraft[] = [];
  /**
   * The owner's ML-DSA-65 verifying key (hex) once the delegate reports the
   * identity. Used to derive this owner's user-shard key. Null until known.
   */
  private ownerVkHex: string | null = null;
  /**
   * The per-owner user-shard contract key, derived from the owner VK and the
   * build-injected shard code hash (ADR-0001 Phase 4). Once set, the feed reads
   * and writes the user shard instead of the legacy global posts contract.
   */
  private userShardKey: ContractKey | null = null;
  /** Base58 instance id of {@link userShardKey}, for response key matching. */
  private userShardInstanceId: string | null = null;
  /** Guards against concurrent user-shard init for the SAME owner. Reset when
   * the owner VK changes (identity switch) so the new shard re-initialises. */
  private userShardInitOwner: string | null = null;
  /**
   * Serialises every `api.get()` so at most one GET is in flight at a time.
   *
   * The stdlib resolves GET promises from a single FIFO queue with NO request
   * correlation: the Nth `GetResponse`/`NotFound` to arrive settles the Nth
   * pending `get()` promise, regardless of which contract it was for. With
   * multiple concurrent shard flows live (user-shard probe/load, per-thread
   * probe/like-refresh) two in-flight GETs can have their responses swapped —
   * a thread GET resolving the user-shard probe (→ feed never instantiates) or
   * a like-refresh popping a thread probe (→ that thread never PUT, the like is
   * silently lost). Routing-by-key in `handleGetResponse` fixes WHICH handler
   * runs, but not WHICH awaited promise settles. The only robust fix without
   * stdlib request-ids is to never have two GETs outstanding: each `api.get()`
   * awaits the previous one's settle. (The prior `startupDone` barrier only
   * covered startup-time traffic, which #33 removed — it serialised nothing
   * against the real post-init concurrency.)
   */
  private getChain: Promise<unknown> = Promise.resolve();
  /**
   * Per-thread shard keys, lazily derived the first time a post is liked. Keyed
   * by root post id (the thread-shard parameter). A thread shard is parameterized
   * by its root post id, so its key = blake3(thread_code_hash || utf8(post_id)).
   */
  private threadKeys = new Map<string, ContractKey>();
  /** Reverse map: thread instance id (base58) → root post id, for GET routing. */
  private threadInstanceToRoot = new Map<string, string>();
  /**
   * The public-timeline global index key. Unlike user/thread shards this is a
   * fixed-key SINGLETON (parameters = empty bytes), so there is exactly one
   * instance: key = blake3(global_index_code_hash || <empty>). Lazily derived on
   * the first opt-in share; null when no code hash is injected (offline / dev).
   */
  private globalIndexKey: ContractKey | null = null;
  /**
   * Base58 instance id of {@link globalIndexKey}, for response key matching on
   * the read side. Mirrors {@link userShardInstanceId}; set when the singleton
   * key is first derived in {@link globalIndexKeyOrNull}.
   */
  private globalIndexInstanceId: string | null = null;
  /** Set once the global index is confirmed instantiated (GET-probe or PUT). */
  private globalIndexEnsured = false;
  /** Collapses concurrent first-share races into one GET-probe + PUT. */
  private globalIndexEnsurePromise: Promise<void> | null = null;
  /**
   * Set once a subscribe was issued AFTER a successful global-index GET. The
   * boot-time subscribe is rejected by the node when the singleton is not yet
   * instantiated ("contract WASM not cached locally") and that rejection never
   * surfaces to the stdlib promise — so the only reliable point to subscribe
   * is right after a GET succeeded (the contract is then cached locally and
   * the node accepts). See #50.
   */
  private globalIndexSubscribedAfterGet = false;
  /** Periodic public-timeline re-GET fallback (see startGlobalIndexRefresh). */
  private globalIndexRefreshTimer: ReturnType<typeof setInterval> | null = null;
  /** Likes awaiting a delegate `SignedLike`, keyed by nonce. */
  private pendingLikes: PendingLike[] = [];
  /** Per-thread debounce timers coalescing like-refresh GETs (root id → timer). */
  private likeRefreshTimers = new Map<string, ReturnType<typeof setTimeout>>();
  /** Reposts awaiting a delegate `SignedRepost`, keyed by nonce. */
  private pendingReposts: PendingRepost[] = [];
  /** Quote-refs awaiting a delegate `SignedQuoteRef`, keyed by nonce. */
  private pendingQuoteRefs: PendingQuoteRef[] = [];
  /** Replies awaiting a delegate `Signed` response (SignReply), keyed by nonce. */
  private pendingReplies: PendingReply[] = [];

  constructor(callbacks: FreenetCallbacks) {
    this.callbacks = callbacks;
  }

  connect(): void {
    // The app talks only to per-owner/per-thread shards + the identity delegate
    // (no global contract). Whether to connect at all is gated upstream by
    // __OFFLINE_MODE__ in index.ts (offline skips connect and renders mock
    // data), so connect() always opens the socket when called.
    this.callbacks.onStatusChange("connecting");

    try {
      const wsUrl = new URL(`ws://${location.host}/v1/contract/command`);

      const handler: ResponseHandler = {
        onContractPut: (_response: PutResponse) => {},
        onContractGet: (response: GetResponse) => {
          this.handleGetResponse(response);
        },
        onContractUpdate: (_response: UpdateResponse) => {},
        onContractUpdateNotification: (notification: UpdateNotification) => {
          this.handleUpdateNotification(notification);
        },
        onContractNotFound: (_instanceId: Uint8Array) => {
          // A shard probe against a not-yet-instantiated key rejects the
          // awaited get() (handled there); the live feed need not error.
          console.warn("[freenet] Contract not found");
        },
        onDelegateResponse: (response: DelegateResponse) => {
          this.callbacks.onDelegateResponse?.(response);
        },
        onErr: (err: HostError) => {
          console.error("[freenet] Error:", err.cause);
          this.callbacks.onStatusChange("error");
        },
        onOpen: () => {
          console.log("[freenet] Connected to Freenet node");
          this.callbacks.onStatusChange("connected");
        },
      };
      // Pass empty string as authToken to skip cookie reading (sandbox blocks it)
      this.api = new FreenetWsApi(wsUrl, handler, "");
    } catch (e) {
      console.warn("[freenet] Connection failed:", e);
      this.callbacks.onStatusChange("error");
    }
  }

  /**
   * Issue a GET serialised behind {@link getChain}, so it is the only GET in
   * flight when its response arrives — defeating the stdlib's uncorrelated FIFO
   * response queue.
   *
   * CRITICAL: the chain must advance on the UNDERLYING `api.get()` settle, not
   * on a shorter app-level timeout. The stdlib keeps the GET registered in its
   * `pendingGets` FIFO until either a real GetResponse/NotFound or its OWN
   * `REQUEST_TIMEOUT_MS` (30 s) fires. If we advanced the chain on a 8 s app
   * timeout we would issue the next `api.get()` while the timed-out one is still
   * in `pendingGets` → two entries → a late response pops the wrong promise
   * (the very misroute this exists to prevent). So `getChain` chains on the raw
   * stdlib promise `p`; the chain can only advance once the stdlib entry is
   * truly gone, and a genuinely hung GET still drains via the stdlib's 30 s
   * reject. The caller's optional `ms` is a SOFT view (resolve/reject the caller
   * early) that does NOT release the next GET.
   */
  private serializedGet(req: GetRequest, ms = 8000): Promise<GetResponse> {
    if (!this.api) return Promise.reject(new Error("no api"));
    const api = this.api;
    // The raw stdlib GET — its settle is what owns a `pendingGets` slot.
    const p = this.getChain.then(
      () => api.get(req),
      () => api.get(req),
    );
    // Advance the chain ONLY when the stdlib GET itself settles (entry drained),
    // never on the soft app timeout below.
    this.getChain = p.then(
      () => undefined,
      () => undefined,
    );
    // Caller sees a soft 8 s bound; the underlying GET keeps its stdlib slot
    // until it really settles, so the chain stays correct even if the caller
    // gave up. (`ms === 0` disables the soft timeout — caller awaits the raw GET.)
    return ms > 0 ? this.withTimeout(p, ms) : p;
  }

  private withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timeout")), ms);
      p.then(
        (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        (e) => {
          clearTimeout(timer);
          reject(e);
        },
      );
    });
  }

  loadState(): void {
    // The feed is sourced solely from the owner's user shard. index.ts refreshes
    // via loadState after a publish, so this targets the same key writes go to.
    if (!this.api || !this.userShardKey) return;
    this.serializedGet(new GetRequest(this.userShardKey, true)).catch((e) =>
      console.error("[freenet] Get request failed:", e)
    );
  }

  /** Base58 instance id of a response's key, for matching against our keys. */
  private responseInstanceId(key: ContractKey | null | undefined): string | null {
    try {
      return key ? key.encode() : null;
    } catch {
      return null;
    }
  }

  private handleGetResponse(response: GetResponse): void {
    try {
      const respId = this.responseInstanceId(response.key);
      // Thread-shard GET (a like/repost refresh / subscription): recompute the
      // post's engagement aggregates and emit them, independent of the
      // user-shard feed below. One thread GET carries both surfaces.
      const threadRoot = respId ? this.threadInstanceToRoot.get(respId) : undefined;
      if (threadRoot) {
        const json = new TextDecoder("utf8").decode(Uint8Array.from(response.state));
        const thread = JSON.parse(json) as ThreadShardState;
        this.emitLikeState(threadRoot, thread.likes ?? {});
        this.emitRepostState(threadRoot, thread.reposts ?? {});
        this.emitQuoteState(threadRoot, thread.quotes ?? {});
        // Emit the full reply list so Thread.svelte can surface real replies.
        const replies = Object.values(thread.replies ?? {}).map(contractPostToUiPost);
        replies.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
        this.callbacks.onRepliesUpdated?.(threadRoot, replies);
        return;
      }
      // Global-index GET (public-timeline snapshot): the singleton's state is a
      // MAP keyed by id (Rust BTreeMap), so iterate `Object.values`, not a Vec.
      // The index MAY hold replies/quotes (acceptance is self-verification only),
      // so filter to top-level posts (empty/absent reply_to) before rendering.
      if (this.globalIndexInstanceId !== null && respId === this.globalIndexInstanceId) {
        const stateJson = new TextDecoder("utf8").decode(
          Uint8Array.from(response.state),
        );
        const rawPosts = (JSON.parse(stateJson) as GlobalIndexState).posts ?? {};
        const posts = Object.values(rawPosts)
          .filter((cp) => !cp.reply_to)
          .map(contractPostToUiPost);
        // Sort by timestamp descending (newest first) — same comparator as the
        // user-shard path.
        posts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
        this.callbacks.onGlobalPostsLoaded?.(posts);
        return;
      }
      // The only other GET source is the owner's user shard. Drop anything else.
      if (this.userShardInstanceId === null || respId !== this.userShardInstanceId) {
        return;
      }
      const stateJson = new TextDecoder("utf8").decode(
        Uint8Array.from(response.state),
      );
      const rawPosts = (JSON.parse(stateJson) as UserShardState).posts ?? [];
      const posts = rawPosts.map(contractPostToUiPost);
      // Sort by timestamp descending (newest first)
      posts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
      this.callbacks.onPostsLoaded(posts);
    } catch (e) {
      console.error("[freenet] Failed to parse state:", e);
    }
  }

  private handleUpdateNotification(notification: UpdateNotification): void {
    try {
      const notifId = this.responseInstanceId(notification.key);
      // Thread-shard update (a like landed): re-GET for the authoritative
      // aggregate rather than reconciling the delta by hand.
      const threadRoot = notifId ? this.threadInstanceToRoot.get(notifId) : undefined;
      if (threadRoot) {
        this.refreshLikes(threadRoot);
        return;
      }
      // Global-index update (a post was shared to the public timeline). The
      // payload shape depends on WHERE the update came from:
      //  * a local client's own UPDATE echoes back as the DELTA it sent — the
      //    externally-tagged `GlobalIndexDelta::Posts` (`{"Posts":[…]}`);
      //  * an update relayed/broadcast FROM ANOTHER NODE arrives as the FULL
      //    post-merge STATE (`UpdateData::State`, same JSON as a GET response).
      // Handling only the delta silently dropped every cross-node update
      // (freenet-core#4764 investigation), so both are parsed here.
      if (this.globalIndexInstanceId !== null && notifId === this.globalIndexInstanceId) {
        const deltaPayload = notificationDelta(notification);
        if (deltaPayload !== null) {
          const parsed = JSON.parse(deltaPayload) as { Posts?: ContractPost[] };
          for (const cp of parsed.Posts ?? []) {
            if (cp.reply_to) continue; // top-level public timeline only
            this.callbacks.onNewGlobalPost?.(contractPostToUiPost(cp));
          }
          return;
        }
        const statePayload = notificationState(notification);
        if (statePayload !== null) {
          // Full snapshot: route through the loaded path — the store merges
          // rather than replaces, so this composes with the poll re-GET.
          const rawPosts = (JSON.parse(statePayload) as GlobalIndexState).posts ?? {};
          const posts = Object.values(rawPosts)
            .filter((cp) => !cp.reply_to)
            .map(contractPostToUiPost);
          posts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
          this.callbacks.onGlobalPostsLoaded?.(posts);
        }
        return;
      }
      // The only other update source is the owner's user shard.
      if (this.userShardInstanceId === null || notifId !== this.userShardInstanceId) {
        return;
      }
      // User-shard deltas are the externally-tagged `ShardDelta` enum
      // (`{"Posts":[…]}` / `{"Op":…}`). Op deltas (profile/follow) carry no feed
      // posts — ignore them here. Cross-node updates arrive as full state (see
      // the global-index branch above), whose JSON is `{posts:[…]}`.
      const deltaPayload = notificationDelta(notification);
      if (deltaPayload !== null) {
        const parsed = JSON.parse(deltaPayload) as {
          Posts?: ContractPost[];
          Op?: unknown;
        };
        for (const cp of parsed.Posts ?? []) {
          this.callbacks.onNewPost(contractPostToUiPost(cp));
        }
        return;
      }
      const statePayload = notificationState(notification);
      if (statePayload !== null) {
        const rawPosts = (JSON.parse(statePayload) as UserShardState).posts ?? [];
        const posts = rawPosts.map(contractPostToUiPost);
        posts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
        this.callbacks.onPostsLoaded(posts);
      }
    } catch (e) {
      console.error("[freenet] Failed to parse update:", e);
    }
  }

  setUser(pubkey: string, name: string, handle: string): void {
    this.currentUser = { pubkey, name, handle };
    // A real ML-DSA-65 VK is 1952 bytes → 3904 hex chars. The offline fallback
    // identity uses a 32-byte fake (64 hex chars), which is not a shard owner.
    if (pubkey && pubkey.length === 3904 && pubkey !== this.ownerVkHex) {
      this.ownerVkHex = pubkey;
      void this.initUserShard();
    }
  }

  /**
   * Derive this owner's user-shard key, ensure the contract is instantiated on
   * the node (PUT the parameterized container if it is not yet present), then
   * load + subscribe so the feed reflects the owner's shard. ADR-0001 Phase 4.
   */
  private async initUserShard(): Promise<void> {
    const owner = this.ownerVkHex;
    // Re-entry guard keyed by owner: a duplicate Identity for the same owner is
    // a no-op, but a new owner (identity switch) must re-initialise.
    if (!this.api || !owner || this.userShardInitOwner === owner) return;
    const codeHash =
      typeof __USER_SHARD_CODE_HASH__ !== "undefined"
        ? __USER_SHARD_CODE_HASH__
        : null;
    if (!codeHash || codeHash === "DEV_MODE_NO_CONTRACT_HASH") {
      console.warn("[user-shard] No code hash injected — feed unavailable");
      return;
    }
    this.userShardInitOwner = owner;
    try {
      // GET-response ordering is handled by serializedGet (one GET in flight at
      // a time), so shard init no longer needs a startup barrier — it can issue
      // its probe/load GETs concurrently with any other flow and the chain
      // keeps each GET's response matched to its own promise.
      const vkBytes = hexToBytes(owner);
      this.userShardKey = deriveShardContractKey(codeHash, vkBytes);
      this.userShardInstanceId = this.userShardKey.encode();
      console.log(
        `[user-shard] derived key ${this.userShardInstanceId} for owner ${owner.slice(0, 8)}…`,
      );

      // Probe for an existing instance. A brand-new owner has none, so PUT the
      // parameterized container (raw WASM + owner VK params + empty initial
      // state) to instantiate it before subscribing.
      const exists = await this.userShardExists();
      if (!exists) {
        await this.putUserShard(vkBytes, codeHash);
      }

      this.loadUserShard();
      this.subscribeUserShard();
    } catch (e) {
      console.error("[user-shard] init failed:", e);
      // No fallback contract — clear so a later setUser can retry.
      this.userShardKey = null;
      this.userShardInstanceId = null;
      this.userShardInitOwner = null;
    }
  }

  /**
   * GET the user shard to check whether the node already has this instance.
   * A genuine not-found AND a transient timeout both return false → we PUT. A
   * spurious PUT over an already-existing shard is safe: Freenet PUT-of-existing
   * runs the contract's CRDT merge (`update_state` → `merge_state`), not an
   * overwrite, so PUTting the empty `{"posts":[]}` initial state merges to a
   * no-op (posts union / profile LWW / follows set-union). The only cost is
   * re-sending the WASM on a slow GET.
   */
  private async userShardExists(): Promise<boolean> {
    if (!this.api || !this.userShardKey) return false;
    try {
      await this.serializedGet(new GetRequest(this.userShardKey, false));
      return true;
    } catch {
      return false;
    }
  }

  /** Fetch the bundled raw shard WASM bytes (served at the dist root). */
  private async fetchShardWasm(): Promise<Uint8Array> {
    const resp = await fetch("./user_shard.wasm");
    if (!resp.ok) {
      throw new Error(`failed to fetch user_shard.wasm: ${resp.status}`);
    }
    return new Uint8Array(await resp.arrayBuffer());
  }

  /**
   * PUT the parameterized user-shard container to instantiate this owner's
   * shard. The node re-hashes the `data` bytes to derive the key, so the
   * shipped WASM must be the raw compiled artifact whose blake3 equals the
   * injected code hash (see Makefile.toml build-user-shard).
   */
  private async putUserShard(
    vkBytes: Uint8Array,
    codeHashBase58: string,
  ): Promise<void> {
    if (!this.api || !this.userShardKey) return;
    const wasm = await this.fetchShardWasm();
    const codeHashBytes = this.userShardKey.codePart() ?? new Uint8Array(0);
    // Empty initial state; `UserShard` defaults fill the rest (posts: []).
    const initialState = new TextEncoder().encode(JSON.stringify({ posts: [] }));
    const req = buildShardPutRequest(wasm, codeHashBytes, vkBytes, initialState);
    console.log(
      `[user-shard] PUT instantiating shard (${codeHashBase58.slice(0, 8)}…)`,
    );
    await this.api.put(req);
  }

  private loadUserShard(): void {
    if (!this.api || !this.userShardKey) return;
    this.serializedGet(new GetRequest(this.userShardKey, true)).catch((e) =>
      console.error("[user-shard] get failed:", e),
    );
  }

  private subscribeUserShard(): void {
    if (!this.api || !this.userShardKey) return;
    this.api
      .subscribe(new SubscribeRequest(this.userShardKey, []))
      .catch((e) => console.error("[user-shard] subscribe failed:", e));
  }

  // --- Thread shard: likes (ADR-0001 Phase 4 slice 2) ----------------------

  /**
   * Derive (and cache) the thread-shard key for a post. A thread shard is
   * parameterized by its root post id, so the key is
   * blake3(thread_code_hash || utf8(post_id)) — note the parameter is the UTF-8
   * bytes of the id string, matching the contract's
   * `String::from_utf8_lossy(parameters)`, NOT raw/hex-decoded bytes.
   */
  private threadKeyFor(rootPostId: string): ContractKey | null {
    const cached = this.threadKeys.get(rootPostId);
    if (cached) return cached;
    const codeHash =
      typeof __THREAD_SHARD_CODE_HASH__ !== "undefined"
        ? __THREAD_SHARD_CODE_HASH__
        : null;
    if (!codeHash || codeHash === "DEV_MODE_NO_CONTRACT_HASH") return null;
    const params = new TextEncoder().encode(rootPostId);
    const key = deriveShardContractKey(codeHash, params);
    this.threadKeys.set(rootPostId, key);
    this.threadInstanceToRoot.set(key.encode(), rootPostId);
    return key;
  }

  /** Fetch the bundled raw thread-shard WASM bytes (served at the dist root). */
  private async fetchThreadWasm(): Promise<Uint8Array> {
    const resp = await fetch("./thread_shard.wasm");
    if (!resp.ok) {
      throw new Error(`failed to fetch thread_shard.wasm: ${resp.status}`);
    }
    return new Uint8Array(await resp.arrayBuffer());
  }

  /**
   * Ensure the post's thread shard is instantiated on the node: GET-probe, and
   * PUT the parameterized container if absent. Awaits the PUT before returning,
   * so the caller knows the shard exists before sending a like UpdateRequest
   * (an update to a never-instantiated contract is silently dropped by the
   * node — see M-3). Throws if the PUT itself fails.
   */
  private async ensureThreadShard(
    key: ContractKey,
    rootPostId: string,
  ): Promise<void> {
    if (!this.api) throw new Error("no api");
    try {
      await this.serializedGet(new GetRequest(key, false));
      return; // already instantiated
    } catch {
      // not found / timeout → PUT below (a spurious re-PUT merges to a no-op)
    }
    const wasm = await this.fetchThreadWasm();
    const codeHashBytes = key.codePart() ?? new Uint8Array(0);
    // Parameter = UTF-8 bytes of the root post id (matches the contract).
    const paramBytes = new TextEncoder().encode(rootPostId);
    const initialState = new TextEncoder().encode(
      JSON.stringify({ replies: {}, likes: {}, quotes: {}, reposts: {} }),
    );
    await this.api.put(
      buildShardPutRequest(wasm, codeHashBytes, paramBytes, initialState),
    );
  }

  /**
   * The public-timeline global index key, or null when it cannot be derived
   * (no code hash injected — offline / dev build). The global index is a
   * SINGLETON: empty parameters, so its key is blake3(code_hash || <empty>).
   * Mirrors {@link threadKeyFor}'s DEV_MODE_NO_CONTRACT_HASH short-circuit so an
   * un-built / offline env disables index writes gracefully.
   */
  private globalIndexKeyOrNull(): ContractKey | null {
    if (this.globalIndexKey) return this.globalIndexKey;
    const codeHash =
      typeof __GLOBAL_INDEX_SHARD_CODE_HASH__ !== "undefined"
        ? __GLOBAL_INDEX_SHARD_CODE_HASH__
        : null;
    if (!codeHash || codeHash === "DEV_MODE_NO_CONTRACT_HASH") return null;
    // Empty parameters → the singleton instance.
    const key = deriveShardContractKey(codeHash, new Uint8Array(0));
    this.globalIndexKey = key;
    // Record the instance id so handleGetResponse / handleUpdateNotification can
    // route the singleton's read + live-update responses (mirrors the user shard).
    this.globalIndexInstanceId = key.encode();
    return key;
  }

  /**
   * Read the public-timeline snapshot from the global index. Mirrors
   * {@link loadState} but targets the singleton index key. Unlike a write
   * (share), a reader MUST NOT instantiate the singleton — so there is no
   * GET-probe/PUT here: an absent index simply rejects the GET and the timeline
   * stays empty. No-ops when the key cannot be derived (offline / dev build).
   */
  loadGlobalIndex(): void {
    const key = this.globalIndexKeyOrNull();
    if (!this.api || !key) return;
    // Signal that the read path actually issued a GET against the singleton.
    // This fires whether or not the index is instantiated yet (a fresh network
    // has no index, so the GET rejects and onGlobalPostsLoaded never fires) —
    // so it is the reliable "read path ran on a live node" marker, distinct from
    // the "[freenet] Loaded N …" success log emitted only on a populated index.
    console.log("[global-index] loading public timeline");
    this.serializedGet(new GetRequest(key, true)).then(
      () => {
        // The GET cached the contract locally, so a subscribe is now accepted
        // by the node. The boot-time attempt below is rejected on a fresh
        // network (singleton not instantiated yet) and that rejection is
        // invisible client-side — this post-GET retry is the reliable one.
        this.subscribeGlobalIndexAfterGet();
      },
      (e) => console.error("[global-index] get failed:", e),
    );
    // Mirror the user-shard flow (loadUserShard + subscribeUserShard): a reader
    // also subscribes so subsequently-shared posts arrive live as deltas. Once
    // the post-GET retry has landed, stop re-issuing this on refresh ticks.
    if (!this.globalIndexSubscribedAfterGet) this.subscribeGlobalIndex();
    // Live deltas alone are not enough: the network drops an update's
    // broadcast when the subscription tree hasn't formed yet (freenet-core
    // fire-and-forget, no anti-entropy), so a subscribed session can still
    // miss posts shared from other nodes. A slow re-GET keeps Discover
    // eventually consistent regardless (#50).
    this.startGlobalIndexRefresh();
  }

  /**
   * Retry the global-index subscribe once, right after a successful GET (the
   * contract is then cached locally, so the node accepts it). No-op after the
   * first success — subscribing is idempotent on the node but there is no
   * point re-issuing it on every 60s refresh tick.
   */
  private subscribeGlobalIndexAfterGet(): void {
    if (this.globalIndexSubscribedAfterGet) return;
    this.globalIndexSubscribedAfterGet = true;
    this.subscribeGlobalIndex();
  }

  /**
   * Start the periodic public-timeline re-GET fallback. One interval per API
   * instance; each tick re-runs {@link loadGlobalIndex}, which no-ops
   * harmlessly when the socket is down (`this.api` null) and re-arms the
   * post-GET subscribe when it has not succeeded yet.
   */
  private startGlobalIndexRefresh(): void {
    if (this.globalIndexRefreshTimer !== null) return;
    this.globalIndexRefreshTimer = setInterval(() => {
      this.loadGlobalIndex();
    }, GLOBAL_INDEX_REFRESH_MS);
  }

  /**
   * Subscribe to the global index so shared posts arrive live as
   * {@link handleUpdateNotification} deltas. Mirrors {@link subscribeUserShard};
   * no-ops when the key cannot be derived (offline / dev build).
   */
  private subscribeGlobalIndex(): void {
    const key = this.globalIndexKeyOrNull();
    if (!this.api || !key) return;
    this.api
      .subscribe(new SubscribeRequest(key, []))
      .catch((e) => console.error("[global-index] subscribe failed:", e));
  }

  /** Fetch the bundled raw global-index-shard WASM bytes (served at dist root). */
  private async fetchGlobalIndexWasm(): Promise<Uint8Array> {
    const resp = await fetch("./global_index_shard.wasm");
    if (!resp.ok) {
      throw new Error(`failed to fetch global_index_shard.wasm: ${resp.status}`);
    }
    return new Uint8Array(await resp.arrayBuffer());
  }

  /**
   * Ensure the singleton global index is instantiated on the node: GET-probe,
   * and PUT the container with empty parameters if absent. Awaits the PUT before
   * returning, so a following UpdateRequest is not dropped against a
   * never-instantiated contract (the thread-shard M-3 hazard). `globalIndexEnsured`
   * + `globalIndexEnsurePromise` collapse concurrent first-share races into one
   * probe + PUT.
   *
   * CAVEAT (verify in the WASM-in-node tier, issue #34): the GET-then-PUT-if-
   * absent probe assumes a GET against a never-instantiated singleton *rejects*
   * (→ we PUT). If instead it resolves with empty/default state, we'd mark
   * ensured and skip the PUT, and the first UPDATE could land against an
   * uninstantiated contract. A spurious re-PUT is a harmless no-op (CRDT merge),
   * so the safe-but-unconfirmed behavior is the rejecting one. This is the same
   * unverified seam the parameterized shards carry; it cannot be exercised
   * without a live node (library tests don't model node GET semantics).
   */
  private async ensureGlobalIndex(key: ContractKey): Promise<void> {
    const api = this.api;
    if (!api) throw new Error("no api");
    if (this.globalIndexEnsured) return;
    if (this.globalIndexEnsurePromise) return this.globalIndexEnsurePromise;
    this.globalIndexEnsurePromise = (async () => {
      try {
        await this.serializedGet(new GetRequest(key, false));
        this.globalIndexEnsured = true;
        return; // already instantiated
      } catch {
        // not found / timeout → PUT below (a spurious re-PUT merges to a no-op)
      }
      const wasm = await this.fetchGlobalIndexWasm();
      const codeHashBytes = key.codePart() ?? new Uint8Array(0);
      // Singleton: empty parameters (matches the contract's blake3(code || <>)).
      // State shape mirrors the contract's BTreeMap<String,Post> — an OBJECT
      // ({"posts":{}}), like the thread shard's {replies:{},…}, NOT the
      // user-shard's {posts:[]} Vec.
      const initialState = new TextEncoder().encode(JSON.stringify({ posts: {} }));
      await api.put(
        buildShardPutRequest(wasm, codeHashBytes, new Uint8Array(0), initialState),
      );
      this.globalIndexEnsured = true;
    })();
    try {
      await this.globalIndexEnsurePromise;
    } finally {
      this.globalIndexEnsurePromise = null;
    }
  }

  /**
   * Mirror an already-signed post into the public-timeline global index
   * (opt-in). Reuses the SAME signed {@link ContractPost} the user-shard publish
   * built — it self-verifies, so the index re-verifies and accepts it. No-ops
   * gracefully when the index key cannot be derived (offline / dev). The index
   * delta is the externally-tagged `GlobalIndexDelta::Posts` form.
   */
  async shareToGlobalIndex(post: ContractPost): Promise<void> {
    const key = this.globalIndexKeyOrNull();
    if (!this.api || !key) return; // offline / no code hash → graceful no-op
    await this.ensureGlobalIndex(key);
    const deltaBytes = new TextEncoder().encode(JSON.stringify({ Posts: [post] }));
    const update = new UpdateData(
      UpdateDataType.DeltaUpdate,
      new DeltaUpdate(Array.from(deltaBytes)),
    );
    await this.api.update(new UpdateRequest(key, update));
    // The boot-time loadGlobalIndex() subscribed to the singleton BEFORE this
    // share instantiated it (a fresh network has no index until the first
    // share), so that pre-instantiation subscription does not deliver this
    // post's delta back. Re-load now: GET the just-instantiated singleton and
    // re-subscribe, so the sharer sees their own post in Discover this session
    // without a reload. Best-effort — the post is already published regardless.
    this.loadGlobalIndex();
  }

  /**
   * Like or unlike a post. Derives/instantiates the post's thread shard, then
   * asks the delegate to sign a `LikeRecord`; the matching `SignedLike` is
   * routed to {@link completeLike}, which folds it into the thread shard via
   * `ThreadDelta::Likes`. Returns false if it cannot proceed (no delegate /
   * thread code hash). Optimistic UI is the caller's concern; the authoritative
   * count comes back via {@link refreshLikes} after the update lands.
   */
  async likePost(rootPostId: string, liked: boolean): Promise<boolean> {
    if (!this.api) return false;
    const key = this.threadKeyFor(rootPostId);
    if (!key) {
      console.warn("[thread] no thread-shard code hash — cannot like");
      return false;
    }
    try {
      await this.ensureThreadShard(key, rootPostId);
      this.subscribeThread(key);
    } catch (e) {
      console.error("[thread] ensure/subscribe failed:", e);
      return false;
    }
    const nonce = crypto.randomUUID();
    this.pendingLikes.push({ nonce, rootPostId, liked });
    // seq is the liker's monotonic counter; ms-precision time is monotonic
    // enough for a single user's like/unlike toggles (the contract resolves
    // concurrent same-key records by higher seq).
    const requested = signLike(nonce, rootPostId, Date.now(), liked);
    if (!requested) {
      this.pendingLikes.pop();
      console.warn("[thread] cannot like: delegate not connected to sign");
      return false;
    }
    return true;
  }

  /**
   * Repost or un-repost a post — the plain-repost (retweet) half of the
   * engagement surface. Mirror of {@link likePost}: derives/instantiates the
   * post's thread shard, then asks the delegate to sign a `RepostRecord`; the
   * matching `SignedRepost` is routed to {@link completeRepost}, which folds it
   * into the thread shard via `ThreadDelta::Reposts`. Returns false if it cannot
   * proceed (no delegate / thread code hash). The authoritative count comes back
   * via the thread-shard refresh GET after the update lands.
   */
  async repostPost(rootPostId: string, reposted: boolean): Promise<boolean> {
    if (!this.api) return false;
    const key = this.threadKeyFor(rootPostId);
    if (!key) {
      console.warn("[thread] no thread-shard code hash — cannot repost");
      return false;
    }
    try {
      await this.ensureThreadShard(key, rootPostId);
      this.subscribeThread(key);
    } catch (e) {
      console.error("[thread] ensure/subscribe failed:", e);
      return false;
    }
    const nonce = crypto.randomUUID();
    this.pendingReposts.push({ nonce, rootPostId, reposted });
    // seq is the reposter's monotonic counter; ms-precision time is monotonic
    // enough for a single user's repost/un-repost toggles (the contract resolves
    // concurrent same-key records by higher seq).
    const requested = signRepost(nonce, rootPostId, Date.now(), reposted);
    if (!requested) {
      this.pendingReposts.pop();
      console.warn("[thread] cannot repost: delegate not connected to sign");
      return false;
    }
    return true;
  }

  /** Complete a like once the delegate returns a `SignedLike`. */
  async completeLike(signed: {
    nonce: string;
    root_post_id: string;
    signer_pubkey: string;
    seq: number;
    liked: boolean;
    signature: string;
  }): Promise<boolean> {
    if (!this.api) return false;
    const idx = this.pendingLikes.findIndex((p) => p.nonce === signed.nonce);
    if (idx === -1) {
      console.warn("[thread] SignedLike with no matching pending like", signed.nonce);
      return false;
    }
    this.pendingLikes.splice(idx, 1);
    const key = this.threadKeyFor(signed.root_post_id);
    if (!key) return false;

    const record: LikeRecord = {
      signer_pubkey: signed.signer_pubkey,
      seq: signed.seq,
      liked: signed.liked,
      signature: signed.signature,
    };
    try {
      const deltaBytes = new TextEncoder().encode(
        JSON.stringify({ Likes: [record] }),
      );
      const update = new UpdateData(
        UpdateDataType.DeltaUpdate,
        new DeltaUpdate(Array.from(deltaBytes)),
      );
      await this.api.update(new UpdateRequest(key, update));
      // Read back the authoritative aggregate once our own update lands — do it
      // immediately (not debounced) for snappy feedback on the user's own like.
      this.refreshLikesNow(signed.root_post_id);
      return true;
    } catch (e) {
      console.error("[thread] failed to send like:", e);
      // The update did not land — re-GET the authoritative aggregate so the
      // optimistic toggle is reconciled away (onLikeUpdated reverts the UI).
      this.refreshLikesNow(signed.root_post_id);
      return false;
    }
  }

  /** Complete a repost once the delegate returns a `SignedRepost`. Mirror of
   * {@link completeLike}. */
  async completeRepost(signed: {
    nonce: string;
    root_post_id: string;
    signer_pubkey: string;
    seq: number;
    reposted: boolean;
    signature: string;
  }): Promise<boolean> {
    if (!this.api) return false;
    const idx = this.pendingReposts.findIndex((p) => p.nonce === signed.nonce);
    if (idx === -1) {
      console.warn("[thread] SignedRepost with no matching pending repost", signed.nonce);
      return false;
    }
    this.pendingReposts.splice(idx, 1);
    const key = this.threadKeyFor(signed.root_post_id);
    if (!key) return false;

    const record: RepostRecord = {
      signer_pubkey: signed.signer_pubkey,
      seq: signed.seq,
      reposted: signed.reposted,
      signature: signed.signature,
    };
    try {
      const deltaBytes = new TextEncoder().encode(
        JSON.stringify({ Reposts: [record] }),
      );
      const update = new UpdateData(
        UpdateDataType.DeltaUpdate,
        new DeltaUpdate(Array.from(deltaBytes)),
      );
      await this.api.update(new UpdateRequest(key, update));
      // Read back the authoritative aggregate once our own update lands.
      this.refreshLikesNow(signed.root_post_id);
      return true;
    } catch (e) {
      console.error("[thread] failed to send repost:", e);
      // The update did not land — re-GET so the optimistic toggle is reconciled
      // away (onRepostUpdated reverts the UI).
      this.refreshLikesNow(signed.root_post_id);
      return false;
    }
  }

  /** GET a post's thread shard now to recompute its like aggregate. */
  private refreshLikesNow(rootPostId: string): void {
    if (!this.api) return;
    const key = this.threadKeyFor(rootPostId);
    if (!key) return;
    this.serializedGet(new GetRequest(key, true)).catch((e) =>
      console.error("[thread] like refresh GET failed:", e),
    );
  }

  /**
   * Debounced like-refresh: coalesce a burst of thread update notifications
   * (e.g. a viral post drawing many remote likes) into one GET per thread per
   * window, instead of one full-state GET per notification.
   */
  private refreshLikes(rootPostId: string): void {
    const existing = this.likeRefreshTimers.get(rootPostId);
    if (existing) clearTimeout(existing);
    this.likeRefreshTimers.set(
      rootPostId,
      setTimeout(() => {
        this.likeRefreshTimers.delete(rootPostId);
        this.refreshLikesNow(rootPostId);
      }, 500),
    );
  }

  private subscribeThread(key: ContractKey): void {
    if (!this.api) return;
    this.api
      .subscribe(new SubscribeRequest(key, []))
      .catch((e) => console.error("[thread] subscribe failed:", e));
  }

  /**
   * Drop a pending like by nonce (delegate returned an Error for it). Returns
   * true if a pending like was actually dropped, so the caller can revert the
   * optimistic UI toggle for that like.
   */
  dropPendingLike(nonce: string): boolean {
    const idx = this.pendingLikes.findIndex((p) => p.nonce === nonce);
    if (idx === -1) return false;
    this.pendingLikes.splice(idx, 1);
    return true;
  }

  /**
   * Drop a pending repost by nonce (delegate returned an Error for it). Returns
   * true if a pending repost was actually dropped, so the caller can revert the
   * optimistic UI toggle. Mirror of {@link dropPendingLike}.
   */
  dropPendingRepost(nonce: string): boolean {
    const idx = this.pendingReposts.findIndex((p) => p.nonce === nonce);
    if (idx === -1) return false;
    this.pendingReposts.splice(idx, 1);
    return true;
  }

  /**
   * Reduce a thread shard's `likes` map to an aggregate for the UI: count of
   * records with `liked == true`, and whether the current owner is among them.
   */
  private emitLikeState(rootPostId: string, likes: Record<string, LikeRecord>): void {
    let count = 0;
    let likedByMe = false;
    for (const rec of Object.values(likes)) {
      if (rec.liked) {
        count++;
        if (this.ownerVkHex && rec.signer_pubkey === this.ownerVkHex) {
          likedByMe = true;
        }
      }
    }
    this.callbacks.onLikeUpdated?.({ postId: rootPostId, count, likedByMe });
  }

  /**
   * Reduce a thread shard's `reposts` map to an aggregate for the UI: count of
   * records with `reposted == true`, and whether the current owner is among
   * them. Mirror of {@link emitLikeState}.
   */
  private emitRepostState(
    rootPostId: string,
    reposts: Record<string, RepostRecord>,
  ): void {
    let count = 0;
    let repostedByMe = false;
    for (const rec of Object.values(reposts)) {
      if (rec.reposted) {
        count++;
        if (this.ownerVkHex && rec.signer_pubkey === this.ownerVkHex) {
          repostedByMe = true;
        }
      }
    }
    this.callbacks.onRepostUpdated?.({ postId: rootPostId, count, repostedByMe });
  }

  /**
   * Begin publishing a post. The delegate must sign it first (ML-DSA-65 over
   * the canonical payload) and assign the content-addressed id, so this stashes
   * the draft and fires a SignPost request. The matching `Signed` response is
   * routed to {@link completePublish}, which sends the signed post on-chain.
   * (Mirrors mail's pending-send pattern; delegate responses are not correlated
   * per-request, so we hold the draft until the signature returns.)
   */
  async publishPost(content: string, shareToGlobal = false): Promise<boolean> {
    return this.publishPostInternal(content, "", shareToGlobal);
  }

  /**
   * Quote-repost `quotedPostId`: publish a new post that embeds it. The post
   * carries `quoted_post = quotedPostId` (signed into its content address); once
   * it lands, {@link completePublish} also signs a `QuoteRef` and folds it into
   * the quoted post's thread shard so the quote count converges. Returns false
   * if it cannot proceed (no shard / delegate).
   */
  async quotePost(quotedPostId: string, content: string): Promise<boolean> {
    if (!quotedPostId) return false;
    // A quote-repost is engagement on an existing post (it folds a QuoteRef into
    // the quoted post's thread shard), not a fresh public-timeline post, so it
    // never opts into the global index.
    return this.publishPostInternal(content, quotedPostId, false);
  }

  /** Shared publish path; `quotedPost` empty for an ordinary post. */
  private async publishPostInternal(
    content: string,
    quotedPost: string,
    shareToGlobal: boolean,
  ): Promise<boolean> {
    // Posts go to the owner's user shard, instantiated once the identity is
    // known. No shard → cannot publish.
    if (!this.api || !this.userShardKey || !this.currentUser) {
      return false;
    }
    const timestamp = Date.now();
    // Per-request nonce uniquely identifies this draft. The Signed response
    // echoes it, so completePublish matches the exact draft even when two posts
    // share the same millisecond timestamp (Date.now() collision) — matching on
    // timestamp alone could otherwise pair the wrong content with a signature.
    const nonce = crypto.randomUUID();
    const draft: PendingPostDraft = {
      nonce,
      author_name: this.currentUser.name,
      author_handle: this.currentUser.handle,
      content,
      timestamp,
      quoted_post: quotedPost,
      shareToGlobal,
    };
    this.pendingPosts.push(draft);

    const requested = signPost(
      nonce,
      content,
      this.currentUser.name,
      this.currentUser.handle,
      timestamp,
      quotedPost
    );
    if (!requested) {
      // No delegate (offline) — cannot sign, so cannot publish.
      this.pendingPosts.pop();
      console.warn("[freenet] Cannot publish: delegate not connected to sign post");
      return false;
    }
    return true;
  }

  /**
   * Complete a publish once the delegate returns a `Signed` response: matches
   * the pending draft, assembles the signed ContractPost, and sends it.
   */
  async completePublish(signed: {
    nonce: string;
    post_id: string;
    signature: string;
    public_key: string;
  }): Promise<boolean> {
    if (!this.api || !this.userShardKey) return false;

    // Match the draft by its unique nonce, not position or timestamp — robust
    // to a dropped/errored sign request and to same-millisecond posts.
    const idx = this.pendingPosts.findIndex((d) => d.nonce === signed.nonce);
    if (idx === -1) {
      console.warn(
        "[freenet] Signed response with no matching pending draft",
        signed.nonce
      );
      return false;
    }
    const [draft] = this.pendingPosts.splice(idx, 1);

    const post: ContractPost = {
      id: signed.post_id,
      author_pubkey: signed.public_key,
      author_name: draft.author_name,
      author_handle: draft.author_handle,
      content: draft.content,
      timestamp: draft.timestamp,
      // Carry the quote target through to the on-chain record; omitted (empty)
      // for an ordinary post so the serialized shape is unchanged.
      ...(draft.quoted_post ? { quoted_post: draft.quoted_post } : {}),
      signature: signed.signature,
    };

    try {
      const encoder = new TextEncoder();
      // The user shard expects the externally-tagged `ShardDelta::Posts` form.
      const deltaBytes = encoder.encode(JSON.stringify({ Posts: [post] }));
      const delta = new DeltaUpdate(Array.from(deltaBytes));
      const update = new UpdateData(UpdateDataType.DeltaUpdate, delta);
      const req = new UpdateRequest(this.userShardKey, update);
      await this.api.update(req);
      // For a quote repost, also record a QuoteRef on the QUOTED post's thread
      // shard (root = quoted_post id, quote_post_id = this new post's id) so the
      // quoted post's quote count converges. Best-effort: a failure here leaves
      // the quote post published but uncounted, which the next refresh repairs.
      if (draft.quoted_post) {
        this.recordQuoteRef(draft.quoted_post, post.id).catch((e) =>
          console.error("[thread] recordQuoteRef failed:", e),
        );
      }
      // If the author opted in, also mirror the signed post into the public
      // global index. Best-effort and fire-and-forget: the primary user-shard
      // publish above is already done, so a failure (or offline / no code hash)
      // here must NEVER fail the publish or change the return value.
      if (draft.shareToGlobal) {
        this.shareToGlobalIndex(post).catch((e) =>
          console.error("[global-index] share failed (post still published):", e),
        );
      }
      return true;
    } catch (e) {
      console.error("[freenet] Failed to publish:", e);
      return false;
    }
  }

  /**
   * Sign + fold a `QuoteRef` into the quoted post's thread shard. Mirrors the
   * like/repost ensure→sign→complete flow: derive the thread shard for the
   * quoted post, ask the delegate to sign a `QuoteRef` bound to it, and route
   * the `SignedQuoteRef` to {@link completeQuoteRef}.
   */
  private async recordQuoteRef(
    quotedPostId: string,
    quotePostId: string,
  ): Promise<boolean> {
    if (!this.api) return false;
    const key = this.threadKeyFor(quotedPostId);
    if (!key) {
      console.warn("[thread] no thread-shard code hash — cannot record quote");
      return false;
    }
    await this.ensureThreadShard(key, quotedPostId);
    this.subscribeThread(key);
    const nonce = crypto.randomUUID();
    this.pendingQuoteRefs.push({ nonce, rootPostId: quotedPostId, quotePostId });
    const requested = signQuoteRef(nonce, quotedPostId, quotePostId);
    if (!requested) {
      this.pendingQuoteRefs.pop();
      console.warn("[thread] cannot record quote: delegate not connected");
      return false;
    }
    return true;
  }

  /** Complete a quote-ref once the delegate returns a `SignedQuoteRef`. */
  async completeQuoteRef(signed: {
    nonce: string;
    root_post_id: string;
    signer_pubkey: string;
    quote_post_id: string;
    signature: string;
  }): Promise<boolean> {
    if (!this.api) return false;
    const idx = this.pendingQuoteRefs.findIndex((p) => p.nonce === signed.nonce);
    if (idx === -1) {
      console.warn("[thread] SignedQuoteRef with no matching pending ref", signed.nonce);
      return false;
    }
    this.pendingQuoteRefs.splice(idx, 1);
    const key = this.threadKeyFor(signed.root_post_id);
    if (!key) return false;

    const record: QuoteRefRecord = {
      signer_pubkey: signed.signer_pubkey,
      quote_post_id: signed.quote_post_id,
      signature: signed.signature,
    };
    try {
      const deltaBytes = new TextEncoder().encode(
        JSON.stringify({ Quotes: [record] }),
      );
      const update = new UpdateData(
        UpdateDataType.DeltaUpdate,
        new DeltaUpdate(Array.from(deltaBytes)),
      );
      await this.api.update(new UpdateRequest(key, update));
      this.refreshLikesNow(signed.root_post_id);
      return true;
    } catch (e) {
      console.error("[thread] failed to send quote ref:", e);
      this.refreshLikesNow(signed.root_post_id);
      return false;
    }
  }

  /** Drop a pending quote-ref by nonce (delegate Error). */
  dropPendingQuoteRef(nonce: string): boolean {
    const idx = this.pendingQuoteRefs.findIndex((p) => p.nonce === nonce);
    if (idx === -1) return false;
    this.pendingQuoteRefs.splice(idx, 1);
    return true;
  }

  /**
   * Reply to a post. Derives/instantiates the root post's thread shard, then
   * asks the delegate to sign a reply Post (via `SignReply`); the matching
   * `SignedReply` response is routed to {@link completeReply}, which folds the signed
   * post into the thread shard via `ThreadDelta::Replies`. Returns false if it
   * cannot proceed (no shard / delegate). A reply is structurally a Post with
   * `reply_to` set — there is no separate record type (see backend facts, #12).
   */
  async replyPost(rootPostId: string, content: string): Promise<boolean> {
    if (!this.api || !this.currentUser) return false;
    const key = this.threadKeyFor(rootPostId);
    if (!key) {
      console.warn("[thread] no thread-shard code hash — cannot reply");
      return false;
    }
    try {
      await this.ensureThreadShard(key, rootPostId);
      this.subscribeThread(key);
    } catch (e) {
      console.error("[thread] ensure/subscribe failed:", e);
      return false;
    }
    const nonce = crypto.randomUUID();
    const timestamp = Date.now();
    this.pendingReplies.push({
      nonce,
      rootPostId,
      author_name: this.currentUser.name,
      author_handle: this.currentUser.handle,
      content,
      timestamp,
    });
    const requested = signReply(
      nonce,
      content,
      this.currentUser.name,
      this.currentUser.handle,
      timestamp,
      rootPostId,
    );
    if (!requested) {
      this.pendingReplies.pop();
      console.warn("[thread] cannot reply: delegate not connected to sign");
      return false;
    }
    return true;
  }

  /**
   * Complete a reply once the delegate returns a `Signed` response for a
   * `SignReply` request. Mirrors {@link completeLike}: matches the pending entry
   * by nonce, assembles the signed ContractPost (reply_to populated), and sends
   * a `ThreadDelta::Replies` UpdateRequest to the root post's thread shard.
   */
  async completeReply(signed: {
    nonce: string;
    post_id: string;
    signature: string;
    public_key: string;
  }): Promise<boolean> {
    if (!this.api) return false;
    const idx = this.pendingReplies.findIndex((p) => p.nonce === signed.nonce);
    if (idx === -1) {
      console.warn("[thread] Signed (reply) with no matching pending reply", signed.nonce);
      return false;
    }
    const [pending] = this.pendingReplies.splice(idx, 1);
    const key = this.threadKeyFor(pending.rootPostId);
    if (!key) return false;

    const post: ContractPost = {
      id: signed.post_id,
      author_pubkey: signed.public_key,
      author_name: pending.author_name,
      author_handle: pending.author_handle,
      content: pending.content,
      timestamp: pending.timestamp,
      reply_to: pending.rootPostId,
      signature: signed.signature,
    };
    try {
      const deltaBytes = new TextEncoder().encode(
        JSON.stringify({ Replies: [post] }),
      );
      const update = new UpdateData(
        UpdateDataType.DeltaUpdate,
        new DeltaUpdate(Array.from(deltaBytes)),
      );
      await this.api.update(new UpdateRequest(key, update));
      // Refresh to pick up the updated reply count.
      this.refreshLikesNow(pending.rootPostId);
      return true;
    } catch (e) {
      console.error("[thread] failed to send reply:", e);
      this.refreshLikesNow(pending.rootPostId);
      return false;
    }
  }

  /**
   * Load the reply list for a thread. Called when the user opens a thread view
   * so the reply list is populated even on a fresh page load (before any
   * engagement action has been taken). Derives and registers the thread key,
   * instantiates the shard if absent, subscribes for live deltas, then issues a
   * GET so {@link handleGetResponse} fires {@link FreenetCallbacks.onRepliesUpdated}.
   * Fire-and-forget: mirrors the {@link loadUserShard} / {@link loadGlobalIndex}
   * pattern. A spurious re-PUT over an already-instantiated shard is a harmless
   * CRDT merge (see the comment at ensureThreadShard line 663–665).
   */
  loadThreadReplies(rootPostId: string): void {
    const key = this.threadKeyFor(rootPostId);
    if (!key) {
      console.warn("[thread] no thread-shard code hash — cannot load replies");
      return;
    }
    this.ensureThreadShard(key, rootPostId)
      .then(() => {
        this.subscribeThread(key);
        this.refreshLikesNow(rootPostId);
      })
      .catch((e) => console.error("[thread] loadThreadReplies failed:", e));
  }

  /**
   * Drop a pending reply by nonce (delegate returned an Error for it). Returns
   * true if a pending reply was actually dropped. Mirror of {@link dropPendingLike}.
   */
  dropPendingReply(nonce: string): boolean {
    const idx = this.pendingReplies.findIndex((p) => p.nonce === nonce);
    if (idx === -1) return false;
    this.pendingReplies.splice(idx, 1);
    return true;
  }

  /**
   * Reduce a thread shard's `quotes` map to a quote-repost count for the UI.
   * Quotes are a grow-set (one entry per quoting post), so the count is the map
   * size — no per-signer dedup or tombstones.
   */
  private emitQuoteState(
    rootPostId: string,
    quotes: Record<string, QuoteRefRecord>,
  ): void {
    const count = Object.keys(quotes).length;
    this.callbacks.onQuoteUpdated?.({ postId: rootPostId, count });
  }

  /**
   * Drop a specific pending post draft by nonce. Called when the delegate
   * returns an Error carrying the originating nonce (a SignPost that failed),
   * so only the stranded draft is removed — unrelated errors (GetIdentity,
   * Export, …) carry no nonce and leave the queue untouched.
   */
  dropPendingPost(nonce: string): void {
    const idx = this.pendingPosts.findIndex((d) => d.nonce === nonce);
    if (idx !== -1) this.pendingPosts.splice(idx, 1);
  }

  /**
   * Expose the underlying FreenetWsApi so delegate-api.ts can access it.
   * Returns null when not yet connected.
   */
  get wsApi(): FreenetWsApi | null {
    return this.api;
  }

  get isConnected(): boolean {
    return this.api !== null;
  }
}
