<script lang="ts">
  import type { Post } from "../types";
  import { formatRelativeTime } from "../utils";
  import { openRepostMenu } from "./repost-menu";
  import { follows, identity, follow } from "../stores/freenet";

  interface Props {
    post: Post;
    onLike?: (postId: string, liked: boolean) => void;
    onRepost?: (postId: string, reposted: boolean) => void;
    onQuote?: (post: Post) => void;
    resolveQuoted?: (postId: string) => Post | undefined;
    onOpen?: (post: Post) => void;
    /** When true, the post-text reads at "lead" size — used for the top of feed. */
    lead?: boolean;
  }

  let {
    post,
    onLike,
    onRepost,
    onQuote,
    resolveQuoted,
    onOpen,
    lead = false,
  }: Props = $props();

  // A post can only be followed if it carries its author's verifying key (the
  // shard parameter). Mock/offline posts have none — no key, no follow button.
  const authorKey = $derived(post.author.publicKey ?? "");
  const isSelf = $derived(!!authorKey && authorKey === $identity?.publicKey);
  const canFollow = $derived(!!authorKey && !isSelf && !!$identity?.publicKey);
  const isFollowed = $derived($follows.has(authorKey));

  function getInitials(displayName: string): string {
    return displayName
      .split(" ")
      .slice(0, 2)
      .map((word) => word[0])
      .join("")
      .toUpperCase();
  }

  const ICON_REPLY = `<svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M2 4h14v8a2 2 0 0 1-2 2H6l-4 2V4z"/>
</svg>`;

  const ICON_REPOST = `<svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M1 7l4-4 4 4"/>
  <path d="M5 3v9a2 2 0 0 0 2 2h5"/>
  <path d="M17 11l-4 4-4-4"/>
  <path d="M13 15V6a2 2 0 0 0-2-2H6"/>
</svg>`;

  const ICON_LIKE = `<svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M9 15.5s-7-4.2-7-8.5a4 4 0 0 1 7-2.65A4 4 0 0 1 16 7c0 4.3-7 8.5-7 8.5z"/>
</svg>`;

  const ICON_LIKE_FILLED = `<svg width="18" height="18" viewBox="0 0 18 18" fill="currentColor" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M9 15.5s-7-4.2-7-8.5a4 4 0 0 1 7-2.65A4 4 0 0 1 16 7c0 4.3-7 8.5-7 8.5z"/>
</svg>`;

  const ICON_SHARE = `<svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M4 12v3a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-3"/>
  <polyline points="12 6 9 3 6 6"/>
  <line x1="9" y1="3" x2="9" y2="12"/>
</svg>`;

  // Optimistic local state. Re-seeded from `post` props whenever the parent
  // re-renders with a reconciled post (onLikeUpdated/onRepostUpdated) so the
  // authoritative counts win after reconcile.
  let liked = $state(post.liked ?? false);
  let likeCount = $state(post.likes ?? 0);
  let reposted = $state(post.reposted ?? false);
  let repostCount = $state(post.reposts ?? 0);
  const quoteCount = post.quotes ?? 0;

  $effect(() => {
    liked = post.liked ?? false;
    likeCount = post.likes ?? 0;
    reposted = post.reposted ?? false;
    repostCount = post.reposts ?? 0;
  });

  let quoted = $derived(post.quotedPostId ? resolveQuoted?.(post.quotedPostId) : undefined);
  let repostTotal = $derived(repostCount + quoteCount);

  let repostBtnEl: HTMLButtonElement;

  function onLikeClick() {
    liked = !liked;
    likeCount += liked ? 1 : -1;
    onLike?.(post.id, liked);
  }

  function doPlainRepost() {
    reposted = !reposted;
    repostCount += reposted ? 1 : -1;
    onRepost?.(post.id, reposted);
  }

  function onRepostClick() {
    if (!onQuote) {
      doPlainRepost();
      return;
    }
    openRepostMenu(repostBtnEl, {
      reposted,
      onRepost: doPlainRepost,
      onQuote: () => onQuote?.(post),
    });
  }
</script>

<article class="post" onclick={() => onOpen?.(post)}>
  {#if post.reposted}
    <div class="post__repost-ctx">{@html ICON_REPOST} <span>You reposted</span></div>
  {/if}

  <div class="post__byline">
    <div
      class="post__avatar"
      style={post.author.avatarColor
        ? `background:${post.author.avatarColor};color:#fff;border-color:transparent`
        : ""}
    >
      {getInitials(post.author.displayName)}
    </div>
    <div class="post__who">
      <span class="post__name">{post.author.displayName}</span>
      <span class="post__when">@{post.author.handle}<i>·</i>{formatRelativeTime(post.timestamp)}</span>
    </div>
    {#if canFollow}
      <button
        class="post__follow"
        class:post__follow--on={isFollowed}
        title={isFollowed
          ? "Unfollow — signed by your key, recorded on your own shard"
          : "Follow — signed by your key, recorded on your own shard"}
        onclick={(e) => {
          // The byline sits inside the card's open-thread click target.
          e.stopPropagation();
          follow(authorKey, !isFollowed);
        }}
      >
        {isFollowed ? "Following" : "Follow"}
      </button>
    {/if}
  </div>

  <p class={lead ? "post__text post__text--lead" : "post__text"}>{post.content}</p>

  {#if post.quotedPostId}
    {#if quoted}
      <div class="post__quote-embed">
        <div class="post__quote-embed-head">
          <span class="post__quote-embed-name">{quoted.author.displayName}</span>
          <span class="post__quote-embed-handle">@{quoted.author.handle}</span>
        </div>
        <div class="post__quote-embed-text">{quoted.content}</div>
      </div>
    {:else}
      <div class="post__quote-embed" style="color:var(--ink-3);font-size:13px">
        Quoted post {post.quotedPostId.slice(0, 10)}… (not loaded)
      </div>
    {/if}
  {/if}

  <div class="post__foot" onclick={(e) => e.stopPropagation()}>
    <div class="post__rule"></div>
    <button
      class="post-act post-act--like"
      class:is-active={liked}
      aria-label="Like"
      onclick={onLikeClick}
    >
      {@html liked ? ICON_LIKE_FILLED : ICON_LIKE}<span>{likeCount > 0 ? likeCount : ""}</span>
    </button>
    <button class="post-act post-act--reply" aria-label="Reply" onclick={() => onOpen?.(post)}>
      {@html ICON_REPLY}<span>{(post.replies ?? 0) > 0 ? post.replies : ""}</span>
    </button>
    <button
      class="post-act post-act--repost"
      class:is-active={reposted}
      aria-label="Repost"
      aria-haspopup="menu"
      bind:this={repostBtnEl}
      onclick={onRepostClick}
    >
      {@html ICON_REPOST}<span>{repostTotal > 0 ? repostTotal : ""}</span>
    </button>
    <button class="post-act post-act--share" aria-label="Share">
      {@html ICON_SHARE}
    </button>
  </div>
</article>
