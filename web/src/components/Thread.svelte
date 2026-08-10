<script lang="ts">
  import type { Post } from "../types";
  import {
    formatRelativeTime,
    MAX_CONTENT_BYTES,
    contentLength,
  } from "../utils";
  import { identity } from "../stores/freenet";

  const ICON_BACK = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <line x1="20" y1="12" x2="4" y2="12"/>
  <polyline points="10 18 4 12 10 6"/>
</svg>`;

  const ICON_SHIELD = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M12 2l8 4v6c0 5-3.5 9-8 10-4.5-1-8-5-8-10V6l8-4z"/>
</svg>`;

  interface Props {
    root: Post;
    replies: Post[];
    onBack: () => void;
    onReply: (rootPostId: string, content: string) => void;
  }

  let { root, replies, onBack, onReply }: Props = $props();

  let replyText = $state("");

  function getInitials(displayName: string): string {
    return displayName
      .split(" ")
      .slice(0, 2)
      .map((w) => w[0])
      .join("")
      .toUpperCase();
  }

  let keyTrunc = $derived(
    root.author.publicKey
      ? `${root.author.publicKey.slice(0, 6)}…${root.author.publicKey.slice(-4)}`
      : "—",
  );

  let composeInitials = $derived($identity ? getInitials($identity.displayName) : "·");

  // The reply box had no length check at all: an over-long reply was signed by
  // the delegate and then dropped in silence by the thread shard, so it simply
  // vanished. Same UTF-8 byte budget the contract enforces.
  const replyRemaining = $derived(MAX_CONTENT_BYTES - contentLength(replyText));
  const replyTooLong = $derived(replyRemaining < 0);

  function submit() {
    const content = replyText.trim();
    if (!content) return;
    if (contentLength(content) > MAX_CONTENT_BYTES) return;
    onReply(root.id, content);
    replyText = "";
  }

  function onKeydown(e: KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && replyText.trim()) {
      e.preventDefault();
      submit();
    }
  }
</script>

{#snippet avatar(post: Post, size: number, fontSize: number)}
  <div
    class="post__avatar"
    style:width={`${size}px`}
    style:height={`${size}px`}
    style:font-size={`${fontSize}px`}
    style:background={post.author.avatarColor ? post.author.avatarColor : null}
    style:color={post.author.avatarColor ? "#fff" : null}
    style:border-color={post.author.avatarColor ? "transparent" : null}
  >{getInitials(post.author.displayName)}</div>
{/snippet}

<main class="feed-column screen">
  <div class="thread-head">
    <button class="thread-back" aria-label="Back" onclick={onBack}>{@html ICON_BACK}</button>
    <span class="thread-head__title">The Feed · Conversation</span>
  </div>

  <div class="thread-root">
    <div class="kicker">Dispatch · No. 0.1.0</div>
    <p class="thread-root__text">{root.content}</p>
    <div class="thread-root__byline">
      {@render avatar(root, 38, 14)}
      <div class="post__who">
        <span class="post__name">{root.author.displayName}</span>
        <span class="post__when">@{root.author.handle}<i>·</i>{formatRelativeTime(root.timestamp)}</span>
      </div>
    </div>
    <div class="thread-seal">{@html ICON_SHIELD}<span>Signed · root key {keyTrunc} · <b>ML-DSA-65</b></span></div>
  </div>

  <div class="thread-compose">
    <div class="post__avatar" style:width="32px" style:height="32px" style:font-size="13px">{composeInitials}</div>
    <textarea
      class="thread-compose__field"
      placeholder="Add your reply…"
      rows="1"
      bind:value={replyText}
      onkeydown={onKeydown}
    ></textarea>
    {#if replyRemaining <= 40}
      <span
        class="thread-compose__count"
        class:thread-compose__count--over={replyTooLong}
        title="Bytes left — the contract limit is {MAX_CONTENT_BYTES} UTF-8 bytes, so accented characters and emoji cost more than one"
      >{replyRemaining}</span>
    {/if}
    <button
      class="thread-compose__btn"
      disabled={replyText.trim().length === 0 || replyTooLong}
      onclick={submit}>Reply</button
    >
  </div>

  <div class="thread-rhead"><span>Responses · {replies.length}</span></div>

  {#each replies as reply (reply.id)}
    <div class="thread-reply">
      <div class="thread-reply__byline">
        {@render avatar(reply, 32, 13)}
        <div class="post__who">
          <span class="thread-reply__name">{reply.author.displayName}</span>
          <span class="thread-reply__meta">@{reply.author.handle} · {formatRelativeTime(reply.timestamp)}</span>
        </div>
      </div>
      <p class="thread-reply__text">{reply.content}</p>
    </div>
  {/each}

  {#if replies.length === 0}
    <div class="screen-empty">No replies yet — be the first.</div>
  {/if}
</main>
