<script lang="ts">
  import type { Post } from "../types";
  import PostCard from "./PostCard.svelte";
  import { identity } from "../stores/freenet";

  interface Props {
    posts: Post[];
    discoverPosts: Post[];
    onCompose: () => void;
    onOpen?: (post: Post) => void;
    onLike?: (postId: string, liked: boolean) => void;
    onRepost?: (postId: string, reposted: boolean) => void;
    onQuote?: (post: Post) => void;
  }

  let {
    posts,
    discoverPosts,
    onCompose,
    onOpen,
    onLike,
    onRepost,
    onQuote,
  }: Props = $props();

  let activeTab: "following" | "discover" = $state("following");

  function getInitials(displayName: string): string {
    return displayName
      .split(" ")
      .slice(0, 2)
      .map((word) => word[0])
      .join("")
      .toUpperCase();
  }

  const avatarInitials = $derived(
    $identity ? getInitials($identity.displayName) : "·",
  );

  const resolveFollowing = (id: string): Post | undefined =>
    posts.find((p) => p.id === id);
  const resolveDiscover = (id: string): Post | undefined =>
    discoverPosts.find((p) => p.id === id);
</script>

<main class="feed-column screen">
  <!-- ── Masthead ── -->
  <div class="masthead">
    <div class="masthead__row">
      <div>
        <div class="kicker">The Feed</div>
        <div class="masthead__title">Today on Freenet</div>
      </div>
    </div>

    <!-- ── Tabs (Following | Discover) ── -->
    <div class="feed-tabs">
      <button
        class="feed-tab"
        class:feed-tab--on={activeTab === "following"}
        onclick={() => (activeTab = "following")}>Following</button
      >
      <button
        class="feed-tab"
        class:feed-tab--on={activeTab === "discover"}
        onclick={() => (activeTab = "discover")}>Discover</button
      >
    </div>
  </div>

  <!-- ── Quickpost row (opens compose modal) ── -->
  <div
    class="quickpost"
    onclick={() => onCompose()}
    role="button"
    tabindex="0"
    onkeydown={(e) => {
      if (e.key === "Enter" || e.key === " ") onCompose();
    }}
  >
    <div class="post__avatar">{avatarInitials}</div>
    <div class="quickpost__field">Share something with the network…</div>
    <button
      class="quickpost__btn"
      onclick={(e) => {
        e.stopPropagation();
        onCompose();
      }}>Compose</button
    >
  </div>

  <!-- ── Post list ── -->
  <div class="feed__posts">
    {#if activeTab === "discover"}
      {#if discoverPosts.length === 0}
        <div class="following-note">
          <div class="following-note__title">No public posts yet</div>
          <div class="following-note__sub">
            Public posts from across the network will appear here.
          </div>
        </div>
      {:else}
        {#each discoverPosts as post, i (post.id)}
          <PostCard
            {post}
            {onLike}
            {onRepost}
            {onQuote}
            {onOpen}
            resolveQuoted={resolveDiscover}
            lead={i === 0}
          />
        {/each}
      {/if}
    {:else if posts.length === 0}
      <div class="following-note">
        <div class="following-note__title">Nothing here yet</div>
        <div class="following-note__sub">
          Follow people, or compose the first post.
        </div>
      </div>
    {:else}
      {#each posts as post, i (post.id)}
        <PostCard
          {post}
          {onLike}
          {onRepost}
          {onQuote}
          {onOpen}
          resolveQuoted={resolveFollowing}
          lead={i === 0}
        />
      {/each}
    {/if}
  </div>
</main>
