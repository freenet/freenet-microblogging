<script lang="ts">
  /**
   * App.svelte — replaces app.ts createApp() orchestration AND the index.ts
   * onboarding/splash/landing routing. Top-level component mounted by main.ts.
   *
   * Global SCSS (styles.scss) is imported in main.ts, NOT here, so this file
   * stays pure. Every class referenced below is a GLOBAL SCSS class — do NOT
   * use scoped <style>.
   */
  import { APP_NAME, APP_LOGO_URL } from "./branding";
  import {
    status,
    appRendered,
    showOnboarding,
    identity,
    posts,
    globalPosts,
    followingPosts,
    threadReplies,
    keyExportSecret,
    publish,
    like,
    repost,
    quote,
    reply,
    loadThreadReplies,
    completeOnboarding,
  } from "./stores/freenet";
  import type { Post } from "./types";
  import type { SidebarView } from "./components/view-types";

  // Child components (created in the next phase at these target paths).
  import Sidebar from "./components/Sidebar.svelte";
  import RightPanel from "./components/RightPanel.svelte";
  import { muted, filterMuted } from "./mute";
  import Feed from "./components/Feed.svelte";
  import Explore from "./components/Explore.svelte";
  import Notifications from "./components/Notifications.svelte";
  import Profile from "./components/Profile.svelte";
  import Roadmap from "./components/Roadmap.svelte";
  import Settings from "./components/Settings.svelte";
  import Thread from "./components/Thread.svelte";
  import ComposeModal from "./components/ComposeModal.svelte";
  import OnboardingOverlay from "./components/OnboardingOverlay.svelte";
  import LandingFeed from "./components/LandingFeed.svelte";
  import KeyExportModal from "./components/KeyExportModal.svelte";

  // ---- Local view state (runes) ----
  let currentView = $state<SidebarView>("feed");
  // When set, thread view replaces the routed view (element-type contract is
  // still `main.feed-column` inside Thread).
  let threadRoot = $state<Post | null>(null);
  // Compose modal control (was app.ts openCompose / openComposeModal).
  let composeState = $state<{ open: boolean; quoted?: Post }>({ open: false });

  // The Following feed: the owner's own posts plus every followed user's,
  // newest first. Own posts are included because a feed that hides your own
  // writing reads as broken — and because a fresh account follows nobody, so
  // the tab would otherwise be permanently empty.
  const followingFeed = $derived(
    filterMuted(
      [...$posts, ...$followingPosts].sort(
        (a, b) => b.timestamp.getTime() - a.timestamp.getTime(),
      ),
      $muted,
    ),
  );

  // Discover is the widest surface — an unfollowed stranger reaches you here
  // first, so it is where muting matters most.
  const discoverFeed = $derived(filterMuted($globalPosts, $muted));

  // Thread replies: sourced from the thread-shard replies store (keyed by root
  // post id), which is populated by onRepliesUpdated whenever the thread shard
  // is read (on like/repost/subscribe). NOT the feed posts list — replies live
  // in the thread shard, not in the owner's user shard.
  let currentThreadReplies = $derived(
    threadRoot ? ($threadReplies.get(threadRoot.id) ?? []) : [],
  );

  // My posts for the profile view (app.ts navigate "profile" logic).
  let myPosts = $derived(
    $identity
      ? $posts.filter(
          (p) => p.author.publicKey && p.author.publicKey === $identity!.publicKey,
        )
      : [],
  );

  // ---- Navigation (mirrors app.ts navigate, including the profile guard) ----
  function navigate(view: SidebarView): void {
    threadRoot = null;
    // app.ts navigate falls back to feed when "profile" is requested without an
    // identity. Apply the same guard up front.
    if (view === "profile" && !$identity) {
      currentView = "feed";
      return;
    }
    currentView = view;
  }

  function openThread(post: Post): void {
    threadRoot = post;
    // Eagerly fetch the thread shard so replies are visible on first open
    // (before any engagement action has been taken on this session).
    loadThreadReplies(post.id);
  }

  function onThreadReply(rootPostId: string, content: string): void {
    reply(rootPostId, content);
  }

  // ---- Compose ----
  function openCompose(quoted?: Post): void {
    composeState = { open: true, quoted };
  }

  function onComposeSubmit(content: string, shareToGlobal: boolean): void {
    const quoted = composeState.quoted;
    composeState = { open: false };
    if (quoted) {
      // Quote modal does not offer the share toggle; ignore shareToGlobal.
      quote(quoted.id, content);
    } else {
      publish(content, shareToGlobal);
    }
  }
</script>

{#if !$appRendered && $status === "connecting"}
  <!-- SPLASH (was index.ts showSplash; inline styles kept verbatim) -->
  <div class="splash-screen" style="display:flex;align-items:center;justify-content:center;height:100vh;">
    <div style="text-align:center;display:flex;flex-direction:column;align-items:center;gap:16px">
      <img
        src={APP_LOGO_URL}
        alt="{APP_NAME} logo"
        draggable="false"
        style="width:72px;height:72px;object-fit:contain;user-select:none"
      />
      <div style="display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.14em;text-transform:uppercase;color:var(--ink-3)">
        <span class="live-dot"></span>
        <span>Connecting to Freenet</span>
      </div>
    </div>
  </div>
{:else if !$appRendered && $showOnboarding}
  <!-- ONBOARDING + read-only LANDING feed mounted simultaneously -->
  <LandingFeed posts={$globalPosts} />
  <OnboardingOverlay
    onComplete={(name, secret) => completeOnboarding(name, secret)}
  />
{:else if $appRendered}
  <!-- APP SHELL (was createApp) -->
  <div class="app-layout">
    <Sidebar
      activeView={currentView}
      onNavigate={(view) => navigate(view)}
      onCompose={() => openCompose()}
    />
    <div class="app-layout__main">
      {#if threadRoot}
        <Thread
          root={threadRoot}
          replies={currentThreadReplies}
          onBack={() => (threadRoot = null)}
          onReply={onThreadReply}
        />
      {:else if currentView === "feed"}
        <Feed
          posts={followingFeed}
          discoverPosts={discoverFeed}
          onCompose={() => openCompose()}
          onOpen={(post) => openThread(post)}
          onLike={(postId, liked) => like(postId, liked)}
          onRepost={(postId, reposted) => repost(postId, reposted)}
          onQuote={(post) => openCompose(post)}
        />
      {:else if currentView === "explore"}
        <Explore />
      {:else if currentView === "notifications"}
        <Notifications />
      {:else if currentView === "profile"}
        <Profile
          user={{
            displayName: $identity!.displayName,
            handle: $identity!.handle,
            publicKey: $identity!.publicKey,
          }}
          posts={myPosts}
          onLike={(postId, liked) => like(postId, liked)}
          onRepost={(postId, reposted) => repost(postId, reposted)}
          onQuote={(post) => openCompose(post)}
          onOpen={(post) => openThread(post)}
          onSettings={() => navigate("settings")}
        />
      {:else if currentView === "roadmap"}
        <Roadmap />
      {:else if currentView === "settings"}
        <Settings />
      {/if}
    </div>
    <div class="right-panel-col">
      <RightPanel onNavigate={(view) => navigate(view)} />
    </div>
  </div>
{/if}

<!-- Compose modal (was app.ts openCompose -> body-appended modal) -->
{#if composeState.open}
  <ComposeModal
    open={composeState.open}
    quoted={composeState.quoted}
    onSubmit={(content, shareToGlobal) => onComposeSubmit(content, shareToGlobal)}
    onClose={() => (composeState = { open: false })}
  />
{/if}

<!-- Key export modal (was index.ts showKeyExportModal). Visible iff non-null. -->
{#if $keyExportSecret != null}
  <KeyExportModal
    secret={$keyExportSecret}
    onClose={() => keyExportSecret.set(null)}
  />
{/if}
