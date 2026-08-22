<script lang="ts">
  import { toggleTheme } from "../theme";
  import { exportIdentity } from "../identity";
  import { identity } from "../stores/freenet";
  import { muted, setMuted } from "../mute";

  function truncateKey(key: string): string {
    if (key.length <= 26) return key;
    return `${key.slice(0, 14)}…${key.slice(-8)}`;
  }

  // Theme / reading-size segmented state. Read the live DOM value at mount and
  // keep a local reactive mirror so the active button highlight tracks clicks
  // (matching the imperative segmented() behavior).
  function currentTheme(): "light" | "dark" {
    return document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
  }
  function currentSize(): "small" | "regular" | "large" {
    const s = document.documentElement.dataset.size;
    return s === "small" || s === "large" ? s : "regular";
  }

  let theme = $state<"light" | "dark">(currentTheme());
  let size = $state<"small" | "regular" | "large">(currentSize());

  // Local toggle states for scaffold rows (visible but not wired to a backend).
  let discoverable = $state(true);
  let showRouting = $state(true);
  let relay = $state(false);
  let notifMentions = $state(true);
  let notifLikes = $state(true);
  let notifReposts = $state(false);
  let notifFollowers = $state(true);

  const themeOptions: { v: "light" | "dark"; label: string }[] = [
    { v: "light", label: "Light" },
    { v: "dark", label: "Dark" },
  ];
  const sizeOptions: { v: "small" | "regular" | "large"; label: string }[] = [
    { v: "small", label: "Small" },
    { v: "regular", label: "Default" },
    { v: "large", label: "Large" },
  ];

  function setTheme(v: "light" | "dark") {
    if (v === theme) return;
    theme = v;
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    if ((v === "dark") !== isDark) toggleTheme();
  }

  function setSize(v: "small" | "regular" | "large") {
    if (v === size) return;
    size = v;
    document.documentElement.dataset.size = v;
  }

  function signOut() {
    if (!confirm("Sign out? Your secret key leaves this device — make sure you've exported it first.")) return;
    window.location.reload();
  }
</script>

{#snippet sectionBlock(title: string, sub: string)}
  <div class="settings-section">
    <div class="settings-section__title">{title}</div>
    <div class="settings-section__sub">{sub}</div>
  </div>
{/snippet}

{#snippet labelMain(label: string, desc: string | null, scaffold: boolean)}
  <div class="settings-row__main">
    <div class="settings-row__label">
      {label}{#if scaffold}<span class="settings-row__scaffold-badge">Coming soon</span>{/if}
    </div>
    {#if desc}<div class="settings-row__desc">{desc}</div>{/if}
  </div>
{/snippet}

{#snippet toggleControl(state: boolean, onchange: (v: boolean) => void, scaffold: boolean)}
  <button
    class="toggle-switch"
    class:on={state}
    aria-pressed={state}
    disabled={scaffold}
    aria-disabled={scaffold ? "true" : undefined}
    tabindex={scaffold ? -1 : undefined}
    onclick={() => onchange(!state)}
  >
    <span class="toggle-switch__knob"></span>
  </button>
{/snippet}

<main class="feed-column screen settings">
  <!-- Masthead -->
  <div class="masthead">
    <div class="masthead__row">
      <div>
        <div class="kicker">Your account · Your keys</div>
        <div class="masthead__title">Settings</div>
      </div>
    </div>
  </div>

  <!-- Account -->
  {@render sectionBlock("Account & identity", "Signed with a post-quantum key, held on your device")}
  <div class="settings-list">
    <div class="settings-row">
      {@render labelMain("Display name", null, false)}
      <span class="settings-row__value">{$identity?.displayName ?? "—"}</span>
    </div>
    <div class="settings-row">
      {@render labelMain("Handle", null, false)}
      <span class="settings-row__value">{$identity ? `@${$identity.handle}` : "—"}</span>
    </div>
    <div class="settings-row is-scaffold">
      {@render labelMain("Discoverable on the network", "Let others find you by handle in Explore", true)}
      {@render toggleControl(discoverable, (v) => (discoverable = v), true)}
    </div>
  </div>

  {#if $identity?.publicKey}
    <div class="settings-keyrow">
      <span class="settings-keyrow__label">ML-DSA-65</span>
      <span class="settings-keyrow__key">{truncateKey($identity.publicKey)}</span>
      <button class="settings-export" onclick={() => exportIdentity()}>Export key</button>
    </div>
  {/if}

  <!-- Appearance -->
  {@render sectionBlock("Appearance", "How Raven reads on your screen")}
  <div class="settings-list">
    <div class="settings-row">
      {@render labelMain("Theme", "Light is the primary theme; dark is a deep-slate variant", false)}
      <div class="segmented">
        {#each themeOptions as opt}
          <button class="segmented__btn" class:on={theme === opt.v} onclick={() => setTheme(opt.v)}>{opt.label}</button>
        {/each}
      </div>
    </div>
    <div class="settings-row">
      {@render labelMain("Reading size", "Body text scale across the feed and threads", false)}
      <div class="segmented">
        {#each sizeOptions as opt}
          <button class="segmented__btn" class:on={size === opt.v} onclick={() => setSize(opt.v)}>{opt.label}</button>
        {/each}
      </div>
    </div>
  </div>

  <!-- Network -->
  {@render sectionBlock("Network", "What the decentralized layer shows you")}
  <div class="settings-list">
    <div class="settings-row is-scaffold">
      {@render labelMain("Show routing & provenance", "Hop trails and signed marks on every post", true)}
      {@render toggleControl(showRouting, (v) => (showRouting = v), true)}
    </div>
    <div class="settings-row is-scaffold">
      {@render labelMain("Relay for the network", "Cache and forward records for nearby peers", true)}
      {@render toggleControl(relay, (v) => (relay = v), true)}
    </div>
  </div>

  <!-- Notifications -->
  {@render sectionBlock("Notifications", "Choose what reaches you")}
  <div class="settings-list">
    <div class="settings-row is-scaffold">
      {@render labelMain("Mentions & replies", null, true)}
      {@render toggleControl(notifMentions, (v) => (notifMentions = v), true)}
    </div>
    <div class="settings-row is-scaffold">
      {@render labelMain("Likes", null, true)}
      {@render toggleControl(notifLikes, (v) => (notifLikes = v), true)}
    </div>
    <div class="settings-row is-scaffold">
      {@render labelMain("Reposts", null, true)}
      {@render toggleControl(notifReposts, (v) => (notifReposts = v), true)}
    </div>
    <div class="settings-row is-scaffold">
      {@render labelMain("New followers", null, true)}
      {@render toggleControl(notifFollowers, (v) => (notifFollowers = v), true)}
    </div>
  </div>

  <!-- Privacy -->
  {@render sectionBlock("Muted accounts", "Hidden from your feeds. Local to this browser — nothing is deleted from the network, and nobody is told.")}
  <div class="settings-list">
    {#if $muted.size === 0}
      <div class="settings-row">
        {@render labelMain("Nobody muted", "Mute an author from any post to stop seeing them here.", false)}
      </div>
    {:else}
      {#each [...$muted] as key (key)}
        <div class="settings-row">
          {@render labelMain(truncateKey(key), "Muted by verifying key, not by handle — handles are self-declared and can be copied.", false)}
          <button class="settings-export" onclick={() => setMuted(key, false)}>Unmute</button>
        </div>
      {/each}
    {/if}
  </div>

  {@render sectionBlock("Privacy & data", "You own it. The network only caches it.")}
  <div class="settings-list">
    <div class="settings-row">
      {@render labelMain("Export your identity key", "Back up your secret key to restore on another device", false)}
      <button class="settings-export" onclick={() => exportIdentity()}>Export key</button>
    </div>
    <div class="settings-row">
      {@render labelMain("Sign out", "Your posts stay on the network; your key leaves this device", false)}
      <button class="settings-danger" onclick={signOut}>Sign out</button>
    </div>
  </div>
</main>
