<script lang="ts">
  import { APP_NAME, APP_LOGO_URL } from "../branding";
  import { toggleTheme } from "../theme";
  import { exportIdentity } from "../identity";
  import { identity } from "../stores/freenet";
  import type { SidebarView } from "./view-types";

  export type { SidebarView };

  interface Props {
    onNavigate: (view: SidebarView) => void;
    onCompose: () => void;
    activeView: SidebarView;
    /** Notification count rendered as a pill on the bell. 0 = hide. */
    notifCount?: number;
  }

  let { onNavigate, onCompose, activeView, notifCount = 0 }: Props = $props();

  // Build version baked at compile time from the git tag (see vite.config.ts).
  // Shown bottom-left so a stale published-contract is visible at a glance.
  const APP_VERSION: string =
    typeof __APP_VERSION__ === "string" ? __APP_VERSION__ : "dev";

  const ICON_HOME = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
  <polyline points="9 22 9 12 15 12 15 22"/>
</svg>`;

  const ICON_EXPLORE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="11" cy="11" r="7"/>
  <line x1="21" y1="21" x2="16.65" y2="16.65"/>
</svg>`;

  const ICON_BELL = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
  <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
</svg>`;

  const ICON_PROFILE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
  <circle cx="12" cy="7" r="4"/>
</svg>`;

  const ICON_SETTINGS = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="3"/>
  <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
</svg>`;

  const ICON_SUN = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="4.5"/>
  <line x1="12" y1="2" x2="12" y2="4"/>
  <line x1="12" y1="20" x2="12" y2="22"/>
  <line x1="4.93" y1="4.93" x2="6.34" y2="6.34"/>
  <line x1="17.66" y1="17.66" x2="19.07" y2="19.07"/>
  <line x1="2" y1="12" x2="4" y2="12"/>
  <line x1="20" y1="12" x2="22" y2="12"/>
  <line x1="4.93" y1="19.07" x2="6.34" y2="17.66"/>
  <line x1="17.66" y1="6.34" x2="19.07" y2="4.93"/>
</svg>`;

  const ICON_MOON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
</svg>`;

  function getInitials(displayName: string): string {
    return displayName
      .split(" ")
      .slice(0, 2)
      .map((w) => w[0])
      .join("")
      .toUpperCase();
  }

  const ICON_ROADMAP = `<svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
  <path d="M3 5h6"/><path d="M3 10h11"/><path d="M3 15h8"/>
  <circle cx="16" cy="5" r="1.6"/><circle cx="17" cy="15" r="1.6"/>
</svg>`;

  type NavSpec = { id: SidebarView; icon: string; label: string; badge?: boolean };
  const items: NavSpec[] = [
    { id: "feed", icon: ICON_HOME, label: "Home" },
    { id: "explore", icon: ICON_EXPLORE, label: "Explore" },
    { id: "notifications", icon: ICON_BELL, label: "Notifications", badge: true },
    { id: "profile", icon: ICON_PROFILE, label: "Profile" },
    { id: "roadmap", icon: ICON_ROADMAP, label: "Roadmap" },
    { id: "settings", icon: ICON_SETTINGS, label: "Settings" },
  ];

  // Theme is not a store; bump a counter on toggle so the derived label/icon recompute.
  let themeBump = $state(0);
  const isDark = $derived.by(() => {
    themeBump;
    return document.documentElement.getAttribute("data-theme") === "dark";
  });

  function onThemeToggle(): void {
    toggleTheme();
    themeBump += 1;
  }

  const keyText = $derived.by(() => {
    const pk = $identity?.publicKey;
    return pk ? `Key ${pk.slice(0, 6)}…${pk.slice(-4)}` : "Anonymous";
  });
</script>

<aside class="sidebar">
  <a
    href="#"
    class="sidebar-logo"
    onclick={(e) => {
      e.preventDefault();
      onNavigate("feed");
    }}
  >
    <img class="sidebar-logo__img" src={APP_LOGO_URL} alt={`${APP_NAME} logo`} draggable="false" />
    <span class="sidebar-logo__text">{APP_NAME}</span>
  </a>

  <button class="sidebar-post-btn" onclick={() => onCompose()}>Compose</button>

  <nav class="sidebar-nav">
    {#each items as spec (spec.id)}
      <button
        class="nav-item"
        class:nav-item--active={activeView === spec.id}
        data-view={spec.id}
        onclick={() => onNavigate(spec.id)}
      >
        <span class="nav-item__icon">{@html spec.icon}</span>
        <span class="nav-item__label">{spec.label}</span>
        {#if spec.badge}
          <span class="nav-item__badge" style:display={notifCount > 0 ? "" : "none"}>
            {notifCount > 0 ? notifCount : ""}
          </span>
        {/if}
      </button>
    {/each}

    <button
      class="nav-item nav-item--theme-toggle"
      aria-label="Toggle theme"
      onclick={onThemeToggle}
    >
      <span class="nav-item__icon">{@html isDark ? ICON_SUN : ICON_MOON}</span>
      <span class="nav-item__label">{isDark ? "Light mode" : "Dark mode"}</span>
    </button>
  </nav>

  {#if $identity}
    <div
      class="sidebar-profile"
      onclick={() => onNavigate("profile")}
      role="button"
      tabindex="0"
    >
      <div class="sidebar-profile__avatar">{getInitials($identity.displayName)}</div>
      <div class="sidebar-profile__info">
        <div class="sidebar-profile__name">{$identity.displayName}</div>
        <div class="sidebar-profile__handle">@{$identity.handle}</div>
        <button
          class="sidebar-profile__export"
          type="button"
          onclick={(e) => {
            e.stopPropagation();
            exportIdentity();
          }}
        >
          Export key
        </button>
      </div>
    </div>
  {/if}

  <div class="sidebar-status">
    <div class="sidebar-section-label">Network</div>
    <div class="sidebar-status__row">
      <span class="live-dot"></span><span>Connected</span>
    </div>
    <div class="sidebar-status__row">
      <span class="live-dot live-dot--static"></span><span>{keyText}</span>
    </div>
    <div class="sidebar-status__row sidebar-status__version" title="Webapp build version">
      <span>{APP_VERSION}</span>
    </div>
  </div>
</aside>
