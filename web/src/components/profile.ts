/**
 * profile.ts — User profile page component
 */

import { Post, User } from "../types";
import { createPostCard } from "./post-card";

function getInitials(displayName: string): string {
  return displayName
    .split(" ")
    .slice(0, 2)
    .map((word) => word[0])
    .join("")
    .toUpperCase();
}

function truncateKey(key: string): string {
  if (key.length <= 20) return key;
  return `${key.slice(0, 8)}…${key.slice(-8)}`;
}

export function createProfile(user: User, posts: Post[]): HTMLElement {
  injectStyles();

  const profile = document.createElement("main");
  profile.className = "profile-page";

  // ---- Header ----
  const header = document.createElement("div");
  header.className = "profile-header";

  const headerTitle = document.createElement("div");
  headerTitle.className = "profile-header__title";
  headerTitle.textContent = "Profile";

  header.appendChild(headerTitle);

  // ---- Hero ----
  const hero = document.createElement("div");
  hero.className = "profile-hero";

  const avatar = document.createElement("div");
  avatar.className = "profile-avatar";
  avatar.textContent = getInitials(user.displayName);
  if (user.avatarColor) {
    avatar.style.background = user.avatarColor;
  }

  const info = document.createElement("div");
  info.className = "profile-info";

  const displayNameEl = document.createElement("div");
  displayNameEl.className = "profile-info__name";
  displayNameEl.textContent = user.displayName;

  const handleEl = document.createElement("div");
  handleEl.className = "profile-info__handle";
  handleEl.textContent = `@${user.handle}`;

  info.appendChild(displayNameEl);
  info.appendChild(handleEl);

  if (user.publicKey) {
    const keyStrip = document.createElement("div");
    keyStrip.className = "profile-info__keystrip";
    keyStrip.title = user.publicKey;
    keyStrip.innerHTML = `
      <span class="profile-info__keystrip-label">Public key</span>
      <span class="profile-info__keystrip-value">${truncateKey(user.publicKey)}</span>
      <span class="verified-badge">✓ verified</span>
    `;
    info.appendChild(keyStrip);
  }

  const stats = document.createElement("div");
  stats.className = "profile-stats";

  const postCountEl = document.createElement("span");
  postCountEl.className = "profile-stats__item";
  postCountEl.innerHTML = `<strong>${posts.length}</strong> Posts`;

  stats.appendChild(postCountEl);

  hero.appendChild(avatar);
  hero.appendChild(info);
  hero.appendChild(stats);

  // ---- Posts section ----
  const postsSection = document.createElement("div");
  postsSection.className = "profile-posts";

  const postsSectionTitle = document.createElement("div");
  postsSectionTitle.className = "profile-posts__title";
  postsSectionTitle.textContent = "Your posts";

  postsSection.appendChild(postsSectionTitle);

  if (posts.length === 0) {
    const empty = document.createElement("div");
    empty.className = "profile-posts__empty";
    empty.innerHTML = `
      <span class="profile-posts__empty-glyph">"</span>
      <span class="profile-posts__empty-text">Nothing posted yet</span>
    `;
    postsSection.appendChild(empty);
  } else {
    for (const post of posts) {
      postsSection.appendChild(createPostCard(post));
    }
  }

  profile.appendChild(header);
  profile.appendChild(hero);
  profile.appendChild(postsSection);

  return profile;
}

let stylesInjected = false;

function injectStyles(): void {
  if (stylesInjected) return;
  stylesInjected = true;

  const style = document.createElement("style");
  style.textContent = `
    .profile-page {
      flex: 1;
      min-width: 0;
      min-height: 100vh;
      background: rgba(255, 255, 255, 0.55);
    }

    .profile-header {
      position: sticky;
      top: 0;
      z-index: 10;
      background: rgba(248, 250, 252, 0.96);
      border-bottom: 1px solid var(--line);
      padding: 18px 26px;
    }

    .profile-header__title {
      font-family: var(--font-display);
      font-size: 22px;
      font-weight: 400;
      letter-spacing: -0.04em;
      color: var(--ink-0);
      line-height: 1.15;
    }

    .profile-hero {
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      gap: 14px;
      padding: 26px 26px 22px;
      border-bottom: 1px solid var(--line-2);
    }

    .profile-avatar {
      width: 72px;
      height: 72px;
      border-radius: 50%;
      background: var(--accent-bg);
      border: 1.5px solid var(--accent-mid);
      color: var(--accent);
      font-family: var(--font-display);
      font-style: italic;
      font-weight: 400;
      font-size: 28px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      box-shadow: var(--shadow-sm);
    }

    .profile-info {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .profile-info__name {
      font-family: var(--font-display);
      font-size: 22px;
      font-weight: 400;
      letter-spacing: -0.04em;
      color: var(--ink-0);
      line-height: 1.2;
    }

    .profile-info__handle {
      font-family: var(--font-mono);
      font-size: 10px;
      letter-spacing: 0.02em;
      color: var(--ink-3);
    }

    .profile-info__keystrip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 8px;
      padding: 6px 10px;
      background: rgba(239, 246, 255, 0.8);
      border: 1px solid var(--line);
      border-radius: 8px;
      max-width: 100%;
      flex-wrap: wrap;
    }

    .profile-info__keystrip-label {
      font-family: var(--font-mono);
      font-size: 8px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--ink-4);
    }

    .profile-info__keystrip-value {
      font-family: var(--font-mono);
      font-size: 10px;
      letter-spacing: 0.02em;
      color: var(--ink-2);
      user-select: all;
    }

    .verified-badge {
      font-family: var(--font-mono);
      font-size: 8px;
      color: var(--trust);
      background: var(--trust-bg);
      padding: 2px 8px;
      border-radius: 4px;
      border: 1px solid rgba(51, 153, 102, 0.15);
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }

    .profile-stats {
      display: flex;
      gap: 16px;
      margin-top: 4px;
    }

    .profile-stats__item {
      font-family: var(--font-mono);
      font-size: 10px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--ink-4);
    }

    .profile-stats__item strong {
      color: var(--ink-0);
      font-family: var(--font-display);
      font-style: normal;
      font-weight: 500;
      font-size: 13px;
      letter-spacing: -0.025em;
      margin-right: 4px;
      text-transform: none;
    }

    .profile-posts__title {
      font-family: var(--font-mono);
      font-size: 7.5px;
      font-weight: 400;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--ink-4);
      padding: 16px 26px 8px;
    }

    .profile-posts__empty {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 10px;
      padding: 48px 20px;
    }

    .profile-posts__empty-glyph {
      font-family: var(--font-display);
      font-style: italic;
      font-weight: 300;
      font-size: 60px;
      color: var(--surface-3);
      line-height: 1;
      letter-spacing: -0.05em;
    }

    .profile-posts__empty-text {
      font-family: var(--font-mono);
      font-size: 9.5px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--ink-4);
    }
  `;
  document.head.appendChild(style);
}
