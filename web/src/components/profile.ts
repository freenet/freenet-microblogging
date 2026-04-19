/**
 * profile.ts — User profile page component
 *
 * Displays a user's avatar, display name, handle, public key, post count,
 * and a list of their posts. Uses CSS custom properties from the design system
 * with inline styles. Styles are injected once via a <style> tag.
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

  // ---- Hero section ----
  const hero = document.createElement("div");
  hero.className = "profile-hero";

  // Large avatar (80px circle with initials + color)
  const avatar = document.createElement("div");
  avatar.className = "profile-avatar";
  avatar.textContent = getInitials(user.displayName);
  if (user.avatarColor) {
    avatar.style.background = user.avatarColor;
  }

  // User info block
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

  // Public key (shown only if present)
  if (user.publicKey) {
    const keyEl = document.createElement("div");
    keyEl.className = "profile-info__pubkey";
    keyEl.title = user.publicKey; // full key on hover
    keyEl.textContent = truncateKey(user.publicKey);
    info.appendChild(keyEl);
  }

  // Post count stat
  const stats = document.createElement("div");
  stats.className = "profile-stats";

  const postCountEl = document.createElement("span");
  postCountEl.className = "profile-stats__item";
  postCountEl.innerHTML = `<strong>${posts.length}</strong> Posts`;

  stats.appendChild(postCountEl);

  hero.appendChild(avatar);
  hero.appendChild(info);
  hero.appendChild(stats);

  // ---- Divider ----
  const divider = document.createElement("div");
  divider.className = "profile-divider";

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
    empty.textContent = "No posts yet.";
    postsSection.appendChild(empty);
  } else {
    for (const post of posts) {
      postsSection.appendChild(createPostCard(post));
    }
  }

  profile.appendChild(header);
  profile.appendChild(hero);
  profile.appendChild(divider);
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
      border-right: 1px solid var(--border-strong);
      min-height: 100vh;
      font-family: var(--font-stack, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif);
    }

    .profile-header {
      position: sticky;
      top: 0;
      z-index: 10;
      background: var(--bg-primary);
      border-bottom: 1px solid var(--border-strong);
      padding: 12px 16px;
    }

    .profile-header__title {
      font-size: 18px;
      font-weight: 700;
      color: var(--text-primary);
    }

    .profile-hero {
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      gap: 12px;
      padding: 24px 20px 20px;
    }

    .profile-avatar {
      width: 80px;
      height: 80px;
      border-radius: 50%;
      background: var(--accent, #0066cc);
      color: #ffffff;
      font-size: 28px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      border: 3px solid var(--bg-primary);
      box-shadow: 0 0 0 2px var(--border-strong);
    }

    .profile-info {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .profile-info__name {
      font-size: 20px;
      font-weight: 700;
      color: var(--text-primary);
      line-height: 1.3;
    }

    .profile-info__handle {
      font-size: 15px;
      color: var(--text-muted);
    }

    .profile-info__pubkey {
      font-family: "SF Mono", "Fira Mono", "Cascadia Mono", Consolas, monospace;
      font-size: 11px;
      color: var(--text-muted);
      background: var(--bg-elevated, rgba(0,0,0,0.04));
      border-radius: 4px;
      padding: 2px 6px;
      margin-top: 4px;
      display: inline-block;
      cursor: default;
      user-select: all;
      letter-spacing: 0.03em;
    }

    .profile-stats {
      display: flex;
      gap: 16px;
      margin-top: 4px;
    }

    .profile-stats__item {
      font-size: 14px;
      color: var(--text-muted);
    }

    .profile-stats__item strong {
      color: var(--text-primary);
      font-weight: 600;
      margin-right: 3px;
    }

    .profile-divider {
      height: 1px;
      background: var(--border-strong);
      margin: 0;
    }

    .profile-posts__title {
      font-size: 15px;
      font-weight: 700;
      color: var(--text-primary);
      padding: 14px 20px 10px;
      border-bottom: 1px solid var(--border-strong);
    }

    .profile-posts__empty {
      padding: 32px 20px;
      color: var(--text-muted);
      font-size: 15px;
      text-align: center;
    }
  `;
  document.head.appendChild(style);
}
