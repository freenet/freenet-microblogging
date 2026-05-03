import { Post } from "../types";
import { formatRelativeTime } from "../utils";
import { getIdentity } from "../identity";

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

export function createPostCard(post: Post): HTMLElement {
  const article = document.createElement("article");
  article.className = "post-card";

  // Avatar column
  const avatarCol = document.createElement("div");
  avatarCol.className = "post-card__avatar-col";

  const avatar = document.createElement("div");
  avatar.className = "post-card__avatar";
  avatar.textContent = getInitials(post.author.displayName);
  if (post.author.avatarColor) {
    avatar.style.background = post.author.avatarColor;
  }

  avatarCol.appendChild(avatar);

  // Body
  const body = document.createElement("div");
  body.className = "post-card__body";

  // Meta row (name + handle + follow button + timestamp)
  const meta = document.createElement("div");
  meta.className = "post-card__meta";

  const displayName = document.createElement("span");
  displayName.className = "post-card__name";
  displayName.textContent = post.author.displayName;
  // Clicking the author name logs the pubkey (routing will be wired later)
  if (post.author.publicKey) {
    displayName.style.cssText = "cursor:pointer;";
    displayName.addEventListener("click", (e) => {
      e.stopPropagation();
      console.log(`[profile] Navigate to profile: ${post.author.displayName} (${post.author.publicKey})`);
    });
  }

  const handle = document.createElement("span");
  handle.className = "post-card__handle";
  handle.textContent = `@${post.author.handle}`;

  const timestamp = document.createElement("span");
  timestamp.className = "post-card__timestamp";
  timestamp.textContent = formatRelativeTime(post.timestamp);

  meta.appendChild(displayName);
  meta.appendChild(handle);

  // Follow button: show only if author has a publicKey and is not the current user
  const identity = getIdentity();
  const isOwnPost =
    identity && post.author.publicKey
      ? identity.publicKey === post.author.publicKey
      : false;

  // Don't show follow button if author has no publicKey or is the current user
  const showFollowBtn = Boolean(post.author.publicKey) && !isOwnPost;

  if (showFollowBtn) {
    const followBtn = document.createElement("button");
    followBtn.className = "post-card__follow-btn";
    followBtn.textContent = "Follow";
    followBtn.style.cssText = [
      "font-family:var(--font-mono)",
      "font-size:9px",
      "font-weight:400",
      "letter-spacing:0.08em",
      "text-transform:uppercase",
      "color:var(--ink-2)",
      "background:transparent",
      "border:1px solid var(--line)",
      "border-radius:7px",
      "padding:2px 8px",
      "cursor:pointer",
      "margin-left:4px",
      "transition:background 0.12s,color 0.12s,border-color 0.12s",
      "flex-shrink:0",
    ].join(";");
    followBtn.addEventListener("mouseenter", () => {
      followBtn.style.background = "var(--ink-0)";
      followBtn.style.color = "var(--surface-0)";
      followBtn.style.borderColor = "var(--ink-0)";
    });
    followBtn.addEventListener("mouseleave", () => {
      followBtn.style.background = "transparent";
      followBtn.style.color = "var(--ink-2)";
      followBtn.style.borderColor = "var(--line)";
    });
    followBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      // TODO: wire to follows contract
      console.log(`[follows] Follow clicked for ${post.author.handle} (${post.author.publicKey ?? "unknown"})`);
    });
    meta.appendChild(followBtn);
  }

  meta.appendChild(timestamp);

  // Content
  const content = document.createElement("p");
  content.className = "post-card__content";
  content.textContent = post.content;

  // Action bar
  const actions = document.createElement("div");
  actions.className = "post-card__actions";

  // Mutable state (local only for now)
  let liked = post.liked ?? false;
  let likeCount = post.likes ?? 0;
  let reposted = post.reposted ?? false;
  let repostCount = post.reposts ?? 0;
  const replyCount = post.replies ?? 0;

  // Helper to build an action button
  function makeAction(
    modifier: string,
    iconHtml: string,
    count: number
  ): { btn: HTMLButtonElement; countEl: HTMLSpanElement; iconWrap: HTMLSpanElement } {
    const btn = document.createElement("button");
    btn.className = `post-action post-action--${modifier}`;

    const iconWrap = document.createElement("span");
    iconWrap.className = "post-action__icon-wrap";
    iconWrap.innerHTML = iconHtml;

    const countEl = document.createElement("span");
    countEl.className = "post-action__count";
    countEl.textContent = count > 0 ? String(count) : "";

    btn.appendChild(iconWrap);
    btn.appendChild(countEl);

    return { btn, countEl, iconWrap };
  }

  // Reply (no action, visual only)
  const reply = makeAction("reply", ICON_REPLY, replyCount);
  reply.btn.setAttribute("aria-label", "Reply");

  // Repost (local toggle)
  const repostEl = makeAction("repost", ICON_REPOST, repostCount);
  repostEl.btn.setAttribute("aria-label", "Repost");
  if (reposted) repostEl.btn.classList.add("is-active");
  repostEl.btn.addEventListener("click", (e) => {
    e.stopPropagation();
    reposted = !reposted;
    repostCount += reposted ? 1 : -1;
    repostEl.countEl.textContent = repostCount > 0 ? String(repostCount) : "";
    repostEl.btn.classList.toggle("is-active", reposted);
    // TODO: wire to reposts contract
  });

  // Like (local toggle)
  const likeEl = makeAction("like", liked ? ICON_LIKE_FILLED : ICON_LIKE, likeCount);
  likeEl.btn.setAttribute("aria-label", "Like");
  if (liked) likeEl.btn.classList.add("is-active");
  likeEl.btn.addEventListener("click", (e) => {
    e.stopPropagation();
    liked = !liked;
    likeCount += liked ? 1 : -1;
    likeEl.countEl.textContent = likeCount > 0 ? String(likeCount) : "";
    likeEl.btn.classList.toggle("is-active", liked);
    likeEl.iconWrap.innerHTML = liked ? ICON_LIKE_FILLED : ICON_LIKE;
    // TODO: wire to likes contract
  });

  // Share (no action)
  const shareEl = makeAction("share", ICON_SHARE, 0);
  shareEl.btn.setAttribute("aria-label", "Share");

  actions.appendChild(reply.btn);
  actions.appendChild(repostEl.btn);
  actions.appendChild(likeEl.btn);
  actions.appendChild(shareEl.btn);

  body.appendChild(meta);
  body.appendChild(content);
  body.appendChild(actions);

  article.appendChild(avatarCol);
  article.appendChild(body);

  return article;
}
