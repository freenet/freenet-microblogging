import { APP_NAME, APP_LOGO_URL } from "../branding";
import { toggleTheme } from "../theme";
import { getIdentity, exportIdentity } from "../identity";

export type SidebarView = "feed" | "profile";

export interface SidebarCallbacks {
  onNavigate: (view: SidebarView) => void;
}

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

const ICON_HOME = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
  <polyline points="9 22 9 12 15 12 15 22"/>
</svg>`;

const ICON_PROFILE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
  <circle cx="12" cy="7" r="4"/>
</svg>`;

function getInitials(displayName: string): string {
  return displayName
    .split(" ")
    .slice(0, 2)
    .map((word) => word[0])
    .join("")
    .toUpperCase();
}

export function createSidebar(callbacks?: SidebarCallbacks): HTMLElement {
  const sidebar = document.createElement("aside");
  sidebar.className = "sidebar";

  // ── Wordmark ──
  const logo = document.createElement("a");
  logo.href = "#";
  logo.className = "sidebar-logo";

  const logoImg = document.createElement("img");
  logoImg.className = "sidebar-logo__img";
  logoImg.src = APP_LOGO_URL;
  logoImg.alt = `${APP_NAME} logo`;
  logoImg.draggable = false;

  const logoText = document.createElement("span");
  logoText.className = "sidebar-logo__text";
  logoText.textContent = APP_NAME;

  logo.appendChild(logoImg);
  logo.appendChild(logoText);

  // ── Primary CTA — focuses the compose textarea ──
  const postBtn = document.createElement("button");
  postBtn.className = "sidebar-post-btn";
  postBtn.textContent = "Compose";
  postBtn.addEventListener("click", () => {
    const textarea = document.querySelector<HTMLTextAreaElement>(
      ".compose-box__textarea"
    );
    if (!textarea) return;
    textarea.scrollIntoView({ behavior: "smooth", block: "start" });
    textarea.focus({ preventScroll: true });
  });

  // ── Nav ──
  const nav = document.createElement("nav");
  nav.className = "sidebar-nav";

  function makeNavItem(iconHtml: string, label: string): HTMLAnchorElement {
    const item = document.createElement("a");
    item.href = "#";
    item.className = "nav-item";

    const iconWrap = document.createElement("span");
    iconWrap.className = "nav-item__icon";
    iconWrap.innerHTML = iconHtml;

    const labelEl = document.createElement("span");
    labelEl.className = "nav-item__label";
    labelEl.textContent = label;

    item.appendChild(iconWrap);
    item.appendChild(labelEl);
    return item;
  }

  const homeItem = makeNavItem(ICON_HOME, "Home");
  homeItem.classList.add("nav-item--active");

  const profileItem = makeNavItem(ICON_PROFILE, "Profile");

  homeItem.addEventListener("click", (e) => {
    e.preventDefault();
    homeItem.classList.add("nav-item--active");
    profileItem.classList.remove("nav-item--active");
    callbacks?.onNavigate("feed");
  });
  profileItem.addEventListener("click", (e) => {
    e.preventDefault();
    profileItem.classList.add("nav-item--active");
    homeItem.classList.remove("nav-item--active");
    callbacks?.onNavigate("profile");
  });

  nav.appendChild(homeItem);
  nav.appendChild(profileItem);

  // ── Theme toggle (rendered as ghost nav item) ──
  const themeToggle = document.createElement("button");
  themeToggle.className = "nav-item nav-item--theme-toggle";
  themeToggle.setAttribute("aria-label", "Toggle theme");

  const themeIconWrapper = document.createElement("span");
  themeIconWrapper.className = "nav-item__icon";

  const themeLabelSpan = document.createElement("span");
  themeLabelSpan.className = "nav-item__label";

  function updateThemeToggle(): void {
    const current = document.documentElement.getAttribute("data-theme");
    const isDark = current === "dark";
    themeIconWrapper.innerHTML = isDark ? ICON_SUN : ICON_MOON;
    themeLabelSpan.textContent = isDark ? "Light mode" : "Dark mode";
  }
  updateThemeToggle();

  themeToggle.appendChild(themeIconWrapper);
  themeToggle.appendChild(themeLabelSpan);
  themeToggle.addEventListener("click", () => {
    toggleTheme();
    updateThemeToggle();
  });

  nav.appendChild(themeToggle);

  // ── Profile pod (if identity) ──
  const identity = getIdentity();
  let profileSection: HTMLElement | null = null;

  if (identity) {
    profileSection = document.createElement("div");
    profileSection.className = "sidebar-profile";

    const profileAvatar = document.createElement("div");
    profileAvatar.className = "sidebar-profile__avatar";
    profileAvatar.textContent = getInitials(identity.displayName);

    const profileInfo = document.createElement("div");
    profileInfo.className = "sidebar-profile__info";

    const profileName = document.createElement("div");
    profileName.className = "sidebar-profile__name";
    profileName.textContent = identity.displayName;

    const profileHandle = document.createElement("div");
    profileHandle.className = "sidebar-profile__handle";
    profileHandle.textContent = `@${identity.handle}`;

    const exportLink = document.createElement("button");
    exportLink.className = "sidebar-profile__export";
    exportLink.type = "button";
    exportLink.textContent = "Export key";
    exportLink.title = "Show your secret key (to import on another node)";
    exportLink.addEventListener("click", (e) => {
      e.stopPropagation();
      exportIdentity();
    });

    profileInfo.appendChild(profileName);
    profileInfo.appendChild(profileHandle);
    profileInfo.appendChild(exportLink);

    profileSection.appendChild(profileAvatar);
    profileSection.appendChild(profileInfo);
  }

  // ── Status / trust panel (ambient network state) ──
  const status = document.createElement("div");
  status.className = "sidebar-status";

  const statusLabel = document.createElement("div");
  statusLabel.className = "sidebar-section-label";
  statusLabel.textContent = "Network";

  const statusRowConn = document.createElement("div");
  statusRowConn.className = "sidebar-status__row";
  statusRowConn.innerHTML = `<span class="live-dot"></span><span>Connected</span>`;

  const statusRowKey = document.createElement("div");
  statusRowKey.className = "sidebar-status__row";
  if (identity?.publicKey) {
    const trunc = `${identity.publicKey.slice(0, 6)}…${identity.publicKey.slice(-4)}`;
    statusRowKey.innerHTML = `<span class="live-dot live-dot--static"></span><span>Key ${trunc}</span>`;
  } else {
    statusRowKey.innerHTML = `<span class="live-dot live-dot--static"></span><span>Anonymous</span>`;
  }

  status.appendChild(statusLabel);
  status.appendChild(statusRowConn);
  status.appendChild(statusRowKey);

  // ── Assemble (CTA up top per design spec) ──
  sidebar.appendChild(logo);
  sidebar.appendChild(postBtn);
  sidebar.appendChild(nav);
  if (profileSection) sidebar.appendChild(profileSection);
  sidebar.appendChild(status);

  return sidebar;
}
