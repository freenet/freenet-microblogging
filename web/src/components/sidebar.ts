import { APP_NAME } from "../branding";
import { toggleTheme } from "../theme";
import { getIdentity } from "../identity";

export type SidebarView = "feed" | "profile";

export interface SidebarCallbacks {
  onNavigate: (view: SidebarView) => void;
}

const ICON_SUN = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="5"/>
  <line x1="12" y1="1" x2="12" y2="3"/>
  <line x1="12" y1="21" x2="12" y2="23"/>
  <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
  <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
  <line x1="1" y1="12" x2="3" y2="12"/>
  <line x1="21" y1="12" x2="23" y2="12"/>
  <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
  <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
</svg>`;

const ICON_MOON = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
</svg>`;

const ICON_HOME = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
  <polyline points="9 22 9 12 15 12 15 22"/>
</svg>`;

const ICON_PROFILE = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
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

  // Logo
  const logo = document.createElement("div");
  logo.className = "sidebar-logo";

  const logoCircle = document.createElement("div");
  logoCircle.className = "sidebar-logo__icon";

  const logoText = document.createElement("span");
  logoText.className = "sidebar-logo__text";
  logoText.textContent = APP_NAME.toLowerCase();

  logo.appendChild(logoCircle);
  logo.appendChild(logoText);

  // Nav — Home + Profile
  const nav = document.createElement("nav");
  nav.className = "sidebar-nav";

  // Helper to create nav items
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
  homeItem.addEventListener("click", (e) => {
    e.preventDefault();
    homeItem.classList.add("nav-item--active");
    profileItem.classList.remove("nav-item--active");
    callbacks?.onNavigate("feed");
  });

  const profileItem = makeNavItem(ICON_PROFILE, "Profile");
  profileItem.addEventListener("click", (e) => {
    e.preventDefault();
    profileItem.classList.add("nav-item--active");
    homeItem.classList.remove("nav-item--active");
    callbacks?.onNavigate("profile");
  });

  nav.appendChild(homeItem);
  nav.appendChild(profileItem);

  // Theme toggle
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

  // Profile section (shown if identity exists)
  const identity = getIdentity();
  let profileSection: HTMLElement | null = null;

  if (identity) {
    profileSection = document.createElement("div");
    profileSection.className = "sidebar-profile";

    const profileAvatar = document.createElement("div");
    profileAvatar.className = "sidebar-profile__avatar";
    // Display initials inside the avatar circle
    profileAvatar.style.cssText = [
      "display:flex",
      "align-items:center",
      "justify-content:center",
      "color:#ffffff",
      "font-size:14px",
      "font-weight:700",
      "background:var(--accent)",
    ].join(";");
    profileAvatar.textContent = getInitials(identity.displayName);

    const profileInfo = document.createElement("div");
    profileInfo.className = "sidebar-profile__info";

    const profileName = document.createElement("div");
    profileName.className = "sidebar-profile__name";
    profileName.textContent = identity.displayName;

    const profileHandle = document.createElement("div");
    profileHandle.className = "sidebar-profile__handle";
    profileHandle.textContent = `@${identity.handle}`;

    profileInfo.appendChild(profileName);
    profileInfo.appendChild(profileHandle);

    profileSection.appendChild(profileAvatar);
    profileSection.appendChild(profileInfo);
  }

  // Post CTA
  const postBtn = document.createElement("button");
  postBtn.className = "sidebar-post-btn";
  postBtn.textContent = "Post";

  sidebar.appendChild(logo);
  sidebar.appendChild(nav);
  sidebar.appendChild(themeToggle);
  if (profileSection) {
    sidebar.appendChild(profileSection);
  }
  sidebar.appendChild(postBtn);

  return sidebar;
}
