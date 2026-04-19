const BOTTOM_NAV_ITEMS = [
  {
    label: "Home",
    active: true,
    icon: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
      <polyline points="9 22 9 12 15 12 15 22"/>
    </svg>`,
  },
  {
    label: "Search",
    active: false,
    icon: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="11" cy="11" r="8"/>
      <line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>`,
  },
  {
    label: "Notifications",
    active: false,
    icon: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
      <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
    </svg>`,
  },
  {
    label: "Profile",
    active: false,
    icon: `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
      <circle cx="12" cy="7" r="4"/>
    </svg>`,
  },
];

export function createBottomNav(): HTMLElement {
  const nav = document.createElement("nav");
  nav.className = "bottom-nav";

  for (const item of BOTTOM_NAV_ITEMS) {
    const navItem = document.createElement("button");
    navItem.className = item.active
      ? "bottom-nav__item bottom-nav__item--active"
      : "bottom-nav__item";
    navItem.setAttribute("aria-label", item.label);
    navItem.innerHTML = item.icon;

    navItem.addEventListener("click", () => {
      const allItems = nav.querySelectorAll(".bottom-nav__item");
      allItems.forEach((el) => el.classList.remove("bottom-nav__item--active"));
      navItem.classList.add("bottom-nav__item--active");
    });

    nav.appendChild(navItem);
  }

  return nav;
}
