export function createRightPanel(): HTMLElement {
  const panel = document.createElement("div");
  panel.className = "right-panel";

  // Search box — sticky at top
  const searchBox = document.createElement("div");
  searchBox.className = "search-box";

  const searchInput = document.createElement("input");
  searchInput.type = "search";
  searchInput.className = "search-box__input";
  searchInput.placeholder = "Search Raven";
  searchInput.setAttribute("aria-label", "Search");

  const searchIcon = document.createElement("span");
  searchIcon.className = "search-box__icon";
  searchIcon.textContent = "⌕";

  searchBox.appendChild(searchInput);
  searchBox.appendChild(searchIcon);

  // About Freenet — editorial card
  const card = document.createElement("div");
  card.className = "panel-card";

  const cardHeader = document.createElement("div");
  cardHeader.className = "panel-card__header";

  const cardTitle = document.createElement("div");
  cardTitle.className = "panel-card__title";
  cardTitle.textContent = "About Freenet";

  const cardSubtitle = document.createElement("div");
  cardSubtitle.className = "panel-card__subtitle";
  cardSubtitle.textContent = "Decentralized · P2P";

  cardHeader.appendChild(cardTitle);
  cardHeader.appendChild(cardSubtitle);

  const cardBody = document.createElement("div");
  cardBody.style.cssText = "padding:14px 16px 16px;display:flex;flex-direction:column;gap:12px;";

  const description = document.createElement("p");
  description.style.cssText = [
    "font-family:var(--font-body)",
    "font-size:13px",
    "color:var(--ink-2)",
    "line-height:1.6",
    "letter-spacing:-0.005em",
  ].join(";");
  description.textContent =
    "A decentralized social network. Your data, your keys, your control. No servers, no trackers.";

  const link = document.createElement("a");
  link.href = "https://freenet.org";
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = "freenet.org →";
  link.style.cssText = [
    "font-family:var(--font-mono)",
    "font-size:9.5px",
    "letter-spacing:0.1em",
    "text-transform:uppercase",
    "color:var(--accent)",
    "text-decoration:none",
    "transition:color 0.12s",
  ].join(";");
  link.addEventListener("mouseenter", () => {
    link.style.color = "var(--ink-0)";
  });
  link.addEventListener("mouseleave", () => {
    link.style.color = "var(--accent)";
  });

  cardBody.appendChild(description);
  cardBody.appendChild(link);

  card.appendChild(cardHeader);
  card.appendChild(cardBody);

  // Network info strip
  const strip = document.createElement("div");
  strip.className = "info-strip";
  strip.innerHTML = `
    <span class="info-strip__label">Network</span>
    <span class="info-strip__content">P2P · encrypted</span>
    <span class="info-strip__badge">✓ live</span>
  `;

  panel.appendChild(searchBox);
  panel.appendChild(strip);
  panel.appendChild(card);

  return panel;
}
