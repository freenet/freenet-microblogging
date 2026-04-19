export function createRightPanel(): HTMLElement {
  const panel = document.createElement("div");
  panel.className = "right-panel";

  // Freenet info card
  const card = document.createElement("div");
  card.className = "panel-card";

  const cardHeader = document.createElement("div");
  cardHeader.className = "panel-card__header";

  const cardTitle = document.createElement("div");
  cardTitle.className = "panel-card__title";
  cardTitle.textContent = "About Freenet";

  cardHeader.appendChild(cardTitle);

  const cardBody = document.createElement("div");
  cardBody.style.cssText = "padding:12px 16px 16px;";

  const description = document.createElement("p");
  description.style.cssText =
    "font-size:15px;color:var(--text-secondary);line-height:1.5;margin-bottom:12px;";
  description.textContent =
    "Decentralized social network. Your data, your control.";

  const link = document.createElement("a");
  link.href = "https://freenet.org";
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = "freenet.org";
  link.style.cssText =
    "font-size:14px;color:var(--accent);text-decoration:none;font-weight:500;";
  link.addEventListener("mouseenter", () => {
    link.style.textDecoration = "underline";
  });
  link.addEventListener("mouseleave", () => {
    link.style.textDecoration = "none";
  });

  cardBody.appendChild(description);
  cardBody.appendChild(link);

  card.appendChild(cardHeader);
  card.appendChild(cardBody);

  panel.appendChild(card);

  return panel;
}
