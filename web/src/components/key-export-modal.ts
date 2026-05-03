// Modal that displays the exported secret key with copy + warning.
// Wired by app via onIdentityExported(secret => showKeyExportModal(secret)).

export function showKeyExportModal(secretKey: string): void {
  // Avoid duplicates
  document.querySelector(".key-export-overlay")?.remove();

  const overlay = document.createElement("div");
  overlay.className = "key-export-overlay";

  const card = document.createElement("div");
  card.className = "key-export-card";

  const title = document.createElement("div");
  title.className = "key-export-card__title";
  title.textContent = "Your secret key";

  const subtitle = document.createElement("div");
  subtitle.className = "key-export-card__subtitle";
  subtitle.textContent = "Save it · Anyone with this key controls your identity";

  const keyBox = document.createElement("div");
  keyBox.className = "key-export-card__key";
  keyBox.textContent = secretKey;

  const actions = document.createElement("div");
  actions.className = "key-export-card__actions";

  const copyBtn = document.createElement("button");
  copyBtn.className = "btn btn--primary";
  copyBtn.textContent = "Copy";
  copyBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(secretKey);
      copyBtn.textContent = "Copied ✓";
      setTimeout(() => (copyBtn.textContent = "Copy"), 1600);
    } catch {
      // Fallback: select text in keyBox
      const range = document.createRange();
      range.selectNodeContents(keyBox);
      const sel = window.getSelection();
      sel?.removeAllRanges();
      sel?.addRange(range);
    }
  });

  const closeBtn = document.createElement("button");
  closeBtn.className = "btn btn--secondary";
  closeBtn.textContent = "Close";
  closeBtn.addEventListener("click", () => overlay.remove());

  actions.appendChild(copyBtn);
  actions.appendChild(closeBtn);

  card.appendChild(title);
  card.appendChild(subtitle);
  card.appendChild(keyBox);
  card.appendChild(actions);

  overlay.appendChild(card);

  // Click outside or Escape closes
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.remove();
  });
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      overlay.remove();
      document.removeEventListener("keydown", onKey);
    }
  };
  document.addEventListener("keydown", onKey);

  document.body.appendChild(overlay);
}
