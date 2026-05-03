/**
 * First-visit onboarding screen.
 * Renders a full-screen overlay asking the user for a display name.
 */

import { APP_NAME, APP_LOGO_URL } from "../branding";

export function createOnboarding(
  onComplete: (displayName: string, secretKey?: string) => void
): HTMLElement {
  injectStyles();

  const overlay = document.createElement("div");
  overlay.className = "onboarding-overlay";

  const card = document.createElement("div");
  card.className = "onboarding-card";

  // App logo
  const logo = document.createElement("img");
  logo.className = "onboarding-logo";
  logo.src = APP_LOGO_URL;
  logo.alt = `${APP_NAME} logo`;
  logo.draggable = false;

  // Tagline above title
  const tagline = document.createElement("div");
  tagline.className = "onboarding-tagline";
  tagline.textContent = "Decentralized Microblog";

  const title = document.createElement("h1");
  title.className = "onboarding-title";
  title.textContent = `Welcome to ${APP_NAME}`;

  const subtitle = document.createElement("p");
  subtitle.className = "onboarding-subtitle";
  subtitle.textContent = "Choose your display name to get started";

  const input = document.createElement("input");
  input.className = "onboarding-input";
  input.type = "text";
  input.placeholder = "Your name";
  input.maxLength = 50;
  input.setAttribute("autocomplete", "off");
  input.setAttribute("spellcheck", "false");

  const button = document.createElement("button");
  button.className = "onboarding-btn";
  button.textContent = "Join";
  button.disabled = true;

  input.addEventListener("input", () => {
    button.disabled = input.value.trim().length === 0;
  });

  const submit = () => {
    const name = input.value.trim();
    if (!name) return;
    overlay.remove();
    onComplete(name);
  };

  button.addEventListener("click", submit);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submit();
  });

  const importLink = document.createElement("button");
  importLink.className = "onboarding-import-link";
  importLink.textContent = "Import existing identity";
  importLink.addEventListener("click", () => {
    importSection.style.display = importSection.style.display === "none" ? "flex" : "none";
    nameSection.style.display = nameSection.style.display === "none" ? "flex" : "none";
  });

  const nameSection = document.createElement("div");
  nameSection.className = "onboarding-section";
  nameSection.appendChild(input);
  nameSection.appendChild(button);

  const importSection = document.createElement("div");
  importSection.className = "onboarding-section";
  importSection.style.display = "none";

  const importInput = document.createElement("input");
  importInput.className = "onboarding-input";
  importInput.type = "text";
  importInput.placeholder = "Your name";
  importInput.maxLength = 50;

  const secretInput = document.createElement("input");
  secretInput.className = "onboarding-input onboarding-input--mono";
  secretInput.type = "password";
  secretInput.placeholder = "Secret key (64 hex characters)";
  secretInput.maxLength = 64;

  const importBtn = document.createElement("button");
  importBtn.className = "onboarding-btn";
  importBtn.textContent = "Import";
  importBtn.disabled = true;

  const checkImportReady = () => {
    importBtn.disabled = importInput.value.trim().length === 0 || secretInput.value.trim().length !== 64;
  };
  importInput.addEventListener("input", checkImportReady);
  secretInput.addEventListener("input", checkImportReady);

  importBtn.addEventListener("click", () => {
    const name = importInput.value.trim();
    const secret = secretInput.value.trim();
    if (!name || secret.length !== 64) return;
    overlay.remove();
    onComplete(name, secret);
  });

  importSection.appendChild(importInput);
  importSection.appendChild(secretInput);
  importSection.appendChild(importBtn);

  card.appendChild(logo);
  card.appendChild(tagline);
  card.appendChild(title);
  card.appendChild(subtitle);
  card.appendChild(nameSection);
  card.appendChild(importLink);
  card.appendChild(importSection);
  overlay.appendChild(card);

  requestAnimationFrame(() => input.focus());

  return overlay;
}

let stylesInjected = false;

function injectStyles(): void {
  if (stylesInjected) return;
  stylesInjected = true;

  const style = document.createElement("style");
  style.textContent = `
    .onboarding-overlay {
      position: fixed;
      inset: 0;
      z-index: 9999;
      background: rgba(15, 23, 42, 0.24);
      display: flex;
      align-items: center;
      justify-content: center;
      animation: veilIn 0.18s ease;
    }
    @keyframes veilIn { from { opacity: 0; } to { opacity: 1; } }

    .onboarding-card {
      background: #ffffff;
      border: 1px solid var(--line);
      border-radius: var(--radius-card-lg, 14px);
      padding: 36px 32px 28px;
      width: 100%;
      max-width: 380px;
      box-shadow: var(--shadow-lg);
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      animation: sheetUp 0.22s cubic-bezier(0.34, 1.28, 0.64, 1) both;
    }

    .onboarding-logo {
      width: 64px;
      height: 64px;
      object-fit: contain;
      user-select: none;
      -webkit-user-drag: none;
      margin-bottom: 4px;
    }

    .onboarding-tagline {
      font-family: var(--font-mono);
      font-size: 8.5px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--ink-4);
      margin-bottom: 4px;
    }

    .onboarding-title {
      margin: 0;
      font-family: var(--font-display);
      font-size: 24px;
      font-weight: 400;
      letter-spacing: -0.04em;
      color: var(--ink-0);
      text-align: center;
      line-height: 1.15;
    }

    .onboarding-subtitle {
      margin: 4px 0 14px;
      font-family: var(--font-body);
      font-size: 13px;
      color: var(--ink-3);
      text-align: center;
      letter-spacing: -0.005em;
    }

    .onboarding-section {
      display: flex;
      flex-direction: column;
      align-items: stretch;
      gap: 10px;
      width: 100%;
    }

    .onboarding-input {
      width: 100%;
      box-sizing: border-box;
      padding: 9px 12px;
      height: 36px;
      font-family: var(--font-body);
      font-size: 13px;
      letter-spacing: -0.005em;
      color: var(--ink-0);
      background: rgba(239, 246, 255, 0.8);
      border: 1px solid var(--line);
      border-radius: var(--radius-input, 8px);
      outline: none;
      transition: border-color 0.18s, background 0.18s;
    }

    .onboarding-input::placeholder { color: var(--ink-4); }

    .onboarding-input--mono {
      font-family: var(--font-mono);
      font-size: 11.5px;
      letter-spacing: 0.02em;
    }

    .onboarding-input:focus {
      background: rgba(255, 255, 255, 0.95);
      border-color: var(--accent-mid);
    }

    .onboarding-btn {
      width: 100%;
      padding: 9px 0;
      height: 36px;
      font-family: var(--font-display);
      font-style: italic;
      font-weight: 400;
      font-size: 14px;
      letter-spacing: -0.01em;
      color: var(--surface-0);
      background: var(--ink-0);
      border: none;
      border-radius: 9px;
      cursor: pointer;
      transition: background 0.14s, opacity 0.14s;
    }

    .onboarding-btn:hover:not(:disabled) { background: var(--ink-1); }

    .onboarding-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .onboarding-import-link {
      background: none;
      border: none;
      color: var(--ink-3);
      font-family: var(--font-mono);
      font-size: 9.5px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      cursor: pointer;
      padding: 8px 0 0;
    }

    .onboarding-import-link:hover { color: var(--accent); }
  `;
  document.head.appendChild(style);
}
