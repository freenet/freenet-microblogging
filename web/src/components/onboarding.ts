/**
 * First-visit onboarding screen.
 * Renders a full-screen overlay asking the user for a display name.
 * Uses CSS custom properties from the app's design system where possible,
 * with inline styles so no SCSS changes are needed.
 */

import { APP_NAME } from "../branding";

export function createOnboarding(
  onComplete: (displayName: string, secretKey?: string) => void
): HTMLElement {
  // Inject component-scoped styles once
  injectStyles();

  // Overlay backdrop
  const overlay = document.createElement("div");
  overlay.className = "onboarding-overlay";

  // Card
  const card = document.createElement("div");
  card.className = "onboarding-card";

  // App logo mark — first character of the app name
  const logo = document.createElement("div");
  logo.className = "onboarding-logo";
  logo.textContent = APP_NAME.charAt(0).toUpperCase();

  // Title
  const title = document.createElement("h1");
  title.className = "onboarding-title";
  title.textContent = `Welcome to ${APP_NAME}`;

  // Subtitle
  const subtitle = document.createElement("p");
  subtitle.className = "onboarding-subtitle";
  subtitle.textContent = "Choose your display name to get started";

  // Input
  const input = document.createElement("input");
  input.className = "onboarding-input";
  input.type = "text";
  input.placeholder = "Your name";
  input.maxLength = 50;
  input.setAttribute("autocomplete", "off");
  input.setAttribute("spellcheck", "false");

  // Join button (disabled until input has text)
  const button = document.createElement("button");
  button.className = "onboarding-btn";
  button.textContent = "Join";
  button.disabled = true;

  // Enable / disable button as user types
  input.addEventListener("input", () => {
    button.disabled = input.value.trim().length === 0;
  });

  // Submit handler
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

  // Import link
  const importLink = document.createElement("button");
  importLink.className = "onboarding-import-link";
  importLink.textContent = "Import existing identity";
  importLink.addEventListener("click", () => {
    // Toggle import section
    importSection.style.display = importSection.style.display === "none" ? "flex" : "none";
    nameSection.style.display = nameSection.style.display === "none" ? "flex" : "none";
  });

  // Name section (default)
  const nameSection = document.createElement("div");
  nameSection.style.cssText = "display:flex;flex-direction:column;align-items:center;gap:12px;width:100%";
  nameSection.appendChild(input);
  nameSection.appendChild(button);

  // Import section (hidden by default)
  const importSection = document.createElement("div");
  importSection.style.cssText = "display:none;flex-direction:column;align-items:center;gap:12px;width:100%";

  const importInput = document.createElement("input");
  importInput.className = "onboarding-input";
  importInput.type = "text";
  importInput.placeholder = "Your name";
  importInput.maxLength = 50;

  const secretInput = document.createElement("input");
  secretInput.className = "onboarding-input";
  secretInput.type = "password";
  secretInput.placeholder = "Secret key (64 hex characters)";
  secretInput.maxLength = 64;
  secretInput.style.fontFamily = "monospace";

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
  card.appendChild(title);
  card.appendChild(subtitle);
  card.appendChild(nameSection);
  card.appendChild(importLink);
  card.appendChild(importSection);
  overlay.appendChild(card);

  // Auto-focus the input after mount (next tick)
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
      background: rgba(0, 0, 0, 0.55);
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: var(--font-stack, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif);
    }

    .onboarding-card {
      background: var(--bg-elevated, #ffffff);
      border-radius: var(--radius-card, 16px);
      padding: 40px 36px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 8px 40px rgba(0, 0, 0, 0.18);
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 12px;
    }

    .onboarding-logo {
      width: 56px;
      height: 56px;
      border-radius: 50%;
      background: var(--accent, #0066cc);
      color: #fff;
      font-size: 26px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 4px;
    }

    .onboarding-title {
      margin: 0;
      font-size: 22px;
      font-weight: 700;
      color: var(--text-primary, #000);
      text-align: center;
    }

    .onboarding-subtitle {
      margin: 0 0 8px;
      font-size: 15px;
      color: var(--text-muted, #64748b);
      text-align: center;
    }

    .onboarding-input {
      width: 100%;
      box-sizing: border-box;
      padding: 10px 14px;
      font-size: 15px;
      font-family: inherit;
      color: var(--text-primary, #000);
      background: var(--bg-primary, #f8fafc);
      border: 1px solid var(--border-strong, #e5e7eb);
      border-radius: var(--radius-pill, 9999px);
      outline: none;
      transition: border-color 0.15s;
    }

    .onboarding-input:focus {
      border-color: var(--accent, #0066cc);
      box-shadow: 0 0 0 3px var(--accent-soft, rgba(0,102,204,0.10));
    }

    .onboarding-btn {
      width: 100%;
      padding: 10px 0;
      font-size: 16px;
      font-weight: 600;
      font-family: inherit;
      color: #fff;
      background: var(--accent, #0066cc);
      border: none;
      border-radius: var(--radius-pill, 9999px);
      cursor: pointer;
      transition: background 0.15s, opacity 0.15s;
      margin-top: 4px;
    }

    .onboarding-btn:hover:not(:disabled) {
      background: var(--accent-hover, #004c99);
    }

    .onboarding-btn:disabled {
      opacity: 0.45;
      cursor: not-allowed;
    }

    .onboarding-import-link {
      background: none;
      border: none;
      color: var(--accent, #0066cc);
      font-size: 13px;
      cursor: pointer;
      padding: 4px 0;
      font-family: inherit;
    }

    .onboarding-import-link:hover {
      text-decoration: underline;
    }
  `;
  document.head.appendChild(style);
}
