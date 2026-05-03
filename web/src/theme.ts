// Theme is in-memory only: Freenet webapps run in an iframe sandboxed without
// `allow-same-origin`, so localStorage / sessionStorage / cookies are blocked.
// On every reload we fall back to the user's OS preference; the toggle holds
// during the session.

export function initTheme(): void {
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  applyTheme(prefersDark ? "dark" : "light");
}

export function toggleTheme(): void {
  const current = document.documentElement.getAttribute("data-theme");
  const next = current === "dark" ? "light" : "dark";
  applyTheme(next);
}

function applyTheme(theme: "dark" | "light"): void {
  document.documentElement.setAttribute("data-theme", theme);
}
