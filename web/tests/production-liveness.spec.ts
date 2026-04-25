import { test, expect } from "@playwright/test";

test("webapp loads, mounts, and renders the feed shell", async ({ page }) => {
  await page.goto("/");
  // Document title set at runtime to APP_NAME ("Current") from web/branding/app.json.
  await expect(page).toHaveTitle("Current", { timeout: 10_000 });
  // App shell mounts (sidebar appears in the 3-column layout).
  await expect(page.locator("aside.sidebar")).toBeVisible({ timeout: 10_000 });
  // At least one mock post renders in offline mode.
  await expect(page.locator("article.post-card").first()).toBeVisible({ timeout: 10_000 });
});
