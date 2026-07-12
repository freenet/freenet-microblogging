import { expect, type FrameLocator, type Page } from "@playwright/test";

/**
 * Shared helpers for the multi-node e2e tier. Each spec drives TWO app
 * sessions against TWO different Freenet nodes of the same local network
 * (booted by scripts/multi-node-e2e.sh, which exports the URLs):
 *
 *   GW_APP_URL   — webapp served by the gateway node
 *   PEER_APP_URL — webapp served by a peer node
 *
 * The app runs inside the loader's sandboxed <iframe id="app">, so all UI
 * assertions go through the frame locator (same pattern as node-e2e).
 */

export const GW_APP_URL = process.env.GW_APP_URL ?? "";
export const PEER_APP_URL = process.env.PEER_APP_URL ?? "";

export function app(page: Page): FrameLocator {
  return page.frameLocator("iframe#app");
}

/**
 * Drive a fresh page to the logged-in shell: register through onboarding when
 * the node's delegate has no identity yet, otherwise ride the existing one.
 * Mirrors node-e2e's ensureAppShell but is shared-network tolerant (a node's
 * delegate keeps the identity of the first spec that registered on it).
 */
export async function ensureShell(
  page: Page,
  url: string,
  displayName: string,
): Promise<FrameLocator> {
  await page.goto(url, { waitUntil: "domcontentloaded" });
  const a = app(page);
  const onboarding = a.locator(".onboarding-overlay");
  const sidebar = a.locator("aside.sidebar");
  await expect
    .poll(async () => (await onboarding.count()) > 0 || (await sidebar.count()) > 0, {
      timeout: 60_000,
    })
    .toBeTruthy();
  if ((await onboarding.count()) > 0 && (await sidebar.count()) === 0) {
    await a.locator(".onboarding-input").first().fill(displayName);
    await a.locator(".onboarding-btn", { hasText: "Join" }).click();
  }
  await expect(sidebar).toBeVisible({ timeout: 60_000 });
  return a;
}

/** Compose a post; `shared` ticks "share to public timeline". */
export async function composePost(
  a: FrameLocator,
  text: string,
  opts: { shared?: boolean } = {},
): Promise<void> {
  await a.locator(".quickpost").click();
  await expect(a.locator(".compose-modal-overlay")).toBeVisible({ timeout: 10_000 });
  await a.locator(".compose-modal__textarea").fill(text);
  if (opts.shared) {
    await a.locator(".compose-modal__share-check").check();
  }
  const postBtn = a.locator(".compose-modal__post");
  await expect(postBtn).toBeEnabled({ timeout: 10_000 });
  await postBtn.click();
  await expect(a.locator(".compose-modal-overlay")).toBeHidden({ timeout: 20_000 });
}

/** Open the Home → Discover tab. */
export async function openDiscover(a: FrameLocator): Promise<void> {
  const tab = a.locator(".feed-tab", { hasText: "Discover" });
  await expect(tab).toBeVisible({ timeout: 30_000 });
  await tab.click();
}

/**
 * Poll the Discover feed until `text` appears. The propagation budget covers
 * the live-notification path (seconds) with the 60s poll re-GET as backstop,
 * so anything beyond ~150s is a real regression, not slowness.
 */
export async function expectInDiscover(
  a: FrameLocator,
  text: string,
  timeout = 150_000,
): Promise<void> {
  await openDiscover(a);
  await expect
    .poll(async () => a.locator(".feed__posts").getByText(text).count(), {
      timeout,
      message: `"${text}" never surfaced in the Discover timeline`,
    })
    .toBeGreaterThan(0);
}
