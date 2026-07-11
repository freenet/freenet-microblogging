// Ad-hoc multi-node live test (not part of CI).
// Drives TWO browsers against TWO different freenet nodes of the same local
// network (booted via freenet-test-network): create identity + share a post on
// the gateway-connected app, assert it propagates to the peer-connected app's
// Discover timeline, then the reverse direction.
//
// Usage: node multi-node-live.mjs <gwAppUrl> <peerAppUrl> <outDir>
import { chromium } from "@playwright/test";

const [gwUrl, peerUrl, outDir] = process.argv.slice(2);
if (!gwUrl || !peerUrl || !outDir) {
  console.error("usage: node multi-node-live.mjs <gwAppUrl> <peerAppUrl> <outDir>");
  process.exit(2);
}

const ts = Date.now();
const markerA = `alice-gw-${ts}`;
const markerB = `bob-peer-${ts}`;

function instrument(page, tag) {
  page.on("console", (m) => {
    const t = m.text();
    if (/\[(identity|freenet|global-index|offline|delegate)\]|error/i.test(t)) {
      console.log(`  {${tag}} [${m.type()}] ${t.slice(0, 250)}`);
    }
  });
  page.on("pageerror", (e) => console.log(`  {${tag}} [pageerror] ${e.message}`));
  page.on("response", (r) => {
    if (r.status() >= 400 && !r.url().includes("fonts.g")) {
      console.log(`  {${tag}} HTTP ${r.status()} ${r.url()}`);
    }
  });
}

const app = (page) => page.frameLocator("iframe#app");

async function shot(page, name) {
  await page.screenshot({ path: `${outDir}/${name}.png`, fullPage: false });
  console.log(`  shot: ${name}.png`);
}

async function ensureShell(page, name, tag) {
  const a = app(page);
  const onboarding = a.locator(".onboarding-overlay");
  const sidebar = a.locator("aside.sidebar");
  const deadline = Date.now() + 90_000;
  let reloaded = false;
  while (Date.now() < deadline) {
    if (!reloaded && Date.now() > deadline - 60_000) {
      // App sometimes fails to boot on first wrapper load (transient 500);
      // one reload recovers.
      console.log(`  {${tag}} no UI after 30s — reloading once`);
      await page.reload({ waitUntil: "domcontentloaded" });
      reloaded = true;
    }
    if ((await sidebar.count()) > 0 && (await sidebar.isVisible().catch(() => false))) break;
    if ((await onboarding.count()) > 0 && (await onboarding.isVisible().catch(() => false))) {
      console.log(`  {${tag}} onboarding visible -> joining as "${name}"`);
      await a.locator(".onboarding-input").first().fill(name);
      const join = a.locator(".onboarding-btn", { hasText: "Join" });
      await join.click();
      break;
    }
    await page.waitForTimeout(500);
  }
  await sidebar.waitFor({ state: "visible", timeout: 60_000 });
  console.log(`  {${tag}} app shell up`);
  return a;
}

async function sharePost(a, text, tag) {
  await a.locator(".quickpost").click();
  await a.locator(".compose-modal__textarea").fill(text);
  await a.locator(".compose-modal__share-check").check();
  await a.locator(".compose-modal__post").click();
  await a
    .locator(".compose-modal-overlay")
    .waitFor({ state: "hidden", timeout: 20_000 });
  console.log(`  {${tag}} posted+shared: "${text}"`);
}

async function pollDiscoverFor(a, page, text, tag, timeoutMs) {
  const discoverTab = a.locator(".feed-tab", { hasText: "Discover" });
  await discoverTab.waitFor({ state: "visible", timeout: 30_000 });
  await discoverTab.click();
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const n = await a.locator(".feed__posts").getByText(text).count();
    if (n > 0) {
      console.log(`  {${tag}} FOUND "${text}" in Discover`);
      return true;
    }
    // Re-click discover tab occasionally in case a re-render reset tabs
    await page.waitForTimeout(3000);
  }
  console.log(`  {${tag}} MISSING "${text}" in Discover after ${timeoutMs}ms`);
  return false;
}

const browser = await chromium.launch();
const results = {};

console.log("== A: gateway node ==");
const ctxA = await browser.newContext();
const pageA = await ctxA.newPage();
instrument(pageA, "A/gw");
await pageA.goto(gwUrl, { waitUntil: "domcontentloaded" });
const a = await ensureShell(pageA, "Alice GW", "A/gw");
await shot(pageA, "A1-shell");
await sharePost(a, markerA, "A/gw");
results.aSeesOwn = await pollDiscoverFor(a, pageA, markerA, "A/gw", 90_000);
await shot(pageA, "A2-discover-own");

console.log("== B: peer0 node ==");
const ctxB = await browser.newContext();
const pageB = await ctxB.newPage();
instrument(pageB, "B/peer");
await pageB.goto(peerUrl, { waitUntil: "domcontentloaded" });
const b = await ensureShell(pageB, "Bob Peer", "B/peer");
await shot(pageB, "B1-shell");

console.log("== B: look for A's post (cross-node GW -> PEER) ==");
results.bSeesA = await pollDiscoverFor(b, pageB, markerA, "B/peer", 180_000);
await shot(pageB, "B2-discover-cross");

console.log("== B: share own post ==");
await sharePost(b, markerB, "B/peer");
results.bSeesOwn = await pollDiscoverFor(b, pageB, markerB, "B/peer", 90_000);
await shot(pageB, "B3-discover-own");

console.log("== A: look for B's post (cross-node PEER -> GW, live update) ==");
results.aSeesB = await pollDiscoverFor(a, pageA, markerB, "A/gw", 180_000);
await shot(pageA, "A3-discover-cross");

console.log("RESULTS " + JSON.stringify(results));
await browser.close();
process.exit(0);
