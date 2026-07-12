import { test, expect, type Page } from "@playwright/test";
import {
  GW_APP_URL,
  PEER_APP_URL,
  app,
  ensureShell,
  composePost,
  expectInDiscover,
} from "./helpers";

// Realistic-usage journeys across TWO nodes of a live local network. Serial
// on purpose: the journeys build on each other exactly like real usage does
// (an identity registered in journey 1 is the author whose posts journey 2
// reads from the other node), and the network/delegates are shared state.
//
// Alice lives on the GATEWAY node, Bob on a PEER node. One browser context
// per user, kept open across journeys so live-update delivery (not just
// reload-GET) is exercised.
test.describe.configure({ mode: "serial" });

const RUN = Date.now();
const ALICE_POST = `alice-first-${RUN}`;
const ALICE_SHARED = `alice-shared-${RUN}`;
const BOB_SHARED = `bob-shared-${RUN}`;
const BOB_REPLY = `bob-reply-${RUN}`;

let alicePage: Page;
let bobPage: Page;

test.beforeAll(({}) => {
  expect(GW_APP_URL, "run via `cargo make test-ui-multi-node`").toBeTruthy();
  expect(PEER_APP_URL, "run via `cargo make test-ui-multi-node`").toBeTruthy();
});

test.afterAll(async () => {
  await alicePage?.context().close();
  await bobPage?.context().close();
});

test("journey 1: Alice onboards on the gateway, posts, and her feed persists a reload", async ({
  browser,
}) => {
  alicePage = await (await browser.newContext()).newPage();
  const a = await ensureShell(alicePage, GW_APP_URL, "Alice");
  await composePost(a, ALICE_POST);
  // Her own (unshared) post lands in the Following feed.
  await expect(a.locator(".feed__posts").getByText(ALICE_POST)).toBeVisible({
    timeout: 30_000,
  });

  // Reload: the delegate-persisted identity skips onboarding and the shard
  // GET restores the feed — the "come back later" experience.
  await alicePage.reload({ waitUntil: "domcontentloaded" });
  const a2 = app(alicePage);
  await expect(a2.locator("aside.sidebar")).toBeVisible({ timeout: 60_000 });
  await expect(a2.locator(".onboarding-overlay")).toHaveCount(0);
  await expect(a2.locator(".feed__posts").getByText(ALICE_POST)).toBeVisible({
    timeout: 30_000,
  });
});

test("journey 2: Alice shares publicly; Bob (other node) finds it in Discover", async ({
  browser,
}) => {
  const a = app(alicePage);
  await composePost(a, ALICE_SHARED, { shared: true });
  // Sharer sees their own post in Discover (same-session round-trip).
  await expectInDiscover(a, ALICE_SHARED, 90_000);

  // Bob onboards on the PEER node and discovers Alice's post — cross-node
  // read of the public timeline (global-index GET over the network).
  bobPage = await (await browser.newContext()).newPage();
  const b = await ensureShell(bobPage, PEER_APP_URL, "Bob");
  await expectInDiscover(b, ALICE_SHARED);
});

test("journey 3: Bob shares publicly; Alice's OPEN session receives it (live update / poll)", async () => {
  const b = app(bobPage);
  await composePost(b, BOB_SHARED, { shared: true });
  await expectInDiscover(b, BOB_SHARED, 90_000);

  // Alice's session has been open since journey 1 — delivery must not
  // require a reload. Live path: cross-node State notification; backstop:
  // the 60s public-timeline re-GET.
  const a = app(alicePage);
  await expectInDiscover(a, BOB_SHARED);
});

test("journey 4: Bob replies to Alice's shared post; the reply thread converges on both nodes", async () => {
  // Bob opens Alice's post from Discover and replies.
  const b = app(bobPage);
  await expectInDiscover(b, ALICE_SHARED, 60_000);
  const alicePost = b
    .locator(".feed__posts .post")
    .filter({ hasText: ALICE_SHARED })
    .first();
  await alicePost.locator(".post-act--reply").click();
  await expect(b.locator(".thread-head")).toBeVisible({ timeout: 30_000 });
  const replyField = b.locator(".thread-compose__field");
  await expect(replyField).toBeVisible({ timeout: 15_000 });
  await replyField.fill(BOB_REPLY);
  await b.locator(".thread-compose__btn").click();
  // Bob sees his reply in the thread.
  await expect
    .poll(
      async () =>
        b.locator(".thread-reply .thread-reply__text").getByText(BOB_REPLY).count(),
      { timeout: 60_000, message: "Bob's own reply never rendered in the thread" },
    )
    .toBeGreaterThan(0);

  // Alice opens the same thread from HER node: the thread shard was
  // instantiated on Bob's node, so this is a cross-node thread GET.
  const a = app(alicePage);
  await expectInDiscover(a, ALICE_SHARED, 60_000);
  const own = a
    .locator(".feed__posts .post")
    .filter({ hasText: ALICE_SHARED })
    .first();
  await own.locator(".post-act--reply").click();
  await expect(a.locator(".thread-head")).toBeVisible({ timeout: 30_000 });
  await expect
    .poll(
      async () =>
        a.locator(".thread-reply .thread-reply__text").getByText(BOB_REPLY).count(),
      {
        timeout: 150_000,
        message: "Bob's reply never surfaced in Alice's view of the thread (cross-node)",
      },
    )
    .toBeGreaterThan(0);
});
