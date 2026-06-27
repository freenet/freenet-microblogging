import { test, expect, type Page, type FrameLocator } from "@playwright/test";

// End-to-end reply flow against a LIVE Freenet node (booted + published by
// scripts/node-e2e.sh). Tests the full reply path:
//   web UI compose-box → SignReply delegate variant → ThreadDelta::Replies →
//   thread-shard contract → thread view renders .thread-reply.
//
// Serial, single-node (workers:1), same shared delegate across tests in this
// file. The "cross-session" test exercises the reload-GET seam (#50) which may
// fail on a single-node setup; it is intentionally a SEPARATE test so the
// same-session assertion can pass independently.

/** The packaged app runs inside the sandboxed loader iframe. */
function app(page: Page): FrameLocator {
  return page.frameLocator("iframe#app");
}

/** Collect WS urls + console for connection assertions. */
function instrument(page: Page) {
  const ws: string[] = [];
  const logs: string[] = [];
  page.on("websocket", (s) => ws.push(s.url()));
  page.on("console", (m) => logs.push(`[${m.type()}] ${m.text()}`));
  page.on("pageerror", (e) => logs.push(`[pageerror] ${e.message}`));
  return { ws, logs };
}

test.beforeEach(({ baseURL }) => {
  expect(
    baseURL,
    "BASE_URL must be the node-served webapp URL — run via `cargo make test-ui-node-e2e`",
  ).toBeTruthy();
});

/**
 * Drive the app to the logged-in shell, tolerant of shared-node state. If the
 * delegate has no identity yet, onboarding shows and we register; if a prior
 * spec already created one, the shell is already up and we just wait for it.
 * Returns the app FrameLocator with the sidebar visible.
 */
async function ensureAppShell(page: Page, displayName: string): Promise<FrameLocator> {
  const a = app(page);
  const onboarding = a.locator(".onboarding-overlay");
  const sidebar = a.locator("aside.sidebar");
  await expect
    .poll(async () => (await onboarding.count()) > 0 || (await sidebar.count()) > 0, {
      timeout: 30_000,
    })
    .toBeTruthy();
  if ((await onboarding.count()) > 0 && (await sidebar.count()) === 0) {
    await a.locator(".onboarding-input").first().fill(displayName);
    const join = a.locator(".onboarding-btn", { hasText: "Join" });
    await expect(join).toBeEnabled({ timeout: 10_000 });
    await join.click();
  }
  await expect(sidebar).toBeVisible({ timeout: 45_000 });
  return a;
}

/**
 * Ensure at least one post exists in the Following feed.
 * If the feed is empty (following-note visible), compose one and wait for it.
 */
async function ensurePostExists(a: FrameLocator): Promise<void> {
  const feedPosts = a.locator(".feed__posts .post");
  const emptyNote = a.locator(".feed__posts .following-note__title", {
    hasText: "Nothing here yet",
  });

  // Wait until the feed settles: either posts appear or the empty-note shows.
  await expect
    .poll(
      async () => {
        const postCount = await feedPosts.count();
        const emptyCount = await emptyNote.count();
        return postCount > 0 || emptyCount > 0;
      },
      { timeout: 20_000 },
    )
    .toBeTruthy();

  // If the feed is still empty after settling, compose a seed post.
  if ((await feedPosts.count()) === 0) {
    await a.locator(".quickpost").click();
    await expect(a.locator(".compose-modal-overlay")).toBeVisible({ timeout: 10_000 });
    await a.locator(".compose-modal__textarea").fill("seed post for reply e2e");
    const postBtn = a.locator(".compose-modal__post");
    await expect(postBtn).toBeEnabled({ timeout: 10_000 });
    await postBtn.click();
    await expect(a.locator(".compose-modal-overlay")).toBeHidden({ timeout: 15_000 });
    // Wait for the seed post to appear in the feed. The first PUT on a cold
    // node (user-shard instantiate → write → subscription delta) can exceed
    // 30s, so allow the same 90s budget the reply round-trip uses.
    await expect(feedPosts.first()).toBeVisible({ timeout: 90_000 });
  }
}

// ---------------------------------------------------------------------------
// Test 1 — same-session: compose a reply and see it in the thread reply list.
// ---------------------------------------------------------------------------
test("reply appears in thread view (same session)", async ({ page }) => {
  const { logs } = instrument(page);
  await page.goto("", { waitUntil: "domcontentloaded" });
  const a = await ensureAppShell(page, "Reply Tester");

  // Wait for the live delegate to confirm identity is known.
  await expect
    .poll(() => logs.some((l) => l.includes("[identity] Delegate connection wired")), {
      timeout: 30_000,
    })
    .toBeTruthy();

  // Ensure there is at least one post to reply to.
  await ensurePostExists(a);

  // Open the first post's thread by clicking the reply-button (post-act--reply)
  // in the PostCard. The button calls onOpen(post) which sets threadRoot.
  const firstPost = a.locator(".feed__posts .post").first();
  await expect(firstPost).toBeVisible({ timeout: 15_000 });
  await firstPost.locator(".post-act--reply").click();

  // Thread view renders inside the same feed-column (replaces the feed).
  await expect(a.locator(".thread-head")).toBeVisible({ timeout: 15_000 });

  // Compose a reply with a unique marker.
  const marker = `e2e-reply-${Date.now()}`;
  const replyField = a.locator(".thread-compose__field");
  await expect(replyField).toBeVisible({ timeout: 10_000 });
  await replyField.fill(marker);
  const replyBtn = a.locator(".thread-compose__btn");
  await expect(replyBtn).toBeEnabled({ timeout: 5_000 });
  await replyBtn.click();

  // The reply textarea should clear after submit.
  await expect(replyField).toHaveValue("", { timeout: 5_000 });

  // SAME-SESSION assert: the reply list (.thread-reply) should contain the
  // marker text. The thread shard is written + the subscription delivers the
  // ThreadDelta::Replies back to the same session before a full reload is needed.
  await expect
    .poll(
      async () => a.locator(".thread-reply .thread-reply__text").getByText(marker).count(),
      {
        // Cold-node delegate-sign → thread-shard PUT → subscription delta
        // round-trip can exceed 30s on first use (matches the 90s poll the
        // live-node post round-trip uses for the same reason).
        timeout: 90_000,
        message: "reply did not appear in .thread-reply list (same session)",
      },
    )
    .toBeGreaterThan(0);
});

// ---------------------------------------------------------------------------
// Test 2 — cross-session: reload and verify the reply persisted.
//
// This exercises the #50 reload-GET seam: after a page.reload() the app
// re-GETs the thread shard from the node and must deserialise the persisted
// ThreadDelta::Replies. On a single-node setup the GET may fail if the shard
// was not yet finalised; this test is intentionally SEPARATE so that test 1
// can pass even when the cross-session GET is broken.
// ---------------------------------------------------------------------------
test("reply persists across page reload (cross-session — #50 seam, opt-in via E2E_RUN_CROSS_SESSION)", async ({
  page,
}) => {
  // This test exercises the #50 reload-GET seam which is not guaranteed to
  // succeed on a single-node setup. Skip in normal CI; set
  // E2E_RUN_CROSS_SESSION=1 to enforce it.
  test.fixme(
    !process.env.E2E_RUN_CROSS_SESSION,
    "Cross-session reload exercises the #50 single-node reload-GET seam, which is not guaranteed on a single node; set E2E_RUN_CROSS_SESSION=1 to enforce it.",
  );

  // Boot the app and get to a known post; the shared delegate already has an
  // identity from the same-session test above (serial workers:1 node).
  const { logs } = instrument(page);
  await page.goto("", { waitUntil: "domcontentloaded" });
  const a = await ensureAppShell(page, "Reply Tester Reload");

  await expect
    .poll(() => logs.some((l) => l.includes("[identity] Delegate connection wired")), {
      timeout: 30_000,
    })
    .toBeTruthy();

  await ensurePostExists(a);

  // Open the first post's thread.
  const firstPost = a.locator(".feed__posts .post").first();
  await expect(firstPost).toBeVisible({ timeout: 15_000 });
  await firstPost.locator(".post-act--reply").click();
  await expect(a.locator(".thread-head")).toBeVisible({ timeout: 15_000 });

  // Compose a FRESH marker for this test (distinct from the same-session run).
  const marker = `e2e-reply-reload-${Date.now()}`;
  const replyField = a.locator(".thread-compose__field");
  await expect(replyField).toBeVisible({ timeout: 10_000 });
  await replyField.fill(marker);
  const replyBtn = a.locator(".thread-compose__btn");
  await expect(replyBtn).toBeEnabled({ timeout: 5_000 });
  await replyBtn.click();
  await expect(replyField).toHaveValue("", { timeout: 5_000 });

  // Wait for the reply to appear in the same session first (gives the shard
  // time to be written before we reload).
  await expect
    .poll(
      async () => a.locator(".thread-reply .thread-reply__text").getByText(marker).count(),
      { timeout: 90_000, message: "reply did not appear in same-session (pre-reload)" },
    )
    .toBeGreaterThan(0);

  // CROSS-SESSION assert: reload the page, navigate back to the same thread,
  // and verify the reply is still rendered.
  // NOTE: this is the #50 seam — the reload-GET of the thread shard is not
  // guaranteed to succeed on a single-node setup. Generous 30 s poll.
  await page.reload({ waitUntil: "domcontentloaded" });
  const a2 = await ensureAppShell(page, "Reply Tester Reload");
  await ensurePostExists(a2);
  // TODO(#50): locate the replied-to post by a stable marker, not .first()
  const firstPost2 = a2.locator(".feed__posts .post").first();
  await expect(firstPost2).toBeVisible({ timeout: 20_000 });
  await firstPost2.locator(".post-act--reply").click();
  await expect(a2.locator(".thread-head")).toBeVisible({ timeout: 15_000 });

  await expect
    .poll(
      async () => a2.locator(".thread-reply .thread-reply__text").getByText(marker).count(),
      {
        timeout: 30_000,
        message:
          "reply did not survive page reload — this is the #50 single-node reload-GET seam",
      },
    )
    .toBeGreaterThan(0);
});
