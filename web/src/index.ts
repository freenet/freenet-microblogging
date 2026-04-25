import "./scss/styles.scss";
import { APP_NAME } from "./branding";
import { createApp } from "./app";
import { FreenetConnection } from "./freenet-api";
import { Post } from "./types";
import { createOnboarding } from "./components/onboarding";
import {
  getIdentity,
  createIdentity,
  applyDelegateIdentity,
  connectDelegate,
  requestIdentityFromDelegate,
  Identity,
} from "./identity";
import { parseDelegateResponse } from "./delegate-api";
import { DelegateResponse } from "@freenetorg/freenet-stdlib";
import { MOCK_POSTS } from "./mock-data";

document.title = APP_NAME;

const appRoot = document.getElementById("app")!;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let localPosts: Post[] = [];
const knownPostIds = new Set<string>();
let appElement: HTMLElement | null = null;
let appRendered = false;
let delegateTimeoutId: ReturnType<typeof setTimeout> | null = null;

// ---------------------------------------------------------------------------
// Feed helpers
// ---------------------------------------------------------------------------
type FeedEl = HTMLElement & { updatePosts: (posts: Post[]) => void };

function getFeedEl(): FeedEl | null {
  return appElement?.querySelector(".feed-column") as FeedEl | null;
}

function refreshFeed(): void {
  getFeedEl()?.updatePosts(localPosts);
}

// ---------------------------------------------------------------------------
// Render the app (called once identity is known)
// ---------------------------------------------------------------------------
function renderApp(identity: Identity): void {
  if (appRendered) return;
  appRendered = true;
  if (delegateTimeoutId) { clearTimeout(delegateTimeoutId); delegateTimeoutId = null; }

  // Remove onboarding/splash if present
  document.querySelector(".onboarding-overlay")?.remove();
  document.querySelector(".splash-screen")?.remove();

  connection.setUser(identity.publicKey, identity.displayName, identity.handle);

  appElement = createApp((content: string) => {
    connection.publishPost(content).then((ok) => {
      if (ok) {
        console.log("[freenet] Post published");
        setTimeout(() => connection.loadState(), 300);
      }
    });
    return Promise.resolve(true);
  });
  appRoot.appendChild(appElement);

  // Load posts now that app is rendered
  connection.loadState();
}

// ---------------------------------------------------------------------------
// Show loading splash
// ---------------------------------------------------------------------------
function showSplash(): void {
  const splash = document.createElement("div");
  splash.className = "splash-screen";
  splash.style.cssText =
    "display:flex;align-items:center;justify-content:center;height:100vh;background:var(--bg-primary);";
  splash.innerHTML = `
    <div style="text-align:center">
      <div style="width:64px;height:64px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--accent-hover));margin:0 auto 16px;display:flex;align-items:center;justify-content:center;color:white;font-size:28px;font-weight:700">F</div>
      <p style="color:var(--text-muted);font-size:15px">Connecting to Freenet...</p>
    </div>
  `;
  appRoot.appendChild(splash);
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------
const connection = new FreenetConnection({
  onPostsLoaded: (posts: Post[]) => {
    console.log(`[freenet] Loaded ${posts.length} posts from network`);
    localPosts = posts;
    knownPostIds.clear();
    for (const post of posts) knownPostIds.add(post.id);
    refreshFeed();
  },
  onNewPost: (post: Post) => {
    if (knownPostIds.has(post.id)) return;
    knownPostIds.add(post.id);
    localPosts = [post, ...localPosts];
    refreshFeed();
  },
  onStatusChange: (status) => {
    console.log(`[freenet] Status: ${status}`);

    if (status === "connected") {
      // Wire delegate and request identity
      wireDelegateAndRequestIdentity();
    }

    if (status === "disconnected" || status === "error") {
      // No Freenet node — show onboarding with in-memory identity
      if (!appRendered) {
        showOnboarding();
      }
    }
  },
  onDelegateResponse: (response: DelegateResponse) => {
    const payloads = parseDelegateResponse(response);
    for (const payload of payloads) {
      console.log("[delegate] Response:", payload);

      if (applyDelegateIdentity(payload)) {
        const identity = getIdentity()!;
        connection.setUser(identity.publicKey, identity.displayName, identity.handle);

        if (!appRendered) {
          renderApp(identity);
        }
        return;
      }

      // Check for "no identity" error from delegate
      const p = payload as { type?: string; message?: string };
      if (p.type === "Error" && p.message?.includes("no identity")) {
        console.log("[identity] No identity in delegate — show onboarding");
        if (!appRendered) {
          showOnboarding();
        }
        return;
      }
    }
  },
});

// ---------------------------------------------------------------------------
// Delegate wiring
// ---------------------------------------------------------------------------
async function wireDelegateAndRequestIdentity(): Promise<void> {
  const api = connection.wsApi;
  if (!api || !__DELEGATE_KEY__) {
    // No delegate configured — fallback to onboarding
    if (!appRendered) showOnboarding();
    return;
  }

  try {
    // Use pre-decoded bytes injected at build time (avoids base58 decode in sandbox)
    const keyBytes = __DELEGATE_KEY_BYTES__;
    const codeHashBytes = __DELEGATE_CODE_HASH_BYTES__;
    if (!keyBytes || keyBytes.length !== 32) {
      console.warn("[identity] Invalid delegate key bytes, length:", keyBytes?.length);
      if (!appRendered) showOnboarding();
      return;
    }
    if (!codeHashBytes || codeHashBytes.length !== 32) {
      console.warn("[identity] Invalid delegate code_hash bytes, length:", codeHashBytes?.length);
      if (!appRendered) showOnboarding();
      return;
    }

    connectDelegate(api, keyBytes, codeHashBytes);
    console.log(`[identity] Delegate wired (key: ${keyBytes.length}b, code_hash: ${codeHashBytes.length}b)`);

    requestIdentityFromDelegate();

    delegateTimeoutId = setTimeout(() => {
      if (!appRendered) {
        console.log("[identity] Delegate timeout — showing onboarding");
        showOnboarding();
      }
      delegateTimeoutId = null;
    }, 5000);
  } catch (e) {
    console.warn("[identity] Failed to wire delegate:", e);
    if (!appRendered) showOnboarding();
  }
}

// ---------------------------------------------------------------------------
// Onboarding
// ---------------------------------------------------------------------------
function showOnboarding(): void {
  if (appRendered) return;
  // Remove splash
  document.querySelector(".splash-screen")?.remove();

  const onboarding = createOnboarding((displayName: string, secretKey?: string) => {
    const identity = createIdentity(displayName, secretKey);
    renderApp(identity);
  });
  document.body.appendChild(onboarding);
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
if (__OFFLINE_MODE__) {
  // Offline mode: skip WebSocket / delegate, render immediately with mock data.
  // Used for CI / Playwright / no-node previews.
  console.log("[offline] Booting in offline mode with mock data");
  const identity = createIdentity("Offline Demo");
  renderApp(identity);
  // renderApp triggers connection.loadState() which is a no-op without a connect().
  // Push mock posts into the feed once the app is mounted.
  setTimeout(() => {
    const feed = appElement?.querySelector(".feed-column") as
      | (HTMLElement & { updatePosts: (posts: Post[]) => void })
      | null;
    feed?.updatePosts(MOCK_POSTS);
  }, 0);
} else {
  showSplash();
  connection.connect();
}
