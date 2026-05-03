import { createSidebar, SidebarView } from "./components/sidebar";
import { createFeed } from "./components/feed";
import { createProfile } from "./components/profile";
import { createRightPanel } from "./components/right-panel";
import { getIdentity } from "./identity";
import { Post } from "./types";

export function createApp(publishFn?: (content: string) => Promise<boolean>): HTMLElement {
  const posts: Post[] = [];
  const followedPubkeys = new Set<string>();

  const app = document.createElement("div");
  app.className = "app-layout";

  // Main content area (feed or profile)
  const mainArea = document.createElement("div");
  mainArea.style.cssText = "flex:1;min-width:0;display:flex;flex-direction:column;";

  // Track current view
  let currentView: SidebarView = "feed";

  // Build feed element (created once, shown/hidden)
  const feed = createFeed(
    posts,
    (content: string) => {
      if (publishFn) {
        publishFn(content).catch((e) =>
          console.error("[freenet] Publish failed:", e)
        );
      }
    },
    followedPubkeys
  );

  mainArea.appendChild(feed);

  // Navigation handler
  function navigate(view: SidebarView): void {
    if (view === currentView) return;
    currentView = view;

    // Remove current child and replace
    mainArea.innerHTML = "";

    if (view === "feed") {
      mainArea.appendChild(feed);
    } else if (view === "profile") {
      const identity = getIdentity();
      if (identity) {
        // Filter posts authored by the current user
        const myPosts = posts.filter(
          (p) => p.author.publicKey && p.author.publicKey === identity.publicKey
        );
        const profileUser = {
          displayName: identity.displayName,
          handle: identity.handle,
          publicKey: identity.publicKey,
        };
        const profileEl = createProfile(profileUser, myPosts);
        mainArea.appendChild(profileEl);
      } else {
        // No identity yet — fall back to feed
        currentView = "feed";
        mainArea.appendChild(feed);
      }
    }
  }

  const sidebar = createSidebar({ onNavigate: navigate });
  app.appendChild(sidebar);

  app.appendChild(mainArea);

  // Right panel column
  const rightCol = document.createElement("div");
  rightCol.className = "right-panel-col";
  rightCol.style.cssText = [
    "width:var(--right-panel-width, 320px)",
    "flex-shrink:0",
    "padding:0 18px",
    "min-height:100vh",
    "border-left:1px solid var(--line)",
    "background:transparent",
  ].join(";");

  const rightPanel = createRightPanel();
  rightCol.appendChild(rightPanel);
  app.appendChild(rightCol);

  // Expose feed methods for external updates
  const appEl = app as unknown as HTMLElement & {
    updatePosts: (updatedPosts: Post[]) => void;
    addPost: (post: Post) => void;
  };

  appEl.updatePosts = (updatedPosts: Post[]) => {
    posts.length = 0;
    posts.push(...updatedPosts);
    const feedEl = feed as HTMLElement & { updatePosts: (p: Post[]) => void };
    feedEl.updatePosts(updatedPosts);
  };

  appEl.addPost = (post: Post) => {
    posts.unshift(post);
    const feedEl = feed as HTMLElement & { updatePosts: (p: Post[]) => void };
    feedEl.updatePosts([...posts]);
  };

  return app;
}
