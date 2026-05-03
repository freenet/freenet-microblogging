import { Post } from "../types";
import { createComposeBox } from "./compose-box";
import { createPostCard } from "./post-card";

export function createFeed(
  posts: Post[],
  onPost: (content: string) => void,
  followedPubkeys: Set<string> = new Set()
): HTMLElement {
  const feed = document.createElement("main");
  feed.className = "feed-column";

  // Feed header
  const header = document.createElement("div");
  header.className = "feed-header";

  // Tab bar
  const tabBar = document.createElement("div");
  tabBar.className = "tab-bar";

  let activeTab: "for-you" | "following" = "for-you";

  const tabForYou = document.createElement("button");
  tabForYou.className = "tab-bar__tab tab-bar__tab--active";
  tabForYou.textContent = "For you";

  const tabFollowing = document.createElement("button");
  tabFollowing.className = "tab-bar__tab";
  tabFollowing.textContent = "Following";

  tabBar.appendChild(tabForYou);
  tabBar.appendChild(tabFollowing);

  header.appendChild(tabBar);

  // Post list
  const postList = document.createElement("div");
  postList.className = "feed__posts";

  // Current posts array (updated externally via postList.dataset or re-render)
  let currentPosts: Post[] = [...posts];

  function renderPosts(): void {
    postList.innerHTML = "";
    const filtered =
      activeTab === "following"
        ? currentPosts.filter(
            (p) =>
              p.author.publicKey !== undefined &&
              followedPubkeys.has(p.author.publicKey)
          )
        : currentPosts;

    if (activeTab === "following" && filtered.length === 0) {
      const empty = document.createElement("div");
      empty.textContent = "Follow people to see their posts here.";
      empty.style.cssText =
        "padding:32px 16px;color:var(--text-muted);font-size:15px;text-align:center;";
      postList.appendChild(empty);
    } else {
      for (const post of filtered) {
        postList.appendChild(createPostCard(post));
      }
    }
  }

  // Tab click handlers
  tabForYou.addEventListener("click", () => {
    activeTab = "for-you";
    tabForYou.classList.add("tab-bar__tab--active");
    tabFollowing.classList.remove("tab-bar__tab--active");
    renderPosts();
  });

  tabFollowing.addEventListener("click", () => {
    activeTab = "following";
    tabFollowing.classList.add("tab-bar__tab--active");
    tabForYou.classList.remove("tab-bar__tab--active");
    renderPosts();
  });

  // Compose box
  const composeBox = createComposeBox((content: string) => {
    onPost(content);
  });

  // Initial render
  renderPosts();

  feed.appendChild(header);
  feed.appendChild(composeBox);
  feed.appendChild(postList);

  // Expose postList for use from app.ts, and a method to update posts
  const feedEl = feed as HTMLElement & {
    postList: HTMLDivElement;
    updatePosts: (posts: Post[]) => void;
  };
  feedEl.postList = postList;
  feedEl.updatePosts = (updatedPosts: Post[]) => {
    currentPosts = updatedPosts;
    renderPosts();
  };

  return feed;
}
