import "./scss/styles.scss";
import { createApp } from "./app";
import { FreenetConnection } from "./freenet-api";

const appRoot = document.getElementById("app");
if (!appRoot) throw new Error("No #app element");

// Try to connect to Freenet node
const connection = new FreenetConnection({
  onPostsLoaded: (posts) => {
    console.log(`[freenet] Loaded ${posts.length} posts from network`);
    // TODO: re-render feed with real posts
  },
  onNewPost: (post) => {
    console.log(`[freenet] New post from @${post.author.handle}`);
    // TODO: prepend to feed
  },
  onStatusChange: (status) => {
    console.log(`[freenet] Status: ${status}`);
    if (status === "disconnected" || status === "error") {
      // Fallback to mock data — render app normally
      if (!appRoot.hasChildNodes()) {
        appRoot.appendChild(createApp());
      }
    }
  },
});

// Start connection attempt
connection.connect();

// If no Freenet node, app renders with mock data via the onStatusChange fallback
// If connected, posts come from the network via callbacks
