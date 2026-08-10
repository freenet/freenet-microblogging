// Shared view-model types for the Svelte UI components.
//
// These were originally co-located with the vanilla-TS create*() component
// factories (sidebar.ts / explore.ts / notifications.ts). After the Svelte 5
// port those imperative modules were deleted; the type contracts they defined
// are still consumed by the corresponding .svelte components and live here.

/** Which primary view the sidebar/right-panel navigation targets. */
export type SidebarView =
  | "feed"
  | "explore"
  | "notifications"
  | "profile"
  | "roadmap"
  | "settings";

/** A trending entry rendered in the Explore view. */
export interface ExploreItem {
  category: string;
  topic: string;
  count: string;
}

/** A single notification row. */
export interface NotificationRecord {
  id: string;
  kind: "like" | "repost" | "reply" | "mention" | "follow";
  actors: { displayName: string; handle: string; avatarColor?: string }[];
  /** Free-form relative time string. */
  ts: string;
  /** Quoted excerpt of the post being reacted to, if relevant. */
  post?: string;
  /** When the actor wrote text (reply/mention), the text itself. */
  text?: string;
}
