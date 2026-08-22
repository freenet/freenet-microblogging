/**
 * roadmap-data.ts — what is built, what is next, and what it would cost.
 *
 * Kept as data rather than markup so the Roadmap view stays a renderer, and so
 * the planned voting layer has something stable to attach to: every item has a
 * permanent `id` that a vote record can reference. Ids are never reused or
 * renumbered — a vote for `retract-posts` must keep meaning the same thing after
 * the list is reordered.
 *
 * `votes` is deliberately absent. Vote counts will come from the network, not
 * from this file; hardcoding a number here would put a fake signal in front of
 * people whose whole purpose is to produce a real one.
 */

export type RoadmapStatus = "done" | "building" | "next" | "considering";

export interface RoadmapItem {
  /** Permanent, never reused — the key a future vote record points at. */
  id: string;
  title: string;
  /** What it actually does, in the user's terms. */
  summary: string;
  /** Why it matters, or what breaks without it. Honest about cost. */
  rationale?: string;
  status: RoadmapStatus;
  /** Rough size, so a vote is cast with some idea of the price. */
  effort: "small" | "medium" | "large";
  /** True when the work changes contract bytes → new addresses, redeploy. */
  breaksAddresses?: boolean;
  /** Open for voting once the voting layer lands. */
  votable: boolean;
}

export interface RoadmapSection {
  heading: string;
  blurb: string;
  items: RoadmapItem[];
}

export const ROADMAP: RoadmapSection[] = [
  {
    heading: "Shipped",
    blurb:
      "Working today. Listed so the rest of the plan can be read against something real.",
    items: [
      {
        id: "posts-likes-reposts",
        title: "Posts, likes, reposts, quotes",
        summary:
          "Every record signed with your own post-quantum key and addressed by its content.",
        status: "done",
        effort: "large",
        votable: false,
      },
      {
        id: "replies",
        title: "Replies",
        summary: "Threads under a root post, each reply self-verifying.",
        rationale: "Nested threads are still flat — a reply to a reply lands on the same thread.",
        status: "done",
        effort: "medium",
        votable: false,
      },
      {
        id: "public-timeline",
        title: "Public timeline",
        summary: "Opt-in Discover feed backed by a singleton index contract.",
        status: "done",
        effort: "medium",
        votable: false,
      },
      {
        id: "follows",
        title: "Follows",
        summary:
          "Follow by key, with the Following feed aggregating everyone you follow.",
        rationale:
          "Your follow list lives in your own shard, which anyone can read. That is public by design, not by accident.",
        status: "done",
        effort: "medium",
        votable: false,
      },
      {
        id: "retract-posts",
        title: "Withdraw a post",
        summary:
          "Stop your shard and the public timeline serving a post, and stop either re-accepting it.",
        rationale:
          "Not a delete, and never called one: nobody can reach a copy already fetched or held offline. Before this the only way to bury a post was to write two hundred more.",
        status: "done",
        effort: "large",
        breaksAddresses: true,
        votable: false,
      },
      {
        id: "mute",
        title: "Mute",
        summary: "Hide an author's posts and replies, for you only.",
        rationale:
          "Local and unannounced. A blocklist stored on the network would be public, and publishing who you are avoiding discloses a social signal the reader never chose to share.",
        status: "done",
        effort: "small",
        votable: false,
      },
    ],
  },
  {
    heading: "Next",
    blurb:
      "Committed work, roughly in order. These close gaps that are already costing people something.",
    items: [
      {
        id: "notifications-wire",
        title: "Real notifications",
        summary:
          "Wire the inbox contract to the notifications screen, which currently renders nothing.",
        rationale:
          "The contract is finished and the screen is built — only the delivery path between them is missing.",
        status: "building",
        effort: "medium",
        votable: true,
      },
      {
        id: "writer-credentials",
        title: "Writer credentials",
        summary:
          "Introduce a scarce writer credential for the surfaces that accept writes from any author.",
        rationale:
          "The largest remaining piece of ADR-0001, and a system to design rather than a patch. Public surfaces are bounded by size caps, so write volume and retention are coupled: the credential work is what lets per-writer limits mean anything. GhostKey is the candidate the ADR names.",
        status: "next",
        effort: "large",
        breaksAddresses: true,
        votable: true,
      },
      {
        id: "handle-registry",
        title: "Handle registry",
        summary: "Make @handles mean one account instead of being a free-text field.",
        rationale:
          "Handles are self-declared today, so ten keys can all claim to be the same person and the interface shows the claim as identity. Follow and mute already work on keys, not handles, but a reader still decides by the name they see. Needs a rule for who wins a name dispute.",
        status: "next",
        effort: "large",
        breaksAddresses: true,
        votable: true,
      },
      {
        id: "profile-editing",
        title: "Editable profile",
        summary: "Set your display name, handle, bio and avatar from Settings.",
        rationale: "The contract and the signing path are done; the screen is not.",
        status: "next",
        effort: "small",
        votable: true,
      },
    ],
  },
  {
    heading: "Under consideration",
    blurb:
      "Wanted, not yet committed. This is where voting will decide the order.",
    items: [
      {
        id: "translation",
        title: "Optional translation, marked on the post",
        summary:
          "Translate a post on demand, with a visible badge showing it was machine-translated and what the original language was. Off by default, per-post, never silent.",
        rationale:
          "A decentralized network is multilingual from day one, and a Polish or Arabic post is invisible to most readers without help. The design constraint is honesty and privacy: a translation must never be presented as the author's words, the original must stay one tap away, and sending text to a translation service leaks who read what — so it has to be explicit, per-post, and ideally pointed at an endpoint the user chooses.",
        status: "considering",
        effort: "medium",
        votable: true,
      },
      {
        id: "media",
        title: "Images and media",
        summary: "Attach pictures to a post.",
        rationale:
          "Needs a story for where bytes live — a 280-byte content bound does not stretch to photographs — and for moderation of content nobody can take down.",
        status: "considering",
        effort: "large",
        votable: true,
      },
      {
        id: "nested-threads",
        title: "Nested conversations",
        summary: "Reply to a reply, with the tree preserved.",
        rationale: "Today every reply attaches to the thread root, so depth is lost.",
        status: "considering",
        effort: "medium",
        breaksAddresses: true,
        votable: true,
      },
      {
        id: "search",
        title: "Real search and suggestions",
        summary:
          "Search posts and people for real; Explore and 'who to follow' currently show fixtures.",
        rationale:
          "Needs an index that is not itself a point of control — otherwise whoever runs the index decides what is findable.",
        status: "considering",
        effort: "large",
        votable: true,
      },
      {
        id: "mute-portable",
        title: "Mute list that follows your key",
        summary:
          "Move the mute list into the identity delegate so it travels between devices.",
        rationale:
          "It lives in browser storage today, so importing your key on a new device starts you with an empty list.",
        status: "considering",
        effort: "medium",
        votable: true,
      },
      {
        id: "monotonic-seq",
        title: "Clock-independent ordering",
        summary:
          "Use a counter held by the delegate instead of wall-clock time to order your own edits.",
        rationale:
          "Profile updates resolve last-write-wins by timestamp, so a second device with a fast clock can block writes from the first until real time catches up.",
        status: "considering",
        effort: "medium",
        votable: true,
      },
      {
        id: "encrypted-follows",
        title: "Private follow list",
        summary: "Stop publishing who you follow.",
        rationale:
          "An open social graph is readable by anyone. Encrypting it costs the ability to show follower counts and mutual connections — a real trade, not a free win.",
        status: "considering",
        effort: "large",
        breaksAddresses: true,
        votable: true,
      },
      {
        id: "anonymous-posting",
        title: "Anonymous posting",
        summary: "Post without tying the record to your long-term identity.",
        rationale:
          "Depends on the writer-credential work landing first: without a scarcity cost there is nothing to attach a per-writer limit to.",
        status: "considering",
        effort: "large",
        votable: true,
      },
    ],
  },
];
