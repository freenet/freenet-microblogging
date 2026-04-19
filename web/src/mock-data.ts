import { Post, TrendingTopic, User } from "./types";

export const MOCK_USERS: User[] = [
  { displayName: "Ian Clarke", handle: "sanity", avatarColor: "#3b82f6" },
  { displayName: "Alice Dev", handle: "alice_dev", avatarColor: "#8b5cf6" },
  { displayName: "Bob P2P", handle: "bob_p2p", avatarColor: "#10b981" },
  { displayName: "Freenet Network", handle: "freenet_net", avatarColor: "#f59e0b" },
  { displayName: "Carol Nodes", handle: "carol_nodes", avatarColor: "#ef4444" },
];

const now = new Date();
const mins = (n: number) => new Date(now.getTime() - n * 60 * 1000);
const hours = (n: number) => new Date(now.getTime() - n * 60 * 60 * 1000);
const days = (n: number) => new Date(now.getTime() - n * 24 * 60 * 60 * 1000);

export const MOCK_POSTS: Post[] = [
  {
    id: "1",
    author: MOCK_USERS[0],
    content: "Freenet 0.1.0 is now live! The first decentralized social network where no single entity controls your data. This is what the internet was always meant to be. #Freenet #Decentralized",
    timestamp: mins(5),
    likes: 312,
    reposts: 87,
    replies: 43,
    liked: false,
    reposted: false,
  },
  {
    id: "2",
    author: MOCK_USERS[1],
    content: "Just published a new contract for Freenet that lets you host your personal blog with zero servers. The code is fully open-source. Pull requests welcome! 🚀",
    timestamp: mins(23),
    likes: 89,
    reposts: 34,
    replies: 12,
    liked: true,
    reposted: false,
  },
  {
    id: "3",
    author: MOCK_USERS[2],
    content: "The Freenet routing algorithm is genuinely impressive. Watched a packet find its destination in 4 hops across 10k nodes. The math just works.",
    timestamp: hours(1),
    likes: 145,
    reposts: 52,
    replies: 28,
    liked: false,
    reposted: false,
  },
  {
    id: "4",
    author: MOCK_USERS[3],
    content: "Network stats for today: 14,200 active nodes, 2.3M contract lookups, avg latency 180ms. Growing every day. Join the network at freenet.org",
    timestamp: hours(2),
    likes: 203,
    reposts: 98,
    replies: 17,
    liked: false,
    reposted: true,
  },
  {
    id: "5",
    author: MOCK_USERS[4],
    content: "Hot take: Freenet's small-world network topology is the most elegant solution to censorship-resistant routing I've ever seen. Study the original paper if you haven't.",
    timestamp: hours(4),
    likes: 67,
    reposts: 23,
    replies: 9,
    liked: false,
    reposted: false,
  },
  {
    id: "6",
    author: MOCK_USERS[1],
    content: "Working on a Freenet-native microblogging contract. No central server, no account deletion by a corporation, no shadowbanning. Just you and the network.",
    timestamp: days(1),
    likes: 421,
    reposts: 156,
    replies: 64,
    liked: true,
    reposted: true,
  },
  {
    id: "7",
    author: MOCK_USERS[0],
    content: "The key insight behind Freenet: if you can't tell the difference between a trusted node and an untrusted one, trust doesn't matter. Design the system to be safe even with adversarial nodes.",
    timestamp: days(2),
    likes: 534,
    reposts: 201,
    replies: 89,
    liked: false,
    reposted: false,
  },
  {
    id: "8",
    author: MOCK_USERS[2],
    content: "Just ran a local Freenet node for 24 hours. Used ~400MB of disk and barely any CPU. The overhead is surprisingly low for what it provides.",
    timestamp: days(3),
    likes: 78,
    reposts: 19,
    replies: 5,
    liked: false,
    reposted: false,
  },
];

export const TRENDING_TOPICS: TrendingTopic[] = [
  { category: "Technology", topic: "#Freenet", postCount: 12400 },
  { category: "Decentralized Web", topic: "#P2P", postCount: 8200 },
  { category: "Privacy", topic: "#CensorshipResistance", postCount: 5100 },
  { category: "Open Source", topic: "#FreenetContracts", postCount: 3700 },
];

export const SUGGESTED_USERS: User[] = [
  { displayName: "Freenet Network", handle: "freenet_net", avatarColor: "#f59e0b" },
  { displayName: "Carol Nodes", handle: "carol_nodes", avatarColor: "#ef4444" },
  { displayName: "Dave Crypto", handle: "dave_crypto", avatarColor: "#6366f1" },
];
