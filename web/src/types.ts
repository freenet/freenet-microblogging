export interface Post {
  id: string;
  author: User;
  content: string;
  timestamp: Date;
  likes: number;
  reposts: number;
  replies: number;
  liked: boolean;
  reposted: boolean;
}

export interface User {
  displayName: string;
  handle: string;
  avatarColor?: string;
  publicKey?: string;
}

export interface TrendingTopic {
  category: string;
  topic: string;
  postCount: number;
}
