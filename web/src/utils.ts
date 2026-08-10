/**
 * Maximum post/reply length the contracts accept.
 *
 * MUST equal `MAX_CONTENT_LEN` in common/src/post.rs. The contracts bound
 * `content.len()`, which in Rust is the UTF-8 BYTE length — so this is a byte
 * budget, not a character count, and `contentLength` below measures it the same
 * way. A post over it is signed happily by the delegate and then dropped in
 * silence by the shard, which at the UI is indistinguishable from a lost write.
 */
export const MAX_CONTENT_BYTES = 280;

/**
 * Length of `text` as the contracts measure it: UTF-8 bytes.
 *
 * `String.length` counts UTF-16 code units, which under-counts every non-ASCII
 * character — "ą" is 1 there and 2 bytes on the wire, an emoji is 2 there and 4
 * on the wire. Using it as the budget let a composer that looked well inside
 * the limit produce a post the contract refused.
 */
export function contentLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

export function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  if (diffMin < 1) return "now";
  if (diffMin < 60) return `${diffMin}m`;
  if (diffHour < 24) return `${diffHour}h`;
  if (diffDay < 7) return `${diffDay}d`;

  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${months[date.getMonth()]} ${date.getDate()}`;
}
