/**
 * mute.ts — local, private mute list.
 *
 * WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT
 *
 * On a decentralized network nobody can take another person's posts off the
 * network, and this file does not pretend otherwise. What it does is give
 * the reader control over their own attention: a muted key's posts and replies
 * stop being rendered here. The record stays on the network, fully valid,
 * readable by anyone else. Muting is not deletion and is not moderation.
 *
 * That distinction matters enough to state plainly, because the alternative
 * designs are worse:
 *
 *   - A blocklist stored in the user shard would be PUBLIC — the shard is
 *     world-readable. Publishing "who I am avoiding" discloses a social
 *     signal the reader never chose to share, turning a personal preference
 *     into public information.
 *   - A contract-enforced block cannot work at all: thread and inbox shards are
 *     anyone-writes by design (ADR-0001). A contract cannot refuse a validly
 *     signed record on the basis of a list the writer can simply ignore.
 *
 * So the mute list is kept where it can be honest about its scope: locally,
 * never replicated, never signed, never announced.
 *
 * KNOWN LIMITATION — storage location
 *
 * This uses localStorage, which means the list is per-browser and does not
 * travel with an imported identity. The architecturally correct home is the
 * identity delegate: ADR-0001 already says delegate state is "private and local
 * — not replicated", which is exactly this list's requirement, and it would
 * then follow the key across devices. That needs new delegate requests and a
 * secret-store schema change, so it is left as a follow-up rather than blocking
 * the ability to mute anyone at all today.
 *
 * Muting keys the AUTHOR'S VERIFYING KEY, never the handle. Handles are
 * self-declared and unverifiable (no registry contract yet), so muting "@bob"
 * would mute an impersonator and miss the real one.
 */

import { writable } from "svelte/store";

const STORAGE_KEY = "raven.muted.v1";

/** Hex ML-DSA-65 verifying keys whose content this reader has muted. */
export const muted = writable<Set<string>>(load());

function load(): Set<string> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return new Set();
    const parsed: unknown = JSON.parse(raw);
    // Tolerate anything: this is user-editable storage, and a corrupt entry
    // must not take the app down on boot.
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed.filter((k): k is string => typeof k === "string"));
  } catch {
    // Private browsing / storage disabled: mute still works for the session.
    return new Set();
  }
}

function persist(keys: Set<string>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify([...keys]));
  } catch {
    // Storage unavailable — the in-memory store is still authoritative for
    // this session, so muting works, it just will not survive a reload.
  }
}

/** Mute or unmute an author by their hex verifying key. */
export function setMuted(pubkey: string, on: boolean): void {
  if (!pubkey) return;
  muted.update((prev) => {
    const next = new Set(prev);
    if (on) next.add(pubkey);
    else next.delete(pubkey);
    persist(next);
    return next;
  });
}

/**
 * Drop posts authored by a muted key.
 *
 * Applied at render time rather than at ingest, so unmuting restores the feed
 * immediately without re-fetching, and so a mute never causes the client to
 * diverge from the network state it actually holds.
 */
export function filterMuted<T extends { author: { publicKey?: string } }>(
  posts: T[],
  mutedKeys: Set<string>,
): T[] {
  if (mutedKeys.size === 0) return posts;
  return posts.filter((p) => !p.author.publicKey || !mutedKeys.has(p.author.publicKey));
}
