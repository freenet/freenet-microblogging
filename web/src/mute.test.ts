import { describe, it, expect, beforeEach, vi } from "vitest";
import { get } from "svelte/store";

// mute.ts reads localStorage at module load, so stub it before importing.
const store = new Map<string, string>();
vi.stubGlobal("localStorage", {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k),
});

const { muted, setMuted, filterMuted } = await import("./mute");

const KEY_A = "aa".repeat(1952);
const KEY_B = "bb".repeat(1952);
const post = (pubkey?: string) => ({ author: { publicKey: pubkey } });

describe("mute list", () => {
  beforeEach(() => {
    for (const k of get(muted)) setMuted(k, false);
  });

  it("mutes and unmutes by verifying key", () => {
    setMuted(KEY_A, true);
    expect(get(muted).has(KEY_A)).toBe(true);
    setMuted(KEY_A, false);
    expect(get(muted).has(KEY_A)).toBe(false);
  });

  it("persists across a reload", () => {
    setMuted(KEY_A, true);
    // What was written is what a fresh load would read back.
    expect(JSON.parse(store.get("raven.muted.v1")!)).toContain(KEY_A);
  });

  it("filters only the muted author's posts", () => {
    setMuted(KEY_A, true);
    const feed = [post(KEY_A), post(KEY_B), post(KEY_A)];
    expect(filterMuted(feed, get(muted))).toEqual([post(KEY_B)]);
  });

  it("keeps posts with no author key rather than hiding them", () => {
    // Offline/mock posts carry no verifying key. Dropping them would make mute
    // silently eat unrelated content.
    setMuted(KEY_A, true);
    expect(filterMuted([post(undefined)], get(muted)).length).toBe(1);
  });

  it("is a no-op allocation-wise when nothing is muted", () => {
    const feed = [post(KEY_A)];
    expect(filterMuted(feed, new Set())).toBe(feed);
  });
});
