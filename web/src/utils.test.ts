import { describe, it, expect } from "vitest";
import { MAX_CONTENT_BYTES, contentLength } from "./utils";

describe("content length budget", () => {
  it("matches the contract's MAX_CONTENT_LEN", () => {
    // Pinned to common/src/post.rs. If that constant moves, this fails loudly
    // instead of the composer silently producing posts the shard drops.
    expect(MAX_CONTENT_BYTES).toBe(280);
  });

  it("counts UTF-8 bytes, not UTF-16 code units", () => {
    // ASCII: the two agree.
    expect(contentLength("hello")).toBe(5);
    // Latin-2: 1 code unit, 2 bytes. `.length` would say 5.
    expect("zażółć".length).toBe(6);
    expect(contentLength("zażółć")).toBe(10);
    // Emoji outside the BMP: 2 code units, 4 bytes. `.length` would say 2.
    expect("🦊".length).toBe(2);
    expect(contentLength("🦊")).toBe(4);
  });

  it("a post that looks legal by .length can be over the byte budget", () => {
    // 200 two-byte characters: well under 280 by `.length`, over it on the wire.
    const text = "ą".repeat(200);
    expect(text.length).toBeLessThan(MAX_CONTENT_BYTES);
    expect(contentLength(text)).toBeGreaterThan(MAX_CONTENT_BYTES);
  });
});
