import { describe, it, expect } from "vitest";
import { ROADMAP } from "./roadmap-data";

const items = ROADMAP.flatMap((s) => s.items);

describe("roadmap data", () => {
  it("has unique, stable ids", () => {
    // Ids are the key a vote record will point at, so a duplicate would merge
    // two features' votes and a rename would silently discard them.
    const ids = items.map((i) => i.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("uses slug-shaped ids safe to use as a record key", () => {
    for (const id of items.map((i) => i.id)) {
      expect(id).toMatch(/^[a-z0-9-]+$/);
    }
  });

  it("never opens shipped work for voting", () => {
    // Voting on something already built wastes the signal.
    for (const item of items.filter((i) => i.status === "done")) {
      expect(item.votable).toBe(false);
    }
  });

  it("gives every undecided item a rationale", () => {
    // An item cannot be voted on honestly without saying what it costs.
    for (const item of items.filter((i) => i.status === "considering")) {
      expect(item.rationale, `${item.id} has no rationale`).toBeTruthy();
    }
  });

  it("has something to vote on", () => {
    expect(items.filter((i) => i.votable).length).toBeGreaterThan(0);
  });
});
