import { describe, expect, it } from "vitest";
import source from "./components/Thread.svelte?raw";

// Regression pin for a stored-XSS fix: Thread.svelte used to render the
// author-chosen (signed, but not sanitized) `author.handle` field via
// `{@html \`@${root.author.handle}...\`}`. A signature proves authorship, not
// safety — a validly-signed post can carry `<img src=x onerror=...>` as its
// handle. Combined with an unrelated identity-delegate bug, viewing one such
// post was enough to exfiltrate the viewer's private key.
//
// There is no component-render test harness in this project (no
// @testing-library/svelte, no DOM test environment configured in
// vite.config.ts), so this is a source-scrape pin rather than a mount test:
// it asserts every `{@html ...}` expression in Thread.svelte is a bare
// ALL_CAPS constant identifier (the ICON_* convention already used for the
// two legitimate hardcoded-SVG uses), never a template literal or a property
// access. A future edit that re-wraps `author.handle`, `formatRelativeTime`,
// or `replies.length` in `{@html}` fails this test. `?raw` (a Vite feature,
// typed by `vite/client`) imports the file's source as a plain string — no
// Node `fs`/`@types/node` needed, which this project does not depend on.

describe("Thread.svelte — no {@html} of attacker-controlled data", () => {
  it("every {@html ...} expression is a bare constant identifier", () => {
    const matches = [...source.matchAll(/\{@html\s+([^}]+?)\s*\}/g)];

    // Fails loudly if the pattern itself disappears (e.g. file renamed,
    // markup restructured) rather than silently passing on zero matches.
    expect(matches.length).toBeGreaterThan(0);

    for (const [, expr] of matches) {
      expect(expr).toMatch(/^[A-Z][A-Z0-9_]*$/);
    }
  });

  it("author.handle, formatRelativeTime, and replies.length never appear inside {@html}", () => {
    const dangerous = [
      /\{@html[^}]*author\.handle/,
      /\{@html[^}]*formatRelativeTime/,
      /\{@html[^}]*replies\.length/,
    ];
    for (const pattern of dangerous) {
      expect(source).not.toMatch(pattern);
    }
  });
});
