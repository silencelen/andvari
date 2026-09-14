import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * H76 (audit 2026-09-13), web half. The server half — `no-cache` on the SPA document, `immutable`
 * on hash-named assets, and a hard 404 for a missing file under /assets/ instead of the index.html
 * fallback — lands in server/App.kt and is pinned by StaticCachingTest. What is left on this side
 * is the screen the reader is actually looking at while it goes wrong: the pre-hydration
 * placeholder says "unsealing…" forever with no bundle running to say anything else, and the first
 * hypothesis a household member forms is that their vault is broken. A reload clears every version
 * of it, so the shell now says so after a delay long enough that it is never a lie.
 *
 * The mechanism matters as much as the copy: the server serves this document under
 * `script-src 'self'` with no 'unsafe-inline', so a setTimeout in the page is not an option — the
 * reveal is a pure-CSS delayed animation. A future "just add a small inline script" would be
 * silently blocked by the CSP in production while working fine in `vite dev`, which is exactly the
 * kind of divergence a pin should catch.
 */
const html = readFileSync(fileURLToPath(new URL("../../index.html", import.meta.url)), "utf8");

describe("the pre-hydration boot shell", () => {
  it("still paints the placeholder React sweeps away", () => {
    expect(html).toContain('<div id="root">');
    expect(html).toContain("Unsealing…");
  });

  it("R06 — the placeholder's wait label is byte-identical to App's, casing included", () => {
    // The comment above the placeholder claims it "mirrors App's loading phase"; H132 recased
    // App's label to "Unsealing…" and left the placeholder lower case, so a cold load painted
    // "unsealing…" and then flipped it in place. Derive the expectation from App rather than
    // re-typing it, so the mirror cannot be broken from either side.
    const app = readFileSync(fileURLToPath(new URL("./App.tsx", import.meta.url)), "utf8");
    const labels = [...app.matchAll(/<Busy>([^<{]*…)<\/Busy>/g)].map((m) => m[1]!);
    const boot = labels.find((l) => /unsealing/i.test(l));
    expect(boot, "App must still render a <Busy> unseal label for the boot phase").toBeTruthy();
    expect(html, "index.html's placeholder must spell it exactly as App does").toContain(`<span>${boot}</span>`);
  });

  it("offers the reload after a delay, in the household voice — no internals, one action", () => {
    expect(html).toContain('<span class="boot-stuck">');
    expect(html).toContain("Reload the page");
    // No jargon on the boot screen: the reader cannot act on a cache header or an asset hash.
    for (const internal of ["Cache-Control", "cache", "hash", "bundle", "MIME"]) {
      const line = html.split("\n").find((l) => l.includes("boot-stuck") && l.includes("</span>"));
      expect(line, "the visible sentence must exist on one line").toBeTruthy();
      expect(line!.includes(internal), `boot copy names an internal: ${internal}`).toBe(false);
    }
  });

  it("the delay is CSS, not script — the document's CSP has no 'unsafe-inline' for scripts", () => {
    expect(html).toMatch(/\.boot-stuck\s*\{[^}]*animation:[^}]*\}/);
    expect(html).toContain("@keyframes boot-stuck");
    // Hidden until it fires: an 8 s reveal that starts visible would accuse a normal cold start.
    expect(html).toMatch(/\.boot-stuck\s*\{[^}]*opacity:\s*0[^}]*\}/);
    // The ONLY <script> tags are the same-origin classic theme boot and the module entry.
    const scripts = html.match(/<script\b[^>]*>/g) ?? [];
    expect(scripts).toEqual(['<script src="/theme-boot.js">', '<script type="module" src="/src/main.tsx">']);
  });
});
