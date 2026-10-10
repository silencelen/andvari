// Service-worker reveal gate (security review 2026-10, root cause B). A page can steer two genuine
// clicks through the in-page dropdown, so nothing a TAB sender says may skip the host-match rule:
// a cross-host fill from a page is honoured only through the popup's one-shot grant, which is
// minted by a click in extension-owned UI the page cannot draw over.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { revealGate } from "./revealgate.ts";

test("an explicit reveal from a tab sender whose origin does not match the item is refused", () => {
  assert.equal(revealGate({ fromTab: true, explicit: true, hostMatched: false }), "needs_grant");
});

test("the host-matched tab reveal and the popup's own explicit reveal are unchanged", () => {
  assert.equal(revealGate({ fromTab: true, explicit: false, hostMatched: true }), "allow");
  assert.equal(revealGate({ fromTab: true, explicit: true, hostMatched: true }), "allow");
  // The popup is extension-owned UI: its explicit flag is the user's click on OUR copy/reveal button.
  assert.equal(revealGate({ fromTab: false, explicit: true, hostMatched: false }), "allow");
  assert.equal(revealGate({ fromTab: false, explicit: false, hostMatched: false }), "needs_grant");
  assert.equal(revealGate({ fromTab: true, explicit: false, hostMatched: false }), "needs_grant");
});

// The leaf above passes just as green if reveal() stops calling it, so the call site is pinned too.
const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");
const ct = readFileSync(new URL("./content.ts", import.meta.url), "utf-8");

function spanOf(src: string, from: string, to: string): string {
  const a = src.indexOf(from);
  assert.ok(a > -1, `span start missing: ${from}`);
  const b = src.indexOf(to, a);
  assert.ok(b > a, `span end missing or out of order: ${to}`);
  return src.slice(a, b);
}

test("reveal() decides through revealGate, and no explicit flag short-circuits the host gate", () => {
  const r = spanOf(bg, "function reveal(msg: Extract<", "/** Card copy egress");
  assert.ok(r.includes("revealGate({"), "reveal must route its decision through revealGate");
  assert.ok(!r.includes("msg.explicit === true ||"), "the explicit flag must not be OR-ed ahead of the host match");
});

test("the content script never asks for an explicit reveal", () => {
  assert.ok(!/explicit:\s*true/.test(ct), "content.ts must not send explicit:true");
  assert.ok(!/fill(?:Item|FromDropdown)\([^)]*,\s*true\)/.test(ct), "no in-page fill may request the explicit path");
});
