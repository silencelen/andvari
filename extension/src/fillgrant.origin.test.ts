// Security review 2026-10, branch A13 (q39, LOW): the popup's one-shot login fill grant was bound to (tabId, itemId)
// only and survived a top-level navigation, so whichever document occupied the tab's top frame when the content
// script's reveal() ran could redeem it — including a different origin than the one the user picked the login for.
// It now carries the card grant's bindings: the top origin at mint, sender.origin equality at redemption, and a
// navigation voids it. Source pins: background.ts touches chrome.* and cannot run under node.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const bg = readFileSync(fileURLToPath(new URL("./background.ts", import.meta.url)), "utf-8");
const between = (a: string, b: string) => {
  const i = bg.indexOf(a);
  assert.ok(i > -1, `missing: ${a}`);
  return bg.slice(i, bg.indexOf(b, i));
};

test("the grant records the tab's top origin at mint, and an opaque top is never eligible", () => {
  assert.match(bg, /const grants = new Map<number, \{ itemId: string; origin: string; expiresMs: number \}>\(\);/);
  const mint = between("async function fillFromPopup(", "// ---- S3 in-page card fill");
  const top = mint.indexOf("const top = await topOrigin(tab.id);");
  const refuse = mint.indexOf("if (top === null) return");
  const set = mint.indexOf("grants.set(tab.id, { itemId, origin: top,");
  assert.ok(top > -1 && refuse > top && set > refuse, "read the top origin, refuse null, then mint with it");
});

test("redemption requires sender.origin to equal the minted origin", () => {
  const reveal = between("function reveal(", "let totpCode");
  assert.ok(reveal.includes('typeof sender.origin === "string" && sender.origin === g.origin'), "origin-bound redemption");
});

test("a top-level navigation voids the login grant, as it does the card grant", () => {
  const nav = between('chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {\n  if (changeInfo.status !== "loading") return;', "topOriginPendingClear.add(tabId);");
  assert.ok(nav.includes("grants.delete(tabId);"), "login grant cleared on loading");
  assert.ok(nav.includes("cardGrants.delete(tabId);"));
});
