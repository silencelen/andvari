// Security review 2026-10, root cause A §3.1 — canonical-key precedence in the extension, as narrowed by branch
// A6 (DESIGN-A §1.7, owner decision Q8): the extension takes UVK WRAPS ONLY. Until A6 this file pinned the
// rule "our wrap wins; a v1 seal is used only when there is no wrap; a seal beside an opened wrap is opened to
// compare". Q8 removes the seal from the extension altogether (no fallback, no compare), so the pins now say:
// the key map comes from the UVK-wraps-only leaf (grantkeys.ts, behaviour graded in grantkeys.test.ts), a wrap
// that does not open leaves the vault keyless, and no grant seal is ever opened in the service worker.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");
const leaf = readFileSync(new URL("./grantkeys.ts", import.meta.url), "utf-8");

function spanOf(src: string, from: string, to: string): string {
  const a = src.indexOf(from);
  assert.ok(a > -1, `span start missing: ${from}`);
  const b = src.indexOf(to, a + from.length);
  assert.ok(b > a, `span end missing or out of order: ${to}`);
  return src.slice(a, b);
}

const build = spanOf(leaf, "export function buildVaultKeysFromWraps(", "\nexport function ");

test("A §3.1 / Q8 — both session builders (full unlock, quick-unlock redeem) use the UVK-wraps-only leaf", () => {
  assert.equal(bg.split("buildVaultKeysFromWraps(sync.grants,").length - 1, 2);
  assert.ok(!/function buildVaultKeys\(/.test(bg), "the seal-opening builder is gone");
});

test("A §3.1 — a damaged wrap leaves the vault keyless: recorded, then `continue`, no fallback", () => {
  const i = build.indexOf("keyUnreadable.add(g.vaultId); // damaged or substituted wrap: NO seal fallback");
  assert.ok(i > -1);
  assert.ok(build.slice(i).indexOf("continue;") > 0);
});

test("Q8 — a row without a wrap is only counted as waiting; nothing opens its seal or signed grant", () => {
  assert.ok(build.includes("if (carriesGrant(g)) waiting.add(g.vaultId); // never opened here (Q8)"));
  assert.ok(!/sealedVk!|signedGrant!|sealOpen|openSharedGrant/.test(build));
  assert.ok(build.includes("vaultKeys.set(g.vaultId, vk);"), "the single key record, from the wrap");
});

test("H64 + A §3.2 — a row with any seal/signed grant or a non-owner role is member-granted", () => {
  assert.ok(build.includes('if (carriesGrant(g) || g.role !== "owner") memberGranted.add(g.vaultId);'));
});
