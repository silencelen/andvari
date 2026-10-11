// Security review 2026-10, root cause A §3.1: canonical-key precedence in the extension's
// buildVaultKeys. Source-text pins in the background.pins.test.ts idiom (background.ts is not
// node-importable); the behaviour itself is proven against the real crypto by core
// VaultKeyPrecedenceTest and web key-precedence.test.ts, whose rule this builder twins.
//
// The rule: our own UVK wrap wins whenever the row carries one; a server-mintable v1 seal is used
// only when there is no wrap; a seal that disagrees with an opened wrap is refused and recorded;
// and a wrap that does not open leaves the vault keyless — never a fallback to the seal.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");

function spanOf(src: string, from: string, to: string): string {
  const a = src.indexOf(from);
  assert.ok(a > -1, `span start missing: ${from}`);
  const b = src.indexOf(to, a + from.length);
  assert.ok(b > a, `span end missing or out of order: ${to}`);
  return src.slice(a, b);
}

function at(hay: string, needle: string, why: string): number {
  const i = hay.indexOf(needle);
  assert.ok(i > -1, `${why}: missing \`${needle}\``);
  return i;
}

const build = spanOf(bg, "function buildVaultKeys(", "\nfunction ");

test("A §3.1 — the UVK wrap is tried first; the seal is the else-branch, never the first choice", () => {
  const wrapBranch = at(build, "if (g.wrappedVk) {", "the wrap branch");
  const sealBranch = at(build, "} else if (g.sealedVk) {", "the legacy seal branch");
  assert.ok(wrapBranch < sealBranch, "the wrap must be decided before any seal is adopted");
  // The pre-fix shape opened the seal first whenever one was present — it must not return.
  assert.ok(!build.includes("if (g.sealedVk) {\n        // Member grant"), "the seal-first branch must not come back");
});

test("A §3.1 — a damaged wrap leaves the vault keyless: recorded, then `continue`, before any seal", () => {
  const wrapBranch = spanOf(build, "if (g.wrappedVk) {", "} else if (g.sealedVk) {");
  const unreadable = at(wrapBranch, "keyUnreadable.add(g.vaultId); // damaged or substituted wrap: NO seal fallback", "the unreadable record");
  const bail = at(wrapBranch.slice(unreadable), "continue;", "the bail-out");
  assert.ok(bail > 0, "the damaged-wrap path must leave the loop iteration");
  const compare = at(wrapBranch, "if (sealVk !== null && !sameKey(sealVk, vk)) vkMismatch.add(g.vaultId);", "the seal comparison");
  assert.ok(unreadable < compare, "the seal is only ever opened AFTER the wrap opened, and only to compare");
});

test("A §3.1 — a mismatching seal never reaches vaultKeys; the wrapped key is the one set", () => {
  const wrapBranch = spanOf(build, "if (g.wrappedVk) {", "} else if (g.sealedVk) {");
  assert.ok(!wrapBranch.includes("vk = sealVk"), "the compare branch must never adopt the seal's key");
  assert.ok(!wrapBranch.includes("vaultKeys.set("), "nothing is stored inside the compare branch");
  at(build, "vaultKeys.set(g.vaultId, vk);", "the single key record");
});

test("H64 + A §3.2 — a row with any seal or a non-owner role is member-granted, even when the wrap opened", () => {
  at(build, 'if (viaSeal || g.sealedVk || g.role !== "owner") memberGranted.add(g.vaultId);', "the widened provenance rule");
});
