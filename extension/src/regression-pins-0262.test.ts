// Audit 2026-09-13 H41: regression pins for the 0.26.2 (2026-08-30 audit) extension fixes that
// shipped with no test — G14 (the totp SW handler's popup-only gate) and G21 (reader-vault
// write offers). Source-text pins in the background.pins.test.ts idiom: background.ts is not
// node-importable (extensionless imports plus top-level `chrome` side effects), so the wiring
// is pinned on the shipped source and any edit to a pinned line must break THIS file first.
//
// Why G14 needs a pin of its own: the H69 test asserts only that the gate's index precedes
// recordUsage's index — but `indexOf` of a DELETED line is -1, which is less than anything, so
// removing the gate outright stayed green there. Every ordering assertion below first proves both
// anchors present.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");
const content = readFileSync(new URL("./content.ts", import.meta.url), "utf-8");
const popup = readFileSync(new URL("./popup.ts", import.meta.url), "utf-8");
const messages = readFileSync(new URL("./messages.ts", import.meta.url), "utf-8");

/** The slice of `src` from `from` to the next `to` AFTER it (searching past `from` itself, so a
 *  `to` that is a prefix of `from` — `case "` after `case "totp"` — cannot yield an empty span).
 *  Both ends asserted present and in order. */
function spanOf(src: string, from: string, to: string): string {
  const a = src.indexOf(from);
  assert.ok(a > -1, `span start missing: ${from}`);
  const b = src.indexOf(to, a + from.length);
  assert.ok(b > a, `span end missing or out of order: ${to}`);
  return src.slice(a, b);
}

/** `needle` occurs in `hay` — returning its index so ordering can be asserted on a PROVEN hit. */
function at(hay: string, needle: string, why: string): number {
  const i = hay.indexOf(needle);
  assert.ok(i > -1, `${why}: missing \`${needle}\``);
  return i;
}

// ---- G14: the totp handler egresses a live 2FA code — popup only, like every sibling ----

test("G14 — the totp SW handler refuses tab senders BEFORE it looks the item up", () => {
  const handler = spanOf(bg, 'case "totp": {', 'case "');
  const gate = at(handler, 'if (sender.tab !== undefined) return { ok: false } satisfies Res<"totp">;', "the popup-only gate");
  const lookup = at(handler, "session?.items.find((i) => i.itemId === msg.itemId)?.doc.login?.totp", "the item lookup");
  assert.ok(gate < lookup, "the gate must stand ahead of the lookup — a page must never reach the code path at all");
  // The refusal carries no code and no reason: a page probing for itemIds learns nothing from it.
  assert.ok(!handler.slice(gate, lookup).includes("error:"), "the page-sender refusal must be silent");
});

// ---- G21: a reader-vault login is never OFFERED a write the server will refuse ----

test("G21 — buildVaultKeys records each opened grant's role beside its key", () => {
  const build = spanOf(bg, "function buildVaultKeys(", "\nfunction ");
  const keySet = at(build, "vaultKeys.set(g.vaultId, vk);", "the key record");
  const roleSet = at(build, "vaultRoles.set(g.vaultId, g.role);", "the role record");
  assert.ok(keySet < roleSet, "the role is recorded for exactly the vaults whose key opened");
  assert.ok(build.includes("return { vaultKeys, vaultRoles };"), "both maps leave the builder together");
});

test("G21 — writableItem is the one gate, and it reads the recorded role", () => {
  const fn = spanOf(bg, "function writableItem(it: DecryptedItem): boolean {", "\n}");
  assert.ok(fn.includes('return session?.vaultRoles.get(it.vaultId) !== "reader";'), "reader ⇒ not writable; a missing role fails OPEN to the pre-fix behaviour (the server still refuses)");
});

test("G21 — the capture banner never offers Update against a reader-vault match", () => {
  const cap = spanOf(bg, "async function capturedCredential(", "\nasync function ");
  assert.ok(cap.includes("const updatable = existing !== undefined && writableItem(existing) ? existing : undefined;"));
  assert.ok(cap.includes("updatesItemId: updatable?.itemId ?? null,"), "the pending save targets the WRITABLE match only");
  assert.ok(!cap.includes("updatesItemId: existing?.itemId ?? null,"), "the pre-fix shape (any match is an update target) must not return");
});

test("G21 — commitPendingSave lands a reader-vault update as a NEW personal item", () => {
  const commit = spanOf(bg, "async function commitPendingSave(", "\nasync function ");
  const override = at(commit, 'if (decision.kind === "update" && !writableItem(decision.target)) decision = { kind: "create" };', "the reader override");
  const suppress = at(commit, 'if (decision.kind === "suppress") {', "the suppress branch");
  assert.ok(override < suppress, "the override runs before any branch consumes the decision");
});

test("G21 — the page TOTP-add target, linkUri and setTotp all refuse a reader-vault item", () => {
  const target = spanOf(bg, "function pageTotpTarget(", "\n}");
  assert.ok(target.includes("if (!writableItem(it)) return null;"), "pageTotpTarget: no offer at all for a reader item");

  const link = spanOf(bg, "async function linkUri(", "\n}");
  const linkGate = at(link, 'if (!writableItem(it)) return { ok: false, error: "read-only vault" };', "linkUri gate");
  const linkPut = at(link, "putExisting(it, doc)", "linkUri push");
  assert.ok(linkGate < linkPut, "linkUri refuses BEFORE it builds and pushes the doc");

  const set = spanOf(bg, "async function setTotp(", "\n}");
  const setGate = at(set, 'if (!writableItem(target)) return { ok: false, code: "read_only", error: "read-only vault" };', "setTotp gate");
  const setWrite = at(set, "writeTotp(target, msg.totp)", "setTotp write");
  assert.ok(setGate < setWrite, "setTotp refuses BEFORE the write");
});

test("G21 — MatchItem carries readOnly so the page-side surfaces suppress the offers at the source", () => {
  assert.ok(messages.includes("readOnly: boolean;"), "messages.ts: the flag is part of the MatchItem contract");
  const toMatch = spanOf(bg, "function toMatchItem(", "\n}");
  assert.ok(toMatch.includes("readOnly: !writableItem(it),"), "the SW computes it from the same gate");
  assert.ok(content.includes("if (!m.siteMatch && !m.readOnly) {"), "content.ts: no one-tap 'link this site' for a read-only item");
  assert.ok(popup.includes("} else if (!it.readOnly) {"), "popup.ts: no TOTP paste-add affordance for a read-only item");
});

test("G21 — vaultRoles survives a service-worker restart (persisted with the session snapshot)", () => {
  const persist = spanOf(bg, "function persistSession(): Promise<void> {", "\nfunction ");
  assert.ok(persist.includes("vaultRoles: Object.fromEntries(session.vaultRoles),"), "written to the snapshot");
  const load = spanOf(bg, "function ensureLoaded(): Promise<void> {", "\nfunction ");
  assert.ok(load.includes("vaultRoles: new Map(Object.entries(snap.vaultRoles ?? {})),"), "read back — a pre-G21 snapshot defaults to the fail-open pre-fix behaviour");
});
