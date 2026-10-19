// Security review 2026-10, branch A11 (q14, MEDIUM): the Save/Update target for a captured password was chosen from
// item metadata a co-member wrote, across EVERY held vault, and the banner never named the vault. A co-member holding
// VK_S plants a login matching the user's personal account; the next password change was offered as "Update <decoy>"
// and sealed under VK_S. Now: a personal-vault match is preferred; the banner names the destination vault; an Update
// into a non-personal vault says so explicitly; and the resolve step never updates into a vault the user did not see
// named (a match the banner did not show lands as a NEW personal item).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { saveOfferCopy } from "./saveoffer.ts";
import { resolveSaveAction, saveTargetFor } from "./savetarget.ts";

const bg = readFileSync(fileURLToPath(new URL("./background.ts", import.meta.url)), "utf-8");
const ui = readFileSync(fileURLToPath(new URL("./content-ui.ts", import.meta.url)), "utf-8");
const P = "00000000-0000-4000-8000-0000000000a1"; // the in-force personal vault
const S = "00000000-0000-4000-8000-0000000000b5"; // a shared vault a co-member writes to
const item = (id: string, vaultId: string, username: string, password: string) => ({ itemId: id, vaultId, doc: { login: { username, password } } });

test("capture: a personal-vault match wins over a co-member's matching decoy, whatever the order", () => {
  const decoy = item("decoy", S, "me@example.com", "old");
  const mine = item("mine", P, "me@example.com", "old");
  assert.equal(saveTargetFor([decoy, mine], "me@example.com", "new", P)?.itemId, "mine");
  assert.equal(saveTargetFor([mine, decoy], "me@example.com", "new", P)?.itemId, "mine");
  // Password-only: a password-equal personal item first, too.
  assert.equal(saveTargetFor([item("d", S, "", "pw"), item("m", P, "", "pw")], "", "pw", P)?.itemId, "m");
  // A shared-only match is still found (the banner will name the vault).
  assert.equal(saveTargetFor([decoy], "me@example.com", "new", P)?.itemId, "decoy");
});

test("resolve: a username match the banner never named, in a non-personal vault, lands as a new personal item", () => {
  const decoy = item("decoy", S, "me@example.com", "old");
  assert.deepEqual(resolveSaveAction(undefined, [decoy], "me@example.com", "new", P), { kind: "create" });
  const mine = item("mine", P, "me@example.com", "old");
  assert.deepEqual(resolveSaveAction(undefined, [decoy, mine], "me@example.com", "new", P), { kind: "update", target: mine });
  // The frozen target is the item the user SAW named, vault included: it still updates.
  assert.deepEqual(resolveSaveAction(decoy, [decoy], "me@example.com", "new", P), { kind: "update", target: decoy });
});

test("the banner names the destination vault, and says so explicitly for a non-personal vault", () => {
  const upd = saveOfferCopy({ host: "example.com", username: "me", updatesItemId: "x", updatesItemName: "Example", updatesItemUsername: "me", vaultName: "Family", vaultShared: true });
  const text = upd.parts.map((p) => p.text).join("");
  assert.ok(text.includes("“Family”") || text.includes("Family"), text);
  assert.match(text, /shared vault/i, text);
  assert.match(text, /can read it|can see it/i, text);
  assert.equal(upd.primary, "Update in Family");
  const own = saveOfferCopy({ host: "example.com", username: "me", updatesItemId: "x", updatesItemName: "Example", updatesItemUsername: "me", vaultName: "Personal", vaultShared: false });
  const ownText = own.parts.map((p) => p.text).join("");
  assert.ok(ownText.includes("Personal") && !/shared vault/i.test(ownText), ownText);
  const save = saveOfferCopy({ host: "example.com", username: "me", updatesItemId: null, updatesItemName: null, updatesItemUsername: null, vaultName: "Personal", vaultShared: false });
  assert.ok(save.parts.map((p) => p.text).join("").includes("Personal"), "a new login names its destination too");
  // No name decrypted: neutral words, never an empty or server label.
  const anon = saveOfferCopy({ host: "example.com", username: "me", updatesItemId: "x", updatesItemName: "E", updatesItemUsername: null, vaultName: null, vaultShared: true });
  assert.match(anon.parts.map((p) => p.text).join(""), /a shared vault/i);
});

test("the worker carries the destination vault, re-checks it at resolve, and the banner renders the shared copy", () => {
  const pub = bg.slice(bg.indexOf("function publicPending("), bg.indexOf("\n}\n", bg.indexOf("function publicPending(")));
  assert.match(pub, /vaultName: p\.vaultName/);
  assert.match(pub, /vaultShared: p\.vaultShared/);
  assert.doesNotMatch(pub, /updatesVaultId/, "the vault id stays SW-side");
  const cap = bg.slice(bg.indexOf("async function capturedCredential("), bg.indexOf("\nasync function ", bg.indexOf("async function capturedCredential(") + 10));
  assert.match(cap, /saveTargetFor\(matchesFor\(host\), username, msg\.password, session\?\.personalVaultId\)/);
  assert.match(cap, /updatesVaultId: updatable\?\.vaultId/);
  const commit = bg.slice(bg.indexOf("async function commitPendingSave("), bg.indexOf("\nasync function ", bg.indexOf("async function commitPendingSave(") + 10));
  assert.match(commit, /frozenTarget/, "the frozen target must still be in the vault the banner named");
  assert.match(commit, /session\.personalVaultId,\n\s*\);/, "resolve prefers the personal vault");
  assert.match(ui, /saveOfferCopy\(/, "the banner text comes from the one pure copy function");
});
