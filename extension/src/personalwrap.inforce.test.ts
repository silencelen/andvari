// Security review 2026-10, branch A11 (q13, MEDIUM): a served personal wrap's vault key is installed into the live key
// map ONLY once that wrap is in force. The server keeps every wrap the account ever minted and chooses which to serve; a
// superseded wrap for a co-held vault S the user has since left used to put VK_S into the session in EVERY branch,
// CHANGED and PROPOSED included, so items the server kept serving under S decrypted, matched captures, became
// Update/TOTP-add targets and were re-sealed under VK_S for the co-holder. While proposed or changed, the served key is
// used for nothing; it is installed by the popup's accept (which re-opens the wrap under the UVK). Also: `writableItem`
// fails CLOSED for a vault with no role entry (only the in-force personal vault needs none).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { adVkPersonal, fromB64, seal, toB64 } from "./crypto.ts";
import { pickPersonal } from "./personalpick.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "personalwrap.json", "utf-8"));
const w = v.wrap;
const uvk = fromB64(w.uvkB64);
const bg = readFileSync(fileURLToPath(new URL("./background.ts", import.meta.url)), "utf-8");

const S = "00000000-0000-4000-8000-0000000000b5";
const superseded = { vaultId: S, wrappedVk: toB64(seal(uvk, new Uint8Array(32).fill(7), adVkPersonal(S, w.userId))) };
const cachedP = { vaultId: w.vaultId, wrappedVk: w.personalWrapB64 };

test("PROPOSED (fresh browser): the served wrap's key is NOT installed", () => {
  const keys = new Map<string, Uint8Array>();
  const p = pickPersonal(superseded, uvk, w.userId, keys);
  assert.equal(p.source, "proposed");
  assert.equal(keys.has(S), false, "a proposal puts nothing in force, not even a key for reading");
  assert.equal(keys.size, 0);
});

test("CHANGED (cached P, served superseded S): only the cached, in-force key is installed", () => {
  const keys = new Map<string, Uint8Array>();
  const p = pickPersonal(superseded, uvk, w.userId, keys, { cached: cachedP });
  assert.equal(p.source, "changed");
  assert.equal(keys.has(S), false, "VK_S stays out of the key map until the human accepts the change");
  assert.equal(toB64(keys.get(w.vaultId)!), w.vkB64, "the cached personal vault stays in force");
});

test("a grant-row key the session already holds for the served vault is left as it was", () => {
  const rowKey = new Uint8Array(32).fill(9); // the vault is genuinely held through this account's own grant row
  const keys = new Map<string, Uint8Array>([[S, rowKey]]);
  pickPersonal(superseded, uvk, w.userId, keys, { cached: cachedP });
  assert.equal(keys.get(S), rowKey, "the pick neither adds nor replaces a key for a vault it does not put in force");
});

test("IN FORCE (served == cached): the served key is installed (precedence rule 1)", () => {
  const keys = new Map<string, Uint8Array>([[w.vaultId, new Uint8Array(32).fill(1)]]);
  assert.equal(pickPersonal(cachedP, uvk, w.userId, keys, { cached: cachedP }).source, "wrap");
  assert.equal(toB64(keys.get(w.vaultId)!), w.vkB64);
});

test("writableItem fails closed with no role entry (only the in-force personal vault needs none)", () => {
  const a = bg.indexOf("function writableItem(");
  assert.ok(a >= 0);
  const body = bg.slice(a, bg.indexOf("\n}\n", a));
  assert.doesNotMatch(body, /vaultRoles\.get\(it\.vaultId\) !== "reader"/, "no longer `role !== \"reader\"` alone (undefined would pass)");
  assert.match(body, /role === undefined/, "a missing role is decided explicitly");
  assert.match(body, /session\.personalVaultId/, "the in-force personal vault is the one exception");
});

test("the popup still names a proposed vault without installing its key (re-open for the name only)", () => {
  const a = bg.indexOf("async function personalChangeText(");
  const body = bg.slice(a, bg.indexOf("\n}\n", a));
  assert.match(body, /reopenStagedPersonalWrap\(/, "the name decrypts under a key re-opened for that purpose");
  assert.doesNotMatch(body, /vaultKeys\.set\(/, "and nothing is installed");
});
