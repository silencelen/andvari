// Security review 2026-10, root cause A §4 / §8.5 (branch A5): the extension's personal-vault pick.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { adVk, fromB64, seal, toB64 } from "./crypto.ts";
import { pickPersonal } from "./personalpick.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "personalwrap.json", "utf-8"));
const w = v.wrap;
const uvk = fromB64(w.uvkB64);
const enc = (s: string) => new TextEncoder().encode(s);
const meta = (vk: Uint8Array, vaultId: string, name: string) => toB64(seal(vk, enc(JSON.stringify({ name })), enc(`andvari/v1|vaultmeta|${vaultId}`)));
const OTHER = "a2222222-2222-4222-8222-222222222222";

test("the personal wrap decides, and its key is installed first", () => {
  const keys = new Map<string, Uint8Array>([[w.vaultId, new Uint8Array(32).fill(1)]]); // a row served a different key
  const p = pickPersonal({ vaultId: w.vaultId, wrappedVk: w.personalWrapB64 }, uvk, w.userId, keys, [{ vaultId: OTHER, type: "personal" }], new Set());
  assert.deepEqual(p, { vaultId: w.vaultId, source: "wrap" });
  assert.equal(toB64(keys.get(w.vaultId)!), w.vkB64);
});

test("an unopenable wrap (the owner wrap served in its place) means NO personal vault, no label fallback", () => {
  const vk = fromB64(w.vkB64);
  const keys = new Map<string, Uint8Array>([[w.vaultId, vk]]);
  const p = pickPersonal({ vaultId: w.vaultId, wrappedVk: w.ownerWrapB64 }, uvk, w.userId, keys, [{ vaultId: w.vaultId, type: "personal", metaBlob: meta(vk, w.vaultId, "Personal") }], new Set());
  assert.deepEqual(p, { vaultId: "", source: "unreadable" });
});

test("no wrap: the strict §8.5 rule adopts only one own-wrapped vault labelled personal and named Personal", () => {
  const vk = fromB64(w.vkB64);
  const vk2 = new Uint8Array(32).fill(2);
  const row = { vaultId: w.vaultId, type: "personal", metaBlob: meta(vk, w.vaultId, "Personal") };
  assert.equal(pickPersonal(null, uvk, w.userId, new Map([[w.vaultId, vk]]), [row], new Set()).vaultId, w.vaultId);
  // A relabelled owner-created shared vault ("Household") is not adopted.
  const relabel = { vaultId: OTHER, type: "personal", metaBlob: meta(vk2, OTHER, "Household") };
  assert.equal(pickPersonal(null, uvk, w.userId, new Map([[OTHER, vk2]]), [relabel], new Set()).vaultId, "");
  // Two labelled candidates: ambiguous, nothing adopted.
  const twin = { vaultId: OTHER, type: "personal", metaBlob: meta(vk2, OTHER, "Personal") };
  assert.equal(pickPersonal(null, uvk, w.userId, new Map([[w.vaultId, vk], [OTHER, vk2]]), [row, twin], new Set()).vaultId, "");
  // A member-granted (seal-delivered) vault is never a candidate.
  assert.equal(pickPersonal(null, uvk, w.userId, new Map([[OTHER, vk2]]), [twin], new Set([OTHER])).vaultId, "");
  assert.ok(adVk(w.vaultId, w.userId).length > 0);
});
