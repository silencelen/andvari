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

test("the personal wrap decides, and its key is installed first", () => {
  const keys = new Map<string, Uint8Array>([[w.vaultId, new Uint8Array(32).fill(1)]]); // a row served a different key
  const p = pickPersonal({ vaultId: w.vaultId, wrappedVk: w.personalWrapB64 }, uvk, w.userId, keys);
  assert.deepEqual(p, { vaultId: w.vaultId, source: "wrap" });
  assert.equal(toB64(keys.get(w.vaultId)!), w.vkB64);
});

test("an unopenable wrap (the owner wrap served in its place) means NO personal vault, no label fallback", () => {
  const keys = new Map<string, Uint8Array>([[w.vaultId, fromB64(w.vkB64)]]);
  const p = pickPersonal({ vaultId: w.vaultId, wrappedVk: w.ownerWrapB64 }, uvk, w.userId, keys);
  assert.deepEqual(p, { vaultId: "", source: "unreadable" });
});

test("H-1: with no wrap, a label NEVER adopts a vault — not even an own-wrapped one labelled personal and named Personal", () => {
  const vk = fromB64(w.vkB64);
  const row = { vaultId: w.vaultId, type: "personal", metaBlob: toB64(seal(vk, enc(JSON.stringify({ name: "Personal" })), enc(`andvari/v1|vaultmeta|${w.vaultId}`))) };
  // Called in the pre-fix shape (vault rows + member-granted set) on purpose: whatever rows arrive, nothing is adopted.
  const legacyShape = pickPersonal as unknown as (...a: unknown[]) => { vaultId: string };
  assert.equal(legacyShape(null, uvk, w.userId, new Map([[w.vaultId, vk]]), [row], new Set()).vaultId, "");
  assert.ok(adVk(w.vaultId, w.userId).length > 0);
});

test("H-1: a wrap withheld after this device saw one is an anomaly; the cached (UVK-sealed) wrap stands", () => {
  const keys = new Map<string, Uint8Array>();
  const p = pickPersonal(null, uvk, w.userId, keys, { cached: { vaultId: w.vaultId, wrappedVk: w.personalWrapB64 } });
  assert.deepEqual(p, { vaultId: w.vaultId, source: "withheld" });
  assert.equal(toB64(keys.get(w.vaultId)!), w.vkB64);
  // A cached blob that does not open is not adopted either.
  assert.equal(pickPersonal(null, uvk, w.userId, new Map(), { cached: { vaultId: w.vaultId, wrappedVk: w.ownerWrapB64 } }).vaultId, "");
});
