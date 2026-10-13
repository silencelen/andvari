// Security review 2026-10 (plugin scan F1/F2; branch A10): the extension's storage.local trust records (item homes,
// the personal-wrap cache, a pending personal change) are decoded STRICTLY — every id re-checked against the UUID
// grammar on the way out of storage — and a value that had to be cleaned is flagged for a one-time rewrite.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { decodeItemHomes, decodePersonalChange, decodePersonalWrap, encodeItemHomes } from "./trustrecords.ts";

const v1 = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const v2 = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const i1 = "33333333-3333-4333-8333-333333333333";
const i2 = "44444444-4444-4444-8444-444444444444";

test("A10: item homes keep only UUID→UUID pairs and flag a cleaned record for rewrite", () => {
  const clean = decodeItemHomes({ [i1]: v1, [i2]: v2 });
  assert.deepEqual([...clean.value], [[i1, v1], [i2, v2]]);
  assert.equal(clean.rewrite, false);
  const dirty = decodeItemHomes({ [i1]: v1, [`${i2}\n${i1}`]: v2, [i2]: `${v2}|x`, "not-an-id": v1, [v1]: 7 });
  assert.deepEqual([...dirty.value], [[i1, v1]]);
  assert.equal(dirty.rewrite, true);
  assert.deepEqual(encodeItemHomes(new Map([[i1, v1], [`${i2}\n`, v2], [i2, "bad"]])), { [i1]: v1 });
  assert.deepEqual(decodeItemHomes(undefined), { value: new Map(), rewrite: false });
  assert.equal(decodeItemHomes("junk").rewrite, true);
  assert.equal(decodeItemHomes([[i1, v1]]).rewrite, true);
});

test("A10: the personal-wrap cache is exactly {vaultId (UUID), wrappedVk}", () => {
  assert.deepEqual(decodePersonalWrap({ vaultId: v1, wrappedVk: "w" }), { value: { vaultId: v1, wrappedVk: "w" }, rewrite: false });
  assert.deepEqual(decodePersonalWrap(undefined), { value: null, rewrite: false });
  for (const bad of [{ vaultId: `${v1}\n${v2}`, wrappedVk: "w" }, { vaultId: v1, wrappedVk: 5 }, { vaultId: v1, wrappedVk: "w", extra: 1 }, { vaultId: v1 }, "junk", [v1, "w"]]) {
    assert.deepEqual(decodePersonalWrap(bad), { value: null, rewrite: true }, JSON.stringify(bad));
  }
});

test("A10: a pending personal change carries a UUID served vault, a UUID-or-empty current vault, and ciphertext names only", () => {
  const full = { vaultId: v1, wrappedVk: "w", currentVaultId: v2, currentMetaBlob: "m1", servedMetaBlob: "m2" };
  assert.deepEqual(decodePersonalChange(full), { value: full, rewrite: false });
  const proposed = { vaultId: v1, wrappedVk: "w", currentVaultId: "", servedMetaBlob: "m2" };
  assert.deepEqual(decodePersonalChange(proposed), { value: proposed, rewrite: false });
  assert.deepEqual(decodePersonalChange(null), { value: null, rewrite: false });
  for (const bad of [
    { ...full, vaultId: `${v1}|x` },
    { ...full, currentVaultId: `${v2}\n${v1}` },
    { ...full, currentMetaBlob: 3 },
    { ...full, unknown: "k" },
    { wrappedVk: "w", currentVaultId: v2 },
  ]) {
    assert.deepEqual(decodePersonalChange(bad), { value: null, rewrite: true }, JSON.stringify(bad));
  }
});
