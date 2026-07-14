// node --test (see version.test.ts). Pins the H1 KDF fence (spec 05 T1) and its four numbers, which
// are duplicated VERBATIM from core KdfUpgrade.kt and web keys.ts — a change is a deliberate
// three-file edit. The extension shares no code with core/web, so the fence is re-implemented here.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  assertServerKdfParams,
  DEFAULT_KDF_PARAMS,
  KDF_MAX_MEM_BYTES,
  KDF_MAX_OPS,
  KDF_MIN_MEM_BYTES,
  KDF_MIN_OPS,
  KdfPolicyError,
} from "./crypto.ts";

test("fence numbers match the core + web copies", () => {
  assert.equal(KDF_MIN_MEM_BYTES, 67_108_864);
  assert.equal(KDF_MIN_OPS, 3);
  assert.equal(KDF_MAX_MEM_BYTES, 1_073_741_824);
  assert.equal(KDF_MAX_OPS, 10);
});

test("the honest at-floor default passes (inclusive bounds)", () => {
  assert.doesNotThrow(() => assertServerKdfParams(DEFAULT_KDF_PARAMS));
});

test("below-floor params are rejected as kdf_below_floor", () => {
  assert.throws(
    () => assertServerKdfParams({ v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 }),
    (e: unknown) => e instanceof KdfPolicyError && e.reason === "kdf_below_floor",
  );
});

test("omitted / non-numeric ops or memBytes is rejected, not silently passed (JS bypass guard)", () => {
  assert.throws(
    () => assertServerKdfParams({ v: 1, alg: "argon2id13" } as never),
    (e: unknown) => e instanceof KdfPolicyError && e.reason === "kdf_below_floor",
  );
});

test("above-ceiling params are rejected as kdf_above_ceiling (blocks a 4 GiB SW OOM)", () => {
  assert.throws(
    () => assertServerKdfParams({ v: 1, alg: "argon2id13", ops: 3, memBytes: 2_147_483_648 }),
    (e: unknown) => e instanceof KdfPolicyError && e.reason === "kdf_above_ceiling",
  );
});
