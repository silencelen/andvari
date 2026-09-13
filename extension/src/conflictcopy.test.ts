// node --test. Pins the extension's conflict-copy twin (H20, 2026-09-13 audit) against the frozen
// cross-engine vectors: a divergence from core ConflictCopy.id / web conflictCopyId would not
// fail loudly — it would silently mint a SECOND copy per conflict on every other client.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { conflictCopyId, conflictCopyName } from "./conflictcopy.ts";

const vectors = JSON.parse(readFileSync(fileURLToPath(new URL("../../spec/test-vectors/conflictcopy.json", import.meta.url)), "utf-8")) as {
  cases: { itemId: string; rev: number; copyId: string }[];
};

test("conflictcopy.json — conflictCopyId == core ConflictCopy.id == web conflictCopyId", () => {
  assert.ok(vectors.cases.length >= 4, "the vector file carries cases");
  for (const c of vectors.cases) assert.equal(conflictCopyId(c.itemId, c.rev), c.copyId, `itemId=${c.itemId} rev=${c.rev}`);
});

test("conflictCopyId is UUIDv4-shaped (the server's item-id validator) and deterministic", () => {
  const id = conflictCopyId("0b7aa1e4-31f5-4f0a-9a6e-0e6a3a3d7d10", 7);
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(conflictCopyId("0b7aa1e4-31f5-4f0a-9a6e-0e6a3a3d7d10", 7), id);
  assert.notEqual(conflictCopyId("0b7aa1e4-31f5-4f0a-9a6e-0e6a3a3d7d10", 8), id); // keyed on the WINNER rev
});

test("conflictCopyName stamps the displaced version's UTC day, spec 03 §5 shape (web store.ts twin)", () => {
  assert.equal(conflictCopyName("Netflix", Date.UTC(2026, 8, 13, 23, 59, 0)), "Netflix (conflict 2026-09-13)");
  assert.equal(conflictCopyName("Netflix", Date.UTC(2026, 8, 14, 0, 0, 1)), "Netflix (conflict 2026-09-14)");
});
