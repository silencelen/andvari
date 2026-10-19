// Security review 2026-10, branch A11 (extension runner of `personalwrap.json` `decision`; core
// `PersonalDecisionVectorTest` / web `personaldecision.vectors.test.ts` twins). The extension has no account-state
// designation reader (spec 05 R14(e)), so it runs exactly the designation-null rows: for those, its pick must agree
// with the full clients (c00 cannot arise here: with no designation, a withheld or unopenable served wrap leaves the
// cached wrap in force on every engine).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { adVkPersonal, fromB64, seal, toB64 } from "./crypto.ts";
import { pickPersonal, type PersonalWrapWire } from "./personalpick.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "personalwrap.json", "utf-8"));
const w = v.wrap;
const uvk = fromB64(w.uvkB64);
const A = w.vaultId as string;
const C = "00000000-0000-4000-8000-0000000000c1";
const wraps: Record<string, PersonalWrapWire> = {
  A: { vaultId: A, wrappedVk: w.personalWrapB64 },
  C: { vaultId: C, wrappedVk: toB64(seal(uvk, new Uint8Array(32).fill(9), adVkPersonal(C, w.userId))) },
  junk: { vaultId: A, wrappedVk: w.ownerWrapB64 }, // an owner wrap (Ad.vk): never opens as a personal wrap
};
const STATUS: Record<string, string> = { wrap: "confirmed", none: "absent" };
const sym = (id: string | undefined | null) => (id === A ? "A" : id === C ? "C" : id ?? null);

interface Row {
  name: string;
  served: string;
  cached: string;
  designation: string | null;
  expected: { status: string; inForce: string; pending: string | null };
}

const rows = (v.decision as Row[]).filter((r) => r.designation === null);

test("the designation-free decision rows exist", () => {
  assert.ok(rows.length >= 5, `${rows.length} rows`);
});

for (const row of rows) {
  test(`decision: ${row.name}`, () => {
    const p = pickPersonal(row.served === "none" ? null : wraps[row.served], uvk, w.userId, new Map(), { cached: row.cached === "none" ? null : wraps[row.cached] });
    assert.equal(STATUS[p.source] ?? p.source, row.expected.status, "status");
    assert.equal(sym(p.vaultId), row.expected.inForce, "in force");
    assert.equal("served" in p ? sym(p.served.vaultId) : null, row.expected.pending, "pending");
  });
}
