// The extension's OWN shared-vector run (node --test, cycle-5 harness) — before this the
// extension mirror was only ever verified transitively via the web copy staying identical.
// Runs BOTH spec vector files: urimatch.json (byte-frozen originals) and urimatch-etld1.json
// (the eTLD+1 amendment), plus the A6 runtime-hash drift guard.
import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { pslResolve, PSL_SNAPSHOT_HASH } from "./psl.ts";
import { PSL_RULES_JOINED } from "./pslData.ts";
import { matches, parseSavedUri, RESOLVE_UNKNOWN } from "./urimatch.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "urimatch.json", "utf-8"));
const v2 = JSON.parse(readFileSync(vectorsDir + "urimatch-etld1.json", "utf-8"));

test("urimatch.json byte-frozen outcomes hold — real resolver AND RESOLVE_UNKNOWN", () => {
  for (const resolve of [pslResolve, RESOLVE_UNKNOWN]) {
    for (const c of v.match) {
      const saved = parseSavedUri(c.savedUri);
      const actual = saved !== null && matches(saved, { webHost: c.webHost ?? null, packageName: c.packageName }, resolve);
      assert.equal(actual, c.expected, `${c.savedUri} @ ${c.webHost}/${c.packageName}`);
    }
  }
});

test("A6: snapshot hash matches the RUNTIME rule string", () => {
  assert.equal(PSL_SNAPSHOT_HASH, v2.snapshotHash);
  const runtime = createHash("sha256").update(PSL_RULES_JOINED, "ascii").digest("hex");
  assert.equal(runtime, v2.snapshotHash, "sha256 of the loaded joined rule string");
});

test("urimatch-etld1.json registrable vectors", () => {
  for (const c of v2.registrable) {
    const r = pslResolve(c.host);
    assert.equal(r.kind, c.kind, `resolve(${c.host}).kind`);
    if (c.kind === "registrable") assert.equal(r.kind === "registrable" && r.domain, c.domain, `resolve(${c.host}).domain`);
  }
});

test("urimatch-etld1.json match vectors (R-SUFFIX-BARE, R-EQ, R-OLD)", () => {
  for (const c of v2.match) {
    const saved = parseSavedUri(c.savedUri);
    const actual = saved !== null && matches(saved, { webHost: c.webHost ?? null, packageName: c.packageName }, pslResolve);
    assert.equal(actual, c.expected, `${c.savedUri} @ ${c.webHost}`);
  }
});
