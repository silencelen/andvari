// The extension's OWN run of spec/test-vectors/itemhome.json (node --test) — the same rows core ItemHomeVectorTest and
// web vault/itemhome.vectors.test.ts grade (security review 2026-10, root cause A §5; branch A1b). The service worker's
// resync/unlock paths call admitRows and its put path calls sealGate; both are graded here, plus a source pin that the
// worker really routes through them.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { admitRow, admitRows, conflictDecision, editDecision, sealDecision, sealGate, serverItemDecision, WRONG_VAULT_LINE, wrongVaultLine } from "./itemhome.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
type Row = { itemId: string; vaultId: string; deleted?: boolean; conflict?: boolean; unheld?: boolean };
const v = JSON.parse(readFileSync(vectorsDir + "itemhome.json", "utf8")) as {
  admit: { name: string; home: string | null; vaultId: string; applies?: boolean; expect: string }[];
  pulls: { name: string; homes: Record<string, string>; rows: Row[]; expect: { verdicts: string[]; homes: Record<string, string>; anomalies: number; materialize: { itemId: string; vaultId: string }[] } }[];
  conflict: { name: string; twin: string | null; flagged: string; home: string | null; expect: string }[];
  serverItem: { name: string; pushed: string; losing: string; home: string | null; expect: string }[];
  edit: { name: string; home: string | null; editor: string | null; expect: string }[];
  seal: { name: string; home: string | null; vaultId: string; expect: string }[];
};

test("itemhome.json admit rows", () => {
  for (const c of v.admit) assert.equal(admitRow(c.home, c.vaultId, c.applies ?? true), c.expect, c.name);
});

test("itemhome.json pulls, through admitRows (the worker's resync/unlock path)", () => {
  assert.ok(v.pulls.some((p) => p.name.startsWith("§5.3 fixture, flagged")) && v.pulls.some((p) => p.name.startsWith("§5.3 fixture, genuine")));
  for (const c of v.pulls) {
    const homes = new Map(Object.entries(c.homes));
    const shadow = new Map(homes);
    // A9: a row applies only when it is live and under a vault this device holds the key for (the worker also needs
    // the envelope to open; the vectors cannot express that, the applied test does).
    const applies = (r: Row) => !r.deleted && !r.unheld;
    const verdicts = c.rows.map((r) => {
      const verdict = admitRow(shadow.get(r.itemId), r.vaultId, applies(r));
      if (verdict === "new_home") shadow.set(r.itemId, r.vaultId);
      return verdict;
    });
    const { admitted, tally } = admitRows(c.rows, homes, applies);
    assert.deepEqual(verdicts, c.expect.verdicts, `${c.name}: verdicts`);
    assert.deepEqual(Object.fromEntries(homes), c.expect.homes, `${c.name}: homes`);
    const twins = new Map<string, string>();
    for (const r of admitted) if (r.deleted) twins.delete(r.itemId); else twins.set(r.itemId, r.vaultId);
    const materialize = admitted.filter((r) => r.conflict).filter((r) => {
      const ok = conflictDecision(twins.get(r.itemId), r.vaultId, homes.get(r.itemId)) === "materialize";
      if (!ok) tally.note(r.vaultId);
      return ok;
    }).map((r) => ({ itemId: r.itemId, vaultId: r.vaultId }));
    assert.equal(tally.anomalies(), c.expect.anomalies, `${c.name}: anomalies`);
    assert.deepEqual(materialize, c.expect.materialize, `${c.name}: materialize`);
  }
});

test("itemhome.json conflict / serverItem / edit / seal rows", () => {
  for (const c of v.conflict) assert.equal(conflictDecision(c.twin, c.flagged, c.home), c.expect, c.name);
  for (const c of v.serverItem) assert.equal(serverItemDecision(c.pushed, c.losing, c.home), c.expect, c.name);
  for (const c of v.edit) assert.equal(editDecision(c.home, c.editor), c.expect, c.name);
  for (const c of v.seal) {
    assert.equal(sealDecision(c.home, c.vaultId), c.expect, c.name);
    assert.equal(sealGate(true, c.home, c.vaultId), c.expect, `${c.name} (key held)`);
    assert.equal(sealGate(false, c.home, c.vaultId), "no_key", `${c.name} (no key: INV-WRITE-KEY)`);
  }
});

test("the wrong-vault popup line is core HouseholdCopy.WRONG_VAULT_NOTICE byte-equal, and empty for none", () => {
  const kt = readFileSync(fileURLToPath(new URL("../../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/HouseholdCopy.kt", import.meta.url)), "utf8");
  const m = kt.match(/const val WRONG_VAULT_NOTICE: String =\s*"([^"]+)"/);
  assert.ok(m, "HouseholdCopy.WRONG_VAULT_NOTICE moved — update the pin");
  assert.equal(WRONG_VAULT_LINE, m![1]);
  assert.equal(wrongVaultLine(0), "");
  assert.equal(wrongVaultLine(3), WRONG_VAULT_LINE);
});

test("the service worker routes every row through admitRows and every item seal through sealGate", () => {
  const bg = readFileSync(fileURLToPath(new URL("./background.ts", import.meta.url)), "utf8");
  // One item-seal site, gated.
  assert.equal((bg.match(/adItem\(vaultId, itemId, formatVersion\)/g) ?? []).length, 1, "one item seal in the worker");
  const put = bg.slice(bg.indexOf("async function putItem("), bg.indexOf("function saveFailure("));
  assert.match(put, /sealGate\(/, "putItem consults the seal gate before sealing");
  assert.ok(put.indexOf("sealGate(") < put.indexOf("adItem("), "the gate runs before the seal");
  // Every snapshot decrypt is home-admitted first.
  const decrypt = bg.slice(bg.indexOf("function homeAndDecrypt("), bg.indexOf("function decryptItems("));
  assert.match(decrypt, /admitRows\(/);
  for (const site of ["const homed = await homeAndDecrypt(sync, vaultKeys, s.userId)", "const homed = await homeAndDecrypt(sync, vaultKeys, begin.userId)", "const homed = await homeAndDecrypt(sync, session.vaultKeys, session.userId, session.homes)"]) {
    assert.ok(bg.includes(site), `routed: ${site}`);
  }
  assert.equal((bg.match(/decryptItems\(sync, /g) ?? []).length, 0, "no un-homed snapshot decrypt left");
});
