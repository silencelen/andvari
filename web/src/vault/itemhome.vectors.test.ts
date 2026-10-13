import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { admitRow, conflictDecision, editDecision, sealDecision, serverItemDecision, WrongVaultTally } from "./itemhome";

/**
 * Consumes spec/test-vectors/itemhome.json (security review 2026-10, root cause A §5; branch A1b) — the SAME file core
 * `ItemHomeVectorTest` and the extension's `itemhome.vectors.test.ts` grade, against the rules store.ts calls. Plus the
 * INV-SEAL routing tripwire: product code never calls the provenance-free `Account.encryptItem` shim.
 */

type Row = { itemId: string; vaultId: string; deleted?: boolean; conflict?: boolean };
const v = JSON.parse(readFileSync(fileURLToPath(new URL("../../../spec/test-vectors/itemhome.json", import.meta.url)), "utf8")) as {
  admit: { name: string; home: string | null; vaultId: string; expect: string }[];
  pulls: { name: string; homes: Record<string, string>; rows: Row[]; expect: { verdicts: string[]; homes: Record<string, string>; anomalies: number; materialize: { itemId: string; vaultId: string }[] } }[];
  conflict: { name: string; twin: string | null; flagged: string; home: string | null; expect: string }[];
  serverItem: { name: string; pushed: string; losing: string; home: string | null; expect: string }[];
  edit: { name: string; home: string | null; editor: string | null; expect: string }[];
  seal: { name: string; home: string | null; vaultId: string; expect: string }[];
};

describe("itemhome.json — the item-home rules on the web engine", () => {
  for (const c of v.admit) it(`admit: ${c.name}`, () => expect(admitRow(c.home, c.vaultId)).toBe(c.expect));

  it("carries the §5.3 fixture in both row orders", () => {
    expect(v.pulls.some((p) => p.name.startsWith("§5.3 fixture, flagged"))).toBe(true);
    expect(v.pulls.some((p) => p.name.startsWith("§5.3 fixture, genuine"))).toBe(true);
  });

  for (const c of v.pulls) {
    it(`pull: ${c.name}`, () => {
      // Replays a pull the way store.ts does: admit every row in order, then the admitted flagged rows go through
      // INV-CONFLICT against the working-set twin and the home.
      const homes = new Map(Object.entries(c.homes));
      const tally = new WrongVaultTally();
      const twins = new Map<string, string>();
      const flagged: { itemId: string; vaultId: string }[] = [];
      const verdicts: string[] = [];
      for (const r of c.rows) {
        const verdict = admitRow(homes.get(r.itemId), r.vaultId);
        verdicts.push(verdict);
        if (verdict === "quarantine") {
          tally.note(r.vaultId);
          continue;
        }
        if (verdict === "new_home") homes.set(r.itemId, r.vaultId);
        if (r.deleted) twins.delete(r.itemId);
        else twins.set(r.itemId, r.vaultId);
        if (r.conflict) flagged.push({ itemId: r.itemId, vaultId: r.vaultId });
      }
      const materialize = flagged.filter((f) => {
        const ok = conflictDecision(twins.get(f.itemId), f.vaultId, homes.get(f.itemId)) === "materialize";
        if (!ok) tally.note(f.vaultId);
        return ok;
      });
      expect({ verdicts, homes: Object.fromEntries(homes), anomalies: tally.anomalies(), materialize }).toEqual(c.expect);
    });
  }

  for (const c of v.conflict) it(`conflict: ${c.name}`, () => expect(conflictDecision(c.twin, c.flagged, c.home)).toBe(c.expect));
  for (const c of v.serverItem) it(`serverItem: ${c.name}`, () => expect(serverItemDecision(c.pushed, c.losing, c.home)).toBe(c.expect));
  for (const c of v.edit) it(`edit: ${c.name}`, () => expect(editDecision(c.home, c.editor)).toBe(c.expect));
  for (const c of v.seal) it(`seal: ${c.name}`, () => expect(sealDecision(c.home, c.vaultId)).toBe(c.expect));
});

describe("INV-SEAL routing tripwire (web)", () => {
  const src = fileURLToPath(new URL("../", import.meta.url));
  const files: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(ts|tsx)$/.test(n) && !/\.test\.tsx?$/.test(n) && !p.includes(`${"/"}vendor${"/"}`)) files.push(p);
    }
  };
  walk(src);

  it("product code never calls the provenance-free Account.encryptItem shim", () => {
    expect(files.length).toBeGreaterThan(50);
    const offenders = files.flatMap((f) =>
      readFileSync(f, "utf8").split("\n").flatMap((line, i) => (/\.encryptItem\(/.test(line.split("//")[0]!) ? [`${f}:${i + 1}`] : [])),
    );
    expect(offenders).toEqual([]);
  });
});
