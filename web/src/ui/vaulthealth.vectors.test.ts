import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { ItemDoc } from "../api/types";
import type { VaultItem } from "../vault/store";
import { type RoleFor, duplicateClusters, planDismiss, planKeep } from "./duplicates";
import { healthRows } from "./Health";
import { type CheckPlan, planCheck, planUnsnooze, stalenessRows, stalenessSummary } from "./staleness";

/**
 * Consumes spec/test-vectors/vaulthealth.json — the SAME file the Kotlin
 * VaultHealthVectorsTest checks (design 2026-08-23 §3.2).
 *
 * Why this file exists when both engines already have exhaustive unit suites: those suites were
 * ported from one another, so they can agree with each other and both be wrong about the SAME
 * thing. Only a shared corpus catches a divergence that both impls consider correct.
 *
 * And a ranking divergence is the worst kind to ship: invisible (both orderings look plausible),
 * unreportable (no user can say which is right), and corrosive to trust in the whole feature.
 * "Your phone says this login is the most neglected, your laptop says a different one" is not a
 * bug anybody files — it is a reason to stop believing the screen.
 *
 * ORDER IS THE ASSERTION for the staleness lists. A set comparison would pass while the ranking
 * — the entire point of the view — was reversed.
 *
 * The `writes` block (audit H42, 2026-09-13) grades what the engines WRITE, not only what they
 * derive: the composed merge doc, planKeep (passwordHistory's only writer), planDismiss,
 * planCheck's okAt carry-forward and snooze horizon, planUnsnooze, and every reader / cross-vault
 * refusal string verbatim under a real roles map. Those are the outputs that land in the vault and
 * sync to every device — a divergence there is the silent write-side drift this file's own
 * rationale calls the worst kind.
 */

const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(`${vectorsDir}vaulthealth.json`, "utf8"));

const now: number = v.now;

const items: VaultItem[] = v.items.map((o: { itemId: string; vaultId: string; updatedAt: number; docJson: string }) => ({
  itemId: o.itemId,
  vaultId: o.vaultId,
  rev: 1,
  updatedAt: o.updatedAt,
  formatVersion: 1,
  doc: JSON.parse(o.docJson) as ItemDoc,
}));

/** Every fixture vault is personal, so none carries a grant and none has a role. */
const noRole: RoleFor = () => null;

describe("vault health — the shared cross-implementation corpus", () => {
  it("healthRows match core, row for row", () => {
    const actual = healthRows(items);
    expect(actual).toHaveLength(v.healthRows.length);
    expect(actual.map((r) => r.itemId)).toEqual(v.healthRows.map((r: { itemId: string }) => r.itemId));
    for (const [i, e] of v.healthRows.entries()) {
      const a = actual[i]!;
      expect(a.name, `name of ${a.itemId}`).toBe(e.name);
      expect(a.strength, `strength of ${a.itemId}`).toBe(e.strength);
      expect(a.reused, `reused of ${a.itemId}`).toBe(e.reused);
      expect(a.hasTotp, `hasTotp of ${a.itemId}`).toBe(e.hasTotp);
    }
  });

  it("the health tile counts match core", () => {
    const rows = healthRows(items);
    expect({
      logins: rows.length,
      weak: rows.filter((r) => r.strength <= 1).length,
      reused: rows.filter((r) => r.reused > 0).length,
    }).toEqual(v.healthSummary);
  });

  for (const [key, includeSnoozed] of [
    ["default", false],
    ["includeSnoozed", true],
  ] as const) {
    it(`staleness "${key}" ranks identically to core — ORDER included`, () => {
      const actual = stalenessRows(items, { now, includeSnoozed });
      const expected = v.staleness[key] as {
        itemId: string;
        bucket: string;
        checkedAt: number | null;
        snoozed: boolean;
        firstUri: string | null;
      }[];
      // The ranking IS the feature — compare the sequence, never a set.
      expect(actual.map((r) => r.itemId)).toEqual(expected.map((r) => r.itemId));
      for (const [i, e] of expected.entries()) {
        const a = actual[i]!;
        expect(a.bucket, `bucket of ${a.itemId}`).toBe(e.bucket);
        expect(a.checkedAt ?? null, `checkedAt of ${a.itemId}`).toBe(e.checkedAt);
        expect(a.snoozed, `snoozed of ${a.itemId}`).toBe(e.snoozed);
        expect(a.firstUri ?? null, `firstUri of ${a.itemId}`).toBe(e.firstUri);
      }
    });
  }

  it("the staleness tile counts match core", () => {
    expect(stalenessSummary(stalenessRows(items, { now }))).toEqual(v.staleness.summary);
  });

  it("duplicate clusters, their member order, and their refusals match core", () => {
    const actual = duplicateClusters(items, noRole);
    expect(actual).toHaveLength(v.duplicates.length);
    for (const [i, e] of v.duplicates.entries()) {
      const a = actual[i]!;
      expect(a.sites).toEqual(e.sites);
      expect(a.kind).toBe(e.kind);
      // Member order carries meaning too: newest-first, so "which copy is likely current".
      expect(a.members.map((m) => m.itemId)).toEqual(e.memberIds);
      expect(a.signature).toBe(e.signature);
      expect(a.dismissed).toBe(e.dismissed);
      expect(a.merge?.survivorId ?? null).toBe(e.survivorId);
      expect(a.merge?.loserIds ?? []).toEqual(e.loserIds);
      // The refusal is user-facing copy — compared verbatim, not merely for presence.
      expect(a.mergeRefusal ?? null).toBe(e.mergeRefusal);
    }
  });

  /**
   * The corpus must actually exercise the two forward-compat properties, or it is grading
   * nothing. A fixture that quietly lost these would still pass every assertion above.
   */
  it("still covers the unknown verdict and the skewed clock", () => {
    const rows = stalenessRows(items, { now });
    expect(rows.find((r) => r.itemId === "unknown-verdict")!.bucket, "an unrecognized verdict must never be failing").toBe("recent");
    expect(rows.find((r) => r.itemId === "skewed-future")!.checkedAt, "a future check.at must clamp to now").toBe(now);
  });
});

// -----------------------------------------------------------------------------------------------
// Write-side cases (H42). Docs are compared as CANONICAL JSON: JSON round-trip (drops undefined),
// then drop any null-valued keys and empty arrays on BOTH sides. "Absent" and "null" / "[]" are one
// value to every reader in the tree (`?.`, `?? []`, Kotlin `?: emptyList()`) but two encodings
// across the language boundary — Kotlin omits a default, this engine spreads whatever key the
// input had — so comparing raw strings would grade the serializers, not the engines. Everything
// else (key presence, values, ORDER inside arrays such as uris and passwordHistory) is exact.
// -----------------------------------------------------------------------------------------------
type Row = { itemId: string; vaultId: string; updatedAt: number; docJson: string };
const writes = v.writes as {
  roles: Record<string, string>;
  items: Row[];
  duplicates: {
    sites: string[];
    kind: string;
    memberIds: string[];
    signature: string;
    dismissed: boolean;
    survivorId: string | null;
    loserIds: string[];
    mergeDocJson: string | null;
    mergeRefusal: string | null;
  }[];
  planKeep: { name: string; memberIds: string[]; keepId: string; retiredAt: number; survivorId: string | null; loserIds: string[]; docJson: string | null; refusal: string | null }[];
  planDismiss: { name: string; memberIds: string[]; signature: string; writes: { itemId: string; docJson: string }[] | null; refusal: string | null }[];
  planCheck: { name: string; itemId: string; result: string; now: number; snoozeMs: number | null; write: { itemId: string; docJson: string } | null; refusal: string | null }[];
  planUnsnooze: { name: string; itemId: string; write: { itemId: string; docJson: string } | null; refusal: string | null }[];
};
const writeItems: VaultItem[] = writes.items.map((o) => ({
  itemId: o.itemId,
  vaultId: o.vaultId,
  rev: 1,
  updatedAt: o.updatedAt,
  formatVersion: 1,
  doc: JSON.parse(o.docJson) as ItemDoc,
}));
const writeRoleFor: RoleFor = (vaultId) => writes.roles[vaultId] ?? null;

function canon(x: unknown): unknown {
  if (Array.isArray(x)) return x.map(canon);
  if (x && typeof x === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(x as Record<string, unknown>)) {
      if (val === null || val === undefined) continue;
      if (Array.isArray(val) && val.length === 0) continue;
      out[k] = canon(val);
    }
    return out;
  }
  return x;
}
const canonDoc = (doc: ItemDoc): unknown => canon(JSON.parse(JSON.stringify(doc)));
const expectDoc = (actual: ItemDoc, expectedDocJson: string, label: string): void => {
  expect(canonDoc(actual), label).toEqual(canon(JSON.parse(expectedDocJson)));
};
const expectCheckPlan = (plan: CheckPlan, c: { name: string; write: { itemId: string; docJson: string } | null; refusal: string | null }): void => {
  expect(plan.refusal ?? null, `${c.name} refusal`).toBe(c.refusal);
  if (c.write === null) {
    expect(plan.write, `${c.name}: no write`).toBeUndefined();
  } else {
    expect(plan.write?.itemId, `${c.name} write target`).toBe(c.write.itemId);
    expectDoc(plan.write!.doc, c.write.docJson, `${c.name} doc (check incl.)`);
  }
};

describe("vault health — the write-side half of the shared corpus (H42)", () => {
  it("clusters over the write fixture, and the composed MERGE DOC, match core", () => {
    const actual = duplicateClusters(writeItems, writeRoleFor);
    expect(actual.map((c) => c.signature), "cluster order").toEqual(writes.duplicates.map((c) => c.signature));
    for (const [i, e] of writes.duplicates.entries()) {
      const a = actual[i]!;
      const label = `cluster ${a.signature}`;
      expect(a.sites, label).toEqual(e.sites);
      expect(a.kind, label).toBe(e.kind);
      expect(a.members.map((m) => m.itemId), label).toEqual(e.memberIds);
      expect(a.dismissed, label).toBe(e.dismissed);
      expect(a.merge?.survivorId ?? null, label).toBe(e.survivorId);
      expect(a.merge?.loserIds ?? [], label).toEqual(e.loserIds);
      expect(a.mergeRefusal ?? null, label).toBe(e.mergeRefusal);
      // THE point of this block: the doc the merge would save, not just who survives.
      if (e.mergeDocJson === null) expect(a.merge, `${label}: refused clusters carry no plan`).toBeUndefined();
      else expectDoc(a.merge!.doc, e.mergeDocJson, `${label} merge doc`);
    }
  });

  it("planKeep — survivor, losers, refusal copy and the passwordHistory it writes — matches core", () => {
    for (const c of writes.planKeep) {
      const plan = planKeep(writeItems, c.memberIds, c.keepId, writeRoleFor, c.retiredAt);
      expect(plan.keepRefusal ?? null, `${c.name} refusal`).toBe(c.refusal);
      expect(plan.keep?.survivorId ?? null, `${c.name} survivor`).toBe(c.survivorId);
      expect(plan.keep?.loserIds ?? [], `${c.name} losers`).toEqual(c.loserIds);
      if (c.docJson === null) expect(plan.keep, `${c.name}: a refusal carries no plan`).toBeUndefined();
      else expectDoc(plan.keep!.doc, c.docJson, `${c.name} doc (passwordHistory incl.)`);
    }
  });

  it("planDismiss — every member write, the empty-signature clear, and the refusals — matches core", () => {
    for (const c of writes.planDismiss) {
      const plan = planDismiss(writeItems, c.memberIds, c.signature, writeRoleFor);
      expect(plan.dismissRefusal ?? null, `${c.name} refusal`).toBe(c.refusal);
      if (c.writes === null) {
        expect(plan.writes, `${c.name}: a refusal carries no writes`).toBeUndefined();
      } else {
        expect(plan.writes!.map((w) => w.itemId), `${c.name} write order`).toEqual(c.writes.map((w) => w.itemId));
        for (const [i, e] of c.writes.entries()) expectDoc(plan.writes![i]!.doc, e.docJson, `${c.name} write ${e.itemId}`);
      }
    }
  });

  it("planCheck — okAt carry-forward, the snooze horizon, and the refusals — matches core", () => {
    for (const c of writes.planCheck) {
      expectCheckPlan(planCheck(writeItems, c.itemId, c.result, c.now, writeRoleFor, c.snoozeMs ?? undefined), c);
    }
  });

  it("planUnsnooze — until dropped, verdict kept, no-ops and refusals — matches core", () => {
    for (const c of writes.planUnsnooze) expectCheckPlan(planUnsnooze(writeItems, c.itemId, writeRoleFor), c);
  });

  // The write fixture must keep exercising what it was added for, or the tests above grade
  // nothing: a reader vault, a planKeep that retires a password, a dismissed cluster, and a
  // non-ok planCheck that carries okAt forward.
  it("still covers its reasons for existing", () => {
    expect(Object.values(writes.roles)).toContain("reader");
    expect(writes.planKeep.some((c) => c.docJson?.includes("passwordHistory"))).toBe(true);
    expect(writes.planKeep.some((c) => c.refusal !== null)).toBe(true);
    expect(writes.duplicates.some((c) => c.dismissed)).toBe(true);
    expect(writes.planCheck.some((c) => c.result !== "ok" && c.write?.docJson.includes("okAt"))).toBe(true);
  });
});

