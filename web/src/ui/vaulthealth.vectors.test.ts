import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { ItemDoc } from "../api/types";
import type { VaultItem } from "../vault/store";
import { type RoleFor, duplicateClusters } from "./duplicates";
import { healthRows } from "./Health";
import { stalenessRows, stalenessSummary } from "./staleness";

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
