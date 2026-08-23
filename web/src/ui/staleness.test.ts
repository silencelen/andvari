import { describe, expect, it } from "vitest";
import type { ItemDoc } from "../api/types";
import type { VaultItem } from "../vault/store";
import {
  type RoleFor,
  SNOOZE_MS,
  isFailing,
  planCheck,
  planUnsnooze,
  stalenessRows,
  stalenessSummary,
} from "./staleness";

/**
 * Staleness + verification-ledger pins (owner-requested 2026-08-22; design
 * 2026-08-22-login-health-staleness-verification). The ranking, the skew clamp, the open
 * `result` vocabulary and the composed verdict doc are all decided in the pure module — pinned
 * here so Health.tsx stays a renderer/writer, exactly as duplicates.test.ts does.
 */

const NOW = 1_755_000_000_000;
const DAY = 86_400_000;

const login = (
  itemId: string,
  docOver: Partial<ItemDoc> = {},
  updatedAt = NOW,
  vaultId = "v1",
): VaultItem => ({
  itemId,
  vaultId,
  rev: 1,
  updatedAt,
  formatVersion: 1,
  doc: {
    type: "login",
    name: itemId,
    login: { username: "u@example.com", password: "hunter2", uris: ["https://example.com/login"] },
    ...docOver,
  },
});

const personal: RoleFor = () => null;
const reader: RoleFor = () => "reader";

describe("stalenessRows", () => {
  it("only ranks logins — notes and cards have nothing to verify", () => {
    const items: VaultItem[] = [
      login("a"),
      { ...login("n"), doc: { type: "note", name: "n" } },
      { ...login("c"), doc: { type: "card", name: "c" } },
    ];
    expect(stalenessRows(items, { now: NOW }).map((r) => r.itemId)).toEqual(["a"]);
  });

  it("orders failing verdicts first, then never-checked oldest, then longest-since-checked", () => {
    const items = [
      login("recent-check", { check: { at: NOW - DAY, result: "ok" } }),
      login("never-new", {}, NOW - DAY),
      login("stale-check", { check: { at: NOW - 400 * DAY, result: "ok" } }),
      login("never-old", {}, NOW - 900 * DAY),
      login("failed", { check: { at: NOW - 10 * DAY, result: "bad" } }),
    ];
    expect(stalenessRows(items, { now: NOW }).map((r) => r.itemId)).toEqual([
      "failed", // tier 1: actionable now
      "never-old", // tier 2: never checked, oldest change first
      "never-new",
      "stale-check", // tier 3: longest since a human confirmed it
      "recent-check",
    ]);
  });

  it("orders MULTIPLE failures most-recent-first — a fresh failure is the most actionable", () => {
    const items = [
      login("old-fail", { check: { at: NOW - 100 * DAY, result: "gone" } }),
      login("new-fail", { check: { at: NOW - 2 * DAY, result: "bad" } }),
    ];
    expect(stalenessRows(items, { now: NOW }).map((r) => r.itemId)).toEqual(["new-fail", "old-fail"]);
  });

  it("buckets by age since the last check", () => {
    const rows = stalenessRows(
      [
        login("never"),
        login("year", { check: { at: NOW - 400 * DAY, result: "ok" } }),
        login("half", { check: { at: NOW - 200 * DAY, result: "ok" } }),
        login("fresh", { check: { at: NOW - 3 * DAY, result: "ok" } }),
      ],
      { now: NOW },
    );
    expect(Object.fromEntries(rows.map((r) => [r.itemId, r.bucket]))).toEqual({
      never: "never",
      year: "over-year",
      half: "six-to-twelve",
      fresh: "recent",
    });
  });

  // spec 02 §3: the vocabulary is OPEN. A future client's verdict must degrade to "checked",
  // never to a red row and never to a crash — this is the forward-compat guarantee.
  it("treats an UNRECOGNIZED result as checked-but-unknown, not as failing", () => {
    const rows = stalenessRows([login("x", { check: { at: NOW - DAY, result: "quantum-verified" } })], { now: NOW });
    expect(rows[0]!.bucket).toBe("recent");
    expect(isFailing("quantum-verified")).toBe(false);
    expect(isFailing(undefined)).toBe(false);
    expect(isFailing("bad")).toBe(true);
  });

  // spec 02 §1/§3: `at` is a CLIENT clock. In a shared vault it can come from another member's
  // skewed — or hostile — device, and must never be able to dominate the ordering.
  it("clamps a future check.at instead of letting it sort above real entries", () => {
    const rows = stalenessRows(
      [login("future", { check: { at: NOW + 999 * DAY, result: "ok" } }), login("never")],
      { now: NOW },
    );
    expect(rows.find((r) => r.itemId === "future")!.checkedAt).toBe(NOW);
    expect(rows.map((r) => r.itemId)).toEqual(["never", "future"]); // never-checked still outranks it
  });

  it("hides snoozed rows by default and reveals them on request", () => {
    const items = [login("snoozed", { check: { at: NOW - 5 * DAY, result: "blocked", until: NOW + 10 * DAY } })];
    expect(stalenessRows(items, { now: NOW })).toHaveLength(0);
    const shown = stalenessRows(items, { now: NOW, includeSnoozed: true });
    expect(shown[0]!.snoozed).toBe(true);
  });

  it("lets an EXPIRED snooze resurface on its own", () => {
    const items = [login("was-snoozed", { check: { at: NOW - 40 * DAY, result: "blocked", until: NOW - DAY } })];
    const rows = stalenessRows(items, { now: NOW });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.snoozed).toBe(false);
  });

  it("injects local usage without knowing where it came from, and never invents one", () => {
    const rows = stalenessRows([login("used"), login("unused")], {
      now: NOW,
      lastUsedAt: (id) => (id === "used" ? NOW - 2 * DAY : undefined),
    });
    expect(rows.find((r) => r.itemId === "used")!.lastUsedAt).toBe(NOW - 2 * DAY);
    // undefined = "no local record", NOT "never used" — the caller must render "—".
    expect(rows.find((r) => r.itemId === "unused")!.lastUsedAt).toBeUndefined();
  });

  it("exposes only a navigable WEB uri as the open-site target", () => {
    const rows = stalenessRows(
      [login("app", { login: { username: "u", password: "p", uris: ["androidapp://com.example"] } })],
      { now: NOW },
    );
    expect(rows[0]!.firstUri).toBeUndefined();
  });

  it("summarises from the same rows the table shows, so a tile cannot disagree with the list", () => {
    const rows = stalenessRows(
      [login("a"), login("b"), login("c", { check: { at: NOW, result: "gone" } })],
      { now: NOW },
    );
    expect(stalenessSummary(rows)).toEqual({ unchecked: 2, failing: 1 });
  });
});

describe("planCheck", () => {
  it("composes one write carrying the verdict", () => {
    const items = [login("a")];
    const plan = planCheck(items, "a", "ok", NOW, personal);
    expect(plan.refusal).toBeUndefined();
    expect(plan.write).toEqual({ itemId: "a", doc: { ...items[0]!.doc, check: { at: NOW, result: "ok", okAt: NOW } } });
  });

  // spec 02 §3: okAt carries forward, so "last worked in March, failed in August" survives.
  it("carries okAt forward across a later failure", () => {
    const items = [login("a", { check: { at: NOW - 100 * DAY, result: "ok", okAt: NOW - 100 * DAY } })];
    expect(planCheck(items, "a", "bad", NOW, personal).write!.doc.check).toEqual({
      at: NOW,
      result: "bad",
      okAt: NOW - 100 * DAY,
    });
  });

  it("omits okAt entirely when a login has never once worked", () => {
    expect(planCheck([login("a")], "a", "bad", NOW, personal).write!.doc.check).toEqual({ at: NOW, result: "bad" });
  });

  it("re-stamps okAt when a previously-failing login works again", () => {
    const items = [login("a", { check: { at: NOW - DAY, result: "bad", okAt: NOW - 50 * DAY } })];
    expect(planCheck(items, "a", "ok", NOW, personal).write!.doc.check!.okAt).toBe(NOW);
  });

  it("records a snooze horizon when one is asked for", () => {
    const plan = planCheck([login("a")], "a", "blocked", NOW, personal, SNOOZE_MS);
    expect(plan.write!.doc.check!.until).toBe(NOW + SNOOZE_MS);
  });

  it("preserves every other field of the doc", () => {
    const items = [login("a", { notes: "keep me", favorite: true, dupeAck: "x|y" })];
    const doc = planCheck(items, "a", "ok", NOW, personal).write!.doc;
    expect(doc.notes).toBe("keep me");
    expect(doc.favorite).toBe(true);
    expect(doc.dupeAck).toBe("x|y");
    expect(doc.login).toEqual(items[0]!.doc.login);
  });

  // The server enforces roles (spec 02 §4) — refuse HERE, with the reason, rather than letting
  // the write fail as an error. The planDismiss refusal idiom.
  it("refuses to record into a vault the user can only read", () => {
    const plan = planCheck([login("a")], "a", "ok", NOW, reader);
    expect(plan.write).toBeUndefined();
    expect(plan.refusal).toMatch(/only view/);
  });

  it("refuses an item that vanished under the user", () => {
    expect(planCheck([], "ghost", "ok", NOW, personal).refusal).toMatch(/changed under you/);
  });

  it("refuses a non-login", () => {
    const note: VaultItem = { ...login("n"), doc: { type: "note", name: "n" } };
    expect(planCheck([note], "n", "ok", NOW, personal).refusal).toMatch(/Only logins/);
  });
});

describe("planUnsnooze", () => {
  it("drops the horizon but KEEPS the verdict — it is still the last true observation", () => {
    const items = [login("a", { check: { at: NOW - DAY, result: "blocked", okAt: NOW - 9 * DAY, until: NOW + DAY } })];
    expect(planUnsnooze(items, "a", personal).write!.doc.check).toEqual({
      at: NOW - DAY,
      result: "blocked",
      okAt: NOW - 9 * DAY,
    });
  });

  it("writes nothing when there is no snooze to clear", () => {
    const plan = planUnsnooze([login("a", { check: { at: NOW, result: "ok" } })], "a", personal);
    expect(plan.write).toBeUndefined();
    expect(plan.refusal).toBeUndefined();
  });

  it("refuses a reader vault", () => {
    const items = [login("a", { check: { at: NOW, result: "blocked", until: NOW + DAY } })];
    expect(planUnsnooze(items, "a", reader).refusal).toMatch(/only view/);
  });
});
