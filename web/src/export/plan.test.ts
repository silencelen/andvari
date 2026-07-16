import { describe, expect, it } from "vitest";
import type { AttachmentRef, ItemDoc } from "../api/types";
import type { VaultInfo, VaultItem } from "../vault/store";
import {
  backupNudge,
  buildPreflight,
  exportFilename,
  orderForExport,
  planAttachments,
} from "./plan";

/** Pure-logic tests only — there is no jsdom setup for panel tests in this repo. */

function item(itemId: string, vaultId: string, updatedAt: number, attachments: AttachmentRef[] = []): VaultItem {
  const doc = { type: "login", name: itemId, login: { username: "u", password: "p" }, attachments } as ItemDoc;
  return { itemId, vaultId, rev: 1, updatedAt, formatVersion: 1, doc };
}

const VAULTS: VaultInfo[] = [
  { vaultId: "p", type: "personal", name: "Personal", role: "owner" },
  { vaultId: "s", type: "shared", name: "Family", role: "writer" },
];

describe("exportFilename", () => {
  it("pads month/day and picks the right extension", () => {
    expect(exportFilename("backup", new Date(2026, 0, 3))).toBe("andvari-backup-2026-01-03.andvari");
    expect(exportFilename("csv", new Date(2026, 6, 6))).toBe("andvari-export-2026-07-06.csv");
  });
});

// isExportOriginAllowed is DELETED (design 2026-07-15 §5.4.2 — origin.ts and the whole origin
// heuristic are gone): export renders whenever the vault is unlocked, on every origin.

describe("orderForExport", () => {
  it("orders by vault position then updatedAt, dropping opted-out vaults", () => {
    const items = [item("b", "s", 5), item("a", "p", 9), item("c", "p", 1), item("d", "x", 2)];
    expect(orderForExport(items, VAULTS).map((i) => i.itemId)).toEqual(["c", "a", "b"]);
    // Opting out the shared vault drops its items entirely.
    expect(orderForExport(items, VAULTS.slice(0, 1)).map((i) => i.itemId)).toEqual(["c", "a"]);
  });
});

describe("buildPreflight", () => {
  it("counts items per vault in vault order", () => {
    const items = [item("a", "p", 1), item("b", "p", 2), item("c", "s", 3)];
    const rows = buildPreflight(VAULTS, items);
    expect(rows.map((r) => [r.name, r.itemCount])).toEqual([
      ["Personal", 2],
      ["Family", 1],
    ]);
  });
});

describe("planAttachments (spec 07 §2.5 cap — over-cap skipped BY NAME)", () => {
  const ref = (name: string, size: number): AttachmentRef => ({ id: name, name, size, fileKey: "a2V5" });
  it("includes in order and names over-cap skips without stopping", () => {
    const items = [item("a", "p", 1, [ref("big.zip", 60), ref("small.txt", 30)]), item("b", "p", 2, [ref("tiny.txt", 10)])];
    const plan = planAttachments(items, 100);
    expect(plan.included.map((e) => e.ref.name)).toEqual(["big.zip", "small.txt", "tiny.txt"]);
    expect(plan.overCap).toEqual([]);
    expect(plan.totalBytes).toBe(100);

    const capped = planAttachments(items, 75);
    expect(capped.included.map((e) => e.ref.name)).toEqual(["big.zip", "tiny.txt"]); // later smaller file still fits
    expect(capped.overCap).toEqual(["small.txt"]);
    expect(capped.totalBytes).toBe(70);
  });
});

describe("backupNudge", () => {
  const DAY = 24 * 60 * 60 * 1000;
  it("nudges on never and on >90 days; quiet when recent", () => {
    expect(backupNudge(null, 1000 * DAY)).toMatch(/never made a backup/);
    expect(backupNudge(0, 91 * DAY)).toMatch(/91 days old/);
    expect(backupNudge(0, 30 * DAY)).toBeNull();
  });
});
