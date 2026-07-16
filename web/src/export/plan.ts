import type { AttachmentRef } from "../api/types";
import type { VaultInfo, VaultItem } from "../vault/store";
import { MAX_TOTAL_ATTACHMENT_PLAINTEXT } from "./export";

/**
 * Pure UI-adjacent export logic (spec 07): filename minting, item ordering, the
 * moment-of-truth preflight summary, the §2.5 attachment plan, and the lastExportAt
 * bookkeeping. Kept DOM-free so it unit-tests in the node vitest environment (no jsdom
 * setup exists for panels).
 */

// ---- filenames (spec 07 §1/§2.6) ----

/** `andvari-backup-YYYY-MM-DD.andvari` / `andvari-export-YYYY-MM-DD.csv` (local date). */
export function exportFilename(kind: "backup" | "csv", date: Date = new Date()): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return kind === "backup" ? `andvari-backup-${y}-${m}-${d}.andvari` : `andvari-export-${y}-${m}-${d}.csv`;
}

// The break-glass export suppression (isExportOriginAllowed) is DELETED with ui/origin.ts
// (design 2026-07-15 §5.4.2): it was SHOULD-level advertising — the page already holds the
// decrypted vault — and origin is no longer a posture signal. Export renders whenever unlocked.

// ---- ordering + preflight ----

/**
 * spec 07 §1: vault order (as [vaults] lists them — personal first, then shared by
 * name, the store's own order) then `updatedAt` ascending within a vault. Items in
 * vaults not listed (opted out) are dropped.
 */
export function orderForExport(items: VaultItem[], vaults: VaultInfo[]): VaultItem[] {
  const order = new Map(vaults.map((v, i) => [v.vaultId, i]));
  return items
    .filter((it) => order.has(it.vaultId))
    .sort((a, b) => {
      const byVault = order.get(a.vaultId)! - order.get(b.vaultId)!;
      return byVault !== 0 ? byVault : a.updatedAt - b.updatedAt;
    });
}

/** One preflight row: the per-vault line of the moment-of-truth screen. */
export interface VaultPreflight extends VaultInfo {
  itemCount: number;
}

/** Per-vault item counts in vault order (the export preview, spec 07 intro + §3). */
export function buildPreflight(vaults: VaultInfo[], items: VaultItem[]): VaultPreflight[] {
  const counts = new Map<string, number>();
  for (const it of items) counts.set(it.vaultId, (counts.get(it.vaultId) ?? 0) + 1);
  return vaults.map((v) => ({ ...v, itemCount: counts.get(v.vaultId) ?? 0 }));
}

// ---- §2.5 attachment plan ----

export interface AttachmentPlanEntry {
  item: VaultItem;
  ref: AttachmentRef;
}

export interface AttachmentPlan {
  /** In export order (item order, then the doc's own attachments[] order). */
  included: AttachmentPlanEntry[];
  /** Names skipped because including them would cross the cap (spec 07 §2.5 — BY NAME). */
  overCap: string[];
  /** Total plaintext bytes of the included set. */
  totalBytes: number;
}

/**
 * Greedy in-order plan of attachment sections under the §2.5 64 MiB total-plaintext
 * cap ([cap] overridable for tests). Over-cap attachments are skipped by name and the
 * scan continues — a later smaller file may still fit (spec: "over-cap attachments are
 * skipped by name", never fatal).
 */
export function planAttachments(orderedItems: VaultItem[], cap: number = MAX_TOTAL_ATTACHMENT_PLAINTEXT): AttachmentPlan {
  const included: AttachmentPlanEntry[] = [];
  const overCap: string[] = [];
  let totalBytes = 0;
  for (const item of orderedItems) {
    for (const ref of item.doc.attachments ?? []) {
      if (totalBytes + ref.size > cap) {
        overCap.push(ref.name);
      } else {
        included.push({ item, ref });
        totalBytes += ref.size;
      }
    }
  }
  return { included, overCap, totalBytes };
}

// ---- lastExportAt (spec 07 §2.6 — recorded LOCALLY, never server-side) ----

const lastExportKey = (userId: string) => `andvari.lastExportAt.${userId}`;

export function readLastExportAt(userId: string): number | null {
  if (typeof localStorage === "undefined") return null;
  const raw = localStorage.getItem(lastExportKey(userId));
  if (!raw) return null;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export function writeLastExportAt(userId: string, at: number): void {
  if (typeof localStorage === "undefined") return;
  localStorage.setItem(lastExportKey(userId), String(at));
}

const NUDGE_AFTER_MS = 90 * 24 * 60 * 60 * 1000;

/** The Settings nudge line, or null when the last backup is recent enough. */
export function backupNudge(lastExportAt: number | null, now: number = Date.now()): string | null {
  if (lastExportAt === null) {
    return "You have never made a backup — an encrypted backup file is the only way back if the server and all its backups are lost.";
  }
  if (now - lastExportAt > NUDGE_AFTER_MS) {
    const days = Math.floor((now - lastExportAt) / (24 * 60 * 60 * 1000));
    return `Your last backup is ${days} days old — consider making a fresh one.`;
  }
  return null;
}
