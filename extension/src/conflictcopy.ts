/**
 * Conflict-copy materialization — the pure half (spec 03 §5), H20 (2026-09-13 audit).
 *
 * The extension is a PUSHING client and therefore the only party that ever receives the losing
 * version of a conflicted put (`MutationResult.serverItem`, PDD-1). It used to treat status
 * "conflict" as a failure: no local rev update, no copy, and a red line saying the save did not
 * land — while the server HAD applied it. The peer's value then survived only in version history,
 * and web/core's pull-side fallback built the "(conflict)" copy from the WINNER, i.e. a duplicate
 * of the extension's own value. background.ts now lands a conflict as saved and pushes the copy;
 * these two helpers are its chrome-free, vector-pinned half.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

/**
 * Deterministic conflict-copy id: UUIDv4-shaped, from the first 16 bytes of
 * sha256("conflict|" + itemId + "|" + rev) with the version/variant nibbles forced. Byte-twin of
 * core ConflictCopy.id / web store.ts conflictCopyId and pinned by spec/test-vectors/conflictcopy.json
 * — concurrent materializers (members, devices, our own retry, the pull-side fallback) converge on
 * ONE id, which the server's idempotent existing-item path absorbs. A divergence here would
 * silently double every conflict copy fleet-wide.
 */
export function conflictCopyId(itemId: string, rev: number): string {
  const h = sha256(new TextEncoder().encode(`conflict|${itemId}|${rev}`)).slice(0, 16);
  h[6] = (h[6]! & 0x0f) | 0x40; // version nibble 4
  h[8] = (h[8]! & 0x3f) | 0x80; // variant 10
  const hex = bytesToHex(h);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** The copy's name, spec 03 §5 `"<name> (conflict YYYY-MM-DD)"` — the day the DISPLACED version
 *  was written (its `updatedAt`, ms since epoch, UTC), the web/core twin's exact stamp. */
export function conflictCopyName(name: string, updatedAtMs: number): string {
  const stamp = new Date(updatedAtMs).toISOString().slice(0, 10);
  return `${name} (conflict ${stamp})`;
}
