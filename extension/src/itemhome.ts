/**
 * Item home in the extension (security review 2026-10, root cause A §5.2: "the extension gets INV-HOME and
 * INV-WRITE-KEY on its capture and update paths"; branch A1b). LEAF module (no chrome), so `node --test` grades the
 * production code path against spec/test-vectors/itemhome.json — the same rows core `ItemHome` and web
 * `vault/itemhome.ts` are graded on.
 *
 * `home(itemId)` is the vaultId of the FIRST row this browser APPLIED for that itemId (A9 L-1: applied, not merely seen —
 * a blob-less tombstone or a row under a vault this session holds no key for never homes an item, so the server cannot
 * home an item away from its genuine row by serving such a row first). The service worker keeps the homes in
 * storage.local (per server origin and user) and in the session snapshot, so they outlive a resync, an MV3 eviction and a
 * browser restart. A later row for that itemId under another vault (live or tombstone) is not applied: it never reaches
 * the matched items, so it can never become a capture's update target, a TOTP-add target or a fill. The first home on a
 * fresh browser is the server's choice among the rows it can apply (the stated residual).
 *
 * INV-WRITE-KEY needs no extra state here: the extension adopts only keys that open under this user's UVK (design §1.7;
 * grantkeys.ts), never a grant seal, so it never holds a legacy-read-only key. The seal gate below still refuses any
 * vault whose key the session does not hold and any itemId whose home is another vault.
 */

/** `skip` (security review 2026-10, A9 L-1): no home yet, but the row CANNOT be applied on this browser — a tombstone, a
 *  vault whose key this session does not hold, an envelope that does not open. No home is recorded (the home is the vault
 *  of the first envelope this browser APPLIED, design §5.1), no anomaly, and the row is not admitted. */
export type Admit = "new_home" | "skip" | "home" | "quarantine";

/** `applies`: whether this browser can apply the row now (live, key held, and it opens). Only an unhomed row reads it. */
export function admitRow(home: string | null | undefined, rowVaultId: string, applies = true): Admit {
  if (home === null || home === undefined) return applies ? "new_home" : "skip";
  return home === rowVaultId ? "home" : "quarantine";
}

export function conflictDecision(twinVaultId: string | null | undefined, flaggedVaultId: string, home: string | null | undefined): "materialize" | "abort" {
  if ((twinVaultId != null && twinVaultId !== flaggedVaultId) || (home != null && home !== flaggedVaultId)) return "abort";
  return "materialize";
}

export function serverItemDecision(pushedVaultId: string, losingVaultId: string, home: string | null | undefined): "copy" | "abort" {
  if (losingVaultId !== pushedVaultId || (home != null && home !== losingVaultId)) return "abort";
  return "copy";
}

export function editDecision(home: string | null | undefined, editorVaultId: string | null | undefined): "ok" | "changed_vaults" | "unbound" {
  if (editorVaultId == null) return "unbound";
  if (home != null && home !== editorVaultId) return "changed_vaults";
  return "ok";
}

export function sealDecision(home: string | null | undefined, vaultId: string): "ok" | "new_home" | "refuse" {
  if (home == null) return "new_home";
  return home === vaultId ? "ok" : "refuse";
}

/** One resync's wrong-vault tally: however many rows were refused, ONE anomaly. */
export class WrongVaultTally {
  refused = 0;
  firstVaultId: string | null = null;
  note(vaultId: string): void {
    if (this.refused++ === 0) this.firstVaultId = vaultId;
  }
  anomalies(): number {
    return this.refused > 0 ? 1 : 0;
  }
}

/** Admit a snapshot's rows in order against `homes` (updated in place): the rows to apply, the refusals, and whether
 *  any new home was recorded (the caller persists the map then). `applies` (A9 L-1) says whether an UNHOMED row can be
 *  applied here — live, blob present, key held, and the envelope opens — so only a row this browser actually applies
 *  can home its item; one that cannot is skipped (no home, no anomaly, not admitted). */
export function admitRows<T extends { itemId: string; vaultId: string }>(
  rows: readonly T[],
  homes: Map<string, string>,
  applies: (row: T) => boolean = () => true,
): { admitted: T[]; tally: WrongVaultTally; changed: boolean } {
  const admitted: T[] = [];
  const tally = new WrongVaultTally();
  let changed = false;
  for (const r of rows) {
    const v = admitRow(homes.get(r.itemId), r.vaultId, applies(r));
    if (v === "quarantine") {
      tally.note(r.vaultId);
      continue;
    }
    if (v === "skip") continue;
    if (v === "new_home") {
      homes.set(r.itemId, r.vaultId);
      changed = true;
    }
    admitted.push(r);
  }
  return { admitted, tally, changed };
}

/**
 * The capture/update/TOTP-add seal gate: INV-WRITE-KEY (the vault's key must be one this session holds, which in the
 * extension means one that opened under the UVK) and the INV-SEAL home cross-check (the item lives in this vault, or
 * is a fresh id that takes it as its home).
 */
export function sealGate(keyHeld: boolean, home: string | null | undefined, vaultId: string): "ok" | "new_home" | "no_key" | "refuse" {
  if (!keyHeld) return "no_key";
  return sealDecision(home, vaultId);
}

/** The popup line for a resync that refused rows (core HouseholdCopy.WRONG_VAULT_NOTICE, byte-equal; empty for none). */
export const WRONG_VAULT_LINE =
  "The server sent an item under the wrong vault. andvari kept the item where it was and ignored the other copy. Tell your admin — the server may be misbehaving.";

export function wrongVaultLine(refused: number): string {
  return Number.isFinite(refused) && refused > 0 ? WRONG_VAULT_LINE : "";
}
