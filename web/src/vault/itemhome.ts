/**
 * The item-home rules (security review 2026-10, root cause A §5.1: INV-HOME, INV-CONFLICT, INV-EDIT and the INV-SEAL
 * home cross-check; branch A1b). Pure, so `spec/test-vectors/itemhome.json` grades exactly what store.ts calls. Twin of
 * core `ItemHome` (and the extension's `itemhome.ts`), code for code.
 *
 * `home(itemId)` is the vaultId of the FIRST envelope this device APPLIED for that itemId (A9 L-1: applied, not merely
 * served: a tombstone or a row under a vault this device holds no key for never homes an item). It is device-local and
 * never a server value after that first row: the server can choose the first home on a fresh device among the rows it
 * can apply (a stated residual), but it can never move an item this device already holds into another vault. No
 * legitimate flow re-homes an itemId: move and copy mint fresh ids and then delete the source.
 */

/**
 * Where item plaintext came from, and therefore the ONLY vault it may be sealed under (INV-SEAL). Every item seal goes
 * through `Account.sealItem`, which takes one of these; no wire field, lookup by itemId or label picks the sealing key.
 *  - `envelope`: (a) the vault bound in the AD of the envelope the plaintext was decrypted from;
 *  - `editor`: (b) the vault an editor session was bound to when it OPENED (user-authored content);
 *  - `chosen`: (c) a destination the user explicitly chose and saw (move, copy, import, the new-item vault picker).
 */
export interface SealProvenance {
  kind: "envelope" | "editor" | "chosen";
  vaultId: string;
}

export const envelopeProvenance = (vaultId: string): SealProvenance => ({ kind: "envelope", vaultId });
export const editorProvenance = (vaultId: string): SealProvenance => ({ kind: "editor", vaultId });
export const chosenProvenance = (vaultId: string): SealProvenance => ({ kind: "chosen", vaultId });

/** What to do with one served row (live or tombstone): `new_home` (no home yet and the row can be applied here: this
 *  row's vault becomes it, and the row applies), `skip` (no home yet but the row CANNOT be applied on this device — a
 *  tombstone, a vault whose key this device does not hold, an envelope that does not open: NO home is recorded, no
 *  anomaly, the row's own handling proceeds; security review 2026-10, A9 L-1), `home` (the row is under the home: it
 *  applies), `quarantine` (another vault: not applied). */
export type Admit = "new_home" | "skip" | "home" | "quarantine";

/** `applies`: whether this device can apply the row now (live, key held, and it opens). Only an unhomed row reads it. */
export function admitRow(home: string | null | undefined, rowVaultId: string, applies = true): Admit {
  if (home === null || home === undefined) return applies ? "new_home" : "skip";
  return home === rowVaultId ? "home" : "quarantine";
}

/**
 * INV-CONFLICT: materialize a conflict-flagged row only when nothing disagrees about its vault — the in-memory twin (if
 * any) and the home (if any) must both be the flagged row's vault. Both mutations are then built from
 * `decrypt(flagged)` under `flagged.vaultId`. Anything else aborts with no push.
 */
export function conflictDecision(twinVaultId: string | null | undefined, flaggedVaultId: string, home: string | null | undefined): "materialize" | "abort" {
  if ((twinVaultId != null && twinVaultId !== flaggedVaultId) || (home != null && home !== flaggedVaultId)) return "abort";
  return "materialize";
}

/** The push-side copy from a server-returned displaced value: it must be the item THIS client wrote, in the vault it
 *  wrote it to; its AD vault (also the copy's seal vault) must equal the pushed vault and the home. */
export function serverItemDecision(pushedVaultId: string, losingVaultId: string, home: string | null | undefined): "copy" | "abort" {
  if (losingVaultId !== pushedVaultId || (home != null && home !== losingVaultId)) return "abort";
  return "copy";
}

/** INV-EDIT: an edit names the vault its editor opened on; a different home now refuses it ("reopen it"). */
export function editDecision(home: string | null | undefined, editorVaultId: string | null | undefined): "ok" | "changed_vaults" | "unbound" {
  if (editorVaultId == null) return "unbound";
  if (home != null && home !== editorVaultId) return "changed_vaults";
  return "ok";
}

/** The INV-SEAL home cross-check every item seal for a push runs: only at the home; no home yet takes this vault. */
export function sealDecision(home: string | null | undefined, vaultId: string): "ok" | "new_home" | "refuse" {
  if (home == null) return "new_home";
  return home === vaultId ? "ok" : "refuse";
}

/** One pull's wrong-vault tally: however many rows were refused, the pull raises ONE anomaly. */
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

/** INV-EDIT copy, byte-equal with core `HouseholdCopy.ITEM_CHANGED_VAULTS` (pinned by vault-copy.test.ts). */
export const ITEM_CHANGED_VAULTS = "This item changed vaults; reopen it.";

/** INV-EDIT / INV-SEAL refusal: the item lives in another vault than the one this write was bound to. Nothing is
 *  re-targeted. Core twin `ItemChangedVaultsException`. */
export class ItemChangedVaultsError extends Error {
  constructor() {
    super(ITEM_CHANGED_VAULTS);
    this.name = "ItemChangedVaultsError";
  }
}

/**
 * The vault a planned write is bound to (INV-EDIT for the Health / Staleness writes): the vault of the item in the SAME
 * snapshot the plan's doc was drawn from — that doc was decrypted from that envelope (provenance (a)). Never a lookup
 * at save time; the store refuses the write if the item's home has changed since.
 */
export function boundVault(items: readonly { itemId: string; vaultId: string }[], itemId: string): string | undefined {
  return items.find((i) => i.itemId === itemId)?.vaultId;
}
