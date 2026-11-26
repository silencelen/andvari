import { ApiError } from "../api/client";
import { VaultKeyNotVerifiedError } from "../vault/account";
import { ItemChangedVaultsError, MoveWaitingError, NoPersonalVaultError, OfflineNotSavedError, ReadOnlyCopyError, VaultNotOpenError } from "../vault/store";
import { CopyBeingRemovedError } from "../vault/policywipe";
import { answerLimitText } from "./errors";
import { MOVE_WAITING_REFUSED, OWNER_OUT_OF_SPACE, OWNER_OUT_OF_SPACE_THEIRS, OWNER_OUT_OF_SPACE_YOURS, SAVE_COPY_BEING_REMOVED, SAVE_COPY_REMOVAL_BLOCKED, SAVE_OFFLINE_ATTACHMENTS, SAVE_OFFLINE_NO_COPY, SAVE_OFFLINE_NOT_PERSISTENT, SAVE_VAULT_NOT_OPEN } from "./copy";

/** A change refused while a server's policy removes the copy: "in a moment", or, while another tab holds the removal up, what to do. */
export function copyRemovalText(err: CopyBeingRemovedError): string {
  return err.blocked ? SAVE_COPY_REMOVAL_BLOCKED : SAVE_COPY_BEING_REMOVED;
}

/**
 * The editor's error line for a save that was not made. Each refusal the store names says what happened and what the
 * person can do; only an unexpected failure gets the generic "Save failed — nothing was changed." [ownsTarget]: whether
 * this account owns the vault the item was saved into (whose space is full).
 */
export function saveErrorText(err: unknown, ownsTarget: boolean): string {
  // A save whose file's upload a limit ended is certainly not saved (the item is written only after its
  // files), so it is said as not saved, before the limit's "may or may not have been done".
  if (err instanceof OfflineNotSavedError && err.reason === "attachments") return SAVE_OFFLINE_ATTACHMENTS;
  // A push that the client's limit ended: the server stopped answering (or took too long); it may have arrived.
  const limit = answerLimitText(err);
  if (limit !== null) return limit;
  // The owner's quota (spec 03 §14.4, a per-row `quota_exceeded`): approved entries 27 and 28 under OWNER_OUT_OF_SPACE,
  // chosen by whose space is full, that is, who owns the vault the item was saved into.
  if (err instanceof ApiError && err.code === "quota_exceeded") return `${OWNER_OUT_OF_SPACE} ${ownsTarget ? OWNER_OUT_OF_SPACE_YOURS : OWNER_OUT_OF_SPACE_THEIRS}`;
  // H03 → recheck R38: a per-row `rejected` is PERMANENT — the referenced attachment is gone — so it gets core's
  // SAVE_REJECTED_ATTACHMENT row (byte-twin, pinned in vault-copy.test.ts), never the generic retry shape.
  if (err instanceof ApiError && (err.code === "unknown_attachment" || err.code === "attachment_mismatch")) {
    return "The server refused this save — an attachment it references is no longer there. Remove that attachment, then save again.";
  }
  if (err instanceof ItemChangedVaultsError) return err.message; // A1b INV-EDIT: core HouseholdCopy.ITEM_CHANGED_VAULTS
  // ux-copy--2: the 413 sentence is the copy canon's 413 row (byte-twin of core HouseholdCopy).
  if (err instanceof ApiError && err.status === 413) return "The server refused that upload — it may be too large, or storage may be full.";
  // The 2026-11-16 walk: with the server gone, a change that could not wait in this browser says why.
  if (err instanceof OfflineNotSavedError) {
    return err.reason === "attachments" ? SAVE_OFFLINE_ATTACHMENTS : err.reason === "no_offline_copy" ? SAVE_OFFLINE_NO_COPY : SAVE_OFFLINE_NOT_PERSISTENT;
  }
  // The refusals after an anomaly carry their own sentences (each a core twin or a marked placeholder).
  if (err instanceof VaultNotOpenError) return SAVE_VAULT_NOT_OPEN;
  // Decided on 2026-11-17: nothing new is queued into a copy a server's policy is removing.
  if (err instanceof CopyBeingRemovedError) return copyRemovalText(err);
  if (err instanceof MoveWaitingError) return MOVE_WAITING_REFUSED;
  if (err instanceof VaultKeyNotVerifiedError || err instanceof NoPersonalVaultError || err instanceof ReadOnlyCopyError) return err.message;
  return "Save failed — nothing was changed.";
}
