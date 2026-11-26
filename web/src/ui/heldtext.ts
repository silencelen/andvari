import type { HeldChange } from "../vault/logstore";
import type { LifecycleNotice } from "../vault/store";
import { fmtDate, fmtDay } from "./format";
import {
  MOVE_UNNAMED_VAULT,
  RESEND_FOUND_MADE_HALF_MADE_DELETE,
  RESEND_FOUND_MADE_HALF_MADE_DELETE_NO_DAY,
  fill,
  RESEND_FOUND_MADE_ADD,
  RESEND_FOUND_MADE_CHANGE,
  RESEND_FOUND_MADE_DELETE,
  RESEND_FOUND_MADE_OFFER,
  RESEND_FOUND_MADE_REMOVE,
  RESEND_FOUND_MADE_ROLE,
  RESEND_FOUND_NOT_MADE,
  RESEND_GIVEN_UP_ADD,
  RESEND_GIVEN_UP_CHANGE,
  RESEND_GIVEN_UP_DELETE,
  RESEND_GIVEN_UP_OFFER,
  RESEND_GIVEN_UP_REMOVE,
  RESEND_GIVEN_UP_ROLE,
  RESEND_NOT_MADE_ADD,
  RESEND_NOT_MADE_CHANGE,
  RESEND_NOT_MADE_REMOVE,
  RESEND_SOMEONE,
  RESEND_WAITING_ADD_NOT_STORED,
  RESEND_WAITING_ADD_UNKNOWN,
  RESEND_WAITING_DELETE_NOT_STORED,
  RESEND_WAITING_DELETE_UNKNOWN,
  RESEND_WAITING_OFFER_NOT_STORED,
  RESEND_WAITING_OFFER_UNKNOWN,
  RESEND_WAITING_OTHER,
  RESEND_WAITING_REMOVE_NOT_STORED,
  RESEND_WAITING_REMOVE_UNKNOWN,
  RESEND_WAITING_ROLE_NOT_STORED,
  RESEND_WAITING_ROLE_UNKNOWN,
  RESEND_WAITING_STORED,
} from "./copy";

/**
 * The notice for a change that was kept to be sent again and did not happen (`held-not-made`), that waited a day and
 * was given up with its outcome unknown (`held-given-up`: never "nothing changed"), or that this browser withdrew or
 * gave up and the log, read since, holds after all (`held-found-made`, with the way to undo it) or, after a withdrawal,
 * does not hold (`held-found-not-made`): what it was, whom it named, in which vault.
 */
export function heldNoticeText(n: Pick<LifecycleNotice, "kind" | "heldKind" | "memberName" | "vaultName" | "halfMade" | "signedAt" | "purgeAt">): string {
  const who = n.memberName || RESEND_SOMEONE;
  const vault = n.vaultName || "a vault";
  // The day only where the server served it; otherwise the line points to the list of deleted vaults.
  if (n.kind === "held-found-made" && n.halfMade === true && n.purgeAt === undefined) return fill(RESEND_FOUND_MADE_HALF_MADE_DELETE_NO_DAY, n.vaultName || MOVE_UNNAMED_VAULT, fmtDate(n.signedAt));
  if (n.kind === "held-found-made" && n.halfMade === true) return fill(RESEND_FOUND_MADE_HALF_MADE_DELETE, n.vaultName || MOVE_UNNAMED_VAULT, fmtDate(n.signedAt), fmtDay(n.purgeAt));
  if (n.kind === "held-found-made") {
    if (n.heldKind === "add") return fill(RESEND_FOUND_MADE_ADD, who, vault);
    if (n.heldKind === "remove") return fill(RESEND_FOUND_MADE_REMOVE, who, vault);
    if (n.heldKind === "role") return fill(RESEND_FOUND_MADE_ROLE, who, vault);
    if (n.heldKind === "offer") return fill(RESEND_FOUND_MADE_OFFER, who, vault);
    if (n.heldKind === "delete") return fill(RESEND_FOUND_MADE_DELETE, who, vault);
    return fill(RESEND_FOUND_MADE_CHANGE, vault);
  }
  if (n.kind === "held-found-not-made") return fill(RESEND_FOUND_NOT_MADE, vault);
  if (n.kind === "held-given-up") {
    if (n.heldKind === "remove") return fill(RESEND_GIVEN_UP_REMOVE, who, vault);
    if (n.heldKind === "add") return fill(RESEND_GIVEN_UP_ADD, who, vault);
    if (n.heldKind === "role") return fill(RESEND_GIVEN_UP_ROLE, who, vault);
    if (n.heldKind === "offer") return fill(RESEND_GIVEN_UP_OFFER, who, vault);
    if (n.heldKind === "delete") return fill(RESEND_GIVEN_UP_DELETE, who, vault);
    return fill(RESEND_GIVEN_UP_CHANGE, vault);
  }
  if (n.heldKind === "add") return fill(RESEND_NOT_MADE_ADD, who, vault);
  if (n.heldKind === "remove") return fill(RESEND_NOT_MADE_REMOVE, who, vault);
  return fill(RESEND_NOT_MADE_CHANGE, vault);
}

/** The member panel's line for the change of this vault that waits to be sent ({@link HeldChange}), or null when none. */
export function heldWaitingText(c: HeldChange | null): string | null {
  if (c === null) return null;
  if (c.known === "stored") return RESEND_WAITING_STORED;
  const who = c.memberLabel || RESEND_SOMEONE;
  const notStored = c.known === "not_stored";
  if (c.kind === "add") return fill(notStored ? RESEND_WAITING_ADD_NOT_STORED : RESEND_WAITING_ADD_UNKNOWN, who);
  if (c.kind === "remove") return fill(notStored ? RESEND_WAITING_REMOVE_NOT_STORED : RESEND_WAITING_REMOVE_UNKNOWN, who);
  if (c.kind === "role") return fill(notStored ? RESEND_WAITING_ROLE_NOT_STORED : RESEND_WAITING_ROLE_UNKNOWN, who);
  if (c.kind === "offer") return fill(notStored ? RESEND_WAITING_OFFER_NOT_STORED : RESEND_WAITING_OFFER_UNKNOWN, who);
  if (c.kind === "delete" && c.withdrawable) return notStored ? RESEND_WAITING_DELETE_NOT_STORED : RESEND_WAITING_DELETE_UNKNOWN;
  return RESEND_WAITING_OTHER;
}
