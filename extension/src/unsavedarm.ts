/**
 * Design §4.4 (decided on 2026-11-17): nothing this browser holds that was not sent is deleted without the person having
 * been told how many. What the extension holds of that kind is what it captured on pages and has not saved to the vault
 * (Res<"status">.unsavedCaptures): it keeps no queue of changes, since everything else it changes is sent at once or
 * refused. A sign-out deletes those captures, and so does a lock of an open vault (a page's password is not kept past
 * a lock). The popup's Sign out and Lock say how many on their first click and act on the second.
 */
import * as T from "./copy.ts";
import { fillApproved } from "./errors.ts";

export type UnsavedAct = "signout" | "lock";

/**
 * The line for [count] unsaved captures before [act], with how to save them first when [canSave] (the vault is open and
 * its session live); null when there are none.
 */
export function unsavedCapturesLine(act: UnsavedAct, count: number, canSave: boolean): string | null {
  if (count <= 0) return null;
  const line = act === "signout" ? (count === 1 ? T.SIGN_OUT_UNSAVED_ONE : fillApproved(T.SIGN_OUT_UNSAVED_MANY, String(count))) : count === 1 ? T.LOCK_UNSAVED_ONE : fillApproved(T.LOCK_UNSAVED_MANY, String(count));
  return canSave ? `${line} ${T.UNSAVED_SAVE_FIRST}` : line;
}

/**
 * The line the popup says once, above the unlock form, for [count] captures that a lock or sign-out nobody was asked
 * about deleted unsaved (Res<"status">.capturesLost); null when there were none. It claims no way to bring them back:
 * a page's password is not kept past a lock, only this number is.
 */
export function capturesLostLine(count: number): string | null {
  if (!(count > 0)) return null;
  return count === 1 ? T.CAPTURES_LOST_ONE : fillApproved(T.CAPTURES_LOST_MANY, String(count));
}

/** "Cannot tell", for [unsavedArmStep]: the worker did not answer the count. Arms like a count, never like none. */
export const COUNT_UNKNOWN = -1;

/** The line at the first click of "Forget this server" for [count] captures ([COUNT_UNKNOWN]: cannot tell); null for none. */
export function forgetUnsavedLine(count: number): string | null {
  if (count === COUNT_UNKNOWN) return T.FORGET_UNSAVED_UNKNOWN;
  if (count <= 0) return null;
  return count === 1 ? T.FORGET_UNSAVED_ONE : fillApproved(T.FORGET_UNSAVED_MANY, String(count));
}

/**
 * One click of the popup's Sign out or Lock (and of the options page's "Forget this server", which asks as Lock does, a
 * count it cannot read included): [armed] is the count the first click showed (null: not armed), [now] the
 * count at this click. A sign-out always asks once ([alwaysAsk]); a lock asks only over captures. The act happens on a
 * second click over the same count, or when nothing is at stake any more; a count that moved arms again with the new one.
 */
export function unsavedArmStep(armed: number | null, now: number, alwaysAsk: boolean): { act: boolean; armed: number | null } {
  if (armed === null) return !alwaysAsk && now === 0 ? { act: true, armed: null } : { act: false, armed: now };
  if (now === armed || now === 0) return { act: true, armed: null };
  return { act: false, armed: now };
}
