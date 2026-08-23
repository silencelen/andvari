/**
 * Signup reuse alert — the decision half (owner ask 2026-08-22).
 *
 * Pure and chrome-free, the knownlogins.ts/savetarget.ts idiom, so `node --test` pins every rule
 * below; content.ts owns the listener, the SW round-trip and the toast, and decides nothing.
 *
 * The rules here are not cosmetic — each one bounds when a typed password crosses to the service
 * worker, so loosening any of them widens that flow:
 *  - SIGNUP forms only, and only a NEW-password field. A sign-in re-typing its saved password is
 *    not "reuse", and warning there would fire on every login the user ever performs.
 *  - never while WE are filling: a generated password is unique by construction.
 *  - never twice for the same settled value on the same field (tab-through, or a blur that
 *    changed nothing).
 *  - a trivially short value is a half-typed one, not a decision worth interrupting.
 */

/** Below this, the user is still typing — asking would both nag and ship fragments to the SW. */
export const MIN_ASKABLE_LENGTH = 4;

export interface ReuseAskInput {
  /** The field's current value. */
  value: string;
  /** The value last asked about for THIS field, if any. */
  lastAsked: string | undefined;
  /** True while the extension is writing into the page itself. */
  filling: boolean;
  /** The detected form is a registration form (detect.ts isSignup). */
  isSignup: boolean;
  /** This exact field is one of the form's new-password targets (detect.ts newPasswords). */
  isNewPasswordField: boolean;
}

/** Whether a blurred field's value should be checked against the vault for reuse. */
export function shouldAskReuse(i: ReuseAskInput): boolean {
  if (i.filling) return false;
  if (!i.isSignup || !i.isNewPasswordField) return false;
  if (i.value.length < MIN_ASKABLE_LENGTH) return false;
  return i.lastAsked !== i.value;
}

/**
 * The warning for a reuse count, or null when there is nothing honest to say. `locked` returns
 * null deliberately: while locked the vault cannot be consulted, and "no warning" must never be
 * read as "not reused" — so the caller stays silent rather than implying an all-clear.
 */
export function reuseWarning(count: number, locked = false): string | null {
  if (locked || count <= 0) return null;
  return count === 1
    ? "You already use this password for another login — a unique one is safer."
    : `You already use this password for ${count} other logins — a unique one is safer.`;
}
