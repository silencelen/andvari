/**
 * Signup reuse alert — the decision half (owner ask 2026-08-22).
 *
 * Pure and chrome-free, the knownlogins.ts/savetarget.ts idiom, so `node --test` pins every rule
 * below; content.ts owns the listeners and the SW round-trip, the SW and popup own the warning
 * (badge + popup line), and none of them decides anything this file does not.
 *
 * The rules here are not cosmetic — each one bounds when a typed password crosses to the service
 * worker, so loosening any of them widens that flow:
 *  - SIGNUP forms only, and only a NEW-password field. A sign-in re-typing its saved password is
 *    not "reuse", and warning there would fire on every login the user ever performs.
 *  - never while WE are filling: a generated password is unique by construction.
 *  - never twice for the same settled value on the same field (tab-through, or a blur that
 *    changed nothing).
 *  - a trivially short value is a half-typed one, not a decision worth interrupting.
 *  - H02 (2026-09-13 audit): only a value the USER TYPED — a trusted keystroke on that field.
 *    Every other input above is page-controlled: a page authors the two-password form (so
 *    isSignup/isNewPasswordField hold), sets `.value` to any guess, and drives a TRUSTED
 *    focusout with `focus(); blur()`. Without this rule that made the unlocked vault a
 *    password-membership oracle — the SW answered a count per guess, and the count was readable
 *    from the page by hit-testing the closed-shadow toast (elementFromPoint retargets to our host
 *    element; the toast renders iff count > 0). A page can forge focus and values but no page
 *    API produces a trusted keydown, so this is the login-capture gesture idiom (content.ts
 *    consumeLoginGesture) applied to the ask. Paste-by-context-menu and browser autofill leave
 *    the mark unset and simply get no warning — a missed nicety, never a leak.
 *  - Security review 2026-10 (root cause E): the mark is per VALUE, not per field. A per-field
 *    mark still let a page swap a guess in after each real keystroke (`field.value = guess;
 *    field.blur()`), one membership query per keypress. [ReuseCustody] tracks the value the user's
 *    own keystrokes produced, edit by edit from an empty field; anything a script wrote breaks the
 *    chain, and only the chained value is askable. The answer itself no longer reaches the page at
 *    all: the SW keeps the count and shows it in extension-owned UI (badge + popup), because a
 *    toast drawn in the page is readable by the page however it is styled.
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
  /** THIS value is the one the user's own keystrokes produced ([ReuseCustody.askable]). The one
   *  input here a page cannot forge — see the H02 rule and its 2026-10 tightening above. */
  typedByUser: boolean;
}

/** Whether a blurred field's value should be checked against the vault for reuse. */
export function shouldAskReuse(i: ReuseAskInput): boolean {
  if (i.filling) return false;
  // H02: the gesture gate sits FIRST among the form-shape rules — every rule below reads
  // page-controlled state, so none of them can stand in for it.
  if (!i.typedByUser) return false;
  if (!i.isSignup || !i.isNewPasswordField) return false;
  if (i.value.length < MIN_ASKABLE_LENGTH) return false;
  return i.lastAsked !== i.value;
}

/**
 * The warning for a reuse count, or null when there is nothing honest to say. Rendered by the
 * POPUP (security review 2026-10) — the page side never sees the count. `locked` returns
 * null deliberately: while locked the vault cannot be consulted, and "no warning" must never be
 * read as "not reused" — so the caller stays silent rather than implying an all-clear.
 */
export function reuseWarning(count: number, locked = false): string | null {
  if (locked || count <= 0) return null;
  return count === 1
    ? "The password you just typed on this page is already used for another login — a unique one is safer."
    : `The password you just typed on this page is already used for ${count} other logins — a unique one is safer.`;
}

/** The field state a trusted keydown sees, read by our capture listener before the browser edits. */
export interface KeySnapshot {
  value: string;
  /** Caret / selection (null where the input type exposes none — the edit is then taken at the end). */
  selStart: number | null;
  selEnd: number | null;
  /** `KeyboardEvent.key`. */
  key: string;
}

/** The value one real keystroke turns `a.value` into, or null when the edit is not one we can
 *  account for (composition, word deletes, drops, a cancelled key with script text) — custody is
 *  then simply lost, never guessed. */
function expectedEdit(a: KeySnapshot, inputType: string, data: string | null): string | null {
  const v = a.value;
  const s = Math.min(a.selStart ?? v.length, v.length);
  const e = Math.max(s, Math.min(a.selEnd ?? v.length, v.length));
  switch (inputType) {
    case "insertText":
      return data !== null && data === a.key ? v.slice(0, s) + data + v.slice(e) : null;
    case "deleteContentBackward":
      if (a.key !== "Backspace") return null;
      return s !== e ? v.slice(0, s) + v.slice(e) : v.slice(0, Math.max(0, s - 1)) + v.slice(s);
    case "deleteContentForward":
      if (a.key !== "Delete") return null;
      return s !== e ? v.slice(0, s) + v.slice(e) : v.slice(0, s) + v.slice(s + 1);
    default:
      return null;
  }
}

/**
 * Per-VALUE custody of what the user typed (security review 2026-10). Fed by content.ts's
 * capture-phase TRUSTED keydown and input listeners; a page can forge neither a trusted keydown
 * nor the browser's own edit, so a value reaches custody only as a chain of real keystrokes from an
 * empty field. Every way a page can touch the value breaks that chain:
 *  - written between keystrokes → the next keydown sees a value that is not the custody value;
 *  - written inside the keystroke (its own keydown/beforeinput handlers, a moved caret) → the
 *    browser's edit lands on the wrong base and the result is not the expected one;
 *  - written after it → the focusout value is not the custody value;
 *  - an edit no keystroke announced (execCommand, drop) → there is no armed keydown to account for it.
 * A broken chain recovers only from an empty field (the user cleared it). Generic over the field
 * type so node --test drives it without a DOM; WeakMaps so a replaced SPA field GCs away.
 */
export class ReuseCustody<F extends object> {
  private readonly typed = new WeakMap<F, string>();
  private readonly armed = new WeakMap<F, KeySnapshot>();

  keydown(field: F, snap: KeySnapshot): void {
    // The value the user's keystrokes produced so far; an empty field is always a clean start.
    if (snap.value !== "" && this.typed.get(field) !== snap.value) {
      this.typed.delete(field);
      this.armed.delete(field);
      return;
    }
    if (snap.value === "") this.typed.set(field, "");
    this.armed.set(field, snap);
  }

  input(field: F, value: string, inputType: string, data: string | null): void {
    const a = this.armed.get(field);
    this.armed.delete(field); // one keystroke accounts for one edit
    const expected = a === undefined ? null : expectedEdit(a, inputType, data);
    if (expected !== null && value === expected) this.typed.set(field, value);
    else this.typed.delete(field);
  }

  /** May [value] be asked about? Only when it IS the user-typed value of this field. */
  askable(field: F, value: string): boolean {
    return value !== "" && this.typed.get(field) === value;
  }

  /** Our own fill replaced the field: nothing in it is the user's typing any more. */
  reset(field: F): void {
    this.typed.delete(field);
    this.armed.delete(field);
  }
}
