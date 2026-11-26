import { WEAK_KDF_MESSAGE } from "../crypto/keys";
import { ReauthStaleSessionError } from "../vault/account";
import { ESCROW_WRONG_FORM, LABEL_NOT_THIS_ACCOUNT, NO_SESSION_WRAP, PASSWORD_CHANGE_UNCONFIRMED, type PasswordChanged, PENDING_CHANGE_UNSETTLED, PROOF_REFUSED, type Reauthed, SERVER_KEYS_NOT_KNOWN, type TwoStepOff, type TwoStepSetup } from "../vault/settingsflow";
import {
  ESCROW_WRONG_FORM_TEXT, fill, KDF_NOT_USABLE, PASSWORD_CHANGE_NOT_CONFIRMED, passwordRuleText, KIT_ROTATE_SESSION_ENDED, SERVER_KEYS_NOT_KNOWN_REFUSED, SERVER_REFUSED_PROOF, KIT_ROTATE_UNKNOWN, KIT_ROTATE_WRONG_PASSWORD, PASSWORD_CHANGE_UNKNOWN, PASSWORD_CHANGED_COPY_STALE, SIGNIN_BACKOFF,
  TOTP_OFF_DONE, TOTP_OFF_DONE_REQUIRED, TOTP_OFF_SESSION_ENDED, TOTP_OFF_UNKNOWN, TOTP_OFF_WAIT, TOTP_WAIT_MINUTE, TOTP_WAIT_MINUTES, TOTP_WAIT_SECOND, TOTP_WAIT_SECONDS,
  TOTP_SETUP_NOT_THIS_ACCOUNT, TOTP_SETUP_SESSION_ENDED, TOTP_SETUP_UNKNOWN, TOTP_WRONG_CODE, TOTP_WRONG_PASSWORD,
} from "./copy";

/**
 * What the person reads when a password-confirmed Settings flow (vault/settingsflow.ts) did not land. Nothing
 * changed in each case except `unknown`, which is never read as a failure.
 */
/** The same for "Make a new recovery kit" (spec 03 §12): nothing was rotated in each case except `unknown`. */
export function kitRotateText(r: Exclude<Reauthed<unknown>, { kind: "done" }>): string {
  switch (r.kind) {
    case "wrong_password":
      return KIT_ROTATE_WRONG_PASSWORD;
    case "session_ended":
      return KIT_ROTATE_SESSION_ENDED;
    case "unknown":
      return KIT_ROTATE_UNKNOWN;
    default:
      return passwordChangeText(r);
  }
}

/** The wait a `429` named, in words; the sign-in back-off's own sentence when it named none. */
export function waitText(retryAfterS: number | null): string {
  if (retryAfterS === null || !Number.isFinite(retryAfterS) || retryAfterS < 1) return SIGNIN_BACKOFF;
  const s = Math.ceil(retryAfterS);
  const words = s < 60 ? (s === 1 ? TOTP_WAIT_SECOND : fill(TOTP_WAIT_SECONDS, String(s))) : Math.ceil(s / 60) === 1 ? TOTP_WAIT_MINUTE : fill(TOTP_WAIT_MINUTES, String(Math.ceil(s / 60)));
  return fill(TOTP_OFF_WAIT, words);
}

/**
 * What the two-factor card says after "Turn off" ({@link TwoStepOff}): the done line as info, everything else as an
 * error. Nothing changed in each error case except `unknown`, which says it may have.
 */
export function twoStepOffText(r: TwoStepOff, totpRequired: boolean): { readonly kind: "info" | "err"; readonly text: string } {
  switch (r.kind) {
    case "done":
      return { kind: "info", text: totpRequired ? TOTP_OFF_DONE_REQUIRED : TOTP_OFF_DONE };
    case "wrong_password":
      return { kind: "err", text: TOTP_WRONG_PASSWORD };
    case "wrong_code":
      return { kind: "err", text: TOTP_WRONG_CODE };
    case "wait":
      return { kind: "err", text: waitText(r.retryAfterS) };
    case "session_ended":
      return { kind: "err", text: TOTP_OFF_SESSION_ENDED };
    case "unknown":
      return { kind: "err", text: TOTP_OFF_UNKNOWN };
    case "password_rule":
    case "refused":
      return { kind: "err", text: passwordChangeText(r) };
  }
}

/** The card's line when setting two-step sign-in up did not answer a secret (the existing sentences of the off step). */
export function twoStepSetupText(r: Exclude<TwoStepSetup, { kind: "setup" }>): string {
  switch (r.kind) {
    case "wrong_password":
      return TOTP_WRONG_PASSWORD;
    case "wait":
      return waitText(r.retryAfterS);
    case "session_ended":
      return TOTP_SETUP_SESSION_ENDED;
    case "unknown":
      return TOTP_SETUP_UNKNOWN;
    case "refused":
      if (r.code === LABEL_NOT_THIS_ACCOUNT) return TOTP_SETUP_NOT_THIS_ACCOUNT;
      return passwordChangeText(r);
    case "password_rule":
      return passwordChangeText(r);
  }
}

/** The note after a change the server made; with the copy line when this browser's offline copy did not take it. */
export function passwordChangedText(r: PasswordChanged): string {
  const done = "Master password changed — sessions on other devices were signed out.";
  return r.copy === "failed" ? `${done} ${PASSWORD_CHANGED_COPY_STALE}` : done;
}

export function passwordChangeText(r: Exclude<Reauthed<unknown>, { kind: "done" }>): string {
  switch (r.kind) {
    case "wrong_password":
      return "Current master password is wrong.";
    case "password_rule":
      return passwordRuleText(r.decision);
    case "session_ended":
      return "Your session ended — sign in again, then change the password.";
    case "rate_limited":
      return SIGNIN_BACKOFF;
    case "refused":
      // This tab keeps no wrap to prove against (spec 01 §7): nothing was sent; the core twin's sentence says what to do.
      // An earlier change is unsettled and the server holds neither wrap: the next unlock settles it (core's sentence).
      if (r.code === NO_SESSION_WRAP || r.code === PENDING_CHANGE_UNSETTLED) return new ReauthStaleSessionError().message;
      // A password change has no answer and the server's keys could not be read: nothing was sent, either password may be the server's.
      if (r.code === PASSWORD_CHANGE_UNCONFIRMED) return PASSWORD_CHANGE_NOT_CONFIRMED;
      // Spec 01 §7: a proof refused while the session is marked as holding keys the server does not.
      if (r.code === SERVER_KEYS_NOT_KNOWN) return SERVER_KEYS_NOT_KNOWN_REFUSED;
      // Spec 01 §7: the server refused a proof made here: never a wrong password.
      if (r.code === PROOF_REFUSED) return SERVER_REFUSED_PROOF;
      // The recovery settings' write reports the server's code as it came (its mapping is the escrow work's, not this
      // file's): the back-off reads the same as everywhere else.
      if (r.code === "rate_limited") return SIGNIN_BACKOFF;
      // A recovery copy of a form the server no longer stores: its own sentence, never the raw code.
      if (r.code === ESCROW_WRONG_FORM) return ESCROW_WRONG_FORM_TEXT;
      if (r.code === "kdf_not_whole") return KDF_NOT_USABLE;
      return r.code === "kdf_below_floor" || r.code === "kdf_above_ceiling" ? WEAK_KDF_MESSAGE : `The server refused the change (${r.code}). Nothing changed.`;
    case "unknown":
      return PASSWORD_CHANGE_UNKNOWN;
  }
}
