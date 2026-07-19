/**
 * User-facing copy for the popup and content surfaces — the extension's port of the
 * fleet error canon (E1-3 / E1-5 / E1-7). Codes cross the message seam (messages.ts);
 * SENTENCES live only here — background.ts never ships user-facing text, and surfaces
 * never render its raw `error` debug detail. Chrome-free on purpose: errors.test.ts
 * pins every string verbatim under node --test, so cross-client copy drift fails a
 * test instead of confusing a family member.
 */

// Structural twins of the messages.ts seam types (the pinned E1 contract). Deliberately
// declared locally, not imported: this file stays dependency-free so the copy tests run
// standalone. The unions must stay literal-identical to messages.ts UnlockCode/SaveErrorCode.
type UnlockCode =
  | "bad_credentials"
  | "totp_required"
  | "totp_bad_code"
  | "totp_rate_limited"
  | "totp_expired"
  | "totp_enroll_required"
  | "aborted"
  | "upgrade_required"
  | "identity_mismatch"
  | "kdf_policy"
  | "server_error"
  | "network"
  | "unknown";
type SaveErrorCode = "locked" | "conflict" | "failed";
type FillFailCode = "locked" | "not_allowed" | "no_form" | "no_fields" | "no_secret" | "unreachable";
type RevealFailCode = "locked" | "not_allowed";
// Structural twins of the messages.ts quick-unlock seam types (spec 01 §8.4). Kept literal-identical.
type PinUnlockCode =
  | "wrong_pin"
  | "expired"
  | "exhausted"
  | "not_armed"
  | "corrupt"
  | "stale_uvk"
  | "revoked"
  | "network"
  | "server_error"
  | "identity_mismatch"
  | "kdf_policy"
  | "aborted";
type PinWeakReason = "too_short" | "digits_need_length" | "trivial";
type EnrollCode = "locked" | "must_change_password" | "need_full_unlock" | "weak_pin";
// Biometric quick-unlock (0.17.0) twins — literal-identical to messages.ts BioUnlockCode / EnrollBioCode.
type BioUnlockCode =
  | "bio_cancelled"
  | "not_armed"
  | "expired"
  | "corrupt"
  | "stale_uvk"
  | "revoked"
  | "network"
  | "server_error"
  | "identity_mismatch"
  | "kdf_policy"
  | "aborted";
type EnrollBioCode = "locked" | "must_change_password" | "need_full_unlock" | "bio_unsupported" | "bio_cancelled";

/** Verbatim web/src/ui/errors.ts UNREACHABLE — the one canonical "can't reach the server"
 *  sentence, duplicated as a const because no build path from extension/ to web/src exists. */
export const UNREACHABLE = "Can't reach the andvari server — check you're on the home network or VPN, then try again.";

/**
 * Unlock failures → web's FreshStart ladder (Welcome.tsx), verbatim where web has the
 * sentence. The extension flow is a full sign-in, not the unlock gate, so the 401 copy is
 * the sign-in form ("Wrong email or master password."). Extension-specific rungs:
 *  - totp_required (0.16.3): the popup flips to a one-time-code field — this copy is the INSTRUCTION
 *    shown there (rendered as info/polite, not an error). totp_bad_code/rate_limited/expired are the
 *    retry rungs; totp_enroll_required routes a restricted (instance-requires-TOTP) session to the web app.
 *  - upgrade_required: the update banner exists only when a strictly-newer build is
 *    actually PUBLISHED, so the copy must not hard-promise the link (AM5).
 *  - identity_mismatch: web IdentityMismatchError's exact sentence — a hard security
 *    fault that must NEVER soften into wrong-password.
 */
export function unlockErrorCopy(code: UnlockCode | undefined): string {
  switch (code) {
    case "bad_credentials":
      return "Wrong email or master password.";
    case "totp_required":
      return "Enter the 6-digit code from your authenticator app.";
    case "totp_bad_code":
      return "That code didn’t work — codes change every 30 seconds, so try the current one.";
    case "totp_rate_limited":
      return "Too many attempts — wait a minute, then sign in again.";
    case "totp_expired":
      return "That took too long — sign in again.";
    case "totp_enroll_required":
      return "This server requires two-factor setup — finish it in the web vault, then sign in here.";
    case "aborted":
      // A switch/lock landed mid-sign-in; the popup silently re-renders, so this is a fallback only.
      return "Sign-in was interrupted — try again.";
    case "upgrade_required":
      return "Your server requires a newer extension — get the update from the web vault or the link above.";
    case "identity_mismatch":
      return "Server identity key mismatch — possible tampering. Do not proceed; contact your admin.";
    case "kdf_policy":
      // H1 (spec 05 T1): the server sent weakened master-password security settings — a hard block,
      // never softened into wrong-password.
      return "This server sent weakened security settings for your master password. Sign-in was blocked to protect you — contact your admin.";
    case "server_error":
      return "The server had a problem answering — your details may be fine. Try again in a moment.";
    case "network":
      return UNREACHABLE;
    default:
      // "unknown" and an absent code (e.g. SW mid-restart) share web's terminal fallback.
      return "Sign-in failed. Please try again.";
  }
}

/** Locked-save banner result line (E1-5): the SW answers a code, never a sentence — the old
 *  path leaked its internal "locked" / "save failed (conflict)" strings into the red line. */
export function saveErrorCopy(code: SaveErrorCode | undefined): string {
  switch (code) {
    case "locked":
      return "Could not save — unlock andvari and try again.";
    case "conflict":
      return "This login changed elsewhere — open it in the web vault.";
    default:
      // "failed" and an absent code (SW unreachable) — retryable, no jargon.
      return "Could not save — try again.";
  }
}

/** Fill-failure line (Cut M, v2 #14): shared by the in-page dropdown toast and the popup's
 *  "Fill this page" #msg strip — the fill paths used to fail SILENTLY (dropdown closed, popup
 *  reported delivery as success). Codes come from messages.ts FillOutcome/FillFailCode; the
 *  content script is the ground truth for what actually landed in the page's fields. */
export function fillErrorCopy(code: FillFailCode | undefined): string {
  switch (code) {
    case "locked":
      return "andvari locked before it could fill — unlock and try again.";
    case "not_allowed":
      return "andvari wouldn't release this login for this page — try again from the popup.";
    case "no_form":
      return "No login fields found on this page — copy the username and password instead.";
    case "no_fields":
      return "Couldn't fill the fields on this page — copy the username and password instead.";
    case "no_secret":
      return "Nothing to fill — this login has no username or password saved.";
    default:
      // "unreachable" and an absent code (SW mid-restart / no outcome from the page) share the
      // popup's long-standing delivery-failure sentence.
      return "Couldn't reach the page — reload the tab and retry.";
  }
}

/** Reveal-seam failure line (#23 string sweep): the popup's clipboard path AND the show/hide
 *  password toggle both used to render the SW's raw `error` debug detail ("locked" / "unknown
 *  item" / "not allowed for this site") straight into the #msg strip. Codes come from the reveal
 *  seam (messages.ts); the popup always asks with explicit:true, so not_allowed here means a stale
 *  row — the item changed or vanished under a sync — not a host mismatch. Verb-neutral ("release
 *  that login", not "copy") because the same sentences render on the show-password path too. */
export function revealErrorCopy(code: RevealFailCode | undefined): string {
  switch (code) {
    case "locked":
      return "andvari locked before it could release that login — unlock and try again.";
    case "not_allowed":
      return "andvari wouldn't release that login — reopen the popup and try again.";
    default:
      // an absent code (SW mid-restart) — retryable, no jargon (the saveErrorCopy idiom).
      return "Could not release that login — try again.";
  }
}

/**
 * Quick-unlock redeem failure (spec 01 §8.4). `wrong_pin` is the generic no-oracle line (breaker
 * A1/A2 — it reveals no partial correctness and never distinguishes a wrong PIN from a corrupt blob);
 * it carries the remaining attempts. A wiped-blob outcome (exhausted/corrupt/stale_uvk) and a revoked
 * session route the user to the master password; identity_mismatch/kdf_policy keep their hard-fault
 * sentences (never softened). The PIN never touches the wire, so there is no remote oracle at all.
 */
export function pinUnlockErrorCopy(code: PinUnlockCode | undefined, attemptsRemaining?: number): string {
  switch (code) {
    case "wrong_pin": {
      const n = typeof attemptsRemaining === "number" ? attemptsRemaining : 0;
      return `That PIN didn't match — ${n} ${n === 1 ? "try" : "tries"} left, or use your master password.`;
    }
    case "expired":
      return "It's been a while since you signed in — enter your master password to continue.";
    case "exhausted":
      return "Too many wrong PINs — quick unlock is off. Unlock with your master password.";
    case "corrupt":
    case "stale_uvk":
      return "Quick unlock needs to be set up again — unlock with your master password.";
    case "revoked":
      return "Your session ended — sign in again with your master password.";
    case "identity_mismatch":
      return "Server identity key mismatch — possible tampering. Do not proceed; contact your admin.";
    case "kdf_policy":
      return "This server sent weakened security settings for your master password. Sign-in was blocked to protect you — contact your admin.";
    case "server_error":
      return "The server had a problem answering — try again in a moment.";
    case "network":
      return UNREACHABLE;
    default:
      // not_armed / aborted (benign races) and an absent code — fall to the master password quietly.
      return "Couldn't quick-unlock — unlock with your master password.";
  }
}

/** Quick-unlock enrollment refusal (spec 01 §8.4). `weak_pin` carries the entropy-floor reason
 *  (breaker A2⊕B8 — enforcement, not copy-only). */
export function enrollErrorCopy(code: EnrollCode | undefined, reason?: PinWeakReason): string {
  switch (code) {
    case "locked":
      return "Unlock andvari first to set up quick unlock.";
    case "must_change_password":
      return "Set a new master password in the web vault before turning on quick unlock.";
    case "need_full_unlock":
      return "Enter your master password once more to set up quick unlock.";
    case "weak_pin":
      switch (reason) {
        case "too_short":
          return "Use at least 6 characters for your PIN.";
        case "digits_need_length":
          return "An all-number PIN needs at least 10 digits — or add a letter to a shorter one.";
        default:
          return "That PIN is too easy to guess — avoid sequences and repeats.";
      }
    default:
      return "Couldn't turn on quick unlock — try again.";
  }
}

/**
 * Biometric quick-unlock redeem failure (0.17.0). No `wrong_pin`/`exhausted` (a hardware-held PRF secret
 * has no offline oracle). `bio_cancelled` = the OS prompt was dismissed / timed out / the passkey was
 * deleted — all indistinguishable by design, and all retryable. Wiped-blob outcomes (expired/corrupt/
 * stale_uvk) and a revoked session route to the master password; hard faults keep their sentences.
 */
export function bioUnlockErrorCopy(code: BioUnlockCode | undefined): string {
  switch (code) {
    case "bio_cancelled":
      return "Device unlock was cancelled — try again, or use your master password.";
    case "expired":
      return "It's been a while since you signed in — enter your master password to continue.";
    case "corrupt":
    case "stale_uvk":
      return "Quick unlock needs to be set up again — unlock with your master password.";
    case "revoked":
      return "Your session ended — sign in again with your master password.";
    case "identity_mismatch":
      return "Server identity key mismatch — possible tampering. Do not proceed; contact your admin.";
    case "kdf_policy":
      return "This server sent weakened security settings for your master password. Sign-in was blocked to protect you — contact your admin.";
    case "server_error":
      return "The server had a problem answering — try again in a moment.";
    case "network":
      return UNREACHABLE;
    default:
      // not_armed / aborted (benign races) and an absent code — fall to the master password quietly.
      return "Couldn't unlock with your device — unlock with your master password.";
  }
}

/** Biometric enrollment refusal (0.17.0). `bio_unsupported` = no platform authenticator / no PRF on this
 *  device (the PIN stays available); `bio_cancelled` = the setup prompt was dismissed (nothing written). */
export function enrollBioErrorCopy(code: EnrollBioCode | undefined): string {
  switch (code) {
    case "locked":
      return "Unlock andvari first to set up quick unlock.";
    case "must_change_password":
      return "Set a new master password in the web vault before turning on quick unlock.";
    case "need_full_unlock":
      return "Enter your master password once more to set up quick unlock.";
    case "bio_unsupported":
      return "This device can't do biometric quick unlock — set up a PIN instead.";
    case "bio_cancelled":
      return "Setup was cancelled — try again when you're ready.";
    default:
      return "Couldn't turn on device quick unlock — try again.";
  }
}

/** Card-field copy failure (#23): the card seam carries no code (messages.ts) — one honest
 *  retryable sentence, never the SW's internal "unknown item"/"no number on this card". The
 *  popup's has* flags gate the buttons, so a real miss is a locked race or a stale row. */
export const CARD_COPY_FAILED = "Could not copy from this card — reopen the popup and try again.";

/** Clipboard write refused (#23; focus loss / browser policy) — never the raw exception text. */
export const CLIPBOARD_FAILED = "Couldn't copy to the clipboard — try again.";

/**
 * F26 lock-reason line (E1-7): verbatim port of web format.ts inactivityNotice. Seconds
 * render ONLY below 60 s; anything ≥ 60 s renders whole minutes via Math.round (AM3 —
 * 90 s → "2 minutes"); the seconds branch clamps to ≥ 1 s.
 */
export function lockNoticeCopy(seconds: number): string {
  if (seconds >= 60) {
    const m = Math.round(seconds / 60);
    return `Locked after ${m} minute${m === 1 ? "" : "s"} of inactivity.`;
  }
  const s = Math.max(1, Math.round(seconds));
  return `Locked after ${s} second${s === 1 ? "" : "s"} of inactivity.`;
}
