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
  | "upgrade_required"
  | "identity_mismatch"
  | "server_error"
  | "network"
  | "unknown";
type SaveErrorCode = "locked" | "conflict" | "failed";

/** Verbatim web/src/ui/errors.ts UNREACHABLE — the one canonical "can't reach the server"
 *  sentence, duplicated as a const because no build path from extension/ to web/src exists. */
export const UNREACHABLE = "Can't reach the andvari server — check you're on the home network or VPN, then try again.";

/**
 * Unlock failures → web's FreshStart ladder (Welcome.tsx), verbatim where web has the
 * sentence. The extension flow is a full sign-in, not the unlock gate, so the 401 copy is
 * the sign-in form ("Wrong email or master password."). Extension-specific rungs:
 *  - totp_required: the popup has no TOTP field (A1 territory) — route to the web vault.
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
      return "This account requires a one-time code — sign in from the web vault.";
    case "upgrade_required":
      return "Your server requires a newer extension — get the update from the web vault or the link above.";
    case "identity_mismatch":
      return "Server identity key mismatch — possible tampering. Do not proceed; contact your admin.";
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
