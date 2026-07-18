// node --test (see version.test.ts). Pins every user-facing sentence the surfaces render
// (E1-3/E1-5/E1-7) — these are VERBATIM ports of the web canon, so any edit here or there
// is cross-client copy drift and must be a deliberate, twin-side change.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  CARD_COPY_FAILED,
  CLIPBOARD_FAILED,
  enrollErrorCopy,
  fillErrorCopy,
  lockNoticeCopy,
  pinUnlockErrorCopy,
  revealErrorCopy,
  saveErrorCopy,
  UNREACHABLE,
  unlockErrorCopy,
} from "./errors.ts";

test("UNREACHABLE is the canonical web sentence", () => {
  // Byte-equal to web/src/ui/errors.ts UNREACHABLE (em dash U+2014, ASCII apostrophes).
  // Duplicated because no build path from extension/ to web/src exists.
  assert.equal(UNREACHABLE, "Can't reach the andvari server — check you're on the home network or VPN, then try again.");
});

test("unlock ladder: every code renders the exact copy", () => {
  assert.equal(unlockErrorCopy("bad_credentials"), "Wrong email or master password.");
  // 0.16.3: totp_required is no longer a web-vault dead-end — it's the instruction the popup shows
  // when it flips to the one-time-code field (rendered polite/info, not as an error).
  assert.equal(unlockErrorCopy("totp_required"), "Enter the 6-digit code from your authenticator app.");
  assert.equal(unlockErrorCopy("totp_bad_code"), "That code didn’t work — codes change every 30 seconds, so try the current one.");
  assert.equal(unlockErrorCopy("totp_rate_limited"), "Too many attempts — wait a minute, then sign in again.");
  assert.equal(unlockErrorCopy("totp_expired"), "That took too long — sign in again.");
  assert.equal(unlockErrorCopy("totp_enroll_required"), "This server requires two-factor setup — finish it in the web vault, then sign in here.");
  assert.equal(unlockErrorCopy("aborted"), "Sign-in was interrupted — try again.");
  // Deliberately does NOT hard-promise the banner link (AM5): a pin can name an
  // unpublished build, in which case no update banner materializes.
  assert.equal(unlockErrorCopy("upgrade_required"), "Your server requires a newer extension — get the update from the web vault or the link above.");
  // web IdentityMismatchError's message, byte-equal — never rendered as wrong-password.
  assert.equal(unlockErrorCopy("identity_mismatch"), "Server identity key mismatch — possible tampering. Do not proceed; contact your admin.");
  assert.equal(unlockErrorCopy("server_error"), "The server had a problem answering — your details may be fine. Try again in a moment.");
  assert.equal(unlockErrorCopy("network"), UNREACHABLE);
  assert.equal(unlockErrorCopy("unknown"), "Sign-in failed. Please try again.");
});

test("unlock ladder: an absent code falls back to the terminal sentence", () => {
  assert.equal(unlockErrorCopy(undefined), "Sign-in failed. Please try again.");
});

test("save banner: the three codes render copy, never SW-internal strings", () => {
  assert.equal(saveErrorCopy("locked"), "Could not save — unlock andvari and try again.");
  assert.equal(saveErrorCopy("conflict"), "This login changed elsewhere — open it in the web vault.");
  assert.equal(saveErrorCopy("failed"), "Could not save — try again.");
  assert.equal(saveErrorCopy(undefined), "Could not save — try again."); // SW unreachable
});

test("fill outcomes (Cut M, v2 #14): every code renders canon copy, never SW/content-internal strings", () => {
  assert.equal(fillErrorCopy("locked"), "andvari locked before it could fill — unlock and try again.");
  assert.equal(fillErrorCopy("not_allowed"), "andvari wouldn't release this login for this page — try again from the popup.");
  assert.equal(fillErrorCopy("no_form"), "No login fields found on this page — copy the username and password instead.");
  assert.equal(fillErrorCopy("no_fields"), "Couldn't fill the fields on this page — copy the username and password instead.");
  assert.equal(fillErrorCopy("no_secret"), "Nothing to fill — this login has no username or password saved.");
  // "unreachable" and an absent code (SW mid-restart / no outcome from the page) share the
  // popup's long-standing delivery-failure sentence.
  assert.equal(fillErrorCopy("unreachable"), "Couldn't reach the page — reload the tab and retry.");
  assert.equal(fillErrorCopy(undefined), "Couldn't reach the page — reload the tab and retry.");
});

test("reveal-seam failures (#23): every code renders verb-neutral copy, never SW-internal strings", () => {
  // Verb-neutral ("release that login") because these render on BOTH the copy button and the
  // show/hide password toggle — a "copy" verb would misdescribe the reveal action.
  assert.equal(revealErrorCopy("locked"), "andvari locked before it could release that login — unlock and try again.");
  assert.equal(revealErrorCopy("not_allowed"), "andvari wouldn't release that login — reopen the popup and try again.");
  assert.equal(revealErrorCopy(undefined), "Could not release that login — try again."); // SW mid-restart
});

test("quick-unlock redeem: wrong_pin is a generic no-oracle line carrying the remaining attempts", () => {
  // breaker A1/A2: no partial-correctness signal, no wrong-PIN-vs-corrupt-blob distinction.
  assert.equal(pinUnlockErrorCopy("wrong_pin", 4), "That PIN didn't match — 4 tries left, or use your master password.");
  assert.equal(pinUnlockErrorCopy("wrong_pin", 1), "That PIN didn't match — 1 try left, or use your master password."); // singular
  assert.equal(pinUnlockErrorCopy("wrong_pin", 0), "That PIN didn't match — 0 tries left, or use your master password.");
});

test("quick-unlock redeem: wiped-blob / revoked / hard-fault outcomes route to the right copy", () => {
  assert.equal(pinUnlockErrorCopy("expired"), "It's been a while since you signed in — enter your master password to continue.");
  assert.equal(pinUnlockErrorCopy("exhausted"), "Too many wrong PINs — quick unlock is off. Unlock with your master password.");
  assert.equal(pinUnlockErrorCopy("corrupt"), "Quick unlock needs to be set up again — unlock with your master password.");
  assert.equal(pinUnlockErrorCopy("stale_uvk"), "Quick unlock needs to be set up again — unlock with your master password.");
  assert.equal(pinUnlockErrorCopy("revoked"), "Your session ended — sign in again with your master password.");
  // Hard security faults keep their exact sentences — NEVER softened (parity with the unlock ladder).
  assert.equal(pinUnlockErrorCopy("identity_mismatch"), unlockErrorCopy("identity_mismatch"));
  assert.equal(pinUnlockErrorCopy("kdf_policy"), unlockErrorCopy("kdf_policy"));
  assert.equal(pinUnlockErrorCopy("network"), UNREACHABLE);
  assert.equal(pinUnlockErrorCopy("server_error"), "The server had a problem answering — try again in a moment.");
  // not_armed / aborted (benign races) + an absent code fall to the master password quietly.
  assert.equal(pinUnlockErrorCopy("aborted"), "Couldn't quick-unlock — unlock with your master password.");
  assert.equal(pinUnlockErrorCopy(undefined), "Couldn't quick-unlock — unlock with your master password.");
});

test("quick-unlock enroll: the entropy-floor nudges (breaker A2⊕B8) + the gate refusals", () => {
  assert.equal(enrollErrorCopy("weak_pin", "too_short"), "Use at least 6 characters for your PIN.");
  assert.equal(enrollErrorCopy("weak_pin", "digits_need_length"), "An all-number PIN needs at least 10 digits — or add a letter to a shorter one.");
  assert.equal(enrollErrorCopy("weak_pin", "trivial"), "That PIN is too easy to guess — avoid sequences and repeats.");
  assert.equal(enrollErrorCopy("locked"), "Unlock andvari first to set up quick unlock.");
  assert.equal(enrollErrorCopy("must_change_password"), "Set a new master password in the web vault before turning on quick unlock.");
  assert.equal(enrollErrorCopy("need_full_unlock"), "Enter your master password once more to set up quick unlock.");
  assert.equal(enrollErrorCopy(undefined), "Couldn't turn on quick unlock — try again.");
});

test("card + clipboard copy failures (#23): honest retryable sentences, never raw exception text", () => {
  assert.equal(CARD_COPY_FAILED, "Could not copy from this card — reopen the popup and try again.");
  assert.equal(CLIPBOARD_FAILED, "Couldn't copy to the clipboard — try again.");
});

test("lock notice: verbatim web format.ts rounding (AM3 — minutes at ≥ 60 s)", () => {
  assert.equal(lockNoticeCopy(900), "Locked after 15 minutes of inactivity.");
  // ≥ 60 s always renders whole minutes: Math.round(90/60) = 2 — never "90 seconds".
  assert.equal(lockNoticeCopy(90), "Locked after 2 minutes of inactivity.");
  assert.equal(lockNoticeCopy(60), "Locked after 1 minute of inactivity."); // singular
  assert.equal(lockNoticeCopy(45), "Locked after 45 seconds of inactivity.");
  assert.equal(lockNoticeCopy(1), "Locked after 1 second of inactivity."); // singular
  assert.equal(lockNoticeCopy(0), "Locked after 1 second of inactivity."); // clamp ≥ 1 s
});
