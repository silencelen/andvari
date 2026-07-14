// node --test (see version.test.ts). Pins every user-facing sentence the surfaces render
// (E1-3/E1-5/E1-7) — these are VERBATIM ports of the web canon, so any edit here or there
// is cross-client copy drift and must be a deliberate, twin-side change.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { CARD_COPY_FAILED, CLIPBOARD_FAILED, fillErrorCopy, lockNoticeCopy, revealErrorCopy, saveErrorCopy, UNREACHABLE, unlockErrorCopy } from "./errors.ts";

test("UNREACHABLE is the canonical web sentence", () => {
  // Byte-equal to web/src/ui/errors.ts UNREACHABLE (em dash U+2014, ASCII apostrophes).
  // Duplicated because no build path from extension/ to web/src exists.
  assert.equal(UNREACHABLE, "Can't reach the andvari server — check you're on the home network or VPN, then try again.");
});

test("unlock ladder: all seven codes render web's exact copy", () => {
  assert.equal(unlockErrorCopy("bad_credentials"), "Wrong email or master password.");
  assert.equal(unlockErrorCopy("totp_required"), "This account requires a one-time code — sign in from the web vault.");
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
