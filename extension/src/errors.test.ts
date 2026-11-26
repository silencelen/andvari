// node --test (see version.test.ts). Each code a surface renders reads the line named for it in errors.ts (E1-3/E1-5/
// E1-7). Lines are named by their constants, never by their words: the owner's words go into those constants by a tool
// at any time, and a test that pinned a placeholder's words would turn red that day although nothing is wrong.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import * as E from "./errors.ts";
import {
  bioUnlockErrorCopy,
  cardFillErrorCopy,
  enrollBioErrorCopy,
  enrollErrorCopy,
  fillApproved,
  fillErrorCopy,
  lockNoticeCopy,
  pinUnlockErrorCopy,
  revealErrorCopy,
  saveErrorCopy,
  totpAddErrorCopy,
  unlockErrorCopy,
} from "./errors.ts";

test("unlock ladder: every code reads its own line", () => {
  const want: Record<string, string> = {
    bad_credentials: E.WRONG_CREDENTIALS,
    totp_required: E.TOTP_ENTER_CODE,
    totp_bad_code: E.TOTP_BAD_CODE,
    totp_rate_limited: E.SIGN_IN_TOO_MANY_TRIES,
    rate_limited: E.SIGN_IN_TOO_MANY_TRIES,
    totp_expired: E.TOTP_EXPIRED,
    totp_enroll_required: E.TOTP_ENROLL_REQUIRED,
    aborted: E.SIGN_IN_INTERRUPTED,
    upgrade_required: E.UPGRADE_REQUIRED,
    identity_mismatch: E.IDENTITY_MISMATCH,
    keys_damaged: E.ACCOUNT_KEYS_DAMAGED,
    kdf_policy: E.KDF_POLICY_BLOCKED,
    bad_wire_id: E.BAD_WIRE_ID,
    confirm_server: E.CONFIRM_SERVER_FIRST,
    server_fork: E.SERVER_FORK,
    card_invalid: E.CARD_INVALID,
    operator_account: E.OPERATOR_NOT_IN_EXTENSION,
    server_error: E.SIGN_IN_SERVER_ERROR,
    network: E.UNREACHABLE,
    unknown: E.SIGN_IN_FAILED,
  };
  for (const [code, line] of Object.entries(want)) assert.equal(unlockErrorCopy(code as never), line, code);
  assert.equal(unlockErrorCopy(undefined), E.SIGN_IN_FAILED);
  // link_required fills the approved sentence with the email that signed in.
  assert.equal(unlockErrorCopy("link_required", "bea@example.org"), fillApproved(E.LINK_REQUIRED_CANNOT_LINK, "bea@example.org"));
  // The hard faults are lines of their own: never a wrong password, never the "try again" terminal.
  for (const hard of ["keys_damaged", "kdf_policy", "identity_mismatch", "bad_wire_id"] as const) {
    assert.notEqual(unlockErrorCopy(hard), unlockErrorCopy("bad_credentials"), hard);
    assert.notEqual(unlockErrorCopy(hard), unlockErrorCopy(undefined), hard);
  }
});

test("save banner: every code reads its own line, never SW-internal strings", () => {
  const want: Record<string, string> = {
    shared_vault: E.SAVE_SHARED_VAULT,
    server_fork: E.SAVE_REFUSED_FORK,
    // Turned round (BZ): the save banner is about a capture a lock deletes, so its line never says "lock".
    server_ended: E.SAVE_REFUSED_SERVER_ENDED_CAUGHT,
    app_no_account: E.SAVE_APP_NO_ACCOUNT,
    app_unavailable: E.SAVE_APP_UNAVAILABLE,
    locked: E.SAVE_LOCKED,
    no_personal_vault: E.NO_PERSONAL_VAULT_CONFIRM,
    conflict: E.SAVE_CONFLICT_KEPT_BOTH,
    // Turned round (BZ): a refusal with no reason the extension knows is no longer said as a missing attachment.
    rejected: E.SAVE_REJECTED_OTHER,
    failed: E.SAVE_FAILED,
    // The Safari app's own refusal has a code of its own, never the server's `rejected`.
    app_refused: E.SAVE_APP_REFUSED,
  };
  for (const [code, line] of Object.entries(want)) assert.equal(saveErrorCopy(code as never), line, code);
  assert.equal(saveErrorCopy(undefined), E.SAVE_FAILED); // SW unreachable
  // H03/R37: `rejected` is the PERMANENT rung, never the retryable default.
  for (const line of [E.SAVE_REJECTED_ATTACHMENT, E.SAVE_REJECTED_FULL, E.SAVE_REJECTED_TOO_LARGE, E.SAVE_REJECTED_OTHER]) assert.notEqual(line, E.SAVE_FAILED);
  assert.notEqual(E.SAVE_APP_REFUSED, E.SAVE_REJECTED_OTHER);
});

test("no line advises an act that destroys what it is about: where a lock would delete what was caught and not saved, nothing says to lock", () => {
  // The save banner is always about such a capture. On the code before: "Lock, then sign in again to save."
  assert.equal(saveErrorCopy("server_ended"), E.SAVE_REFUSED_SERVER_ENDED_CAUGHT);
  assert.notEqual(saveErrorCopy("server_ended"), E.SAVE_REFUSED_SERVER_ENDED);
  // The notice beside the vault: with nothing caught, the approved line; with captures, or a count not known, another.
  assert.equal(E.serverEndedNotice(0), E.SERVER_ENDED_NOTICE);
  assert.notEqual(E.serverEndedNotice(2), E.SERVER_ENDED_NOTICE);
  assert.notEqual(E.serverEndedNotice(1), E.SERVER_ENDED_NOTICE);
  assert.equal(E.serverEndedNotice(null), E.SERVER_ENDED_NOTICE_UNSAVED_UNKNOWN);
  assert.equal(E.serverEndedNotice(2), E.SERVER_ENDED_NOTICE_UNSAVED_MANY.replace("{0}", "2"));
  assert.equal(E.serverEndedNotice(1), E.SERVER_ENDED_NOTICE_UNSAVED_ONE);
});

test("a refused save is said by the server's own reason, up to the sentence: a full account as a full account", () => {
  const want: Record<string, string> = {
    quota_exceeded: E.SAVE_REJECTED_FULL,
    unknown_attachment: E.SAVE_REJECTED_ATTACHMENT,
    attachment_mismatch: E.SAVE_REJECTED_ATTACHMENT,
    item_too_large: E.SAVE_REJECTED_TOO_LARGE,
    item_attachment_quota: E.SAVE_REJECTED_TOO_LARGE,
    too_many_attachments: E.SAVE_REJECTED_TOO_LARGE,
    bad_item_id: E.SAVE_REJECTED_OTHER,
  };
  for (const [reason, line] of Object.entries(want)) assert.equal(saveErrorCopy("rejected", reason), line, reason);
  // On the code before: a full account read "an attachment it references is no longer there".
  assert.notEqual(saveErrorCopy("rejected", "quota_exceeded"), E.SAVE_REJECTED_ATTACHMENT);
});

test("TOTP add: every code reads its own line", () => {
  const want: Record<string, string> = {
    locked: E.TOTP_ADD_LOCKED,
    no_personal_vault: E.NO_PERSONAL_VAULT_CONFIRM,
    invalid: E.TOTP_ADD_INVALID,
    exists: E.TOTP_ADD_EXISTS,
    not_allowed: E.TOTP_ADD_NOT_ALLOWED,
    conflict: E.TOTP_ADD_CONFLICT,
    read_only: E.TOTP_ADD_READ_ONLY,
    failed: E.TOTP_ADD_FAILED,
  };
  for (const [code, line] of Object.entries(want)) assert.equal(totpAddErrorCopy(code as never), line, code);
  assert.equal(totpAddErrorCopy(undefined), E.TOTP_ADD_FAILED); // SW mid-restart
  // `exists` is the ADD-ONLY contract: it is not the retryable failure.
  assert.notEqual(E.TOTP_ADD_EXISTS, E.TOTP_ADD_FAILED);
});

test("fill outcomes (Cut M, v2 #14): every code reads its own line", () => {
  const want: Record<string, string> = {
    locked: E.FILL_LOCKED,
    not_allowed: E.FILL_NOT_ALLOWED,
    no_form: E.FILL_NO_FORM,
    no_fields: E.FILL_NO_FIELDS,
    no_secret: E.FILL_NO_SECRET,
    unreachable: E.FILL_UNREACHABLE,
  };
  for (const [code, line] of Object.entries(want)) assert.equal(fillErrorCopy(code as never), line, code);
  assert.equal(fillErrorCopy(undefined), E.FILL_UNREACHABLE);
});

test("reveal-seam failures (#23): every code reads its own line", () => {
  assert.equal(revealErrorCopy("locked"), E.REVEAL_LOCKED);
  assert.equal(revealErrorCopy("not_allowed"), E.REVEAL_NOT_ALLOWED);
  assert.equal(revealErrorCopy(undefined), E.REVEAL_FAILED); // SW mid-restart
});

test("quick-unlock redeem: wrong_pin carries the remaining attempts, singular for one", () => {
  // breaker A1/A2: no partial-correctness signal, no wrong-PIN-vs-corrupt-blob distinction.
  assert.equal(pinUnlockErrorCopy("wrong_pin", 1), fillApproved(E.PIN_WRONG_ONE_TRY_LEFT, "1"));
  assert.equal(pinUnlockErrorCopy("wrong_pin", 3), fillApproved(E.PIN_WRONG_TRIES_LEFT, "3"));
  assert.equal(pinUnlockErrorCopy("wrong_pin"), fillApproved(E.PIN_WRONG_TRIES_LEFT, "0"));
  for (const k of ["PIN_WRONG_ONE_TRY_LEFT", "PIN_WRONG_TRIES_LEFT"] as const) assert.deepEqual(E[k].match(/\{\d+\}/g), ["{0}"], k);
});

test("quick-unlock redeem: wiped-blob / revoked / hard-fault outcomes route to the right line", () => {
  const want: Record<string, string> = {
    expired: E.QUICK_UNLOCK_EXPIRED,
    exhausted: E.PIN_EXHAUSTED,
    corrupt: E.QUICK_UNLOCK_SET_UP_AGAIN,
    stale_uvk: E.QUICK_UNLOCK_SET_UP_AGAIN,
    keys_damaged: E.ACCOUNT_KEYS_DAMAGED,
    revoked: E.QUICK_UNLOCK_SESSION_ENDED,
    identity_mismatch: E.IDENTITY_MISMATCH,
    kdf_policy: E.KDF_POLICY_BLOCKED,
    confirm_server: E.CONFIRM_SERVER_FIRST,
    server_error: E.QUICK_UNLOCK_SERVER_ERROR,
    network: E.UNREACHABLE,
    operator_account: E.OPERATOR_NOT_IN_EXTENSION,
    not_armed: E.PIN_UNLOCK_FAILED,
    aborted: E.PIN_UNLOCK_FAILED,
  };
  for (const [code, line] of Object.entries(want)) assert.equal(pinUnlockErrorCopy(code as never), line, code);
  assert.equal(pinUnlockErrorCopy(undefined), E.PIN_UNLOCK_FAILED);
  // Hard security faults keep the unlock ladder's own lines (never softened).
  assert.equal(pinUnlockErrorCopy("identity_mismatch"), unlockErrorCopy("identity_mismatch"));
  assert.equal(pinUnlockErrorCopy("kdf_policy"), unlockErrorCopy("kdf_policy"));
});

test("quick-unlock enroll: the entropy-floor nudges (breaker A2⊕B8) + the gate refusals", () => {
  assert.equal(enrollErrorCopy("locked"), E.ENROLL_LOCKED);
  assert.equal(enrollErrorCopy("must_change_password"), E.ENROLL_MUST_CHANGE_PASSWORD);
  assert.equal(enrollErrorCopy("need_full_unlock"), E.ENROLL_NEED_FULL_UNLOCK);
  assert.equal(enrollErrorCopy("weak_pin", "too_short"), E.PIN_TOO_SHORT);
  assert.equal(enrollErrorCopy("weak_pin", "digits_need_length"), E.PIN_DIGITS_NEED_LENGTH);
  assert.equal(enrollErrorCopy("weak_pin", "trivial"), E.PIN_TRIVIAL);
  assert.equal(enrollErrorCopy("weak_pin"), E.PIN_TRIVIAL);
  assert.equal(enrollErrorCopy("switched_off"), E.QUICK_UNLOCK_SWITCHED_OFF);
  assert.equal(enrollErrorCopy(undefined), E.ENROLL_FAILED);
});

test("biometric redeem (0.17.0): cancel is retryable; wiped/revoked/hard-fault route like the PIN lane", () => {
  const want: Record<string, string> = {
    bio_cancelled: E.BIO_UNLOCK_CANCELLED,
    expired: E.QUICK_UNLOCK_EXPIRED,
    corrupt: E.QUICK_UNLOCK_SET_UP_AGAIN,
    stale_uvk: E.QUICK_UNLOCK_SET_UP_AGAIN,
    keys_damaged: E.ACCOUNT_KEYS_DAMAGED,
    revoked: E.QUICK_UNLOCK_SESSION_ENDED,
    identity_mismatch: E.IDENTITY_MISMATCH,
    kdf_policy: E.KDF_POLICY_BLOCKED,
    confirm_server: E.CONFIRM_SERVER_FIRST,
    server_error: E.QUICK_UNLOCK_SERVER_ERROR,
    network: E.UNREACHABLE,
    operator_account: E.OPERATOR_NOT_IN_EXTENSION,
  };
  for (const [code, line] of Object.entries(want)) assert.equal(bioUnlockErrorCopy(code as never), line, code);
  assert.equal(bioUnlockErrorCopy(undefined), E.BIO_UNLOCK_FAILED);
});

test("biometric enroll (0.17.0): unsupported keeps the PIN path; cancel is retryable; gates route like the PIN", () => {
  assert.equal(enrollBioErrorCopy("locked"), E.ENROLL_LOCKED);
  assert.equal(enrollBioErrorCopy("must_change_password"), E.ENROLL_MUST_CHANGE_PASSWORD);
  assert.equal(enrollBioErrorCopy("need_full_unlock"), E.ENROLL_NEED_FULL_UNLOCK);
  assert.equal(enrollBioErrorCopy("bio_unsupported"), E.BIO_UNSUPPORTED);
  assert.equal(enrollBioErrorCopy("bio_cancelled"), E.BIO_SETUP_CANCELLED);
  assert.equal(enrollBioErrorCopy("switched_off"), E.QUICK_UNLOCK_SWITCHED_OFF);
  assert.equal(enrollBioErrorCopy(undefined), E.ENROLL_BIO_FAILED);
});

test("A16: an enroll refused because nothing could keep quick unlock says why, and is not the retryable failure", () => {
  assert.equal(enrollErrorCopy("unavailable"), E.QUICK_UNLOCK_UNAVAILABLE);
  assert.equal(enrollBioErrorCopy("unavailable"), E.QUICK_UNLOCK_UNAVAILABLE);
  assert.notEqual(E.QUICK_UNLOCK_UNAVAILABLE, E.ENROLL_FAILED);
});

test("lock notice: the web's rounding (AM3 — minutes at ≥ 60 s), singular for one, the number in the line's slot", () => {
  assert.equal(lockNoticeCopy(900), fillApproved(E.LOCKED_AFTER_MINUTES, "15"));
  // ≥ 60 s always renders whole minutes: Math.round(90/60) = 2 — never "90 seconds".
  assert.equal(lockNoticeCopy(90), fillApproved(E.LOCKED_AFTER_MINUTES, "2"));
  assert.equal(lockNoticeCopy(60), fillApproved(E.LOCKED_AFTER_ONE_MINUTE, "1"));
  assert.equal(lockNoticeCopy(45), fillApproved(E.LOCKED_AFTER_SECONDS, "45"));
  assert.equal(lockNoticeCopy(1), fillApproved(E.LOCKED_AFTER_ONE_SECOND, "1"));
  assert.equal(lockNoticeCopy(0), fillApproved(E.LOCKED_AFTER_ONE_SECOND, "1")); // clamp ≥ 1 s
});

test("a card fill that wrote nothing says why: each code reads its own line", () => {
  const want: Record<string, string> = {
    no_focus: E.CARD_NO_FOCUS,
    not_visible: E.CARD_NOT_VISIBLE,
    closed_form: E.CARD_CLOSED_FORM,
    page_form: E.CARD_PAGE_FORM,
    duplicate_fields: E.CARD_DUPLICATE_FIELDS,
    changed: E.CARD_FORM_CHANGED,
    mixed_forms: E.CARD_MIXED_FORMS,
    no_frame_origin: E.CARD_NO_FRAME_ORIGIN,
    no_form: E.CARD_NO_FORM,
    no_fields: E.CARD_NO_FIELDS,
  };
  for (const [code, line] of Object.entries(want)) assert.equal(cardFillErrorCopy(code as never), line, code);
  // The provider's host fills both of its slots when one is known; with none, every website.
  assert.equal(cardFillErrorCopy("provider_not_allowed", "https://js.stripe.com", true), fillApproved(E.CARD_PROVIDER_NOT_ALLOWED_SAFARI, "js.stripe.com"));
  assert.equal(cardFillErrorCopy("provider_not_allowed", "https://js.stripe.com"), fillApproved(E.CARD_PROVIDER_NOT_ALLOWED, "js.stripe.com"));
  assert.equal(cardFillErrorCopy("provider_not_allowed", undefined, true), E.CARD_PROVIDER_NOT_ALLOWED_ANY_SAFARI);
  assert.equal(cardFillErrorCopy("provider_not_allowed", undefined), E.CARD_PROVIDER_NOT_ALLOWED_ANY);
  assert.equal(cardFillErrorCopy("provider_not_allowed", "not a url", true), E.CARD_PROVIDER_NOT_ALLOWED_ANY_SAFARI);
  assert.equal(cardFillErrorCopy("fill_off", undefined, true), E.CARD_FILL_FROM_APP);
  assert.equal(cardFillErrorCopy("fill_off"), E.CARD_FILL_OFF_COPY);
  assert.equal(cardFillErrorCopy("locked"), fillErrorCopy("locked"), "the rest as for a login fill");
  assert.equal(cardFillErrorCopy(undefined), fillErrorCopy(undefined));
});

test("waiting grants: none is empty; one and more read their own lines with the number", () => {
  assert.equal(E.waitingGrantsLine(0), "");
  assert.equal(E.waitingGrantsLine(1), E.GRANTS_WAITING_ONE);
  assert.equal(E.waitingGrantsLine(4), fillApproved(E.GRANTS_WAITING, "4"));
});

test("waiting grants: the line for one vault and for more has the approved words (decided on 2026-11-23)", () => {
  assert.equal(E.GRANTS_WAITING_ONE, "1 shared vault is not open here. Review it in andvari if it asks you to, then lock and unlock this extension. It may still stay closed here.");
  assert.equal(E.GRANTS_WAITING, "{0} shared vaults are not open here. Review them in andvari if it asks you to, then lock and unlock this extension. Some may still stay closed here.");
  assert.equal(E.waitingGrantsLine(2), "2 shared vaults are not open here. Review them in andvari if it asks you to, then lock and unlock this extension. Some may still stay closed here.");
});
