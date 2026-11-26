/**
 * User-facing copy for the popup and content surfaces — the extension's port of the
 * fleet error canon (E1-3 / E1-5 / E1-7). Codes cross the message seam (messages.ts);
 * SENTENCES live only here and in copy.ts — background.ts never ships user-facing text, and surfaces
 * never render its raw `error` debug detail. Chrome-free on purpose: errors.test.ts
 * names every line by its constant under node --test.
 *
 * Every sentence is an exported, named constant with its own doc comment, marked as the web marks its copy:
 * `PLACEHOLDER` (the words await the owner's) or `Approved wording` (the owner's words, or the design's own). The
 * wording tool places the owner's words by the constant's name; copy-walk.test.ts fails on a sentence outside one.
 */

// Structural twins of the messages.ts seam types (the pinned E1 contract). Deliberately
// declared locally, not imported: this file stays dependency-free so the copy tests run
// standalone. The unions must stay literal-identical to messages.ts UnlockCode/SaveErrorCode.
type UnlockCode =
  | "bad_credentials"
  | "totp_required"
  | "totp_bad_code"
  | "totp_rate_limited"
  | "rate_limited"
  | "totp_expired"
  | "totp_enroll_required"
  | "aborted"
  | "upgrade_required"
  | "identity_mismatch"
  | "memory_unreadable" // what this extension remembers of the server's accounts could not be read: nothing taken, try again
  | "keys_damaged"
  | "kdf_policy"
  | "bad_wire_id" // A11 (c18): a login answer with malformed session ids (A10 grammar) — tampering class, terminal
  | "confirm_server" // no server is chosen, or its pin forked or is damaged (serverstate.ts) — nothing was sent anywhere
  | "link_required" // §8.7: a correct password, but the account only allows linked devices, which the extension cannot be
  | "server_fork" // §4.4: the card chain forked at sign-in — the extension stopped before anything password-derived left
  | "card_invalid" // the served card chain does not verify — nothing password-derived was sent
  | "operator_account" // §12.2 rule 7: the session is the operator account's — revoked at once, refused
  | "remade_account" // the address is known here as another account (accountmemory.ts): both possibilities are said
  | "server_error"
  | "network"
  | "unknown";
type SaveErrorCode = "locked" | "no_personal_vault" | "conflict" | "rejected" | "failed" | "app_no_account" | "app_unavailable" | "shared_vault" | "server_fork" | "server_ended" | "cannot_tell" | "app_refused";
type TotpAddCode = "locked" | "no_personal_vault" | "invalid" | "exists" | "not_allowed" | "conflict" | "failed" | "read_only";
type FillFailCode = "locked" | "not_allowed" | "no_form" | "no_fields" | "no_secret" | "unreachable";
type CardFillFailCode = "locked" | "not_allowed" | "no_form" | "no_fields" | "unreachable" | "no_focus" | "not_visible" | "closed_form" | "page_form" | "provider_not_allowed" | "duplicate_fields" | "changed" | "fill_off" | "mixed_forms" | "no_frame_origin";
type RevealFailCode = "locked" | "not_allowed";
// Structural twins of the messages.ts quick-unlock seam types (spec 01 §8.4). Kept literal-identical.
type PinUnlockCode =
  | "wrong_pin"
  | "expired"
  | "exhausted"
  | "not_armed"
  | "corrupt"
  | "stale_uvk"
  | "keys_damaged" // A13 (q38): the served account-key blob is not a readable envelope — terminal, blob kept
  | "revoked"
  | "not_confirmed" // the record held no refresh token (a refresh got no answer before the lock): nothing sent, not revoked
  | "network"
  | "server_error"
  | "identity_mismatch"
  | "memory_unreadable" // what this extension remembers of the server's accounts could not be read: nothing taken, try again
  | "kdf_policy"
  | "confirm_server" // no usable server (serverstate.ts) — nothing was sent anywhere
  | "server_fork" // §4.4: the card chain forked — nothing was spent
  | "card_invalid" // the served card chain does not verify — nothing was spent
  | "operator_account" // §12.2 rule 7: the pinned card names this account as the operator — signed out
  | "aborted";
type PinWeakReason = "too_short" | "digits_need_length" | "trivial";
type EnrollCode = "locked" | "must_change_password" | "need_full_unlock" | "weak_pin" | "unavailable" | "switched_off";
// Biometric quick-unlock (0.17.0) twins — literal-identical to messages.ts BioUnlockCode / EnrollBioCode.
type BioUnlockCode =
  | "bio_cancelled"
  | "not_armed"
  | "expired"
  | "corrupt"
  | "stale_uvk"
  | "keys_damaged" // A13 (q38): the served account-key blob is not a readable envelope — terminal, blob kept
  | "revoked"
  | "not_confirmed" // the record held no refresh token (a refresh got no answer before the lock): nothing sent, not revoked
  | "network"
  | "server_error"
  | "identity_mismatch"
  | "memory_unreadable" // what this extension remembers of the server's accounts could not be read: nothing taken, try again
  | "kdf_policy"
  | "confirm_server" // no usable server (serverstate.ts) — nothing was sent anywhere
  | "server_fork" // §4.4: the card chain forked — nothing was spent
  | "card_invalid" // the served card chain does not verify — nothing was spent
  | "operator_account" // §12.2 rule 7: the pinned card names this account as the operator — signed out
  | "aborted";
type EnrollBioCode = "locked" | "must_change_password" | "need_full_unlock" | "bio_unsupported" | "bio_cancelled" | "unavailable" | "switched_off";

/** Approved wording (the released extension's own words): A16, quick unlock cannot be kept here (no session sealing key: Firefox's "Never remember history" gives
 *  the extension no IndexedDB), so enrolling is refused rather than pretend. Shared by the PIN and the biometric enroll. */
export const QUICK_UNLOCK_UNAVAILABLE =
  "Quick unlock isn't available in this browser mode — andvari has no private storage here to keep it in (Firefox does this when it never remembers history).";

/** Approved wording (decided on 2026-11-17): the refusal while no usable server is chosen (serverstate.ts). The popup shows the server choice (or the
 *  stop notice) instead of any sign-in form, so this is the fallback line only (a stale popup). */
export const CONFIRM_SERVER_FIRST = "Choose your server first. andvari signs in nowhere until you do.";

/** The owner's approved words with `values` in place of `{0}`, `{1}`, …: one pass, so a value reading "{0}" is copied. */
export function fillApproved(template: string, ...values: string[]): string {
  return template.replace(/\{(\d+)\}/g, (slot, n: string) => (Number(n) < values.length ? values[Number(n)]! : slot));
}

/** A message the popup or the options page shows with a title above its body (the message area renders the title,
 *  then one paragraph per line of the body). `title` is null where a message has none. */
export interface TitledCopy {
  title: string | null;
  body: string;
}

/** §8.7: a password login answered `link_required`, after the password and any code verified. Approved wording
 *  (copy page 2026-11-15, entry 15): the title. */
export const LINK_REQUIRED_CANNOT_LINK_TITLE = "This account only allows linked devices";
/** Approved wording (copy page 2026-11-15, entry 15): the body, with {0} the account's email. */
export const LINK_REQUIRED_CANNOT_LINK =
  "{0} has “New devices must be linked” turned on, and andvari in a browser can't be linked. Your master password was right. To sign in here, open andvari on one of your devices → Settings → Your devices, and turn that setting off. You can turn it on again once this browser has signed in.";
export function linkRequiredCopy(email: string): string {
  return fillApproved(LINK_REQUIRED_CANNOT_LINK, email);
}

/** InstanceCardState.Damaged in the extension: the origin's pin record does not decode. Approved wording (entry 12):
 *  the title. */
export const CARD_RECORD_DAMAGED_TITLE = "andvari can't read its record of this server";
/** Approved wording (entry 12): two paragraphs with {0} the server's address. */
export const CARD_RECORD_DAMAGED =
  "The record this device keeps of the identity of {0} is damaged, or comes from a newer version of andvari. Without it andvari can't tell whether this is still the same server, so it has stopped using it on this device.\nIf you went back to an older version of andvari, update it. Otherwise choose Forget this server and connect again. That removes this server's data from this device, including changes that hadn't synced. Your account on the server is not affected.";
export function cardRecordDamagedCopy(origin: string): string {
  return fillApproved(CARD_RECORD_DAMAGED, origin);
}

/** A move tapped while this browser already holds a pin for the new origin (`pin_conflict`). Approved wording
 *  (entry 13): the title. */
export const CARD_MOVE_NOT_FOLLOWED_TITLE = "andvari didn't follow this move";
/** Approved wording (entry 13): the body, with {0} the address the server says it moved to. */
export const CARD_MOVE_NOT_FOLLOWED =
  "This device already knows {0} as a server, and a move never replaces a server this device already knows. Nothing changed. If you set it up on this device yourself, as this server's new address, sign out and sign in there. If you didn't, ask this server's operator what happened.";
export function moveNotFollowedCopy(to: string): string {
  return fillApproved(CARD_MOVE_NOT_FOLLOWED, to);
}

/** A first pin refused because the newest verified card names another address than the one dialed (`origin_mismatch`).
 *  Approved wording (entry 8): the title. */
export const CARD_OTHER_ADDRESS_TITLE = "This address doesn't match the server's identity card";
/** Approved wording (entry 8): {0} the address dialed, whole; {1} the address the card names. */
export const CARD_OTHER_ADDRESS =
  "The server at {0} showed an identity card made for a different address, {1}. andvari didn't connect, and nothing of yours was sent. The address may be wrong, the server may have moved, or someone may be imitating it. Check the address with the person who runs the server.";

/** Approved wording (entry 8, core CARD_MOVED_UPDATE): the baked public instance's chain says it moved; store builds
 *  never follow it (§4.4). */
export const SERVER_MOVED_UPDATE = "This server says it moved. Update andvari.";

/** The `kind` change gate's title. Approved wording (entry 10); its body is §12.3's sentence, its buttons Continue and
 *  Not now. */
export const GATE_TITLE_KIND_CHANGE = "This server says it changed";

/**
 * A refused `chooseServer` → what the popup or options page shows. `origin_mismatch` takes entry 8's words, with both
 * addresses from the worker's answer: the one it dialed, and the one the verified card names (`mismatch`, set only from
 * a chain that verified). At the baked public instance it is the store builds' "Update andvari" sentence instead (the
 * entry's own rule). Every other code is [chooseServerCopy], with no title.
 */
export function chooseServerMessage(
  r: { code?: string; mismatch?: { dialed: string; named: string }; redirectTo?: string } | null | undefined,
  publicOrigin: string,
): TitledCopy {
  // A redirect is never followed; where it points is said when the worker could read it.
  if (r?.code === "redirected" && typeof r.redirectTo === "string" && r.redirectTo !== "") return { title: null, body: fillApproved(SERVER_REDIRECTS_TO, r.redirectTo) };
  const m = r?.code === "origin_mismatch" ? r.mismatch : undefined;
  if (m !== undefined && typeof m.dialed === "string" && typeof m.named === "string" && m.dialed !== "" && m.named !== "") {
    if (m.dialed === publicOrigin) return { title: null, body: SERVER_MOVED_UPDATE };
    return { title: CARD_OTHER_ADDRESS_TITLE, body: fillApproved(CARD_OTHER_ADDRESS, m.dialed, m.named) };
  }
  return { title: null, body: chooseServerCopy(r?.code) };
}

/** A sign-in failure with the title its approved words carry: `link_required` (entry 15); every other code has none. */
export function unlockErrorMessage(code: UnlockCode | undefined, email?: string): TitledCopy {
  return { title: code === "link_required" ? LINK_REQUIRED_CANNOT_LINK_TITLE : null, body: unlockErrorCopy(code, email) };
}

/** Approved wording (the design's own words, §4.4): the fork. */
export const SERVER_FORK =
  "This server's identity changed in a way andvari can't verify. Don't continue. If you trust the operator, ask them what happened.";

/** PLACEHOLDER: `remade_account` (decided on 2026-11-17), the sign-in refused because this extension knows the address
 *  {0} at this server as another account. Must say: andvari stopped and nothing was changed; the two possibilities in
 *  plain words (the account under this address was deleted and made again, and the extension still remembers the earlier
 *  one; or the server is not giving this extension the account it knows, and then something is wrong with the server
 *  and nothing should be forgotten); how to tell (the person knows whether they, or the operator with their knowledge,
 *  deleted the account and made it again); that if it was, "Forget the earlier account on this device" (offered below
 *  the line) lets this extension take the new account; and (the owner's decision of 2026-11-17) if the account was NOT
 *  deleted and made again, forgetting means trusting whatever account the server serves under this address from now on. */
export const REMADE_ACCOUNT =
  "⟦This extension knows {0} on this server as another account, so andvari stopped and nothing was changed. Either the account was deleted and made again, and the extension still remembers the earlier one; or the server isn't giving this extension the account it knows, and then something is wrong with the server and nothing should be forgotten. You know which: you, or the operator with your knowledge, deleted the account and made it again. If it was, forget the earlier account on this device. If it wasn't, forgetting means trusting whatever account the server gives under this address from now on.⟧";

/** PLACEHOLDER: the offer's button below REMADE_ACCOUNT (decided on 2026-11-17). Must say: Forget the earlier account on
 *  this device. */
export const FORGET_EARLIER_OFFER = "⟦Forget the earlier account on this device⟧";
/** PLACEHOLDER: the second confirmation of FORGET_EARLIER_OFFER; {0} the address. Must say: this extension forgets the
 *  earlier account under {0} on this server: which account the address is, and what it keeps of that account here (where
 *  its items live, its cached keys, what it remembers of its account state, this browser's device record for the address,
 *  and quick unlock where it is set up for that account); it keeps no changes of that account waiting to be sent (each
 *  save is sent at once); a login the person asked to save while the extension was locked is saved in the account that
 *  signs in next; it cannot be undone; the server's identity stays checked as before; and if the account was NOT deleted
 *  and made again, forgetting means trusting whatever account the server serves under this address from now on. */
export const FORGET_EARLIER_CONFIRM =
  "⟦This extension will forget the earlier account under {0} on this server: which account the address is, where its items live, its cached keys, what it remembers of its account state, this browser's device record for the address, and quick unlock if it's set up for that account. It holds no changes of that account waiting to be sent. A login you asked to save while the extension was locked is saved in the account that signs in next. This can't be undone. The server is still checked as before. If the account wasn't deleted and made again, forgetting means trusting whatever account the server gives under this address from now on.⟧";
/** PLACEHOLDER: the button that carries out FORGET_EARLIER_CONFIRM. Must say: forget it (the earlier account). */
export const FORGET_EARLIER_CONFIRM_BUTTON = "⟦Forget it⟧";
/** PLACEHOLDER: said where a click on FORGET_EARLIER_CONFIRM_BUTTON came within a second of the confirmation appearing
 *  (or from a held key), so it was not taken; shown above the confirmation, which stays. Must say: read the confirmation
 *  first, then choose the button again to forget the earlier account. */
export const FORGET_EARLIER_READ_FIRST = "⟦Read the confirmation below first, then choose the button again to forget the earlier account.⟧";
/** PLACEHOLDER: the forgetting could not read or remove what it had to (`failed`): nothing is said forgotten. Must say: the
 *  earlier account could not be forgotten, and why it may be (this browser's storage); its quick unlock may already be
 *  gone (it is removed first); try again. */
export const FORGET_EARLIER_FAILED = "⟦andvari couldn't forget the earlier account: this browser's storage didn't answer. Its quick unlock may already be gone. Try again.⟧";
/** PLACEHOLDER: the forgetting refused because a session of the earlier account is open here (`open`). Must say: that
 *  account is open in this extension; lock or sign out of it first. */
export const FORGET_EARLIER_OPEN = "⟦That account is open in this extension. Lock it or sign out of it first.⟧";
/** PLACEHOLDER: the forgetting refused because no refusal of another account under that address stands any more
 *  (`not_offered`; the offer lives in the extension's memory only, so a browser that stopped the extension in between
 *  also lands here). Must say: there is nothing to forget for that address now; signing in again brings the refusal and
 *  the offer to forget the earlier account back. */
export const FORGET_EARLIER_NOT_OFFERED = "⟦There's nothing to forget for that address now. Sign in again: if the address still belongs to another account here, the refusal and the offer to forget the earlier account come back.⟧";
/** PLACEHOLDER: said once the earlier account is forgotten. Must say: this extension forgot the earlier account under
 *  this address; sign in to take the account the server gives now. */
export const FORGET_EARLIER_DONE = "⟦The earlier account is forgotten on this device. Sign in to use the account under this address now.⟧";
/** PLACEHOLDER: said once, at the first sign-in taken under the address after the forgetting (`account_remembered`).
 *  Must say: this extension now remembers this account under this address at this server. */
export const ACCOUNT_REMEMBERED = "⟦This extension now remembers this account for this address on this server.⟧";

/** PLACEHOLDER: `memory_unreadable`, a sign-in or a quick unlock refused because this extension could not read what it
 *  remembers of this server's accounts (which account an address is, each account's identity key). Must say: the
 *  extension could not read what it remembers of this server; nothing was taken (the vault was not opened, nothing was
 *  changed); try again; and where it keeps happening, restart the browser. Must not advise any step that forgets what the
 *  extension remembers (not "Forget this server", not removing the extension or its data). */
export const MEMORY_UNREADABLE =
  "andvari couldn't read what this extension remembers of this server, so it took nothing and changed nothing. Try again. If this keeps happening, restart your browser.";

/** PLACEHOLDER: §4.4 "A fork stops traffic, not reading": what "Forget this server" does to what this browser holds
 *  (2026-11-15). Shown beside the fork warning wherever the button is. */
export const FORGET_DELETES_COPY = "What andvari already has here stays readable until you forget this server. Forget this server deletes this browser's copy.";

/** PLACEHOLDER: §12.2 rule 7, the extension never signs in as the operator account (2026-11-15; the web's
 *  OPERATOR_NOT_ON_WEB twin). */
export const OPERATOR_NOT_IN_EXTENSION = "The operator account can't be used in the browser extension. Use the andvari desktop app or andvari-cli.";

/** Approved wording (decided on 2026-11-17): the locked popup's "Forgot your master password?": the extension
 *  recovers nothing, so it says where recovery happens. */
export const RECOVER_IN_APP = "The browser extension can't recover an account. Open the andvari app, choose Sign in, then Forgot your master password?";

/** Approved wording (decided on 2026-11-17): the server ended this session (§4.4), the notice beside the vault. */
export const SERVER_ENDED_NOTICE = "The server signed this browser out. You're reading the copy in this browser: nothing is sent, and nothing can be changed. To sync again, lock, then sign in.";
/**
 * PLACEHOLDER: SERVER_ENDED_NOTICE where this browser holds logins or cards it caught on pages and has not saved: a lock
 * would delete them, so the line never tells the person to lock. ONE: one such capture; MANY: {0} of them (a number).
 * Must say: the server signed this browser out, nothing is sent or changed; signing in again starts with a lock, and a
 * lock deletes those captures; keep what they need from them first. Must not advise locking.
 */
export const SERVER_ENDED_NOTICE_UNSAVED_ONE = "The server signed this browser out. You're reading the copy in this browser: nothing is sent, and nothing can be changed. 1 login or card caught on a page and not saved yet would be deleted by a lock, and signing in again starts with one: keep what you need from it first.";
/** PLACEHOLDER: as SERVER_ENDED_NOTICE_UNSAVED_ONE, for {0} (a number above one) such captures. */
export const SERVER_ENDED_NOTICE_UNSAVED_MANY = "The server signed this browser out. You're reading the copy in this browser: nothing is sent, and nothing can be changed. {0} logins or cards caught on pages and not saved yet would be deleted by a lock, and signing in again starts with one: keep what you need from them first.";
/** PLACEHOLDER: the same where the number of such captures cannot be told. */
export const SERVER_ENDED_NOTICE_UNSAVED_UNKNOWN = "The server signed this browser out. You're reading the copy in this browser: nothing is sent, and nothing can be changed. Logins or cards caught on pages and not saved yet would be deleted by a lock, and signing in again starts with one: keep what you need from them first.";
/** Approved wording (decided on 2026-11-17): a save refused because the server ended this session (§4.4). */
export const SAVE_REFUSED_SERVER_ENDED = "Not saved: the server signed this browser out. Lock, then sign in again to save.";
/**
 * PLACEHOLDER: the save banner's line for a save refused because the server ended this session: the banner is about a
 * login or card caught and not saved, which a lock deletes, so it never tells the person to lock (it replaces
 * SAVE_REFUSED_SERVER_ENDED there). Must say: not saved, the server signed this browser out; a lock deletes what was
 * caught, and signing in again starts with one; keep the password somewhere first.
 */
export const SAVE_REFUSED_SERVER_ENDED_CAUGHT = "Not saved: the server signed this browser out. A lock deletes what andvari caught here, and signing in again starts with one: keep this password somewhere first.";

/**
 * The notice beside the vault while the server's end of this session stands. [unsaved]: the logins or cards caught and
 * not saved (null: cannot tell). Where there are any, or it cannot be told, the line does not advise the lock that
 * would delete them.
 */
/**
 * PLACEHOLDER: after a person's own sign-out of an account whose session this extension could not confirm with its
 * server (a refresh that got no answer; its token was kept for the next sign-in's name and goes with the sign-out). Must
 * say: the end of that session could not be confirmed with the server; to end it, sign in again in the extension (its
 * sign-in ends its earlier sessions), or remove the extension from the list of devices on another device.
 */
export const SIGN_OUT_NOT_CONFIRMED = "⟦Signed out, but andvari couldn't confirm with the server that the extension's session ended. To end it, sign in again in the extension, or remove the extension from your devices on another device.⟧";
/**
 * PLACEHOLDER: in place of SERVER_ENDED_NOTICE where no server ended the session: a refresh whose answer never came had
 * no try left, so the extension sent nothing again and ended the session itself. Never said as signed out by the server,
 * nor as revoked. Must say: andvari could not confirm this browser's session with its server in time; it sent nothing
 * again, so no other session was ended; you're reading the copy in this browser: nothing is sent, and nothing can be
 * changed; sign in again on this browser, which also ends the session that could not be confirmed.
 */
export const SESSION_NOT_CONFIRMED_NOTICE = "⟦andvari could not confirm this browser's session with its server in time and sent nothing again, so no other session was ended. You're reading the copy in this browser: nothing is sent, and nothing can be changed. Sign in again on this browser: that also ends the session that could not be confirmed.⟧";
/**
 * PLACEHOLDER: SESSION_NOT_CONFIRMED_NOTICE where this browser holds logins or cards it caught on pages and has not
 * saved: signing in again starts with a lock, and a lock deletes them, so the line advises no step that deletes them (as
 * SERVER_ENDED_NOTICE_UNSAVED_ONE does for the server's end). ONE: one such capture; MANY: {0} of them (a number);
 * UNKNOWN: the number cannot be told. Must say: andvari could not confirm this browser's session with its server in time
 * and sent nothing again, so no other session was ended; you're reading the copy in this browser: nothing is sent, and
 * nothing can be changed; how many logins or cards caught on pages are not saved yet, that a lock would delete them and
 * signing in again starts with one: keep what you need from them first. Must not advise locking or signing in now.
 */
export const SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_ONE = "⟦andvari could not confirm this browser's session with its server in time and sent nothing again, so no other session was ended. You're reading the copy in this browser: nothing is sent, and nothing can be changed. 1 login or card caught on a page and not saved yet would be deleted by a lock, and signing in again starts with one: keep what you need from it first.⟧";
/** PLACEHOLDER: as SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_ONE, for {0} (a number above one) such captures. */
export const SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_MANY = "⟦andvari could not confirm this browser's session with its server in time and sent nothing again, so no other session was ended. You're reading the copy in this browser: nothing is sent, and nothing can be changed. {0} logins or cards caught on pages and not saved yet would be deleted by a lock, and signing in again starts with one: keep what you need from them first.⟧";
/** PLACEHOLDER: as SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_ONE, where the number of such captures cannot be told. */
export const SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_UNKNOWN = "⟦andvari could not confirm this browser's session with its server in time and sent nothing again, so no other session was ended. You're reading the copy in this browser: nothing is sent, and nothing can be changed. Logins or cards caught on pages and not saved yet would be deleted by a lock, and signing in again starts with one: keep what you need from them first.⟧";
/**
 * PLACEHOLDER: a quick unlock (PIN or biometrics) that found no refresh token in its record because a refresh of the
 * session got no answer before the lock (`not_confirmed`). Nothing was sent and nothing was deleted; quick unlock is off
 * on this browser until the next sign-in. Never said as the session's end by the server. Must say: andvari could not
 * confirm this browser's session with its server in time and sent nothing; sign in with the master password on this
 * browser, which also ends the session that could not be confirmed.
 */
export const QUICK_UNLOCK_NOT_CONFIRMED = "⟦andvari couldn't confirm this browser's session with its server in time, so it sent nothing. Sign in with your master password: that also ends the session that couldn't be confirmed.⟧";

/** The notice beside the vault for a session this browser could not confirm: as [serverEndedNotice], it says how many
 *  captures are not saved yet and advises no step that deletes them. */
export function sessionNotConfirmedNotice(unsaved: number | null): string {
  if (unsaved === 0) return SESSION_NOT_CONFIRMED_NOTICE;
  if (unsaved === null || !Number.isSafeInteger(unsaved) || unsaved < 0) return SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_UNKNOWN;
  return unsaved === 1 ? SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_ONE : SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_MANY.replace("{0}", String(unsaved));
}

export function serverEndedNotice(unsaved: number | null): string {
  if (unsaved === 0) return SERVER_ENDED_NOTICE;
  if (unsaved === null || !Number.isSafeInteger(unsaved) || unsaved < 0) return SERVER_ENDED_NOTICE_UNSAVED_UNKNOWN;
  return unsaved === 1 ? SERVER_ENDED_NOTICE_UNSAVED_ONE : SERVER_ENDED_NOTICE_UNSAVED_MANY.replace("{0}", String(unsaved));
}
/** Approved wording (decided on 2026-11-17): §4.4, a save refused while the server is stopped by a fork (2026-11-15). */
export const SAVE_REFUSED_FORK ="Not saved: this server's identity changed in a way andvari can't verify, so nothing is sent to it.";

/** Approved wording (decided on 2026-11-17): §4.4, the baked public instance's chain says it moved or changed kind; store builds never follow either. */
export const SERVER_CHANGED_UPDATE = "This server says it changed. Update andvari.";

/** Approved wording (decided on 2026-11-17): §4.4, the served chain ends below the pinned card. */
export const CARD_WITHHELD = "This server is showing an older version of its identity card.";
/** A session's refresh found a newer card that does not verify (the pin stays where it was). Approved wording
 *  (copy page 2026-11-15, entry 11). */
export const CARD_REFUSED_KEPT =
  "This server showed an update to its identity card that andvari can't verify. andvari ignored it and kept the card it had already checked. If this message stays, ask the operator what happened.";

/** Approved wording (decided on 2026-11-17): choosing a server refused, `invalid`: the address is not an https address with a domain name. */
export const SERVER_ADDRESS_INVALID = "andvari needs an https address with a domain name for this server.";
/** Approved wording (decided on 2026-11-17): choosing a server refused, `no_permission`: the browser declined access to the server's address. */
export const SERVER_ACCESS_NOT_ALLOWED = "The browser didn't allow andvari to reach that server. Nothing changed.";
/** Approved wording (decided on 2026-11-17): choosing a server refused, `card_invalid`: the server's card chain does not verify. */
export const SERVER_CARD_NOT_CHECKED = "andvari couldn't verify this server's identity card, so it didn't connect. Nothing of yours was sent.";
/** Approved wording (decided on 2026-11-17): choosing a server refused, `chain_too_long`: a first pin over
 *  MAX_FIRST_PIN_CARDS. */
export const SERVER_CHAIN_TOO_LONG = "This server's identity card has a longer history than the browser extension can check, so andvari won't connect to it here. Use this server in the andvari app instead.";
/** Approved wording (decided on 2026-11-17): choosing a server refused, `withheld`: the server shows no identity card yet. */
export const SERVER_NO_CARD_YET = "This server isn't set up yet, so andvari can't connect to it. Ask the person who runs it.";
/** Approved wording (decided on 2026-11-17): choosing a server refused, `origin_mismatch` without the two addresses. */
export const SERVER_CARD_OTHER_ADDRESS = "This server's identity card names a different address than the one you entered, so andvari didn't connect. Check the address with the person who runs the server.";
/** Approved wording (decided on 2026-11-17): choosing a server refused, `card0_mismatch` or `instance_mismatch`: not the public server this version
 *  knows. */
export const SERVER_NOT_THE_KNOWN_ONE = "That server isn't the andvari server this version knows, so andvari won't use it. Update andvari, or check the address.";
/** Approved wording (decided on 2026-11-17): choosing the public server refused, `no_public_instance`: this build knows none yet. */
export const NO_PUBLIC_INSTANCE = "This version of andvari doesn't know the public server yet. Update andvari, or use your own server.";
/** PLACEHOLDER: following a move refused, `pin_conflict`: this browser already holds a record for the new address. */
export const SERVER_MOVE_PIN_CONFLICT = "andvari already has a record for the new address, so it can't follow the move. Forget that server first.";
/** Approved wording (decided on 2026-11-17): choosing a server refused, `pin_damaged`: this browser's record of it does not decode. */
export const SERVER_PIN_DAMAGED = "andvari can't read its record of this server, so it won't use it. Forget this server and choose it again.";
/** Approved wording (decided on 2026-11-17): choosing a server refused, `stale`: the check the person answered is out of date. */
export const SERVER_CHECK_STALE = "That check is out of date. Continue again.";
/** Approved wording (decided on 2026-11-17): choosing a server refused, `storage`: the browser gives andvari no storage of its own in this mode. */
export const SERVER_CHOICE_NO_STORAGE = "This browser gives andvari no storage of its own in this mode, so it can't keep a server choice. Nothing changed.";
/** Approved wording (decided on 2026-11-17): choosing a server failed for any other reason. */
export const SERVER_CHOICE_FAILED = "andvari couldn't choose that server. Nothing changed. Try again.";

/**
 * PLACEHOLDER (review of 2026-11-17): choosing a server refused, `redirected`, where the browser does not let andvari
 * read where the redirect points. Must say: the address sends visitors somewhere else; andvari follows no redirect, so it
 * didn't connect and nothing was sent; check the server's exact address with the person who runs it.
 */
export const SERVER_REDIRECTS =
  "That address sends visitors to another address, and andvari doesn't follow that, so it didn't connect. Nothing of yours was sent. Check the server's exact address with the person who runs it.";
/** PLACEHOLDER: the same, naming where it points. {0}: that address, as plain text. Must also say: type it only if it is
 *  the server's own address. */
export const SERVER_REDIRECTS_TO =
  "That address sends visitors to {0}, and andvari doesn't follow that, so it didn't connect. Nothing of yours was sent. If {0} is your server's own address, type that one instead.";

/** Why choosing a server failed (messages.ts ChooseServerCode, structurally) → the sentence the popup and options show. */
export function chooseServerCopy(code: string | undefined): string {
  switch (code) {
    case "redirected":
      return SERVER_REDIRECTS;
    case "invalid":
      return SERVER_ADDRESS_INVALID;
    case "no_permission":
      return SERVER_ACCESS_NOT_ALLOWED;
    case "unavailable":
      return UNREACHABLE;
    case "card_invalid":
      return SERVER_CARD_NOT_CHECKED;
    case "chain_too_long":
      return SERVER_CHAIN_TOO_LONG;
    case "withheld":
      return SERVER_NO_CARD_YET;
    case "origin_mismatch":
      return SERVER_CARD_OTHER_ADDRESS;
    case "card0_mismatch":
    case "instance_mismatch":
      return SERVER_NOT_THE_KNOWN_ONE;
    case "fork":
      return SERVER_FORK;
    case "changed":
      return SERVER_CHANGED_UPDATE;
    case "no_public_instance":
      return NO_PUBLIC_INSTANCE;
    case "pin_conflict":
      return SERVER_MOVE_PIN_CONFLICT;
    case "pin_damaged":
      return SERVER_PIN_DAMAGED;
    case "stale":
      return SERVER_CHECK_STALE;
    case "storage":
      return SERVER_CHOICE_NO_STORAGE;
    default:
      return SERVER_CHOICE_FAILED;
  }
}

/** Approved wording (decided on 2026-11-17): the served card chain does not verify (not a fork: nothing validly signed disagrees with the pin). */
export const CARD_INVALID = "andvari couldn't verify this server's identity card, so it didn't sign in. Try again later, or ask the operator.";

/** Approved wording (the released extension's own words): the web's UNREACHABLE, word for word — the one "can't reach the server" sentence, duplicated as a const
 *  because no build path from extension/ to web/src exists. */
export const UNREACHABLE = "Can't reach the andvari server — check your connection (and your VPN, if your server is private), then try again.";

/** Approved wording (the released extension's own words): the sign-in form, `bad_credentials` (a 401 to the full sign-in). */
export const WRONG_CREDENTIALS = "Wrong email or master password.";
/** Approved wording (the released extension's own words): the one-time-code field's instruction, `totp_required` (shown as info, not as an error). */
export const TOTP_ENTER_CODE = "Enter the 6-digit code from your authenticator app.";
/** Approved wording (the released extension's own words): the one-time-code field, `totp_bad_code`. */
export const TOTP_BAD_CODE = "That code didn’t work — codes change every 30 seconds, so try the current one.";
/**
 * Approved wording (decided on 2026-11-17): the sign-in's back-off, `totp_rate_limited` and `rate_limited`, in the wording
 * page's PQ1 first line, put in by hand: FX3's earlier line said "with this email address", which is untrue when the
 * server counted the tries of one network address (it answers both the same way). The server answers a sign-in, whose
 * caller has proven nothing, with a fixed 60 seconds, so the line says "at least a minute", never "a minute".
 */
export const SIGN_IN_TOO_MANY_TRIES = "Too many tries to sign in. Wait at least a minute, then try again.";
/** Approved wording (the released extension's own words): the one-time-code step took too long, `totp_expired`. */
export const TOTP_EXPIRED = "That took too long — sign in again.";
/** Approved wording (decided on 2026-11-17): `totp_enroll_required`, a server that requires two-step sign-in for an account without it (the wording
 *  page's NW1 names it). */
export const TOTP_ENROLL_REQUIRED = "This server requires two-step sign-in. Set it up in andvari on the web, then sign in here.";
/** Approved wording (the released extension's own words): `aborted`, a switch or lock landed mid-sign-in; the popup re-renders, so this is a fallback only. */
export const SIGN_IN_INTERRUPTED = "Sign-in was interrupted — try again.";
/** Approved wording (the released extension's own words): `upgrade_required`; the update banner exists only when a newer build is published, so it does not
 *  promise the link (AM5). */
export const UPGRADE_REQUIRED = "Your server requires a newer extension — get the update from the web vault or the link above.";
/** Approved wording (the released extension's own words): `identity_mismatch`, the web IdentityMismatchError's sentence — a hard security fault that never softens
 *  into a wrong password. */
export const IDENTITY_MISMATCH = "Server identity key mismatch — possible tampering. Do not proceed; contact your admin.";
/** Approved wording (the released extension's own words): `keys_damaged` (H67), the stored wrappedUvk isn't a readable envelope: terminal, never a wrong password and
 *  never "try again"; the same words as core HouseholdCopy.ACCOUNT_KEYS_DAMAGED and the web's VAULT_KEYS_DAMAGED. */
export const ACCOUNT_KEYS_DAMAGED = "This account's stored keys are damaged or from a newer version, so sign-in cannot continue. Contact your admin or restore from a backup.";
/** Approved wording (the released extension's own words): `kdf_policy` (H1, spec 05 T1), the server sent weakened master-password settings: a hard block. */
export const KDF_POLICY_BLOCKED = "This server sent weakened security settings for your master password. Sign-in was blocked to protect you — contact your admin.";
/** Approved wording (the released extension's own words): `bad_wire_id` (A11, c18), the login answer carried a malformed user or device id: tampering class. */
export const BAD_WIRE_ID = "The server sent a malformed account record, so sign-in was stopped. Tell your admin — the server may be misbehaving.";
/** Approved wording (the released extension's own words): the sign-in, `server_error`. */
export const SIGN_IN_SERVER_ERROR = "The server had a problem answering — your details may be fine. Try again in a moment.";
/** Approved wording (the released extension's own words): the sign-in, `unknown` or no code at all (the web's last fallback). */
export const SIGN_IN_FAILED = "Sign-in failed. Please try again.";

/**
 * Unlock failures → web's FreshStart ladder (Welcome.tsx), verbatim where web has the
 * sentence. The extension flow is a full sign-in, not the unlock gate, so the 401 copy is
 * the sign-in form ([WRONG_CREDENTIALS]). Extension-specific rungs:
 *  - totp_required (0.16.3): the popup flips to a one-time-code field — this copy is the INSTRUCTION
 *    shown there (rendered as info/polite, not an error). totp_bad_code/rate_limited/expired are the
 *    retry rungs; totp_enroll_required routes a restricted (instance-requires-TOTP) session to the web app.
 *  - upgrade_required: the update banner exists only when a strictly-newer build is
 *    actually PUBLISHED, so the copy must not hard-promise the link (AM5).
 *  - identity_mismatch: web IdentityMismatchError's exact sentence — a hard security
 *    fault that must NEVER soften into wrong-password.
 *  - keys_damaged (H67): the stored wrappedUvk isn't a readable envelope — terminal copy, never
 *    wrong-password and never "try again"; byte-identical to core + web.
 */
export function unlockErrorCopy(code: UnlockCode | undefined, email?: string): string {
  switch (code) {
    case "bad_credentials":
      return WRONG_CREDENTIALS;
    case "totp_required":
      return TOTP_ENTER_CODE;
    case "totp_bad_code":
      return TOTP_BAD_CODE;
    case "totp_rate_limited":
    case "rate_limited":
      return SIGN_IN_TOO_MANY_TRIES;
    case "totp_expired":
      return TOTP_EXPIRED;
    case "totp_enroll_required":
      return TOTP_ENROLL_REQUIRED;
    case "aborted":
      // A switch/lock landed mid-sign-in; the popup silently re-renders, so this is a fallback only.
      return SIGN_IN_INTERRUPTED;
    case "upgrade_required":
      return UPGRADE_REQUIRED;
    case "identity_mismatch":
      return IDENTITY_MISMATCH;
    case "keys_damaged":
      // H67: the account's server-stored key blob (wrappedUvk) isn't a readable envelope — bad
      // base64url, too short, or an envelope version/alg this build doesn't know. Refused from its
      // PUBLIC header, before the password's wrap key was applied, so it is NOT a credentials
      // verdict and no retry can fix it: the same row fails identically forever.
      return ACCOUNT_KEYS_DAMAGED;
    case "kdf_policy":
      // H1 (spec 05 T1): the server sent weakened master-password security settings — a hard block,
      // never softened into wrong-password.
      return KDF_POLICY_BLOCKED;
    case "bad_wire_id":
      // Security review 2026-10, branch A11 (c18): the login answer carried a malformed user/device id (A10 wire
      // grammar). A tampering-class refusal: never softened into "try again", like identity_mismatch above.
      return BAD_WIRE_ID;
    case "confirm_server":
      return CONFIRM_SERVER_FIRST;
    case "link_required":
      // The email that signed in fills the approved sentence; every caller that can see this code passes it.
      return linkRequiredCopy(email ?? "");
    case "server_fork":
      return SERVER_FORK;
    case "card_invalid":
      return CARD_INVALID;
    case "operator_account":
      return OPERATOR_NOT_IN_EXTENSION;
    case "remade_account":
      return fillApproved(REMADE_ACCOUNT, email ?? "");
    case "memory_unreadable":
      return MEMORY_UNREADABLE;
    case "server_error":
      return SIGN_IN_SERVER_ERROR;
    case "network":
      return UNREACHABLE;
    default:
      // "unknown" and an absent code (e.g. SW mid-restart) share web's terminal fallback.
      return SIGN_IN_FAILED;
  }
}

/** Locked-save banner result line (E1-5): the SW answers a code, never a sentence — the old
 *  path leaked its internal "locked" / "save failed (conflict)" strings into the red line.
 *  Unlock-prompt (2026-08-12): the LOGIN banner no longer renders the `locked` rung — its Save
 *  click summons the unlock screen and shows SAVE_UNLOCK_* below instead. The rung stays for the
 *  card banner's narrow lock-mid-resolve race (a locked card capture never records a pending, so
 *  there is nothing an unlock could finish there). */
/** Approved wording (the released extension's own words): Safari on iOS, the save was handed to the andvari app. */
export const SAVE_SENT_TO_APP = "Sent to andvari. Open the app to finish saving.";

/** Approved wording (decided on 2026-11-17): a Save (or a Save approved while
 *  locked) landed in the account that was open when it was made, and another account was open by the time it answered.
 *  The in-page toast after the save, in place of "Saved to the hoard." It names no account (the page reads the toast). */
export const SAVED_IN_OTHER_ACCOUNT = "Saved, in the andvari account that was open when you chose Save. The account open now doesn't have it.";

/** Approved wording (decided on 2026-11-17): a save refused, `shared_vault` (§12.2 rule 4: the extension writes only to the personal vault). */
export const SAVE_SHARED_VAULT = "This login is in a shared vault. Update it in the andvari app.";
/** Approved wording (the released extension's own words): Safari on iOS, a save refused because the andvari app has no account signed in. */
export const SAVE_APP_NO_ACCOUNT = "Could not save — open the andvari app and sign in first.";
/** Approved wording (the released extension's own words): Safari on iOS, a save refused because the andvari app did not answer. */
export const SAVE_APP_UNAVAILABLE = "Could not save — open the andvari app, then try again.";
/** Approved wording (the released extension's own words): a save refused, `locked` (the card banner's lock-mid-resolve race). */
export const SAVE_LOCKED = "Could not save — unlock andvari and try again.";
/** Approved wording (the released extension's own words): a save the server applied as a `conflict` (H20): no put path emits it any more; true if one ever does. */
export const SAVE_CONFLICT_KEPT_BOTH = "Saved — this login also changed elsewhere; both versions are in your vault.";
/** Approved wording (the released extension's own words): a save the server refused as `rejected` (H03): an attachment it references is gone. The same words as
 *  core HouseholdCopy.SAVE_REJECTED_ATTACHMENT. */
export const SAVE_REJECTED_ATTACHMENT = "The server refused this save — an attachment it references is no longer there. Remove that attachment, then save again.";
/**
 * PLACEHOLDER: a save of a new login or card whose answer from the server was lost: it may be saved. Must say: andvari
 * can't tell whether it was saved; saving again sends the same item, so it is never saved twice. Never "could not save".
 */
export const SAVE_CANNOT_TELL = "andvari can't tell whether this was saved: the server's answer didn't arrive. Save again: andvari sends the same item, so it is never saved twice.";
/**
 * PLACEHOLDER: a save the server refused as `rejected` because the account is full (`quota_exceeded`). Must say: the
 * server refused it because the account has no room left; saving again won't help until space is freed (or the
 * server's operator gives more). Never "try again", never an attachment.
 */
export const SAVE_REJECTED_FULL = "The server refused this save: your andvari account is full. Free some space, or ask your server's operator for more, then save again.";
/**
 * PLACEHOLDER: a save the server refused as `rejected` because the item, or its attachments, is too large or has too
 * many attachments (`item_too_large`, `item_attachment_quota`, `too_many_attachments`). Must say: it is too large for
 * the server; saving the same again won't work.
 */
export const SAVE_REJECTED_TOO_LARGE = "The server refused this save: the item is too large for it. Saving the same again won't work.";
/**
 * PLACEHOLDER: a save the server refused as `rejected` for a reason this extension does not know, or with none. Must
 * say: the server refused it, and saving the same again won't change that. Must not name a cause.
 */
export const SAVE_REJECTED_OTHER = "The server refused this save, and saving the same again won't change that.";
/**
 * PLACEHOLDER: Safari on iOS, the andvari app refused the capture handed to it (`app_refused`: it could not be sealed
 * for the app, or the app's queue did not take it). Must say: the app refused it, nothing was saved; open the app and
 * save again. Must not say the server refused it.
 */
export const SAVE_APP_REFUSED = "Could not save — the andvari app didn't take this login. Open the app, then save again.";
/** Approved wording (the released extension's own words): a save that failed for any other reason (retryable). */
export const SAVE_FAILED = "Could not save — try again.";

/**
 * The line for a refused save. [reason]: for `rejected`, the server's own reason for it (its wire code), so that a full
 * account is said as a full account and a missing attachment as a missing attachment.
 */
export function saveErrorCopy(code: SaveErrorCode | undefined, reason?: string): string {
  switch (code) {
    case "shared_vault":
      // §12.2 rule 4: the extension writes only to the personal vault.
      return SAVE_SHARED_VAULT;
    case "server_fork":
      // §4.4 "A fork stops traffic, not reading": nothing is written while the server's identity is in doubt.
      return SAVE_REFUSED_FORK;
    case "server_ended":
      // §4.4 "A session the server ends does not delete the device's copy": nothing is written while it stands so.
      // The banner is about a capture a lock would delete: never "lock" here (BZ).
      return SAVE_REFUSED_SERVER_ENDED_CAUGHT;
    case "app_no_account":
      return SAVE_APP_NO_ACCOUNT;
    case "app_unavailable":
      return SAVE_APP_UNAVAILABLE;
    case "locked":
      return SAVE_LOCKED;
    case "no_personal_vault":
      return NO_PERSONAL_VAULT_CONFIRM; // A9 review MEDIUM-1
    case "conflict":
      // H20 (2026-09-13 audit): a `conflict` push status is a write the server APPLIED (spec 03
      // §5), so "changed elsewhere — open it in the web vault" told the user the save did not
      // happen when it had. The SW now lands a conflict as ok:true and materializes the displaced
      // version itself, so this rung is no longer produced by any put path; it keeps the code's
      // slot in the union with copy that is TRUE if a future path ever emits it.
      return SAVE_CONFLICT_KEPT_BOTH;
    case "rejected":
      // H03 (recheck R37): the server's per-row `rejected` verdict. PERMANENT: the same put fails identically forever,
      // so the retryable default below would be a lie. Said by the server's own reason (BZ): only a missing or
      // mismatched attachment is said as one.
      if (reason === "quota_exceeded") return SAVE_REJECTED_FULL;
      if (reason === "unknown_attachment" || reason === "attachment_mismatch") return SAVE_REJECTED_ATTACHMENT;
      if (reason === "item_too_large" || reason === "item_attachment_quota" || reason === "too_many_attachments") return SAVE_REJECTED_TOO_LARGE;
      return SAVE_REJECTED_OTHER;
    case "app_refused":
      return SAVE_APP_REFUSED;
    case "cannot_tell":
      // BZ: the answer was lost, so it may be stored. Never "could not save": a second try sends the same item, once.
      return SAVE_CANNOT_TELL;
    default:
      // "failed" and an absent code (SW unreachable) — retryable, no jargon.
      return SAVE_FAILED;
  }
}

/** Approved wording (the released extension's own words): A9 review MEDIUM-1 (the §1.7 pattern), the browser holds no confirmed personal vault — a served wrap it
 *  never confirmed is a proposal, not a capture destination — so a save or TOTP add is refused with the way through. */
export const NO_PERSONAL_VAULT_CONFIRM = "Open andvari to confirm your personal vault.";

/** Approved wording (the released extension's own words): the popup's one-time-code add, done (design 2026-08-12). */
export const TOTP_ADDED = "One-time code added.";

/** Approved wording (the released extension's own words): the one-time-code add, `locked`. */
export const TOTP_ADD_LOCKED = "andvari locked before it could add the code — unlock and try again.";
/** Approved wording (the released extension's own words): the one-time-code add, `invalid`: what was pasted is no one-time-code secret. */
export const TOTP_ADD_INVALID = "That doesn't look like a one-time-code secret — paste the otpauth:// link or the setup key.";
/** Approved wording (the released extension's own words): the one-time-code add, `exists`: the extension never replaces a stored second factor. */
export const TOTP_ADD_EXISTS = "This login already has a one-time code — manage it in the web vault.";
/** Approved wording (the released extension's own words): the one-time-code add, `not_allowed`: a refused non-popup sender, so it names the popup. */
export const TOTP_ADD_NOT_ALLOWED = "andvari couldn't tell which login this code belongs to — add it from the popup instead.";
/** Approved wording (the released extension's own words): the one-time-code add, `conflict` (H20): a landed write; no put path emits it any more. */
export const TOTP_ADD_CONFLICT = "One-time code added — this login also changed elsewhere; both versions are in your vault.";
/** Approved wording (the released extension's own words): the one-time-code add, `read_only` (G21): a shared vault the person can only view. */
export const TOTP_ADD_READ_ONLY = "This login is in a shared vault you can only view — ask its owner to add a one-time code.";
/** Approved wording (the released extension's own words): the one-time-code add failed for any other reason (retryable). */
export const TOTP_ADD_FAILED = "Could not add the code — try again.";

/** TOTP-add failure lines (setTotp). `exists` is the ADD-ONLY contract speaking — the
 *  extension never replaces a stored second factor, so the copy routes to the web vault rather
 *  than hinting at a retry. `not_allowed` is a refused non-popup sender — it names the popup as
 *  the way through, because that's where the user picks the item themselves. */
export function totpAddErrorCopy(code: TotpAddCode | undefined): string {
  switch (code) {
    case "locked":
      return TOTP_ADD_LOCKED;
    case "no_personal_vault":
      return NO_PERSONAL_VAULT_CONFIRM; // A9 review MEDIUM-1
    case "invalid":
      return TOTP_ADD_INVALID;
    case "exists":
      return TOTP_ADD_EXISTS;
    case "not_allowed":
      return TOTP_ADD_NOT_ALLOWED;
    case "conflict":
      // H20: same truth as saveErrorCopy — a conflict is a LANDED write; no put path emits this
      // code any more, and if one ever does the sentence must not claim the add failed.
      return TOTP_ADD_CONFLICT;
    case "read_only":
      // G21: a reader-role shared vault — the owner has to add the code, or move the login to a
      // vault you can edit. Honest, not the lying retry the server refusal used to render.
      return TOTP_ADD_READ_ONLY;
    default:
      // "failed" and an absent code (SW mid-restart) — retryable, no jargon.
      return TOTP_ADD_FAILED;
  }
}

/** Approved wording (the released extension's own words): a Save clicked while locked summons the unlock screen (2026-08-12), and it opened. The SW keeps the click
 *  as approval and lands the save on unlock, so the line asks for no second Save. */
export const SAVE_UNLOCK_PROMPTED = "Unlock andvari to finish saving.";
/** Approved wording (the released extension's own words): the same, where the unlock screen could not be opened (Firefox rejects the gesture-less call): the
 *  toolbar is the way there. */
export const SAVE_UNLOCK_TOOLBAR = "Open andvari from the toolbar and unlock to finish saving.";

/** Approved wording (the released extension's own words): a login fill, `locked`. */
export const FILL_LOCKED = "andvari locked before it could fill — unlock and try again.";
/** Approved wording (the released extension's own words): a login fill, `not_allowed`: the worker would not release the login for this page. */
export const FILL_NOT_ALLOWED = "andvari wouldn't release this login for this page — try again from the popup.";
/** Approved wording (the released extension's own words): a login fill, `no_form`. */
export const FILL_NO_FORM = "No login fields found on this page — copy the username and password instead.";
/** Approved wording (the released extension's own words): a login fill, `no_fields`. */
export const FILL_NO_FIELDS = "Couldn't fill the fields on this page — copy the username and password instead.";
/** Approved wording (the released extension's own words): a login fill, `no_secret`: the login has no username or password. */
export const FILL_NO_SECRET = "Nothing to fill — this login has no username or password saved.";
/** Approved wording (the released extension's own words): a login fill, `unreachable` or no outcome from the page. */
export const FILL_UNREACHABLE = "Couldn't reach the page — reload the tab and retry.";

/** Fill-failure line (Cut M, v2 #14): shared by the in-page dropdown toast and the popup's
 *  "Fill this page" #msg strip — the fill paths used to fail SILENTLY (dropdown closed, popup
 *  reported delivery as success). Codes come from messages.ts FillOutcome/FillFailCode; the
 *  content script is the ground truth for what actually landed in the page's fields. */
export function fillErrorCopy(code: FillFailCode | undefined): string {
  switch (code) {
    case "locked":
      return FILL_LOCKED;
    case "not_allowed":
      return FILL_NOT_ALLOWED;
    case "no_form":
      return FILL_NO_FORM;
    case "no_fields":
      return FILL_NO_FIELDS;
    case "no_secret":
      return FILL_NO_SECRET;
    default:
      // "unreachable" and an absent code (SW mid-restart / no outcome from the page) share the
      // popup's long-standing delivery-failure sentence.
      return FILL_UNREACHABLE;
  }
}

/** Approved wording (the released extension's own words): why a card is not filled into this page (owner decision 2026-11-14): andvari fills a card only into a
 *  payment provider's card form, and this page takes the card in its own fields. One line; the popup adds the remedy
 *  (the copy buttons, or the andvari app in Safari). */
export const CARD_PAGE_FORM = "andvari fills a card only into a payment provider's card form, and this page takes the card itself.";

/** Approved wording (the released extension's own words): andvari may not run where the card form is, and no provider's address is known; the Safari build. */
export const CARD_PROVIDER_NOT_ALLOWED_ANY_SAFARI =
  "andvari isn't running on this page, so it can't fill a card here. To let it, allow andvari on Every Website in Safari's extension settings.";
/** Approved wording (the released extension's own words): andvari may not run where the card form is, and no provider's address is known; Chrome and Firefox. */
export const CARD_PROVIDER_NOT_ALLOWED_ANY =
  "andvari isn't running on this page, so it can't fill a card here. To let it, allow andvari on all sites in the extension's site access.";
/** Approved wording (the released extension's own words): andvari may not run where the card form is; the Safari build. {0} the provider's host. */
export const CARD_PROVIDER_NOT_ALLOWED_SAFARI =
  "The card form comes from {0}, where Safari doesn't let andvari run yet. To fill it, allow andvari on {0} or on Every Website in Safari's extension settings.";
/** Approved wording (the released extension's own words): andvari may not run where the card form is; Chrome and Firefox. {0} the provider's host. */
export const CARD_PROVIDER_NOT_ALLOWED =
  "The card form comes from {0}, where andvari isn't allowed to run. To fill it, allow andvari on {0} in the extension's site access.";

/** andvari may not run where the card form is: the provider's origin to allow when one is known (from the frames the
 *  page shows), else every website. [safari]: the Safari build, where the person allows it per site (or on every
 *  website) in Safari. */
export function cardProviderNotAllowedCopy(origin: string | undefined, safari: boolean): string {
  let host: string | null = null;
  try {
    if (origin !== undefined) host = new URL(origin).host || null;
  } catch {
    host = null;
  }
  if (host === null) return safari ? CARD_PROVIDER_NOT_ALLOWED_ANY_SAFARI : CARD_PROVIDER_NOT_ALLOWED_ANY;
  return fillApproved(safari ? CARD_PROVIDER_NOT_ALLOWED_SAFARI : CARD_PROVIDER_NOT_ALLOWED, host);
}

/** Approved wording (the released extension's own words): two provider card frames on the page ask for the same card detail (round-11 review): an invisible one
 *  laid over the real one, or an extra one beside it, looks exactly like this, so andvari fills none of them. */
export const CARD_DUPLICATE_FIELDS = "This page shows more than one payment form asking for the same card detail, so andvari fills none of them.";

/** Approved wording (the released extension's own words): this browser does not say which site a frame comes from (Firefox before 126, round-12 review), so a card
 *  is never filled into a payment form inside a frame. */
export const CARD_NO_FRAME_ORIGIN = "This browser doesn't tell andvari which site a payment form's frame comes from, so andvari fills no card into one. Update the browser to fill cards here.";

/** Approved wording (the released extension's own words): the popup's line over the cards in a build without in-page card fill (cardfillflag.ts; owner decision
 *  2026-11-14), in the Safari build, whose popup copies no card number or code: the app does. */
export const CARD_FILL_FROM_APP = "andvari fills no cards here: copy a card's number and code in the andvari app.";
/** Approved wording (the released extension's own words): the same line in a Chrome or Firefox build made with CARDFILL=0, whose popup copies every card detail
 *  itself. */
export const CARD_FILL_OFF_COPY = "This build of andvari fills no cards into pages: copy a card's details with the buttons below.";

/** The line for a build without in-page card fill, by target: only the Safari popup sends the person to the app. */
export function cardFillOffLine(safari: boolean): string {
  return safari ? CARD_FILL_FROM_APP : CARD_FILL_OFF_COPY;
}
/** Approved wording (the released extension's own words): the person tapped card fields in two different payment forms (round-13 review): nothing is filled until
 *  they start over and tap the one they mean. */
export const CARD_MIXED_FORMS = "You tapped card fields in two different payment forms; tap the one you want to pay with, then Fill.";

/** Approved wording (the released extension's own words): a card fill, `changed`: the payment form changed after the popup opened. */
export const CARD_FORM_CHANGED = "The payment form changed after andvari opened. Open andvari again and fill.";
/** Approved wording (the released extension's own words): a card fill, `no_focus`: no card field was tapped first. */
export const CARD_NO_FOCUS = "Tap the card field in the payment form first, then fill again.";
/** Approved wording (the released extension's own words): a card fill, `not_visible`: the tapped card field can't be seen. */
export const CARD_NOT_VISIBLE = "The card field you tapped can't be seen on the page, so nothing was filled. Scroll to the form and try again, or fill it by hand.";
/** Approved wording (the released extension's own words): a card fill, `closed_form`: the form keeps its fields where andvari can't tell which one was tapped. */
export const CARD_CLOSED_FORM = "This payment form keeps its fields where andvari can't tell which one you tapped, so nothing was filled. Fill it by hand.";
/** Approved wording (the released extension's own words): a card fill, `no_form`: the payment form changed. */
export const CARD_NO_FORM = "The payment form changed — tap its card field and try again.";
/** Approved wording (the released extension's own words): a card fill, `no_fields`. */
export const CARD_NO_FIELDS = "Couldn't fill the card fields on this page.";

/** A card fill that wrote nothing: the refusals in words, the rest as for a login fill. */
export function cardFillErrorCopy(code: CardFillFailCode | undefined, allowOrigin?: string, safari = false): string {
  switch (code) {
    case "page_form":
      return CARD_PAGE_FORM;
    case "provider_not_allowed":
      return cardProviderNotAllowedCopy(allowOrigin, safari);
    case "duplicate_fields":
      return CARD_DUPLICATE_FIELDS;
    case "changed":
      return CARD_FORM_CHANGED;
    case "fill_off":
      return cardFillOffLine(safari);
    case "mixed_forms":
      return CARD_MIXED_FORMS;
    case "no_frame_origin":
      return CARD_NO_FRAME_ORIGIN;
    case "no_focus":
      return CARD_NO_FOCUS;
    case "not_visible":
      return CARD_NOT_VISIBLE;
    case "closed_form":
      return CARD_CLOSED_FORM;
    case "no_form":
      return CARD_NO_FORM;
    case "no_fields":
      return CARD_NO_FIELDS;
    default:
      return fillErrorCopy(code);
  }
}

/** Approved wording (the released extension's own words): showing or copying a password, `locked`. */
export const REVEAL_LOCKED = "andvari locked before it could release that login — unlock and try again.";
/** Approved wording (the released extension's own words): showing or copying a password, `not_allowed`: a stale row (the item changed or vanished under a sync). */
export const REVEAL_NOT_ALLOWED = "andvari wouldn't release that login — reopen the popup and try again.";
/** Approved wording (the released extension's own words): showing or copying a password failed for any other reason (retryable). */
export const REVEAL_FAILED = "Could not release that login — try again.";

/** Reveal-seam failure line (#23 string sweep): the popup's clipboard path AND the show/hide
 *  password toggle both used to render the SW's raw `error` debug detail ("locked" / "unknown
 *  item" / "not allowed for this site") straight into the #msg strip. Codes come from the reveal
 *  seam (messages.ts); the popup always asks with explicit:true, so not_allowed here means a stale
 *  row — the item changed or vanished under a sync — not a host mismatch. Verb-neutral ("release
 *  that login", not "copy") because the same sentences render on the show-password path too. */
export function revealErrorCopy(code: RevealFailCode | undefined): string {
  switch (code) {
    case "locked":
      return REVEAL_LOCKED;
    case "not_allowed":
      return REVEAL_NOT_ALLOWED;
    default:
      // an absent code (SW mid-restart) — retryable, no jargon (the saveErrorCopy idiom).
      return REVEAL_FAILED;
  }
}

/** Approved wording (decided on 2026-11-17): a wrong quick-unlock PIN with one try left; {0} the number. */
export const PIN_WRONG_ONE_TRY_LEFT = "That PIN isn't right. {0} try left, or use your master password.";
/** Approved wording (decided on 2026-11-17): a wrong quick-unlock PIN with more tries left (or none); {0} the number. */
export const PIN_WRONG_TRIES_LEFT = "That PIN isn't right. {0} tries left, or use your master password.";
/** Approved wording (the released extension's own words): quick unlock, `expired`: the sign-in it rests on is too old. */
export const QUICK_UNLOCK_EXPIRED = "It's been a while since you signed in — enter your master password to continue.";
/** Approved wording (the released extension's own words): quick unlock, `exhausted`: too many wrong PINs, so it is off. */
export const PIN_EXHAUSTED = "Too many wrong PINs — quick unlock is off. Unlock with your master password.";
/** Approved wording (the released extension's own words): quick unlock, `corrupt` or `stale_uvk`: its record is gone and must be set up again. */
export const QUICK_UNLOCK_SET_UP_AGAIN = "Quick unlock needs to be set up again — unlock with your master password.";
/** Approved wording (the released extension's own words): quick unlock, `revoked`: the session it rests on ended. */
export const QUICK_UNLOCK_SESSION_ENDED = "Your session ended — sign in again with your master password.";
/** Approved wording (the released extension's own words): quick unlock, `server_error`. */
export const QUICK_UNLOCK_SERVER_ERROR = "The server had a problem answering — try again in a moment.";
/** Approved wording (the released extension's own words): a PIN unlock that failed for a benign reason (not armed, aborted, no code). */
export const PIN_UNLOCK_FAILED = "Couldn't quick-unlock — unlock with your master password.";

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
      return fillApproved(n === 1 ? PIN_WRONG_ONE_TRY_LEFT : PIN_WRONG_TRIES_LEFT, String(n));
    }
    case "expired":
      return QUICK_UNLOCK_EXPIRED;
    case "exhausted":
      return PIN_EXHAUSTED;
    case "corrupt":
    case "stale_uvk":
      return QUICK_UNLOCK_SET_UP_AGAIN;
    case "keys_damaged":
      // A13 (q38): the full unlock's H67 sentence, byte-identical — the same damaged row, the same verdict.
      return unlockErrorCopy("keys_damaged");
    case "revoked":
      return QUICK_UNLOCK_SESSION_ENDED;
    case "not_confirmed":
      return QUICK_UNLOCK_NOT_CONFIRMED;
    case "identity_mismatch":
      return IDENTITY_MISMATCH;
    case "memory_unreadable":
      return MEMORY_UNREADABLE;
    case "kdf_policy":
      return KDF_POLICY_BLOCKED;
    case "confirm_server":
      return CONFIRM_SERVER_FIRST;
    case "server_error":
      return QUICK_UNLOCK_SERVER_ERROR;
    case "network":
      return UNREACHABLE;
    case "operator_account":
      return OPERATOR_NOT_IN_EXTENSION;
    default:
      // not_armed / aborted (benign races) and an absent code — fall to the master password quietly.
      return PIN_UNLOCK_FAILED;
  }
}

/** Approved wording (decided on 2026-11-17): a quick unlock opened the vault,
 *  but the quick-unlock record could not be updated afterwards (`quick_unlock_not_updated`). The record is kept and the
 *  next lock arms it again; if it does not, the master password unlocks as always. */
export const QUICK_UNLOCK_NOT_UPDATED = "Your vault is open, but andvari couldn't update quick unlock in this browser. If quick unlock doesn't work next time, use your master password.";

/** Approved wording (decided on 2026-11-17): quick unlock was switched off
 *  (in another window, say) while this setup was under way (`switched_off`); nothing was set up. */
export const QUICK_UNLOCK_SWITCHED_OFF = "Quick unlock was turned off while it was being set up, so it's still off. Set it up again if you want it.";

/** Approved wording (decided on 2026-11-17): a password (or one-time-code)
 *  sign-in opened the vault, but the session could not be written to this browser's session storage
 *  (`session_not_saved`). The vault stays open; if the browser stops andvari's background worker before the next lock,
 *  the vault comes back locked. */
export const SESSION_NOT_SAVED = "Your vault is open, but andvari couldn't save this session in this browser. If it locks sooner than you expect, unlock it again.";

/** Approved wording (decided on 2026-11-17): the browser refused andvari's
 *  auto-lock alarm twice (`timerNotice: "autolock"`). The vault still locks at its time: the worker checks the deadline
 *  at every way in, before anything is served. One line beside the open vault. */
export const AUTOLOCK_TIMER_NOT_SET = "Your browser didn't let andvari set its auto-lock timer. Your vault still locks on time: once the time is up, andvari locks it before doing anything else.";

/** Approved wording (decided on 2026-11-17): the browser refused andvari's
 *  periodic check for changes twice (`timerNotice: "resync"`). The live connection still brings changes while it is up. */
export const RESYNC_TIMER_NOT_SET = "Your browser didn't let andvari set its timer for checking your vault, so changes made on your other devices may take longer to show up here.";

/** The open vault's one line for an alarm the browser refused; empty when none. */
export function timerNoticeLine(notice: "autolock" | "resync" | null | undefined): string {
  return notice === "autolock" ? AUTOLOCK_TIMER_NOT_SET : notice === "resync" ? RESYNC_TIMER_NOT_SET : "";
}

/** Approved wording (the released extension's own words): setting up quick unlock, `locked`. */
export const ENROLL_LOCKED = "Unlock andvari first to set up quick unlock.";
/** Approved wording (the released extension's own words): setting up quick unlock, `must_change_password`. */
export const ENROLL_MUST_CHANGE_PASSWORD = "Set a new master password in the web vault before turning on quick unlock.";
/** Approved wording (the released extension's own words): setting up quick unlock, `need_full_unlock`. */
export const ENROLL_NEED_FULL_UNLOCK = "Enter your master password once more to set up quick unlock.";
/** Approved wording (the released extension's own words): a quick-unlock PIN refused, `too_short`. */
export const PIN_TOO_SHORT = "Use at least 6 characters for your PIN.";
/** Approved wording (the released extension's own words): a quick-unlock PIN refused, `digits_need_length`. */
export const PIN_DIGITS_NEED_LENGTH = "An all-number PIN needs at least 10 digits — or add a letter to a shorter one.";
/** Approved wording (the released extension's own words): a quick-unlock PIN refused as too easy to guess. */
export const PIN_TRIVIAL = "That PIN is too easy to guess — avoid sequences and repeats.";
/** Approved wording (the released extension's own words): setting up quick unlock failed for any other reason. */
export const ENROLL_FAILED = "Couldn't turn on quick unlock — try again.";

/** Quick-unlock enrollment refusal (spec 01 §8.4). `weak_pin` carries the entropy-floor reason
 *  (breaker A2⊕B8 — enforcement, not copy-only). */
export function enrollErrorCopy(code: EnrollCode | undefined, reason?: PinWeakReason): string {
  switch (code) {
    case "locked":
      return ENROLL_LOCKED;
    case "must_change_password":
      return ENROLL_MUST_CHANGE_PASSWORD;
    case "need_full_unlock":
      return ENROLL_NEED_FULL_UNLOCK;
    case "unavailable":
      return QUICK_UNLOCK_UNAVAILABLE;
    case "weak_pin":
      switch (reason) {
        case "too_short":
          return PIN_TOO_SHORT;
        case "digits_need_length":
          return PIN_DIGITS_NEED_LENGTH;
        default:
          return PIN_TRIVIAL;
      }
    case "switched_off":
      return QUICK_UNLOCK_SWITCHED_OFF;
    default:
      return ENROLL_FAILED;
  }
}

/** Approved wording (the released extension's own words): device unlock, `bio_cancelled`: the system's prompt was dismissed, timed out, or its passkey is gone. */
export const BIO_UNLOCK_CANCELLED = "Device unlock was cancelled — try again, or use your master password.";
/** Approved wording (the released extension's own words): device unlock that failed for a benign reason (not armed, aborted, no code). */
export const BIO_UNLOCK_FAILED = "Couldn't unlock with your device — unlock with your master password.";
/** Approved wording (the released extension's own words): setting up device unlock, `bio_unsupported`: no platform authenticator with PRF here. */
export const BIO_UNSUPPORTED = "This device can't do biometric quick unlock — set up a PIN instead.";
/** Approved wording (the released extension's own words): setting up device unlock, `bio_cancelled`: the setup prompt was dismissed (nothing written). */
export const BIO_SETUP_CANCELLED = "Setup was cancelled — try again when you're ready.";
/** Approved wording (the released extension's own words): setting up device unlock failed for any other reason. */
export const ENROLL_BIO_FAILED = "Couldn't turn on device quick unlock — try again.";

/**
 * Biometric quick-unlock redeem failure (0.17.0). No `wrong_pin`/`exhausted` (a hardware-held PRF secret
 * has no offline oracle). `bio_cancelled` = the OS prompt was dismissed / timed out / the passkey was
 * deleted — all indistinguishable by design, and all retryable. Wiped-blob outcomes (expired/corrupt/
 * stale_uvk) and a revoked session route to the master password; hard faults keep their sentences.
 */
export function bioUnlockErrorCopy(code: BioUnlockCode | undefined): string {
  switch (code) {
    case "bio_cancelled":
      return BIO_UNLOCK_CANCELLED;
    case "expired":
      return QUICK_UNLOCK_EXPIRED;
    case "corrupt":
    case "stale_uvk":
      return QUICK_UNLOCK_SET_UP_AGAIN;
    case "keys_damaged":
      return unlockErrorCopy("keys_damaged"); // A13 (q38): the H67 sentence, byte-identical
    case "revoked":
      return QUICK_UNLOCK_SESSION_ENDED;
    case "not_confirmed":
      return QUICK_UNLOCK_NOT_CONFIRMED;
    case "identity_mismatch":
      return IDENTITY_MISMATCH;
    case "memory_unreadable":
      return MEMORY_UNREADABLE;
    case "kdf_policy":
      return KDF_POLICY_BLOCKED;
    case "confirm_server":
      return CONFIRM_SERVER_FIRST;
    case "server_error":
      return QUICK_UNLOCK_SERVER_ERROR;
    case "network":
      return UNREACHABLE;
    case "operator_account":
      return OPERATOR_NOT_IN_EXTENSION;
    default:
      // not_armed / aborted (benign races) and an absent code — fall to the master password quietly.
      return BIO_UNLOCK_FAILED;
  }
}

/** Biometric enrollment refusal (0.17.0). `bio_unsupported` = no platform authenticator / no PRF on this
 *  device (the PIN stays available); `bio_cancelled` = the setup prompt was dismissed (nothing written). */
export function enrollBioErrorCopy(code: EnrollBioCode | undefined): string {
  switch (code) {
    case "locked":
      return ENROLL_LOCKED;
    case "must_change_password":
      return ENROLL_MUST_CHANGE_PASSWORD;
    case "need_full_unlock":
      return ENROLL_NEED_FULL_UNLOCK;
    case "bio_unsupported":
      return BIO_UNSUPPORTED;
    case "bio_cancelled":
      return BIO_SETUP_CANCELLED;
    case "unavailable":
      return QUICK_UNLOCK_UNAVAILABLE;
    case "switched_off":
      return QUICK_UNLOCK_SWITCHED_OFF;
    default:
      return ENROLL_BIO_FAILED;
  }
}

/** Approved wording (the released extension's own words): a card detail could not be copied (#23): the card seam carries no code — one retryable sentence, never
 *  the SW's internal "unknown item"/"no number on this card". */
export const CARD_COPY_FAILED = "Could not copy from this card — reopen the popup and try again.";

/** Approved wording (the released extension's own words): the clipboard write was refused (#23; focus loss or browser policy), never the raw exception text. */
export const CLIPBOARD_FAILED = "Couldn't copy to the clipboard — try again.";

/** Approved wording (decided on 2026-11-17): the lock-reason line (E1-7, the web's inactivityNotice), one minute. */
export const LOCKED_AFTER_ONE_MINUTE = "Locked after {0} minute without use.";
/** Approved wording (decided on 2026-11-17): the lock-reason line, {0} minutes (whole minutes from 60 seconds on, rounded). */
export const LOCKED_AFTER_MINUTES = "Locked after {0} minutes without use.";
/** Approved wording (decided on 2026-11-17): the lock-reason line, one second. */
export const LOCKED_AFTER_ONE_SECOND = "Locked after {0} second without use.";
/** Approved wording (decided on 2026-11-17): the lock-reason line, {0} seconds (below 60 seconds only). */
export const LOCKED_AFTER_SECONDS = "Locked after {0} seconds without use.";

/**
 * F26 lock-reason line (E1-7): verbatim port of web format.ts inactivityNotice. Seconds
 * render ONLY below 60 s; anything ≥ 60 s renders whole minutes via Math.round (AM3 —
 * 90 s → "2 minutes"); the seconds branch clamps to ≥ 1 s.
 */
export function lockNoticeCopy(seconds: number): string {
  if (seconds >= 60) {
    const m = Math.round(seconds / 60);
    return fillApproved(m === 1 ? LOCKED_AFTER_ONE_MINUTE : LOCKED_AFTER_MINUTES, String(m));
  }
  const s = Math.max(1, Math.round(seconds));
  return fillApproved(s === 1 ? LOCKED_AFTER_ONE_SECOND : LOCKED_AFTER_SECONDS, String(s));
}

/** Approved wording (decided on 2026-11-23): the popup line for one shared vault that is served and not open here: a
 *  new grant, which a full client may ask the person to review, or a vault closed in this session and served again,
 *  which opens at the next unlock here. It says: it is not open here; review it in andvari if andvari asks; then lock
 *  and unlock this extension; it may still stay closed here. */
export const GRANTS_WAITING_ONE = "1 shared vault is not open here. Review it in andvari if it asks you to, then lock and unlock this extension. It may still stay closed here.";
/** Approved wording (decided on 2026-11-23): the same line for {0} (a number above one) shared vaults. */
export const GRANTS_WAITING = "{0} shared vaults are not open here. Review them in andvari if it asks you to, then lock and unlock this extension. Some may still stay closed here.";

/** The popup line for shared vaults that are served and not open here: a new grant waits for a full client to verify
 *  it, and a vault closed in this session opens at the next unlock here. Empty for none. */
export function waitingGrantsLine(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "";
  return n === 1 ? GRANTS_WAITING_ONE : fillApproved(GRANTS_WAITING, String(n));
}
