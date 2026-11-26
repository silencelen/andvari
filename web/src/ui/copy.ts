/**
 * The design's copy as the web shows it (design 2026-11-15 §4.4, §7.7, §10, §12.2, §12.3), word for word as core's
 * `AppCopy` holds it. Values are filled in once, as plain text, and rendered as text, never markup.
 *
 * Sentences the design gives no wording for are marked `PLACEHOLDER` below, each with what it must say: a copy pass
 * is writing them. Never ship one as final copy.
 */
import { type KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";

/** `{0}`, `{1}`, … in [template] replaced by [values] in one pass (a value reading "{0}" is copied, not filled). */
export function fill(template: string, ...values: string[]): string {
  return template.replace(/\{(\d+)\}/g, (m, i: string) => {
    const v = values[Number(i)];
    return v === undefined ? m : v;
  });
}

/**
 * [text] less its last sentence, with the end of the sentence before it kept ("A. B. C." -> "A. B."). A sentence ends
 * at ".", "!" or "?" (with any closing quote or bracket after it) followed by a space. Throws on a single sentence, so
 * a line built from another can never come out empty.
 */
export function withoutLastSentence(text: string): string {
  let cut = -1;
  for (const m of text.matchAll(/[.!?][”"’)]*(?= +\S)/g)) cut = (m.index ?? 0) + m[0].length;
  if (cut < 0) throw new Error(`one sentence only: ${text}`);
  return text.slice(0, cut);
}

// §12.2: the web's first screen.
export const CREATE_ACCOUNT_HERE = "Create an account here";
export const SIGN_IN = "Sign in";
export const USE_THE_APP = "Joining with an invite or connecting with someone? Use the andvari app.";
export const SIGNUP_FULL = "Sign-up is full right now";
export const SIGN_IN_FORGOT = "Forgot your master password?";

// §4.4, §12.3: the Trust Gate and the card.
export const GATE_TITLE_CONNECT = "Connect to this server?";
export const GATE_BASELINE = "This server will store your encrypted vault and see your account activity (email, sign-ins, item counts). Only continue if you trust it.";
export const GATE_CALLS_ITSELF = "It calls itself “{0}” — nobody you know has vouched for it";
export const GATE_ENTERING_PASSWORD = "You're about to enter your master password for this server.";
export const GATE_KIND_CHANGE = "{0} ({1}) now says it is a {2} server. This changes who can be offered operator recovery. Continue only if you expected this.";
export const MASTER_PASSWORD_FOR = "Master password for {0} on {1} ({2})";
export const CARD_FORK = "This server's identity changed in a way andvari can't verify. Don't continue. If you trust the operator, ask them what happened.";
export const FORGET_THIS_SERVER = "Forget this server";
/** Approved wording (decided on 2026-11-17): §4.4 "'Forget this server' says plainly that it deletes this copy". */
export const FORGET_DELETES_COPY = "What andvari has in this browser stays readable until you forget this server. Forget this server removes it from this browser, including changes that haven't synced. Your account on the server is not affected.";
/** Approved wording (decided on 2026-11-17): §4.4, the copy under a fork stays readable. */
export const FORKED_COPY_READ = "This browser still has a copy of your vault. You can open it to read, copy and export what's in it. Nothing is sent to this server, and nothing can be changed.";
/** Approved wording (decided on 2026-11-17): the button that opens that copy. */
export const FORKED_COPY_OPEN = "Open the copy in this browser";
/** Approved wording (decided on 2026-11-17): there is no copy to open. */
export const FORKED_NO_COPY = "There's no copy of this account in this browser to open.";
/**
 * Approved entry 12 (CARD_RECORD_DAMAGED), title and body: this browser's pin record of the origin does not decode, and
 * (as core's engine shows its orphan) a kept session whose origin holds no pin record. {0} the origin. Two paragraphs,
 * split at the line break. Its one button is {@link FORGET_THIS_SERVER}.
 */
export const CARD_RECORD_DAMAGED_TITLE = "andvari can't read its record of this server";
export const CARD_RECORD_DAMAGED =
  "The record this device keeps of the identity of {0} is damaged, or comes from a newer version of andvari. Without it andvari can't tell whether this is still the same server, so it has stopped using it on this device.\nIf you went back to an older version of andvari, update it. Otherwise choose Forget this server and connect again. That removes this server's data from this device, including changes that hadn't synced. Your account on the server is not affected.";
/**
 * Approved entry 8 (CARD_OTHER_ADDRESS), title and body: a first pin refused with `origin_mismatch`. {0} the address
 * this browser dialed (the one that served it), {1} the address the card names. No buttons.
 */
export const CARD_OTHER_ADDRESS_TITLE = "This address doesn't match the server's identity card";
export const CARD_OTHER_ADDRESS =
  "The server at {0} showed an identity card made for a different address, {1}. andvari didn't connect, and nothing of yours was sent. The address may be wrong, the server may have moved, or someone may be imitating it. Check the address with the person who runs the server.";
/** Approved entry 11 (CARD_NOT_VERIFIED): under a pin, a newer card failed verification. A notice where CARD_WITHHELD shows. */
export const CARD_NOT_VERIFIED =
  "This server showed an update to its identity card that andvari can't verify. andvari ignored it and kept the card it had already checked. If this message stays, ask the operator what happened.";
/** Approved entry 10 (GATE_TITLE_KIND_CHANGE): the kind-change gate's title and its two buttons. The body is GATE_KIND_CHANGE. */
export const GATE_TITLE_KIND_CHANGE = "This server says it changed";
export const GATE_KIND_CONTINUE = "Continue";
export const GATE_KIND_NOT_NOW = "Not now";
/** Core's CARD_MOVED_UPDATE: entry 8 says the baked public instance shows this in its place. */
export const CARD_MOVED_UPDATE = "This server says it moved. Update andvari.";
/** Approved wording (decided on 2026-11-17): §4.4, the unlock card of a session the server ended, with the offline copy kept. */
export const SESSION_ENDED_HELD = "The server signed this browser out. Your master password still opens the copy in this browser, to read only. Sign in again to sync and make changes.";
/**
 * PLACEHOLDER: a session this browser could not confirm (a refresh whose answer never came had no try left, spec 03 §2),
 * said where the session ends and on the card the person lands on. No server ended it, so it is never said as ended by
 * the server, nor as revoked. Must say: andvari could not confirm this browser's session with its server in time; it sent
 * nothing again, so no other session was ended; sign in again on this browser, which also ends the session that could
 * not be confirmed (the server may still hold it).
 */
export const SESSION_NOT_CONFIRMED =
  "⟦andvari could not confirm this browser's session with its server in time. It sent nothing again, so no other session was ended. Sign in again on this browser: that also ends the session that could not be confirmed.⟧";
/**
 * PLACEHOLDER: where a session this browser could not confirm ends on a browser without the offline copy, and changes
 * made here were not sent (they go with the session: there is no copy to keep them). {0} the count. Never says the
 * session expired. Must say: how many changes made in this browser were not sent before it ended its session, and that
 * they are lost.
 */
export const UNSENT_LOST_NOT_CONFIRMED = "⟦{0} changes made in this browser were not sent before it ended its session, and they are lost⟧";
/**
 * PLACEHOLDER: as UNSENT_LOST_NOT_CONFIRMED, for exactly one change. Never says the session expired. Must say: one
 * change made in this browser was not sent before it ended its session, and it is lost.
 */
export const UNSENT_LOST_NOT_CONFIRMED_ONE = "⟦1 change made in this browser was not sent before it ended its session, and it is lost⟧";
/**
 * PLACEHOLDER: a request that needed the session renewed, where this browser could not save the mark that a renewal is
 * on its way (its storage refused the write), so nothing was sent. Must say: this browser could not save what it needs to
 * renew the session, so nothing was sent; free some space in the browser's storage, or sign in again.
 */
/**
 * PLACEHOLDER: on the card after a person's own sign-out of an account whose session this browser could not confirm
 * with its server (a refresh that got no answer; the token kept for the next sign-in's name goes with the sign-out).
 * Must say: the end of that session could not be confirmed with the server; to end it, sign in again on this browser and
 * then sign out, or remove this browser from the list of devices on another device. (A sign-in again alone does not end
 * it: a browser's entry at the server ends only what a sign-in names, and the token is no longer kept to be named.)
 */
export const SIGN_OUT_NOT_CONFIRMED =
  "⟦Signed out, but andvari couldn't confirm with the server that this browser's session ended. To end it, sign in again on this browser and then sign out, or remove this browser from your devices on another device.⟧";
/**
 * PLACEHOLDER: on the card after a person's own sign-out of an account whose session this browser could not confirm
 * with its server, where removing what this browser kept of that session could not be written (tried twice). Must say:
 * the end of that session could not be confirmed with the server, and this browser still holds data of that session and
 * could not remove it; to end it, remove this browser from the list of devices on another device (the only way that
 * then works).
 */
export const SIGN_OUT_KEPT_NOT_REMOVED =
  "⟦Signed out, but andvari couldn't confirm with the server that this browser's session ended, and this browser still holds data of that session that it could not remove. To end it, remove this browser from your devices on another device.⟧";
/**
 * PLACEHOLDER: on the card a tab lands on when its session ended because another account was signed in on this browser
 * (with the offline copy on, a browser holds one account's session at a time; nothing was sent, and this account was not
 * signed out by anyone). Must say: another account is signed in on this browser now, so this tab's session ended here; to
 * go on with this account, sign in again (which takes this browser's session from the other account).
 */
export const ANOTHER_ACCOUNT_SIGNED_IN =
  "⟦Another account is signed in on this browser now, so this tab's session ended here. To go on with your account, sign in again; that takes this browser's session from the other account.⟧";
export const RENEWAL_NOT_SAVED ="⟦This browser could not save what it needs to renew the session, so nothing was sent. Free some space in the browser's storage, or sign in again.⟧";
/**
 * PLACEHOLDER: the vault's notice while the copy of that session is open to read (in place of SESSION_ENDED_COPY, which
 * says the server signed the browser out). Must say: this browser could not confirm its session with the server in time
 * and ended it itself; you're reading the copy in this browser: nothing is sent, and nothing can be changed; to sync
 * again, lock, then sign in.
 */
export const SESSION_NOT_CONFIRMED_COPY =
  "⟦This browser could not confirm its session with the server in time and ended it. You're reading the copy in this browser: nothing is sent, and nothing can be changed. To sync again, lock, then sign in.⟧";
/** Approved wording (decided on 2026-11-17): §4.4, the line above the read-only open of that copy. */
export const ENDED_COPY_READ = "You can open the copy in this browser with your master password to read, copy and export what's in it. Nothing is sent, and nothing can be changed until you sign in again.";
/** Approved wording (decided on 2026-11-17): the button that opens it. */
export const ENDED_COPY_OPEN = "Open the copy";
/** Approved wording (decided on 2026-11-17): §4.4 "with a notice in view", the vault's notice while that copy is open. */
export const SESSION_ENDED_COPY = "The server signed this browser out. You're reading the copy in this browser: nothing is sent, and nothing can be changed. To sync again, lock, then sign in.";
/** Approved wording (decided on 2026-11-17): the changes the queue still holds when the server ended the session. {0} the count. */
export const KEPT_CHANGES_ONE = "1 change hasn't been sent yet. It stays in this browser and is sent when you sign in again.";
/** Approved wording (decided on 2026-11-17): as above, more than one. {0} the count. */
export const KEPT_CHANGES_MANY = "{0} changes haven't been sent yet. They stay in this browser and are sent when you sign in again.";

// Design §4.4 (decided on 2026-11-17): this browser's copy is never deleted over changes that were not sent without the
// person having been told how many. Said before "Sign out", "Forget this server" and turning the offline copy off or
// removing it; the act then needs a second click. Filled by unsentLine (session.ts counts them).
/** Approved wording (decided on 2026-11-17): before an act that deletes this browser's copy, when one change made here was not sent. */
export const UNSENT_LOST_ONE = "1 change made in this browser hasn't been sent to the server yet. It is lost with this browser's copy.";
/** Approved wording (decided on 2026-11-17): as above, more than one. {0} the count. */
export const UNSENT_LOST_MANY = "{0} changes made in this browser haven't been sent to the server yet. They are lost with this browser's copy.";
/** Approved wording (decided on 2026-11-17): as above, when this browser cannot read its copy to count them. Never said as none. */
export const UNSENT_UNKNOWN = "This browser can't tell whether changes made in it haven't been sent to the server yet. Any that haven't are lost with this browser's copy.";
/** Approved wording (decided on 2026-11-17): under that line on the unlock card, where sending them needs the vault open: the way to send them first. */
export const UNSENT_SEND_FIRST_UNLOCK = "To try sending them first, unlock instead: they're sent once the vault is open and the server answers.";
/** Approved wording (decided on 2026-11-17): under that line where the server ended the session, or a sign-in is asked for: the way to send them first. */
export const UNSENT_SEND_FIRST_SIGN_IN = "To try sending them first, sign in again instead: they're sent once the server answers.";
/**
 * Approved wording (decided on 2026-11-17): after the browser itself ended a sign-in (the recovery kit was not confirmed in time; the account is the
 * operator's) while its copy holds changes not sent, or it cannot tell: said after the count line, on the card the
 * person lands on. Nothing is deleted until they sign out there.
 */
export const SIGN_IN_ENDED_KEPT = "No session is open in this browser now. Its copy of your account, with anything not sent yet, stays here until you sign out of it below.";
/** Approved wording (decided on 2026-11-17): the button beside that line in Settings, where the vault is open. */
export const UNSENT_SEND_FIRST = "Try sending them first";
/** Approved wording (decided on 2026-11-17): after that button, when every change was sent: nothing is lost now, and the act needs one click again. */
export const UNSENT_ALL_SENT = "Every change was sent to the server.";
/** Approved wording (decided on 2026-11-17): after that button, when not every change could be sent now; the line above says how many remain. */
export const UNSENT_SEND_FIRST_FAILED = "Not every change could be sent. The ones that weren't are still only in this browser.";
/** Approved wording (decided on 2026-11-17): the "Forget this server" button once armed by unsent changes; the second click forgets. */
export const FORGET_ARMED_LABEL = "Forget and lose unsent changes";
/** Approved wording (decided on 2026-11-17): beside it, the button that leaves things as they are. */
export const FORGET_KEEP = "Keep this server";

/** The line for [unsent] changes not sent: null = this browser cannot tell; none for 0. */
export function unsentLine(unsent: number | null): string | undefined {
  if (unsent === null) return UNSENT_UNKNOWN;
  if (unsent <= 0) return undefined;
  return unsent === 1 ? UNSENT_LOST_ONE : fill(UNSENT_LOST_MANY, String(unsent));
}
export const CARD_WITHHELD = "This server is showing an older version of its identity card";
/** §13: the web cannot follow a move. {0} the new origin. */
export const CARD_MOVED_WEB = "This server says it moved to {0}";
export const CARD_CHANGED_UPDATE = "This server says it changed. Update andvari.";
/**
 * PLACEHOLDER: at the first screen's check, the server's newest identity card verified and says the server changed its
 * kind (and no update is needed), which this page must show the person before going on; it reaches this stop only when
 * another tab moved the record meanwhile. Must say: the server's card says it changed; nothing of this person's was sent;
 * load the page again to see the change and decide. Must not say the card could not be verified.
 */
export const CARD_KIND_CHANGED_RELOAD = "This server's identity card says the server changed. Nothing of yours was sent. Load this page again to see the change before you go on.";
export const AS_THE_SERVER_NAMES_ITSELF = "(as the server names itself)";
/** Approved wording (decided on 2026-11-17): the label beside the operator key's short form on the Trust Gate (§4.4 names the value, not its label). */
export const GATE_OPERATOR_KEY = "Operator key";
/** Approved wording (decided on 2026-11-17): the gate's confirm and cancel buttons (§12.3 gives none for the typed-address wording). */
export const GATE_CONTINUE = "Connect";
export const GATE_CANCEL = "Cancel";
/** Approved wording (decided on 2026-11-17): the served card chain failed to verify, or does not belong to this address. */
export const CARD_REFUSED = "andvari couldn't verify this server's identity card, so it didn't connect. Nothing of yours was sent.";
/**
 * PLACEHOLDER (the wording page's proposal PQ15): the password rule refused an act of a signed-in person because this
 * browser must confirm the server first (the Trust Gate). No identity card failed: CARD_REFUSED is not true here.
 */
export const CONFIRM_SERVER_REFUSED = "This browser needs you to confirm this server first, so nothing was sent. Sign in again to see it.";
/** PLACEHOLDER (PQ15): the same, when this browser has stopped using the server (the rule refuses entry). */
export const SERVER_STOPPED_REFUSED = "andvari has stopped using this server in this browser, so nothing was sent.";

/**
 * PLACEHOLDER (decided on 2026-11-17): the password rule refused a recovery with the kit because this browser must
 * confirm the server first (the Trust Gate). The person forgot their master password, so "sign in again" is not open to
 * them. Must say: nothing was sent (the old kit and password still stand); load this page again, confirm the server
 * there, and start the recovery with the kit again.
 */
export const KIT_RECOVERY_CONFIRM_SERVER_REFUSED =
  "This browser needs you to confirm this server first, so nothing was sent and your recovery kit still works. Load this page again, confirm the server, then start the recovery again.";

/**
 * PLACEHOLDER: the password rule refused a sign-up (its emailed code, or the registration) because this browser must
 * confirm the server first (the Trust Gate). The person has no account yet, so "sign in again" is not open to them.
 * Must say: nothing was sent (no account was made); load this page again, confirm the server there, and sign up again.
 * Must not say an identity card failed.
 */
export const SIGNUP_CONFIRM_SERVER_REFUSED = "This browser needs you to confirm this server first, so nothing was sent and no account was made. Load this page again, confirm the server, then sign up again.";

/** The line for an act the password rule refused, by the rule's decision: never the card's refusal, which did not happen. */
export function passwordRuleText(decision: "trust_gate" | "refuse_entry"): string {
  return decision === "trust_gate" ? CONFIRM_SERVER_REFUSED : SERVER_STOPPED_REFUSED;
}

// §7.2, §7.6, §11.4: sign-up.
export const AGE_13_OR_OLDER = "I am 13 or older";
export const MAIL_UNAVAILABLE = "We can't send email right now. Try again in a while.";
export const EMAIL_CHECK_SPAM = "If no email arrives in a few minutes, check spam or try again.";
/**
 * Approved wording (decided on 2026-11-17): , OPEN: the line above the emailed-code field. {0} the address. Not true as it stands for an address that
 * already has an account: the server answers alike and mails that address a different email, on purpose. The owner is
 * being shown a replacement; do not ship this one.
 */
export const CODE_SENT = "If {0} can be used for a new account, a 6-digit code is on its way there. If you already have an account with it, you'll get an email that says so instead.";
/**
 * PLACEHOLDER: shown in CODE_SENT's place: the server mails the "you already have an account" email at most once a day per
 * address (and answers alike every time), so a second start that day for such an address sends nothing. {0} the address.
 */
export const CODE_SENT_DAILY = "If {0} can be used for a new account, a 6-digit code is on its way there. If you already have an account with it, you'll get an email that says so instead (at most one such email a day).";
/** Approved wording (decided on 2026-11-17): the proof-of-work progress line. */
export const POW_PROGRESS = "Getting ready to send your code…";

// §7.7: recovery at sign-up (the only choice the web offers there; operator recovery is turned on in Settings).
export const RECOVERY_KIT_ONLY = "You'll save a recovery kit now. If you lose both your master password and your recovery kit, nobody can get your vault back.";
export const RECOVERY_ONLY_ME_DETAIL = "You'll save a recovery kit now. If you lose both your master password and your recovery kit, nobody can get your vault back, not even the people who run this server.";

// §10: the kit.
export const KIT_TITLE = "andvari recovery kit";
export const KIT_KEEP_PRIVATE = "Keep this private. Anyone with this kit and your email address can reset your master password and open your vault.";
export const KIT_ACCOUNT_ID = "Your account ID: {0}";
export const KIT_HOW_TO_RECOVER = "To recover: open andvari → Sign in → Forgot your master password? → Scan your recovery kit";
export const KIT_TYPE_GROUPS = "Type groups {0}, {1} and {2}";
export const KIT_RECOVER = "Recover {0} on {1} ({2})";
/** Approved wording (decided on 2026-11-17): what the recovery screen says this does (§10 asks for it, gives no words). */
export const KIT_RECOVER_SETS_PASSWORD = "This sets a new master password for that account, signs it out on its other devices and turns off two-step sign-in. You'll save a new recovery kit afterwards.";
/** Approved wording (decided on 2026-11-17): the field for a typed or pasted kit on the web (the web has no scanner). */
export const KIT_PASTE_LABEL = "Your kit's text";
/** Approved wording (decided on 2026-11-17): the three tries are used up: the kit is shown again. */
export const KIT_SHOWN_AGAIN = "Those groups don't match your kit, so here it is again. Check what you saved, then type the groups again.";
/** Approved wording (decided on 2026-11-17): a kit made for another server or another identity card than this one. */
export const KIT_WRONG_SERVER = "This kit was made for a different server.";
/** Approved wording (decided on 2026-11-17): the kit was replaced (409 recovery_piece_stale). */
export const KIT_REPLACED = "A newer recovery kit was made on another of your devices, so the one shown here doesn't work. Make a new one here, and throw away any copy of the old one.";

// §8.7, spec 03 §16.8: an account that allows only linked devices.
/** `403 link_required` on the web, which cannot be linked (§13). The owner's approved wording of 2026-11-15
 *  (copy key `LINK_REQUIRED_CANNOT_LINK`): a title, and a body whose {0} is the account's email. */
export const LINK_REQUIRED_WEB_TITLE = "This account only allows linked devices";
export const LINK_REQUIRED_WEB =
  "{0} has “New devices must be linked” turned on, and andvari in a browser can't be linked. Your master password was right. To sign in here, open andvari on one of your devices → Settings → Your devices, and turn that setting off. You can turn it on again once this browser has signed in.";
/** Approved wording (decided on 2026-11-17): the web never signs in as the operator account (§9.1, §13). */
export const OPERATOR_NOT_ON_WEB = "This is the server's operator account. It can only be used in the andvari desktop app or in andvari-cli, not in a browser.";
/**
 * Approved wording (decided on 2026-11-17): an operator's kit recovery refused after its commit (a pin behind a handover): the password was reset
 * and the kit replaced without being shown here, so the operator signs in natively and makes a new kit there.
 */
export const OPERATOR_KIT_RESET_NOT_ON_WEB =
  "Your master password was changed. The operator account can't be used in a browser, so your new recovery kit wasn't shown here. Sign in with the new master password in the andvari desktop app or andvari-cli, and make a new recovery kit there straight away.";
/**
 * PLACEHOLDER: a kit recovery the server STORED (it answered the commit with success) and whose answer this browser then
 * refused (another account's id, keys other than the ones sent, keys that do not open as this account, or an answer it
 * could not read). Shown above the new kit, which is shown before anything is wiped, and again once the kit was saved.
 * The old kit no longer works; the new password and the new kit do.
 */
export const KIT_RECOVERY_STORED_UNCHECKED =
  "The server stored your recovery, then gave an answer this browser couldn't check, so andvari didn't open your vault here. Your new master password is set and your old recovery kit no longer works: keep this new kit. Don't enter your master password on this page again until the person who runs this server tells you what happened.";
/** PLACEHOLDER: the same, at a registration the server stored: the account exists, with the kit shown before anything is wiped. */
export const SIGNUP_STORED_UNCHECKED =
  "The server created your account, then gave an answer this browser couldn't check, so andvari didn't open it here. Your account exists with this email and master password: keep this recovery kit with them. Don't enter your master password on this page again until the person who runs this server tells you what happened.";
/**
 * PLACEHOLDER: a kit recovery's commit that got NO answer: whether the server stored it cannot be told. Shown above the new
 * kit (which works only if it was stored) and alone once the kit was saved. Must say: no answer came; keep both kits (this
 * new one and the old one); try the new master password first; if it is refused, nothing was changed and the old kit and
 * the old master password are as before.
 */
export const KIT_RECOVERY_UNKNOWN =
  "The server didn't answer, so andvari can't tell whether your new master password was set. Keep both recovery kits: this new one and your old one. Sign in with the new master password first: if that works, the new kit is the one that works, and andvari asks you to make another. If it's refused, nothing was changed: your old master password and your old recovery kit work as before.";
/** PLACEHOLDER: the same, when the answer was an error (a 5xx, from the server or something in front of it). Same content otherwise. */
export const KIT_RECOVERY_UNKNOWN_SERVER_ERROR =
  "The server answered with an error, so andvari can't tell whether your new master password was set. Keep both recovery kits: this new one and your old one. Sign in with the new master password first: if that works, the new kit is the one that works, and andvari asks you to make another. If it's refused, nothing was changed: your old master password and your old recovery kit work as before.";
/**
 * PLACEHOLDER: the same, when an answer came that this browser could not take as the server's (a page from something between
 * the browser and the server, a redirect, or an answer it set aside because its record of the server changed). Same content otherwise.
 */
export const KIT_RECOVERY_UNKNOWN_UNREADABLE =
  "An answer came back, but this browser couldn't take it as the server's, so andvari can't tell whether your new master password was set. Keep both recovery kits: this new one and your old one. Sign in with the new master password first: if that works, the new kit is the one that works, and andvari asks you to make another. If it's refused, nothing was changed: your old master password and your old recovery kit work as before.";
/**
 * PLACEHOLDER: a registration that got NO answer: whether the account was made cannot be told. Shown above the account's kit
 * and alone once it was saved. Must say: no answer came; keep this kit; try to sign in with this email and master password,
 * and if there is no such account, nothing was made.
 */
export const SIGNUP_UNKNOWN =
  "The server didn't answer, so andvari can't tell whether your account was created. Keep this recovery kit with your email and master password, and sign in with them: if there's no such account, nothing was made, and you can start again with a new code.";
/** PLACEHOLDER: the same, when the answer was an error (a 5xx, from the server or something in front of it). */
export const SIGNUP_UNKNOWN_SERVER_ERROR =
  "The server answered with an error, so andvari can't tell whether your account was created. Keep this recovery kit with your email and master password, and sign in with them: if there's no such account, nothing was made, and you can start again with a new code.";
/** PLACEHOLDER: the same, when an answer came that this browser could not take as the server's. */
export const SIGNUP_UNKNOWN_UNREADABLE =
  "An answer came back, but this browser couldn't take it as the server's, so andvari can't tell whether your account was created. Keep this recovery kit with your email and master password, and sign in with them: if there's no such account, nothing was made, and you can start again with a new code.";
/**
 * PLACEHOLDER: a kit recovery whose commit this browser stopped before sending it (its record of this server was forgotten
 * or found forked meanwhile, in this tab or another). Must say: nothing was sent and nothing changed; the old master
 * password and the old recovery kit work as before; and the way on: load the page again (this browser has set the server
 * aside, so trying again in the same form would send nothing again).
 */
export const KIT_RECOVERY_NOT_SENT =
  "This browser stopped before sending your new master password, because its record of this server changed meanwhile (in this tab or another). Nothing was sent and nothing changed: your old master password and your old recovery kit work as before. To go on, load this page again: trying again here would send nothing.";
/** PLACEHOLDER: the same, at a registration: nothing was sent, so no account was made; load the page again to go on. */
export const SIGNUP_NOT_SENT =
  "This browser stopped before sending your registration, because its record of this server changed meanwhile (in this tab or another). Nothing was sent, so no account was made. To go on, load this page again: trying again here would send nothing.";
/**
 * PLACEHOLDER: the idle limit's warning on a screen that shows a recovery kit (as the vault's lock warns before it acts):
 * the kit leaves the screen soon unless the person does something on the page. Must name only what resets the limit
 * (useAutoLock counts a click, a tap or a key: moving the pointer does not).
 */
export const KIT_IDLE_WARNING = "This recovery kit leaves the screen in 30 seconds unless you click, tap, or press a key.";
/**
 * PLACEHOLDER: what stays after the idle limit took the new kit off the screen, after a kit recovery the server stored and
 * whose answer this browser refused. Must say: the kit was taken off the screen; the new master password is set; the
 * next sign-in with it offers a new kit (after the server's operator has said what happened).
 */
export const KIT_RECOVERY_STORED_KIT_GONE =
  "The new recovery kit was taken off the screen after 5 minutes without activity, so it was not saved. Your new master password is set and your old kit no longer works. When the person who runs this server has told you what happened, sign in with your new master password: andvari then asks you to make a new kit.";
/** PLACEHOLDER: the same after a kit recovery whose outcome cannot be told: try the new password; its sign-in offers a new kit. */
export const KIT_RECOVERY_UNKNOWN_KIT_GONE =
  "The new recovery kit was taken off the screen after 5 minutes without activity, so it was not saved. Sign in with the new master password first: if that works, andvari asks you to make a new kit. If it's refused, nothing was changed: your old master password and your old recovery kit work as before.";
/** PLACEHOLDER: the same after a registration the server stored: the account exists; its next sign-in offers a new kit. */
export const SIGNUP_STORED_KIT_GONE =
  "The recovery kit was taken off the screen after 5 minutes without activity, so it was not saved. Your account exists with this email and master password. When the person who runs this server has told you what happened, sign in: andvari then asks you to make a new kit.";
/** PLACEHOLDER: the same after a registration whose outcome cannot be told: a sign-in says whether the account exists. */
export const SIGNUP_UNKNOWN_KIT_GONE =
  "The recovery kit was taken off the screen after 5 minutes without activity, so it was not saved. Try to sign in with this email and master password: if the account exists, andvari asks you to make a new kit. If there's no such account, nothing was made.";

/**
 * PLACEHOLDER (decided on 2026-11-17): said once, after a server's policy that forbids the offline copy made this browser
 * remove its copy, when every change that waited in it was sent first. {0}: the server's name. Must say: the copy was
 * removed because this server asks for it; nothing was lost.
 */
export const POLICY_WIPE_NOTHING_LOST =
  "This browser removed its offline copy of your vault, because {0} asks browsers not to keep one. Every change waiting in it was sent first: nothing was lost.";
/**
 * PLACEHOLDER: the same, when one change could not be sent before the copy was removed. {0}: the server's name. Must not
 * say that a send was tried: with no session there was nothing to try with.
 */
export const POLICY_WIPE_UNSENT_ONE =
  "This browser removed its offline copy of your vault, because {0} asks browsers not to keep one. 1 change waiting in it could not be sent first, and it is lost.";
/** PLACEHOLDER: the same, for several. {0}: the server's name; {1}: how many changes could not be sent. */
export const POLICY_WIPE_UNSENT_MANY =
  "This browser removed its offline copy of your vault, because {0} asks browsers not to keep one. {1} changes waiting in it could not be sent first, and they are lost.";
/** PLACEHOLDER: the same, when this browser could not read how many changes waited. {0}: the server's name. */
export const POLICY_WIPE_UNSENT_UNKNOWN =
  "This browser removed its offline copy of your vault, because {0} asks browsers not to keep one. It could not read the copy first, so it cannot tell whether changes made here were lost.";
/**
 * PLACEHOLDER (decided on 2026-11-17): the notice's opening when no change was lost and some may or may not have arrived
 * (followed by the sentence below). {0}: the server's name. Must say: the copy was removed because this server asks for
 * it; the browser tried once to send what waited in it first. Must not say that nothing was lost.
 */
export const POLICY_WIPE_TRIED =
  "This browser removed its offline copy of your vault, because {0} asks browsers not to keep one. It tried once to send the changes waiting in it first.";
/**
 * PLACEHOLDER (decided on 2026-11-17): a sentence of its own after the notice, for one change whose request went out and
 * whose answer did not come in time. {0}: the server's name. Must say: it may or may not have arrived at the server;
 * how to find out (look for it there, from this or another device).
 */
export const POLICY_WIPE_UNSURE_ONE =
  "1 change was sent but no answer came in time: it may or may not have reached {0}. Look for it in your vault.";
/** PLACEHOLDER: the same, for several. {0}: the server's name; {1}: how many. */
export const POLICY_WIPE_UNSURE_MANY =
  "{1} changes were sent but no answer came in time: they may or may not have reached {0}. Look for them in your vault.";

/**
 * The notice for a copy a server's policy removed (vault/policywipe.ts): the lost changes and those that may or may not
 * have arrived, each number with a sentence of its own. "Cannot tell" when the copy could not be read.
 */
export function policyWipeText(n: { server: string; unsent: number | null; unsure: number }): string {
  if (n.unsent === null) return fill(POLICY_WIPE_UNSENT_UNKNOWN, n.server);
  const unsure = n.unsure === 0 ? null : n.unsure === 1 ? fill(POLICY_WIPE_UNSURE_ONE, n.server) : fill(POLICY_WIPE_UNSURE_MANY, n.server, String(n.unsure));
  const lead =
    n.unsent === 0
      ? unsure === null
        ? fill(POLICY_WIPE_NOTHING_LOST, n.server)
        : fill(POLICY_WIPE_TRIED, n.server)
      : n.unsent === 1
        ? fill(POLICY_WIPE_UNSENT_ONE, n.server)
        : fill(POLICY_WIPE_UNSENT_MANY, n.server, String(n.unsent));
  return unsure === null ? lead : `${lead} ${unsure}`;
}

/**
 * PLACEHOLDER (decided on 2026-11-17): a change refused because the server's policy is removing this browser's offline
 * copy at that moment. Must say: the change was not made, because this server asks browsers not to keep an offline copy
 * and this browser is removing it now; make the change again in a moment.
 */
export const SAVE_COPY_BEING_REMOVED =
  "This change wasn't made: this server asks browsers not to keep an offline copy, and this browser is removing its copy now. Make the change again in a moment.";

/**
 * PLACEHOLDER (decided on 2026-11-17): a change refused because the server's policy is removing this browser's offline
 * copy and the removal is held up: another tab of andvari in this browser keeps the copy open. Must say: the change was
 * not made; this browser can't finish removing its offline copy while andvari is open in another tab; close andvari's
 * other tabs in this browser, then make the change again.
 */
export const SAVE_COPY_REMOVAL_BLOCKED =
  "This change wasn't made: this browser can't finish removing its offline copy while andvari is open in another tab. Close andvari's other tabs in this browser, then make the change again.";

/**
 * PLACEHOLDER (decided on 2026-11-17): an answer whose size grows with the vault or a file (a sync, a file's upload or
 * download, an import) was ended because nothing came from the server for 30 seconds. Must say: the server stopped
 * answering in the middle; what it was doing may or may not have been done; try again (it is not the person's password).
 */
export const ANSWER_STALLED =
  "The server stopped answering: nothing came from it for 30 seconds, so andvari stopped waiting. What was under way may or may not have been done. Try again in a moment.";
/**
 * PLACEHOLDER (decided on 2026-11-17): an answer that is small by its nature took longer than its limit of one minute.
 * Must say: this took too long, so andvari stopped waiting; it may or may not have been done; try again.
 */
export const ANSWER_TOO_LONG =
  "This took too long: the server had not answered after a minute, so andvari stopped waiting. It may or may not have been done. Try again in a moment.";

// ---- The recovery choice on a private (family) instance: design §7.7's exact copy, normative ----

export const RECOVERY_QUESTION = "How should this account be recovered if you forget your master password?";
export const RECOVERY_ONLY_ME = "Only me";
export const RECOVERY_FAMILY_OPTION = "Me, or the person who runs {instance name}";
export const RECOVERY_FAMILY_OPTION_DETAIL = "They can restore your account if you forget your master password.";
export const RECOVERY_FAMILY_CONFIRM_TITLE = "Let the person who runs {instance name} ({origin}) restore your account?";
export const RECOVERY_FAMILY_CONFIRM_BODY =
  "With this on, they keep a key that can restore your account. Restoring it means they could open your vault, every password, note and card in it, and act as you. Anyone who gets into your email can ask them to reset your account; a request waits 7 days, and your signed-in devices can cancel it. Choose this only if you trust the person who runs this server with your passwords. You will still get your own recovery kit.";
export const RECOVERY_FAMILY_UNDERSTAND = "I understand that the person who runs this server could open my vault and act as me.";
/** §4.5's unsigned-change warning (T2-R-f). `{name}` and `{origin}` are the pinned card's, as plain text. */
export const RECOVERY_UNSIGNED_TITLE = "The recovery key for {name} ({origin}) changed without the old key's signature.";
export const RECOVERY_UNSIGNED_BODY =
  "This can mean the operator lost the old key. It can also mean someone has taken over this server's identity. Keep operator recovery only if the operator has told you why it changed.";
export const RECOVERY_KEEP_NEW_KEY = "Keep it with the new key";

/** Approved wording (decided on 2026-11-17): the operator-recovery choice at sign-up was refused before anything was sent (stale offer, box not ticked). */
export const RECOVERY_CHOICE_REFUSED = "andvari couldn't use your recovery choice, so nothing was sent. Check your choice and try again.";

// ---- The account's own devices (design §8.6) ----

/** Approved wording (decided on 2026-11-17): the devices card's heading. */
export const DEVICES_TITLE = "Your devices";
/** Approved wording (decided on 2026-11-17): */
export const DEVICES_CURRENT = "This browser";
/** Approved wording (decided on 2026-11-17): */
export const DEVICES_REVOKE = "Sign this device out";
/** PLACEHOLDER: {0} is the device's name as plain text (filled with the common `fill`, as the wording page's line has it). */
export const DEVICES_REVOKE_CONFIRM = "Enter your master password to remove “{0}”. It will have to sign in again, and it will count as a new device.";
/** Approved wording (decided on 2026-11-17): */
export const DEVICES_REVOKED = "The device was signed out.";
/** PLACEHOLDER: the mark on a device that was removed (no longer live); it stays listed. */
export const DEVICES_REMOVED_TAG = "Removed";
/** PLACEHOLDER: §4.4 "The cost is stated on the Devices screen": a revoke stops syncing and wipes nothing. */
export const DEVICES_REVOKE_KEEPS_COPY = "Removing a device stops it syncing. It doesn't erase it: any copy of your vault on it stays encrypted under your master password.";
/** PLACEHOLDER: how each device joined (§8.6 `how`), in place of the raw wire value. */
export const DEVICES_HOW: Record<string, string> = {
  registered: "Created the account",
  password: "Signed in with the master password",
  linked: "Linked from another device",
  recovered: "Signed in by a recovery",
};
/** PLACEHOLDER: a `how` this version does not know. */
export const DEVICES_HOW_OTHER = "Joined another way";
/** PLACEHOLDER: the platform of each device (§8.6 `platform`), in place of the raw wire value. */
export const DEVICES_PLATFORM: Record<string, string> = {
  web: "Browser",
  android: "Android",
  ios: "iPhone or iPad",
  windows: "Windows",
  macos: "Mac",
  linux: "Linux",
  cli: "Command line",
  extension: "Browser extension",
};
/** Approved wording (decided on 2026-11-17): a platform this version does not know. */
export const DEVICES_PLATFORM_OTHER = "Another kind of device";
/** Approved wording (decided on 2026-11-17): {0} the date and time the device was last seen. */
export const DEVICES_LAST_SEEN = "Last seen {0}";
/** Approved wording (decided on 2026-11-17): */
export const DEVICES_WRONG_PASSWORD = "That master password isn't right. Nothing was changed.";
/** Approved wording (decided on 2026-11-17): no clear answer to the revoke. */
export const DEVICES_UNKNOWN = "andvari couldn't tell whether the device was signed out. Check the list again in a moment.";
/** Approved wording (decided on 2026-11-17): */
export const DEVICES_UNAVAILABLE = "Your devices couldn't be loaded or changed right now. Nothing changed.";
/** PLACEHOLDER: after a revoke the server confirmed, the list could not be loaded again (the device WAS signed out). */
export const DEVICES_RELOAD_FAILED = "The list couldn't be loaded again just now.";

// ---- Shared vaults and contacts on this browser (design §3.6, §6.9, §8.5) ----

/** §8.5, the design's words: the one-tap list of a device that signed in with only the password, shown once. */
export const ONE_TAP_TITLE = "People you've connected with";
/**
 * §8.5, the design's words, without its braced clause ", or the operator, because you chose operator recovery", which
 * belongs only to an account whose recovery record says `operator`: the one-tap list does not read the recovery record
 * on the web yet, so that clause is still to be wired.
 */
export const ONE_TAP_BODY =
  "You signed in without linking from another device, so andvari can't yet tell whether this list is current. The server keeps it sealed under your account's key. On its own, the server can hide people or bring back someone you removed, but it can't add anyone. Whoever holds your account's key could: a page from a dishonest server while you used andvari on the web. Untick anyone you don't recognise.";
export const ONE_TAP_CONFIRM = "Use these on this device";
export const ONE_TAP_LATER = "Later";
/** PLACEHOLDER: a contact made on another device, waiting for one tap here. `{name}` is plain text. §6.9 words it
 *  "New person from your *iPhone*: *label* — Use on this device?", which needs the device that made the contact: the
 *  web does not resolve `madeOn` to a device name yet, so this line is still open. */
export const CONTACT_PROMPT = "{name} was added as a contact on another of your devices. Is this someone you know?";
/** The owner's approved button (copy entry 18, PERSON_FROM_OTHER_DEVICE_HINT's first button). */
export const CONTACT_PROMPT_YES = "Use on this device";
/** §3.6, the design's words: the acceptance prompt of a shared vault. `{name}` and `{vault}` are plain text. */
export const SHARE_ASK = "{name} wants to share “{vault}” with you.";
/**
 * PLACEHOLDER: under the acceptance prompt of a vault the person was removed from and added to again, when changes they
 * made before the removal wait on this browser (kept with the vault's sealed copy). Must say how many, and that accepting
 * sends them to the vault. `{0}`: the number; `{1}`: the vault's name, plain text.
 */
export const SHARE_ASK_WAITING = "⟦{0} changes you made in “{1}” before you were removed wait on this browser. If you accept, they are sent to the vault.⟧";
/** PLACEHOLDER: {@link SHARE_ASK_WAITING} for one change. `{0}`: the vault's name, plain text. */
export const SHARE_ASK_WAITING_ONE = "⟦1 change you made in “{0}” before you were removed waits on this browser. If you accept, it is sent to the vault.⟧";
export const SHARE_ACCEPT = "Accept";
export const SHARE_DECLINE = "Decline";
/** Approved wording (decided on 2026-11-17): an answer the account state could not record: nothing changed. */
export const SHARE_NOT_RECORDED = "Your answer wasn't saved. Nothing changed. Try again.";
/**
 * PLACEHOLDER: an answer to an incoming share whose write to the account state got no answer, an answer cut off, a 5xx
 * or an answer that is not the server's: it may be saved, and then the vault is adopted at the next sync. Must say what
 * to do: if the vault doesn't appear, answer again.
 */
export const SHARE_ANSWER_UNKNOWN = "andvari can't tell whether your answer was saved. If it was, the vault appears after the next sync; if it doesn't, answer again.";
/**
 * PLACEHOLDER: the person declined a shared vault; the decline is saved on their account, but the message that tells
 * the owner (it also takes back their access) got no answer from the server, and is sent again the next time they
 * unlock. Must say: you declined it; the owner may still see you as invited until it goes through; nothing to do.
 */
export const SHARE_DECLINE_WAITING = "You declined it. The owner may still see you as invited until andvari can tell the server, which it tries again the next time you unlock.";
/**
 * PLACEHOLDER: the person declined a shared vault; the decline is saved on their account, but the server did not take
 * the message that tells the owner; andvari signs it again at a later unlock while the vault still lists them through
 * that invitation. Must say: you declined it; the owner may still see the invitation until it goes through; nothing to
 * do. Must say nothing more (no "try again", no "ask them to remove you": the share is no longer offered here).
 */
export const SHARE_DECLINE_NOT_STORED = "⟦You declined it; the owner may still see the invitation until it goes through⟧";
/**
 * PLACEHOLDER: as SHARE_DECLINE_NOT_STORED, on a shared vault frozen on this browser (the server's record of it
 * contradicts itself), where no answer told whether the server got the decline (no answer, an answer cut off), and andvari
 * never sends it again. Must say: you declined it here; andvari can't tell whether the server got the answer and will not
 * send it again, so the owner may still see you as invited. Never "until it goes through", never that it is tried again.
 */
export const SHARE_DECLINE_FROZEN_UNKNOWN = "⟦You declined it here. andvari can't tell whether the server got your answer and won't send it again, so the owner may still see you as invited.⟧";
/**
 * PLACEHOLDER: the notice when this browser learns that the person no longer has access to a shared vault frozen on this
 * browser (the server's record of it contradicts itself), after the person left that vault on this browser. {0} the
 * vault's name. Must say: you left this vault on this browser; for this vault, this browser can't check whether anything
 * else happened since; a sealed copy of the vault's data, as the server served it when this was learned, is kept on this
 * device for 30 days, and where to find it (as the notice of an unexpected removal says). Nothing more.
 */
export const VAULT_LEFT_FROZEN_NOTICE = "⟦You left “{0}” on this browser. For this vault, this browser can't check whether anything else happened since. A sealed copy of its data, as the server served it when this was learned, is kept on this device for 30 days (Sharing → the trash icon).⟧";
/**
 * PLACEHOLDER: the notice when this browser, holding nothing of it (the first sync after a sign-in, a reload with no
 * offline copy), learns that the server no longer gives this account a shared vault that was frozen on this browser (what
 * the server served of it did not match what this browser or this account had recorded of it, so this browser could not
 * check what happened to it), or that the person had left on this browser. No name: this browser does not know the vault's name. Must say: the server no longer gives
 * you a shared vault that this browser could not check; this browser does not know its name; nothing of it is kept on
 * this device. Nothing more (no "tell your admin": it may be the person's own leave).
 */
export const VAULT_GONE_UNCHECKED_NOTICE = "⟦The server no longer gives you a shared vault that this browser couldn't check. This browser doesn't know its name, and no copy of it is kept on this device.⟧";
/**
 * PLACEHOLDER: the notice when this browser synced again from the start (the server told it to) and the full list the
 * server sent neither held in the personal vault nor marked as deleted items this browser held of it (an item the list
 * served only under another vault counts too). {0} how many ("1 item", "3 items"). What the browser knows: the list did
 * not hold them in that vault and did not say they were deleted; it cannot tell why (another device may have deleted
 * them long ago, or the server may be misbehaving). Must say: {0} from your personal vault were not in the server's list
 * for that vault and the server did not say they were deleted; this browser can't tell why; a sealed copy of them is
 * kept on this device for 30 days, and where to find it (as the notice of an unexpected removal says); if the server
 * sends them again unchanged they go back on their own. Never that they were deleted.
 */
export const ITEMS_SET_ASIDE_PERSONAL_NOTICE = "⟦{0} from your personal vault weren't in the list the server sent for it, and the server didn't say they were deleted. This browser can't tell why. A sealed copy of them is kept on this device for 30 days (Sharing → the trash icon); if the server sends them again unchanged, they go back on their own.⟧";
/**
 * PLACEHOLDER: as ITEMS_SET_ASIDE_PERSONAL_NOTICE, for items of a shared vault this browser still lists and that is not
 * frozen here, whatever this browser could read of the vault's history at that moment (checked, or not checkable just
 * then). {0} how many ("1 item", "3 items"), {1} the vault's name. What the browser knows: the list did not hold the
 * items in that vault (an item it served only under another vault counts too) and did not say they were deleted;
 * nothing about why, nor about whether the person still has access. Must say: {0} from “{1}” were not in the server's
 * list for that vault and the server did not say they were deleted; this browser can't tell why; a sealed copy is kept
 * on this device for 30 days, and where; they go back on their own if the server sends them again unchanged.
 */
export const ITEMS_SET_ASIDE_SHARED_NOTICE = "⟦{0} from “{1}” weren't in the list the server sent for that vault, and the server didn't say they were deleted. This browser can't tell why. A sealed copy of them is kept on this device for 30 days (Sharing → the trash icon); if the server sends them again unchanged, they go back on their own.⟧";
/**
 * PLACEHOLDER: as ITEMS_SET_ASIDE_SHARED_NOTICE, for a shared vault frozen on this browser (what the server served of
 * it did not match what this browser or this account had recorded, so this browser cannot check its history). {0} how
 * many, {1} the vault's name. What the browser knows less of: it cannot tell whether the person still has access to the
 * vault, nor whether the items were deleted. Must say what ITEMS_SET_ASIDE_SHARED_NOTICE says (also that they go back
 * on their own if the server sends them again unchanged), and that for this vault this browser can't check its
 * history, so it can't tell whether you still have access to it.
 */
export const ITEMS_SET_ASIDE_FROZEN_NOTICE = "⟦{0} from “{1}” weren't in the list the server sent for that vault, and the server didn't say they were deleted. For this vault, this browser can't check its history, so it can't tell why, or whether you still have access to it. A sealed copy of them is kept on this device for 30 days (Sharing → the trash icon); if the server sends them again unchanged, they go back on their own.⟧";
/**
 * PLACEHOLDER: the notice when items set aside (see ITEMS_SET_ASIDE_PERSONAL_NOTICE) were sent again by the server, in
 * their own vault, with other content than the copy kept on this device. Told once per item. {0} how many ("1 item",
 * "3 items"), {1} the vault: ITEMS_SET_ASIDE_PERSONAL_NAME for the personal vault, else the vault's name. What the
 * browser knows: only that the server sent these items again with other content than the copy kept here; not which is
 * newer, nor why. The item as the server sent it is in the vault; the copy kept here stays set aside. Must say: the
 * server sent {0} of {1} again with other content than the copy kept on this device; the copy kept here stays set
 * aside, and where to find it. Never which one is right or newer.
 */
export const ITEMS_SET_ASIDE_OTHER_NOTICE = "⟦The server sent {0} of {1} again, with other content than the copy kept on this device. That copy stays set aside (Sharing → the trash icon).⟧";
/** PLACEHOLDER: the heading of the list of items set aside, beside "Recently removed" (Sharing → the trash icon). */
export const ITEMS_SET_ASIDE_TITLE = "⟦Items set aside⟧";
/**
 * PLACEHOLDER: the line under ITEMS_SET_ASIDE_TITLE. Must say: items this browser held that the server's list left out
 * of their vault without saying they were deleted; a sealed copy is kept on this device for 30 days; an item the server
 * sends again unchanged goes back to its vault on its own (one sent again with other content stays here). Nothing about
 * why (the browser does not know).
 */
export const ITEMS_SET_ASIDE_INTRO = "⟦Items this browser held that the server's list left out of their vault without saying they were deleted. A sealed copy is kept on this device for 30 days; an item the server sends again unchanged goes back to its vault on its own.⟧";
/** PLACEHOLDER: one vault's row in that list. {0} how many ("1 item", "3 items"), {1} the day the copy leaves this device. */
export const ITEMS_SET_ASIDE_LINE = "⟦{0} · kept until {1}⟧";
/** PLACEHOLDER: the name shown for the personal vault in that list. */
export const ITEMS_SET_ASIDE_PERSONAL_NAME = "⟦Your personal vault⟧";
/** PLACEHOLDER: the button that copies a vault's items set aside into the personal vault, each as a new item. */
export const ITEMS_SET_ASIDE_COPY = "⟦Copy them to your personal vault⟧";
/**
 * PLACEHOLDER: the confirmation before "Remove from this device" on items set aside. {0} the vault's name (or
 * ITEMS_SET_ASIDE_PERSONAL_NAME). Must say: this browser's copy of the items set aside from {0} goes; nothing is sent.
 */
export const ITEMS_SET_ASIDE_REMOVE_CONFIRM = "⟦Remove this browser's copy of the items set aside from “{0}”? Nothing is sent to the server.⟧";
/**
 * PLACEHOLDER: as SHARE_DECLINE_FROZEN_UNKNOWN, where the server refused the decline (or it was never sent), so this
 * browser knows it was not stored; andvari never sends it again. Must say: you declined it here; the server did not take
 * your answer and andvari won't send it again, so the owner may still see you as invited. Never "can't tell", never that
 * it is tried again.
 */
export const SHARE_DECLINE_FROZEN_REFUSED = "⟦You declined it here, but the server refused your answer and andvari won't send it again, so the owner may still see you as invited.⟧";
/**
 * PLACEHOLDER: as SHARE_DECLINE_FROZEN_UNKNOWN, where the server answered naming the decline as stored. This browser can
 * no longer read the vault's history, so it cannot see the decline there itself. Must say: you declined it; the server
 * says it took your answer; this browser can no longer check this vault's history. Never "can't tell".
 */
export const SHARE_DECLINE_FROZEN_STORED = "⟦You declined it. The server says it took your answer; this browser can no longer check this vault's history.⟧";
/**
 * PLACEHOLDER: a vault's new name whose outcome cannot be told (no answer, an answer cut off, a 5xx, an answer that is
 * not the server's). Must say: it may be stored; look at the vault's name after the next sync before renaming again.
 */
export const RENAME_UNKNOWN = "andvari can't tell whether the server stored the new name. Look at the vault's name after the next sync before you rename it again.";
/** §3.6, the design's words: a share from someone who is not a current contact here. {0} the sender's name as the
 *  server reports it; [SHARE_CONNECT_FIRST_UNNAMED] when the server gave none. */
export const SHARE_CONNECT_FIRST = "{0} wants to share a vault with you. Connect with them first.";
/** Approved wording (decided on 2026-11-17): the same when the server reported no name for the sender. */
export const SHARE_CONNECT_FIRST_UNNAMED = "Someone wants to share a vault with you. Connect with them first.";
// ---- §3 ownership offer: the owner's approved entry 26 (OWNERSHIP_OFFER), word for word ----
/** {0} the member's label, {1} the vault's name. */
export const OWNERSHIP_OFFER_TITLE = "Make {0} the owner of “{1}”?";
export const OWNERSHIP_OFFER_BODY = "Nothing changes until they accept in their app. They have 14 days, and you can cancel until then. Afterwards they manage the vault's members, and only they can rename it, hand it over or delete it. You stay in it as a writer.";
/** {0} the member's label. */
export const OWNERSHIP_OFFER_ASK = "Ask {0} to take over";
/** The note on the vault while the offer is open: {0} the member's label, {1} the vault's name, {2} the day the offer ends. */
export const OWNERSHIP_OFFER_OPEN = "You asked {0} to take over “{1}”. They can accept until {2}.";

/** Approved wording (decided on 2026-11-17): the Settings card holding §7.7's recovery choice after sign-up. */
export const POSTURE_TITLE = "Who can recover your account";
/** Approved wording (decided on 2026-11-17): the choice was saved (account state, mirror and escrow). */
export const POSTURE_SAVED = "Saved.";
/** Approved wording (decided on 2026-11-17): the offer could not be made now (the card chain did not verify, the key did not match, or no answer). */
export const POSTURE_UNAVAILABLE = "This server's recovery setting can't be checked right now, so it can't be changed here. Nothing changed.";

/**
 * The sign-in back-off's own sentence (Welcome's `rate_limited`, a placeholder there since sign-up), also for every action
 * that asks for the master password again when the server's back-off of password proofs holds (spec 03, 2026-11-16: a
 * back-off of its own, per account; wrong proofs never block a sign-in).
 */
export const SIGNIN_BACKOFF = "Too many tries. Wait a little and try again.";
/**
 * PLACEHOLDER: the sign-in's own back-off (the wording page's FX3), apart from a wait a signed-in session is told. The
 * server answers a sign-in, whose caller has proven nothing, with a fixed 60 seconds, which says nothing about the tries
 * made for the address; so the line says "at least a minute", never "a minute", and never the number.
 */
export const SIGN_IN_WAIT = "Too many tries. Wait at least a minute, then sign in again.";
/**
 * Approved wording (decided on 2026-11-17): sign-up, the display name has a character the server refuses in a name (spec 03 §0.1 `text`), found before
 * anything was sent, said by its kind (crypto/trust/grammar.ts RefusedCharacterKind): a control character. {0} the code
 * point ("U+0009").
 */
export const NAME_BAD_CONTROL = "This name has a control character ({0}), such as a tab or a line break, which andvari can't use in a name. Type it again without it.";
/** Approved wording (decided on 2026-11-17): as above, a line or paragraph separator. {0} the code point. */
export const NAME_BAD_LINE_BREAK = "This name has a line or paragraph separator ({0}), which andvari can't use in a name. Type it again on one line.";
/** Approved wording (decided on 2026-11-17): as above, a mark that changes the direction of the text. {0} the code point. */
export const NAME_BAD_DIRECTION = "This name has an invisible character that changes the direction of the text ({0}), which andvari can't use in a name. Type it again without it.";
/** Approved wording (decided on 2026-11-17): as above, any other invisible character (a zero-width space or joiner, a soft hyphen…). {0} the code point. */
export const NAME_BAD_INVISIBLE = "This name has an invisible character ({0}), such as a zero-width space, which andvari can't use in a name. Type it again without it.";
/** Approved wording (decided on 2026-11-17): as above, a broken character (half of a pair the keyboard or a paste left behind). */
export const NAME_BAD_BROKEN = "This name has a broken character, half of one that didn't paste whole. Type it again.";
/** Approved wording (decided on 2026-11-17): as above, a name longer than 256 characters. */
export const NAME_TOO_LONG = "This name is too long. Use 256 characters or fewer.";
/**
 * Approved wording (decided on 2026-11-17): the account-deletion preview, one line per vault the person already deleted that is still restorable
 * (spec 03 §13, 2026-11-16). {0} its name, {1} the day it could be restored until.
 */
export const DELETE_ALREADY_DELETED = "“{0}”, which you already deleted: it could still be restored until {1}, and it goes for good with your account now.";
/** Approved wording (decided on 2026-11-17): as above, for one whose name this browser could not read. {0} the day. */
export const DELETE_ALREADY_DELETED_UNNAMED = "A vault you already deleted: it could still be restored until {0}, and it goes for good with your account now.";
/** Approved wording (decided on 2026-11-17): no clear answer to a password change: it may have landed. */
export const PASSWORD_CHANGE_UNKNOWN = "andvari couldn't tell whether your master password changed. Next time you sign in, try the new one. If it doesn't work, the old one still does.";
/**
 * Approved wording (decided on 2026-11-17): after a change the server made, when this browser's offline copy could not take the new keys (a failed
 * write is said, never swallowed). The next online unlock writes them.
 */
export const PASSWORD_CHANGED_COPY_STALE = "This browser's offline copy couldn't be updated just now, so until you next unlock andvari online, it may still open with your old master password.";

/** Approved wording (decided on 2026-11-17): the add-member list of a log-governed vault (design §6.9: current contacts only). */
export const LOG_ADD_TITLE = "Add someone you're connected with";
/** Approved wording (decided on 2026-11-17): */
export const LOG_ADD_NONE = "Nobody you're connected with can be added from this browser. Connect with someone in the andvari app first.";

/** Approved wording (decided on 2026-11-17): a sharing action the signed vault log did not take (design §3.7), by outcome. Nothing changed in each. */
export const LOG_NOT_CURRENT_CONTACT = "You can only add someone you've confirmed in this browser. Connect with them in the andvari app first.";
/** Approved wording (decided on 2026-11-17): */
export const LOG_NOT_COMPARED = "You haven't compared codes with this person yet. Compare codes in the andvari app first.";
/** Approved wording (decided on 2026-11-17): */
export const LOG_READ_ONLY = "This vault's history can't be checked in this browser right now, so nothing can be changed in it here. Nothing changed.";
/**
 * PLACEHOLDER: a change to a shared vault ended because the vault froze on this browser after the change was sent and
 * the server answered (its own follow-up read, or the moment the server's word was recorded, found the server's record
 * of the vault contradicting itself; also a waiting deletion the freeze dropped). Must say: the server's record of this
 * vault contradicts itself, and andvari has stopped changing this vault in this browser, for good. Never says whether
 * the change was made, never "nothing changed", never "right now".
 */
export const LOG_FROZEN = "⟦The server's record of this vault contradicts itself, so andvari has stopped changing this vault in this browser, for good.⟧";
/**
 * PLACEHOLDER: a change to a shared vault refused because the vault was frozen on this browser before it (the server's
 * record of the vault contradicts itself); nothing of the change was sent. Must say: the server's record of this vault
 * contradicts itself, andvari has stopped changing this vault in this browser, for good, and this change was not sent.
 * Never "right now".
 */
export const LOG_FROZEN_NOT_SENT = "⟦The server's record of this vault contradicts itself, so andvari has stopped changing this vault in this browser, for good. This change was not sent.⟧";
/**
 * PLACEHOLDER: the person left a shared vault that was frozen on this browser (the server's record of it contradicts
 * itself), and the server answered that it took the leave. Must say: the server says it took the leave, and this browser
 * can no longer check this vault's history. Never "nothing changed", never "right now".
 */
export const LOG_LEAVE_FROZEN_TAKEN = "⟦The server says it took your leave. This browser can no longer check this vault's history.⟧";
/**
 * PLACEHOLDER: as LOG_LEAVE_FROZEN_TAKEN, where the server refused the leave. Must say: the server refused the leave, and
 * andvari has stopped changing this vault in this browser because the server's record of it contradicts itself. Never
 * "right now", never that it is sent again.
 */
export const LOG_LEAVE_FROZEN_REFUSED = "⟦The server refused your leave. The server's record of this vault contradicts itself, so andvari has stopped changing it in this browser.⟧";
/**
 * PLACEHOLDER: as LOG_LEAVE_FROZEN_TAKEN, where no answer told whether the server took the leave (no answer, an answer cut
 * off, a 5xx, or an answer that named no leave). Must say: andvari can't tell whether the server took the leave, and this
 * browser can no longer check this vault's history. Never that it is sent again, never "nothing changed".
 */
export const LOG_LEAVE_FROZEN_UNKNOWN = "⟦andvari can't tell whether the server took your leave. This browser can no longer check this vault's history.⟧";
/** Approved wording (decided on 2026-11-17): */
export const LOG_HEAD_MOVED = "Someone else changed this vault at the same moment. Nothing changed. Try again.";
/** §3.3, the design's words: a vault change refused because this device's clock is ahead of the server's. */
export const LOG_CLOCK_AHEAD ="Your device's clock is ahead. Set the correct time and try again.";
/** Approved wording (decided on 2026-11-17): a change still waiting to reach the server is held; nothing new is signed until it does. */
export const LOG_APPEND_PENDING = "An earlier change to this vault hasn't reached the server yet. Try again once it has.";
/** Approved wording (decided on 2026-11-17): this change was signed but the server never answered: it is held and sent again, and is not shown as made. */
export const LOG_NOT_STORED = "The server didn't confirm this change, so it isn't made yet. andvari sends it again the next time you unlock.";
/** Approved wording (decided on 2026-11-17): any other refusal; {0} is the reason code. */
export const LOG_NOT_TAKEN = "This change wasn't made ({0}). Nothing changed.";
/**
 * PLACEHOLDER: a signed change to a shared vault whose outcome cannot be told (no answer, an answer cut off, a 5xx, an
 * answer that is not the server's). Must say: andvari can't tell whether the server stored it; it is sent again the next
 * time the person unlocks and is never made twice; look at the vault before changing it again. Never "it isn't made".
 */
export const LOG_UNKNOWN =
  "andvari can't tell whether the server stored this change. It sends it again the next time you unlock, and the change is never made twice. Look at this vault before you change it again.";
/**
 * PLACEHOLDER: the same, after ADDING a member: the person may already be a member and hold the vault's key. Must say:
 * look at the member list before trying again.
 */
export const LOG_UNKNOWN_ADD =
  "andvari can't tell whether the server stored this addition, so this person may already be a member and hold this vault's key. Look at the member list before you try again. andvari sends the change again the next time you unlock, and it is never made twice.";
/**
 * PLACEHOLDER: LOG_UNKNOWN_ADD where the vault could not be read from the server again afterwards: the member list on
 * the screen may be old. Must not send the person to a list that may be old as if it were the server's.
 */
export const LOG_UNKNOWN_ADD_UNREAD =
  "andvari can't tell whether the server stored this addition, so this person may already be a member and hold this vault's key. andvari couldn't read the vault from the server just now, so the member list on the screen may be old. andvari sends the change again the next time you unlock, and it is never made twice.";
/** PLACEHOLDER: LOG_UNKNOWN where the vault could not be read from the server again afterwards. */
export const LOG_UNKNOWN_UNREAD =
  "andvari can't tell whether the server stored this change, and couldn't read the vault from the server just now, so what the screen shows of it, its members included, may be old. It sends the change again the next time you unlock, and the change is never made twice.";
/** PLACEHOLDER: the same, after CREATING a shared vault: it may exist; don't make it again before the next unlock. */
export const LOG_UNKNOWN_CREATE =
  "andvari can't tell whether the server made this vault. It sends it again the next time you unlock, and it is never made twice, so don't make it again before then.";
/**
 * PLACEHOLDER: a signed change the server's own complete answer said it stored, which this browser couldn't read back
 * (the follow-up read failed): it is made; it shows once the vault is read again.
 */
export const LOG_STORED_UNREAD =
  "The server stored this change, but this browser couldn't read the vault again just now, so it may not show here yet. It shows once andvari reads the vault again, at the latest the next time you unlock.";
/**
 * PLACEHOLDER: a change this browser stopped before sending it (its record of this server changed meanwhile, in this
 * tab or another). Must say: nothing was sent, nothing changed; the way on is to load the page again.
 */
export const LOG_NOT_SENT =
  "This browser stopped before sending this change, because its record of this server changed meanwhile (in this tab or another). Nothing was sent and nothing changed. To go on, load this page again: trying again here would send nothing.";
/**
 * PLACEHOLDER: the server's answer to a change named no record of it (its head lay beyond the change), and the vault as
 * read from the server right afterwards does not hold the change: it was not made, and nothing of it is kept. Must say:
 * not made; nothing changed; the way on is to make it again.
 */
export const LOG_NOT_MADE =
  "The server answered, but the vault as read from it now doesn't hold this change, so it wasn't made. Nothing changed. Make the change again if you still want it.";

/**
 * PLACEHOLDER (a notice, at the unlock that sent it again): an ADDITION that was kept to be sent again did not happen
 * (the server refused it then, another change took its place, or the vault does not hold it). {0} the person (a
 * contact's label, or {@link RESEND_SOMEONE}), {1} the vault. Must say: not made; they were not given the vault.
 */
export const RESEND_NOT_MADE_ADD = "Adding {0} to “{1}” didn't happen. andvari kept it to send again, and it wasn't made, so {0} wasn't given this vault. Add them again if you still want to.";
/** PLACEHOLDER: the same for a REMOVAL. Must say: not made; the person is still a member and can still open the vault. */
export const RESEND_NOT_MADE_REMOVE = "Removing {0} from “{1}” didn't happen. andvari kept it to send again, and it wasn't made, so {0} is still a member and can still open this vault. Remove them again if you still want to.";
/** PLACEHOLDER: the same for any other change of a shared vault (a role, an ownership offer, a deletion...). {0} the vault. */
export const RESEND_NOT_MADE_CHANGE = "A change to “{0}” that andvari kept to send again didn't happen. Nothing changed. Make it again if you still want it.";
/**
 * PLACEHOLDER: an ADDITION whose outcome could not be told waited a day and was given up (not sent again); whether it
 * was made still cannot be told. {0} the person, {1} the vault.
 */
export const RESEND_GIVEN_UP_ADD = "andvari stopped sending your addition of {0} to “{1}”: a day went by without the server confirming it. It can't tell whether it was made, so {0} may hold this vault's key. Look at the vault's members once andvari has read it again.";
/** PLACEHOLDER: the same for a REMOVAL: the person may still be a member. */
export const RESEND_GIVEN_UP_REMOVE = "andvari stopped sending your removal of {0} from “{1}”: a day went by without the server confirming it. It can't tell whether it was made, so {0} may still be a member. Look at the vault's members once andvari has read it again.";
/** PLACEHOLDER: the person a held change names when this browser has no contact label for them. */
export const RESEND_SOMEONE = "a person who isn't among your contacts here";

/**
 * PLACEHOLDER (the vault's member panel): an addition or removal waits to be sent; the server's own answer said it is
 * not made yet (it asked andvari to slow down). {0} the person. Must say: not made yet; sent again at the next unlock,
 * for a day at most; can be withdrawn until then.
 */
export const RESEND_WAITING_ADD_NOT_STORED = "Adding {0} waits to be sent: the server asked andvari to slow down, and it isn't made yet. andvari sends it again the next time you unlock, for a day at most. You can withdraw it until then.";
export const RESEND_WAITING_REMOVE_NOT_STORED = "Removing {0} waits to be sent: the server asked andvari to slow down, and it isn't made yet, so {0} can still open this vault. andvari sends it again the next time you unlock, for a day at most. You can withdraw it until then.";
/**
 * PLACEHOLDER: an addition or removal whose answer was lost waits to be confirmed. It cannot be withdrawn: it may already
 * be made. {0} the person.
 */
export const RESEND_WAITING_ADD_UNKNOWN = "Adding {0} waits to be confirmed: andvari can't tell whether the server made it, so {0} may already hold this vault's key. andvari sends it again the next time you unlock, for a day at most. You can withdraw it: andvari then won't send it again, but it may already be made, and andvari reads the vault to tell you.";
export const RESEND_WAITING_REMOVE_UNKNOWN = "Removing {0} waits to be confirmed: andvari can't tell whether the server made it, so {0} may still be able to open this vault. Don't save anything into it for {0}'s eyes only. andvari sends it again the next time you unlock, for a day at most. You can withdraw it: andvari then won't send it again, but it may already be made, and andvari reads the vault to tell you.";
/**
 * PLACEHOLDER (the vault's member panel): a change of a member's ROLE, an ownership OFFER (a hand-over) or the vault's
 * DELETION waits to be sent. NOT_STORED: the server's own answer said it is not made yet (it asked andvari to slow
 * down). UNKNOWN: its answer was lost, so it may already be made. {0} the person (role, offer). Must say: sent again at
 * the next unlock, for a day at most; can be withdrawn (and, for UNKNOWN, that it may already be made).
 */
export const RESEND_WAITING_ROLE_NOT_STORED = "Changing {0}'s role waits to be sent: the server asked andvari to slow down, and it isn't made yet. andvari sends it again the next time you unlock, for a day at most. You can withdraw it until then.";
export const RESEND_WAITING_ROLE_UNKNOWN = "Changing {0}'s role waits to be confirmed: andvari can't tell whether the server made it. andvari sends it again the next time you unlock, for a day at most. You can withdraw it: andvari then won't send it again, but it may already be made, and andvari reads the vault to tell you.";
export const RESEND_WAITING_OFFER_NOT_STORED = "Offering ownership of this vault to {0} waits to be sent: the server asked andvari to slow down, and it isn't made yet. andvari sends it again the next time you unlock, for a day at most. You can withdraw it until then.";
export const RESEND_WAITING_OFFER_UNKNOWN = "Offering ownership of this vault to {0} waits to be confirmed: andvari can't tell whether the server made it, so {0} may already be able to accept it. andvari sends it again the next time you unlock, for a day at most. You can withdraw it: andvari then won't send it again, but it may already be made, and andvari reads the vault to tell you.";
/**
 * PLACEHOLDER: the vault's DELETION waits (NOT_STORED, UNKNOWN as above). Unlike the others it is never sent again on its
 * own: at the next unlock andvari asks whether to delete the vault now or keep it, for a day at most. Must say so, and
 * that what is saved in the vault meanwhile goes with it if it is deleted.
 */
export const RESEND_WAITING_DELETE_NOT_STORED = "Deleting this vault waits to be sent: the server asked andvari to slow down, and it isn't deleted yet. andvari doesn't send it again on its own: the next time you unlock, for a day at most, it asks whether to delete the vault now or keep it. Anything you save in it meanwhile goes with it if you delete it. You can withdraw it now.";
export const RESEND_WAITING_DELETE_UNKNOWN = "Deleting this vault waits to be confirmed: andvari can't tell whether the server deleted it. andvari doesn't send it again on its own: the next time you unlock, for a day at most, it asks whether to delete the vault now or keep it. Anything you save in it meanwhile goes with it if it is deleted. You can withdraw it: andvari then won't send it again, but it may already be deleted, and andvari reads the vault to tell you.";
/**
 * PLACEHOLDER (a notice at the unlock, with two buttons): the person's deletion of a vault waits, and is sent again only
 * at their word. {0} the vault. Must say: the deletion of that vault wasn't confirmed; nothing is sent until they
 * choose; deleting it now takes the vault, with what was saved in it since, from every member; keeping it withdraws the
 * deletion. NOW and KEEP are the two buttons.
 */
export const RESEND_DELETE_ASK = "Your deletion of “{0}” isn't confirmed, and andvari won't send it again until you choose. Delete it now, and the vault goes for every member, with anything saved in it since; or keep the vault, and the deletion is withdrawn.";
export const RESEND_DELETE_ASK_NOW = "Delete it now";
export const RESEND_DELETE_ASK_KEEP = "Keep the vault";
/**
 * PLACEHOLDER (the same notice, for a vault this browser cannot name: no offline copy, and the server's list, read since,
 * does not show it). Must say what RESEND_DELETE_ASK says, of "a shared vault you deleted", without a name, and never
 * as a move's new vault.
 */
export const RESEND_DELETE_ASK_UNNAMED = "Your deletion of one of your shared vaults isn't confirmed, and andvari can't show its name here. andvari won't send it again until you choose. Delete it now, and the vault goes for every member, with anything saved in it since; or keep the vault, and the deletion is withdrawn.";
/**
 * PLACEHOLDER (a notice at the unlock): the person's deletion of a vault, whose answer was lost, was found in the vault's
 * log before they were asked about it: it was made. {0} the vault, {1} the last day it can be restored. Must say: the
 * vault was deleted (for every member); it can be restored from the deleted vaults until that day. Must not ask anything.
 */
export const RESEND_DELETE_MADE = "Your deletion of “{0}” went through: the server has it, though its answer didn't reach this browser, and the vault is deleted for every member. You can restore it from your deleted vaults until {1}.";
/**
 * PLACEHOLDER (the line under the question, after "Delete it now"): the deletion's day ran out between the question and
 * the tap, so it was given up and not sent. Must say: it was given up (not sent); to delete the vault, delete it again
 * from its sharing panel. Must not say whether the vault was deleted (its own notice says what is known).
 */
export const RESEND_DELETE_ASK_GIVEN_UP = "A day went by since this deletion was signed, so andvari gave it up and didn't send it. If you still want the vault deleted, delete it again from its sharing panel.";
/** PLACEHOLDER: the same, for a vault this browser cannot name. {0} the last day it can be restored. */
export const RESEND_DELETE_MADE_UNNAMED = "Your deletion of one of your shared vaults went through: the server has it, though its answer didn't reach this browser, and the vault is deleted for every member. You can restore it from your deleted vaults until {0}.";
/**
 * PLACEHOLDER: RESEND_DELETE_MADE where the server did not serve the day until which the vault can be restored (an
 * older server). {0} the vault. Must say: the vault was deleted (for every member); it can be restored from the list of
 * deleted vaults, which shows until when. Must not name a day.
 */
export const RESEND_DELETE_MADE_NO_DAY = "Your deletion of “{0}” went through: the server has it, though its answer didn't reach this browser, and the vault is deleted for every member. You can restore it from your deleted vaults, which show until when.";
/** PLACEHOLDER: the same, for a vault this browser cannot name. No slot. Must not name a day. */
export const RESEND_DELETE_MADE_UNNAMED_NO_DAY = "Your deletion of one of your shared vaults went through: the server has it, though its answer didn't reach this browser, and the vault is deleted for every member. You can restore it from your deleted vaults, which show until when.";
/**
 * PLACEHOLDER (a notice): a change of ROLE, an ownership OFFER or a DELETION whose outcome could not be told waited a day
 * and was given up (not sent again); whether it was made still cannot be told. {0} the person (role, offer), {1} the
 * vault. Must never say that nothing changed. CHANGE: any other kind, {0} the vault.
 */
export const RESEND_GIVEN_UP_ROLE = "andvari stopped sending your change of {0}'s role in “{1}”: a day went by without the server confirming it. It can't tell whether it was made. Look at the vault's members once andvari has read it again.";
export const RESEND_GIVEN_UP_OFFER = "andvari stopped sending your offer of “{1}” to {0}: a day went by without the server confirming it. It can't tell whether it was made, so {0} may be able to accept it. Look at the vault once andvari has read it again.";
export const RESEND_GIVEN_UP_DELETE = "andvari stopped sending your deletion of “{1}”: a day went by without the server confirming it. It can't tell whether the vault was deleted. Look at your vaults once andvari has read them again.";
export const RESEND_GIVEN_UP_CHANGE = "andvari stopped sending a change to “{0}”: a day went by without the server confirming it. It can't tell whether it was made. Look at the vault once andvari has read it again.";
/** PLACEHOLDER: any held change of this vault the server said it stored, not read back yet. */
export const RESEND_WAITING_STORED = "A change to this vault is stored on the server and shows here once andvari reads the vault again.";
/** PLACEHOLDER: any other held change of this vault (a role, an offer, a deletion) that waits to be sent or confirmed. */
export const RESEND_WAITING_OTHER = "A change to this vault waits to be sent or confirmed. andvari sends it again the next time you unlock, and it is never made twice.";
/** PLACEHOLDER: the button that withdraws a waiting addition or removal, and the line after it. */
export const RESEND_WITHDRAW = "Withdraw";
export const RESEND_WITHDRAWN = "Withdrawn. It won't be sent.";
/**
 * PLACEHOLDER: the line after withdrawing a change whose answer was lost. Must say: this browser won't send it again;
 * it may already be made; andvari reads the vault and says what it finds.
 */
export const RESEND_WITHDRAWN_UNKNOWN = "Withdrawn: andvari won't send it again. It may already be made, so andvari reads the vault from the server and tells you what it finds.";
/**
 * PLACEHOLDER (a notice): a change this browser withdrew or gave up without knowing whether it was made is in the
 * vault's log after all. {0} the person (add, remove, role, offer), {1} the vault. Must say: it was made after all, and
 * the way to undo it.
 */
export const RESEND_FOUND_MADE_ADD = "Adding {0} to “{1}” was made after all: the server has it. {0} holds this vault's key and may have opened it. To undo it, remove {0} from the vault's members.";
export const RESEND_FOUND_MADE_REMOVE = "Removing {0} from “{1}” was made after all: the server has it, and {0} is no longer a member. To undo it, add {0} again.";
export const RESEND_FOUND_MADE_ROLE = "Changing {0}'s role in “{1}” was made after all: the server has it. To undo it, change their role back in the vault's members.";
export const RESEND_FOUND_MADE_OFFER = "Offering “{1}” to {0} was made after all: the server has it, and {0} can accept it. To undo it, cancel the offer in the vault's sharing panel.";
export const RESEND_FOUND_MADE_DELETE = "Deleting “{1}” was made after all: the server has it, and the vault is deleted. To undo it, restore it from your deleted vaults before its time runs out.";
/**
 * PLACEHOLDER (a notice): the deletion of the new vault an earlier, stopped move made, which this browser signed and
 * then dropped unsent (the vault held more than that move's copies) or gave up while its answer was lost, is in the
 * vault's log after all: the vault is deleted. {0} the vault's name, {1} when the deletion was signed, {2} the last day
 * it can be restored. Must say: it was deleted after all, by a deletion signed then; it can be restored until that
 * day. Must not say the person withdrew it.
 */
export const RESEND_FOUND_MADE_HALF_MADE_DELETE = "“{0}”, the new vault an earlier, stopped move made, was deleted after all, by a deletion this browser signed on {1}. You can restore it from your deleted vaults until {2}.";
/**
 * PLACEHOLDER: RESEND_FOUND_MADE_HALF_MADE_DELETE where the server did not serve the day until which the vault can be
 * restored. {0} the vault's name (or MOVE_UNNAMED_VAULT), {1} when the deletion was signed. Must point to the list of
 * deleted vaults; must not name a day.
 */
export const RESEND_FOUND_MADE_HALF_MADE_DELETE_NO_DAY = "“{0}”, the new vault an earlier, stopped move made, was deleted after all, by a deletion this browser signed on {1}. You can restore it from your deleted vaults, which show until when.";
/** PLACEHOLDER: the same for any other kind of change. {0} the vault. */
export const RESEND_FOUND_MADE_CHANGE = "A change to “{0}” that you withdrew was made after all: the server has it. Look at the vault to see it.";
/**
 * PLACEHOLDER (a notice): a change withdrawn while its outcome could not be told; the vault, read from the server since,
 * does not hold it. {0} the vault. Must say: not made (as read now), and that andvari says so if it turns up later.
 */
export const RESEND_FOUND_NOT_MADE = "The change to “{0}” that you withdrew wasn't made: the vault as read from the server doesn't hold it. If the server takes it later after all, andvari tells you.";
/**
 * PLACEHOLDER: a new change refused before signing because an EARLIER change of this vault is held and not confirmed
 * (it may or may not be stored). Replaces LOG_APPEND_PENDING's "hasn't reached the server", which can be untrue.
 */
export const LOG_APPEND_UNCONFIRMED = "An earlier change to this vault isn't confirmed yet. andvari sends it again the next time you unlock; try again after that.";
/** PLACEHOLDER: the same, when the server's own answer said the earlier change is stored and this browser can't read it back yet. */
export const LOG_APPEND_UNREAD = "An earlier change to this vault is stored, but this browser couldn't read the vault back yet. Try again in a moment.";

/** §4.5, the own-mirror prompt at unlock (the design's words). {0} name, {1} origin. */
export const ESCROW_KEEP_QUESTION = "Your account lets the operator of {0} ({1}) restore it. Keep that?";
export const ESCROW_NOT_NOW = "Not now";
export const ESCROW_KEEP = "Keep operator recovery";
export const ESCROW_TURN_OFF = "Turn it off";
/** §4.5, the unsigned-change warning (T2-R-f; the design's words). {0} name, {1} origin. */
export const ESCROW_UNSIGNED_TITLE = "The recovery key for {0} ({1}) changed without the old key's signature.";
export const ESCROW_UNSIGNED_BODY = "This can mean the operator lost the old key. It can also mean someone has taken over this server's identity. Keep operator recovery only if the operator has told you why it changed.";
export const ESCROW_UNSIGNED_OFF = "Turn off operator recovery";
export const ESCROW_UNSIGNED_KEEP = "Keep it with the new key";
export const ESCROW_LATER = "Later";
/** Approved wording (decided on 2026-11-17): the answer to either prompt was saved. */
export const ESCROW_SAVED = "Saved.";

/** Approved wording (decided on 2026-11-17): the Settings card that rotates the kit (spec 03 §12; §10 names the action, not the card). */
export const KIT_ROTATE_TITLE = "Recovery kit";
/** Approved wording (decided on 2026-11-17): what rotating does. */
export const KIT_ROTATE_BODY = "Make a new recovery kit if yours is lost or someone else may have seen it. Your current kit stops working as soon as the new one is made.";
/** Approved wording (decided on 2026-11-17): the master password typed to make a new kit is wrong (nothing was rotated). */
export const KIT_ROTATE_WRONG_PASSWORD = "That master password isn't right. Nothing was changed.";
/** Approved wording (decided on 2026-11-17): the session ended before the new kit was made (nothing was rotated). */
export const KIT_ROTATE_SESSION_ENDED = "You were signed out before the new kit was made. Sign in again, then make a new kit. Your current kit still works.";
/** Approved wording (decided on 2026-11-17): the rotation's outcome is not known (no answer, or a 5xx). */
export const KIT_ROTATE_UNKNOWN = "The server didn't answer, so your old kit may already have stopped working. Make a new kit again, so you have one that works.";
/** Approved wording (decided on 2026-11-17): the new kit was confirmed. */
export const KIT_ROTATE_DONE = "Your new recovery kit is saved. The old one no longer works.";

/**
 * Turning two-factor sign-in off (server rule of 2026-11-16: the master password as well as a current code). The card
 * keeps its own name for the feature, "two-factor sign-in", in these lines too.
 */
/** The card's existing sentences (not placeholders), kept here so the flow's text and the card say the same. */
export const TOTP_WRONG_CODE = "That code is wrong or expired — try the current one.";
export const TOTP_WRONG_PASSWORD = "That master password isn't right — try again.";
/** Approved wording (decided on 2026-11-17): two-step sign-in turned off. Was "Two-factor sign-in is off. …". */
export const TOTP_OFF_DONE = "Two-step sign-in is off. Signing in now asks only for your master password.";
/** Approved wording (decided on 2026-11-17): the same, on a server that requires it. Was "Two-factor sign-in is off. This server requires it, …". */
export const TOTP_OFF_DONE_REQUIRED = "Two-step sign-in is off. This server requires it, so your next sign-in asks you to set it up again.";
/** Approved wording (decided on 2026-11-17): the master-password field beside the code, on the card while two-factor sign-in is on. */
export const TOTP_OFF_PASSWORD_LABEL = "Master password, to turn it off";
/** Approved wording (decided on 2026-11-17): the server answered that the code was refused for the wait it names. {0} the wait (TOTP_WAIT_* below). */
export const TOTP_OFF_WAIT = "Too many tries. Wait {0} and try again.";
/** Approved wording (decided on 2026-11-17): the wait's words. {0} the number. */
export const TOTP_WAIT_SECOND = "1 second";
export const TOTP_WAIT_SECONDS = "{0} seconds";
export const TOTP_WAIT_MINUTE = "1 minute";
export const TOTP_WAIT_MINUTES = "{0} minutes";
// The two-step card's own lines, in the design's term ("two-step sign-in"; they said "two-factor" before 2026-11-17).
/** Approved wording (decided on 2026-11-17): the card's heading. Was "Two-factor sign-in (server)". */
export const TWO_STEP_TITLE = "Two-step sign-in";
/** Approved wording (decided on 2026-11-17): the card could not read whether two-step sign-in is on. Was "Couldn't check two-factor sign-in — reload to try again." */
export const TWO_STEP_CHECK_FAILED = "andvari couldn't check two-step sign-in. Reload this page to try again.";
/** Approved wording (decided on 2026-11-17): two-step sign-in was just turned on. Was "Two-factor sign-in is on. Every sign-in now also asks for a code from your authenticator app." */
export const TWO_STEP_TURNED_ON = "Two-step sign-in is on. Every sign-in now also asks for a code from your authenticator app.";
/** Approved wording (decided on 2026-11-17): the server's policy requires it. Was "This server requires two-factor sign-in for every account." */
export const TWO_STEP_REQUIRED_HERE = "This server requires two-step sign-in for every account.";
/** Approved wording (decided on 2026-11-17): the setup QR code's accessible name. Was "Two-factor enrollment QR code". */
export const TWO_STEP_QR_LABEL = "QR code for setting up two-step sign-in";
/** Approved wording (decided on 2026-11-17): under the setup link and code; {0} the seconds. Was "Both of these are your second factor — copying one clears it from your clipboard again after {0} seconds." */
export const TWO_STEP_SECRET_CLEARS = "Both of these are your two-step sign-in's secret: keep them to yourself. A copied one is cleared from your clipboard after {0} seconds.";
/** Approved wording (decided on 2026-11-17): the button that turns it on. Was "Turn on two-factor sign-in". */
export const TWO_STEP_TURN_ON = "Turn on two-step sign-in";
/** Approved wording (decided on 2026-11-17): the import report's group of logins whose one-time-code secret differs. Was "Same login as your vault, but a different 2FA secret — imported separately (renamed) for review:". */
export const IMPORT_TOTP_DIFFERS = "The same login as one in your vault, but with a different one-time code. Imported separately, under a new name, for you to check:";
/** PLACEHOLDER: the same group on the import's PREVIEW, before anything is imported: what will be done. */
export const IMPORT_TOTP_DIFFERS_PREVIEW = "The same login as one in your vault, but with a different one-time code. Will be imported separately, under a new name, for you to check:";
/** Approved wording (decided on 2026-11-17): the session ended before two-factor sign-in was turned off (nothing changed). */
export const TOTP_OFF_SESSION_ENDED = "Your session ended, so two-step sign-in is still on. Sign in again, then turn it off.";
/** Approved wording (decided on 2026-11-17): the two-factor card, when the session ended as two-step sign-in was being set up. */
export const TOTP_SETUP_SESSION_ENDED = "Your session ended before two-step sign-in was set up. Sign in again, then turn it on.";
/** Approved wording (decided on 2026-11-17): the two-factor card, when setting it up got no answer or a server error: nothing is set up yet. */
export const TOTP_SETUP_UNKNOWN = "The server didn't answer, so two-step sign-in isn't set up. Try again.";
/**
 * PLACEHOLDER: the two-factor card, when the server's setup named another account or another product than this one in
 * the label an authenticator app files the key under: nothing of it was shown, and two-step sign-in is not set up.
 */
export const TOTP_SETUP_NOT_THIS_ACCOUNT = "The server's answer couldn't be used: it didn't name this account, so nothing of it is shown and two-step sign-in isn't set up.";
/** Approved wording (decided on 2026-11-17): no answer, or a 5xx: it may or may not be off. */
export const TOTP_OFF_UNKNOWN = "The server didn't answer, so andvari can't tell whether two-step sign-in is off. Reload this page to see.";

/** Approved wording (decided on 2026-11-17): §5.3's "no personal vault" anomaly (a withheld or unopenable personal wrap); there is no question. */
export const NO_PERSONAL_VAULT = "The server didn't send your personal vault this time, or sent one andvari can't open. Until it does, choose a vault each time you save or import. If this keeps happening, tell the person who runs this server.";

/** §3.9 "Member lists": a member whose log key is not a current contact's key here (the design's own words). */
export const ROSTER_UNVERIFIED = "unverified member (as the server names them)";
/** §3.9, FC-10: an item head mentioned history the server has not shown (the design's own words). */
export const ROSTER_MAY_BE_INCOMPLETE = "This list may be incomplete. An item mentions history the server hasn't shown.";
/** Approved wording (decided on 2026-11-17): this browser holds no verified history for the vault yet, so it shows no members. */
export const ROSTER_NONE = "andvari hasn't checked this vault's history yet, so it can't show who is in it.";
/** Approved wording (decided on 2026-11-17): the log does not verify now; the list is the last one this browser verified. */
export const ROSTER_STALE = "This shared vault's history doesn't check out right now. These are the members andvari last checked.";
/**
 * PLACEHOLDER: the members' status line of a shared vault frozen on this browser (the server's record of the vault
 * contradicts itself), in place of ROSTER_STALE. Must say: the server's record of this vault contradicts itself, so
 * andvari has stopped checking and changing this vault in this browser, for good, and these are the members andvari
 * last checked. Never "right now".
 */
export const ROSTER_FROZEN = "⟦The server's record of this vault contradicts itself, so andvari has stopped checking it in this browser, for good. These are the members andvari last checked.⟧";
/** Approved wording (decided on 2026-11-17): the incoming-offer card; the offer is the owner's signed log entry (§3.5). {0} the owner's label. */
export const OFFER_SIGNED = "The offer is signed by {0} in this vault's history. As its owner you would manage its members, and only you could rename it, hand it over or delete it.";
/** Approved wording (decided on 2026-11-17): the generator over an existing password asks first ("tap" said nothing to a mouse or a keyboard). */
export const GENERATE_REPLACE_ASK = "This replaces the current password. To go ahead, choose Replace. To keep it, change the field instead.";

/** A save refused for the vault owner's quota (`quota_exceeded`): core AppCopy's OWNER_OUT_OF_SPACE, byte for byte. */
export const OWNER_OUT_OF_SPACE = "This vault's owner is out of space on this server.";
/** The owner's approved entry 27, under OWNER_OUT_OF_SPACE when this account owns the vault (the personal vault included). */
export const OWNER_OUT_OF_SPACE_YOURS = "This wasn't saved. You own this vault: remove items or attachments you no longer need, or ask the operator for more space.";
/** The owner's approved entry 28, under OWNER_OUT_OF_SPACE when someone else owns the vault. */
export const OWNER_OUT_OF_SPACE_THEIRS = "This wasn't saved. Ask the vault's owner to free up space.";
/**
 * Approved wording (decided on 2026-11-17): VaultKeyNotVerifiedError's message (vault/account.ts), shown where a save, a move or an import into a
 * shared vault this account may not write to is refused (the editor's and the import's error lines). The old text named
 * a "Shared vaults" review that no longer exists.
 */
export const VAULT_KEY_NOT_VERIFIED = "This wasn't saved. andvari can't confirm that you may change this shared vault, so it's read-only in this browser.";
/**
 * Approved wording (decided on 2026-11-17). A lock or a sign-out overtook work still on its way (a save, the rest of an import, an
 * upload, a password change, a kit rotation): the unlock card or the first screen, under its other notices.
 */
export const LOCK_INTERRUPTED_WORK =
  "andvari locked while a change was still being sent, so it may not have reached the server. After you unlock, check your last change, and make it again if it's missing.";
/**
 * Approved wording (decided on 2026-11-17). A sync answer said the personal vault was removed; nothing was changed. The vault's notice
 * area, in the vault list.
 */
export const PERSONAL_REMOVAL_REFUSED =
  "The server said you were removed from your personal vault. andvari ignored that: nobody else is in your personal vault, so nobody can remove you from it. Your items stay, and your changes are still saved. If this keeps happening, the server may be misbehaving.";

/** §3.13 (T-R6): the remove dialog, in the design's own words. */
export const REMOVE_MEMBER_DOES_NOT = "Removing someone stops the server from giving them this vault. It doesn't change the vault's key: if they kept a copy and the server helps them, they could still read and change what's in it. To be sure, move everything to a new vault.";
/** Approved wording (decided on 2026-11-17): the incoming-offer card's title. {0} the vault's name. */
export const OFFER_IN_TITLE = "Become the owner of “{0}”?";
/** Approved wording (decided on 2026-11-17): the incoming-offer card's first line. {0} the owner's label, {1} the vault's name. */
export const OFFER_IN_BODY = "{0} asked you to take over “{1}”.";
/** Approved wording (decided on 2026-11-17): , NEW (the 2026-11-16 walk: the card never said how long the offer stands). {0} the day the offer ends. */
export const OFFER_IN_UNTIL = "You can accept until {0}.";
/** Approved wording (decided on 2026-11-17): the incoming-offer card's buttons, and the accept button while it runs. */
export const OFFER_IN_ACCEPT = "Become the owner";
export const OFFER_IN_ACCEPTING = "Taking over…";
export const OFFER_IN_DECLINE = "Decline";
/** Approved wording (decided on 2026-11-17): the owner's name when this browser's verified list has no owner row to name them. */
export const OFFER_IN_OWNER_UNKNOWN = "The vault's owner";

/** Approved wording (decided on 2026-11-17): the owner's vault settings, after the person an ownership offer was made to refused it (their signed `cancel`, §3.3). {0} their name, {1} the vault's name. */
export const OFFER_REFUSED = "{0} declined to take over “{1}”. You're still the owner.";
/** Approved wording (decided on 2026-11-17): the confirming step of a role change (the drop-down alone signs nothing). {0} the member's name, {1} the new role. */
export const ROLE_CHANGE_ASK = "Make {0} a {1}?";
/** Approved wording (decided on 2026-11-17): what a reader and a writer may do, under ROLE_CHANGE_ASK. */
export const ROLE_CHANGE_READER = "A reader can see the items in this vault but can't change them.";
export const ROLE_CHANGE_WRITER = "A writer can add, change and delete the items in this vault.";
/** Approved wording (decided on 2026-11-17): the confirming button, and while it runs. */
export const ROLE_CHANGE_CONFIRM = "Change role";
export const ROLE_CHANGE_RUNNING = "Changing…";
/** Approved wording (decided on 2026-11-17): the note after deleting a vault that had no other members. {0} the vault's name, {1} the day it can be restored until. */
export const DELETED_NOTE_ALONE = "“{0}” is deleted. You can restore it until {1} (the trash icon above).";
/**
 * PLACEHOLDER: the note after deleting a vault where the server did not serve the day until which it can be restored
 * (an older server). {0} the vault's name. Must say: it is deleted; members lost access at once; it can be restored
 * from the list of deleted vaults (the trash icon above), which shows until when. Must not name a day.
 */
export const DELETED_NOTE_NO_DAY = "“{0}” is deleted. Members lost access immediately. You can restore it from your deleted vaults (the trash icon above), which show until when.";
/** PLACEHOLDER: the same for a vault that had no other members. {0} the vault's name. Must not name a day. */
export const DELETED_NOTE_ALONE_NO_DAY = "“{0}” is deleted. You can restore it from your deleted vaults (the trash icon above), which show until when.";

// ---- What the save screen says when a save could not be made (the 2026-11-16 walk) ----

/**
 * Approved wording (decided on 2026-11-17): the one-time question after the first unlock. The web ships no offline app shell: the page itself comes
 * from the server, so the copy serves only a tab that is already open, and a reload without the server cannot load.
 */
export const OFFLINE_COPY_OFFER = "Keep an encrypted offline copy of your vault on this device? It is made the next time you unlock or sign in here; from then on, a tab you already have open can unlock it even when the server can't be reached. A reload or a fresh tab still needs the server: without it, the page itself can't load.";
/**
 * Approved wording (decided on 2026-11-17): the vault opened from this browser's offline copy while the server can't be reached (spec 02 §8), above
 * every view until a sync reaches the server.
 */
export const OFFLINE_OPENED = "You opened this browser's offline copy, because the server can't be reached. Items you save wait here and are sent when it can be. Sharing, Settings, the trash and earlier versions need the server, and say so if you try them now.";
/** Approved wording (decided on 2026-11-17): the top bar's retry while the vault is the offline copy (in place of "Sync now"). */
export const OFFLINE_TRY_SERVER = "Try the server again";
/** Approved wording (decided on 2026-11-17): Settings → Offline copy, what the copy is. */
export const OFFLINE_COPY_ABOUT = "An encrypted copy of your vault kept in this browser, so you can open it in a tab you already have open, even when the server can't be reached. Only your master password can open it, and your password itself is never stored.";
/** Approved wording (decided on 2026-11-17): Settings → Offline copy, what it cannot do (no offline app shell; stated by mechanism, as the web app can be installed to a home screen). */
export const OFFLINE_COPY_LIMIT = "A fresh tab still needs the server, and so does a reload: without the server the page itself can't load, so this copy keeps only a tab that is already open working, a home-screen shortcut for this site included. The andvari apps you install for your computer and phone do open offline from cold.";
/**
 * Approved wording (decided on 2026-11-17): the unlock card's line when this browser holds an offline copy of the account that it cannot read (its
 * keys are not a usable set, or the browser's database does not open). In place of "Offline copy on this device — last
 * synced …", which would speak of a copy nothing here can open.
 */
export const OFFLINE_COPY_UNREADABLE = "This browser has an offline copy of your vault, but can't read it.";
/** Approved wording (decided on 2026-11-17): the one line above Settings' cards that need the server, while the vault is the offline copy. */
export const OFFLINE_SETTINGS_WAIT = "The server can't be reached, so the settings below that need it can't be changed until it can.";
/** Approved wording (decided on 2026-11-17): the one line at the top of Sharing, same condition. */
export const OFFLINE_SHARING_WAIT = "The server can't be reached, so vaults can't be made, shared, changed or restored until it can.";
/** Approved wording (decided on 2026-11-17): the server can't be reached and this browser keeps no offline copy, so the change could not wait here. */
export const SAVE_OFFLINE_NO_COPY = "This wasn't saved. The server can't be reached, and this browser keeps no offline copy, so the change can't wait here. Try again once you're back online. To let a change wait in this browser next time, turn on Settings → Offline copy.";
/** Approved wording (decided on 2026-11-17): the server can't be reached and the browser has not granted lasting storage, so a waiting change could be lost. */
export const SAVE_OFFLINE_NOT_PERSISTENT = "This wasn't saved. The server can't be reached, and this browser hasn't allowed andvari to keep data for good, so a change waiting here could be lost. Try again once you're back online.";
/** Approved wording (decided on 2026-11-17): files go up only while the server answers. */
export const SAVE_OFFLINE_ATTACHMENTS = "This wasn't saved. Attachments can be added only while the server can be reached. Try again once you're back online, or save without the new attachment for now.";
/** Approved wording (decided on 2026-11-17): after an anomaly the personal vault is named but its key isn't held here. */
export const SAVE_VAULT_NOT_OPEN = "This wasn't saved. This browser can't open your personal vault right now. Choose a shared vault for this item, or lock and unlock to try again.";

// ---- The holding area's copy-out (design §3.8, §3.12: "items can still be copied out") ----

/** Approved wording (decided on 2026-11-17): the button on a vault in "Recently removed". */
export const HELD_COPY = "Copy its items to your personal vault";
/**
 * Approved wording (decided on 2026-11-17): the holding area's line for a vault this account deleted itself (design §3.8 keeps its copy too, once the
 * deletion is verified; it is listed here once it can no longer be restored). {0} the day the copy leaves this device.
 */
export const HELD_DELETED_BY_ME = "you deleted it · kept sealed until {0}";
/** Approved wording (decided on 2026-11-17): under it, before copying: what happens to attachments. */
export const HELD_COPY_ATTACHMENTS = "Attachments are copied only if the server still sends them to this browser, which it usually doesn't once you've lost the vault.";
/** Approved wording (decided on 2026-11-17): done. {0} the count with its noun ("1 item", "3 items"), as for every count below. */
export const HELD_COPIED = "Copied {0} to your personal vault.";
/** Approved wording (decided on 2026-11-17): after HELD_COPIED, attachments left out. {0} the count ("1 attachment"). */
export const HELD_COPIED_NO_FILES = "Not copied: {0}, which the server no longer sends to this browser.";
/** Approved wording (decided on 2026-11-17): after HELD_COPIED, items that could not be opened. {0} the count ("1 item"). */
export const HELD_COPIED_UNREADABLE = "Not copied: {0} that this browser can't open.";
/** Approved wording (decided on 2026-11-17): a held vault whose key this browser no longer holds (kept before the key was), so nothing can be copied out. */
export const HELD_NO_KEY = "This browser no longer has this vault's key, so its items can't be copied out here.";
/**
 * Approved wording (decided on 22 November 2026; core AppCopy.HELD_ADDED_AGAIN, byte for byte): the line of a vault in
 * "Recently removed" while this browser shows an invitation to it that its person can answer, so the copy is closed.
 * {0} the vault's name as the invitation names it, {1} the day the copy leaves this device.
 */
export const HELD_ADDED_AGAIN = "You were added to “{0}” again. Until you accept, this device can't open the copy it kept. Accept before {1} to get it back. On that day it goes from this device.";
/**
 * PLACEHOLDER (the wording page's proposal PQ7): copying a held vault's items into the personal vault refused because the
 * person's account is out of space. Never OWNER_OUT_OF_SPACE's "this vault's owner": the held vault may be someone else's.
 */
export const HELD_COPY_OUT_OF_SPACE = "Not copied: your account is out of space on this server. Remove items or attachments you no longer need, or ask the operator for more space.";
/** The design's own words (§3.8, spec 02 §10.6; core AppCopy.REMOVE_FROM_THIS_DEVICE): the person drops a held copy. */
export const REMOVE_FROM_THIS_DEVICE = "Remove from this device";
/** Approved wording (decided on 2026-11-17): the confirmation before REMOVE_FROM_THIS_DEVICE on a vault in "Recently removed". {0} the vault's name. */
export const HELD_REMOVE_CONFIRM = "Remove this browser's copy of “{0}”? Any changes to it that were never sent are lost with it. Nothing is sent to the server.";

// ---- "Move everything to a new vault" (design §3.13) ----

/** §3.13: the action's name, in the design's own words (core AppCopy MOVE_EVERYTHING). The button that opens it and the one that runs it. */
export const MOVE_EVERYTHING = "Move everything to a new vault";
/** §3.6, T2-R-k: the copy dialog on a frozen or failed vault, in the design's own words (core AppCopy CHECK_WHAT_YOU_COPY). */
export const CHECK_WHAT_YOU_COPY = "Items in this vault may have been changed by someone the server let in. Check what you copy.";
/** Approved wording (decided on 2026-11-17): what the move does, on a vault in good standing. {0} the old vault's name. */
export const MOVE_INTRO = "andvari makes a new vault with a new key, copies every item into it, adds the people below to it with the same role, and then deletes “{0}”. Each of them is asked to accept the new vault. Until the move ends, everything stays in “{0}” as well.";
/** Approved wording (decided on 2026-11-17): what the move does on a frozen or failed vault (§3.13, FS-R3). {0} the old vault's name. */
export const MOVE_INTRO_STAYS = "andvari makes a new vault with a new key and copies every item into it. “{0}” stays as it is. This browser can't be sure its list of members is current, and it could include someone who was removed, so nobody is added unless you tick them.";
/** Approved wording (decided on 2026-11-17, on design §3.13): what does not move, on a vault in good standing. {0} the old vault's name. */
export const MOVE_NOT_MOVED = "Only the items move. Items in the trash and earlier versions of items stay with “{0}”, and go when it is erased for good.";
/** Approved wording (decided on 2026-11-17, on design §3.13): what does not move, on a frozen or failed vault, which stays. {0} the old vault's name. */
export const MOVE_NOT_MOVED_STAYS = "Only the items move. Items in the trash and earlier versions of items stay in “{0}”.";
/** Approved wording (decided on 2026-11-17): the move opened from the remove dialog. {0} the old vault's name, {1} the member's name (the entry numbers its slots across all three lines). */
export const MOVE_REMOVING = "{1} is removed from “{0}” first, and isn't added to the new vault.";
/** Approved wording (decided on 2026-11-17): the new vault's name field. */
export const MOVE_NAME = "Name of the new vault";
/** Approved wording (decided on 2026-11-17): the old vault has no other member to add. */
export const MOVE_NOBODY = "Nobody else is in this vault.";
/** Approved wording (decided on 2026-11-17): beside a member this browser can't add (not a current contact here, or codes never compared). */
export const MOVE_CANNOT_ADD = "This browser can't add them.";
/** Approved wording (decided on 2026-11-17): why the old vault will be kept when someone can't be added. {0} the old vault's name. */
export const MOVE_KEEPS_OLD = "Because not everyone can be added from this browser, “{0}” won't be deleted. Add them to the new vault from another of your devices, then delete “{0}” yourself.";
/** Approved wording (decided on 2026-11-17): the old vault kept because someone holds the new vault's key who isn't in the move. {0} the old vault's name. */
export const MOVE_KEPT_MEMBERS_DIFFER = "Someone who isn't part of this move can open the new vault, so “{0}” won't be deleted.";
/** Approved wording (decided on 2026-11-17): items changed in the old vault while the move ran. {0} the count ("1 item"), {1} the old vault's name. */
export const MOVE_CHANGED_MEANWHILE = "{0} in “{1}” changed after it was copied, so “{1}” won't be deleted. Check the new vault against it, then delete “{1}” yourself.";
/**
 * PLACEHOLDER: every check passed but the old vault's history moved on before its deletion was signed (a member left,
 * another change): nothing was signed, and no item count is said. {1} the old vault's name ({0} unused).
 */
export const MOVE_CHANGED_MOVED_ON = "“{1}” changed while the move ran, so it won't be deleted. Move everything again to finish, or check the new vault against it and delete “{1}” yourself.";
/**
 * PLACEHOLDER: every check passed, and the server refused the old vault's deletion because an item in it was saved,
 * changed, put in the trash or restored after the move's last read of it (another member, or another device). Nothing
 * was deleted. {1} the old vault's name ({0} unused). Must say: something in the old vault changed after it was
 * copied, so it won't be deleted; moving everything again brings over what changed, or the person checks the new vault
 * against it and deletes the old one themselves. Must not give a count of items (none is known), nor say who changed it.
 */
export const MOVE_CHANGED_AFTER_READ = "Something in “{1}” changed after it was copied, so it won't be deleted. Move everything again to bring that over, or check the new vault against it and delete “{1}” yourself.";
/** Approved wording (decided on 2026-11-17): a stopped earlier move's new vault was replaced and deleted. {0} that vault's name. */
export const MOVE_DISCARDED = "The new vault an earlier, stopped move made, “{0}”, held only copies and someone who isn't part of this move could open it, so it was deleted and this move made a fresh one.";
/**
 * Approved wording (decided on 2026-11-17): as MOVE_DISCARDED, when the fresh vault has the same name as the one deleted (finishing a move keeps
 * its name), so the note does not read as "everything is in “X”" and "“X” was deleted" at once. {0} the name both share.
 */
export const MOVE_DISCARDED_SAME_NAME = "The “{0}” an earlier, stopped move made held only copies and someone who isn't part of this move could open it, so that one was deleted and this move made a new “{0}”.";
/**
 * PLACEHOLDER (design §3.13 as decided on 2026-11-18): as MOVE_DISCARDED, said when the move stopped before it made its
 * own new vault (the half-made one is dealt with before anything is copied). {0} that vault's name. Must not say this
 * move made a fresh one.
 */
export const MOVE_DISCARDED_BEFORE_START = "The new vault an earlier, stopped move made, “{0}”, held only copies and someone who isn't part of this move could open it, so it was deleted.";
/** Approved wording (decided on 2026-11-17): as above, when that delete didn't go through. {0} that vault's name. */
export const MOVE_DISCARD_FAILED = "The new vault an earlier, stopped move made, “{0}”, holds only copies and someone who isn't part of this move can open it. It couldn't be deleted just now. Delete it yourself.";
/** Approved wording (decided on 2026-11-17): items this browser can't read, so can't copy. {0} the count ("1 item"), {1} the old vault's name. */
export const MOVE_UNCOPYABLE = "This browser can't read {0} in “{1}”. Those aren't copied, so “{1}” won't be deleted.";
/** Approved wording (decided on 2026-11-17): the progress line. {0} items copied, {1} all of them. */
export const MOVE_PROGRESS = "Copying {0} of {1}…";
/** Approved wording (decided on 2026-11-17): a move this session started and that stopped. {0} the new vault's name, {1} the count copied so far ("1 item"). */
export const MOVE_RESUME = "A move into “{0}” stopped after copying {1}. Moving everything again carries on from there.";
/** Approved wording (decided on 2026-11-17): the move stopped before anything was made. {0} the old vault's name. */
export const MOVE_STOPPED_START = "Nothing was moved, and “{0}” wasn't changed.";
/** Approved wording (decided on 2026-11-17): stopped while copying. {0} copied, {1} all with its noun ("7 items"), {2} the new vault's name, {3} the old vault's name. */
export const MOVE_STOPPED_COPY = "The move stopped after copying {0} of {1} into “{2}”. Everything is still in “{3}”, which wasn't changed. Move everything again to carry on from there.";
/** Approved wording (decided on 2026-11-17): stopped while adding members. {2} the new vault's name, {3} the old vault's name. */
export const MOVE_STOPPED_ADD = "Every item is in “{2}”, but not everyone has been added to it yet. “{3}” wasn't changed. Move everything again to carry on from there.";
/** Approved wording (decided on 2026-11-17): stopped at the last step. {2} the new vault's name, {3} the old vault's name. */
export const MOVE_STOPPED_DELETE = "Everything is in “{2}” and everyone has been added, but “{3}” couldn't be deleted. Move everything again to delete it.";
/**
 * Approved wording (decided on 2026-11-17): stopped at the last step because the server never answered the old vault's delete (signed, held, not known
 * to be stored; design §3.13 as decided on 2026-11-16: never "kept", never "deleted"). {2} the new vault's name, {3} the
 * old vault's name.
 */
export const MOVE_STOPPED_DELETE_HELD = "Everything is in “{2}” and everyone is added. The deletion of “{3}” is signed and waiting for the server, and it can't be taken back. Finish the move to complete it.";
/**
 * PLACEHOLDER: the same stop, when the server's own complete answer said it stored the old vault's deletion and this
 * browser couldn't read it back yet. {2} the new vault's name, {3} the old vault's name.
 */
export const MOVE_STOPPED_DELETE_STORED = "Everything is in “{2}” and everyone is added. The server stored the deletion of “{3}”, but this browser couldn't read it back yet. Finish the move to complete it.";
/**
 * PLACEHOLDER: a move stopped at its first step because the removal it signs first is held (not confirmed, or stored and
 * not read back). Must not say the old vault "wasn't changed" (the removal may be stored); the line for the held change
 * follows it. {0} the old vault's name.
 */
export const MOVE_STOPPED_REMOVE_HELD = "Nothing was moved out of “{0}” yet.";
/**
 * PLACEHOLDER: a move stopped at the step that adds the members because the last addition is held (not confirmed, or
 * stored and not read back). Must not say "not everyone has been added" (that addition may be stored); the line for the
 * held change follows it. {2} the new vault's name, {3} the old vault's name.
 */
export const MOVE_STOPPED_ADD_HELD = "Every item is in “{2}”, and “{3}” wasn't changed. Move everything again to carry on from there.";
/**
 * PLACEHOLDER (section on "wasn't changed", 2026-11-18): the move stopped before anything was copied, after the server
 * stored the removal it signs first. Must not say the old vault "wasn't changed" (the removal changed who is in it);
 * must say nothing was moved and every item is still there. {0} the old vault's name.
 */
export const MOVE_STOPPED_START_REMOVED = "Nothing was moved yet, and every item is still in “{0}”. The person you removed is out of it.";
/**
 * PLACEHOLDER: as MOVE_STOPPED_COPY, after the server stored the removal the move signed first. Must not say "wasn't
 * changed". {0} copied, {1} all with its noun, {2} the new vault's name, {3} the old vault's name.
 */
export const MOVE_STOPPED_COPY_REMOVED = "The move stopped after copying {0} of {1} into “{2}”. Every item is still in “{3}”, and the person you removed is out of it. Move everything again to carry on from there.";
/**
 * PLACEHOLDER: as MOVE_STOPPED_ADD, after the server stored the removal the move signed first. Must not say "wasn't
 * changed". {2} the new vault's name, {3} the old vault's name.
 */
export const MOVE_STOPPED_ADD_REMOVED = "Every item is in “{2}”, but not everyone has been added to it yet. Every item is still in “{3}” too, and the person you removed is out of it. Move everything again to carry on from there.";
/**
 * PLACEHOLDER: as MOVE_STOPPED_ADD_HELD, after the server stored the removal the move signed first. Must not say
 * "wasn't changed" nor "not everyone has been added"; the held change's own line follows. {2} the new vault's name,
 * {3} the old vault's name.
 */
export const MOVE_STOPPED_ADD_HELD_REMOVED = "Every item is in “{2}”, and every item is still in “{3}” too. Move everything again to carry on from there.";
/**
 * PLACEHOLDER (a notice; spec 03 §5): a change of this browser was saved over an item that had been deleted elsewhere
 * (another device, or another member), and the server brought the item back with this change (an edit beats a
 * deletion). {0} the item's name, {1} the vault's name. Must say: this change brought the item back; it had been
 * deleted elsewhere; it is back, with this change, and nothing else was copied. Must not call it a conflict copy, nor
 * say who deleted it.
 */
export const ITEM_BROUGHT_BACK = "Your change to “{0}” in “{1}” brought it back: it had been deleted elsewhere. It's back with your change, and no copy was made.";
/**
 * PLACEHOLDER: ITEM_BROUGHT_BACK for exactly one change whose item this browser cannot name (it is not in the vault as
 * held here). {0} the vault's name. Must say: one of your changes in that vault brought back an item that had been
 * deleted elsewhere; it is back with your change, and no copy was made. Must not count it as "1 of your changes".
 */
export const ITEM_BROUGHT_BACK_UNNAMED = "⟦One of your changes in “{0}” brought back an item that had been deleted elsewhere. It's back with your change, and no copy was made.⟧";
/** PLACEHOLDER: the same for several items of one vault. {0} how many, {1} the vault's name. */
export const ITEM_BROUGHT_BACK_MANY = "{0} of your changes in “{1}” brought back items that had been deleted elsewhere. They're back with your changes, and no copies were made.";
/**
 * PLACEHOLDER: not everyone can be added from this browser while the old vault's deletion is already signed and waiting
 * (it cannot be taken back, and nothing else can be changed on that vault until the move is finished). {0} the old
 * vault's name. Must not say it "won't be deleted" nor "delete it yourself".
 */
export const MOVE_KEEPS_OLD_WAITING = "Not everyone can be added from this browser. The deletion of “{0}” is already signed and waiting: add them to the new vault from another of your devices, then finish the move.";
/**
 * PLACEHOLDER (design §3.13 as decided on 2026-11-18): the new vault an earlier, stopped move made was due for deletion,
 * and as read from the server it holds items that move did not make (an item someone saved there, a copy changed since,
 * an item this browser can't read, an item in its trash that isn't one of the move's copies) or a copy whose revision
 * at the server is not known, so it was NOT deleted: it stays a vault of its own. Shown after the move and, when the
 * deletion was due outside a run, as a notice. {0} its name. Must say: its name; andvari can't confirm it holds only
 * that move's copies (in the vault or its trash); it wasn't deleted and stays a vault of its own; someone who isn't
 * part of this move can open it. Must not say for certain that it holds items the move didn't make (a copy whose
 * revision isn't known is enough to keep it).
 */
export const MOVE_DISCARD_KEPT = "The new vault an earlier, stopped move made, “{0}”, may hold items that move didn't make, in it or in its trash, so it wasn't deleted. It stays a vault of its own, and someone who isn't part of this move can open it. Check what's in it, its trash too, and who's in it.";
/**
 * PLACEHOLDER (design §3.13 as decided on 2026-11-18): that vault could not be read from the server just now, so it was
 * not deleted, and what it holds is not known. andvari reads it again at its next sync and deletes it only if it holds
 * nothing but the move's copies. {0} its name. Must say: its name; not deleted; it couldn't be checked; checked again
 * later. Must not say what it holds.
 */
export const MOVE_DISCARD_UNREAD = "The new vault an earlier, stopped move made, “{0}”, couldn't be checked just now, so it wasn't deleted. andvari checks it again later and deletes it only if it holds nothing but that move's copies.";
/**
 * PLACEHOLDER: the new vault an earlier, stopped move made, read from the server, held only the move's copies, and its deletion
 * is signed and held (no answer, or the server refused it for now): it may already be stored. At the next unlock andvari
 * reads the vault again first and asks again only while it still holds nothing but those copies (otherwise it keeps it
 * and says so). {0} that vault's name. Must not say it asks again unconditionally.
 */
export const MOVE_DISCARD_WAITING = "The new vault an earlier, stopped move made, “{0}”, holds only copies and someone who isn't part of this move can open it. andvari asked the server to delete it and has no confirmation yet. The next time you unlock, andvari checks it again and asks again only if it still holds nothing but that move's copies.";
/**
 * PLACEHOLDER (design §3.13 as decided on 2026-11-18): said after MOVE_DISCARD_KEPT, MOVE_DISCARD_UNREAD,
 * MOVE_DISCARD_WAITING or MOVE_DISCARD_FAILED when a move that leaves people out dealt with the half-made vault of an
 * earlier, stopped run before copying anything, and that vault was not deleted: the people this move leaves out (the
 * person being removed among them) can still open it, and what is in it. {0} their names ("Carol", "Carol, Dan"),
 * {1} the vault's name, {2} the count of copies the earlier move made in it ("2 items"). Must say: they still hold it;
 * the copies in it. Must not say they can't open it.
 */
export const MOVE_DISCARD_HOLDERS = "{0} can still open “{1}” and the {2} that move copied into it.";
/** PLACEHOLDER: as MOVE_DISCARD_HOLDERS where this browser has a name for none of them. {1} and {2} as there ({0} unused). */
export const MOVE_DISCARD_HOLDERS_UNNAMED = "Someone this move leaves out can still open “{1}” and the {2} that move copied into it.";
/**
 * PLACEHOLDER: as MOVE_DISCARD_HOLDERS for a vault found as an earlier move's new vault by its own sealed description,
 * where no record of that move is kept: what is in it is not known to be that move's copies. {0} the names, {1} the
 * vault, {2} the count the read from the server just made ("3 items"): its items, the rows of its trash, and what this
 * browser cannot read. Must say: they can still open it and what is in it, that many; must not call them copies.
 */
export const MOVE_DISCARD_HOLDERS_FOUND = "{0} can still open “{1}” and the {2} in it, its trash included.";
/** PLACEHOLDER: as MOVE_DISCARD_HOLDERS_FOUND where this browser has a name for none of them ({0} unused). */
export const MOVE_DISCARD_HOLDERS_FOUND_UNNAMED = "Someone this move leaves out can still open “{1}” and the {2} in it, its trash included.";
/**
 * PLACEHOLDER: as MOVE_DISCARD_HOLDERS_FOUND where the read from the server failed: no number can be said. {0} the names,
 * {1} the vault ({2} unused). Must say they can still open it and whatever is in it.
 */
export const MOVE_DISCARD_HOLDERS_FOUND_UNREAD = "{0} can still open “{1}” and whatever is in it.";
/** PLACEHOLDER: the same where this browser has a name for none of them ({0}, {2} unused). */
export const MOVE_DISCARD_HOLDERS_FOUND_UNREAD_UNNAMED = "Someone this move leaves out can still open “{1}” and whatever is in it.";
/**
 * PLACEHOLDER: the new vault an earlier, stopped move made is, as read from the server just now, no longer among this
 * account's vaults (deleted from another device, or this account no longer holds it): nothing was deleted, and nothing
 * checks it again. {0} its name. Must not say it is checked again later, nor what it holds, nor that it was deleted.
 */
export const MOVE_DISCARD_NOT_HELD = "The new vault an earlier, stopped move made, “{0}”, is no longer among your vaults, so andvari didn't delete it.";
/**
 * Approved wording (decided on 2026-11-17): a run finishing such a move stopped before it re-posted the deletion (a copy of what changed in the old vault
 * could not be made, or something is left that this browser can't settle). {2} the new vault's name, {3} the old vault's
 * name. The reason follows.
 */
export const MOVE_STOPPED_DELETE_WAITING = "The move into “{2}” isn't finished. The deletion of “{3}” is signed and waiting for the server, and it can't be taken back. Finish the move once this is sorted out:";
/**
 * Approved wording (decided on 2026-11-17): a vault's name where another vault in the same list bears it too (the vault lists, the vault pickers and
 * a move's sentences). {0} the name, {1} when it was made ("November 16, 9:31 PM").
 */
export const SAME_NAME_MADE = "{0} (made {1})";
/** Approved wording (decided on 2026-11-17): the Sharing list's second line for a vault whose name another vault bears too, after "shared vault · ". {0} when it was made. */
export const SAME_NAME_MADE_LINE = "made {0}";
/** Approved wording (decided on 2026-11-17): {1} of SAME_NAME_MADE when the server gave no time the vault was made. */
export const SAME_NAME_UNDATED = "at a time this browser wasn't told";
/**
 * Approved wording (decided on 2026-11-17): the one line at the top of the old vault's panel while its deletion waits (design §3.13), in place of the
 * owner's line; renaming, roles, removing, adding, an ownership offer and deleting are not offered then. {0} the old name.
 */
export const MOVE_WAITING_LOCKED = "While its deletion waits, “{0}” can't be renamed, shared differently, handed over or deleted.";
/**
 * Approved wording (decided on 2026-11-17): a change refused because the vault's deletion, signed by a move, waits for the server (design §3.13 as
 * decided on 2026-11-17): an item saved, deleted, restored, imported or moved into or out of it, a rename, or any
 * sharing action on it. Shown where the change was tried (the editor, a dialog, a panel).
 */
export const MOVE_WAITING_REFUSED = "This vault's deletion is signed and waiting for the server, so it can't be changed until its move is finished. Finish the move first.";
/**
 * Approved wording (decided on 2026-11-17): the one line above an item of such a vault, and above the list filtered to it: nothing in it can be added
 * or changed. {0} the vault's name. The banner "Moving … isn't finished" with "Finish the move" sits above it.
 */
export const MOVE_WAITING_READ_ONLY = "“{0}” is read-only while its deletion waits for the server. Finish the move to go on.";

/**
 * PLACEHOLDER: the one line above the vault list after the item the person had open (its detail, no editor) was closed
 * because this browser no longer shows it: the person was removed from its vault, or it was deleted or moved elsewhere.
 * It names no field of the item (the screen keeps nothing of it). Must say: the item that was open is no longer in your
 * vaults on this browser, so it was closed.
 */
export const ITEM_CLOSED = "⟦The item you had open is no longer in your vaults on this browser, so it was closed.⟧";
/**
 * PLACEHOLDER: as ITEM_CLOSED, where the editor of the item was open and held nothing that was not saved. Must say: the
 * item being edited is no longer in your vaults on this browser, so the editor was closed.
 */
export const ITEM_CLOSED_EDITING = "⟦The item you were editing is no longer in your vaults on this browser, so the editor was closed.⟧";
/**
 * PLACEHOLDER: as ITEM_CLOSED_EDITING, where the editor held typing (or files to attach) that was not saved. Nothing of it
 * is kept and nothing is sent: nobody pressed Save. Must say: the editor was closed because the item is no longer in your
 * vaults on this browser; what was typed was not saved, and it is not kept.
 */
export const ITEM_CLOSED_EDITING_NOT_KEPT =
  "⟦The item you were editing is no longer in your vaults on this browser, so the editor was closed. What you typed was not saved, and it is not kept.⟧";
/**
 * PLACEHOLDER: as ITEM_CLOSED_EDITING, where the person had pressed Save and the save had not been answered when the item
 * was closed: its change may have reached the vault or not, and this browser cannot tell which. Must say: the editor was
 * closed because the item is no longer in your vaults on this browser; your save got no answer before that, so it may or
 * may not have reached the vault.
 */
export const ITEM_CLOSED_EDITING_SENT =
  "⟦The item you were editing is no longer in your vaults on this browser, so the editor was closed. Your save got no answer before that, so it may or may not have reached the vault.⟧";
/**
 * PLACEHOLDER: on the backup panel, where a backup was not made because the vaults or items this browser shows changed
 * while it was being sealed (a removal from a shared vault carried out meanwhile), three times in a row, or until nothing
 * was left to back up. No file was saved. Must say: what you can read here changed while the backup was being made, so
 * no backup was made and no file was saved.
 */
export const BACKUP_NOT_MADE_CHANGED = "⟦What you can read here changed while the backup was being made, so no backup was made and no file was saved.⟧";
/**
 * PLACEHOLDER: in the editor of a NEW item, under the vault picker, when the vault the person chose for it is no longer
 * offered (they were removed from it, or it became read-only) while the editor was open. Nothing was saved, and nothing
 * is saved elsewhere in its place; Save waits until another vault is chosen. Must say: the vault chosen for this item is
 * no longer one you can save into; choose another; nothing was saved.
 */
export const EDITOR_VAULT_GONE = "⟦The vault you chose for this item is no longer one you can save into. Choose another one. Nothing was saved.⟧";
/** Approved wording (decided on 2026-11-17): the mark on each member's role on that panel (its tooltip, and read after the role). */
export const ROLE_LOCKED_NOW = "Can't be changed while the deletion waits";
/** Approved wording (decided on 2026-11-17): the old vault's own panel while its move's deletion waits. {0} the old vault's name, {1} the new vault's name. */
export const MOVE_WAITING_PANEL = "The deletion of “{0}” is signed and waiting for the server, and it can't be taken back. Its move into “{1}” needs to be finished.";
/**
 * Approved wording (decided on 2026-11-17): the first screen after an unlock, for each move whose deletion waits (design §3.13: the unlock's re-posting
 * leaves it alone). {0} the old vault's name, {1} the new vault's name.
 */
export const MOVE_UNFINISHED = "Moving “{0}” into “{1}” isn't finished. The deletion of “{0}” is signed and waiting for the server, and it can't be taken back.";
/** Approved wording (decided on 2026-11-17): the button that finishes such a move (the banner and the old vault's panel). */
export const MOVE_FINISH = "Finish the move";
/**
 * PLACEHOLDER: a move whose deletion of the old vault was dropped because the old vault froze on this browser (the
 * server's answer about that deletion and its record of the vault disagree): said where the move stops, and on the first
 * screen after an unlock in place of MOVE_UNFINISHED, until dismissed. {0} the old vault's name, {1} the new vault's name.
 * Never says "waiting" or "finish the move", nor that anything failed. Must say: the server's record of “{0}” contradicts
 * itself, andvari has stopped writing to it on this browser, the items are in “{1}”, and “{0}” stays as it is here.
 */
export const MOVE_OLD_FROZEN = "⟦The server's record of “{0}” contradicts itself, so andvari has stopped writing to it on this browser. The items are in “{1}”; “{0}” stays as it is here.⟧";
/**
 * PLACEHOLDER: the end of the notice that a shared vault was deleted by its owner, where exactly one edit made on this
 * device had not synced (two or more keep the counted sentence). Must say: one of the person's edits had not synced, and
 * it will be recovered if the vault is restored this week. Never "1 of your edits".
 */
export const DELETED_PARKED_ONE = "⟦One of your edits hadn't synced; it will be recovered if the vault is restored this week.⟧";
/**
 * Approved wording (decided on 2026-11-17): the notice when the server stored a move's signed deletion of the old vault outside a run of the move
 * (design §3.13 as decided on 2026-11-17). {0} the old vault's name, {1} the new vault's name. Followed by
 * MOVE_STORED_LATE or MOVE_STORED_NOTHING_LATE, then MOVE_STORED_UNSEEN.
 */
export const MOVE_STORED_OUTSIDE = "The server deleted “{0}” before its move into “{1}” was finished.";
/**
 * PLACEHOLDER: shown in MOVE_STORED_OUTSIDE's place: the deletion may also have been made by the same person from another
 * of their devices, so the line names no one. {0} the old vault's name, {1} the new vault's name.
 */
export const MOVE_DELETED_OUTSIDE = "“{0}” was deleted before its move into “{1}” was finished.";
/**
 * Approved wording (decided on 2026-11-17): after MOVE_STORED_OUTSIDE. {0} how many ("2 items"), {1} how many of them were added, {2} how many were
 * changed after their copy, {3} the new vault's name.
 */
export const MOVE_STORED_LATE = "This browser kept {0} that the move hadn't copied: {1} added and {2} changed after their copy. You can copy them into “{3}”.";
/** Approved wording (decided on 2026-11-17): after MOVE_STORED_OUTSIDE when everything this browser held had been copied. {0} the new vault's name. */
export const MOVE_STORED_NOTHING_LATE = "Everything this browser had of it was already copied into “{0}”.";
/** Approved wording (decided on 2026-11-17): the last sentence of that notice. */
export const MOVE_STORED_UNSEEN = "Anything another member added that this browser never received can't be saved here.";
/** Approved wording (decided on 2026-11-17): the button under that notice. {0} the new vault's name. */
export const MOVE_STORED_COPY = "Copy them into “{0}”";
/** Approved wording (decided on 2026-11-17): after that button did its work. {0} how many ("2 items"), {1} the new vault's name. */
export const MOVE_STORED_COPIED = "Copied {0} into “{1}”.";
/** Approved wording (decided on 2026-11-17): a new vault's name this browser can't read (a move's banner after a reload). */
export const MOVE_UNNAMED_VAULT = "the new vault";
/** Approved wording (decided on 2026-11-17): an old vault's name this browser can't read (a move's banner). */
export const MOVE_UNNAMED_OLD = "a shared vault";
/** Approved wording (decided on 2026-11-17): under OWNER_OUT_OF_SPACE when the move ran out of space (§3.13: it needs room for a second copy). */
export const MOVE_NEEDS_SPACE = "While both vaults exist, the move needs space for a second copy of this vault. Remove items you no longer need, or ask the operator for more space.";
/**
 * Approved wording (decided on 2026-11-17): under OWNER_OUT_OF_SPACE when the check before a move or an import found the account short (spec 03 §14.4):
 * nothing started. {0} each limit passed and by how much, joined with "and" (QUOTA_OVER_*).
 */
export const QUOTA_SHORT = "Nothing was started: this would go {0}. The server's operator can raise this account's limits.";
/** Approved wording (decided on 2026-11-17): one limit passed. {0} by how much ("2.1 KiB"), {1} the limit ("100 MiB"). */
export const QUOTA_OVER_BYTES = "{0} of space over the limit of {1}";
/** Approved wording (decided on 2026-11-17): as above for items. {0} by how many ("3 items"), {1} the limit ("5000 items"). */
export const QUOTA_OVER_ITEMS = "{0} over the limit of {1}";
/** Approved wording (decided on 2026-11-17): as above for shared vaults. {0} "1 shared vault", {1} the limit ("50 shared vaults"). */
export const QUOTA_OVER_VAULTS = "{0} over the limit of {1}";
/**
 * Approved wording (decided on 2026-11-17): Settings, the account's own use and limits on this server (spec 03 §14.4), shown only when the server
 * served them. {0}/{1} space used/limit, {2}/{3} items, {4}/{5} shared vaults, {6}/{7} open links.
 */
export const QUOTA_LINE = "On this server this account uses {0} of its {1} of space, {2} of {3} items, {4} of {5} shared vaults and {6} of {7} open links.";
/** Approved wording (decided on 2026-11-17): done, the old vault deleted. {0} the new name, {1} the old name, {2} the day it can be restored until. */
export const MOVE_DONE = "Everything is in “{0}” now. “{1}” is deleted, and you can restore it until {2} (the trash icon above). The people you added are asked to accept “{0}”.";
/**
 * MOVE_DONE when the move added nobody (everyone else had left), so no one is asked anything: MOVE_DONE less its last
 * sentence, whatever its words are. Same slots.
 */
export const MOVE_DONE_ALONE = withoutLastSentence(MOVE_DONE);
/**
 * PLACEHOLDER: MOVE_DONE in the banner above every view (a move finished from the first screen), where no trash icon is
 * above it: the restore place is named as Sharing's. Same slots.
 */
export const MOVE_DONE_BANNER = "Everything is in “{0}” now. “{1}” is deleted, and you can restore it until {2} from Sharing (the trash icon at its top). The people you added are asked to accept “{0}”.";
/** PLACEHOLDER: MOVE_DONE_BANNER when the move added nobody: less its last sentence, whatever its words are. Same slots. */
export const MOVE_DONE_ALONE_BANNER = withoutLastSentence(MOVE_DONE_BANNER);
/**
 * PLACEHOLDER: MOVE_DONE where the server did not serve the day until which the old vault can be restored. {0} the new
 * name, {1} the old name. Must point to the list of deleted vaults (the trash icon above); must not name a day. Its last
 * sentence is the one about the people added, as MOVE_DONE's.
 */
export const MOVE_DONE_NO_DAY = "Everything is in “{0}” now. “{1}” is deleted, and you can restore it from your deleted vaults (the trash icon above), which show until when. The people you added are asked to accept “{0}”.";
/** PLACEHOLDER: MOVE_DONE_NO_DAY when the move added nobody: less its last sentence. Same slots. */
export const MOVE_DONE_ALONE_NO_DAY = withoutLastSentence(MOVE_DONE_NO_DAY);
/** PLACEHOLDER: MOVE_DONE_NO_DAY in the banner above every view: the restore place is named as Sharing's. Same slots. */
export const MOVE_DONE_BANNER_NO_DAY = "Everything is in “{0}” now. “{1}” is deleted, and you can restore it from your deleted vaults in Sharing (the trash icon at its top), which show until when. The people you added are asked to accept “{0}”.";
/** PLACEHOLDER: MOVE_DONE_BANNER_NO_DAY when the move added nobody: less its last sentence. Same slots. */
export const MOVE_DONE_ALONE_BANNER_NO_DAY = withoutLastSentence(MOVE_DONE_BANNER_NO_DAY);
/** Approved wording (decided on 2026-11-17): done, the old vault kept. {0} the new name, {1} the old name. Followed by why. */
export const MOVE_DONE_KEPT = "Everything this browser could copy is in “{0}” now. “{1}” is still there.";
/** Approved wording (decided on 2026-11-17): why it was kept, for a frozen or failed vault. */
export const MOVE_KEPT_STAYS = "Its history doesn't check out, so andvari leaves it as it is.";

/**
 * Approved wording (decided on 2026-11-17): the server refused a recovery copy as a form it no longer stores (`escrow_wrong_form`), at sign-up, at the
 * recovery settings and at the silent re-seal after a signed rotation. Never shown as the raw code.
 */
export const ESCROW_WRONG_FORM_TEXT = "This version of andvari made a recovery copy in a form this server no longer takes, so nothing was changed. Reload this page to get the newest version, then try again. If it happens again, tell the operator.";
/** PLACEHOLDER: a served key failed an identity check (the old IDENTITY_MISMATCH sentence names the old trust model). */
export const IDENTITY_FAULT = "This account's keys failed a security check, so andvari won't open the vault. Don't enter your password again here; contact the person who runs this server.";

// ---- Forget the earlier account on this device (decided on 2026-11-17): the shared code's REMADE_ACCOUNT_* lines ----
// Each line is the shared code's key of the same name, in the same words; every one but the button is a PLACEHOLDER that
// says what the line must say (the wording page has an entry for each).
/** PLACEHOLDER (the shared code's REMADE_ACCOUNT_TITLE): heading of the refusal for an address this browser knows as another account. */
export const REMADE_ACCOUNT_TITLE = "⟦Heading of the refusal for an address this device knows as another account: this address belongs to another account on this device⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_REFUSAL): {0} the address, {1} the server. Must say: known as another account, stopped, nothing changed. */
export const REMADE_ACCOUNT_REFUSAL = "⟦The refusal: this device knows {0} on {1} as another account, so andvari stopped and nothing was changed⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_IF_REMADE): the first possibility, a sentence of its own. */
export const REMADE_ACCOUNT_IF_REMADE = "⟦The first possibility, a sentence of its own: the account under this address was deleted and made again, and this device still remembers the earlier one⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_IF_SERVER): the second possibility, a sentence of its own, never preferred to the first. */
export const REMADE_ACCOUNT_IF_SERVER = "⟦The second possibility, a sentence of its own: the server is not giving this device the account it knows; then something is wrong with the server, and nothing should be forgotten⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_HOW_TO_TELL): how to tell which. */
export const REMADE_ACCOUNT_HOW_TO_TELL = "⟦How to tell: the person knows which, because they, or the operator with their knowledge, deleted the account and made it again⟧";
/** Approved wording (decided on 2026-11-17, the owner's own words): the offer's button (REMADE_ACCOUNT_FORGET). */
export const REMADE_ACCOUNT_FORGET = "Forget the earlier account on this device";
/** PLACEHOLDER (REMADE_ACCOUNT_CONFIRM_TITLE): heading of the second confirmation. */
export const REMADE_ACCOUNT_CONFIRM_TITLE = "⟦Heading of the second confirmation: forget the earlier account?⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_CONFIRM): {0} the address. Must say what goes, and that the server and what is known of it stay. */
export const REMADE_ACCOUNT_CONFIRM = "⟦What goes: this device forgets the earlier account under {0}; the server and what this device knows of it stay as they are⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_CONFIRM_COPY_UNSENT): {0} the address, {1} how many changes were not sent. */
export const REMADE_ACCOUNT_CONFIRM_COPY_UNSENT = "⟦This device's copy of the earlier account is deleted; {1} changes made in it were not sent, and they are lost⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_CONFIRM_COPY_ONE_UNSENT): the same, for one change. */
export const REMADE_ACCOUNT_CONFIRM_COPY_ONE_UNSENT = "⟦This device's copy of the earlier account is deleted; one change made in it was not sent, and it is lost⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL): the same, where the copy cannot be read to count. */
export const REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL = "⟦This device's copy of the earlier account is deleted; andvari cannot tell whether changes made in it were not sent, and any that were not are lost⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT): the same, where nothing waits in it. */
export const REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT = "⟦This device's copy of the earlier account is deleted; every change made in it was sent⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_CONFIRM_ALWAYS): the second confirmation's last line, always shown. */
export const REMADE_ACCOUNT_CONFIRM_ALWAYS = "⟦Always: this cannot be undone; if the account was not deleted and made again, forgetting means this device trusts whatever account the server gives it under this address from now on⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_CONFIRM_FORGET): the second confirmation's button. */
export const REMADE_ACCOUNT_CONFIRM_FORGET = "⟦The second confirmation's button: forget it⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_FORGOTTEN): {0} the address. Shown after the forgetting, above the refused form. */
export const REMADE_ACCOUNT_FORGOTTEN = "⟦After the forgetting: this device has forgotten the earlier account under {0}; nothing was sent to the server, and andvari still checks the server as before; try again to go on⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_NOTHING_TO_FORGET): {0} the address. */
export const REMADE_ACCOUNT_NOTHING_TO_FORGET = "⟦This device does not remember an earlier account under {0}, so there was nothing to forget; nothing changed⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_FORGET_ACCOUNT_OPEN): the earlier account is the session this browser keeps; its sign-out comes first. */
export const REMADE_ACCOUNT_FORGET_ACCOUNT_OPEN = "⟦Nothing was forgotten: the earlier account is open or kept on this device; sign out of it first (its sign-out says how many changes were not sent), then try again⟧";
/**
 * PLACEHOLDER (the web's own, no key in the shared code yet): the forgetting was refused because this browser cannot tell
 * whether another of its tabs has the earlier account open (it has no Web Locks). Must say: nothing was forgotten; this
 * browser cannot tell whether the earlier account is open in another tab; after updating this browser it can forget it, or
 * the person clears this site's data in the browser (which forgets every account here). Must not say "sign out first".
 */
export const REMADE_ACCOUNT_FORGET_CANNOT_TELL_OPEN = "⟦Nothing was forgotten: this browser cannot tell whether the earlier account is open in another of its tabs; update this browser and try again, or clear this site's data in the browser, which forgets every account here⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_FORGET_NOT_CONFIRMED): what the second confirmation said has changed since; it is shown again. */
export const REMADE_ACCOUNT_FORGET_NOT_CONFIRMED = "⟦Nothing was forgotten: the second confirmation was not given, or what it said has changed since (a lock took it back, or the count of changes not sent changed); read it again before confirming⟧";
/**
 * PLACEHOLDER (the web's own, no key in the shared code yet): the forgetting failed on this browser part-way. Must say:
 * part of it may be done; nothing was sent; confirm again to finish it.
 */
export const REMADE_ACCOUNT_FORGET_FAILED = "⟦The forgetting failed on this device part-way; part of it may be done and nothing was sent; confirm again to finish it⟧";
/** PLACEHOLDER (REMADE_ACCOUNT_REMEMBERED): {0} the address. Once, when the next account under the address is taken, until dismissed. */
export const REMADE_ACCOUNT_REMEMBERED = "⟦Once, after the forgetting, when the next account under the address is taken: this device now remembers the new account under {0}⟧";
/**
 * PLACEHOLDER (the web's own, no key in the shared code yet): {0} the address. The second confirmation was refused because
 * what the offer was made for no longer holds (the account this browser now remembers under the address is the one the
 * server gave, or the earlier account is that one). Must say: nothing was forgotten; try again to go on.
 */
export const REMADE_ACCOUNT_FORGET_NO_LONGER_HOLDS = "⟦Nothing was forgotten: what this offer was made for no longer holds (the account this device now remembers under {0} is the one the server gave); try again to go on⟧";
/**
 * PLACEHOLDER (the web's own, no key in the shared code yet): {0} the address, {1} how many. A line of the second
 * confirmation where this browser keeps no copy of the earlier account but holds changes to shared vaults it signed here,
 * which the server said it did not store. Must say: they go with the forgetting, were not sent, and are lost.
 */
export const REMADE_ACCOUNT_CONFIRM_HELD_UNSENT = "⟦{1} changes to shared vaults made on this device under the earlier account were not sent; they are deleted with it and lost⟧";
/** PLACEHOLDER (the web's own): the same, for one change. */
export const REMADE_ACCOUNT_CONFIRM_HELD_ONE_UNSENT = "⟦One change to a shared vault made on this device under the earlier account was not sent; it is deleted with it and lost⟧";
/**
 * PLACEHOLDER (the web's own): the same, where it cannot be told whether such changes reached the server (an answer was
 * lost or never came). Must say: they go with the forgetting; andvari cannot tell whether they were sent; any that were
 * not are lost.
 */
export const REMADE_ACCOUNT_CONFIRM_HELD_CANNOT_TELL = "⟦Changes to shared vaults made on this device under the earlier account are deleted with it; andvari cannot tell whether they reached the server, and any that did not are lost⟧";
/**
 * Approved wording (decided on 2026-11-17): the unlock card, when the account's keys the server serves are not the ones this browser knows and nothing
 * here opened to compare them with (spec 01 §7): the password opens the server's keys and not this browser's copy, or the
 * copy cannot be read. Nothing is opened or changed; a "Sign in" button follows. Never said as a wrong password.
 */
export const SERVER_KEYS_NOT_KNOWN_SIGN_IN = "The server's keys for this account aren't the ones this browser knows, so nothing was opened or changed here. That isn't a wrong password. Sign in again to go on.";
/**
 * Approved wording (decided on 2026-11-17): the line above every view of a vault opened from this browser's copy while the server serves keys this
 * browser does not know (spec 01 §7, "leaves both"). It stays for the session.
 */
export const SERVER_KEYS_NOT_KNOWN_OPENED = "The server's keys for this account aren't the ones this browser knows, so this vault was opened from this browser's copy, and nothing that asks for your master password works here. If your master password was changed on another device, lock and unlock with the new one. If it wasn't, the server may be misbehaving: don't change anything until you've checked with the operator.";
/**
 * Approved wording (decided on 2026-11-17): a proof the server refused while that line is shown: said as the keys not being known, never as a wrong
 * password.
 */
export const SERVER_KEYS_NOT_KNOWN_REFUSED = "The server didn't accept your master password here, because its keys for this account aren't the ones this browser knows. That isn't a wrong password. Nothing changed.";
/**
 * Approved wording (decided on 2026-11-17): the one line above Settings' cards while that line is shown: every one of them asks for the master
 * password (a new password, a new kit, recovery settings, devices, two-step sign-in, deleting the account), so they are
 * shown unavailable for the session instead of offered and then refused.
 */
export const SERVER_KEYS_NOT_KNOWN_SETTINGS = "The settings below ask for your master password, and the server's keys for this account aren't the ones this browser knows, so they're turned off until you sign in again.";
/**
 * Approved wording (decided on 2026-11-17): the unlock, when the typed master password opens none of this browser's own keys and the server also sent
 * a password-hashing cost this app does not take (nothing was derived at it): both are so, and both are said.
 */
export const WRONG_PASSWORD_KDF_NOT_USABLE = "That master password doesn't open this browser's copy of your vault. This server also sent settings for your master password that andvari can't use, so nothing was opened or sent. Tell the operator.";
/**
 * Approved wording (decided on 2026-11-17): the unlock, when the typed master password is the new one of a change made in this browser that got no
 * answer and never reached the server: the earlier password is still the account's. {0} the day the change was made.
 */
export const CHANGE_NOT_STORED = "The master password change made in this browser on {0} didn't reach the server, so your earlier master password is still the one. Unlock with it.";
/** Approved wording (decided on 2026-11-17): as above, for a change this browser kept before it recorded the day. */
export const CHANGE_NOT_STORED_UNDATED = "A master password change made in this browser didn't reach the server, so your earlier master password is still the one. Unlock with it.";
/**
 * Approved wording (decided on 2026-11-17): the server refused a proof of the master password that was made in this browser (the password opened the
 * account here first; a wrong password is found here and sends nothing), while this browser does not know the server's
 * keys to be other than its own. Never said as a wrong password, on every action that asks for the password again.
 */
export const SERVER_REFUSED_PROOF = "The server didn't accept your master password, although it opened your account in this browser. That isn't a wrong password. Nothing changed. If it keeps happening, sign in again.";
/**
 * PLACEHOLDER: an action that asks for the master password again, while a change of the master password made in this
 * browser has no answer and the server's keys could not be read to find out which password it holds: nothing was sent.
 * Must say: a master password change wasn't confirmed; the server holds either the password from before that change or
 * the new one; nothing was sent; try again once the server can be reached. Must not say the password is wrong, nor that
 * the server refused it.
 */
export const PASSWORD_CHANGE_NOT_CONFIRMED = "A change of your master password wasn't confirmed, so the server holds either the master password from before that change or the new one. andvari couldn't check which just now, and nothing was sent. Try again once the server can be reached.";
/**
 * PLACEHOLDER: a sign-in on a browser that holds a copy of this account, where the account key the server's keys open does
 * not open that copy (spec 01 §7): nothing was opened or written, the copy stays as it was, and the session is ended. It
 * says the way out (decided on 2026-11-17): ask whoever runs the server; and, if the person is sure, sign out of this
 * browser's copy (its Sign out, on the same card, says first how many changes were not sent) and sign in again.
 */
export const SIGN_IN_KEYS_NOT_THIS_ACCOUNT = "The server's keys for this account aren't this account's keys as this browser knows them, so nothing was opened or changed here, and this browser's copy stays as it was. Ask the person who runs this server what changed. If you're sure the server is right, sign out of this browser's copy, then sign in again: Sign out first says how many changes made here weren't sent, and those are lost with the copy.";
/**
 * Approved wording (decided on 2026-11-17): the one line above every view after a sign-in over a copy of the same account (the same account key) that
 * the typed master password does not open: the copy now follows the server's keys. It goes at the next lock.
 */
export const COPY_FOLLOWS_SERVER = "This browser's copy of your vault was locked with a different master password than the one you just typed. It now uses the one on the server, the one you typed.";
/**
 * Approved wording (decided on 2026-11-17): the server sent a password-hashing cost this app does not take (outside the floor or the ceiling, not a
 * whole number, or a memory cost that is not a whole number of KiB). Nothing was derived at it. The server's fault,
 * never a wrong password.
 */
export const KDF_NOT_USABLE = "This server sent settings for your master password that andvari can't use, so nothing was opened or sent. That isn't a wrong password. Tell the operator.";

/**
 * PLACEHOLDER: a sign-in the server took (it made a session for this browser) whose ANSWER this browser refused, for a
 * password-hashing cost in it that andvari does not take; this browser then ended that session again, and the server
 * confirmed it. Must say: the server took the sign-in, this browser ended it again, why; nothing was opened. Never
 * "nothing was sent".
 */
export const SIGN_IN_ANSWER_COST_ENDED =
  "The server took your sign-in, but its answer carried settings for your master password that andvari can't use. So this browser opened nothing and ended that session again. That isn't a wrong password. Tell the operator.";
/**
 * PLACEHOLDER: the same, and the end of that session was not confirmed (no answer, or a refusal): the session the
 * server made ends by itself (its access within an hour, all of it within thirty days).
 */
export const SIGN_IN_ANSWER_COST_NOT_ENDED =
  "The server took your sign-in, but its answer carried settings for your master password that andvari can't use. So this browser opened nothing. It tried to end that session again, and the server didn't confirm it: the session ends by itself within thirty days. That isn't a wrong password. Tell the operator.";
/**
 * PLACEHOLDER: a sign-in the server took whose answer named other settings for the master password (salt or cost) than
 * the server's first answer named a moment before; this browser ended that session again, and the server confirmed it.
 */
export const SIGN_IN_ANSWER_CHANGED_ENDED =
  "The server took your sign-in, but its answer named other settings for your master password than it had named a moment before. So this browser opened nothing and ended that session again. That isn't a wrong password. Tell the operator.";
/** PLACEHOLDER: the same, and the end of that session was not confirmed: it ends by itself within thirty days. */
export const SIGN_IN_ANSWER_CHANGED_NOT_ENDED =
  "The server took your sign-in, but its answer named other settings for your master password than it had named a moment before. So this browser opened nothing. It tried to end that session again, and the server didn't confirm it: the session ends by itself within thirty days. That isn't a wrong password. Tell the operator.";

/** The line for a sign-in whose answer this browser refused ([reason]), by whether the end of the session it was given was confirmed. */
export function signInAnswerRefusedText(reason: "cost" | "other_kdf", ended: boolean): string {
  if (reason === "cost") return ended ? SIGN_IN_ANSWER_COST_ENDED : SIGN_IN_ANSWER_COST_NOT_ENDED;
  return ended ? SIGN_IN_ANSWER_CHANGED_ENDED : SIGN_IN_ANSWER_CHANGED_NOT_ENDED;
}

/** The sentence for a served cost the fence refused: below the floor or above the ceiling is the approved weakened-settings sentence; a cost that is not whole is {@link KDF_NOT_USABLE}. */
export function kdfRefusalText(e: Pick<KdfPolicyError, "code">): string {
  return e.code === "kdf_not_whole" ? KDF_NOT_USABLE : WEAK_KDF_MESSAGE;
}
