import { AccountDeleteBlockedError, AccountDeleteUnknownError, ApiError, type ApiClient, type SessionEndKind } from "../api/client";
import type { AccountDeleteBlocker, AccountDeletePreview } from "../api/types";
import { KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import { ReauthFailedError, ReauthStaleSessionError, type Account } from "../vault/account";
import { UNREACHABLE } from "./errors";

/**
 * Settings → Delete account (spec 03 §13; design docs/design/2026-11-10-account-deletion.md §11). The pure half of the
 * flow — what the card says and does — kept out of the component so the node test environment can pin it
 * (account-delete.test.ts). The card (DeleteAccount.tsx) renders these and owns only the state.
 */

/** The typed confirmation matches the account's address, trimmed and case-folded — exactly how the server compares it
 *  (it re-checks: `400 confirm_email_mismatch`). A session saved before the address was recorded knows none: then any
 *  non-empty entry passes HERE and the server decides. */
export function emailConfirmed(typed: string, accountEmail: string): boolean {
  const t = typed.trim().toLowerCase();
  if (!t) return false;
  const a = accountEmail.trim().toLowerCase();
  return a === "" || t === a;
}

/** The code field holds what an authenticator shows ("123 456"); the server wants the digits. */
export const totpDigits = (code: string): string => code.replace(/\s/g, "");

export type BlockerLink = { kind: "vault"; vaultId: string } | { kind: "admin" };

export interface BlockerLine {
  text: string;
  link: BlockerLink | null;
  linkLabel: string;
}

const people = (n: number): string => (n === 1 ? "1 other person" : `${n} other people`);

/**
 * One sentence per blocker, in the server's order, each with the place that resolves it. A vault is named by the name
 * this browser decrypts for it (the server knows vaults only as ids); one it cannot name is still listed. An unknown kind
 * is listed as a blocker this version cannot explain — never dropped (spec 03 §13: a client never proceeds past one).
 */
export function blockerLines(blockers: AccountDeleteBlocker[], vaultName: (vaultId: string) => string | null): BlockerLine[] {
  return blockers.map((b) => {
    if (b.kind === "shared_vault") {
      const name = b.vaultId ? vaultName(b.vaultId) : null;
      const verb = b.others === 1 ? "still uses it" : "still use it";
      if (name !== null && b.vaultId) {
        return {
          text: `You own “${name}”, and ${people(b.others)} ${verb}. Delete it, or make one of them its owner, first.`,
          link: { kind: "vault", vaultId: b.vaultId },
          linkLabel: `Open “${name}” settings →`,
        };
      }
      return {
        text: `You own a shared vault that ${people(b.others)} ${verb}. Delete it, or make one of them its owner, first — you'll find it under Sharing.`,
        link: null,
        linkLabel: "",
      };
    }
    if (b.kind === "last_admin") {
      // Exact on purpose: there is no promote route (spec 03 §11, §13), so the copy must not send anyone hunting for a
      // "make admin" control — the only way is a NEW account invited as an admin.
      return {
        text: `You're the only admin of this andvari server, and ${people(b.others)} ${b.others === 1 ? "has an account" : "have accounts"} on it. andvari can't make an existing account an admin — an account is an admin only if it was invited as one. Invite a new admin first (Administration → Users → Invite a user, with “Admin” ticked, for an address that has no account yet), then come back.`,
        link: { kind: "admin" },
        linkLabel: "Open Administration →",
      };
    }
    return {
      text: "The server reports something else that stops this account being deleted, which this version of andvari can't explain. Reload to update, or ask whoever runs your server.",
      link: null,
      linkLabel: "",
    };
  });
}

/** The line shown when the server refused without naming anything it could decode — still a refusal. */
export const BLOCKED_UNEXPLAINED = "The server refused to delete your account and didn't say why. Nothing was deleted.";

const quoted = (names: string[]): string => {
  const q = names.map((n) => `“${n}”`);
  return q.length <= 1 ? q.join("") : `${q.slice(0, -1).join(", ")} and ${q[q.length - 1]}`;
};

/**
 * What the preview means, in the member's words: what goes for good, and the vaults it leaves. `personalVaultId` names
 * the vault this browser knows as the personal one (so it reads "your Personal vault", not a list entry).
 */
export function deletionSummary(
  preview: AccountDeletePreview,
  vaultName: (vaultId: string) => string | null,
  personalVaultId: string | null,
): { deletes: string[]; leaves: string[] } {
  const others = preview.deletedVaults.filter((v) => v !== personalVaultId);
  const named = others.map(vaultName).filter((n): n is string => n !== null);
  const unnamed = others.length - named.length;
  const vaults: string[] = [];
  if (personalVaultId !== null && preview.deletedVaults.includes(personalVaultId)) vaults.push("your Personal vault");
  if (named.length > 0) vaults.push(`${named.length === 1 ? "the vault" : "the vaults"} only you use, ${quoted(named)}`);
  if (unnamed > 0) vaults.push(unnamed === 1 ? "1 other vault only you hold" : `${unnamed} other vaults only you hold`);
  const deletes = [
    "Your account, and its sign-in on every device.",
    ...(vaults.length > 0 ? [`${capitalize(joinAnd(vaults))} — every item, attachment and earlier version in them.`] : []),
    "Your recovery phrase and your household recovery backup: nobody, an admin included, can bring the account back.",
    "Invites you sent that nobody has used yet.",
  ];
  const leftNamed = preview.leftVaults.map(vaultName).filter((n): n is string => n !== null);
  const leftUnnamed = preview.leftVaults.length - leftNamed.length;
  const leaves: string[] = [];
  if (preview.leftVaults.length > 0) {
    const what = [
      ...(leftNamed.length > 0 ? [quoted(leftNamed)] : []),
      ...(leftUnnamed > 0 ? [leftUnnamed === 1 ? "1 other shared vault" : `${leftUnnamed} other shared vaults`] : []),
    ];
    leaves.push(`You'll leave ${joinAnd(what)}. What you saved there stays for the people who still use ${preview.leftVaults.length === 1 ? "it" : "them"}.`);
  }
  return { deletes, leaves };
}

function joinAnd(parts: string[]): string {
  return parts.length <= 1 ? parts.join("") : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Why the preview could not be loaded. */
export function previewErrorText(e: unknown): string {
  if (e instanceof ApiError && e.code === "account_delete_public_disabled") return PUBLIC_ORIGIN_REFUSED;
  if (e instanceof ApiError && e.code === "totp_enrollment_required") return TOTP_ENROLL_FIRST;
  if (e instanceof TypeError) return UNREACHABLE;
  return "Couldn't check what deleting your account would do — try again.";
}

const PUBLIC_ORIGIN_REFUSED =
  "Deleting an account isn't available from this emergency address. Use your household's usual andvari address.";
const TOTP_ENROLL_FIRST = "This server requires two-factor sign-in: turn it on above first, then delete the account.";

/** One sentence per refusal of the deletion request (or of the local password proof that precedes it). Every one of them
 *  means NOTHING was deleted — the server refuses before its transaction writes anything. */
export function deleteErrorText(e: unknown): string {
  if (e instanceof ReauthFailedError) return e.message; // caught locally — the password never left this browser
  if (e instanceof ReauthStaleSessionError) return e.message;
  if (e instanceof KdfPolicyError) return WEAK_KDF_MESSAGE;
  if (e instanceof TypeError) return UNREACHABLE;
  if (e instanceof ApiError) {
    switch (e.code) {
      case "reauth_failed":
        return new ReauthFailedError().message;
      case "totp_code_required":
        return "Enter the code from your authenticator app.";
      case "bad_totp_code":
        return "That code is wrong or was already used — wait for the next one and try again.";
      case "confirm_email_mismatch":
        return "That isn't this account's email address.";
      case "account_delete_public_disabled":
        return PUBLIC_ORIGIN_REFUSED;
      case "totp_enrollment_required":
        return TOTP_ENROLL_FIRST;
      case "credential_changed":
        return "Your password was changed, or this device was signed out, while deleting — nothing was deleted. Sign in again and retry.";
      case "rate_limited":
        return "Too many attempts — wait a while, then try again.";
      case "upgrade_required":
        return "This tab is running an older version — reload to update, then try again.";
    }
    if (e.status === 401) return "Your session ended — nothing was deleted. Sign in again and retry.";
  }
  return "Something went wrong and your account was not deleted — try again.";
}

/** Shown when the deletion request got no answer that says what happened — none at all (or none within the request's
 *  timeout), a 5xx, or a reply that is not the server's — so the server may or may not have committed it (spec 03 §13:
 *  never reported as either). */
export const OUTCOME_UNKNOWN =
  "The server didn't answer in a way that says whether your account was deleted — it may have been. Check below, or reload andvari and sign in: if your account is gone, the deletion went through.";

/** After an unknown outcome, the check found the account still here. */
export const NOT_DELETED_AFTER_CHECK = "Your account is still here — it was not deleted. You can try again.";

/** A 401 with no unknown outcome before it: the request was refused before anything was deleted. */
export const SESSION_ENDED = "Your session ended — nothing was deleted. Sign in again and retry.";

/** The session ended after an unknown outcome, by something this browser cannot tie to the deletion — a 401 on the check
 *  or on a retry, a revocation that arrived afterwards. An admin's revocation, disable or recovery and a password change
 *  elsewhere end a session too, so the account may still exist: this is said instead, the spec 01 §5 self-identity
 *  records stay, and nothing offers to forget the account. */
export const SESSION_ENDED_OUTCOME_UNKNOWN =
  "Your session ended, so andvari can't tell whether your account was deleted. Sign in to find out: if your account still exists, you can.";

/** App's card when the session ended WHILE the deletion request was in flight and its answer never came: that end was, most
 *  likely, the deletion's own revocation (the server revokes the account's sockets the moment the deletion commits). */
export const DELETION_MOST_LIKELY_DONE =
  "Your session ended while your account was being deleted, and the server's answer never arrived — the deletion most likely went through. You can make this browser forget the account: its sign-in, its offline copy and everything else it kept for it. Or sign in to check: if your account still exists, you can.";

export type DeletionOutcome =
  | { kind: "deleted"; deletedAt: number }
  | { kind: "blocked"; blockers: AccountDeleteBlocker[] }
  /** Refused, or failed before the request was sent. `unanswered`: the server could not be reached at all, so this says
   *  nothing about the account (every other error is an answer from a live session, or a local check after one). */
  | { kind: "error"; message: string; code?: string; unanswered?: true }
  | { kind: "unknown" }
  /** The server answered 401: this session no longer works (the account may be gone). */
  | { kind: "session_gone" };

/**
 * The submit. The master-password proof is derived through the account's fenced reauth (`Account.reauthAuthKey`: the KDF
 * floor, only this session's salt, and the derivation proved by opening this session's UVK), so a wrong password is caught
 * HERE and never sent. Then the one request; `onSend` fires just before it (App holds a session end that lands while it is
 * in flight). A transport failure, a timeout, a 5xx or a reply that is not the server's JSON is the ambiguous case — it may
 * have committed — and is reported as `unknown`, never as a failure; a 401, before or on the request, is `session_gone`.
 */
export async function runAccountDeletion(
  client: Pick<ApiClient, "accountKeys" | "deleteAccount">,
  account: Pick<Account, "reauthAuthKey">,
  input: { email: string; password: string; totp: string; totpRequired: boolean },
  onSend?: () => void,
): Promise<DeletionOutcome> {
  let currentAuthKey: string;
  try {
    currentAuthKey = await account.reauthAuthKey(input.password, await client.accountKeys());
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return { kind: "session_gone" };
    if (e instanceof TypeError) return { kind: "error", message: deleteErrorText(e), unanswered: true };
    return { kind: "error", message: deleteErrorText(e), ...(e instanceof ApiError ? { code: e.code } : {}) };
  }
  const totp = input.totpRequired ? totpDigits(input.totp) : "";
  onSend?.();
  try {
    const r = await client.deleteAccount({ confirmEmail: input.email.trim(), currentAuthKey, ...(totp ? { totp } : {}) });
    return { kind: "deleted", deletedAt: r.deletedAt };
  } catch (e) {
    if (e instanceof AccountDeleteBlockedError) return { kind: "blocked", blockers: e.blockers };
    if (e instanceof AccountDeleteUnknownError || e instanceof TypeError) return { kind: "unknown" };
    if (e instanceof ApiError && e.status === 401) return { kind: "session_gone" };
    return { kind: "error", message: deleteErrorText(e), ...(e instanceof ApiError ? { code: e.code } : {}) };
  }
}

/** What the "check whether it went through" probe found: the preview answers 200 while the account exists. A 401 means only
 *  that this session no longer works — the deletion's doing, or a revocation's: it does NOT say the account is gone. */
export type DeletionCheck = { kind: "still_here"; preview: AccountDeletePreview } | { kind: "session_ended" } | { kind: "unknown" };

export async function checkDeletion(client: Pick<ApiClient, "accountDeletePreview">): Promise<DeletionCheck> {
  try {
    return { kind: "still_here", preview: await client.accountDeletePreview() };
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return { kind: "session_ended" };
    return { kind: "unknown" };
  }
}

/**
 * The card's flow state, as a pure function of what happened (account-delete.test.ts pins it). `unknown` is sticky until a
 * check or a later answer settles it. A 401 after an unknown outcome is NOT read as the deletion: it says only that this
 * session ended, which a revocation does too, so the card says the account may still exist and offers nothing to forget —
 * and App, which handles every session end (stepDeletionWatch), signs out. `totpRequired` turns on when the server asks
 * for a code the preview did not know about (TOTP enrolled on another device mid-flow).
 */
export interface DeleteFlowState {
  unknown: boolean;
  totpRequired: boolean;
  err: string;
  info: string;
  /** A refusal of the request itself (the preview's blockers are older). */
  refused: AccountDeleteBlocker[] | null;
}

export const initialFlow = (): DeleteFlowState => ({ unknown: false, totpRequired: false, err: "", info: "", refused: null });

export function afterOutcome(s: DeleteFlowState, o: DeletionOutcome): DeleteFlowState {
  const base = { ...s, err: "", info: "" };
  switch (o.kind) {
    case "deleted":
      return base;
    case "blocked":
      return { ...base, unknown: false, refused: o.blockers };
    case "unknown":
      return { ...base, unknown: true };
    case "session_gone":
      return { ...base, err: s.unknown ? SESSION_ENDED_OUTCOME_UNKNOWN : SESSION_ENDED };
    case "error":
      return {
        ...base,
        unknown: o.unanswered ? s.unknown : false,
        err: o.message,
        totpRequired: s.totpRequired || o.code === "totp_code_required",
      };
  }
}

export function afterCheck(s: DeleteFlowState, c: DeletionCheck): DeleteFlowState {
  switch (c.kind) {
    case "still_here":
      return { ...s, unknown: false, err: "", info: NOT_DELETED_AFTER_CHECK, totpRequired: s.totpRequired || c.preview.totpRequired };
    case "session_ended":
      return { ...s, err: SESSION_ENDED_OUTCOME_UNKNOWN, info: "" };
    case "unknown":
      return { ...s, err: UNREACHABLE };
  }
}

/**
 * App's side of a deletion request (spec 03 §13 client duties; design 2026-11-10 §11), as a pure step function so the node
 * test environment can pin it. The server revokes every socket of the account the moment a deletion commits, so a session
 * end — the WebSocket `revoked` frame, or `expired` at a ticket re-mint — can land while the request is still in flight,
 * and signing out right then would unmount the card before it learns the outcome. Such an end is HELD while the request is
 * in flight, and acted on — never dropped — when it settles:
 *  - deleted: App's wipe takes over;
 *  - the server answered and refused (nothing was deleted), or the request was never sent: the end was real → the
 *    ordinary sign-out;
 *  - the answer was lost: the end was, most likely, the deletion's own revocation → App leaves the vault for a card that
 *    offers to forget the account on this browser, or to sign in and check (`offer_forget`);
 *  - a 401: this request deleted nothing, and the session is over → sign out.
 * The hold is bounded twice: the request times out (ApiClient.deleteTimeoutMs), and App steps `hold_expired` after
 * DELETION_HOLD_LIMIT_MS in case no settle ever arrives.
 * After an unknown outcome, a session end seen at any OTHER time — a revocation that lands later, a 401 on the check or on
 * a retry — cannot be told from a real one, so App signs out saying the account may still exist, and nothing offers to
 * forget it: forgetting wipes the spec 01 §5 self-identity records, which exist precisely to catch an account that changed
 * under this browser (an admin's recovery). Only an end seen during the request itself counts as the deletion's own.
 * The watch is tied to the account it was armed for, and a new session (`session_start`: an unlock, a sign-in) clears it
 * unless a request is still in flight — so neither an old unknown outcome nor an old request reaches a later session,
 * least of all another account's.
 */
export interface DeletionWatch {
  /** The account the watch is armed for (its request, its unknown outcome); null when idle. A session end of any OTHER
   *  account is never held, never worded "can't tell", never routed to Forget. */
  userId: string | null;
  /** Between `started` (just before the POST) and its settle. */
  inFlight: boolean;
  /** The first session end of that account that landed while in flight. */
  held: SessionEndKind | null;
  /** The last request's outcome is unknown, and nothing since has settled it. */
  unknown: boolean;
}

export const IDLE_DELETION_WATCH: DeletionWatch = { userId: null, inFlight: false, held: null, unknown: false };

/** Longer than the request can take — ApiClient.deleteTimeoutMs for the POST, plus a token refresh's own bounds between a
 *  401 and its one re-send — so it fires only when no settle ever arrives. */
export const DELETION_HOLD_LIMIT_MS = 120_000;

/** How a request ended, for App: `unsent` — it never reached the server (nothing learned about the account). */
export type DeletionSettle = "deleted" | "refused" | "unsent" | "unknown" | "session_gone";

/** What the card reports; App adds the account the card is for. */
export type DeletionCardEvent =
  | { kind: "started" }
  | { kind: "settled"; outcome: DeletionSettle }
  | { kind: "checked"; result: "still_here" | "session_ended" | "unreachable" };

export type DeletionWatchEvent =
  | (DeletionCardEvent & { userId: string })
  /** A session ended (the WebSocket `revoked` frame, `expired` at a ticket re-mint) — whose, if this tab knows. */
  | { kind: "session_end"; end: SessionEndKind; userId: string | null }
  /** A session began in this tab (an unlock, a sign-in — perhaps of another account). */
  | { kind: "session_start" }
  /** App's belt: no settle arrived within DELETION_HOLD_LIMIT_MS of `started`. */
  | { kind: "hold_expired" };

export type DeletionWatchAction =
  | { kind: "none" }
  /** Sign out that account's session (the self-identity records stay); `notice` replaces the kind's own line. */
  | { kind: "end_session"; userId: string | null; end: SessionEndKind; notice?: string }
  /** Sign that account out onto the card that offers to forget it (DELETION_MOST_LIKELY_DONE). */
  | { kind: "offer_forget"; userId: string; end: SessionEndKind };

export function settledOutcome(o: DeletionOutcome): DeletionSettle {
  switch (o.kind) {
    case "deleted":
      return "deleted";
    case "blocked":
      return "refused";
    case "error":
      return o.unanswered ? "unsent" : "refused";
    case "unknown":
      return "unknown";
    case "session_gone":
      return "session_gone";
  }
}

export function checkedResult(c: DeletionCheck): "still_here" | "session_ended" | "unreachable" {
  return c.kind === "unknown" ? "unreachable" : c.kind;
}

export function stepDeletionWatch(w: DeletionWatch, e: DeletionWatchEvent): { watch: DeletionWatch; action: DeletionWatchAction } {
  const none: DeletionWatchAction = { kind: "none" };
  const idle = IDLE_DELETION_WATCH;
  if (e.kind === "session_start") {
    // An outcome nothing settled belonged to the session that ended; a request still in flight keeps its watch — tied to
    // its account, so the new session's own ends pass it by.
    return { watch: w.inFlight ? w : idle, action: none };
  }
  if (e.kind === "hold_expired") {
    return w.inFlight && w.userId !== null ? stepDeletionWatch(w, { kind: "settled", outcome: "unknown", userId: w.userId }) : { watch: w, action: none };
  }
  if (e.kind === "session_end") {
    // Not the account the watch is armed for: an ordinary end — never held, never "can't tell", never Forget.
    if (e.userId === null || e.userId !== w.userId) return { watch: w, action: { kind: "end_session", userId: e.userId, end: e.end } };
    if (w.inFlight) return { watch: { ...w, held: w.held ?? e.end }, action: none };
    // After an unknown outcome, an end this browser cannot tie to the deletion: sign out, saying the account may still exist.
    return { watch: idle, action: { kind: "end_session", userId: e.userId, end: e.end, ...(w.unknown ? { notice: SESSION_ENDED_OUTCOME_UNKNOWN } : {}) } };
  }
  // A card's event: the watch follows the account it is for (a stale watch of another account gives way).
  const u = e.userId;
  const s = u === w.userId ? w : { ...idle, userId: u };
  const ended = (end: SessionEndKind, notice?: string): DeletionWatchAction =>
    s.unknown ? { kind: "end_session", userId: u, end, notice: SESSION_ENDED_OUTCOME_UNKNOWN } : { kind: "end_session", userId: u, end, ...(notice ? { notice } : {}) };
  if (e.kind === "started") {
    // A held end is kept, never dropped (there is none in practice: every settle consumes it).
    return { watch: { ...s, inFlight: true }, action: none };
  }
  if (e.kind === "checked") {
    if (e.result === "still_here") return { watch: { ...s, unknown: false }, action: none };
    if (e.result === "session_ended") return { watch: idle, action: ended("expired") };
    return { watch: s, action: none };
  }
  switch (e.outcome) {
    case "deleted":
      return { watch: idle, action: none };
    case "refused":
      // The server answered a live session, so the account exists: an earlier unknown is settled too, and an end held
      // meanwhile was a real one.
      return { watch: idle, action: s.held ? { kind: "end_session", userId: u, end: s.held } : none };
    case "unsent":
      // Nothing reached the server, so nothing was learned about the account.
      return s.held ? { watch: idle, action: ended(s.held) } : { watch: { ...s, inFlight: false }, action: none };
    case "unknown":
      if (s.held) return { watch: idle, action: { kind: "offer_forget", userId: u, end: s.held } };
      return { watch: { ...idle, userId: u, unknown: true }, action: none };
    case "session_gone":
      return { watch: idle, action: s.held ? ended(s.held) : ended("expired", SESSION_ENDED) };
  }
}

/** The notice on the sign-in card after a deletion this browser ran. */
export const ACCOUNT_DELETED_NOTICE =
  "Your andvari account was deleted. Everything only it held is gone from the server, and this browser kept nothing of it.";

/** The notice after the member chose to forget an account whose deletion's answer was lost (it no longer signs in). */
export const ACCOUNT_FORGOTTEN_NOTICE =
  "This browser forgot the account. It no longer signed in, so its deletion most likely went through; if it still exists after all, sign in again.";
