import type { ApiClient, SessionEndKind } from "../api/client";
import { fill, KEPT_CHANGES_MANY, KEPT_CHANGES_ONE, SESSION_NOT_CONFIRMED, SIGN_IN_ENDED_KEPT, UNSENT_LOST_NOT_CONFIRMED, UNSENT_LOST_NOT_CONFIRMED_ONE, unsentLine } from "./copy";
import { clearLockRevoke, clearTabTokens, endedUnconfirmedInThisDocument, loadSession, noteEndedUnconfirmed, saveSession, type Session, tokensKeptAcrossLock, unconfirmedRefresh } from "./session";

/**
 * Design §4.4 "A session the server ends does not delete the device's copy". A refused refresh, a revoked session, or
 * any other answer by which the server ends a session, ends the session: its tokens go (this tab's client, the
 * persisted pair, the tab's slot). What the browser holds stays when the offline copy is on for the account: the copy
 * in IndexedDB (items, the account keys it unlocks with) and its queue of changes not yet sent, the pin, the
 * self-identity records and the session record itself, without a pair, which is how the account now stands here:
 * signed out by the server. The unlock card then offers the sign-in that restores the session (the same account at
 * the same origin, under its pin; the queue is sent then) and the copy, opened read-only with the master password.
 * The web keeps no quick-unlock material (spec 01 §8), so there is none to drop.
 *
 * Only the person's own acts delete the copy: "Sign out", "Forget this server", deleting the account, turning the
 * offline copy off or removing it in Settings, or a policy that forbids an offline copy (`offlineCacheAllowed`).
 *
 * Without the offline copy there is nothing to keep, and today's rule stands: the caller signs out
 * ({@link ServerEnd} `sign_out`).
 */
export type ServerEnd =
  /** The session ended and its tokens went; the copy, its queue and the session record stay. */
  | { readonly kind: "kept"; readonly session: Session }
  /** No offline copy for the account (or no session record): the ordinary sign-out. */
  | { readonly kind: "sign_out" };

export function endSessionByServer(client: Pick<ApiClient, "setTokens"> | null, kind?: SessionEndKind): ServerEnd {
  const s = loadSession();
  if (kind === "unconfirmed" && s !== null) noteEndedUnconfirmed(s.userId);
  if (s === null || !tokensKeptAcrossLock(s.userId)) return { kind: "sign_out" };
  return { kind: "kept", session: dropPair(client, s, kind === "unconfirmed") };
}

/**
 * [s] without its pair, in this tab's client, the persisted record and the tab's slot; the record itself stays. A session
 * that ended here unconfirmed ([unconfirmed]) says so in the same write ({@link Session.endedUnconfirmed}).
 */
function dropPair(client: Pick<ApiClient, "setTokens"> | null, s: Session, unconfirmed = false): Session {
  const { endedUnconfirmed: _was, ...rest } = s;
  const ended: Session = { ...rest, tokens: null, ...(unconfirmed || _was === true ? { endedUnconfirmed: true as const } : {}) };
  try {
    client?.setTokens(null); // the persistence hook writes `tokens: null` for the session this client is bound to
  } catch {
    /* the in-memory pair is already gone (ApiClient.setTokens clears it before its hook runs) */
  }
  saveSession(ended); // and so does this, whatever the client was bound to
  clearTabTokens();
  clearLockRevoke();
  return ended;
}

/**
 * Design §4.4 (decided on 2026-11-17): a sign-in, or an open session, that this browser ends by itself (the recovery kit
 * was not confirmed in time; the account turned out to be the operator's, which the web does not take) deletes nothing
 * the person has not been told about, with the same two steps as every other way out: the number first, and the copy
 * deleted only by the person's own "Sign out" after it. No session stays either way: the caller has already ended the
 * one the sign-in opened (or ends the open one), and the pair goes here.
 *
 * [unsent] is the count of changes this browser's copy holds that were not sent (session.ts unsentChangeCount: null
 * when it cannot tell). With none, and with no session record, the answer is the ordinary sign-out, which deletes the
 * copy as before. Otherwise the copy, its queue and the session record stay, without a pair, and the answer carries the
 * card's line: the browser's own reason, the number (or "cannot tell"), and what stays.
 */
export type ClientEnd =
  /** Nothing unsent: the caller signs out, deleting the copy as before. */
  | { readonly kind: "sign_out" }
  /** Changes not sent, or the browser cannot tell: the copy and the record stay, the pair is gone, and [line] is said. */
  | { readonly kind: "kept"; readonly session: Session; readonly line: string };

export function endByClientDecision(client: Pick<ApiClient, "setTokens"> | null, notice: string, unsent: number | null): ClientEnd {
  const s = loadSession();
  if (s === null || unsent === 0) return { kind: "sign_out" };
  const session = dropPair(client, s);
  return { kind: "kept", session, line: clientEndLine(notice, unsent) };
}

/** The line on the card the person lands on after {@link endByClientDecision} kept the copy. */
export function clientEndLine(notice: string, unsent: number | null): string {
  return [notice, unsentLine(unsent), SIGN_IN_ENDED_KEPT].filter((l): l is string => !!l).join(" ");
}

/**
 * A held session the server ended: the offline copy is on for its account and the record carries no pair. A lock
 * there keeps the pair (session.ts), so a held record without one exists only after the server ended the session:
 * through {@link endSessionByServer}, or a refused refresh that dropped the pair before a reload.
 */
export function endedByServer(s: Session | null): boolean {
  return s !== null && s.tokens === null && tokensKeptAcrossLock(s.userId);
}

/**
 * A held session that ended in this browser because it could not be confirmed with its server in time (api/client.ts
 * noTryLeft: its token is kept for the next sign-in, session.ts unconfirmedRefresh). No server ended it: the card and the
 * copy's notice say that end ({@link SESSION_NOT_CONFIRMED}), never "the server signed this browser out".
 */
export function endedUnconfirmed(userId: string | null): boolean {
  if (userId === null) return false;
  if (endedUnconfirmedInThisDocument(userId)) return true;
  let s: Session | null = null;
  try {
    s = loadSession();
  } catch {
    s = null; // storage unreachable: the record says nothing
  }
  if (s !== null && s.userId === userId && s.endedUnconfirmed === true) return true;
  return unconfirmedRefresh(userId) !== null;
}

/** The line said where a session ends: the browser's own end for a session it could not confirm, else the server's. */
export function sessionEndLine(kind: SessionEndKind): string {
  return kind === "unconfirmed" ? SESSION_NOT_CONFIRMED : kind === "revoked" ? "This device's access was revoked." : "Your session ended — sign in again.";
}

/**
 * The line of a sign-out that deletes this browser's copy (App signOut) about the changes it held unsent: for a session
 * that expired, the count and that it expired; for a session this browser could not confirm, the count in a line of its
 * own ({@link UNSENT_LOST_NOT_CONFIRMED}), never "expired". [notice] first where there is one.
 */
export function lostChangesLine(kind: "user" | SessionEndKind, notice: string | undefined, unsynced: number): string | undefined {
  if (unsynced <= 0 || (kind !== "expired" && kind !== "unconfirmed")) return notice;
  if (kind === "expired") return `${notice ? notice + " " : ""}${unsynced} offline ${unsynced === 1 ? "change" : "changes"} could not be synced — this session expired before reconnecting.`;
  return [notice, unsynced === 1 ? UNSENT_LOST_NOT_CONFIRMED_ONE : fill(UNSENT_LOST_NOT_CONFIRMED, String(unsynced))].filter(Boolean).join(" ");
}

/**
 * The notice above the unlock card a session the server ended (or this browser could not confirm) lands on, with the
 * offline copy kept: the end's [line] and the count of changes kept ([kept]). The card says a session not confirmed
 * itself (Welcome), so the notice does not say it again unless the end came with a notice of its own ([notice]).
 */
export function heldEndNotice(kind: SessionEndKind, notice: string | undefined, line: string, kept: string | undefined): string {
  return [kind === "unconfirmed" && notice === undefined ? undefined : line, kept].filter(Boolean).join(" ");
}

/** The line App adds to its notice when the server ended the session and the kept queue holds changes. */
export function keptChangesLine(unsent: number): string | undefined {
  if (unsent <= 0) return undefined;
  return unsent === 1 ? KEPT_CHANGES_ONE : fill(KEPT_CHANGES_MANY, String(unsent));
}
