import type { ApiClient, Tokens } from "../api/client";
import type { ReplacedSession, Replaces, SessionInstalled } from "../api/wireclient";
import { isUuid } from "../api/wireids";
import { revokeSessionBestEffort, SESSION_STORAGE_KEY, type Session, unconfirmedRefreshes } from "./session";

const isKeptList = (r: Replaces): r is readonly ReplacedSession[] => Array.isArray(r);

/**
 * Security review 2026-10, A14 review 1 (W1, W4, W5, W7, We): the per-tab token rules App applies on
 * a browser without the offline copy (spec 05 A14(h)), as functions of the tab's client so they can
 * be driven by tests. App owns the phases; these own what happens to the pair.
 */

type TokenHolder = Pick<ApiClient, "getTokens" | "setTokens" | "logout">;
type LockHolder = Pick<ApiClient, "getTokens" | "setTokens" | "endSession">;
type BindableHolder = TokenHolder & Pick<ApiClient, "boundUserId">;
type AbandonHolder = Pick<ApiClient, "getTokens" | "setTokens" | "endSession" | "boundUserId" | "holdsSessionOf">;

/**
 * A per-tab lock's token half: let the Vault's usage flush land (bounded; a failure is ignored),
 * end this tab's session while the pair is still held (endSession() reads it synchronously), then drop it.
 * Spec 03 §2: the lock ends exactly this tab's session by its own refresh token (`end-session`, which
 * also lets a refresh on its way finish first and ends what it brings back, and closes the tab's events socket); the
 * logout would end every tab of this browser for the account. "Sign out" stays the logout ([revokeForSignOut]).
 * Resolves to `{ revoked }`: the end's own promise (true: the server confirmed it), wrapped so
 * the lock does not wait for it, for App to record for a later sign-out (W1) and to say when it
 * failed; null when this tab held no pair or [revoke] is false. Never throws, and never returns with the pair still in the client (W7): ApiClient.setTokens
 * clears its field before the persistence hook runs, so even a hook that throws leaves no pair.
 */
export async function lockTabTokens(
  client: LockHolder | null,
  opts: { flush: (() => Promise<void>) | null; flushWaitMs: number; revoke: boolean },
): Promise<{ revoked: Promise<boolean> | null }> {
  if (opts.flush) {
    const flush = opts.flush;
    await Promise.race([
      Promise.resolve().then(flush).catch(() => {}),
      new Promise<void>((r) => setTimeout(r, opts.flushWaitMs)),
    ]);
  }
  if (!client?.getTokens()) return { revoked: null };
  const revoked = opts.revoke ? client.endSession().catch(() => false) : null;
  try {
    client.setTokens(null);
  } catch {
    /* the persistence hook threw; the in-memory pair is already gone */
  }
  return { revoked };
}

/**
 * W1: the revocation a USER sign-out reports. A pair in this client is revoked now, as before. With
 * none there is nothing to POST — an unauthenticated logout only 401s and read as "the server didn't
 * confirm" on every sign-out after a lock. The answer is then the lock's own revocation of the pair
 * it dropped ([lockRevoke], `revoked` from [lockTabTokens]), or, for a tab that never held a pair, true: no
 * session of this tab's is left to end.
 */
export async function revokeForSignOut(
  client: TokenHolder | null,
  lockRevoke: Promise<boolean> | null,
  lockUnconfirmedOnRecord = false,
): Promise<boolean> {
  if (client?.getTokens()) return revokeSessionBestEffort(client);
  // A14 review 3 (W-b): with no in-memory record (a reload, a new App instance) the tab's sessionStorage record of
  // the last lock is the answer (session.ts lockRevokeUnconfirmed).
  return lockRevoke ?? !lockUnconfirmedOnRecord;
}

/**
 * A14 review 3 (W-a): what the client is bound to between login() and Account.unlock. The login response's userId is
 * the server's word until unlock has checked the keys that came with it; bound to it, a rotation in that window would
 * be written under (and another tab's pair adopted from) whatever session that id names. A fresh random placeholder
 * matches no account, so the persistence hooks write nothing and adopt nothing until Welcome binds the real id.
 */
export function pendingSignInBinding(): string {
  return `pending-sign-in-${crypto.randomUUID()}`;
}

/**
 * One sign-in, registration, kit recovery or unlock on a screen, from its start to its way out. It is the flow's own
 * record, never the client's: two flows on one client (a second one started while the first is busy) each keep theirs.
 *  - A sign-in, registration or kit recovery ([beginSignIn]) records the pair that its OWN login, registration or commit
 *    installed, at the moment the wire installs it ([installed], passed down to that call). Its way out ends that
 *    session and no other: not a pair the tab held before, not a pair another tab rotated and this tab adopted meanwhile.
 *  - An unlock ([beginUnlock]) opens the session the tab already holds: that session is its own.
 */
export interface SignInFlow {
  readonly kind: "sign_in" | "unlock";
  /** Hand this to the flow's login, registration or commit: it records the pair that call installed. */
  readonly installed: SessionInstalled;
  /** The refresh token of the pair the flow's own call installed; null until one was. */
  readonly given: () => string | null;
}

function newFlow(kind: SignInFlow["kind"]): SignInFlow {
  let given: string | null = null;
  return {
    kind,
    installed: (t: Tokens) => {
      given = t.refreshToken;
    },
    given: () => given,
  };
}

/**
 * Every sign-in, registration and kit recovery starts here, before anything is sent: it binds the client to a
 * placeholder until the account is checked ([pendingSignInBinding]) and returns the flow's own record. [abandonSignIn]
 * then ends only the pair that this flow's own call was given.
 */
export function beginSignIn(client: Pick<ApiClient, "boundUserId">): SignInFlow {
  client.boundUserId = pendingSignInBinding();
  return newFlow("sign_in");
}

/**
 * A14 review 3: a sign-in that fails after login() succeeded used to keep the new device session's pair in the
 * tab's memory, live and unrevoked, until the next sign-in replaced it. This ends it and drops it, rebinding the client
 * to a placeholder first so dropping it writes nothing under any session. A refused session is ended alone, by its own
 * refresh token (`end-session`, which reads the pair synchronously): the logout would end every session of this
 * browser's device at the server, other tabs' sessions of the account included. Returns the end's result, or null when
 * nothing of this flow's is held.
 *
 * A sign-in's flow ends only the pair that its own login, registration or commit installed ([SignInFlow.installed]), as
 * this client has kept it (its own refreshes of it included: ApiClient.holdsSessionOf). Any other pair is never ended
 * nor dropped: one the tab held before the sign-in began (a kept session's, whose token may even be one the server
 * already replaced after a refresh's lost answer: sending it would end every session of the browser's row), or one
 * another tab rotated and this tab adopted while the sign-in was under way (the kept session every tab shares). With no
 * flow, nothing is ended: a pair whose origin is not known is not this function's to end. An unlock's flow ends the
 * session the tab holds, which is the one it opened.
 */
export function abandonSignIn(client: AbandonHolder, flow: SignInFlow | null): Promise<boolean> | null {
  if (flow?.kind === "unlock" && client.getTokens()) {
    // An unlock's session is the account the client is bound to: it is ended (or, where a refresh of it got no answer,
    // its token is kept for that account's next sign-in, reading the mark every tab shares) BEFORE the binding resets.
    // Rebound first, the token's keep named no account and nothing was kept.
    const revoked = client.endSession();
    client.boundUserId = pendingSignInBinding();
    try {
      client.setTokens(null);
    } catch {
      /* the in-memory pair is already gone (ApiClient.setTokens clears it before its hook runs) */
    }
    return revoked;
  }
  client.boundUserId = pendingSignInBinding();
  if (!client.getTokens() || flow === null) return null;
  const given = flow.given();
  if (given === null || !client.holdsSessionOf(given)) return null;
  return endAndDrop(client);
}

/**
 * What a sign-in in this tab names as the session it replaces (the login's `replacesRefreshToken`; read BEFORE
 * [beginSignIn] rebinds the client): the pair THIS tab's client holds, by the refresh token it last held (also one the
 * server already replaced after a refresh's lost answer: the server then ends that chain and records it as such, never
 * as a reuse), with the account it is bound to. Named only when that pair is the tab's own: on a browser without the
 * offline copy each tab holds its own session (section AI: a browser's row holds several live sessions, one per tab).
 * Null when the tab holds no pair, when its binding is no account (a sign-in's placeholder: the pair is not known to be
 * this account's), or when the pair is the one every tab shares (the offline copy is on): another tab's session is never
 * named. The wire adds the last condition: the email's row on this browser is the same account's ([WireApi.login]).
 */
export function replacedSession(client: Pick<ApiClient, "boundUserId" | "getTokens">, keptAcrossLock: (userId: string) => boolean): Replaces | null {
  const userId = client.boundUserId;
  const tokens = client.getTokens();
  // A session that ended here because a refresh whose answer never came had no try left (or that a lock or a sign-out
  // dropped while such a refresh stood): its token was kept for this one use (session.ts unconfirmedRefreshes), one per
  // account, and every submit of a sign-in in any tab offers them, since no tab holds those sessions any more. The wire
  // names only the one of the account whose row on this browser the email is ([WireApi.login]).
  if (tokens === null) {
    const kept = unconfirmedRefreshes();
    return kept.length > 0 ? kept : null;
  }
  if (!isUuid(userId)) return null;
  if (keptAcrossLock(userId)) return null;
  return { userId, refreshToken: tokens.refreshToken };
}

/** One sign-in form ([signInForm]): each submit starts its flow here and is told the session it replaces. */
export interface SignInForm {
  submit(): { readonly flow: SignInFlow; readonly replaces: Replaces | null };
}

/**
 * A sign-in form that may be submitted more than once (after the server asks for the two-step code, after a wrong
 * password, after any refusal): EVERY submit names the session it replaces, not only the first. The first submit reads
 * it ([replacedSession]) before its [beginSignIn] binds the client to a placeholder; a later submit finds that
 * placeholder and names what the first one found, as long as the pair the client holds is still that session (its
 * token, or what this client's own refreshes made of it: [ApiClient.holdsSessionOf]), by the token held now. Once the
 * client holds another pair, or none (a login of this form replaced it, a way out ended it), nothing is named. A submit
 * that finds the client bound to an account again reads it afresh.
 */
export function signInForm(client: Pick<ApiClient, "boundUserId" | "getTokens" | "holdsSessionOf">, keptAcrossLock: (userId: string) => boolean): SignInForm {
  let found: Replaces | null = null;
  return {
    submit() {
      const now = replacedSession(client, keptAcrossLock);
      if (now !== null || isUuid(client.boundUserId)) found = now;
      else if (found !== null) {
        const held = client.getTokens();
        // Kept tokens (a list) are named only while the client holds no pair, which [replacedSession] reads afresh.
        found = held !== null && !isKeptList(found) && client.holdsSessionOf(found.refreshToken) ? { userId: found.userId, refreshToken: held.refreshToken } : null;
      }
      return { flow: beginSignIn(client), replaces: found };
    },
  };
}

/**
 * The unlock of a session this browser holds starts here: that session is the one the unlock opens, so a way out of it
 * that the web must take (the card names the account as the operator, §12.2 rule 7; the kit's time limit at the unlock)
 * ends it through [abandonSignIn], by its own refresh token, as before. A "Sign in" from the unlock card starts a sign-in
 * of its own ([beginSignIn]), which then never ends the held session.
 */
export function beginUnlock(): SignInFlow {
  return newFlow("unlock");
}

function endAndDrop(client: AbandonHolder): Promise<boolean> {
  const revoked = client.endSession();
  try {
    client.setTokens(null);
  } catch {
    /* the in-memory pair is already gone (ApiClient.setTokens clears it before its hook runs) */
  }
  return revoked;
}

/** What the `storage` listener does with a change of the persisted session (F27, A14 F5). */
export type StorageVerdict =
  | { kind: "ignore" }
  /** The session was removed: another tab signed out or was revoked. */
  | { kind: "signedOutElsewhere"; revokeOwn: boolean }
  /** Another tab turned the offline copy OFF and took the shared pair this tab was riding. */
  | { kind: "lockWithoutRevoke"; meta: Session }
  /** Another tab persisted a shared pair for this tab's account. */
  | { kind: "adopt"; tokens: Tokens; revokeOwnFirst: boolean }
  /** Design §4.4: the shared pair of this tab's account went, the offline copy still on: the server ended the session. */
  | { kind: "endedElsewhere"; meta: Session };

function tokensIn(raw: string | null): Tokens | null {
  if (!raw) return null;
  try {
    return (JSON.parse(raw) as Session).tokens ?? null;
  } catch {
    return null;
  }
}

/**
 * The listener's decision. [after] is the session as this tab reads it now (loadSession()), [have]
 * the pair this tab's client holds, [activeUserId] the account live in this tab.
 *  - removal: drop this tab's pair; without the offline copy that pair is this tab's OWN device
 *    session, so it is revoked first (W4) — with it, the pair was the shared one the signing-out tab
 *    already revoked;
 *  - the shared pair this tab rode moved into another tab (offline copy turned off there): lock, and
 *    do not revoke, which would end that tab's session;
 *  - the shared pair of this account went while the offline copy stays on: the server ended the session (§4.4);
 *  - a shared pair for this account appeared or rotated: adopt it. When the previous persisted
 *    session carried NO pair, the offline copy was just turned on elsewhere and this tab's pair is its
 *    own per-tab device session: revoke it before adopting (We), so it does not stay live. A rotation
 *    of the shared pair is never revoked: that would end the session every tab now shares.
 */
export function storageVerdict(
  e: { key: string | null; oldValue: string | null; newValue: string | null },
  ctx: { activeUserId: string | null; have: Tokens | null; after: Session | null; keptAcrossLock: (userId: string) => boolean },
): StorageVerdict {
  if (e.key !== SESSION_STORAGE_KEY) return { kind: "ignore" };
  if (e.newValue === null) {
    return { kind: "signedOutElsewhere", revokeOwn: ctx.activeUserId !== null && !ctx.keptAcrossLock(ctx.activeUserId) };
  }
  const oldTokens = tokensIn(e.oldValue);
  const after = ctx.after;
  if (
    after &&
    oldTokens &&
    !ctx.keptAcrossLock(after.userId) &&
    after.userId === ctx.activeUserId &&
    ctx.have?.refreshToken === oldTokens.refreshToken
  ) {
    return { kind: "lockWithoutRevoke", meta: after };
  }
  // §4.4: with the offline copy on a lock keeps the pair, so the shared pair going (the record kept) is the server
  // ending the session: a refused refresh, or another tab's endSessionByServer.
  if (after && oldTokens && after.tokens === null && ctx.keptAcrossLock(after.userId) && after.userId === ctx.activeUserId) {
    return { kind: "endedElsewhere", meta: after };
  }
  const t = after?.tokens;
  if (after && t && after.userId === ctx.activeUserId && (!ctx.have || ctx.have.refreshToken !== t.refreshToken)) {
    const wasPerTab = e.oldValue !== null && oldTokens === null;
    return { kind: "adopt", tokens: t, revokeOwnFirst: wasPerTab && ctx.have !== null };
  }
  return { kind: "ignore" };
}

/**
 * The `storage` event a tab would get for the session every tab shares going, built where this tab's client found it gone
 * from the record first (ApiClient.onEndedElsewhere): the record as it stands for [activeUserId]'s account ([now] kept
 * with no pair reads as the server's end, `endedElsewhere`), or its removal (`signedOutElsewhere`) where it is gone or
 * another account's. Handed to the same listener, so the landing is the event's own.
 */
export function endedInAnotherTabEvent(now: Session | null, activeUserId: string | null): { key: string; oldValue: string; newValue: string | null } {
  const mine = now !== null && now.userId === activeUserId;
  return { key: SESSION_STORAGE_KEY, oldValue: JSON.stringify({ tokens: { accessToken: "", refreshToken: "" } }), newValue: mine ? JSON.stringify(now) : null };
}

/**
 * How a tab whose client found the shared session gone lands: where the record now holds ANOTHER account (another account
 * was signed in on this browser, and with the offline copy on a browser holds one account's session at a time), with a
 * line of its own (ANOTHER_ACCOUNT_SIGNED_IN); otherwise as the `storage` event would land it ([endedInAnotherTabEvent]).
 */
export function endedInAnotherTabLanding(now: Session | null, activeUserId: string | null): { kind: "another_account" } | { kind: "event"; event: ReturnType<typeof endedInAnotherTabEvent> } {
  if (now !== null && activeUserId !== null && now.userId !== activeUserId) return { kind: "another_account" };
  return { kind: "event", event: endedInAnotherTabEvent(now, activeUserId) };
}

/**
 * Design §4.4, [storageVerdict]'s `endedElsewhere` for a tab on the unlock card: the session every tab shares ended in
 * another tab, so this tab's client lets go of the pair it still holds in memory, and nothing of it can leave from here.
 */
export function dropHeldPair(client: Pick<ApiClient, "getTokens" | "setTokens"> | null): void {
  if (!client?.getTokens()) return;
  try {
    client.setTokens(null);
  } catch {
    /* the in-memory pair is already gone (ApiClient.setTokens clears it before its hook runs) */
  }
}

/** W4: apply [storageVerdict]'s removal: revoke this tab's own pair when [revokeOwn], then drop it. */
export function dropOnSignOutElsewhere(client: TokenHolder | null, revokeOwn: boolean): Promise<boolean> | null {
  const revoked = revokeOwn && client?.getTokens() ? revokeSessionBestEffort(client) : null;
  client?.setTokens(null);
  return revoked;
}

/** We: apply [storageVerdict]'s adoption: revoke this tab's own pair first when [revokeOwnFirst]. */
export function adoptSharedPair(client: TokenHolder | null, tokens: Tokens, revokeOwnFirst: boolean): Promise<boolean> | null {
  if (!client) return null;
  const revoked = revokeOwnFirst && client.getTokens() ? revokeSessionBestEffort(client) : null;
  client.setTokens(tokens);
  return revoked;
}

/**
 * W5: whose idle timer runs. An open vault's, as before; and, on a browser without the offline copy,
 * an unlock card that still holds this tab's pair — a reload of an unlocked tab keeps the pair in
 * sessionStorage, and with no timer that pair stayed live for as long as the tab stayed open.
 */
export function idleTimerUserId(vaultUserId: string | null, unlockSession: Session | null, keptAcrossLock: (userId: string) => boolean): string | null {
  if (vaultUserId !== null) return vaultUserId;
  if (unlockSession && unlockSession.tokens && !keptAcrossLock(unlockSession.userId)) return unlockSession.userId;
  return null;
}
