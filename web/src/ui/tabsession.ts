import type { ApiClient, Tokens } from "../api/client";
import { revokeSessionBestEffort, SESSION_STORAGE_KEY, type Session } from "./session";

/**
 * Security review 2026-10, A14 review 1 (W1, W4, W5, W7, We): the per-tab token rules App applies on
 * a browser without the offline copy (spec 05 A14(h)), as functions of the tab's client so they can
 * be driven by tests. App owns the phases; these own what happens to the pair.
 */

type TokenHolder = Pick<ApiClient, "getTokens" | "setTokens" | "logout">;
type BindableHolder = TokenHolder & Pick<ApiClient, "boundUserId">;

/**
 * A per-tab lock's token half: let the Vault's usage flush land (bounded; a failure is ignored),
 * revoke the pair while it is still held (logout() captures it synchronously), then drop it.
 * Resolves to `{ revoked }`: the revocation's own promise (true: the server confirmed it), wrapped so
 * the lock does not wait for it, for App to record for a later sign-out (W1) and to say when it
 * failed; null when this tab held no pair or [revoke] is false. Never throws, and never returns with the pair still in the client (W7): ApiClient.setTokens
 * clears its field before the persistence hook runs, so even a hook that throws leaves no pair.
 */
export async function lockTabTokens(
  client: TokenHolder | null,
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
  const revoked = opts.revoke ? revokeSessionBestEffort(client) : null;
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
 * A14 review 3: a sign-in that fails after login() succeeded used to keep the new device session's pair in the
 * tab's memory, live and unrevoked, until the next sign-in replaced it. This revokes it (logout() captures it now)
 * and drops it, rebinding the client to a placeholder first so dropping it writes nothing under any session.
 * Returns the revocation's result, or null when the client held no pair.
 */
export function abandonSignIn(client: BindableHolder): Promise<boolean> | null {
  client.boundUserId = pendingSignInBinding();
  if (!client.getTokens()) return null;
  const revoked = revokeSessionBestEffort(client);
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
  | { kind: "adopt"; tokens: Tokens; revokeOwnFirst: boolean };

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
  const t = after?.tokens;
  if (after && t && after.userId === ctx.activeUserId && (!ctx.have || ctx.have.refreshToken !== t.refreshToken)) {
    const wasPerTab = e.oldValue !== null && oldTokens === null;
    return { kind: "adopt", tokens: t, revokeOwnFirst: wasPerTab && ctx.have !== null };
  }
  return { kind: "ignore" };
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
