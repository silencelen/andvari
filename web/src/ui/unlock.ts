import { ApiClient, ApiError } from "../api/client";
import type { AccountKeys } from "../api/types";
import { assertServerKdfParams, KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import { Account, IdentityMismatchError } from "../vault/account";
import { NullCache, openVaultCache, type VaultCache } from "../vault/idbcache";
import { SyncIntegrityError, VaultStore } from "../vault/store";
import { NetworkError, UNREACHABLE, net } from "./errors";
import { needsRecoveryCapture } from "./recovery-capture";
import { webCacheEnabled, type Session } from "./session";
import type { LoginMeta } from "./Welcome";

/**
 * design 2026-07-13-web-offline-cache §C — the returning-session unlock as a testable seam
 * (the node-env / renderToStaticMarkup test posture can't drive a React form, so — as with
 * recovery-capture.ts — the flow lives here and Welcome's `Unlock.submit` just maps the
 * outcome to state). Online-FIRST with an OFFLINE fallback:
 *
 *   1. Try `client.accountKeys()` (net()-wrapped). SUCCESS ⇒ unlock with the fresh payload +
 *      re-cache it (§D.2c write point). new VaultStore(client, account, cache) → hydrate →
 *      first sync (the S2 wiring contract).
 *   2. `NetworkError` ONLY (net() distinguishes transport from a server answer) ⇒ read the
 *      cached accountKeys, assert the H1 floor at cache-READ (C3, fail closed), Account.unlock
 *      against the CACHED payload (C4 identity hard-fail fires against the cached identityPub),
 *      hydrate, and attempt a non-fatal sync (the Vault's offline dot + F29 poll take over).
 *   3. A SERVER-ANSWERED error NEVER falls back: a definitive 401 (after a refused refresh) ⇒
 *      `expired` (the caller routes it through App.signOut → the §E.4 wipe); a 5xx keeps today's
 *      honest "server had a problem" copy.
 *
 * The function is TOTAL — every expected outcome is a returned {@link UnlockResult}, and the
 * outer catch turns a genuine infra throw (a rare IndexedDB read/write failure) into a
 * retryable error rather than an unhandled rejection in the caller's event handler.
 */

/** Kept byte-identical to today's Welcome copy so no existing behavior text shifts. */
const SERVER_PROBLEM = "The server had a problem answering — your password may be fine. Try again in a moment.";
const WRONG_PASSWORD = "Wrong master password.";

/**
 * The default cache factory — the §F.1/§E.3.3 dark-ship gate (session.webCacheEnabled) decides
 * durable-vs-none: on a PRIVATE origin (tailnet/LAN/localhost, IndexedDB supported, not opted-out) it
 * opens the real per-account IndexedDB cache; on the PUBLIC break-glass origin — or an opted-out /
 * unsupported device — it returns today's cache-less NullCache, so S3 deploys safe everywhere. Injected
 * via the openCache parameter in tests.
 */
async function gatedOpenCache(userId: string): Promise<VaultCache> {
  return webCacheEnabled() ? openVaultCache(userId) : new NullCache();
}

export type UnlockResult =
  | { kind: "ready"; account: Account; store: VaultStore; meta: LoginMeta }
  | { kind: "capture"; account: Account; store: VaultStore; meta: LoginMeta; currentAuthKey: string }
  | { kind: "error"; message: string }
  /** Definitive 401 — the caller routes it through App.signOut so the §E.4 wipe fires. */
  | { kind: "expired" };

export async function unlockExistingSession(
  client: ApiClient,
  session: Pick<Session, "userId" | "isAdmin">,
  password: string,
  /** Injected for tests; defaults to the §F.1/§E.3.3 gated factory (durable on a private origin,
   *  NullCache on the public break-glass origin / opted-out / unsupported — {@link gatedOpenCache}). */
  openCache: (userId: string) => Promise<VaultCache> = gatedOpenCache,
): Promise<UnlockResult> {
  const { userId } = session;
  try {
    // §C.1 step 1 — try the server. net() tags a TRANSPORT failure as NetworkError so a VPN
    // drop / server restart can never be mistaken for a server-answered rejection.
    let onlineKeys: AccountKeys | null = null;
    let allowOffline = false; // ONLY a caught NetworkError (transport) earns the offline cache read
    try {
      onlineKeys = await net(client.accountKeys());
    } catch (e) {
      // §C.1 step 3 — a SERVER-ANSWERED error NEVER falls back to the cache.
      if (!(e instanceof NetworkError)) {
        if (e instanceof KdfPolicyError) return { kind: "error", message: WEAK_KDF_MESSAGE }; // H1 (client.accountKeys asserts)
        if (e instanceof ApiError && e.status === 401) return { kind: "expired" }; // definitive 401 → signOut + §E.4 wipe
        return { kind: "error", message: SERVER_PROBLEM }; // 5xx / garbage body — honest server-problem copy
      }
      allowOffline = true; // NetworkError only → the offline branch may read the cache
    }
    // §C.1 step 3 (S3-4a) — a RESOLVED online call that returned a nullish/non-object body is still a
    // SERVER answer (a 200-empty body makes ApiClient.json() undefined), so it must NOT fall back to the
    // offline cache: "a server-answered response never falls back." Only a caught NetworkError
    // (allowOffline) reaches the cache read; a hostile 200-empty is a server problem, not offline.
    if (!allowOffline && (!onlineKeys || typeof onlineKeys !== "object")) {
      return { kind: "error", message: SERVER_PROBLEM };
    }

    // Cache creation is the §F.1/§E.3.3 gated factory (durable on a private origin, NullCache on the
    // public break-glass origin / opted-out / unsupported — idbSupported() is folded into the gate).
    let cache = await openCache(userId);
    let keys: AccountKeys;
    let offline: boolean;
    if (onlineKeys) {
      // §D.2c online-unlock re-cache write point (setAccountKeys keep-old-on-bad-write is the belt;
      // C3's read-time assert below is the suspenders). S3-4b/§B.4(iii): a runtime cache-WRITE failure
      // (quota/corruption) must NOT fail an unlock the online path could complete cache-less — degrade
      // to NullCache and PROCEED rather than let the throw reach the outer "server had a problem" catch.
      keys = onlineKeys;
      offline = false;
      try {
        await cache.setAccountKeys(keys);
      } catch {
        cache.close();
        cache = new NullCache();
      }
    } else {
      // §C.1 step 2 — offline fallback (NetworkError only; allowOffline is true here).
      const cached = await cache.accountKeys();
      if (!cached) {
        cache.close();
        return { kind: "error", message: UNREACHABLE }; // no cached keys ⇒ today's cold copy
      }
      // Invariant C3 — assert the H1 floor at cache-READ. A planted weak payload refuses offline
      // unlock (fail closed, KdfPolicyError → WEAK_KDF_MESSAGE); the cache is never a floor bypass.
      try {
        assertServerKdfParams(cached.kdfParams);
      } catch {
        cache.close();
        return { kind: "error", message: WEAK_KDF_MESSAGE };
      }
      keys = cached;
      offline = true;
    }

    // §C.4 — the SAME Account.unlock → unlockFromUvk tail: the identity hard-fail fires against
    // the (offline: cached) identityPub. IdentityMismatch is tampering, never "wrong password".
    let account: Account;
    try {
      account = await Account.unlock(userId, password, keys);
    } catch (e) {
      cache.close();
      if (e instanceof IdentityMismatchError) return { kind: "error", message: e.message };
      return { kind: "error", message: WRONG_PASSWORD };
    }

    const store = new VaultStore(client, account, cache);
    // §D.4 — rebuild the working set from cached envelopes, no server call. S3-4b/§B.4(iii): a cache-READ
    // failure (corruption) here must degrade cache-less + PROCEED, never brick an unlock the online path
    // needed no cache for pre-S3. The first sync (online) repopulates from the server, and store.sync()'s
    // own cache commits are already failure-swallowing (commitPull → self-demote), so proceeding is safe.
    try {
      await store.hydrate();
    } catch {
      /* skip-hydrate + proceed in-memory (§B.4 iii) — the cache self-demotes on repeated sync-commit failures */
    }

    if (offline) {
      // Non-fatal (§C.1) — the Vault's offline dot + F29 poll take over. Fire-and-forget with a
      // catch so an offline sync's transport reject is never an unhandled rejection.
      void store.sync().catch(() => {});
    } else {
      try {
        await net(store.sync()); // rediscovers the personal vault id + delivers the delta
      } catch (e) {
        // §D.6 — with a disk-RESTORED cursor the first sync is now a DELTA, so the F31 guards can
        // trip cross-session. State was KEPT + coherent, so PROCEED (the offline dot surfaces the
        // rejected answer). Every other first-sync failure keeps today's copy.
        if (!(e instanceof SyncIntegrityError)) {
          cache.close();
          if (e instanceof ApiError && e.status === 401) return { kind: "expired" };
          if (e instanceof NetworkError) return { kind: "error", message: UNREACHABLE };
          if (e instanceof ApiError) return { kind: "error", message: SERVER_PROBLEM };
          return { kind: "error", message: WRONG_PASSWORD };
        }
      }
    }

    const meta: LoginMeta = {
      isAdmin: session.isAdmin,
      // F61: accountKeys carries no mustChangePassword and web doesn't persist it across a lock —
      // a returning-session unlock cannot observe a flip, so it hardcodes false (Welcome comment).
      mustChangePassword: false,
      escrowStale: keys.escrowStale ?? false,
      escrowFingerprint: keys.escrowFingerprint,
      // §C6 — ONLY the offline path nags; online proceeds to the (unchanged) hard-blocking gate.
      offlineRecoveryReminder: offline && needsRecoveryCapture(keys),
    };

    // §C6 — the ONLINE capture gate is UNCHANGED (hard-block until captured). The OFFLINE path
    // never reaches it: it proceeds with meta.offlineRecoveryReminder (the persistent in-vault nag).
    if (!offline && needsRecoveryCapture(keys)) {
      const currentAuthKey = await Account.deriveAuthKey(password, keys.kdfSalt, keys.kdfParams);
      return { kind: "capture", account, store, meta, currentAuthKey };
    }
    return { kind: "ready", account, store, meta };
  } catch {
    // The flow above is total by construction; an escape here is an unexpected infra error
    // (a genuine IndexedDB failure mid-flow). Fail safe to a retryable message.
    return { kind: "error", message: SERVER_PROBLEM };
  }
}
