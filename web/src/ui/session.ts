import { ApiClient, type Tokens } from "../api/client";
import { idbSupported, openVaultCache } from "../vault/idbcache";
import { isPrivateOrigin } from "./origin";

/**
 * Non-secret session metadata persisted across reloads. Tokens are here too (MVP);
 * the vault KEY is NEVER persisted — a reload always re-prompts for the master
 * password (spec 01 §8: web has no quick-unlock).
 */
export interface Session {
  baseUrl: string;
  userId: string;
  personalVaultId: string;
  email: string;
  isAdmin: boolean;
  tokens: Tokens | null;
}

/** Exported for App's cross-tab `storage` listener (F27): a removal of THIS key by
 *  another tab means that tab signed out / was revoked. */
export const SESSION_STORAGE_KEY = "andvari.session";
const KEY = SESSION_STORAGE_KEY;

export function loadSession(): Session | null {
  const raw = localStorage.getItem(KEY);
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as Session;
    return { ...s, isAdmin: !!s.isAdmin }; // sessions saved before P4 lack the field
  } catch {
    return null;
  }
}

export function saveSession(s: Session): void {
  localStorage.setItem(KEY, JSON.stringify(s));
}

export function clearSession(): void {
  localStorage.removeItem(KEY);
}

/**
 * §E.4 wipe-by-userId — the durable offline cache is one DB per account
 * (`andvari-vault-<userId>`), so a sign-out / server revocation / definitive-401 deletes
 * exactly that account's DB (envelopes + queue + holding AND the cached accountKeys — the one
 * artifact that removes offline-unlock material). Routed through App.signOut, the ONE wipe
 * choke point (design §E.4). Opens then wipes (deleteDatabase); safe + a no-op on a NullCache /
 * unsupported IndexedDB, and never rejects (idbcache's wipe() contract). A LOCK deliberately
 * does NOT call this — locking is a key-drop, and the cache is retained (spec 05 T3).
 *
 * A sibling connection (this tab's own live store, or another tab) self-closes on the
 * deleteDatabase versionchange (idbcache §D.5.3), so the wipe completes promptly.
 */
export async function wipeVaultCache(userId: string): Promise<void> {
  const cache = await openVaultCache(userId);
  await cache.wipe();
}

/**
 * §E.4 / breaker #9: how many UNSYNCED offline edits (pending + staged-denied queue rows) a
 * wipe of this account's cache would destroy. App.signOut reads it to BLOCK a user sign-out
 * on a confirm ("N unsynced changes will be lost") and to surface the count on a definitive-
 * 401 wipe it cannot block. Opens read-only then closes; 0 on a NullCache / unsupported IDB /
 * any error (a count failure must never wedge sign-out). The store owns the live count while a
 * vault is open (VaultStore.queuedMutationCount); this is the choke-point path where it is not.
 */
export async function pendingSyncCount(userId: string): Promise<number> {
  try {
    const cache = await openVaultCache(userId);
    try {
      const [pending, staged] = await Promise.all([cache.pending(), cache.stagedDenied()]);
      return pending.length + staged.length;
    } finally {
      cache.close();
    }
  } catch {
    return 0;
  }
}

/** design 2026-07-13-web-offline-cache §E.3.2: the per-device opt-out marker. READ-ONLY in S1–S3
 *  (nothing writes it yet); the S5 settings toggle writes it. Its mere presence forces the cache OFF. */
const CACHE_OPT_OUT_KEY = "andvari.cacheOptOut";

/**
 * design 2026-07-13-web-offline-cache §F.1/§E.3.3 — the durable-offline-cache GATING PREDICATE (the
 * "dark-ship gate"). The two openVaultCache call sites that stand up a durable cache — the
 * returning-session unlock (unlock.ts) and the SignIn seed (Welcome.tsx) — consult this and fall back
 * to a cache-less NullCache when it is false, so S1–S3 deploy SAFE: the public break-glass origin keeps
 * today's no-at-rest-cache behavior by default. True iff, in order:
 *   1. IndexedDB is usable at all (Firefox private windows etc. refuse — idbSupported), AND
 *   2. this device has NOT opted out (the "andvari.cacheOptOut" marker is absent — S5 writes it), AND
 *   3. the origin default is ON: a PRIVATE origin (tailnet *.ts.net / LAN RFC1918 / localhost, via
 *      isPrivateOrigin) defaults the cache ON; the PUBLIC origin (andvari.monahanhosting.com — anything
 *      else) defaults it OFF. A tailnet/LAN browser is an enrolled personal device by construction; the
 *      public origin exists for borrowed/emergency machines (CF Access + TOTP), so caching there is
 *      opt-in only.
 * NOTE for S5: the settings toggle that WRITES the opt-out marker, the org offlineCacheAllowed
 * policy-wipe, and the Unlock transparency line remain S5 — this predicate is the seam they build on.
 */
export function webCacheEnabled(): boolean {
  if (!idbSupported()) return false;
  try {
    if (localStorage.getItem(CACHE_OPT_OUT_KEY) !== null) return false;
  } catch {
    // localStorage unreachable (rare / non-window context) — fall through to the origin default.
  }
  const origin = typeof window !== "undefined" && window.location ? window.location.origin : "";
  return isPrivateOrigin(origin);
}

/**
 * §D.2c/§E.4 (S3-2): refresh the durable offline cache's accountKeys after a master-password change.
 * Without this the cache keeps the OLD kdfSalt/kdfParams/wrappedUvk, so an offline unlock rejects the
 * NEW password while the OLD (possibly compromised) password still opens the cached vault until the
 * next online unlock — exactly the spec 05 T3 stale-wrap window (§D.2c lists "after changePassword"
 * as a re-cache write point). floorGood passes on the fresh payload, so setAccountKeys overwrites
 * unconditionally. Gated on webCacheEnabled() so it never CREATES a cache on an origin/device where
 * caching is off (§E.3.3 — the public origin must not gain an at-rest artifact from a password change).
 * Best-effort: any cache failure is swallowed — the change already committed server-side, and the next
 * online unlock re-caches.
 */
export async function refreshCachedAccountKeys(client: Pick<ApiClient, "accountKeys">, userId: string): Promise<void> {
  if (!webCacheEnabled()) return;
  try {
    const cache = await openVaultCache(userId);
    try {
      await cache.setAccountKeys(await client.accountKeys());
    } finally {
      cache.close();
    }
  } catch {
    /* best-effort — a cache failure must never fail a password change that already committed */
  }
}

export function defaultBaseUrl(): string {
  // Same-origin when served by the andvari server; overridable for dev.
  return localStorage.getItem("andvari.baseUrl") ?? "";
}

const INSTALL_ID_KEY = "andvari.installId";

/**
 * Stable per-browser-install id (F28), minted once and kept under its OWN key so it
 * survives sign-out (clearSession touches only the session key). Sent with login so
 * the server can collapse repeat sign-ins from this browser onto one device row once
 * it supports upserting on it (today it ignores the field — see ApiClient.login).
 */
export function installId(): string {
  if (typeof localStorage === "undefined") return crypto.randomUUID(); // non-persistent fallback
  let id = localStorage.getItem(INSTALL_ID_KEY);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(INSTALL_ID_KEY, id);
  }
  return id;
}

export function makeClient(session: Session | null, baseUrl: string): ApiClient {
  // SAME-USER guard: capture WHO this client was created for. On a shared browser the
  // persisted session can come to belong to a DIFFERENT account (user X's frozen tab
  // wakes after user Y signed in) — X's client must neither adopt Y's token pair nor
  // write X's rotations into Y's persisted session. A client created without a session
  // (fresh sign-in form) never adopts; its post-login rotations still persist because
  // by then the persisted session is its own (sign-in replaces it atomically).
  const userId = session?.userId ?? null;
  return new ApiClient(
    baseUrl,
    session?.tokens ?? null,
    (tokens) => {
      const cur = loadSession();
      if (cur && (userId === null || cur.userId === userId)) saveSession({ ...cur, tokens });
    },
    // F25 cross-tab refresh dedup: lets the client re-read, inside the Web Lock, a
    // pair another tab already rotated and adopt it instead of replaying ours —
    // only when that pair belongs to the SAME user this client was created for.
    () => {
      const cur = loadSession();
      return userId !== null && cur?.userId === userId ? cur.tokens : null;
    },
  );
}
