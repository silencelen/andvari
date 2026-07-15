import { ApiClient, type Tokens } from "../api/client";
import { idbSupported, openVaultCache, vaultDbName } from "../vault/idbcache";
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

/** design 2026-07-13-web-offline-cache §E.3.2: the per-device opt-out marker. Written by the S5
 *  settings toggle ({@link setOfflineCopyEnabled}); its mere presence forces the cache OFF. */
const CACHE_OPT_OUT_KEY = "andvari.cacheOptOut";
/** §E.3.3: the per-device opt-IN marker for the PUBLIC break-glass origin, where the cache defaults
 *  OFF. Written by the settings toggle when flipped ON there; ignored wherever an opt-out or the org
 *  policy bit says no. (S5 ships the gate + marker; the public origin has no in-settings entry point
 *  yet — the card is hidden there until opted in — so the writer today is a future one-tap prompt.) */
const CACHE_OPT_IN_KEY = "andvari.cacheOptIn";
/** §E.4 policy row: the LAST-KNOWN `offlineCacheAllowed === false` pin, written on every successful
 *  ClientPolicy fetch ({@link applyOrgOfflineCachePolicy}) and honored on OFFLINE boot — a device that
 *  saw the org forbid caching keeps refusing to create one until a later fetch says otherwise
 *  (Android persisted-policy parity, spec 02 §8). Presence = disallowed; absence = allowed. */
const ORG_CACHE_OFF_KEY = "andvari.orgCacheOff";
/** §B.5: navigator.storage.persist() has been REQUESTED once on this device (advisory, never
 *  re-nagged — Firefox surfaces a doorhanger). The settings toggle's explicit ON re-requests. */
const PERSIST_REQUEST_KEY = "andvari.persistRequested";

/** Guarded localStorage reads/writes — unreachable storage (non-window context, privacy mode)
 *  degrades to "marker absent" / silent no-op, matching the gate's historical fall-through. */
function lsGet(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function lsSet(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unreachable — the caller's behavior degrades to the origin default */
  }
}
function lsRemove(key: string): void {
  try {
    localStorage.removeItem(key);
  } catch {
    /* storage unreachable */
  }
}

/**
 * design 2026-07-13-web-offline-cache §F.1/§E.3.3 — the durable-offline-cache GATING PREDICATE (the
 * "dark-ship gate"). The two openVaultCache call sites that stand up a durable cache — the
 * returning-session unlock (unlock.ts) and the SignIn seed (Welcome.tsx) — consult this and fall back
 * to a cache-less NullCache when it is false, so the public break-glass origin keeps
 * today's no-at-rest-cache behavior by default. True iff, in order:
 *   1. IndexedDB is usable at all (Firefox private windows etc. refuse — idbSupported), AND
 *   2. the ORG allows it: the last-known `offlineCacheAllowed === false` pin is absent (§E.4 policy
 *      row — written on every successful policy fetch, honored on offline boot; false ⇒ NEVER cache,
 *      beating every device-level choice), AND
 *   3. this device has NOT opted out (the "andvari.cacheOptOut" marker is absent — the S5 settings
 *      toggle writes it), AND
 *   4. the origin default is ON: a PRIVATE origin (tailnet *.ts.net / LAN RFC1918 / localhost, via
 *      isPrivateOrigin) defaults the cache ON; the PUBLIC origin (andvari.monahanhosting.com — anything
 *      else) defaults it OFF and enables only via the explicit per-device opt-IN marker. A tailnet/LAN
 *      browser is an enrolled personal device by construction; the public origin exists for
 *      borrowed/emergency machines (CF Access + TOTP), so caching there is opt-in only.
 */
export function webCacheEnabled(): boolean {
  if (!idbSupported()) return false;
  if (lsGet(ORG_CACHE_OFF_KEY) !== null) return false; // org policy: false ⇒ never cache (§E.4)
  if (lsGet(CACHE_OPT_OUT_KEY) !== null) return false; // per-device opt-out (§E.3.2)
  const origin = typeof window !== "undefined" && window.location ? window.location.origin : "";
  if (isPrivateOrigin(origin)) return true;
  return lsGet(CACHE_OPT_IN_KEY) !== null; // public origin: explicit opt-in only (§E.3.3)
}

/** §E.4: the org policy currently pins the cache OFF on this device (last-known bit — see
 *  {@link applyOrgOfflineCachePolicy}). The settings card reads this to explain WHY the
 *  toggle is unavailable rather than showing a mysteriously-off switch. */
export function orgOfflineCacheDisallowed(): boolean {
  return lsGet(ORG_CACHE_OFF_KEY) !== null;
}

/**
 * §B.5: request durable (eviction-protected) storage for this origin — advisory, result surfaced in
 * the settings row via navigator.storage.persisted(). LOAD-BEARING beyond display: S4's offline-write
 * queue path (`store.offlineQueueAllowed`) is offered only while persisted() is TRUE, so until
 * persist() is REQUESTED at least once, offline writes stay push-or-throw everywhere. Records the
 * request under {@link PERSIST_REQUEST_KEY} so the once-per-device auto path never re-nags (Firefox
 * shows a user-visible doorhanger); an explicit settings-toggle ON calls this directly (a deliberate
 * user gesture may re-prompt). Never rejects; absent API ⇒ false and NO marker (a browser that gains
 * the API later still gets the one auto-request).
 */
export async function requestCachePersistence(): Promise<boolean> {
  try {
    const s = typeof navigator !== "undefined" ? navigator.storage : undefined;
    if (typeof s?.persist !== "function") return false;
    lsSet(PERSIST_REQUEST_KEY, String(Date.now()));
    return (await s.persist()) === true;
  } catch {
    return false;
  }
}

/**
 * §B.5: the ONCE-per-device persist() request, fired at cache-enable — the first time a DURABLE cache
 * is stood up (returning-session unlock, SignIn seed, settings toggle ON). Idempotent across the
 * multiple call sites via the request marker; fire-and-forget (the grant result is read live by the
 * settings row, never awaited on the unlock path).
 */
export function ensureCachePersistenceRequested(): void {
  if (lsGet(PERSIST_REQUEST_KEY) !== null) return; // already asked on this device — never re-nag
  void requestCachePersistence();
}

/**
 * §E.3.2 the per-device "Keep an offline copy on this device" toggle (settings card).
 *  - OFF: pin the opt-out marker FIRST (the gate closes synchronously, so a concurrent unlock can't
 *    re-create mid-wipe), drop any public-origin opt-in, then WIPE this account's cache DB —
 *    envelopes + queue + holding + cached accountKeys (§E.4 "opt-out toggled off" row; the queue is
 *    destroyed with it, so the CALLER gates on a confirm when unsynced edits exist, breaker #9).
 *  - ON: clear the opt-out; on the PUBLIC origin additionally pin the explicit opt-in (§E.3.3 — the
 *    private-origin default is already ON); then request eviction protection (§B.5 — an explicit
 *    gesture, so this bypasses the once-marker dedup). The cache itself is (re-)created by the next
 *    unlock / sign-in seed — this session's store keeps its current cache shape.
 */
export async function setOfflineCopyEnabled(userId: string, enabled: boolean): Promise<void> {
  if (!enabled) {
    lsSet(CACHE_OPT_OUT_KEY, String(Date.now()));
    lsRemove(CACHE_OPT_IN_KEY);
    await wipeVaultCache(userId);
    return;
  }
  lsRemove(CACHE_OPT_OUT_KEY);
  const origin = typeof window !== "undefined" && window.location ? window.location.origin : "";
  if (!isPrivateOrigin(origin)) lsSet(CACHE_OPT_IN_KEY, String(Date.now()));
  await requestCachePersistence();
}

/**
 * §E.4 policy row (spec 02 §8 "re-evaluated on every successful policy fetch"): apply the org's
 * `offlineCacheAllowed` bit. false ⇒ pin the last-known bit (synchronously — webCacheEnabled consults
 * it from this instant, and an OFFLINE boot keeps honoring it) and FORCE-WIPE the signed-in account's
 * cache DB — deleteDatabase destroys the queue too (server-initiated, spec 03 §4-style silent drop;
 * unlike a user sign-out this cannot be blocked). true ⇒ clear the pin; nothing is created here —
 * creation stays with the gated unlock/sign-in paths. Called from App.loadPolicy on every successful
 * ClientPolicy fetch.
 */
export async function applyOrgOfflineCachePolicy(allowed: boolean, userId: string | null): Promise<void> {
  if (allowed) {
    lsRemove(ORG_CACHE_OFF_KEY);
    return;
  }
  lsSet(ORG_CACHE_OFF_KEY, String(Date.now()));
  if (userId) await wipeVaultCache(userId);
}

/**
 * §E.3.4 Unlock transparency line: does THIS device hold a durable offline copy for `userId`, and
 * as of when? Returns null when there is no cache DB — the probe MUST NOT create one (an IDB open
 * creates on demand, which would mint an at-rest artifact just by rendering the Unlock card on the
 * public origin). NON-CREATING END-TO-END (S5 review F1): the DB is opened via {@link openIfExists}
 * — no version, a missing DB's just-started creation aborted + rolled back — and the stamp is read
 * through THAT handle. The previous exists-check-then-`openVaultCache` shape left a gap where a
 * concurrent wipe (org-policy flip / sign-out in another tab) could delete the DB between the two,
 * so the creating re-open minted an empty owner-stamped husk on a device where caching had just
 * been forbidden. An existing-but-empty DB (no cached accountKeys AND no sync stamp — e.g. the
 * husk a pre-wipe count left behind) also reads as null: there is nothing there to be transparent
 * about. Never rejects — the line is an affordance; unlock must render regardless.
 */
export async function offlineCopyStamp(userId: string): Promise<{ lastSyncAt: number | null } | null> {
  const db = await openIfExists(vaultDbName(userId));
  if (!db) return null;
  try {
    // Raw kv reads over the probe's own handle. "kv" + the key names + the { key, value } row
    // shape are the frozen idbcache §B.2 schema (design §A rows 1+6 name kv:lastSyncAt /
    // kv:accountKeys) — the VaultCache surface is deliberately NOT used here, because reaching
    // it requires the creating openVaultCache.
    const kv = db.transaction("kv", "readonly").objectStore("kv");
    const read = (key: string): Promise<unknown> =>
      new Promise((resolve, reject) => {
        const r = kv.get(key);
        r.onsuccess = () => resolve(r.result && typeof r.result === "object" ? (r.result as { value?: unknown }).value : undefined);
        r.onerror = () => reject(r.error ?? new Error("IndexedDB read failed"));
      });
    const [syncRaw, keysRaw] = await Promise.all([read("lastSyncAt"), read("accountKeys")]);
    const lastSyncAt = typeof syncRaw === "number" ? syncRaw : null;
    return (typeof keysRaw === "object" && keysRaw !== null) || lastSyncAt !== null ? { lastSyncAt } : null;
  } catch {
    return null; // kv store missing (coherence-broken DB) or a wipe raced the read — nothing to disclose
  } finally {
    try {
      db.close();
    } catch {
      /* already closed */
    }
  }
}

/**
 * Non-creating open for the probe (see {@link offlineCopyStamp}): open WITHOUT a version — an
 * existing DB opens as-is; a MISSING one fires onupgradeneeded, where aborting the versionchange
 * tx ROLLS BACK the just-started creation and the request settles as an error ⇒ null. The
 * standard non-creating idiom, but returning the live handle so the caller's reads ride THIS
 * open — no exists-then-reopen gap for a concurrent wipe to slip a fresh create into. The handle
 * self-closes on versionchange (idbcache §D.5.3 posture) so a sibling deleteDatabase never blocks
 * on a lingering probe connection.
 */
function openIfExists(name: string): Promise<IDBDatabase | null> {
  let f: IDBFactory | undefined;
  try {
    f = (globalThis as { indexedDB?: IDBFactory }).indexedDB ?? undefined;
  } catch {
    return Promise.resolve(null); // privacy modes can THROW on access (idbcache §B.5)
  }
  if (!f) return Promise.resolve(null);
  return new Promise((resolve) => {
    let req: IDBOpenDBRequest;
    try {
      req = f.open(name);
    } catch {
      return resolve(null);
    }
    req.onupgradeneeded = () => {
      // Missing DB — this open began CREATING it. Abort the versionchange tx: the creation
      // rolls back (nothing is minted, no owner stamp) and the request errors (AbortError).
      try {
        req.transaction?.abort();
      } catch {
        /* already aborting */
      }
    };
    req.onsuccess = () => {
      const db = req.result;
      db.onversionchange = () => db.close(); // never block a sibling wipe (§D.5.3)
      resolve(db);
    };
    req.onerror = () => resolve(null); // AbortError from the rolled-back create, or a broken factory
  });
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
