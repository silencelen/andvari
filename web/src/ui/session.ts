import { ApiClient, LOGOUT_TIMEOUT_MS, type Tokens } from "../api/client";
import { idbSupported, openVaultCache, vaultDbName } from "../vault/idbcache";

/**
 * The session: non-secret metadata persisted across reloads, plus the token pair. The vault KEY is
 * NEVER persisted — a reload always re-prompts for the master password (spec 01 §8: web has no
 * quick-unlock).
 *
 * WHERE THE TOKENS LIVE (security review 2026-10, A14 F5 — owner decision: "a browser not opted
 * into the offline copy keeps no token once locked"):
 *  - offline copy ON for this user on this browser ({@link webCacheEnabled}): today's behaviour —
 *    the pair rides the localStorage session, shared by every tab (the F25 Web Lock + re-read
 *    keeps their rotations from colliding);
 *  - otherwise: localStorage keeps the metadata only (`tokens: null` — its REMOVAL is the F27
 *    cross-tab sign-out signal), and each TAB holds its own pair in sessionStorage
 *    ({@link TAB_TOKENS_KEY}). A tab with no pair signs in (a new device session of its own, so tabs
 *    never share one rotating refresh token); a lock revokes the tab's pair and drops it (App).
 * {@link saveSession} places the pair by that rule every time it writes, so a toggle of the offline
 * copy moves it at once ({@link setOfflineCopyEnabled}, {@link applyOrgOfflineCachePolicy}), and
 * {@link migrateLegacySessionTokens} moves a pre-A14 pair off disk at load.
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

/** This tab's token slot in sessionStorage (A14 F5): `{ tabId, userId, tokens }`. Per tab, never on
 *  disk — but browsers COPY sessionStorage into a duplicated tab, hence {@link claimTabTokens}. */
export const TAB_TOKENS_KEY = "andvari.tabTokens";

interface TabSlot {
  tabId: string;
  userId: string;
  tokens: Tokens;
}

function ssGet(key: string): string | null {
  try {
    return typeof sessionStorage === "undefined" ? null : sessionStorage.getItem(key);
  } catch {
    return null;
  }
}
function ssSet(key: string, value: string): void {
  try {
    sessionStorage.setItem(key, value);
  } catch {
    /* storage unreachable: the pair then lives only in this tab's memory (the ApiClient) */
  }
}
function ssRemove(key: string): void {
  try {
    sessionStorage.removeItem(key);
  } catch {
    /* storage unreachable */
  }
}

function readSlot(): TabSlot | null {
  const raw = ssGet(TAB_TOKENS_KEY);
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as Partial<TabSlot>;
    const t = s.tokens as Partial<Tokens> | undefined;
    if (typeof s.tabId !== "string" || typeof s.userId !== "string" || typeof t?.accessToken !== "string" || typeof t.refreshToken !== "string") return null;
    return { tabId: s.tabId, userId: s.userId, tokens: { accessToken: t.accessToken, refreshToken: t.refreshToken } };
  } catch {
    return null;
  }
}

/** Drop this tab's pair (a per-tab lock, a sign-out). */
export function clearTabTokens(): void {
  ssRemove(TAB_TOKENS_KEY);
}

/** True when a lock keeps this user's tokens (the offline copy is on): today's behaviour. */
export function tokensKeptAcrossLock(userId: string): boolean {
  return webCacheEnabled(userId);
}

// ---- duplicated-tab guard ----
// The id of the tab slot this document has claimed (holds the Web Lock for). Document-lifetime state.
let claimedTabId: string | null = null;

type LockManagerLike = {
  request(name: string, options: { signal?: AbortSignal; ifAvailable?: boolean }, callback: (lock: unknown) => unknown): Promise<unknown>;
};
function lockManager(): LockManagerLike | null {
  const l = typeof navigator !== "undefined" ? (navigator as { locks?: LockManagerLike }).locks : undefined;
  return l && typeof l.request === "function" ? l : null;
}
const tabLockName = (tabId: string): string => `andvari-tab-${tabId}`;

/** Hold `andvari-tab-<tabId>` for the rest of this document's life (the callback never settles).
 *  With [signal] the request waits until it is granted or the signal aborts; without one it only
 *  takes a lock that is free right now (`ifAvailable`), so it can never wait forever. */
function holdTabLock(locks: LockManagerLike, tabId: string, signal?: AbortSignal): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    locks
      .request(tabLockName(tabId), signal ? { signal } : { ifAvailable: true }, (lock) => {
        if (lock === null) {
          resolve(false); // ifAvailable and held elsewhere
          return undefined;
        }
        resolve(true);
        return new Promise(() => {});
      })
      .catch(() => resolve(false));
  });
}

/**
 * Boot (A14 F5): is this tab's slot its own, or a COPY? Chrome's and Firefox's "Duplicate tab" (and a
 * window.open that keeps the opener) copy sessionStorage, pair included, and two tabs spending one
 * single-use refresh token trip the server's reuse heuristic, which revokes the whole device. Each
 * tab with a slot holds a Web Lock named after its tab id for its lifetime; at boot this tab waits a
 * moment (a reloading tab's previous document releases its lock on unload) for its slot's lock. A
 * tab that cannot get it is a copy: it drops the copied pair and signs in on its own. Without Web
 * Locks a copy cannot be told from a reload, and the slot is kept (residual, spec 05 A14).
 */
export async function claimTabTokens(opts: { waitMs?: number } = {}): Promise<void> {
  const slot = readSlot();
  if (!slot || claimedTabId === slot.tabId) return;
  const locks = lockManager();
  if (!locks) return;
  const waitMs = opts.waitMs ?? 1500;
  // No AbortSignal.timeout (some browsers have Web Locks without it): no bounded wait is possible, so
  // only a lock that is free right now counts — a reload that races its previous document's unload
  // then signs in again, which is the safe side.
  const signal = typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(waitMs) : undefined;
  if (await holdTabLock(locks, slot.tabId, signal)) {
    claimedTabId = slot.tabId;
  } else {
    clearTabTokens();
  }
}

/** Test seam: forget this document's claim (a fresh document, as far as the module is concerned). */
export function resetTabClaim(): void {
  claimedTabId = null;
}

/** The tab id this document's slot is written under, claiming a fresh one (and its lock) if needed. */
function ownTabId(): string {
  if (claimedTabId) return claimedTabId;
  const id = crypto.randomUUID();
  const locks = lockManager();
  if (locks) void holdTabLock(locks, id);
  claimedTabId = id;
  return id;
}

function readPersisted(): Session | null {
  const raw = localStorage.getItem(KEY);
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as Session;
    return { ...s, isAdmin: !!s.isAdmin, tokens: s.tokens ?? null }; // sessions saved before P4 lack isAdmin
  } catch {
    return null;
  }
}

export function loadSession(): Session | null {
  const meta = readPersisted();
  if (!meta) return null;
  if (tokensKeptAcrossLock(meta.userId)) return meta; // offline copy ON: today's behaviour
  // Per-tab: only THIS tab's own pair, and only for the account the metadata names — another
  // tab may have signed a different member in since this tab wrote its slot.
  const slot = readSlot();
  return { ...meta, tokens: slot && slot.userId === meta.userId ? slot.tokens : null };
}

export function saveSession(s: Session): void {
  if (tokensKeptAcrossLock(s.userId)) {
    localStorage.setItem(KEY, JSON.stringify(s));
    clearTabTokens();
    return;
  }
  localStorage.setItem(KEY, JSON.stringify({ ...s, tokens: null }));
  if (s.tokens) ssSet(TAB_TOKENS_KEY, JSON.stringify({ tabId: ownTabId(), userId: s.userId, tokens: s.tokens } satisfies TabSlot));
  else clearTabTokens();
}

export function clearSession(): void {
  localStorage.removeItem(KEY);
  clearTabTokens();
}

/**
 * A14 F5 migration, at load: a pre-A14 session carrying its pair in localStorage on a browser that
 * does not keep the offline copy has the pair moved off disk at once — into this tab's slot, unless
 * this tab already holds its own pair for that account (then the disk copy is simply dropped).
 */
export function migrateLegacySessionTokens(): void {
  const meta = readPersisted();
  if (!meta?.tokens || tokensKeptAcrossLock(meta.userId)) return;
  const own = readSlot();
  saveSession({ ...meta, tokens: own && own.userId === meta.userId ? own.tokens : meta.tokens });
}

/** Re-place the persisted pair after the offline-copy gate changed (A14 F5). [before] is the session
 *  as read under the OLD placement. */
function rehomeSessionTokens(before: Session | null, userId: string | null): void {
  if (before && userId !== null && before.userId === userId) saveSession(before);
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
 * wipe of this account's cache would destroy. Two callers, two jobs (H135 split them, R07
 * corrected this note): SignOutLink reads it at click time to arm the inline confirm that
 * BLOCKS a user sign-out ("N unsynced changes will be lost"), and App.signOut — the
 * unconditional wipe choke point — reads it to SURFACE the count on a definitive-401 wipe it
 * cannot block. Opens read-only then closes; 0 on a NullCache / unsupported IDB /
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

/** design 2026-07-13-web-offline-cache §E.3.2: the per-device opt-out marker (device-wide — "this
 *  browser keeps no offline copies, for anyone"). Written by the S5 settings toggle
 *  ({@link setOfflineCopyEnabled}) and by declining the one-time nudge ({@link declineCacheNudge});
 *  its mere presence forces the cache OFF and suppresses the nudge. */
const CACHE_OPT_OUT_KEY = "andvari.cacheOptOut";
/** design 2026-07-15-multi-tenant-endpoints §5.4.1: the per-(device, user) opt-IN marker. The
 *  durable cache now defaults OFF on EVERY origin (the origin heuristic is deleted — walk-up
 *  browsers are the T3 case everywhere) and turns on only via this explicit consent, written by
 *  the settings toggle, the one-time post-unlock nudge (B2-11), or the continuity boot migration
 *  ({@link migrateCacheConsentOnce}). Per-user so one member's consent on a shared browser never
 *  mints an at-rest artifact for another; localStorage is origin-partitioned, so the marker is
 *  (origin, device, user)-scoped by construction. */
const cacheOptInKey = (userId: string): string => `andvari.cacheOptIn.${userId}`;
/** §5.4.1 continuity: the one-time boot-migration flag — the pre-pivot cache (private-origin
 *  default-ON, no marker) has been reconciled into an explicit opt-in on this device. */
const CACHE_CONSENT_MIGRATED_KEY = "andvari.cacheConsentMigrated";
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
 * design 2026-07-13-web-offline-cache §F.1 / 2026-07-15-multi-tenant-endpoints §5.4.1 — the
 * durable-offline-cache GATING PREDICATE (the "dark-ship gate"). The two openVaultCache call sites
 * that stand up a durable cache — the returning-session unlock (unlock.ts) and the SignIn seed
 * (Welcome.tsx) — consult this and fall back to a cache-less NullCache when it is false.
 *
 * The origin heuristic is GONE (origin.ts deleted): origin is just an address, and every origin
 * gets the same formula —
 *
 *     idbUsable && !orgCacheOff && !deviceOptOut && deviceOptIn(userId)
 *
 *   1. IndexedDB is usable at all (Firefox private windows etc. refuse — idbSupported), AND
 *   2. the ORG allows it: the last-known `offlineCacheAllowed === false` pin is absent (§E.4 policy
 *      row — written on every successful policy fetch, honored on offline boot; false ⇒ NEVER cache,
 *      beating every device-level choice), AND
 *   3. this device has NOT opted out (the "andvari.cacheOptOut" marker is absent), AND
 *   4. THIS user explicitly opted in on this device (settings toggle / one-time nudge / continuity
 *      migration). Default OFF everywhere: a walk-up browser is the T3 case on any origin, and
 *      `offlineCacheAllowed=true` from a (possibly hostile) server is necessary but NEVER sufficient
 *      (§2.3 trust table — a server may make the client safer, never laxer). Browser IndexedDB is
 *      origin-partitioned, so (origin, user) isolation holds by construction.
 */
export function webCacheEnabled(userId: string): boolean {
  if (!idbSupported()) return false;
  if (lsGet(ORG_CACHE_OFF_KEY) !== null) return false; // org policy: false ⇒ never cache (§E.4)
  if (lsGet(CACHE_OPT_OUT_KEY) !== null) return false; // per-device opt-out (§E.3.2)
  return lsGet(cacheOptInKey(userId)) !== null; // explicit per-(device, user) opt-in only (§5.4.1)
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
 * §E.3.2 the per-device "Keep an offline copy on this device" toggle (settings card) — also the
 * accept path of the one-time nudge (B2-11).
 *  - OFF: pin the opt-out marker FIRST (the gate closes synchronously, so a concurrent unlock can't
 *    re-create mid-wipe), drop THIS user's opt-in, then WIPE this account's cache DB — envelopes +
 *    queue + holding + cached accountKeys (§E.4 "opt-out toggled off" row; the queue is destroyed
 *    with it, so the CALLER gates on a confirm when unsynced edits exist, breaker #9).
 *  - ON: clear the opt-out and pin this user's explicit opt-in UNCONDITIONALLY — every origin is
 *    opt-in now (design 2026-07-15 §5.4.1; the old `!isPrivateOrigin` guard is gone with origin.ts);
 *    then request eviction protection (§B.5 — an explicit gesture, so this bypasses the once-marker
 *    dedup). The cache itself is (re-)created by the next unlock / sign-in seed — this session's
 *    store keeps its current cache shape.
 */
export async function setOfflineCopyEnabled(userId: string, enabled: boolean): Promise<void> {
  // A14 F5: the session's pair follows the gate — read it under the OLD placement, re-place it after.
  const before = loadSession();
  if (!enabled) {
    lsSet(CACHE_OPT_OUT_KEY, String(Date.now()));
    lsRemove(cacheOptInKey(userId));
    rehomeSessionTokens(before, userId); // off disk, into this tab, before the wipe's await
    await wipeVaultCache(userId);
    return;
  }
  lsRemove(CACHE_OPT_OUT_KEY);
  lsSet(cacheOptInKey(userId), String(Date.now()));
  rehomeSessionTokens(before, userId);
  await requestCachePersistence();
}

/**
 * design 2026-07-15-multi-tenant-endpoints §5.4.1 CONTINUITY — the one-time boot migration. The
 * pre-pivot gate defaulted the cache ON on private origins with NO marker written; the new gate
 * requires an explicit per-user opt-in, so without this every existing private-origin member would
 * silently lose offline access at the flip. Rule (design wording): an existing cache DB with no
 * opt-out marker writes the opt-in marker — the member's standing cache IS the evidence of the old
 * default's consent, so it is adopted, not destroyed.
 *
 * Runs at App boot, BEFORE the first policy fetch / unlock (both consult the gate). One-shot
 * **per user** (`CACHE_CONSENT_MIGRATED_KEY.<userId>`) — NOT per device (review 2026-07-16): a
 * device-wide flag let the first account on a shared browser burn the one shot, so a second
 * pre-pivot account silently lost its standing cache. The flag is only written once a signed-in
 * user is actually evaluated — a signed-out boot has no cache to reconcile (sign-out wipes it,
 * §E.4) and must not burn the shot for the user who signs in later. The DB probe is
 * {@link offlineCopyStamp}: non-creating end-to-end, and an empty husk (no keys, no stamp) reads
 * as "no cache" — a contentless DB grandfathers nothing.
 */
export async function migrateCacheConsentOnce(userId: string | null): Promise<void> {
  if (!userId) return; // nothing to evaluate — leave the one shot for a signed-in boot
  const migratedKey = `${CACHE_CONSENT_MIGRATED_KEY}.${userId}`; // PER-USER — matches the per-user opt-in/nudge markers
  if (lsGet(migratedKey) !== null) return;
  lsSet(migratedKey, String(Date.now()));
  lsRemove("andvari.cacheOptIn"); // the legacy device-wide opt-in key (pre-pivot, writer unreachable)
  if (lsGet(CACHE_OPT_OUT_KEY) !== null) return; // an explicit opt-out always wins (§5.4.1)
  if ((await offlineCopyStamp(userId)) === null) return; // no standing cache — the new default (OFF) stands
  lsSet(cacheOptInKey(userId), String(Date.now()));
}

/**
 * design 2026-07-15-multi-tenant-endpoints §5.4.1 / B2-11 — the ORIGIN-MOVE NUDGE predicate: the
 * one-time "keep an encrypted offline copy on this device?" prompt fires on first unlock at ANY
 * (origin, device) where policy allows and no per-device marker exists. localStorage (and the cache
 * DB) are origin-partitioned, so a member following the household to a new origin lands with a
 * fresh marker namespace — the nudge fires once there and one tap ({@link setOfflineCopyEnabled}
 * ON) re-gains offline access instead of it silently vanishing. True iff the gate is OFF purely
 * for LACK OF AN ANSWER: IndexedDB usable, org policy allows (no §E.4 pin), no device opt-out
 * (a prior "no" — from the toggle or a declined nudge — is never re-asked), and no opt-in for
 * THIS user yet. Answering writes a marker either way, so it can never fire twice for the same
 * (origin, device, user).
 */
export function shouldOfferCacheNudge(userId: string): boolean {
  if (!idbSupported()) return false;
  if (lsGet(ORG_CACHE_OFF_KEY) !== null) return false; // policy forbids — never advertise it
  if (lsGet(CACHE_OPT_OUT_KEY) !== null) return false; // this device already said no
  return lsGet(cacheOptInKey(userId)) === null; // unanswered ⇒ ask once
}

/** B2-11 decline path: "not on this device" pins the device-wide opt-out — the same marker the
 *  settings toggle's OFF writes — so the nudge never re-fires here and the gate stays closed. No
 *  wipe: the nudge only fires where the gate was already off, so no cache DB exists to remove
 *  (and the settings card remains the way back — toggle ON clears the marker). */
export function declineCacheNudge(): void {
  lsSet(CACHE_OPT_OUT_KEY, String(Date.now()));
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
  const before = loadSession(); // A14 F5: the pair follows the gate, like the device toggle
  if (allowed) {
    lsRemove(ORG_CACHE_OFF_KEY);
    rehomeSessionTokens(before, userId);
    return;
  }
  lsSet(ORG_CACHE_OFF_KEY, String(Date.now()));
  rehomeSessionTokens(before, userId);
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
 * unconditionally. Gated on webCacheEnabled(userId) so it never CREATES a cache on a device where
 * caching is off (§5.4.1 — a non-consented device must not gain an at-rest artifact from a password
 * change). Best-effort: any cache failure is swallowed — the change already committed server-side,
 * and the next online unlock re-caches.
 */
export async function refreshCachedAccountKeys(client: Pick<ApiClient, "accountKeys">, userId: string): Promise<void> {
  if (!webCacheEnabled(userId)) return;
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

/**
 * bug-web--0: best-effort server-side revocation on USER sign-out (spec 03: POST /auth/logout
 * revokes every session for this device). Without it "Sign out" leaves the refresh token
 * refreshable server-side for ~30 days and this browser listed as an active device — exactly
 * the bug the natives fixed by awaiting a bounded api.logout() before teardown. Bounded and
 * swallowed: a dead or hung server must never block the local wipe, so this always resolves
 * within ~LOGOUT_TIMEOUT_MS and never rejects. The bound is the client's OWN abort clock
 * (LOGOUT_TIMEOUT_MS), so giving up here also cancels the POST — an uncancelled revocation
 * would keep running past the sign-out and into whatever session comes next. Call it BEFORE
 * clearSession()/setTokens(null) — logout() captures the token pair synchronously at call time,
 * so even a fire-and-forget `void` call from a sync path revokes correctly as long as it is
 * issued first, and clearing the pair is the CALLER's job (logout() no longer does it).
 * Deliberately NOT used for the "expired"/"revoked" sign-out kinds (the session is already dead
 * server-side) and NOT on lock (locking keeps the session — spec 05 T3). Resolves true when the
 * server confirmed the revocation, false otherwise, so a caller can say so.
 */
/** Shown on the sign-in card after a USER sign-out whose server-side revocation was not confirmed
 *  (security review 2026-10): the device is wiped either way, but a copied refresh token may still
 *  be live, and a password change from another device is what ends every session. */
export const REVOKE_UNCONFIRMED =
  "Signed out of this browser, but the server didn't confirm it ended the session. If this was a shared computer, change your master password from another device to end every session.";

export async function revokeSessionBestEffort(client: Pick<ApiClient, "logout"> | null): Promise<boolean> {
  if (!client) return false;
  return Promise.race([
    // true only when the server CONFIRMED the revocation (security review 2026-10) — an expired
    // access token is refreshed once inside logout(), so false now means refused/unreachable/hung,
    // never "the access token had merely expired".
    client.logout().then((resp) => resp.ok, () => false), // refused/unreachable — best-effort
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), LOGOUT_TIMEOUT_MS)),
  ]);
}
