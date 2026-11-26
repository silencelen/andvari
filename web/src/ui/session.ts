import { ApiClient, LOGOUT_TIMEOUT_MS, SECOND_TRY_AFTER_MS, type Tokens } from "../api/client";
import { DeviceIdentity, type KeyValue } from "../api/devicesecret";
import { isUuid } from "../api/wireids";
import { idbSupported, openVaultCache, readWaiting, type VaultCache, vaultDbName } from "../vault/idbcache";
import { clearCopyBeingRemoved, detachPolicyWipeNotice, dropHeldPolicyWipes, exclusiveForCopy, markCopyBeingRemoved, type MayWrite, ORG_CACHE_OFF_KEY, releaseCopiesAfterLift, type PolicyWipeLimits, type PolicyWipeNotice, removeCopyForPolicy, type SendOnce } from "../vault/policywipe";
import { boundAccountAt, forgetEarlierRecords, forgetSelfIdentity, forgettingMarks, markForgetting, rememberNextAt, selfIdentityPinKey, unmarkForgetting } from "../vault/selfidentity";
import { emailNorm } from "../crypto/trust/grammar";
import type { CopyKeeper, CopyWrite, SessionKeys } from "../vault/settingsflow";

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
  tokens: Tokens | null;
  /**
   * A held session (no pair) that ended in this browser because a refresh whose answer never came had no try left: no
   * server ended it. Written in the same write that drops the pair (sessionend.ts endSessionByServer), so the card and the
   * copy's notice say that end even where the kept token could not be written. Gone with the next session taken.
   */
  endedUnconfirmed?: true;
}

/** Exported for App's cross-tab `storage` listener (F27): a removal of THIS key by
 *  another tab means that tab signed out / was revoked. */
export const SESSION_STORAGE_KEY = "andvari.session";
const KEY = SESSION_STORAGE_KEY;

/** This tab's token slot in sessionStorage (A14 F5): `{ tabId, userId, tokens }`. Per tab, and gone when
 *  the tab is closed — but NOT guaranteed off disk (A14 review Wb): Chrome and Firefox write
 *  sessionStorage into the profile's session-restore data so a crash restore, "continue where you left
 *  off" or reopen-closed-tab can bring the tab back with it. So an UNLOCKED tab's pair (only an unlocked
 *  tab holds one; a lock drops it) can sit in those files while it is valid, and a tab brought back that
 *  way resumes at the unlock card with its pair; anyone who can read the profile can read it then.
 *  Browsers COPY sessionStorage into a duplicated tab, hence {@link claimTabTokens}. */
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
    // The mark that a refresh of the pair is out rides with it (api/client.ts Tokens.refreshOutAt).
    const mark = typeof t.refreshOutAt === "number" ? { refreshOutAt: t.refreshOutAt, ...(t.refreshTriedAgain === true ? { refreshTriedAgain: true } : {}) } : {};
    return { tabId: s.tabId, userId: s.userId, tokens: { accessToken: t.accessToken, refreshToken: t.refreshToken, ...mark } };
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
  request(name: string, options: { signal?: AbortSignal; ifAvailable?: boolean; mode?: "shared" | "exclusive" }, callback: (lock: unknown) => unknown): Promise<unknown>;
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

/** The Web Lock a tab holds, shared, for as long as it has [userId]'s account open; a forgetting takes it exclusively. */
export const accountOpenLockName = (userId: string): string => `andvari-account-open-${userId}`;

/**
 * This tab has [userId]'s account open from now until the returned function is called (the vault's store closes) or the
 * document ends (closed, reloaded or crashed: the browser lets its locks go). Held in shared mode, so every tab with the
 * account open holds it at once; no record is written, so a full storage cannot hide an open account from a forgetting.
 * Without Web Locks nothing is held, and a forgetting refuses ({@link forgetEarlierAccount}).
 */
export function holdAccountOpen(userId: string): () => void {
  const locks = lockManager();
  if (!locks) return () => {};
  let release: () => void = () => {};
  const held = new Promise<void>((r) => (release = r));
  void locks.request(accountOpenLockName(userId), { mode: "shared" }, () => held).catch(() => {});
  return release;
}

/**
 * [fn] while no tab of this browser holds [userId]'s account lock: under that lock, taken exclusively and only if it is
 * free. `open` where a tab holds it; `cannot_tell` where the browser has no Web Locks. A failure of [fn] is thrown. A tab
 * that opens the account while [fn] runs is not held back: its own request for the lock waits, but the account is open
 * there meanwhile (a window of the forgetting's few milliseconds; no key is lost in it).
 */
async function whileNotOpen<T>(userId: string, fn: () => Promise<T>): Promise<{ ran: true; value: T } | { ran: false; why: "open" | "cannot_tell" }> {
  const locks = lockManager();
  if (!locks) return { ran: false, why: "cannot_tell" };
  let out: { ran: true; value: T } | null = null;
  await locks.request(accountOpenLockName(userId), { mode: "exclusive", ifAvailable: true }, async (lock) => {
    if (lock === null) return;
    out = { ran: true, value: await fn() };
  });
  return out ?? { ran: false, why: "open" };
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
    const s = JSON.parse(raw) as Session & { isAdmin?: unknown };
    if (typeof s.userId !== "string" || typeof s.email !== "string") return null;
    // A record written by a pre-cut-over build (it carries `isAdmin`) names an account on the old server: not ours.
    if ("isAdmin" in s) return null;
    return { baseUrl: s.baseUrl ?? "", userId: s.userId, personalVaultId: s.personalVaultId ?? "", email: s.email, tokens: s.tokens ?? null, ...(s.endedUnconfirmed === true && !s.tokens ? { endedUnconfirmed: true as const } : {}) };
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

/** A14 review W7: every storage write here is guarded. saveSession runs inside ApiClient.setTokens (the
 *  rotation hook), so a throwing write (a full quota, storage disabled) used to escape from a lock's
 *  `setTokens(null)` and skip the rest of the lock, leaving the vault open. A failed write leaves the
 *  pair unpersisted (a reload then asks to sign in), never the lock half-done. */
export function saveSession(s: Session): void {
  // A new session of this account taken here: the token kept from one of its sessions that ended unconfirmed has had its
  // use (the sign-in named it); another account's kept token stays for that account's next sign-in. The record's own
  // mark of that end goes with it.
  if (s.tokens) {
    dropUnconfirmedRefresh(s.userId);
    endedUnconfirmedHere.delete(s.userId);
    if (s.endedUnconfirmed !== undefined) {
      const { endedUnconfirmed: _gone, ...rest } = s;
      s = rest;
    }
  }
  if (tokensKeptAcrossLock(s.userId)) {
    const v = JSON.stringify(s);
    lsSet(KEY, v);
    // A record that could not be written (a full storage) is remembered in this document, so that the tab's renewal says
    // that the session could not be saved rather than that another tab signed out.
    if (lsGet(KEY) === v) unsavedShared = null;
    else if (s.tokens) unsavedShared = { userId: s.userId, refreshToken: s.tokens.refreshToken };
    clearTabTokens();
    return;
  }
  lsSet(KEY, JSON.stringify({ ...s, tokens: null }));
  if (s.tokens) ssSet(TAB_TOKENS_KEY, JSON.stringify({ tabId: ownTabId(), userId: s.userId, tokens: s.tokens } satisfies TabSlot));
  else clearTabTokens();
}

/** This document's own session, with the offline copy on, whose record could not be written: its account and token. */
let unsavedShared: { userId: string; refreshToken: string } | null = null;

/** Whether this browser holds a session record at all (of any account). */
function hasSessionRecord(): boolean {
  return lsGet(KEY) !== null;
}

export function clearSession(): void {
  lsRemove(KEY);
  clearTabTokens();
  clearLockRevoke();
}

/**
 * The refresh token of a session that ended here because a refresh whose answer never came had no try left
 * (api/client.ts noTryLeft), with its account: `{ userId, refreshToken }`. Kept for ONE use: the next sign-in names it as
 * the session it replaces (ui/tabsession.ts replacedSession), so that the server ends that chain as replaced, which on a
 * browser's row nothing else does. It is never sent as a refresh or to end a session. Kept where the pair was: the tab's
 * sessionStorage, or localStorage where the pair every tab shares lived (the offline copy on). It goes with a new session
 * taken here ({@link saveSession}), the person's own sign-out, and a forgetting of the account.
 */
export const UNCONFIRMED_REFRESH_KEY = "andvari.unconfirmedRefresh";

/** A kept token is held per account, for this many accounts at most in each place; the oldest goes first. */
export const UNCONFIRMED_REFRESH_MAX = 4;

export interface KeptRefresh {
  readonly userId: string;
  readonly refreshToken: string;
}

/** The accounts whose session ended unconfirmed in this document (also where nothing of it could be written). */
const endedUnconfirmedHere = new Set<string>();

function keptIn(raw: string | null): KeptRefresh[] {
  try {
    const r = JSON.parse(raw ?? "null") as unknown;
    if (!Array.isArray(r)) return [];
    return r.filter((k): k is KeptRefresh => typeof k?.userId === "string" && typeof k.refreshToken === "string").map((k) => ({ userId: k.userId, refreshToken: k.refreshToken }));
  } catch {
    return []; // a record that does not read keeps nothing
  }
}

/**
 * Keeps [refreshToken] as [userId]'s ({@link UNCONFIRMED_REFRESH_KEY}): where the pair was (the tab's sessionStorage, or
 * localStorage with the offline copy on), one per account, the newest last, at most {@link UNCONFIRMED_REFRESH_MAX}.
 * True when it was written (read back).
 */
export function keepUnconfirmedRefresh(userId: string, refreshToken: string): boolean {
  const shared = tokensKeptAcrossLock(userId);
  const list = [...keptIn(shared ? lsGet(UNCONFIRMED_REFRESH_KEY) : ssGet(UNCONFIRMED_REFRESH_KEY)).filter((k) => k.userId !== userId), { userId, refreshToken }].slice(-UNCONFIRMED_REFRESH_MAX);
  const v = JSON.stringify(list);
  if (shared) lsSet(UNCONFIRMED_REFRESH_KEY, v);
  else ssSet(UNCONFIRMED_REFRESH_KEY, v);
  return (shared ? lsGet(UNCONFIRMED_REFRESH_KEY) : ssGet(UNCONFIRMED_REFRESH_KEY)) === v;
}

/** Every kept token ({@link keepUnconfirmedRefresh}): this tab's, then those every tab shares. */
export function unconfirmedRefreshes(): KeptRefresh[] {
  return [...keptIn(ssGet(UNCONFIRMED_REFRESH_KEY)), ...keptIn(lsGet(UNCONFIRMED_REFRESH_KEY))];
}

/** The kept token of [userId] (this tab's first), or null. */
export function unconfirmedRefresh(userId: string): KeptRefresh | null {
  return unconfirmedRefreshes().find((k) => k.userId === userId) ?? null;
}

/** Whether [refreshToken] is a kept token, of any account. */
export function isUnconfirmedRefresh(refreshToken: string): boolean {
  return unconfirmedRefreshes().some((k) => k.refreshToken === refreshToken);
}

/**
 * A person's own sign-out of [userId]: nothing that may still be a live credential of that account stays in this browser
 * after it, so its kept token goes (another account's stays). True when one was kept: the sign-out then says that the end
 * of that session could not be confirmed with the server, and how to end it. Called after the sign-out's own revocation,
 * which keeps a token it meets marked.
 */
export function dropKeptAtSignOut(userId: string | null): boolean {
  if (userId === null || unconfirmedRefresh(userId) === null) return false;
  dropUnconfirmedRefresh(userId);
  // A removal that could not be written is tried once more; where the token still stays, the sign-out says so
  // ({@link unconfirmedRefresh} is then still that account's, and App's line names the one way that then works).
  if (unconfirmedRefresh(userId) !== null) dropUnconfirmedRefresh(userId);
  return true;
}

/** The channel by which a person's own sign-out tells this browser's other tabs (each tab's own kept token included). */
const SIGN_OUT_CHANNEL = "andvari-signout";

/**
 * A person's own sign-out of [userId] in this tab: every other tab of this browser drops that account's kept token
 * ({@link followSignOuts}). On a browser where each tab holds its own session, the token a tab kept lives in that tab's
 * sessionStorage, which no other tab can reach. Best effort: a browser without the channel tells nothing.
 */
export function tellSignedOut(userId: string): void {
  try {
    const ch = new BroadcastChannel(SIGN_OUT_CHANNEL);
    ch.postMessage({ signedOut: userId });
    ch.close();
  } catch {
    /* no channel in this browser */
  }
}

/** This tab follows other tabs' sign-outs ({@link tellSignedOut}) until the returned function is called. */
export function followSignOuts(): () => void {
  let ch: BroadcastChannel;
  try {
    ch = new BroadcastChannel(SIGN_OUT_CHANNEL);
  } catch {
    return () => {};
  }
  ch.onmessage = (e: MessageEvent) => {
    const who = (e.data as { signedOut?: unknown } | null)?.signedOut;
    if (typeof who === "string" && isUuid(who)) dropKeptAtSignOut(who);
  };
  (ch as { unref?: () => void }).unref?.();
  return () => ch.close();
}

/** Drops the kept tokens: every one, or only [userId]'s (a new session of that account, a forgetting of it). */
export function dropUnconfirmedRefresh(userId?: string): void {
  if (userId === undefined) endedUnconfirmedHere.clear();
  else endedUnconfirmedHere.delete(userId);
  for (const [get, set, remove] of [
    [ssGet, ssSet, ssRemove],
    [lsGet, lsSet, lsRemove],
  ] as const) {
    const raw = get(UNCONFIRMED_REFRESH_KEY);
    if (raw === null) continue;
    const rest = userId === undefined ? [] : keptIn(raw).filter((k) => k.userId !== userId);
    if (rest.length === 0) remove(UNCONFIRMED_REFRESH_KEY);
    else set(UNCONFIRMED_REFRESH_KEY, JSON.stringify(rest));
  }
}

/** A session of [userId] ended unconfirmed in this document: remembered here, whatever storage could keep of it. */
export function noteEndedUnconfirmed(userId: string): void {
  endedUnconfirmedHere.add(userId);
}

/** Whether a session of [userId] ended unconfirmed in this document (see sessionend.ts endedUnconfirmed). */
export function endedUnconfirmedInThisDocument(userId: string): boolean {
  return endedUnconfirmedHere.has(userId);
}

/**
 * A14 review 3 (W-b): this tab's record of its last per-tab lock's revocation of the pair it dropped, kept in the
 * tab's sessionStorage so that a reload or a new App instance still knows it. App's in-memory record (W1) died with
 * the document, and a sign-out after a reload then reported "confirmed" for a lock whose revocation the server had
 * refused. `pending` until the server answers — a document that reloads first never learns the answer, so pending
 * counts as unconfirmed; `unconfirmed` when the server did not confirm it; removed once it did. Same lifetime and
 * same tab scope as the token slot; it names the account, so another account's sign-out never reads it.
 */
export const TAB_LOCK_REVOKE_KEY = "andvari.tabLockRevoke";

export function recordLockRevoke(userId: string, state: "pending" | "unconfirmed" | "confirmed"): void {
  if (state === "confirmed") ssRemove(TAB_LOCK_REVOKE_KEY);
  else ssSet(TAB_LOCK_REVOKE_KEY, JSON.stringify({ userId, state }));
}

/** True when this tab's last lock of [userId]'s session may have left its pair live (pending or unconfirmed). An
 *  unreadable record counts as unconfirmed: the warning is the safe side. */
export function lockRevokeUnconfirmed(userId: string | null): boolean {
  if (userId === null) return false;
  const raw = ssGet(TAB_LOCK_REVOKE_KEY);
  if (!raw) return false;
  try {
    const r = JSON.parse(raw) as { userId?: unknown; state?: unknown };
    if (typeof r.userId !== "string") return true;
    return r.userId === userId && r.state !== "confirmed";
  } catch {
    return true;
  }
}

export function clearLockRevoke(): void {
  ssRemove(TAB_LOCK_REVOKE_KEY);
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
  // A third review: a wipe that waits for the lock (a policy's run holds it) was lost when the tab closed meanwhile, and
  // the copy of an account that signed out stayed on disk. The wipe is owed from this moment until it is made: a mark
  // that holds nothing but which copy, finished by the next start of the app in this browser (finishOwedWipes).
  markWipeOwed(userId);
  // A second review: a wipe that lands while a server's policy counts what waits in the copy made that count "nothing was
  // lost". Every wipe of a copy takes the lock the policy's run takes, so it waits for that run, and the run for it.
  await exclusiveForCopy(userId, async () => {
    const cache = await openVaultCache(userId);
    await cache.wipe();
  });
  clearWipeOwed(userId);
}

/** One device-wide key per copy whose wipe was asked for in this browser and not yet made; its value is only a time. */
export const WIPE_OWED_PREFIX = "andvari.wipeOwed.";

function markWipeOwed(userId: string): void {
  try {
    localStorage.setItem(WIPE_OWED_PREFIX + userId, String(Date.now()));
  } catch {
    /* storage unreachable: the wipe still goes on in this tab */
  }
}

function clearWipeOwed(userId: string): void {
  try {
    localStorage.removeItem(WIPE_OWED_PREFIX + userId);
  } catch {
    /* storage unreachable */
  }
}

/** Whether a wipe of [userId]'s copy was asked for in this browser and not made yet (in any tab). */
export function wipeIsOwed(userId: string): boolean {
  try {
    return localStorage.getItem(WIPE_OWED_PREFIX + userId) !== null;
  } catch {
    return false;
  }
}

/** The copies whose wipe is owed. */
export function owedWipes(): string[] {
  const out: string[] = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k !== null && k.startsWith(WIPE_OWED_PREFIX)) out.push(k.slice(WIPE_OWED_PREFIX.length));
    }
  } catch {
    /* storage unreachable */
  }
  return out;
}

/**
 * At each start of the app, with or without a session: every wipe owed from an earlier tab (a sign-out, Settings turning
 * the copy off, an account deletion, whose tab was closed while the wipe waited) is made now, so a person who signed out
 * does not find the copy still on disk. Each waits for the copy's lock as any wipe does. Never rejects.
 */
export async function finishOwedWipes(): Promise<void> {
  await Promise.all(owedWipes().map((u) => wipeVaultCache(u).catch(() => {})));
}

/**
 * True for a localStorage key that belongs to [userId]: every per-account key this client writes is `andvari.<what>.<userId>`
 * or `andvari.<what>.<userId>.<sub>` (`andvari.cs.<userId>.*` client state — the account-state copy and high-water seq, the
 * personal-wrap cache, the trust records —, the cache opt-in and consent markers, the auto-lock and last-export stamps, the
 * self-identity pin, and the post-cut-over stores `andvari.log2.<userId>.<vaultId>.*`, `andvari.as2.<userId>.*`,
 * `andvari.recmirror.<userId>`, `andvari.current.<userId>`, `andvari.onetap.<userId>`, `andvari.how.<userId>`). A userId is
 * a UUID, which carries no dot. Only the third segment names the account: a vault id elsewhere in another account's key
 * (a server chooses which vault ids a browser sees) never makes that key this account's.
 */
export function isAccountScopedKey(key: string, userId: string): boolean {
  return key.startsWith("andvari.") && key.split(".")[2] === userId;
}

/**
 * Account deletion (spec 03 §13, client duty) — after the server CONFIRMED the deletion, remove everything this browser holds
 * for the account: the session record and this tab's token slot ({@link clearSession}), every localStorage key scoped to the
 * userId ({@link isAccountScopedKey}), the spec 01 §5 self-identity records ({@link forgetSelfIdentity}: the pin, and the email
 * binding where it names this account), and the offline copy (the account's IndexedDB). Device-wide settings — theme, install
 * id, server address, this device's offline-copy opt-out and the org's cache pin — are not account data and stay.
 *
 * The synchronous part runs before the first await, so the caller can drop its token pair right after the call and no
 * rotation hook writes the session back; the returned promise settles when the IndexedDB wipe has (idbcache's wipe never
 * rejects, and neither does this). Not for sign-out: a sign-out keeps the self-identity records on purpose (an admin
 * recovery revokes every session first, spec 01 §5).
 */
export async function wipeLocalAccountState(userId: string, email?: string, deletion: "confirmed" | "unconfirmed" = "confirmed"): Promise<void> {
  // A deletion whose outcome is not known (the person's "Forget" after the session ended during the request) keeps the
  // records of which account the address is and of its identity key, as a sign-out does: the account may still exist.
  const keepIdentity = deletion === "unconfirmed";
  clearSession();
  dropUnconfirmedRefresh(userId);
  const doomed: string[] = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k !== null && isAccountScopedKey(k, userId) && !(keepIdentity && k === selfIdentityPinKey(userId))) doomed.push(k);
    }
  } catch {
    /* storage unreachable: nothing persisted to remove */
  }
  for (const k of doomed) lsRemove(k);
  if (!keepIdentity) forgetSelfIdentity(userId, email);
  // The 2026-11-16 walk: the device record (one key for the whole browser) still mapped the account to its deviceId, and
  // its address hash to the account, after "this browser kept nothing of it".
  new DeviceIdentity().forget(userId);
  // A server's policy wipe's notice kept for the account's copy is a word owed to the person about changes that were
  // lost: it stays, to be said once, but under a key of its own and no longer under the account's id (as at a forgetting).
  try {
    detachPolicyWipeNotice(userId);
  } catch {
    /* storage unreachable: nothing persisted to move */
  }
  await wipeVaultCache(userId);
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
  // Read as the copy is: counting never creates a copy, nor deletes one that cannot be opened.
  const w = await readWaiting(userId);
  return w.kind === "read" ? w.pending.length + w.staged.length : 0;
}

/**
 * Design §4.4 (decided on 2026-11-17): how many changes made in this browser were not sent, for the line said before an
 * act that deletes this browser's copy of [userId]'s account. Counted as the shared code counts them: the queue's
 * pending and refused rows, and every change parked with a vault held back (never the number of held vaults, which
 * would say too few). The same count a server's policy wipe says afterwards (vault/policywipe.ts). Read while locked too: the
 * queue is in IndexedDB, so it can be counted without the keys. Null when a copy exists and cannot be read (another
 * schema, a failed read): this browser cannot tell, which is never said as none, and the copy is left as it is. 0 on a
 * browser that keeps no copy (nothing is queued without one); asking creates none.
 */
export async function unsentChangeCount(userId: string): Promise<number | null> {
  const w = await readWaiting(userId);
  if (w.kind === "none") return 0;
  if (w.kind === "unreadable") return null;
  return w.pending.length + w.staged.length + w.parked;
}

/**
 * Whether this browser keeps a copy of an account, and how many changes in it were not sent (null: cannot tell); and how
 * many changes to shared vaults the account signed here are held, not known to be stored ({@link heldSharedChanges}).
 */
export interface EarlierCopy {
  readonly kept: boolean;
  readonly unsent: number | null;
  readonly held: number | null;
}

/**
 * The changes to shared vaults that [userId] signed in this browser and that are held, not known to be stored at the
 * server: what the shared-vault code keeps at rest outside the copy, one record per vault (`andvari.log2.<id>.<vault>.pending`),
 * named also by its index (`andvari.log2.<id>.pending-index`), and kept across a sign-out. A forgetting removes them. The
 * number of those the server's own answer said it did not store; 0 where none is held (or only ones it said it stored);
 * null, "cannot tell", where any one may have reached the server (its answer was lost or never came: it is never counted
 * as not sent) or a record cannot be read.
 */
export function heldSharedChanges(userId: string): number | null {
  const vaults = new Set<string>();
  try {
    for (const v of (localStorage.getItem(`andvari.log2.${userId}.pending-index`) ?? "").split(",")) if (v !== "") vaults.add(v);
    for (let i = 0; i < localStorage.length; i++) {
      const p = localStorage.key(i)?.split(".");
      if (p && p.length === 5 && p[0] === "andvari" && p[1] === "log2" && p[2] === userId && p[4] === "pending") vaults.add(p[3]!);
    }
  } catch {
    return null;
  }
  let n = 0;
  for (const v of vaults) {
    let raw: string | null;
    let flag: string | null;
    try {
      raw = localStorage.getItem(`andvari.log2.${userId}.${v}.pending`);
      flag = localStorage.getItem(`andvari.log2.${userId}.${v}.flag`);
    } catch {
      return null;
    }
    if (raw === null) continue; // the index names a vault with nothing held
    // A frozen vault holds nothing: its change was dropped at the freeze (a record kept from before that rule is not one).
    if (flag?.startsWith("frozen:") === true) continue;
    let held: { frame?: unknown; acked?: unknown; notStored?: unknown } | null;
    try {
      held = JSON.parse(raw) as typeof held;
    } catch {
      return null;
    }
    if (held === null || typeof held !== "object" || typeof held.frame !== "string") return null;
    if (held.acked === true) continue; // the server's own answer said it is stored
    if (held.notStored !== true) return null; // it may have arrived
    n++;
  }
  return n;
}

/**
 * What the second confirmation of "Forget the earlier account on this device" says of [userId]'s copy (decided on
 * 2026-11-17): whether this browser keeps one (any copy at all, also one it cannot read), and how many changes in it were
 * not sent, counted as {@link unsentChangeCount} counts them for a sign-out; and the changes to shared vaults it holds for
 * that account outside the copy ({@link heldSharedChanges}), which go with the forgetting too. Asking creates nothing.
 */
export async function earlierCopyOf(userId: string): Promise<EarlierCopy> {
  const w = await readWaiting(userId);
  const held = heldSharedChanges(userId);
  if (w.kind === "none") return { kept: false, unsent: 0, held };
  if (w.kind === "unreadable") return { kept: true, unsent: null, held };
  return { kept: true, unsent: w.pending.length + w.staged.length + w.parked, held };
}

/** What a forgetting of an earlier account came to. Nothing is sent to the server in any of them. */
export type ForgetEarlierResult =
  /** The address is new to this browser: nothing of the earlier account is left here. */
  | { readonly kind: "forgotten" }
  /** No record ties the address to that account any more, and no forgetting of it was begun: nothing was removed. */
  | { readonly kind: "nothing_to_forget" }
  /** The earlier account is the session this browser keeps (open or locked, in any tab), or a tab has it open: nothing was removed. */
  | { readonly kind: "account_open" }
  /** This browser has no Web Locks, so whether a tab has the earlier account open cannot be told: nothing was removed. */
  | { readonly kind: "open_cannot_tell" }
  /** What the second confirmation said of the copy is no longer so: nothing was removed; [copy] is what holds now. */
  | { readonly kind: "not_confirmed"; readonly copy: EarlierCopy }
  /**
   * What the offer was made for no longer holds: the address is now tied to the account the refused flow met, or the
   * earlier account is that account (the same account under another key is never forgotten). Nothing was removed.
   */
  | { readonly kind: "no_longer_holds" };

/**
 * "Forget the earlier account on this device" (decided on 2026-11-17), called only from the person's own click on the
 * second confirmation, with what that confirmation said ([shown]). It removes the record that ties [email] to the earlier
 * account [userId], that account's copy in this browser, and everything this browser keeps under that account's id at
 * this origin but the record of its identity key (its id-keyed pin, kept so that the account never comes back here under
 * another key); it leaves other accounts and everything known of the server (its card, its pin). Nothing is sent.
 *
 * - The earlier account's session is kept here (some tab may have it open), or a tab has the account open (it holds the
 *   account's lock, {@link holdAccountOpen}, also where its session record could not be written): `account_open`, nothing
 *   removed. Its sign-out comes first, and no other tab is left using records or a copy that are gone. Everything below
 *   runs under that lock taken exclusively, so a tab that already had the account open refuses it; a tab that opens the
 *   account while it runs is not held back (see {@link whileNotOpen}). A browser without Web Locks cannot tell whether a
 *   tab has the account open: `open_cannot_tell`, nothing removed.
 * - A forgetting of it begun and not finished (its mark stands) is finished and answered `forgotten`, even where the
 *   address's record is already gone; with no mark and no record, `nothing_to_forget`.
 * - [served] is the account the refused flow met (the offer's): where it is the earlier account itself, or the address is
 *   by now tied to it, `no_longer_holds`, nothing removed. The same account under another key is what the address's
 *   record exists to stop, never a remade account, and an address taken by the served account has nothing earlier left.
 * - The copy is counted again: where it differs from [shown], `not_confirmed` with what holds now.
 * - Otherwise the mark is written first (a mark that cannot be written throws, and nothing is removed), then everything
 *   goes, then the mark is taken away. A store that throws part-way leaves the mark: the next click, or the next start
 *   ({@link settleForgettings}), finishes it.
 */
export async function forgetEarlierAccount(email: string, userId: string, shown: EarlierCopy, served: string): Promise<ForgetEarlierResult> {
  const n = emailNorm(email);
  if (n === null) return { kind: "nothing_to_forget" };
  if (readPersisted()?.userId === userId) return { kind: "account_open" };
  if (served === userId) return { kind: "no_longer_holds" };
  const r = await whileNotOpen(userId, async (): Promise<ForgetEarlierResult> => {
    if (readPersisted()?.userId === userId) return { kind: "account_open" };
    const begun = forgettingMarks().some((m) => m.email === n && m.userId === userId);
    const bound = boundAccountAt(n);
    if (bound !== userId) {
      if (!begun) return bound !== null && bound === served ? { kind: "no_longer_holds" } : { kind: "nothing_to_forget" };
      await dropEarlierAccount(n, userId);
      return { kind: "forgotten" };
    }
    const now = await earlierCopyOf(userId);
    if (now.kept !== shown.kept || now.unsent !== shown.unsent || now.held !== shown.held) return { kind: "not_confirmed", copy: now };
    markForgetting(n, userId);
    await dropEarlierAccount(n, userId);
    return { kind: "forgotten" };
  });
  if (r.ran) return r.value;
  return r.why === "open" ? { kind: "account_open" } : { kind: "open_cannot_tell" };
}

/**
 * At each start of the app: every forgetting begun and not finished is finished where its first removal was made (the
 * address no longer names that account) and this browser keeps no session of that account; otherwise its mark is dropped
 * with nothing removed (it never got that far, or that account was signed in to here since). Only a mark the person's
 * click wrote is settled: nothing else starts a forgetting. A mark whose account a tab has open (or where that cannot be
 * told) is left for a later start.
 */
export async function settleForgettings(): Promise<void> {
  for (const m of forgettingMarks()) {
    if (boundAccountAt(m.email) !== m.userId && readPersisted()?.userId !== m.userId) await whileNotOpen(m.userId, () => dropEarlierAccount(m.email, m.userId));
    else unmarkForgetting(m.email, m.userId);
  }
}

/** localStorage for a write that must not fail silently: every failure throws (browserStorage swallows them). */
const throwingLocalStore: KeyValue = {
  get: (k) => localStorage.getItem(k),
  set: (k, v) => localStorage.setItem(k, v),
  remove: (k) => localStorage.removeItem(k),
};

/** Everything of the earlier account [userId] under the address [email], in the order the mark relies on; then the mark goes. */
async function dropEarlierAccount(email: string, userId: string): Promise<void> {
  // First the record that ties the address to the account: from here the address is new to this browser. The record of
  // the account's identity key (its id-keyed pin) is kept, here and in the walk below.
  forgetEarlierRecords(userId, email);
  // This tab's token slot and lock record, where they name that account (another tab's go with that tab). Their removal
  // swallows a failure, so it is read back: one still there throws, and the mark stands.
  const revokeNames = (): boolean => {
    try {
      return (JSON.parse(ssGet(TAB_LOCK_REVOKE_KEY) ?? "null") as { userId?: unknown } | null)?.userId === userId;
    } catch {
      return false; // a record that does not read names no account
    }
  };
  if (readSlot()?.userId === userId) clearTabTokens();
  if (revokeNames()) clearLockRevoke();
  dropUnconfirmedRefresh(userId); // a session of that account that ended unconfirmed: its token's one use is gone with it
  if (readSlot()?.userId === userId || revokeNames()) throw new Error("this tab's record of the account could not be removed");
  // Every key of this origin's storage scoped to the account's id, by what it is keyed with ({@link isAccountScopedKey}),
  // so that a kind added later goes too. Keys of the server (its pin), of the device and of other accounts stay, and so does
  // the record of this account's identity key.
  const keptPin = selfIdentityPinKey(userId);
  const doomed: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (k !== null && k !== keptPin && isAccountScopedKey(k, userId)) doomed.push(k);
  }
  for (const k of doomed) localStorage.removeItem(k);
  // The device record's row for the account and every address hash that maps to it (the secret stays: it is the browser's),
  // written through a store that throws where the write fails, so that the mark stands and nothing is answered forgotten.
  new DeviceIdentity(throwingLocalStore).forget(userId);
  // The copy: its database, as a sign-out wipes it (owed until made, so a tab closed meanwhile finishes it at the next start).
  // A copy still there afterwards throws: the mark stands, and the next click or start finishes it.
  await wipeVaultCache(userId);
  if ((await readWaiting(userId)).kind !== "none") throw new Error("the copy of the account could not be removed");
  // A server's policy wipe's notice for that copy stays (a word owed to the person), under a key that is not the account's
  // id, to be said; a wipe the policy still owed for the copy is not run again for an account this browser forgot.
  detachPolicyWipeNotice(userId);
  // The next account taken under the address is said once ("this browser now remembers the new account"), until dismissed.
  rememberNextAt(email);
  unmarkForgetting(email, userId);
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
 *  (Android persisted-policy parity, spec 02 §8). Presence = disallowed; absence = allowed. The key
 *  (ORG_CACHE_OFF_KEY) lives in vault/policywipe.ts, where an open store reads it too. */
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
 *
 * Decided on 2026-11-17: before the wipe, the changes that wait in the copy are sent ONCE ([sent.send], null when no live
 * session of the account is held: then nothing is sent and the wipe follows at once), and how many could not be sent is
 * kept apart from the copy with [sent.server]'s name, to be said once the copy is gone (vault/policywipe.ts
 * removeCopyForPolicy: one run per copy across tabs, the session checked at every request, one limit for the whole
 * attempt, the number read at the wipe). The pin above is set first: from that moment an open store queues nothing new
 * into the copy. Only a copy that exists is tried and counted: with none, nothing waits and nothing is said. Resolves to
 * what is to be said now that the copy is gone, or null (no copy; another run wiped it; or the wipe is not made yet, and
 * is said when it is). Without [sent] (no server to name) the copy is wiped and nothing is said. [sent.mayWrite] is
 * asked for every change at the moment its request is handed to the transport ({@link policyWipeQuestion}); a change it
 * holds back is counted as not sent.
 */
export async function applyOrgOfflineCachePolicy(
  allowed: boolean,
  userId: string | null,
  sent: { send: SendOnce | null; server: string; mayWrite: MayWrite } | null = null,
  limits: PolicyWipeLimits = {},
): Promise<PolicyWipeNotice | null> {
  const before = loadSession(); // A14 F5: the pair follows the gate, like the device toggle
  if (allowed) {
    lsRemove(ORG_CACHE_OFF_KEY);
    rehomeSessionTokens(before, userId);
    // A policy that was lifted ends every wipe it asked for that was not made, with its notice: the copy is used again.
    dropHeldPolicyWipes();
    releaseCopiesAfterLift();
    return null;
  }
  lsSet(ORG_CACHE_OFF_KEY, String(Date.now()));
  rehomeSessionTokens(before, userId);
  if (!userId) return null;
  // From this moment only THIS account's copy is closed for new changes (a tab of another account goes on as before).
  markCopyBeingRemoved(userId);
  if (sent === null) {
    await wipeVaultCache(userId);
    clearCopyBeingRemoved(userId);
    return null;
  }
  return (await removeCopyForPolicy(userId, sent.server, sent.send, sent.mayWrite, limits)).notice;
}

/**
 * The question the one attempt before a policy's wipe asks of each change of [userId]'s copy (decided on 22 November
 * 2026). Where this tab has that account open ([open]) and a pull of this session has run the removal's rule, its
 * store's `mayWrite`, asked at each change: the verified log says there whether the vault's key still works. Before that
 * first pull (an unlock: the policy is read beside it), what the store knows of a log is what was verified at rest, which
 * a removal made while this browser was away has not reached: only the open account's personal vault may be written.
 * Where no account is open (a start, a locked tab, or another account open here), no verified state of any log is in
 * memory, so only the personal vault may be written: the one this browser's own session record of that account names.
 * That record is written only where an unlock opened the account (ui/opensession.ts, from `Account.personalVaultId`: the
 * vault of the genesis this account signed, and only when its own wrap opened), never from a label a server serves. No
 * record of that account, or one that names no personal vault: nothing may be written.
 */
export function policyWipeQuestion(open: OpenAccountQuestion | null, userId: string): MayWrite {
  if (open !== null && open.userId === userId) {
    return (vaultId) => (open.pulled() ? open.mayWrite(vaultId) : open.personalVaultId !== "" && vaultId === open.personalVaultId);
  }
  const record = loadSession();
  const personal = record !== null && record.userId === userId ? record.personalVaultId : "";
  return (vaultId) => personal !== "" && vaultId === personal;
}

/** What {@link policyWipeQuestion} asks of an account open in this tab (its store and its own personal vault). */
export interface OpenAccountQuestion {
  readonly userId: string;
  readonly personalVaultId: string;
  /** Whether a pull of this session has run the removal's rule (`VaultStore.pulledInThisSession`). */
  pulled(): boolean;
  mayWrite(vaultId: string): boolean;
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
 * After a password change (spec 03 §3, §D.2c/§E.4 S3-2): the offline cache's copy of the account keys takes the change's own new salt,
 * parameters and wrapped UVK, so the old password no longer opens the cached vault offline (spec 05 T3), and the
 * pending wraps kept beside it become [pending] (none once the change is made). Nothing is fetched: the values are the
 * ones this browser just sent, or the server's keys at a settle. Only where caching is on and a copy exists. A failed
 * write never fails the committed change, and it is never swallowed either: it answers `failed`, the screen says so,
 * and the next online unlock writes the server's keys again.
 */
export async function rekeyCachedAccountKeys(userId: string, keys: SessionKeys, pending: readonly SessionKeys[] = [], open: CopyOpener = gatedCopy): Promise<CopyWrite> {
  try {
    const cache = await open(userId);
    if (cache === null) return "none";
    try {
      const next = { kdfSalt: keys.kdfSalt, kdfParams: keys.kdfParams, wrappedUvk: keys.wrappedUvk };
      let any = false;
      const v2 = await cache.accountKeysV2();
      if (v2 !== null) {
        if (!(await cache.setAccountKeysV2({ ...v2, ...next }))) return "failed";
        any = true;
      }
      const held = await cache.accountKeys();
      if (held !== null) {
        if (!(await cache.setAccountKeys({ ...held, ...next }))) return "failed";
        any = true;
      }
      if (!any) return "none";
      return (await cache.setPendingWraps(pending)) ? "written" : "failed";
    } finally {
      cache.close();
    }
  } catch {
    return "failed";
  }
}

/**
 * Before a password change is sent: its wrap, with any earlier one still unanswered, is kept beside this browser's
 * offline copy of the account keys, so that after a lost answer and a reload the copy opens with the new password too.
 * `none` where caching is off or no copy is held.
 */
export async function keepPendingWraps(userId: string, pending: readonly SessionKeys[], open: CopyOpener = gatedCopy): Promise<CopyWrite> {
  try {
    const cache = await open(userId);
    if (cache === null) return "none";
    try {
      if ((await cache.accountKeysV2()) === null && (await cache.accountKeys()) === null) return "none";
      return (await cache.setPendingWraps(pending)) ? "written" : "failed";
    } finally {
      cache.close();
    }
  } catch {
    return "failed";
  }
}

/** The pending wraps kept beside this browser's offline copy, for an offline unlock; none where caching is off. */
export async function cachedPendingWraps(userId: string, open: CopyOpener = gatedCopy): Promise<SessionKeys[]> {
  try {
    const cache = await open(userId);
    if (cache === null) return [];
    try {
      // The wraps only: the day each was kept is read where it is said (onboardflow's unlock, through copyAtUnlock).
      return (await cache.pendingWraps()).map((w) => ({ kdfSalt: w.kdfSalt, kdfParams: { ...w.kdfParams }, wrappedUvk: w.wrappedUvk }));
    } finally {
      cache.close();
    }
  } catch {
    return [];
  }
}

/** Opens this browser's offline copy of [userId], or null where caching is off for it. */
export type CopyOpener = (userId: string) => Promise<VaultCache | null>;

const gatedCopy: CopyOpener = async (userId) => (webCacheEnabled(userId) ? openVaultCache(userId) : null);

/** The offline copy's keeper for a Settings session of [userId] (vault/settingsflow.ts CopyKeeper). */
export function cacheCopyKeeper(userId: string, open: CopyOpener = gatedCopy): CopyKeeper {
  return {
    keepPending: (pending) => keepPendingWraps(userId, pending, open),
    settle: (own, pending) => rekeyCachedAccountKeys(userId, own, pending, open),
  };
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
  // SAME-USER guard: WHO this client's pair belongs to ([ApiClient.boundUserId]). On a shared
  // browser the persisted session can come to belong to a DIFFERENT account (user X's frozen tab
  // wakes after user Y signed in) — X's client must neither adopt Y's token pair nor write X's
  // rotations into Y's persisted session. A client created without a session (fresh sign-in form)
  // never adopts. A14 review W3: the bound account is no longer fixed at creation — the one client
  // lives for the whole tab, so a sign-in or register rebinds it to the account the server answered
  // for (Welcome), and until that account's own saveSession lands, its rotations are written nowhere.
  const client: ApiClient = new ApiClient(
    baseUrl,
    session?.tokens ?? null,
    (tokens) => {
      const cur = loadSession();
      const bound = client.boundUserId;
      if (cur && (bound === null || cur.userId === bound)) saveSession({ ...cur, tokens });
    },
    // F25 cross-tab refresh dedup: lets the client re-read, inside the Web Lock, a
    // pair another tab already rotated and adopt it instead of replaying ours —
    // only when that pair belongs to the SAME user this client is bound to.
    () => {
      const cur = loadSession();
      const bound = client.boundUserId;
      return bound !== null && cur?.userId === bound ? cur.tokens : null;
    },
  );
  client.boundUserId = session?.userId ?? null;
  // A refresh whose answer never came and had no try left: its token is kept for the next sign-in's name, under the
  // account the client is bound to (api/client.ts noTryLeft), and a client still holding it sends nothing.
  client.keepUnconfirmed = (t, owner) => {
    // A sign-in's placeholder binding names no account. Where this browser holds no session record at all (a sign-out
    // removed it, with the tokens it kept), a late answer keeps nothing: no record of a removed token is kept.
    if (isUuid(owner) && hasSessionRecord()) keepUnconfirmedRefresh(owner, t);
  };
  // A kept token is never sent, by any tab, whatever a tab still holds in its memory.
  client.isKeptUnconfirmed = (t) => isUnconfirmedRefresh(t);
  // With the offline copy on every tab shares one pair, and a tab's token leaves only while this browser's record holds
  // that same pair (or this tab's own slot does: its own pair from before the copy was turned on in another tab).
  client.sharedRecord = (t) => {
    const bound = client.boundUserId;
    if (bound === null || !tokensKeptAcrossLock(bound)) return undefined;
    const slot = readSlot();
    if (slot && slot.userId === bound && slot.tokens.refreshToken === t) return "holds";
    const rec = readPersisted();
    if (!rec || rec.userId !== bound) return unsavedShared?.userId === bound && unsavedShared.refreshToken === t ? "unsaved" : "gone";
    if (!rec.tokens) return "ended";
    return rec.tokens.refreshToken === t ? "holds" : "other";
  };
  // The app's client makes the one more try of a refresh whose answer never came by itself, inside its window.
  client.secondTryAfterMs = SECOND_TRY_AFTER_MS;
  return client;
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

/** A14 review W1: shown on the unlock card when the lock's own revocation of this tab's pair was not
 *  confirmed — the pair is gone from this browser either way, but a copy of it may still be live. */
export const LOCK_REVOKE_UNCONFIRMED =
  "The server didn't confirm it ended this tab's session. If this was a shared computer, change your master password from another device to end every session.";

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
