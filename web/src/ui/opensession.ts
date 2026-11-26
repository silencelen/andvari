import type { ApiClient } from "../api/client";
import type { DeviceIdentity, KeyValue } from "../api/devicesecret";
import type { AccountKeysV2 } from "../api/wire";
import { WireApi } from "../api/wireclient";
import type { BakedInstance } from "../vault/publicinstance";
import { Account } from "../vault/account";
import { accountId, type OpenedAccount } from "../vault/accountopen";
import { AccountStateStore } from "../vault/accountdocstore";
import { NullCache, openVaultCache, type VaultCache } from "../vault/idbcache";
import { type CardStatus, cardNamesOperator, PinStore, type PinState, pinStopsTraffic, type WebPin } from "../vault/pinstore";
import { recordRecoveryChoice } from "../vault/recoverymirror";
import type { SessionKeys } from "../vault/sessionwrap";
import type { CopyAtUnlock } from "../vault/onboardflow";
import { loadSelfIdentityPub, recordSelfIdentityPub } from "../vault/selfidentity";
import { VaultStore } from "../vault/store";
import type { SessionHow } from "../vault/contactbook";
import { boundTo, SessionFence } from "../vault/sessionfence";
import { SharedLogSession } from "../vault/sharedlogs";
import { type SettingsSession, writeEscrowSeen } from "../vault/settingsflow";
import { type QuietReKey, quietReKey } from "../vault/rekey";
import { emailNorm } from "../crypto/trust/grammar";
import { NONE } from "../crypto/trust/grammar";
import { net } from "./errors";
import { cacheCopyKeeper, ensureCachePersistenceRequested, saveSession, webCacheEnabled, wipeIsOwed, wipeVaultCache } from "./session";

/** What every signed-out screen works with: the one transport, its post-cut-over calls, the pins, and the origin that served this page. */
export interface WebContext {
  readonly client: ApiClient;
  readonly wire: WireApi;
  readonly pins: PinStore;
  /** The origin that served this web client: the only one it dials (§13). */
  readonly origin: string;
  readonly storage: KeyValue;
}

/**
 * The context App builds once per tab: the one transport, its wire client, the pin store of the origin it dials, and
 * the transport's traffic gate on that pin (design §4.4 "a fork stops traffic, not reading"). While the origin's pin is
 * forked or damaged nothing leaves this browser for it — no policy probe, socket, sync, usage flush, file or sign-out
 * POST — and an answer already on its way is dropped. "Forget this server" removes the mark, and traffic resumes.
 *
 * [hold] is a second stop beside the pin's: App passes {@link endedCopyHold} of its current screen, so that while the
 * copy of a session the server ended is open (§4.4 "nothing is sent and nothing is written while it stands so")
 * nothing leaves either, Settings' calls included.
 */
export function createWebContext(client: ApiClient, origin: string, storage: KeyValue, baked: BakedInstance | null, device?: DeviceIdentity, hold?: () => string | null): WebContext {
  const wire = new WireApi(client, device);
  const pins = new PinStore(storage, () => wire.instance(), baked);
  client.trafficGate = (credentialed) => {
    const st = pins.state(origin);
    return pinStopsTraffic(st) ?? (credentialed ? noPinInForce(st) : null) ?? hold?.() ?? null;
  };
  return { client, wire, pins, origin, storage };
}

/**
 * Design §4.4: a session this browser keeps, at an origin that holds no pin record (a move that stopped half-way, a
 * record that was lost). It is shown as a blocked server that can be forgotten: it does not unlock, it dials nothing,
 * and forgetting it ends it on the device without telling the server.
 */
export function heldWithoutPin(session: object | null, ctx: Pick<WebContext, "pins" | "origin">): boolean {
  return session !== null && ctx.pins.state(ctx.origin).kind === "none";
}

/** The stop reason for a credential to an origin with no pin in force (design §4.4). */
export const NO_PIN_STOP = "no_pin";

/**
 * Design §4.4 "No credential goes to an origin without a pin in force": with no pin record at the origin (a first
 * load, after "Forget this server", a record lost, or a storage read that failed and so reads as none), only the
 * requests of a first pin go out (the card chain, the policy), and they carry no credential. A forked or damaged
 * record is stopped whole by {@link pinStopsTraffic} before this is asked.
 */
export function noPinInForce(st: PinState): string | null {
  return st.kind === "pinned" ? null : NO_PIN_STOP;
}

/** The stop reason while the copy of a session the server ended is open (design §4.4). */
export const ENDED_COPY_STOP = "session_ended";

/** [hold] for {@link createWebContext}: stopped while the screen shows the copy of a session the server ended. */
export function endedCopyHold(screen: { readonly kind: string; readonly store?: Pick<VaultStore, "readOnlyCopyReason"> }): string | null {
  return screen.kind === "vault" && screen.store?.readOnlyCopyReason() === "ended" ? ENDED_COPY_STOP : null;
}

/**
 * Design §4.4, a fork (or a damaged pin) found while a vault is open: traffic stops at once (the gate already refuses
 * every request; the live sockets close now), and the store freezes as the read-only copy, so nothing queued is sent.
 * Returns true when the session is (now) the read-only copy.
 */
export function stopSessionTraffic(ctx: Pick<WebContext, "client" | "pins" | "origin">, store: VaultStore): boolean {
  if (pinStopsTraffic(ctx.pins.state(ctx.origin)) === null) return store.isReadOnlyCopy();
  ctx.client.cutLiveTraffic();
  store.freezeAsReadOnlyCopy();
  return true;
}

/**
 * The pin refresh an open session runs beside every sync (design §4.4). A refresh that finds a fork (or a damaged
 * record) stops the session's traffic before the sync goes on, so nothing queued is sent. App also listens
 * (PinStore.onStopped), for a fork its policy probe finds, and shows the warning.
 */
export function pinRefreshFor(ctx: Pick<WebContext, "client" | "pins" | "origin">, store: VaultStore): () => Promise<CardStatus> {
  return async () => {
    try {
      return await ctx.pins.refresh(ctx.origin);
    } finally {
      stopSessionTraffic(ctx, store);
    }
  };
}

/** Design §12.2 rule 7: the verified card names the account as its operator; the web does not hold it. */
export class OperatorAccountError extends Error {
  constructor() {
    super("operator_account");
    this.name = "OperatorAccountError";
  }
}

/** What the vault shell needs to know about how this session came to be. */
export interface LoginMeta {
  readonly pin: WebPin;
  /** A card notice to show (withheld, moved, kind changed), or null. */
  readonly cardNotice: CardStatus | null;
  readonly email: string;
  /** The account ID shown on the kit (32-hex short identity fingerprint). */
  readonly accountId: string;
  /**
   * What the Settings flows (vault/settingsflow.ts) act for: this session's wire client, pins and origin, the
   * account's normalized address, and the opened keys (the same arrays the Account holds). A lock wipes neither: it
   * closes the session's fence (VaultStore.close), so nothing here can be sent afterwards, and leaves the arrays to the
   * collector (a wipe without that fence would seal under a zeroed key).
   */
  readonly settings: SettingsSession;
  /** This session's transport, behind its fence: what the vault's screens call (sockets, HIBP, devices, two-step). */
  readonly client: ApiClient;
  /** The usage ledger's transport: its last flush at a lock may land, but only while the tab is bound to this account. */
  readonly usageWire: WireApi;
  /** How the vault was opened: `offline` is this browser's copy, opened while the server could not be reached. */
  readonly openedFrom: "online" | "offline" | "forked_copy" | "ended_copy";
  /**
   * Spec 01 §7: this session is a sign-in over this browser's copy of the same account, which the typed password did not
   * open; the copy now follows the server's keys, and the vault says so in one line for this session.
   */
  readonly copySealedElsewhere?: true;
}

/**
 * This browser's own record of the account's identity key, looked up by the userId the server answered for: throws
 * (an identity fault) when its records bind the address to another account or disagree.
 */
export function knownIdentity(email: string): (userId: string) => Uint8Array | null {
  return (userId) => loadSelfIdentityPub(userId, email);
}

async function gatedCache(userId: string): Promise<VaultCache> {
  if (!webCacheEnabled(userId)) return new NullCache();
  // A wipe of this copy that is still owed (a sign-out whose tab closed while it waited) is made before the copy is used
  // again, so a later start never wipes a copy in use.
  if (wipeIsOwed(userId)) await wipeVaultCache(userId);
  const c = await openVaultCache(userId);
  if (c.durable) ensureCachePersistenceRequested();
  return c;
}

/** This browser's copy of the account keys with their genesis (spec 02 §8), or null where caching is off or none is held. */
export async function cachedAccountKeys(userId: string, openCache: (userId: string) => Promise<VaultCache> = gatedCache): Promise<AccountKeysV2 | null> {
  try {
    const cache = await openCache(userId);
    try {
      return await cache.accountKeysV2();
    } finally {
      cache.close();
    }
  } catch {
    return null;
  }
}

/** Whether this browser has IndexedDB at all (where the offline copy lives); the feature test openVaultCache makes too. */
export function browserHasStore(): boolean {
  try {
    return typeof globalThis.indexedDB !== "undefined" && globalThis.indexedDB !== null;
  } catch {
    // A getter that throws (a browser that forbids storage outright): no store.
    return false;
  }
}

/**
 * What this browser holds to compare the server's keys with at the unlock of a held session (spec 01 §7; the states are
 * {@link CopyAtUnlock}'s): `none` where the copy is off for this account here (no copy chosen, storage that keeps
 * nothing, a private window) or on with no keys written yet; `unreadable` where the copy is on and cannot be opened, or
 * its keys row is there and is not a usable key set, or reading it fails; otherwise the copy's keys and pending wraps.
 */
export async function copyAtUnlock(
  userId: string,
  openCache: (userId: string) => Promise<VaultCache> = gatedCache,
  copyOn: (userId: string) => boolean = webCacheEnabled,
  hasStore: () => boolean = browserHasStore,
): Promise<CopyAtUnlock> {
  // A browser with no store at all (no IndexedDB) holds no copy, whatever its setting says: the unlock is a sign-in's
  // checks, as on any browser that keeps nothing, and not a copy that cannot be read (which would send it to the sign-in
  // form at every unlock).
  if (!hasStore()) return { kind: "none" };
  if (!copyOn(userId)) return { kind: "none" };
  let cache: VaultCache;
  try {
    cache = await openCache(userId);
  } catch {
    return { kind: "unreadable" };
  }
  try {
    // The copy is on here, and the database did not open (openVaultCache answers a NullCache then).
    if (!cache.durable) return { kind: "unreadable" };
    const keys = await cache.accountKeysV2();
    if (keys === null) return (await cache.hasAccountKeysV2Row()) ? { kind: "unreadable" } : { kind: "none" };
    return { kind: "copy", keys, pending: await cache.pendingWraps() };
  } catch {
    return { kind: "unreadable" };
  } finally {
    cache.close();
  }
}

/**
 * The account-state `recovery` record of a sign-up on this browser and the browser's own mirror (§4.5, §7.7): the
 * choice made at sign-up, `{private, none, now}` by default or `{operator, fp, now}` when the registration sealed
 * the escrow to the offered key. Returns the write's kind; anything but
 * `written` or `unchanged` is shown to the person with a retry (it is never swallowed).
 */
export async function writeSignupRecovery(
  ctx: Pick<WebContext, "wire" | "storage">,
  opened: OpenedAccount,
  nowMs: number,
  choice: { readonly posture: "private" | "operator"; readonly fp: string } = { posture: "private", fp: NONE },
): Promise<string> {
  const store = new AccountStateStore(opened.userId, opened.uvk, ctx.wire, ctx.storage);
  const w = await recordRecoveryChoice(store, ctx.storage, opened.userId, choice, nowMs);
  // The registration sealed the escrow to `fp` when the choice was operator: the escrow this browser knows of (§4.5).
  if (w.kind === "written" || w.kind === "unchanged") writeEscrowSeen(ctx.storage, opened.userId, choice.posture === "operator" ? choice.fp : null);
  return w.kind;
}

/**
 * Opens the vault for a session whose unlock checks passed: the session is persisted, the identity key recorded,
 * and the store hydrated and synced. Takes ownership of [opened]'s keys.
 */
export async function enterVault(
  ctx: WebContext,
  params: {
    opened: OpenedAccount;
    /** The account keys the unlock opened; a full set (with its genesis) is cached for the offline unlock. */
    keys: Pick<AccountKeysV2, "kdfSalt"> & Partial<AccountKeysV2>;
    /**
     * The wrap the unlock opened or sealed (spec 01 §7): kept in memory with the session, and every re-authentication of
     * the session is proven against it on this device before anything is sent.
     */
    wrap: SessionKeys;
    /** An unlock from the copy: the pending wraps kept beside it (vault/onboardflow.ts openFromCopy), kept pending here. */
    pendingWraps?: readonly SessionKeys[];
    email: string;
    pin: WebPin;
    cardNotice: CardStatus | null;
    /** How this session was made (§8.5): null for the unlock of a held session, which keeps what it recorded. */
    how?: SessionHow | null;
    /**
     * `online` (the default); `offline`, opened from this browser's copy while the server was unreachable;
     * `forked_copy`, the copy read under a forked pin (§4.4); or `ended_copy`, the copy of a session the server ended
     * (§4.4). In the last two nothing is sent, accepted or written, and the held session record is left as it is.
     */
    mode?: "online" | "offline" | "forked_copy" | "ended_copy";
    /**
     * The master password of a full-password unlock that reached the server (spec 01 §7): only for the quiet re-key,
     * awaited here and not kept. Absent for every other way in (the copy, sign-up, a kit recovery).
     */
    password?: string;
    /**
     * Spec 01 §7, "leaves both" (onboardflow `opened_from_copy`): the vault opens from the copy while the server serves
     * keys this browser does not know. The copy and its pending wraps stay exactly as they are, the session keeps them
     * pending as at an offline unlock, the session is marked ({@link SessionWrap.serverKeysNotKnown}), and no quiet
     * re-key runs: its proof would be refused.
     */
    serverKeysNotKnown?: boolean;
    /** A sign-in over a copy of the same account sealed under another master password (onboardflow `copySealedElsewhere`). */
    copySealedElsewhere?: boolean;
  },
  openCache: (userId: string) => Promise<VaultCache> = gatedCache,
): Promise<{ account: Account; store: VaultStore; meta: LoginMeta; shared: SharedLogSession; reKey?: QuietReKey }> {
  const { opened, email } = params;
  const mode = params.mode ?? "online";
  const readOnly = mode === "forked_copy" || mode === "ended_copy";
  // Design §12.2 rule 7: the pinned card names this account as the operator: nothing of the session is kept.
  if (cardNamesOperator(params.pin, opened.userId) || cardNamesOperator(ctx.pins.pinFor(ctx.origin), opened.userId)) throw new OperatorAccountError();
  const id = accountId(opened.identity.publicKey);
  // The shared-vault layer borrows the session's keys before the Account takes ownership of them.
  const parts = { userId: opened.userId, uvk: opened.uvk, identity: opened.identity, signing: opened.signing };
  const account = Account.fromOpened(opened, params.wrap);
  // Every transport this session uses goes through its fence, which a lock or a sign-out closes
  // (VaultStore.close), so nothing the session started can go out later, under this account's token or another's.
  const fence = new SessionFence();
  const client = fence.wrap(ctx.client);
  const wire = fence.wrap(ctx.wire);
  const shared = new SharedLogSession(parts, wire, ctx.storage, account.logKeyRing());
  if (params.how) shared.setSessionHow(params.how);
  ctx.client.boundUserId = account.userId;
  if (!readOnly) {
    recordSelfIdentityPub(account.userId, account, email);
    saveSession({ baseUrl: ctx.client.baseUrl, userId: account.userId, personalVaultId: account.personalVaultId, email, tokens: ctx.client.getTokens() });
  }
  let cache: VaultCache;
  try {
    cache = await openCache(account.userId);
  } catch {
    cache = new NullCache();
  }
  // Spec 02 §8: an online unlock refreshes this browser's copy of the account keys, with the genesis openAccount
  // checks at the next offline unlock. Only a full, fenced set displaces the held one (idbcache keeps the old).
  const k = params.keys;
  const notKnown = params.serverKeysNotKnown === true;
  if (notKnown) {
    account.sessionWrap.markServerKeysNotKnown();
    if (params.pendingWraps !== undefined) account.sessionWrap.adoptPending(params.pendingWraps);
  } else if (mode === "online") {
    let own = false;
    if (typeof k.genesis === "string" && k.wrappedUvk !== undefined && k.kdfParams !== undefined && k.encryptedIdentitySeed !== undefined && k.identityPub !== undefined) {
      own = await cache.setAccountKeysV2(k as AccountKeysV2).catch(() => false);
    }
    // Spec 01 §7: the server's word settles every password change left pending beside the copy, whichever password
    // opened it: the copy takes the wrap the password just opened online, and nothing stays pending. A write that fails
    // leaves the pending wraps where they are (the copy then still opens with either password), and the next online
    // unlock tries again; the vault opens either way.
    try {
      if (!own) {
        const held = await cache.accountKeysV2();
        if (held !== null) own = await cache.setAccountKeysV2({ ...held, kdfSalt: params.wrap.kdfSalt, kdfParams: params.wrap.kdfParams, wrappedUvk: params.wrap.wrappedUvk });
      }
      if (own && (await cache.pendingWraps()).length > 0) await cache.setPendingWraps([]);
    } catch {
      /* kept as it was: see above */
    }
  } else if (params.pendingWraps !== undefined) {
    // An unlock from the copy: the changes an earlier session sent with no answer stay pending in this one too.
    account.sessionWrap.adoptPending(params.pendingWraps);
  }
  // The item layer (sync, push, history, trash, attachments) runs on the post-cut-over wire client.
  const store = new VaultStore(client, account, cache, undefined, wire);
  store.attachFence(fence);
  store.attachSharedLogs(shared);
  if (readOnly) store.freezeAsReadOnlyCopy(mode === "ended_copy" ? "ended" : "forked");
  else store.attachPinRefresh(pinRefreshFor(ctx, store));
  try {
    await store.hydrate();
  } catch {
    /* a cache that does not read is skipped; the sync below repopulates */
  }
  // `copy`: the offline copy's side of a password change, on the same cache this session opened (a closed gate keeps none).
  const settings: SettingsSession = { wire, pins: ctx.pins, origin: ctx.origin, account: emailNorm(email) ?? email.trim().toLowerCase(), opened, wrap: account.sessionWrap, ...(readOnly ? {} : { copy: cacheCopyKeeper(account.userId, openCache) }) };
  const meta: LoginMeta = { pin: params.pin, cardNotice: params.cardNotice, email, accountId: id, settings, client, usageWire: boundTo(ctx.wire, () => ctx.client.boundUserId === account.userId), openedFrom: mode, ...(params.copySealedElsewhere === true && mode === "online" && !notKnown ? { copySealedElsewhere: true as const } : {}) };
  // §4.4: a read-only copy sends nothing, so no retry and no first sync.
  if (readOnly) return { account, store, meta, shared };
  // The first sync's failure is the vault's to show (its offline and anomaly states), not a sign-in failure: the
  // account's keys are verified by now. A log append left pending by an earlier session is re-posted byte for byte
  // first (the pull that follows reads it); each one that did not happen is said, with what it was (the store's notices).
  void net(
    (async () => {
      await store.resendHeldChanges().catch(() => []);
      await store.sync();
      // A decline whose leave never got through, where the log still lists this account through the declined add.
      await shared.leaveAgainForDeclines();
    })(),
  ).catch(() => {});
  // Spec 01 §7 (F61): after a full-password unlock that reached the server, the quiet re-key, inline and before the vault
  // is shown; the password is handed in for this only and not kept. Never for an unlock from the copy (mode `offline`).
  const reKey = params.password === undefined || notKnown ? "not_counted" : await quietReKey({ settings, password: params.password, unlock: mode === "online" ? "full_password_online" : "offline_copy", policy: () => wire.clientPolicy() });
  return { account, store, meta, shared, reKey };
}
