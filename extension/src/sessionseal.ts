// Runtime (value) imports carry the .ts extension so this leaf resolves under `node --test` (sessionseal.test.ts).
import { fromB64 } from "./crypto.ts";
import { nsKey } from "./serverurl.ts";
import type { KvArea } from "./trustedkv.ts";

/**
 * Sealed custody in storage.session (security review 2026-10, branch A16, and its review of 2026-10-23).
 *
 * The worker keeps unlocked custody in storage.session so the vault survives the worker being stopped when idle: the
 * session snapshot (tokens, unwrapped vault keys, decrypted items), the tab records (a pending save holds a page's
 * password in plaintext, also while locked), the armed quick-unlock record (the PIN-crackable UVK blob and a live
 * refresh token) and the known-logins digest (an HMAC key beside (site, username) digests). That content scripts cannot
 * reach storage.session is NOT relied on, on either engine (Chrome's browser-side enforcement stays, as a second
 * layer). Each of those records is therefore sealed here — AES-GCM 256 under a NON-EXTRACTABLE key that lives
 * in the extension origin's own IndexedDB, the isolation boundary both vendors document (Chromium
 * `docs/security/compromised-renderers.md`; Mozilla bug 2018494 points at origin-bound storage such as IndexedDB).
 *
 * The rules:
 *  - One key per browser session ([SEAL_DB_NAME], record [SEAL_KEY_RECORD], beside nothing else). Who decides that a
 *    browser session is new matters, because anyone who can write storage.session can make it look like anything:
 *     - [rotate]: the browser reported a new browser session (background: `runtime.onStartup`, `runtime.onInstalled`,
 *       events a web page cannot raise). Every sealed record is dropped and a fresh key replaces the old one; a write
 *       issued before that is dropped and a read issued before it reads absent.
 *     - At any other worker start the stored key is kept only if a record in storage.session OPENS under it (the shape
 *       of one proves nothing). Otherwise — no record, garbage, another key's records, copies from before a lock — every
 *       sealed record is dropped and a fresh key replaces the old one.
 *  - Each record is stored as `{v:1, iv, ct}`; the AAD binds the record kind and the origin namespace (and, for the
 *    snapshot and the tab records, the custody epoch below), so a sealed record replayed into another slot, another
 *    origin's slot, or the same slot after a lock does not open.
 *  - A read that does not open — a wrong key, a tampered or swapped record, an older epoch, plaintext — is ABSENT, which
 *    reads as locked. Such a record can never open, so it is dropped. Nothing unsealable is ever adopted.
 *  - Start: a plaintext value in a sealed slot (the previous build's, or anyone's), the pre-namespacing bare quick-unlock
 *    key, and any key this build does not keep are dropped. The plain inventory ([PLAIN_KINDS]) stays.
 *  - The custody epoch: a counter kept with the key and advanced by every lock ([lockErase]). The session snapshot and
 *    the tab records are sealed under it, so a copy taken while unlocked does not open once the vault locked, restarts
 *    included. The lock erases first and only then waits, bounded, for the new epoch to be written ([lockDurable]); a
 *    write that failed is retried at every later operation here; and a snapshot or tab record is written only under an
 *    epoch the key store already holds (held until it does, and not written at all if it will not), so no later worker
 *    reads it under an older epoch. A lock made with no key store is recorded against the stored key if the store
 *    answers later in the same worker life. The quick-unlock record and the known-logins digest are not bound to the
 *    epoch (they survive a lock by design).
 *  - No key store (no IndexedDB, Firefox "Never remember history", or no answer within the store's bound): nothing
 *    secret is persisted. A write removes the slot instead, so custody stays in worker memory (a stopped worker means a
 *    locked vault), and the caller must not arm quick unlock ([available] is false).
 *  - A lock never waits to erase: [lockErase] takes a copy of the two lock-scoped records as they stand (ciphertext,
 *    which the caller may open afterwards, under the epoch it was sealed in, to decide the quick-unlock arm) and
 *    dispatches their removal in the same step, before anything can wait; a write issued before a removal of its slot
 *    is dropped even if it was still waiting for the key or encrypting.
 *
 * Chrome-free: storage.session and the key store are injected (background.ts: chrome.storage.session, and the bounded
 * IndexedDB adapter trustedkv.idbKv over [SEAL_DB_NAME]).
 */

/** The sealing key's database: its own, apart from the quick-unlock co-key (`andvari-qu`) and the trust state
 *  (`andvari-trusted`). One record, [SEAL_KEY_RECORD] = `{ key: CryptoKey, epoch: number }`. */
export const SEAL_DB_NAME = "andvari-session-seal";
export const SEAL_KEY_RECORD = "sealKey";

/** The secret-bearing records of storage.session: each is sealed. */
export const SEALED_KINDS = ["session", "tabs", "quickUnlock", "knownLogins"] as const;
export type SealKind = (typeof SEALED_KINDS)[number];
/** The records left plain, none secret: the idle-lock notice (`{kind:"idle", seconds}`, the reason line on the unlock
 *  form), the update-check throttle stamp and the update channel's quiet marker (a reason from a fixed set). A write by
 *  anyone else can at most show a false reason line or move an update check; the forced check at start re-derives the
 *  last two. */
export const PLAIN_KINDS = ["lockNotice", "updateCheckedAt", "updateChannelQuiet"] as const;
export type PlainKind = (typeof PLAIN_KINDS)[number];

/** Kinds sealed under the custody epoch, which every lock advances. */
const EPOCH_BOUND: ReadonlySet<SealKind> = new Set<SealKind>(["session", "tabs"]);

/** The storage.session key a record lives under: the worker's existing keys (two global slots, the rest under the
 *  origin's `ns.<originKey>.` namespace). */
export function slotKey(kind: SealKind | PlainKind, originKey: string): string {
  return kind === "session" || kind === "tabs" || kind === "lockNotice" ? kind : nsKey(originKey, kind);
}

/** The two lock-scoped slots ([EPOCH_BOUND]), which every lock erases. */
const LOCK_SLOTS: readonly string[] = [slotKey("session", ""), slotKey("tabs", "")];

export type SessionKeyClass = { cls: "sealed"; kind: SealKind } | { cls: "plain"; kind: PlainKind } | { cls: "other" };

/** What a storage.session key is in this build's inventory. */
export function classifySessionKey(key: string): SessionKeyClass {
  if (key === "session" || key === "tabs") return { cls: "sealed", kind: key };
  if (key === "lockNotice") return { cls: "plain", kind: "lockNotice" };
  const m = /^ns\.[0-9a-f]{16}\.([A-Za-z]+)$/.exec(key);
  if (m) {
    const k = m[1]!;
    if (k === "quickUnlock" || k === "knownLogins") return { cls: "sealed", kind: k };
    if (k === "updateCheckedAt" || k === "updateChannelQuiet") return { cls: "plain", kind: k };
  }
  return { cls: "other" };
}

export interface SealedRecord {
  v: 1;
  iv: string;
  ct: string;
}

/** Exactly `{v:1, iv, ct}` with string fields. */
export function isSealedRecord(v: unknown): v is SealedRecord {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o);
  return keys.length === 3 && o.v === 1 && typeof o.iv === "string" && typeof o.ct === "string";
}

const IV_BYTES = 12;

function sealAad(kind: SealKind, originKey: string, epoch: number | null): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(JSON.stringify(["andvari/ext-session-seal", 1, kind, originKey, epoch]));
}

/** base64url, chunked (a session snapshot can run to megabytes; one char at a time would be slow). */
function b64(u: Uint8Array): string {
  let s = "";
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const ab = (u: Uint8Array): Uint8Array<ArrayBuffer> => {
  const c = new Uint8Array(u.length);
  c.set(u);
  return c;
};

/** A usable sealing key: a non-extractable AES-GCM 256 key that can encrypt and decrypt. */
function usableKey(k: unknown): k is CryptoKey {
  if (typeof k !== "object" || k === null) return false;
  const c = k as { type?: unknown; extractable?: unknown; algorithm?: { name?: unknown; length?: unknown }; usages?: unknown };
  return (
    c.type === "secret" &&
    c.extractable === false &&
    c.algorithm?.name === "AES-GCM" &&
    c.algorithm?.length === 256 &&
    Array.isArray(c.usages) &&
    c.usages.includes("encrypt") &&
    c.usages.includes("decrypt")
  );
}

interface KeyState {
  key: CryptoKey;
  /** The custody epoch; advanced in place by [SessionSeal.lockErase]. */
  epoch: number;
}

/** A stored key record that can be used, or null. */
function keyRecordOf(v: unknown): KeyState | null {
  if (typeof v !== "object" || v === null) return null;
  const r = v as { key?: unknown; epoch?: unknown };
  const epoch = r.epoch;
  if (!usableKey(r.key) || typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 0) return null;
  return { key: r.key, epoch };
}

export interface SessionSealDeps {
  /** storage.session (background: chrome.storage.session). */
  session: KvArea;
  /** The key store (background: trustedkv.idbKv over [SEAL_DB_NAME], bounded per operation). */
  keys: KvArea;
  /** Key generation; tests may stand one in. Default: a non-extractable AES-GCM 256 key. */
  generateKey?: () => Promise<CryptoKey>;
  /** The current origin's key, asked only when a start has to tell whether a record in one of the two global slots
   *  (`session`, `tabs`, whose origin is in the AAD alone) opens under the stored key. Null or absent: they do not count.
   *  Background: serverReady, then currentOriginKey. */
  originKey?: () => Promise<string | null>;
}

/** What a lock's erase hands back. */
export interface LockErase {
  /** The removal of the session snapshot and the tab records, dispatched before [SessionSeal.lockErase] returned. */
  erased: Promise<void>;
  /** Those two records as they stood at the lock, opened for [originKey] under the epoch they were sealed in: what the
   *  caller may use to decide the quick-unlock arm and keep the tab records' page-known half. Absent where a record does
   *  not open, with no key store, or once the key was replaced. Waits for the key; the caller bounds that wait. */
  opened(originKey: string): Promise<{ session?: unknown; tabs?: unknown }>;
}

const defaultGenerate = (): Promise<CryptoKey> =>
  crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, /* extractable */ false, ["encrypt", "decrypt"]) as Promise<CryptoKey>;

export class SessionSeal {
  /** Settles once worker start decided the key (following any [rotate] started meanwhile): true = sealing works; false =
   *  nothing secret is persisted. Never rejects. */
  readonly ready: Promise<boolean>;
  private readonly deps: SessionSealDeps;
  /** The key in effect: undefined while a decision is pending (worker start's, or a rotation's); null = no key store. */
  private state: KeyState | null | undefined = undefined;
  /** The decision in progress or last made (worker start's, or the latest rotation's). Never rejects. */
  private decision: Promise<void>;
  /** Bumped by every [rotate]: an operation issued under an older generation is dropped (a write) or absent (a read). */
  private gen = 0;
  /** Locks that ran while a decision was pending: their epoch advance is applied when the key is known. */
  private pendingBumps = 0;
  /** The epoch the key in effect was loaded with, before [pendingBumps]: what an early lock's copy was sealed under. */
  private loadedEpoch = 0;
  /** Locks that ran with no key store: recorded against the stored key should the store answer later in this life. */
  private owedBumps = 0;
  /** The highest epoch the key store is known to hold for the key in effect. */
  private durable = -1;
  private flushing: Promise<boolean> | null = null;
  private owedFlush: Promise<void> | null = null;
  /** Every key-store write, one at a time and in order (a fresh key, an epoch, an owed epoch, a removal). */
  private keyChain: Promise<void> = Promise.resolve();
  /** Per slot: bumped by every removal, so a write issued before it is dropped. */
  private readonly removals = new Map<string, number>();
  /** Per slot: bumped by every write, so a failed read drops the record only if no write was issued meanwhile. */
  private readonly writes = new Map<string, number>();
  /** Per slot: the tail of its write queue (never rejects); writes land in call order. */
  private readonly chains = new Map<string, Promise<void>>();

  constructor(deps: SessionSealDeps) {
    this.deps = deps;
    this.decision = this.decide(0, this.init(0));
    this.ready = this.settled();
  }

  /** true or false once a decision is in effect; null while one is pending (at start, or while the key is replaced). */
  available(): boolean | null {
    return this.state === undefined ? null : this.state !== null;
  }

  /** How many times the key was replaced in this worker life ([rotate]). */
  generation(): number {
    return this.gen;
  }

  /** Resolves once no decision is pending, following any rotation started meanwhile: whether sealing works. */
  async settled(): Promise<boolean> {
    return (await this.current()) !== null;
  }

  private async current(): Promise<KeyState | null> {
    for (;;) {
      const d = this.decision;
      await d;
      if (d === this.decision) return this.state ?? null;
    }
  }

  /** Put generation [g]'s decision into effect, unless a rotation superseded it (that one decides instead). */
  private decide(g: number, loading: Promise<KeyState | null>): Promise<void> {
    return loading.then(
      (st) => this.adopt(g, st),
      () => this.adopt(g, null),
    );
  }

  private adopt(g: number, st: KeyState | null): void {
    if (g !== this.gen) return;
    if (st === null) {
      this.owedBumps += this.pendingBumps;
      this.pendingBumps = 0;
      this.state = null;
    } else {
      this.loadedEpoch = st.epoch;
      this.durable = st.epoch; // what the store holds: it was just read, or just written
      this.state = { key: st.key, epoch: st.epoch + this.pendingBumps };
      this.pendingBumps = 0;
    }
    this.kick();
  }

  private async init(g: number): Promise<KeyState | null> {
    const { session, keys } = this.deps;
    let all: Record<string, unknown>;
    try {
      all = await session.get(null);
    } catch {
      return null; // no storage.session: nothing to seal into
    }
    const drop: string[] = [];
    const sealed: [string, unknown][] = [];
    for (const [k, v] of Object.entries(all)) {
      const c = classifySessionKey(k);
      if (c.cls === "plain") continue;
      if (c.cls === "sealed" && isSealedRecord(v)) sealed.push([k, v]);
      else drop.push(k); // plaintext in a sealed slot, the bare pre-namespacing key, or not this build's
    }
    if (drop.length > 0) await session.remove(drop).catch(() => {});
    try {
      if (sealed.length > 0) {
        const stored = keyRecordOf((await keys.get(SEAL_KEY_RECORD))[SEAL_KEY_RECORD]);
        // A16 review R1: kept only if something here was really sealed under it. A record's shape proves nothing (a
        // planted `{v:1, iv, ct}` used to keep the key, and with it a copy of an earlier session's records, openable).
        if (stored !== null && (await this.anyOpens(stored, sealed))) return stored;
        // No usable key, or nothing opens under it (another key's records, garbage, copies from before a lock): they
        // can never open. Drop them; start over.
        await session.remove(sealed.map(([k]) => k)).catch(() => {});
      }
      return await this.freshKey(g);
    } catch {
      return null; // the key store refused or did not answer in time: persist nothing secret
    }
  }

  /** Whether any of [sealed] opens under [st] — its own slot, origin and the stored epoch. */
  private async anyOpens(st: KeyState, sealed: readonly [string, unknown][]): Promise<boolean> {
    const global: [SealKind, unknown][] = [];
    for (const [k, raw] of sealed) {
      const c = classifySessionKey(k);
      if (c.cls !== "sealed") continue;
      if (k === "session" || k === "tabs") {
        global.push([c.kind, raw]);
        continue;
      }
      const originKey = k.slice("ns.".length, "ns.".length + 16); // ns.<16 hex>.<kind>, checked by classifySessionKey
      if ((await this.open(st, c.kind, originKey, raw, st.epoch)) !== undefined) return true;
    }
    if (global.length === 0 || !this.deps.originKey) return false;
    let originKey: string | null;
    try {
      originKey = await this.deps.originKey();
    } catch {
      originKey = null;
    }
    if (originKey === null) return false;
    for (const [kind, raw] of global) if ((await this.open(st, kind, originKey, raw, st.epoch)) !== undefined) return true;
    return false;
  }

  /** A fresh key, written in place of any older one (so that one is gone) — unless generation [g] was superseded. */
  private async freshKey(g: number): Promise<KeyState | null> {
    const key = await (this.deps.generateKey ?? defaultGenerate)();
    if (!usableKey(key)) return null;
    if (!(await this.keyWrite(() => (g === this.gen ? { key, epoch: 0 } : null)))) return null;
    return { key, epoch: 0 };
  }

  /** Queue a key-store write; [make] is evaluated when its turn comes (null: skip it). Resolves whether it was written;
   *  rejects when the store refused. */
  private keyWrite(make: () => KeyState | null): Promise<boolean> {
    const run = this.keyChain.then(async () => {
      const rec = make();
      if (rec === null) return false;
      await this.deps.keys.set({ [SEAL_KEY_RECORD]: { key: rec.key, epoch: rec.epoch } });
      return true;
    });
    this.keyChain = run.then(
      () => {},
      () => {},
    );
    return run;
  }

  /**
   * The browser reported a new browser session (background: `runtime.onStartup`, `runtime.onInstalled` — a browser start,
   * an install, an update, a reload): nothing sealed in storage.session can be ours. Drop every sealed record and replace
   * the key. Until that is decided nothing is read or written; an operation issued before this call is dropped (a write)
   * or reads absent (a read), and a lock's copy taken before it never opens. When the key store refuses the new key, the
   * old one is deleted too (best effort) and nothing secret is persisted. Resolves whether a new key is in effect. Never
   * rejects.
   */
  rotate(): Promise<boolean> {
    this.gen += 1;
    const g = this.gen;
    const prior = this.decision;
    this.state = undefined;
    this.pendingBumps = 0;
    this.owedBumps = 0;
    this.durable = -1;
    const loading = (async (): Promise<KeyState | null> => {
      await prior;
      try {
        const all = await this.deps.session.get(null);
        const sealed = Object.keys(all).filter((k) => classifySessionKey(k).cls !== "plain");
        if (sealed.length > 0) await this.deps.session.remove(sealed);
      } catch {
        /* storage.session unreadable: the new key alone keeps every older record from opening */
      }
      try {
        const st = await this.freshKey(g);
        if (st !== null) return st;
      } catch {
        /* refused below */
      }
      await this.keyRemove(g).catch(() => {});
      return null;
    })();
    this.decision = this.decide(g, loading);
    return this.settled();
  }

  private keyRemove(g: number): Promise<void> {
    const run = this.keyChain.then(async () => {
      if (g === this.gen) await this.deps.keys.remove(SEAL_KEY_RECORD);
    });
    this.keyChain = run.then(
      () => {},
      () => {},
    );
    return run;
  }

  private async open(st: KeyState, kind: SealKind, originKey: string, raw: unknown, epoch: number): Promise<unknown> {
    if (!isSealedRecord(raw)) return undefined;
    try {
      const iv = fromB64(raw.iv);
      if (iv.length !== IV_BYTES) return undefined;
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ab(iv), additionalData: sealAad(kind, originKey, EPOCH_BOUND.has(kind) ? epoch : null) },
        st.key,
        ab(fromB64(raw.ct)),
      );
      return JSON.parse(new TextDecoder().decode(pt));
    } catch {
      return undefined;
    }
  }

  private async read(kind: SealKind, originKey: string, st: KeyState, g: number): Promise<unknown> {
    const k = slotKey(kind, originKey);
    const writes = this.writes.get(k) ?? 0;
    const removals = this.removals.get(k) ?? 0;
    let raw: unknown;
    try {
      raw = (await this.deps.session.get(k))[k];
    } catch {
      return undefined;
    }
    if (raw === undefined) return undefined;
    const v = await this.open(st, kind, originKey, raw, st.epoch);
    if (g !== this.gen || this.state !== st) return undefined; // the key was replaced meanwhile: nothing read under the old one counts
    if (v === undefined && (this.writes.get(k) ?? 0) === writes && (this.removals.get(k) ?? 0) === removals) {
      void this.removeKeys([k]).catch(() => {}); // it can never open under this key: drop it (absent = locked)
    }
    return v;
  }

  /** The record in [kind]'s slot for [originKey], or undefined when absent or unopenable. Waits for writes to that
   *  slot issued before it, and for the key. Absent when the key is replaced after this call. */
  async get(kind: SealKind, originKey: string): Promise<unknown> {
    const g = this.gen;
    await this.chains.get(slotKey(kind, originKey));
    const st = await this.current();
    this.kick();
    if (st === null || g !== this.gen) return undefined;
    return this.read(kind, originKey, st, g);
  }

  /** Like [get], but never waits for the key: while a decision is pending (the key store has not answered), absent. */
  async peek(kind: SealKind, originKey: string): Promise<unknown> {
    const st = this.state;
    if (!st) return undefined;
    return this.read(kind, originKey, st, this.gen);
  }

  /** Seal [value] (captured now, as JSON) into [kind]'s slot for [originKey]. Resolves true when the sealed record was
   *  written; false when nothing was written — no key store (the slot is removed instead, so no older copy outlives
   *  this write), a snapshot or tab record whose epoch the key store would not take (removed likewise), the slot was
   *  removed after this call, or the key was replaced after it. Writes to one slot land in call order. */
  set(kind: SealKind, originKey: string, value: unknown): Promise<boolean> {
    const k = slotKey(kind, originKey);
    const json = JSON.stringify(value);
    if (json === undefined) return Promise.reject(new TypeError(`sessionseal: nothing to seal for ${kind}`));
    const g = this.gen;
    const removals = this.removals.get(k) ?? 0;
    this.writes.set(k, (this.writes.get(k) ?? 0) + 1);
    const dropped = () => g !== this.gen || (this.removals.get(k) ?? 0) !== removals;
    const op = async (): Promise<boolean> => {
      const st = await this.current();
      this.kick();
      if (dropped()) return false;
      if (st === null) {
        await this.deps.session.remove(k).catch(() => {}); // custody stays in worker memory
        return false;
      }
      let epoch: number | null = null;
      if (EPOCH_BOUND.has(kind)) {
        // A16 review R2: held until the key store holds the epoch it is sealed under. Written under an epoch that never
        // reached the store, the record would not open at the next start (which reads the older one), and the copies
        // taken before the lock that advanced it would.
        if (!(await this.epochDurable(st))) {
          if (!dropped()) await this.deps.session.remove(k).catch(() => {});
          return false;
        }
        if (dropped()) return false;
        epoch = st.epoch; // durable; a lock since would have removed this slot (dropped above)
      }
      const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
      const ct = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: sealAad(kind, originKey, epoch) }, st.key, new TextEncoder().encode(json)),
      );
      // Re-checked right before the write: the check and the dispatch below run in one step, so a removal (a lock) or a
      // rotation is either already dispatched (and this write dropped) or dispatched after this write.
      if (dropped() || this.state !== st || (epoch !== null && st.epoch !== epoch)) return false;
      await this.deps.session.set({ [k]: { v: 1, iv: b64(iv), ct: b64(ct) } satisfies SealedRecord });
      return true;
    };
    const p = (this.chains.get(k) ?? Promise.resolve()).then(op);
    const tail = p.then(
      () => {},
      () => {},
    );
    this.chains.set(k, tail);
    void tail.then(() => {
      if (this.chains.get(k) === tail) this.chains.delete(k);
    });
    return p;
  }

  /** Remove storage.session [keys] now (dispatched before this returns; it never waits for the key). A write to one of
   *  them issued earlier and not yet landed is dropped. */
  removeKeys(keys: readonly string[]): Promise<void> {
    for (const k of keys) this.removals.set(k, (this.removals.get(k) ?? 0) + 1);
    const removed = keys.length === 0 ? Promise.resolve() : this.deps.session.remove([...keys]); // dispatched first
    this.kick();
    return removed;
  }

  remove(kind: SealKind, originKey: string): Promise<void> {
    return this.removeKeys([slotKey(kind, originKey)]);
  }

  /**
   * The lock's erase (doLock). Waits on nothing: in one step it takes a copy of the session snapshot and the tab records
   * as they stand (storage.session, ciphertext), advances the custody epoch in memory — so no copy taken before this call
   * opens through [get] again — and dispatches the removal of both. A lock that runs before the key is known advances
   * the epoch as soon as it is; one with no key store records the advance against the stored key if the store answers
   * later in this worker life. Writing the new epoch is retried until the store takes it ([lockDurable]).
   */
  lockErase(): LockErase {
    let captured: Promise<Record<string, unknown>>;
    try {
      captured = this.deps.session.get(LOCK_SLOTS).then(
        (r) => r,
        () => ({}),
      );
    } catch {
      captured = Promise.resolve({});
    }
    const g = this.gen;
    const st = this.state;
    let sealedIn: () => number | null;
    if (st) {
      const e = st.epoch;
      st.epoch += 1;
      sealedIn = () => e;
    } else if (st === undefined) {
      const i = this.pendingBumps;
      this.pendingBumps += 1;
      sealedIn = () => this.loadedEpoch + i;
    } else {
      this.owedBumps += 1;
      sealedIn = () => null;
    }
    const erased = this.removeKeys(LOCK_SLOTS); // kicks the epoch's write too
    return {
      erased,
      opened: async (originKey: string) => {
        const raw = await captured;
        const cur = await this.current();
        const e = sealedIn();
        if (cur === null || g !== this.gen || e === null) return {};
        return { session: await this.open(cur, "session", originKey, raw.session, e), tabs: await this.open(cur, "tabs", originKey, raw.tabs, e) };
      },
    };
  }

  /**
   * After a lock's erase: whether the key store now holds the epoch that lock advanced to (with no key store: whether the
   * lock was recorded against the stored key), waiting at most [boundMs]. The erase never waits for this; past the bound
   * the write goes on, and a failed one is retried at every later operation here.
   */
  lockDurable(boundMs: number): Promise<boolean> {
    const work = (async (): Promise<boolean> => {
      const st = await this.current();
      if (st !== null) return this.epochDurable(st);
      if (this.owedBumps > 0) await this.flushOwed();
      return this.owedBumps === 0;
    })();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const bound = new Promise<boolean>((r) => (timer = setTimeout(() => r(false), boundMs)));
    return Promise.race([work, bound]).finally(() => clearTimeout(timer));
  }

  /** Retry what the key store still owes — the epoch in effect, or a lock made with no key store. Never waits. */
  private kick(): void {
    const st = this.state;
    if (st && st.epoch > this.durable) void this.flush(st);
    else if (st === null && this.owedBumps > 0) void this.flushOwed();
  }

  private isDurable(st: KeyState): boolean {
    return this.state === st && this.durable >= st.epoch;
  }

  /** Write the epoch in effect beside the key (one write at a time; a caller during one gets that one). The epoch is
   *  read when the write's turn comes, so a write queued behind others carries the latest. Resolves whether the store
   *  took it. */
  private flush(st: KeyState): Promise<boolean> {
    if (this.flushing) return this.flushing;
    const g = this.gen;
    let written = -1;
    const p: Promise<boolean> = this.keyWrite(() => {
      if (g !== this.gen || this.state !== st) return null;
      written = st.epoch;
      return { key: st.key, epoch: written };
    })
      .then(
        (wrote) => {
          if (wrote && g === this.gen && this.state === st && written > this.durable) this.durable = written;
          return wrote;
        },
        () => false, // the store refused: still owed, retried at the next operation
      )
      .then((took) => {
        if (this.flushing === p) this.flushing = null;
        return took;
      });
    this.flushing = p;
    return p;
  }

  private async epochDurable(st: KeyState): Promise<boolean> {
    if (this.isDurable(st)) return true;
    const queued = this.flushing !== null;
    const took = await this.flush(st);
    // A write already under way when this was asked may carry an earlier epoch: one more, if the store is taking them.
    if (queued && took && this.state === st && !this.isDurable(st)) await this.flush(st);
    return this.isDurable(st);
  }

  /** No key store in this worker life, yet it locked: once the store answers, advance the stored key's epoch by those
   *  locks, so a copy sealed before them does not open in a later life. */
  private flushOwed(): Promise<void> {
    if (this.owedFlush) return this.owedFlush;
    const g = this.gen;
    const n = this.owedBumps;
    const p: Promise<void> = (async () => {
      const stored = keyRecordOf((await this.deps.keys.get(SEAL_KEY_RECORD))[SEAL_KEY_RECORD]);
      // No usable key there: nothing sealed can open under it, so nothing is owed.
      const done = stored === null || (await this.keyWrite(() => (g === this.gen && this.state === null ? { key: stored.key, epoch: stored.epoch + n } : null)));
      if (done && g === this.gen) this.owedBumps = Math.max(0, this.owedBumps - n);
    })()
      .catch(() => {})
      .then(() => {
        if (this.owedFlush === p) this.owedFlush = null;
      });
    this.owedFlush = p;
    return p;
  }

  /** storage.session for the per-origin purge's prefix sweep (serverswitch.purgeOriginRecords): lists the raw keys,
   *  removes through [removeKeys]. */
  purgeArea(): KvArea {
    return {
      get: (keys) => this.deps.session.get(keys),
      set: () => {
        throw new Error("sessionseal: the purge area removes only");
      },
      remove: (keys) => this.removeKeys(typeof keys === "string" ? [keys] : keys),
    };
  }
}

function plainOnly(key: string): void {
  if (classifySessionKey(key).cls !== "plain") throw new Error(`sessionseal: ${key} is not in the plain session inventory`);
}

/**
 * storage.session for the plain inventory ([PLAIN_KINDS]) only. Every other key — a sealed slot above all — is refused
 * when called (it throws), so a secret cannot be written, read or removed around the seal through this area.
 */
export function plainSessionArea(session: KvArea): KvArea {
  const list = (keys: string | readonly string[] | null): string[] => {
    if (keys === null) throw new Error("sessionseal: (all keys) is not in the plain session inventory");
    const l = typeof keys === "string" ? [keys] : [...keys];
    l.forEach(plainOnly);
    return l;
  };
  return {
    get(keys) {
      return session.get(list(keys));
    },
    set(items) {
      Object.keys(items).forEach(plainOnly);
      return session.set(items);
    },
    remove(keys) {
      return session.remove(list(keys));
    },
  };
}
