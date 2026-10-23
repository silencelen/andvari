// Runtime (value) imports carry the .ts extension so this leaf resolves under `node --test` (sessionseal.test.ts).
import { fromB64 } from "./crypto.ts";
import { nsKey } from "./serverurl.ts";
import type { KvArea } from "./trustedkv.ts";

/**
 * Sealed custody in storage.session (security review 2026-10, branch A16).
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
 *  - One key per browser session ([SEAL_DB_NAME], record [SEAL_KEY_RECORD], beside nothing else). At worker start, if
 *    storage.session holds no sealed record (a browser restart, an extension reload or update), a fresh key REPLACES
 *    the old one, so a key never outlives the records it seals. If sealed records exist but no usable key does, they
 *    can never be opened: they are dropped and a fresh key is made.
 *  - Each record is stored as `{v:1, iv, ct}`; the AAD binds the record kind and the origin namespace (and, for the
 *    snapshot and the tab records, the custody epoch below), so a sealed record replayed into another slot, another
 *    origin's slot, or the same slot after a lock does not open.
 *  - A read that does not open — a wrong key, a tampered or swapped record, an older epoch, plaintext — is ABSENT, which
 *    reads as locked. Such a record can never open, so it is dropped. Nothing unsealable is ever adopted.
 *  - Start: a plaintext value in a sealed slot (the previous build's, or anyone's), the pre-namespacing bare quick-unlock
 *    key, and any key this build does not keep are dropped. The plain inventory ([PLAIN_KINDS]) stays.
 *  - The custody epoch: a counter kept with the key and advanced by every lock ([lockErase]). The session snapshot and
 *    the tab records are sealed under it, so a copy taken while unlocked does not open once the vault locked, restarts
 *    included. The epoch is persisted without the lock waiting for it; the quick-unlock record and the known-logins
 *    digest are not bound to it (they survive a lock by design).
 *  - No key store (no IndexedDB, Firefox "Never remember history", or no answer within the store's bound): nothing
 *    secret is persisted. A write removes the slot instead, so custody stays in worker memory (a stopped worker means a
 *    locked vault), and the caller must not arm quick unlock ([available] is false).
 *  - A lock never waits on IndexedDB: [remove] and [lockErase] dispatch the storage.session removal at once, and a
 *    write issued before a removal of its slot is dropped even if it was still waiting for the key or encrypting.
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

export interface SessionSealDeps {
  /** storage.session (background: chrome.storage.session). */
  session: KvArea;
  /** The key store (background: trustedkv.idbKv over [SEAL_DB_NAME], bounded per operation). */
  keys: KvArea;
  /** Key generation; tests may stand one in. Default: a non-extractable AES-GCM 256 key. */
  generateKey?: () => Promise<CryptoKey>;
}

const defaultGenerate = (): Promise<CryptoKey> =>
  crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, /* extractable */ false, ["encrypt", "decrypt"]) as Promise<CryptoKey>;

export class SessionSeal {
  /** Settles once worker start decided the key: true = sealing works; false = nothing secret is persisted. Never rejects. */
  readonly ready: Promise<boolean>;
  private readonly deps: SessionSealDeps;
  /** undefined while [ready] is pending; null = no key store. */
  private state: KeyState | null | undefined = undefined;
  /** Locks that ran before [ready] settled: their epoch advance is applied when the key is known. */
  private pendingBumps = 0;
  /** Per slot: bumped by every removal, so a write issued before it is dropped. */
  private readonly removals = new Map<string, number>();
  /** Per slot: bumped by every write, so a failed read drops the record only if no write was issued meanwhile. */
  private readonly writes = new Map<string, number>();
  /** Per slot: the tail of its write queue (never rejects); writes land in call order. */
  private readonly chains = new Map<string, Promise<void>>();
  private epochChain: Promise<void> = Promise.resolve();

  constructor(deps: SessionSealDeps) {
    this.deps = deps;
    this.ready = this.init().then(
      (st) => {
        if (st && this.pendingBumps > 0) {
          st.epoch += this.pendingBumps;
          this.persistEpoch(st);
        }
        this.state = st;
        return st !== null;
      },
      () => {
        this.state = null;
        return false;
      },
    );
  }

  /** true or false once [ready] settled; null before. */
  available(): boolean | null {
    return this.state === undefined ? null : this.state !== null;
  }

  private async init(): Promise<KeyState | null> {
    const { session, keys } = this.deps;
    let all: Record<string, unknown>;
    try {
      all = await session.get(null);
    } catch {
      return null; // no storage.session: nothing to seal into
    }
    const drop: string[] = [];
    const sealed: string[] = [];
    for (const [k, v] of Object.entries(all)) {
      const c = classifySessionKey(k);
      if (c.cls === "plain") continue;
      if (c.cls === "sealed" && isSealedRecord(v)) sealed.push(k);
      else drop.push(k); // plaintext in a sealed slot, the bare pre-namespacing key, or not this build's
    }
    if (drop.length > 0) await session.remove(drop).catch(() => {});
    try {
      if (sealed.length > 0) {
        const rec = (await keys.get(SEAL_KEY_RECORD))[SEAL_KEY_RECORD] as { key?: unknown; epoch?: unknown } | undefined;
        const epoch = rec?.epoch;
        if (rec && usableKey(rec.key) && typeof epoch === "number" && Number.isSafeInteger(epoch) && epoch >= 0) {
          return { key: rec.key, epoch };
        }
        // Sealed records but no usable key (site data cleared): they can never open. Drop them; start over.
        await session.remove(sealed).catch(() => {});
      }
      const key = await (this.deps.generateKey ?? defaultGenerate)();
      if (!usableKey(key)) return null;
      await keys.set({ [SEAL_KEY_RECORD]: { key, epoch: 0 } }); // replaces (and so deletes) any older key
      return { key, epoch: 0 };
    } catch {
      return null; // the key store refused or did not answer in time: persist nothing secret
    }
  }

  private epochOf(kind: SealKind, st: KeyState): number | null {
    return EPOCH_BOUND.has(kind) ? st.epoch : null;
  }

  private async unseal(kind: SealKind, originKey: string, raw: unknown): Promise<unknown> {
    const st = this.state;
    if (!st || !isSealedRecord(raw)) return undefined;
    try {
      const iv = fromB64(raw.iv);
      if (iv.length !== IV_BYTES) return undefined;
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ab(iv), additionalData: sealAad(kind, originKey, this.epochOf(kind, st)) },
        st.key,
        ab(fromB64(raw.ct)),
      );
      return JSON.parse(new TextDecoder().decode(pt));
    } catch {
      return undefined;
    }
  }

  private async read(kind: SealKind, originKey: string): Promise<unknown> {
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
    const v = await this.unseal(kind, originKey, raw);
    if (v === undefined && this.state && (this.writes.get(k) ?? 0) === writes && (this.removals.get(k) ?? 0) === removals) {
      void this.removeKeys([k]).catch(() => {}); // it can never open under this key: drop it (absent = locked)
    }
    return v;
  }

  /** The record in [kind]'s slot for [originKey], or undefined when absent or unopenable. Waits for writes to that
   *  slot issued before it, and for the key. */
  async get(kind: SealKind, originKey: string): Promise<unknown> {
    await this.chains.get(slotKey(kind, originKey));
    if (!(await this.ready)) return undefined;
    return this.read(kind, originKey);
  }

  /** Like [get], but never waits for the key: before [ready] settled (the key store has not answered), absent. */
  async peek(kind: SealKind, originKey: string): Promise<unknown> {
    if (!this.state) return undefined;
    return this.read(kind, originKey);
  }

  /** Seal [value] (captured now, as JSON) into [kind]'s slot for [originKey]. Resolves true when the sealed record was
   *  written; false when nothing was written — no key store (the slot is removed instead, so no older copy outlives
   *  this write), or the slot was removed after this call. Writes to one slot land in call order. */
  set(kind: SealKind, originKey: string, value: unknown): Promise<boolean> {
    const k = slotKey(kind, originKey);
    const json = JSON.stringify(value);
    if (json === undefined) return Promise.reject(new TypeError(`sessionseal: nothing to seal for ${kind}`));
    const removals = this.removals.get(k) ?? 0;
    this.writes.set(k, (this.writes.get(k) ?? 0) + 1);
    const removedSince = () => (this.removals.get(k) ?? 0) !== removals;
    const op = async (): Promise<boolean> => {
      const ok = await this.ready;
      if (removedSince()) return false;
      const st = this.state;
      if (!ok || !st) {
        await this.deps.session.remove(k).catch(() => {}); // custody stays in worker memory
        return false;
      }
      const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
      const ct = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv, additionalData: sealAad(kind, originKey, this.epochOf(kind, st)) },
          st.key,
          new TextEncoder().encode(json),
        ),
      );
      // Re-checked right before the write: the check and the dispatch below run in one step, so a removal (a lock) is
      // either already dispatched (and this write dropped) or dispatched after this write.
      if (removedSince()) return false;
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
    return keys.length === 0 ? Promise.resolve() : this.deps.session.remove([...keys]);
  }

  remove(kind: SealKind, originKey: string): Promise<void> {
    return this.removeKeys([slotKey(kind, originKey)]);
  }

  /**
   * The lock's erase (doLock). Never waits on IndexedDB: the custody epoch advances in memory at once, so no copy of
   * the session snapshot or the tab records taken before this call opens again, and the removal of both is dispatched
   * before this returns. The new epoch is persisted beside the key without the lock waiting for it. A lock that runs
   * before the key is known advances the epoch as soon as it is.
   */
  lockErase(): Promise<void> {
    const st = this.state;
    if (st) {
      st.epoch += 1;
      this.persistEpoch(st);
    } else if (st === undefined) {
      this.pendingBumps += 1;
    }
    return this.removeKeys([slotKey("session", ""), slotKey("tabs", "")]);
  }

  private persistEpoch(st: KeyState): void {
    const rec = { key: st.key, epoch: st.epoch };
    this.epochChain = this.epochChain.then(
      () => this.deps.keys.set({ [SEAL_KEY_RECORD]: rec }).catch(() => {}),
      () => {},
    );
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
