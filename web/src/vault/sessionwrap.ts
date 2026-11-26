import { adUvk } from "../crypto/ad";
import { ctEquals, fromB64, toB64 } from "../crypto/bytes";
import { open } from "../crypto/envelope";
import { assertServerKdfParams, authKey as deriveAuthKey, type KdfParams, KdfPolicyError, masterKey, wrapKey as deriveWrapKey } from "../crypto/keys";

/** The KDF salt and parameters and the wrapped UVK a session holds; a password change answers the new ones. */
export interface SessionKeys {
  readonly kdfSalt: string;
  readonly kdfParams: KdfParams;
  readonly wrappedUvk: string;
}

/** What the proof on this device found. Nothing in it is a guess about the server. */
export type WrapProof =
  /** The password opened one of the session's own wraps to the session's UVK; `currentAuthKey` is derived in the same pass. */
  | { readonly kind: "proven"; readonly currentAuthKey: string; readonly wrap: SessionKeys }
  /** The password opens none of the session's own wraps: found out here, and nothing is sent. */
  | { readonly kind: "wrong_password" }
  /** The kept cost is outside this client's own bounds (never expected: every kept wrap was fenced when it was kept). */
  | { readonly kind: "weakened"; readonly error: KdfPolicyError }
  /** This tab holds no wrap for the session, so it cannot prove anything: nothing is derived or sent. */
  | { readonly kind: "no_wrap" };

/**
 * The wrap this tab keeps for its session (spec 01 §7, "the proof runs against the device's own wrap"; the web twin of
 * core `SessionKeeper`). It is the salt, cost and wrapped UVK that the typed password opened, or that this tab sealed
 * under it, when the session was made: at sign-in the prelogin's salt and cost with the wrap the login answered, at
 * the unlock of a held session the account's keys the password opened, at the offline unlock the offline copy's own
 * keys, at sign-up and at a kit recovery the wrap this tab sealed and sent. It lives in memory only, beside the
 * session's keys, for as long as the session is open in this tab: a lock, a sign-out or a reload drops it, and the
 * next unlock keeps the wrap that unlock opened.
 *
 * While a password change is pending (sent, with no answer that it was made or refused), the new wrap is kept beside
 * the old one, and either password proves. The server's answer settles it, or, when no answer came, the server's keys
 * ({@link settle}) before another change is sent. Where the browser keeps the offline copy, the pending wraps are also
 * kept beside it (vault/settingsflow.ts CopyKeeper), so an offline unlock after a reload opens with either password
 * ({@link adoptPending}) until the next online unlock settles them.
 *
 * Every re-authentication is proven here first, under the kept wrap's own salt and cost. Nothing is dialed for the
 * proof, no value a server names at that moment goes into it, and a wrong password sends nothing at all.
 */
export class SessionWrap {
  private own: SessionKeys | null;
  /** The wraps of changes sent with no answer yet, oldest first. A later change never drops an earlier one unanswered. */
  private pendingWraps: SessionKeys[] = [];
  private notKnown = false;

  constructor(own: SessionKeys | null) {
    this.own = own === null ? null : copyOf(own);
  }

  /**
   * Spec 01 §7, "leaves both": this session was opened from the offline copy while the server served keys this browser
   * does not know, so the server checks this session's proofs against another wrap. While it is set, a proof the
   * server refuses is said as that, never as a wrong password. It lasts as long as the session.
   */
  get serverKeysNotKnown(): boolean {
    return this.notKnown;
  }

  markServerKeysNotKnown(): void {
    this.notKnown = true;
  }

  /** The session's own wrap, or null when this tab holds none. */
  get current(): SessionKeys | null {
    return this.own;
  }

  /** The newest wrap of a password change sent with no answer yet, or null. */
  get pending(): SessionKeys | null {
    return this.pendingWraps[this.pendingWraps.length - 1] ?? null;
  }

  /** Every wrap of a change sent with no answer yet, oldest first. */
  get pendingAll(): readonly SessionKeys[] {
    return this.pendingWraps;
  }

  /** A password change is about to be sent with [next]: kept beside the session's own wrap until the answer. */
  beginChange(next: SessionKeys): void {
    this.pendingWraps.push(copyOf(next));
  }

  /** The server made the change: exactly the wrap that was sent, same salt and same cost, is the session's own now. */
  changeMade(next: SessionKeys): void {
    this.own = copyOf(next);
    this.pendingWraps = [];
  }

  /** The server answered that the change sent with [next] was not made: that pending wrap goes, and only that one. */
  changeRefused(next: SessionKeys): void {
    this.pendingWraps = this.pendingWraps.filter((w) => w.wrappedUvk !== next.wrappedUvk);
  }

  /**
   * Wraps of changes an earlier session in this browser sent with no answer, read from beside the offline copy at an
   * offline unlock: kept as pending again, so either password proves until the server's word settles them.
   */
  adoptPending(wraps: readonly SessionKeys[]): void {
    for (const w of wraps) if (!this.pendingWraps.some((p) => sameWrap(p, w)) && (this.own === null || !sameWrap(this.own, w))) this.pendingWraps.push(copyOf(w));
  }

  /**
   * The account's keys as the server holds them now ([served]) settle every pending change (core `SessionKeeper.settleWrap`):
   * - `made`: the server holds a pending wrap, exactly as sent: it is the session's own, and nothing is pending;
   * - `not_made`: the server holds the session's own wrap: no change landed, and every pending wrap goes;
   * - `elsewhere`: the server holds neither (a change made elsewhere since): both are kept, and nothing is decided here;
   * - `none`: nothing was pending.
   */
  settle(served: SessionKeys): "made" | "not_made" | "elsewhere" | "none" {
    if (this.pendingWraps.length === 0) return "none";
    const landed = this.pendingWraps.find((w) => sameWrap(w, served));
    if (landed !== undefined) {
      this.own = copyOf(landed);
      this.pendingWraps = [];
      return "made";
    }
    if (this.own !== null && sameWrap(this.own, served)) {
      this.pendingWraps = [];
      return "not_made";
    }
    return "elsewhere";
  }

  /**
   * Proves [password] against the session's own wrap, then any pending one, each under its own salt and cost: one
   * argon2id pass per wrap yields the wrap key, which must open the wrap to [uvk], the UVK the session holds, and the
   * auth key, returned only then. The master key and both derived keys are wiped on the way out.
   */
  async prove(password: string, userId: string, uvk: Uint8Array): Promise<WrapProof> {
    const wraps = [this.own, ...this.pendingWraps].filter((w): w is SessionKeys => w !== null);
    if (wraps.length === 0) return { kind: "no_wrap" };
    for (const w of wraps) {
      try {
        assertServerKdfParams(w.kdfParams);
      } catch (e) {
        if (e instanceof KdfPolicyError) return { kind: "weakened", error: e };
        throw e;
      }
    }
    for (const w of wraps) {
      const key = await proveOne(password, userId, uvk, w);
      if (key !== null) return { kind: "proven", currentAuthKey: key, wrap: w };
    }
    return { kind: "wrong_password" };
  }
}

/** The wrap part of a set of account keys that the password just opened. */
export function wrapOf(keys: SessionKeys): SessionKeys {
  return copyOf(keys);
}

/** The same wrap: the same salt, cost and wrapped UVK. */
export function sameWrap(a: SessionKeys, b: SessionKeys): boolean {
  const p = a.kdfParams;
  const q = b.kdfParams;
  return a.kdfSalt === b.kdfSalt && a.wrappedUvk === b.wrappedUvk && p.v === q.v && p.alg === q.alg && p.ops === q.ops && p.memBytes === q.memBytes;
}

function copyOf(w: SessionKeys): SessionKeys {
  return { kdfSalt: w.kdfSalt, kdfParams: { ...w.kdfParams }, wrappedUvk: w.wrappedUvk };
}

async function proveOne(password: string, userId: string, uvk: Uint8Array, w: SessionKeys): Promise<string | null> {
  let salt: Uint8Array;
  let envelope: Uint8Array;
  try {
    salt = fromB64(w.kdfSalt);
    envelope = fromB64(w.wrappedUvk);
  } catch {
    return null;
  }
  const mk = masterKey(password, salt, w.kdfParams);
  let ak: Uint8Array | null = null;
  let wk: Uint8Array | null = null;
  try {
    ak = await deriveAuthKey(mk);
    wk = await deriveWrapKey(mk);
    let opened: Uint8Array;
    try {
      opened = open(wk, envelope, adUvk(userId));
    } catch {
      return null;
    }
    try {
      if (!ctEquals(opened, uvk)) return null;
    } finally {
      opened.fill(0);
    }
    return toB64(ak);
  } finally {
    mk.fill(0);
    ak?.fill(0);
    wk?.fill(0);
  }
}
