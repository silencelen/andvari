import { ApiError, TrafficStoppedError } from "../api/client";
import type { KeyValue } from "../api/devicesecret";
import type { AccountStatePut, AccountStateResponseV2 } from "../api/wire";
import { adAccountState } from "../crypto/ad";
import { fromB64, fromUtf8, toB64, utf8 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import {
  ACCOUNT_STATE_DAMAGED,
  ACCOUNT_STATE_FULL,
  type AccountDocument,
  type AccountLimits,
  boundDocument,
  decodeDocument,
  DEFAULT_LIMITS,
  EMPTY_DOCUMENT,
  encodeDocument,
  MAX_SEQ,
  type MergeAnomaly,
  mergeDocuments,
} from "./accountdoc";

/**
 * The account-state store (spec 03 §3, design §5.4) over `GET` and `PUT /account/state`.
 *
 * Trust. A served blob is used only if it opens under the UVK with the AD `andvari/v1|account-state|{userId}` and
 * decodes as this account's v2 document. It is then MERGED with the local copy, never adopted, so the server alone
 * can only withhold or roll back (both reported) and nothing the local copy holds is lost. This browser keeps its
 * copy sealed under the UVK, with the high-water mark of the in-blob seq, the server's compare-and-set token and
 * whether it has ever seen a blob, in its device storage. The UVK is borrowed and never wiped here, nor at a lock:
 * a lock closes the session's fence (vault/sessionfence.ts), so this store's wire refuses every later call, and the
 * key is left to the collector, with the session's objects and the document this store last opened ({@link local}).
 */

/** The two calls the store makes (api/wireclient.ts WireApi has both). */
export interface AccountStateWire {
  accountState(): Promise<AccountStateResponseV2>;
  putAccountState(sealedState: string, baseSeq: number): Promise<AccountStateResponseV2>;
}

export type StateRead =
  | { readonly kind: "ok"; readonly document: AccountDocument; readonly anomalies: readonly MergeAnomaly[]; readonly dropped: number }
  /** The served blob did not open under the UVK or failed the strict decode: the local copy stays in force, and this is shown. */
  | { readonly kind: "unopenable"; readonly document: AccountDocument }
  /** The read failed; the local copy stays in force. The error is carried, never swallowed. */
  | { readonly kind: "unreachable"; readonly document: AccountDocument; readonly error: unknown };

export type StateWrite =
  | { readonly kind: "written"; readonly document: AccountDocument }
  /** The change was already in the merged document; nothing was written. */
  | { readonly kind: "unchanged"; readonly document: AccountDocument }
  /** `409 stale_state` kept coming back after the bounded merge-and-retry. */
  | { readonly kind: "contended" }
  /**
   * Not known to be written. [sent] true: the write went out and its outcome cannot be told (no answer, an answer cut
   * off or not the server's, a 5xx): it may have landed, and the next read merges either way. [sent] false: the read
   * before it failed, so the write itself was never sent and nothing changed.
   */
  | { readonly kind: "unknown"; readonly error: unknown; readonly sent: boolean }
  /** Refused: `account_state_full`, `account_state_damaged`, `unopenable`, or the server's code. */
  | { readonly kind: "refused"; readonly code: string };

/**
 * Whether a pull may find the account state changed (spec 03 §4 `accountStateSeq`, as the shared code decides it):
 * always without a served counter or without one held here; with both, unless they are equal. A counter below the one
 * held (a lie, or a server rolled back) or above it is read, never skipped.
 *
 * What a server that lies about the counter can do: say "unchanged" while another device wrote, which only delays this
 * browser learning of that write until the next pull the counter moves, or until a read made for its own sake (an
 * update always reads first and writes with compare-and-set). It could already withhold the state outright; nothing it
 * says here is taken as state. What it cannot do: make this browser take a document, drop a record it holds, or decide
 * an adoption; those use the records this browser holds, and every read still merges and checks for a rollback.
 */
export function stateMayHaveMoved(served: number | null | undefined, held: number | null): boolean {
  if (typeof served !== "number" || !Number.isSafeInteger(served) || served < 0) return true;
  if (held === null) return true;
  return served !== held;
}

/** The store's rollback rule (accountstate.json `expect.rollback`): a served document below the high-water mark, or none after one was seen. */
export function isRollback(servedSeq: number | null, highWater: number): boolean {
  return servedSeq === null ? highWater > 0 : servedSeq < highWater;
}

export class AccountStateStore {
  private readonly kSealed: string;
  private readonly kHigh: string;
  private readonly kCas: string;
  private readonly kSeen: string;

  constructor(
    private readonly userId: string,
    private readonly uvk: Uint8Array,
    private readonly wire: AccountStateWire,
    private readonly storage: KeyValue,
    private readonly limits: AccountLimits = DEFAULT_LIMITS,
    private readonly maxAttempts = 4,
  ) {
    const base = `andvari.as2.${userId}.`;
    this.kSealed = base + "sealed";
    this.kHigh = base + "hw";
    this.kCas = base + "cas";
    this.kSeen = base + "seen";
  }

  private openBlob(sealed: string): AccountDocument | null {
    try {
      const plain = open(this.uvk, fromB64(sealed), adAccountState(this.userId));
      const text = new TextDecoder("utf-8", { fatal: true }).decode(plain);
      return decodeDocument(this.userId, text)?.document ?? null;
    } catch {
      return null;
    }
  }

  private sealDoc(doc: AccountDocument): string {
    return toB64(seal(this.uvk, utf8(encodeDocument(this.userId, doc)), adAccountState(this.userId)));
  }

  /**
   * The document this store last opened from its device storage, beside the exact sealed text it was opened from. It
   * lives on this object alone, beside the UVK, and goes with it: nothing of it is put in storage or shared with another
   * store. A text that does not open is never kept.
   */
  private opened: { readonly sealed: string; readonly document: AccountDocument } | null = null;

  /**
   * A document this store read or wrote whose sealed copy the device storage did not keep (a full storage drops a write
   * without a word), beside the text the storage held instead. It lives on this object alone, as {@link opened} does.
   */
  private unkept: { readonly over: string | null; readonly document: AccountDocument } | null = null;

  /**
   * The merged document as this browser holds it now (no network). A local copy that does not open reads as empty.
   * The sealed copy is read from storage at every call, and opened only when it is not the very text this store opened
   * last: another tab's write is another text, and it is opened here at the next call. The document handed out is the
   * one kept, so it is never changed in place (every change of a document makes a new one). Where this store read or
   * wrote a document whose copy the storage did not keep, that document is answered while the storage holds the text it
   * held then, and it is merged with another tab's later text: this store never answers a document older than one it read.
   */
  local(): AccountDocument {
    const unkept = this.unkept;
    const sealed = this.storage.get(this.kSealed);
    if (unkept !== null && unkept.over === sealed) return unkept.document;
    const atRest = this.atRest(sealed);
    if (unkept === null) return atRest;
    const document = mergeDocuments(atRest, unkept.document, this.limits).document;
    this.unkept = { over: sealed, document };
    return document;
  }

  /** The document the sealed copy [sealed] holds (empty where there is none, or it does not open). */
  private atRest(sealed: string | null): AccountDocument {
    if (!sealed) {
      this.opened = null;
      return EMPTY_DOCUMENT;
    }
    const kept = this.opened;
    if (kept !== null && kept.sealed === sealed) return kept.document;
    const document = this.openBlob(sealed);
    this.opened = document === null ? null : { sealed, document };
    return document ?? EMPTY_DOCUMENT;
  }

  /**
   * The server's counter of the account state (its compare-and-set token, spec 03 §3) as this browser last saw it: in
   * the answer of its last read or write. Null when none was kept or it does not read as a counter. A sync answer whose
   * `accountStateSeq` equals it says no other device of the account wrote since (spec 03 §4).
   */
  heldCounter(): number | null {
    const raw = this.storage.get(this.kCas);
    if (raw === null || raw === "") return null;
    const n = Number(raw);
    return Number.isSafeInteger(n) && n >= 0 ? n : null;
  }

  highWater(): number {
    const n = Number(this.storage.get(this.kHigh) ?? "0");
    return Number.isSafeInteger(n) && n >= 0 ? n : 0;
  }

  /**
   * Keeps [doc] as the sealed copy, and reads the copy back. Where it did not land, the document is kept on this object
   * instead ({@link unkept}), so that {@link local} never answers the older copy at rest.
   */
  private keep(doc: AccountDocument, cas: number | null): void {
    const sealed = this.sealDoc(doc);
    this.storage.set(this.kSealed, sealed);
    const now = this.storage.get(this.kSealed);
    this.unkept = now === sealed ? null : { over: now, document: doc };
    this.storage.set(this.kHigh, String(Math.max(this.highWater(), doc.seq)));
    if (cas !== null) this.storage.set(this.kCas, String(cas));
  }

  /** GET, open, merge with the local copy, persist (§5.4: merge on every read). */
  async read(): Promise<StateRead> {
    let resp: AccountStateResponseV2;
    try {
      resp = await this.wire.accountState();
    } catch (error) {
      return { kind: "unreachable", document: this.local(), error };
    }
    // The local copy as it is when the answer is in (another tab may have written it while this read was out).
    const local = this.local();
    if (resp.sealedState === null) {
      const anomalies: MergeAnomaly[] = this.storage.get(this.kSeen) === "1" ? [{ kind: "withheld" }] : [];
      this.storage.set(this.kCas, String(resp.seq));
      return { kind: "ok", document: local, anomalies, dropped: 0 };
    }
    let dropped = 0;
    let served: AccountDocument | null = null;
    try {
      const plain = open(this.uvk, fromB64(resp.sealedState), adAccountState(this.userId));
      const decoded = decodeDocument(this.userId, new TextDecoder("utf-8", { fatal: true }).decode(plain));
      if (decoded) {
        served = decoded.document;
        dropped = decoded.dropped;
      }
    } catch {
      served = null;
    }
    if (!served) return { kind: "unopenable", document: local };
    this.storage.set(this.kSeen, "1");
    const anomalies: MergeAnomaly[] = [];
    const hw = this.highWater();
    if (isRollback(served.seq, hw)) anomalies.push({ kind: "rollback", servedSeq: served.seq, highWater: hw });
    const merged = mergeDocuments(local, served, this.limits);
    anomalies.push(...merged.anomalies);
    this.keep(merged.document, resp.seq);
    return { kind: "ok", document: merged.document, anomalies, dropped };
  }

  /** Applies [change] to the freshly merged document and writes it with compare-and-set, merging and retrying on `409 stale_state`. */
  update(change: (doc: AccountDocument) => AccountDocument): Promise<StateWrite> {
    return this.updateVia(change, (put) => this.wire.putAccountState(put.sealedState, put.baseSeq));
  }

  /**
   * [update], with the sealed document handed to [send]: a route that carries `accountState: {sealedState, baseSeq}`
   * beside its own fields (`PUT /account/recovery`, FI-R5) and answers the new token. `409 stale_state` merges and
   * retries; any other refusal is returned with its code.
   */
  async updateVia(change: (doc: AccountDocument) => AccountDocument, send: (put: AccountStatePut) => Promise<AccountStateResponseV2>): Promise<StateWrite> {
    for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
      const read = await this.read();
      if (read.kind === "unopenable") return { kind: "refused", code: "unopenable" };
      if (read.kind === "unreachable") return { kind: "unknown", error: read.error, sent: false };
      // Built on the document just read and merged, never on the copy at rest (which a full storage may not have kept).
      const base = read.document;
      const next = change(base);
      if (next === base || encodeDocument(this.userId, next) === encodeDocument(this.userId, base)) return { kind: "unchanged", document: base };
      // A document whose in-blob seq cannot be advanced is damaged: nothing is written, and nothing loops.
      if (base.seq >= MAX_SEQ) return { kind: "refused", code: ACCOUNT_STATE_DAMAGED };
      // The caps and the size rule hold on write as on merge.
      const bounded = boundDocument({ ...next, seq: base.seq + 1 }, this.limits);
      if (!bounded.fits) return { kind: "refused", code: ACCOUNT_STATE_FULL };
      const doc = bounded.document;
      const sealed = this.sealDoc(doc);
      if (sealed.length > this.limits.sealedChars) return { kind: "refused", code: ACCOUNT_STATE_FULL };
      const cas = Number(this.storage.get(this.kCas) ?? "0");
      try {
        const w = await send({ sealedState: sealed, baseSeq: Number.isSafeInteger(cas) ? cas : 0 });
        this.keep(doc, w.seq);
        this.storage.set(this.kSeen, "1");
        return { kind: "written", document: doc };
      } catch (e) {
        if (e instanceof ApiError && e.code === "stale_state") continue;
        // Nothing left the browser (its traffic gate stopped the write before it was sent): nothing changed.
        if (e instanceof TrafficStoppedError && !e.sent) return { kind: "refused", code: e.code };
        // The server's refusal (a 4xx): nothing was stored.
        if (e instanceof ApiError && !(e instanceof TrafficStoppedError) && e.status >= 400 && e.status < 500) return { kind: "refused", code: e.code };
        // Everything else cannot be told: no answer (status 0), a redirect, an answer cut off or not the server's, an
        // answer the gate dropped, a 5xx.
        return { kind: "unknown", error: e, sent: true };
      }
    }
    return { kind: "contended" };
  }
}

/** For tests and diagnostics: the plaintext a sealed blob holds, or null. */
export function openAccountBlob(uvk: Uint8Array, userId: string, sealed: string): string | null {
  try {
    return fromUtf8(open(uvk, fromB64(sealed), adAccountState(userId)));
  } catch {
    return null;
  }
}
