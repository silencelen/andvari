import { isUuid } from "../api/wireids";

/**
 * The device-local trust records as JSON (security review 2026-10, plugin scan F1/F2; branch A10). Twin of core
 * `TrustRecords.kt` (byte-compatible encodings, same rules).
 *
 * Before A10 every one of these was a newline-joined set of `|`-joined lines, and a server-chosen id that carried
 * either delimiter wrote extra lines into the record — a forged vouch, held-key tag or tombstone for a vault the
 * human never reviewed. Each record is now a JSON array of objects (or of strings, for the plain id sets) with a
 * STRICT decode: exactly the expected keys, the expected types, and every id in the UUID grammar (wireids.ts) or
 * the token grammar (the SAFE_ID shape, for base64url grant ids and nonces); anything else is refused. The encoders
 * THROW on the same rows (A10 review LOW-1: a silently dropped row is a record that lies — product code that reaches
 * an encoder with a malformed row has a bug upstream, and the throw names it), so a malformed id can neither be
 * written nor read back.
 *
 * Migration: a value that is not a JSON array is a pre-A10 line record. It is parsed ONCE with the old grammar,
 * line by line, keeping only the lines that have exactly the old field count and well-formed ids, and the caller
 * re-persists the result as JSON (`Decoded.rewrite`). A JSON record that had to drop a row is rewritten too.
 */

const HEX64 = /^[0-9a-f]{64}$/;
/** base64url grant ids and removal nonces (itemdoc-shape SAFE_ID's grammar, kept local so this module has no engine deps). */
const TOKEN = /^[A-Za-z0-9_-]{1,128}$/;

/** §8.2 vouch: this browser vouches for the key whose SHA-256 is `tag` on `vaultId`; `kind` = frozen | confirmed. */
export interface Vouch {
  vaultId: string;
  tag: string;
  kind: "frozen" | "confirmed";
}
/** A7 held-key memory: the first key this browser adopted for `vaultId`. */
export interface HeldKey {
  vaultId: string;
  tag: string;
}
/** A9 M-3: THIS browser removed `userId` from `vaultId` at `at` (device clock, ms). */
export interface Tombstone {
  vaultId: string;
  userId: string;
  at: number;
}
/** A5/A6: a human confirmed the identity key whose SHA-256 is `keyTag` for `userId` on this browser. */
export interface ConfirmedPin {
  userId: string;
  keyTag: string;
}
/** A7: a removal nonce this browser consumed for `vaultId`. */
export interface ConsumedNonceRow {
  vaultId: string;
  nonce: string;
  issuedAt: number;
}

/** The decoded rows; `rewrite` = the stored form must be replaced by `rows` re-encoded (legacy, or junk dropped). */
export interface Decoded<T> {
  rows: T[];
  rewrite: boolean;
}

const str = (o: Record<string, unknown>, k: string): string | null => (typeof o[k] === "string" ? (o[k] as string) : null);
const num = (o: Record<string, unknown>, k: string): number | null => (typeof o[k] === "number" && Number.isSafeInteger(o[k]) ? (o[k] as number) : null);
const int = (s: string): number | null => (/^-?\d{1,16}$/.test(s) && Number.isSafeInteger(Number(s)) ? Number(s) : null);

function parseArray(raw: string): unknown[] | null {
  if (!raw.startsWith("[")) return null;
  try {
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

function sameKeys(o: Record<string, unknown>, keys: readonly string[]): boolean {
  const ks = Object.keys(o);
  return ks.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(o, k));
}

/**
 * Strict JSON first (exactly `keys` per object, every row through `fromJson`); otherwise the legacy line record
 * through `fromLine` over each line's `|` parts. A record that is neither (e.g. a JSON object, or an array a row
 * of which was refused) comes back without the refused rows and flagged for rewrite.
 */
function decode<T>(raw: string | null | undefined, keys: readonly string[], fromJson: (o: Record<string, unknown>) => T | null, fromLine: (p: string[]) => T | null): Decoded<T> {
  if (!raw) return { rows: [], rewrite: false };
  const arr = parseArray(raw);
  if (arr) {
    const rows: T[] = [];
    let dropped = false;
    for (const e of arr) {
      const o = e && typeof e === "object" && !Array.isArray(e) ? (e as Record<string, unknown>) : null;
      const row = o && sameKeys(o, keys) ? fromJson(o) : null;
      if (row === null) dropped = true;
      else rows.push(row);
    }
    return { rows, rewrite: dropped };
  }
  if (raw.startsWith("[") || raw.startsWith("{")) return { rows: [], rewrite: true }; // JSON of an unknown shape: refused
  const rows: T[] = [];
  for (const line of raw.split("\n")) {
    if (!line) continue;
    const row = fromLine(line.split("|"));
    if (row !== null) rows.push(row);
  }
  return { rows, rewrite: true };
}

const encode = <T>(rows: T[]): string | null => (rows.length === 0 ? null : JSON.stringify(rows));

/** An encoder was handed a row the strict grammar refuses: a bug upstream, never a row to drop quietly. */
function malformed(what: string, row: unknown): never {
  throw new Error(`malformed ${what} record: ${JSON.stringify(row).slice(0, 200)}`);
}

function decodeStrings(raw: string | null | undefined, accept: (s: string) => boolean): Decoded<string> {
  if (!raw) return { rows: [], rewrite: false };
  const arr = parseArray(raw);
  if (arr) {
    const rows: string[] = [];
    let dropped = false;
    for (const e of arr) {
      if (typeof e === "string" && accept(e)) rows.push(e);
      else dropped = true;
    }
    return { rows: [...new Set(rows)], rewrite: dropped };
  }
  if (raw.startsWith("[") || raw.startsWith("{")) return { rows: [], rewrite: true };
  return { rows: [...new Set(raw.split("\n").filter((l) => l.length > 0 && accept(l)))], rewrite: true };
}

const encodeStrings = (rows: Iterable<string>, accept: (s: string) => boolean, what: string): string | null => {
  const out = [...new Set([...rows].map((s) => (accept(s) ? s : malformed(what, s))))].sort();
  return out.length === 0 ? null : JSON.stringify(out);
};

// ---- vouches ----

const vouch = (vaultId: string | null, tag: string | null, kind: string | null): Vouch | null =>
  isUuid(vaultId) && tag !== null && HEX64.test(tag) && (kind === "frozen" || kind === "confirmed") ? { vaultId, tag, kind } : null;

export const decodeVouches = (raw: string | null | undefined): Decoded<Vouch> =>
  decode(raw, ["vaultId", "tag", "kind"], (o) => vouch(str(o, "vaultId"), str(o, "tag"), str(o, "kind")), (p) => (p.length === 3 ? vouch(p[0]!, p[1]!, p[2]!) : null));

export const encodeVouches = (rows: Iterable<Vouch>): string | null =>
  encode([...rows].map((v) => { const r = vouch(v.vaultId, v.tag, v.kind) ?? malformed("vouch", v); return { vaultId: r.vaultId, tag: r.tag, kind: r.kind }; }));

// ---- held keys ----

const held = (vaultId: string | null, tag: string | null): HeldKey | null => (isUuid(vaultId) && tag !== null && HEX64.test(tag) ? { vaultId, tag } : null);

export const decodeHeldKeys = (raw: string | null | undefined): Decoded<HeldKey> =>
  decode(raw, ["vaultId", "tag"], (o) => held(str(o, "vaultId"), str(o, "tag")), (p) => (p.length === 2 ? held(p[0]!, p[1]!) : null));

export const encodeHeldKeys = (rows: Iterable<HeldKey>): string | null =>
  encode([...rows].map((h) => { const r = held(h.vaultId, h.tag) ?? malformed("held key", h); return { vaultId: r.vaultId, tag: r.tag }; }));

// ---- plain sets ----

/** A set of vault ids (member-granted). */
export const decodeIdSet = (raw: string | null | undefined): Decoded<string> => decodeStrings(raw, isUuid);
export const encodeIdSet = (rows: Iterable<string>): string | null => encodeStrings(rows, isUuid, "vault id");

/** A set of opaque tokens (declined grant ids, base64url). */
export const decodeTokenSet = (raw: string | null | undefined): Decoded<string> => decodeStrings(raw, (s) => TOKEN.test(s));
export const encodeTokenSet = (rows: Iterable<string>): string | null => encodeStrings(rows, (s) => TOKEN.test(s), "token");

// ---- issued tombstones ----

const tomb = (vaultId: string | null, userId: string | null, at: number | null): Tombstone | null =>
  isUuid(vaultId) && isUuid(userId) && at !== null ? { vaultId, userId, at } : null;

export const decodeTombstones = (raw: string | null | undefined): Decoded<Tombstone> =>
  decode(raw, ["vaultId", "userId", "at"], (o) => tomb(str(o, "vaultId"), str(o, "userId"), num(o, "at")), (p) => (p.length === 3 ? tomb(p[0]!, p[1]!, int(p[2]!)) : null));

export const encodeTombstones = (rows: Iterable<Tombstone>): string | null =>
  encode([...rows].map((t) => { const r = tomb(t.vaultId, t.userId, Number.isSafeInteger(t.at) ? t.at : null) ?? malformed("tombstone", t); return { vaultId: r.vaultId, userId: r.userId, at: r.at }; }));

// ---- confirmed pins ----

const pin = (userId: string | null, keyTag: string | null): ConfirmedPin | null => (isUuid(userId) && keyTag !== null && HEX64.test(keyTag) ? { userId, keyTag } : null);

export const decodeConfirmedPins = (raw: string | null | undefined): Decoded<ConfirmedPin> =>
  decode(raw, ["userId", "keyTag"], (o) => pin(str(o, "userId"), str(o, "keyTag")), (p) => (p.length === 2 ? pin(p[0]!, p[1]!) : null));

export const encodeConfirmedPins = (rows: Iterable<ConfirmedPin>): string | null =>
  encode([...rows].map((c) => { const r = pin(c.userId, c.keyTag) ?? malformed("confirmed pin", c); return { userId: r.userId, keyTag: r.keyTag }; }));

// ---- consumed nonces ----

const nonceRow = (vaultId: string | null, nonce: string | null, issuedAt: number | null): ConsumedNonceRow | null =>
  isUuid(vaultId) && nonce !== null && TOKEN.test(nonce) && issuedAt !== null ? { vaultId, nonce, issuedAt } : null;

export const decodeConsumedNonces = (raw: string | null | undefined): Decoded<ConsumedNonceRow> =>
  decode(raw, ["vaultId", "nonce", "issuedAt"], (o) => nonceRow(str(o, "vaultId"), str(o, "nonce"), num(o, "issuedAt")), (p) => (p.length === 3 ? nonceRow(p[0]!, p[1]!, int(p[2]!)) : null));

export const encodeConsumedNonces = (rows: Iterable<ConsumedNonceRow>): string | null =>
  encode([...rows].map((n) => { const r = nonceRow(n.vaultId, n.nonce, Number.isSafeInteger(n.issuedAt) ? n.issuedAt : null) ?? malformed("consumed nonce", n); return { vaultId: r.vaultId, nonce: r.nonce, issuedAt: r.issuedAt }; }));

/**
 * Read one record through `decoder`, migrating the stored form when it asks for a rewrite. `get` / `set` are the
 * record's own store (client state, kv rows, …).
 */
export function loadRecord<T>(
  key: string,
  get: (key: string) => string | null,
  set: (key: string, value: string | null) => void,
  decoder: (raw: string | null) => Decoded<T>,
  encoder: (rows: T[]) => string | null,
): T[] {
  const d = decoder(get(key));
  if (d.rewrite) set(key, encoder(d.rows));
  return d.rows;
}
