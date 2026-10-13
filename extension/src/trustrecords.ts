import { isUuid } from "./wireids.ts";

/**
 * The extension's device-local trust records, decoded STRICTLY (security review 2026-10, plugin scan F1/F2; branch
 * A10; core `TrustRecords.kt` / web `trustrecords.ts` twins in spirit — the extension never used line records, its
 * storage.local values are objects already, so "structured" here means every id is re-checked on the way out of
 * storage, exactly as it is checked on the way in from the wire).
 *
 *  - item homes (`itemHomes:<userId>`): `{ [itemId]: vaultId }` — a key or value that is not a UUID is dropped;
 *  - the personal-wrap cache (`personalWrap:<userId>`): `{ vaultId, wrappedVk }` with a UUID vault id and nothing
 *    else, or null;
 *  - a pending personal change (`personalChange:<userId>`): the wrap plus the optional ciphertext names and the
 *    current vault id ("" while nothing is in force — A9 review MEDIUM-1), or null.
 *
 * A decoder reports whether the stored value had to be cleaned (`rewrite`) so the caller can re-persist it once.
 * Chrome-free and runtime-import-free (node --test friendly).
 */

export interface Decoded<T> {
  value: T;
  rewrite: boolean;
}

export function decodeItemHomes(raw: unknown): Decoded<Map<string, string>> {
  const out = new Map<string, string>();
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { value: out, rewrite: raw !== undefined && raw !== null };
  let rewrite = false;
  for (const [itemId, vaultId] of Object.entries(raw as Record<string, unknown>)) {
    if (isUuid(itemId) && isUuid(vaultId)) out.set(itemId, vaultId);
    else rewrite = true;
  }
  return { value: out, rewrite };
}

/** The storable form: only well-formed pairs are ever written. */
export function encodeItemHomes(homes: ReadonlyMap<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [itemId, vaultId] of homes) if (isUuid(itemId) && isUuid(vaultId)) out[itemId] = vaultId;
  return out;
}

export interface PersonalWrapRecord {
  vaultId: string;
  wrappedVk: string;
}

/** The cached personal wrap: exactly `{vaultId, wrappedVk}` with a UUID vault id; anything else reads as absent. */
export function decodePersonalWrap(raw: unknown): Decoded<PersonalWrapRecord | null> {
  if (raw === undefined || raw === null) return { value: null, rewrite: false };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { value: null, rewrite: true };
  const o = raw as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== 2 || !isUuid(o.vaultId) || typeof o.wrappedVk !== "string") return { value: null, rewrite: true };
  return { value: { vaultId: o.vaultId, wrappedVk: o.wrappedVk }, rewrite: false };
}

export interface PersonalChangeStored extends PersonalWrapRecord {
  currentVaultId?: string;
  currentMetaBlob?: string;
  servedMetaBlob?: string;
}

const CHANGE_KEYS = new Set(["vaultId", "wrappedVk", "currentVaultId", "currentMetaBlob", "servedMetaBlob"]);

/** A pending personal change: the served wrap (UUID vault id), `currentVaultId` a UUID or "" (nothing in force). */
export function decodePersonalChange(raw: unknown): Decoded<PersonalChangeStored | null> {
  if (raw === undefined || raw === null) return { value: null, rewrite: false };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { value: null, rewrite: true };
  const o = raw as Record<string, unknown>;
  if (!Object.keys(o).every((k) => CHANGE_KEYS.has(k))) return { value: null, rewrite: true };
  if (!isUuid(o.vaultId) || typeof o.wrappedVk !== "string") return { value: null, rewrite: true };
  const cur = o.currentVaultId;
  if (cur !== undefined && cur !== "" && !isUuid(cur)) return { value: null, rewrite: true };
  for (const k of ["currentMetaBlob", "servedMetaBlob"] as const) if (o[k] !== undefined && typeof o[k] !== "string") return { value: null, rewrite: true };
  const out: PersonalChangeStored = { vaultId: o.vaultId, wrappedVk: o.wrappedVk };
  if (cur !== undefined) out.currentVaultId = cur as string;
  if (typeof o.currentMetaBlob === "string") out.currentMetaBlob = o.currentMetaBlob;
  if (typeof o.servedMetaBlob === "string") out.servedMetaBlob = o.servedMetaBlob;
  return { value: out, rewrite: false };
}
