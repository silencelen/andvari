import type { AccountKeys, DeletedItem, DeletedVaultSummary, SessionResponse, SyncResponse, UserLookupResponse, VaultMemberSummary } from "./types";

/**
 * The id grammar at the wire boundary (security review 2026-10, plugin scan F1/F2; branch A10).
 *
 * Every id the server supplies — vaultId, userId, itemId, deviceId, the user ids riding a transfer — is checked
 * here, in the API client, BEFORE it can reach the account, a cache row or a device-local trust record. The
 * grammar is the lowercase RFC 4122 form every client mints and the server already enforces on what it ACCEPTS
 * (`requireUuid`); a well-behaved server therefore never serves anything else, and a hostile one — the adversary
 * this design is built against — cannot smuggle a record delimiter, a path segment or a second id inside one. A
 * row carrying a malformed id is REFUSED: dropped from the response, never stored, with the refusal reported so
 * the store can surface an anomaly. One shared helper per engine: this module, core `WireIds.kt`, extension
 * `wireids.ts`.
 */

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isUuid(s: unknown): s is string {
  return typeof s === "string" && UUID_RE.test(s);
}

/** One refused id: `field` names the wire field (dotted for a nested one), `value` the offending string. */
export interface Refusal {
  field: string;
  value: string;
}

export interface Sanitized<T> {
  value: T;
  refused: Refusal[];
}

class Collector {
  refused: Refusal[] = [];
  /** True when `value` is a UUID; records a refusal otherwise. */
  ok(field: string, value: unknown): boolean {
    if (isUuid(value)) return true;
    this.refused.push({ field, value: typeof value === "string" ? value : String(value) });
    return false;
  }
}

export function sanitizeSync(resp: SyncResponse): Sanitized<SyncResponse> {
  const c = new Collector();
  const vaults = (resp.vaults ?? []).filter((v) => {
    // Evaluate every field (the report names them all), then keep the row only when all passed.
    const a = c.ok("vaultId", v.vaultId);
    const b = v.pendingTransfer ? c.ok("pendingTransfer.toUserId", v.pendingTransfer.toUserId) : true;
    const d = v.lastTransfer ? c.ok("lastTransfer.newOwnerUserId", v.lastTransfer.newOwnerUserId) : true;
    return a && b && d;
  });
  const grants = (resp.grants ?? []).filter((g) => {
    const a = c.ok("vaultId", g.vaultId);
    const b = c.ok("userId", g.userId);
    return a && b;
  });
  const items = (resp.items ?? []).filter((i) => {
    const a = c.ok("itemId", i.itemId);
    const b = c.ok("vaultId", i.vaultId);
    return a && b;
  });
  const removedGrants = (resp.removedGrants ?? []).filter((id) => c.ok("removedGrants", id));
  const removedGrantsInfo = resp.removedGrantsInfo?.filter((r) => c.ok("removedGrantsInfo.vaultId", r.vaultId));
  if (c.refused.length === 0) return { value: resp, refused: [] };
  return { value: { ...resp, vaults, grants, items, removedGrants, ...(removedGrantsInfo ? { removedGrantsInfo } : {}) }, refused: c.refused };
}

export function sanitizeMembers(rows: VaultMemberSummary[]): Sanitized<VaultMemberSummary[]> {
  const c = new Collector();
  return { value: rows.filter((m) => c.ok("userId", m.userId)), refused: c.refused };
}

export function sanitizeDeletedItems(rows: DeletedItem[]): Sanitized<DeletedItem[]> {
  const c = new Collector();
  const value = rows.filter((d) => {
    const a = c.ok("itemId", d.itemId);
    const b = c.ok("vaultId", d.vaultId);
    return a && b;
  });
  return { value, refused: c.refused };
}

export function sanitizeDeletedVaults(rows: DeletedVaultSummary[]): Sanitized<DeletedVaultSummary[]> {
  const c = new Collector();
  return { value: rows.filter((v) => c.ok("vaultId", v.vaultId)), refused: c.refused };
}

/** The served personal wrap names a vault: a malformed id drops the wrap (the account then has no served wrap). */
export function sanitizeAccountKeys(keys: AccountKeys): Sanitized<AccountKeys> {
  const c = new Collector();
  if (!keys.personalWrap || c.ok("personalWrap.vaultId", keys.personalWrap.vaultId)) return { value: keys, refused: [] };
  return { value: { ...keys, personalWrap: null }, refused: c.refused };
}

/** A served identity row is refused outright (there is no partial row to keep). */
export function refusedUser(u: UserLookupResponse): Refusal | null {
  return isUuid(u.userId) ? null : { field: "userId", value: String(u.userId) };
}

/** A session naming a malformed user or device id is refused outright: both are storage namespace keys. */
export function refusedSession(s: SessionResponse): Refusal | null {
  if (!isUuid(s.userId)) return { field: "userId", value: String(s.userId) };
  if (!isUuid(s.deviceId)) return { field: "deviceId", value: String(s.deviceId) };
  return null;
}
