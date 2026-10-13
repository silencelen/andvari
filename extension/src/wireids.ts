import type { AccountKeys, SessionResponse, SyncResponse, VaultMemberSummary } from "./api.ts";

/**
 * The id grammar at the wire boundary (security review 2026-10, plugin scan F1/F2; branch A10). Twin of core
 * `WireIds.kt` and web `api/wireids.ts`.
 *
 * Every id the server supplies — vaultId, userId, itemId, deviceId — is checked here, in the API client, BEFORE it
 * can reach the session, a snapshot or a storage.local record (item homes, the personal-wrap cache). The grammar is
 * the lowercase RFC 4122 form every client mints and the server already enforces on what it ACCEPTS; a well-behaved
 * server never serves anything else, and a hostile one cannot smuggle a storage key, a path segment or a second id
 * inside one. A row carrying a malformed id is REFUSED: dropped from the response, never stored, with the refusal
 * reported so the worker can log an anomaly. Chrome-free and runtime-import-free (node --test friendly).
 */

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isUuid(s: unknown): s is string {
  return typeof s === "string" && UUID_RE.test(s);
}

/** One refused id: `field` names the wire field, `value` the offending string. */
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
  ok(field: string, value: unknown): boolean {
    if (isUuid(value)) return true;
    this.refused.push({ field, value: typeof value === "string" ? value : String(value) });
    return false;
  }
}

export function sanitizeSync(resp: SyncResponse): Sanitized<SyncResponse> {
  const c = new Collector();
  const vaults = (resp.vaults ?? []).filter((v) => c.ok("vaultId", v.vaultId));
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
  if (c.refused.length === 0) return { value: resp, refused: [] };
  return { value: { ...resp, vaults, grants, items }, refused: c.refused };
}

export function sanitizeMembers(rows: VaultMemberSummary[]): Sanitized<VaultMemberSummary[]> {
  const c = new Collector();
  return { value: rows.filter((m) => c.ok("userId", m.userId)), refused: c.refused };
}

/** The served personal wrap names a vault: a malformed id drops the wrap (the session then has no served wrap). */
export function sanitizeAccountKeys(keys: AccountKeys): Sanitized<AccountKeys> {
  const c = new Collector();
  if (!keys.personalWrap || c.ok("personalWrap.vaultId", keys.personalWrap.vaultId)) return { value: keys, refused: [] };
  return { value: { ...keys, personalWrap: null }, refused: c.refused };
}

/** A session naming a malformed user or device id is refused outright: the user id is the storage namespace key. */
export function refusedSession(s: SessionResponse): Refusal | null {
  if (!isUuid(s.userId)) return { field: "userId", value: String(s.userId) };
  if (!isUuid(s.deviceId)) return { field: "deviceId", value: String(s.deviceId) };
  return null;
}
