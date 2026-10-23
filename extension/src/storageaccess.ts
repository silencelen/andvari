/**
 * Restrict the extension's storage areas to its own pages and worker (security review 2026-10, branch A15, step 1).
 *
 * `setAccessLevel({accessLevel:"TRUSTED_CONTEXTS"})` is enforced in the browser process, `onChanged` included, and a
 * content script cannot undo it (Chromium `storage_api.cc`: only a privileged context may set the level). Where it
 * exists:
 *  - Chrome 102+: storage.session (whose default is already TRUSTED_CONTEXTS — the call re-affirms it);
 *  - Chrome 140+: storage.local too (default TRUSTED_AND_UNTRUSTED_CONTEXTS); the level is kept in the extension's
 *    prefs, so it survives restarts. Chrome 127–139 have no `setAccessLevel` on `local`;
 *  - Firefox: nowhere (bug 1724754).
 * Since A15 storage.local holds no trust state at all (trustedkv.ts), so locking it is defense in depth, not the fix.
 * Since A16 the same holds for storage.session: every secret-bearing record there is sealed under a key in the
 * extension origin's IndexedDB (sessionseal.ts), and that content scripts cannot reach storage.session is not relied
 * on, on either engine. The session call is kept as a belt on Chrome.
 *
 * Both calls are AWAITED, and the verdict reports only what was seen: `sessionTrusted` is true when the session call
 * resolved, or — where the API does not exist (Firefox) — when storage.session exists at all; a call that exists and
 * fails leaves it false. Quick unlock arms only when [quickUnlockCompartment] holds: the sealing key is available AND
 * this verdict is true. Chrome-free; the storage object is passed in.
 */

export interface AccessLevelArea {
  setAccessLevel?: unknown;
  get?: unknown;
}
export interface StorageAccessAreas {
  session?: AccessLevelArea;
  local?: AccessLevelArea;
}
export interface StorageAccessVerdict {
  /** The session area's access level was confirmed (Chrome: the call resolved) or cannot be set (Firefox: the API is
   *  absent, storage.session exists). The belt beside the seal; never sufficient alone (A16). */
  sessionTrusted: boolean;
  /** storage.local is restricted to trusted contexts (Chrome 140+ only). */
  localRestricted: boolean;
}

const TRUSTED = { accessLevel: "TRUSTED_CONTEXTS" } as const;

async function restrict(area: AccessLevelArea | undefined): Promise<"restricted" | "failed" | "absent"> {
  const fn = area?.setAccessLevel;
  if (typeof fn !== "function") return "absent";
  try {
    await (fn as (o: typeof TRUSTED) => unknown).call(area, TRUSTED);
    return "restricted";
  } catch {
    return "failed";
  }
}

export async function restrictStorageAccess(storage: StorageAccessAreas | null | undefined): Promise<StorageAccessVerdict> {
  const session = await restrict(storage?.session);
  const local = await restrict(storage?.local);
  const sessionTrusted = session === "restricted" || (session === "absent" && typeof storage?.session?.get === "function");
  return { sessionTrusted, localRestricted: local === "restricted" };
}

/**
 * The quick-unlock compartment verdict (spec 01 §8.4; A16): quick unlock may arm — and the known-logins digest may
 * outlive a lock — only when the session sealing key is available ([sealAvailable], sessionseal.ts: true once worker
 * start found or made the key; false with no key store; null while undecided), AND the access-level verdict holds
 * (on Chrome, `setAccessLevel` on storage.session resolved). What this verifies: the armed record would be sealed under
 * a non-extractable key in the extension origin's IndexedDB; and, on Chrome, that the browser restricts the area.
 */
export function quickUnlockCompartment(verdict: Pick<StorageAccessVerdict, "sessionTrusted">, sealAvailable: boolean | null): boolean {
  return sealAvailable === true && verdict.sessionTrusted;
}
