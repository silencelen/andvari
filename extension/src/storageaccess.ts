/**
 * Restrict the extension's storage areas to its own pages and worker (security review 2026-10, branch A15, step 1).
 *
 * `setAccessLevel({accessLevel:"TRUSTED_CONTEXTS"})` is enforced in the browser process, `onChanged` included, and a
 * content script cannot undo it (Chromium `storage_api.cc`: only a privileged context may set the level). Where it
 * exists:
 *  - Chrome 102+: storage.session (whose default is already TRUSTED_CONTEXTS — the call re-affirms it);
 *  - Chrome 140+: storage.local too (default TRUSTED_AND_UNTRUSTED_CONTEXTS); the level is kept in the extension's
 *    prefs, so it survives restarts. Chrome 127–139 have no `setAccessLevel` on `local`;
 *  - Firefox: nowhere (bug 1724754). storage.session is kept from content scripts by Firefox's API schema only;
 *    storage.local is open to them by design.
 * Since A15 storage.local holds no trust state at all (trustedkv.ts), so locking it is defense in depth, not the fix.
 *
 * Both calls are AWAITED, and the verdict reports only what was seen: `sessionTrusted` is true when the session call
 * resolved, or — where the API does not exist (Firefox) — when storage.session exists at all (the documented default
 * then stands; nothing here can verify it). A call that exists and fails leaves the compartment untrusted, so quick
 * unlock does not arm (fail closed). Chrome-free; the storage object is passed in.
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
  /** storage.session may hold the quick-unlock record (the A9 precondition). */
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
