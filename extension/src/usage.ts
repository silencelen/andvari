// Runtime imports carry the .ts extension so this module resolves under `node --test` (the
// quickunlock.ts/knownlogins.ts rule); esbuild + tsc (allowImportingTsExtensions) accept it.

/**
 * Usage ledger (spec 02 §8.2) — the extension's half. Twin of web/src/vault/usage.ts; the merge
 * and parse rules MUST stay identical across the two or the clients would clobber each other's
 * entries instead of converging.
 *
 * Pure and chrome-free (the knownlogins.ts idiom) so `node --test` pins every decision;
 * background.ts owns the network, the timer and the session keys.
 *
 * WHY THE EXTENSION CAN DO THIS AT ALL: the ledger is sealed under a key derived from the
 * PERSONAL VAULT KEY, not the UVK. The extension's UVK is memory-only (spec 01 breaker B1) and an
 * evicted MV3 service worker restores a session holding `vaultKeys` but no UVK — so a UVK-bound
 * ledger would have been unwritable here for most fills, from the client that does most of the
 * filling. See spec 02 §8.2 and design 2026-08-22-login-health §4a.
 */

export interface UsageEntry {
  lastUsedAt: number;
  /** A FLOOR, not an exact total — see mergeUsage. */
  useCount: number;
}

export type UsageMap = Record<string, UsageEntry>;

/** How long recorded uses sit in SW memory before a flush. Spec 03 §3 forbids a PUT per fill.
 *  Kept shorter than the web client's window because an MV3 worker can be evicted at any moment
 *  and an in-memory record dies with it — see the note on the recorder in background.ts. */
export const FLUSH_DEBOUNCE_MS = 15_000;

/**
 * Merge two ledgers. Both fields take the MAX, so `useCount` is a floor rather than a true total.
 * Summing is the intuitive choice and is wrong: flushes re-merge against the server copy, so the
 * same use would be re-counted on every round trip and inflate without bound. Max is idempotent
 * and order-independent, so any sequence of merges between any number of clients converges —
 * which matters far more here than exactness, since nothing but a column reads it.
 */
export function mergeUsage(a: UsageMap, b: UsageMap): UsageMap {
  const out: UsageMap = { ...a };
  for (const [itemId, entry] of Object.entries(b)) {
    const held = out[itemId];
    out[itemId] = held
      ? { lastUsedAt: Math.max(held.lastUsedAt, entry.lastUsedAt), useCount: Math.max(held.useCount, entry.useCount) }
      : entry;
  }
  return out;
}

/**
 * Drop entries whose item no longer exists, so a long-lived ledger cannot grow forever. Twin of
 * web/src/vault/usage.ts pruneUsage — keep the two identical.
 *
 * The caller MUST pass the COMPLETE live item set. Passing a partial one (a sync still in flight, a
 * vault whose key has not arrived) would silently discard usage for items merely not loaded YET —
 * which is why this is an explicit, separately-tested function rather than something the flush does
 * implicitly on whatever it happens to hold. In the SW only resync()'s post-full-snapshot point
 * passes a set; the debounce and lock-path flushes pass nothing.
 */
export function pruneUsage(map: UsageMap, liveItemIds: ReadonlySet<string>): UsageMap {
  const out: UsageMap = {};
  for (const [itemId, entry] of Object.entries(map)) if (liveItemIds.has(itemId)) out[itemId] = entry;
  return out;
}

/** Stamp one use. Clamps backwards so a skewed-backward clock cannot walk a stamp down. */
export function recordUse(map: UsageMap, itemId: string, now: number): UsageMap {
  const held = map[itemId];
  return { ...map, [itemId]: { lastUsedAt: Math.max(held?.lastUsedAt ?? 0, now), useCount: (held?.useCount ?? 0) + 1 } };
}

/** Tolerant parse: anything malformed reads as an EMPTY ledger and never throws. A corrupt
 *  ledger must cost one health column, never a fill. */
export function parseUsage(json: string): UsageMap {
  try {
    const raw: unknown = JSON.parse(json);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
    const out: UsageMap = {};
    for (const [itemId, v] of Object.entries(raw as Record<string, unknown>)) {
      if (!v || typeof v !== "object") continue;
      const e = v as { lastUsedAt?: unknown; useCount?: unknown };
      if (typeof e.lastUsedAt !== "number" || !Number.isFinite(e.lastUsedAt)) continue;
      out[itemId] = {
        lastUsedAt: e.lastUsedAt,
        useCount: typeof e.useCount === "number" && Number.isFinite(e.useCount) ? e.useCount : 1,
      };
    }
    return out;
  } catch {
    return {};
  }
}

export function serializeUsage(map: UsageMap): string {
  return JSON.stringify(map);
}
