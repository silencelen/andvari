import type { ApiClient } from "../api/client";
import { fromUtf8, utf8 } from "../crypto/bytes";
import type { Account } from "./account";

/**
 * The usage ledger (spec 02 §8.2, design 2026-08-22-login-health) — "when did I last use this
 * login", the signal behind the vault-health staleness ranking.
 *
 * ONE SEALED BLOB PER USER, not a field on the item and not a row per item. Both exclusions are
 * the design, not an accident: a `usedAt` inside the item document would make every use an item
 * overwrite, and spec 02 §7 caps `item_versions` at ten per item — so roughly ten uses would
 * evict an item's whole real edit history. Per-item rows would leak the same behavioral timing
 * through row metadata instead. One aggregate blob leaks only that a ledger changed and roughly
 * how big it is.
 *
 * The pure half (merge/serialize/prune) is exported and pinned by usage.test.ts; the class below
 * owns only the network and the timer.
 */

export interface UsageEntry {
  /** Epoch ms of the most recent recorded use, from whichever client recorded it. */
  lastUsedAt: number;
  /** A FLOOR, not an exact count — see mergeUsage for why it cannot be exact. */
  useCount: number;
}

export type UsageMap = Record<string, UsageEntry>;

/** How long a recorded use sits in memory before it is flushed. Spec 03 §3 requires batching:
 *  one PUT per fill would turn the blob's `updatedAt` into a keystroke-grade activity trace. */
export const FLUSH_DEBOUNCE_MS = 30_000;

/**
 * Merge two ledgers. **Both fields take the MAX, and `useCount` is therefore a floor rather than
 * a true total.** Summing would be the intuitive choice and is wrong: flushes re-merge against
 * the server copy, so the same use would be counted again on every round trip and the number
 * would inflate without bound. Max is idempotent and order-independent, so any sequence of
 * merges between any number of devices converges — which matters more here than exactness, since
 * nothing but a tooltip reads the count.
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
 * Drop entries whose item no longer exists, so a long-lived ledger cannot grow forever.
 *
 * The caller MUST pass the COMPLETE live item set. Passing a partial one (a sync still in
 * flight, a vault whose key has not arrived) would silently discard usage for items that are
 * merely not loaded YET — which is why this is an explicit, separately-tested function rather
 * than something the flush does implicitly on whatever it happens to hold.
 */
export function pruneUsage(map: UsageMap, liveItemIds: ReadonlySet<string>): UsageMap {
  const out: UsageMap = {};
  for (const [itemId, entry] of Object.entries(map)) if (liveItemIds.has(itemId)) out[itemId] = entry;
  return out;
}

/** Tolerant parse: anything malformed reads as an EMPTY ledger, never throws. A corrupt ledger
 *  must degrade one health column, never break unlock or block a sync. */
export function parseUsage(json: string): UsageMap {
  try {
    const raw: unknown = JSON.parse(json);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
    const out: UsageMap = {};
    for (const [itemId, v] of Object.entries(raw as Record<string, unknown>)) {
      if (!v || typeof v !== "object") continue;
      const e = v as { lastUsedAt?: unknown; useCount?: unknown };
      // A future client's extra keys are dropped rather than preserved: unlike the item document
      // (spec 02 §3) this blob is wholly rewritten by one writer at a time and carries no
      // user-authored content, so there is nothing whose loss would be silent damage.
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

/** Stamp one use into a ledger, pure so the tracker's bookkeeping is pinned too. */
export function recordUse(map: UsageMap, itemId: string, now: number): UsageMap {
  const held = map[itemId];
  return {
    ...map,
    // Clamp backwards: a device with a skewed-forward clock must not pin an item's stamp in the
    // future permanently, and a skewed-backward one must not walk it backwards.
    [itemId]: { lastUsedAt: Math.max(held?.lastUsedAt ?? 0, now), useCount: (held?.useCount ?? 0) + 1 },
  };
}

/**
 * Network + timer around the pure functions above. One per unlocked session; `dispose()` on lock
 * or sign-out.
 */
export class UsageTracker {
  private map: UsageMap = {};
  private dirty = false;
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly client: ApiClient,
    private readonly account: Account,
  ) {}

  /** Pull the stored ledger. A failure — offline, a blob sealed under a different key, garbage —
   *  leaves an EMPTY ledger and is never surfaced: this is a ranking hint, and it must not be
   *  able to fail an unlock or spawn an error banner. */
  async load(): Promise<void> {
    try {
      const res = await this.client.getUsage();
      if (!res.sealedUsage) return;
      this.map = mergeUsage(this.map, parseUsage(fromUtf8(await this.account.openUsage(res.sealedUsage))));
    } catch {
      /* no ledger this session — the column reads "—", which is the honest rendering */
    }
  }

  lastUsedAt(itemId: string): number | undefined {
    return this.map[itemId]?.lastUsedAt;
  }

  /** A bound lookup for the health views, stable enough to pass as a prop. */
  readonly lookup = (itemId: string): number | undefined => this.lastUsedAt(itemId);

  /** Record a use. In memory only — the flush is debounced (spec 03 §3). */
  record(itemId: string, now: number = Date.now()): void {
    this.map = recordUse(this.map, itemId, now);
    this.dirty = true;
    if (this.timer !== null) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.flush();
    }, FLUSH_DEBOUNCE_MS);
  }

  /**
   * Re-merge against the server's current copy, then store. The re-read is what keeps
   * last-writer-wins from meaning last-writer-DESTROYS: another device's entries survive our
   * flush even though the endpoint itself has no merge semantics.
   */
  async flush(liveItemIds?: ReadonlySet<string>): Promise<void> {
    if (!this.dirty) return;
    this.dirty = false;
    try {
      let merged = this.map;
      try {
        const res = await this.client.getUsage();
        if (res.sealedUsage) merged = mergeUsage(parseUsage(fromUtf8(await this.account.openUsage(res.sealedUsage))), this.map);
      } catch {
        /* could not read the remote copy — store ours rather than lose the session's uses */
      }
      if (liveItemIds) merged = pruneUsage(merged, liveItemIds);
      this.map = merged;
      await this.client.putUsage(await this.account.sealUsage(utf8(serializeUsage(merged))));
    } catch {
      // Re-arm: a failed flush must not silently drop the session's recorded uses.
      this.dirty = true;
    }
  }

  /** Stop the timer. Callers flush FIRST if they want the pending uses stored — dispose alone
   *  deliberately performs no network call, because it runs on lock and sign-out paths. */
  dispose(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.map = {};
    this.dirty = false;
  }
}
