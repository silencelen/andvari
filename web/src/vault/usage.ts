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

/**
 * What a flush learned about the server's copy before deciding whether to write (spec 02 §8.2,
 * audit H05). Three DISTINCT outcomes rather than a nullable map, because two of them used to
 * collapse into "empty" — and an empty server view merged with one session's buffer and PUT back
 * is how one device's handful of uses overwrote the whole household's ledger.
 */
export type ServerLedger =
  /** The GET succeeded and answered `sealedUsage: null`: this account has never written a ledger.
   *  The ONLY case in which a write with no server merge is a first write rather than an overwrite. */
  | { kind: "absent" }
  /** The GET succeeded and the blob opened under our key — `map` is authoritative. A blob that
   *  opens but parses as garbage is a PRESENT, EMPTY ledger (parseUsage is tolerant by contract on
   *  every twin): it authenticated under this user's key, so replacing it is the "corrupt ledger
   *  costs one health column" posture, not a cross-client overwrite. */
  | { kind: "present"; map: UsageMap }
  /** The GET failed (offline, 5xx, 401, timeout) OR a blob came back that would NOT open (wrong
   *  key, AD mismatch, a future encoding). Either way this client cannot see what it would be
   *  replacing, and spec 02 §8.2 says it MUST leave the ledger untouched. */
  | { kind: "unreadable" };

/**
 * Decide what ONE flush round PUTs — the ledger to store, or null for "do not write this round".
 * Pure, and the TWIN of `planFlush` in extension/src/usage.ts and `UsageLedger.planFlush` in
 * core: the three clients pin the same cases so they cannot drift in WHEN they write.
 *
 *  - `unreadable` → null, ALWAYS, even with buffered uses. The endpoint is last-writer-wins with
 *    no server-side merge, so a PUT here would replace the household's whole ledger with `mine`
 *    — spec 02 §8.2's "a client that cannot open the ledger MUST leave it untouched". The caller
 *    re-buffers `mine` and the next flush retries; the conservative direction loses at most one
 *    session's ranking hints.
 *  - `absent` → `mine` if non-empty (the first write), else null.
 *  - `present` → merge, then prune when `liveItemIds` was handed in (against the live set PLUS
 *    `mine`'s keys — a use buffered after the caller's snapshot is inherently live: you cannot
 *    copy a deleted item's secret — so a stale snapshot may under-prune, never drop a live
 *    entry), and write ONLY if something changed: buffered uses, or a prune that dropped an
 *    entry. A quiet post-sync prune therefore costs one GET and no `updatedAt` bump (spec 03 §3:
 *    batched, never spurious).
 */
export function planFlush(server: ServerLedger, mine: UsageMap, liveItemIds?: ReadonlySet<string>): UsageMap | null {
  switch (server.kind) {
    case "unreadable":
      return null;
    case "absent":
      return Object.keys(mine).length > 0 ? mine : null;
    case "present": {
      let merged = mergeUsage(server.map, mine);
      if (liveItemIds) merged = pruneUsage(merged, new Set([...liveItemIds, ...Object.keys(mine)]));
      return Object.keys(mine).length > 0 || Object.keys(merged).length !== Object.keys(server.map).length ? merged : null;
    }
  }
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
 *
 * Two maps, deliberately (audit H79). `map` is the DISPLAY view — the unlock-time server copy
 * with this session's uses stamped over it, what the health column reads. `pending` is the
 * BUFFER — only what this session recorded and has not yet landed — and it is the ONLY thing a
 * flush merges over the server copy, exactly as core (`take()`) and the extension
 * (`pendingUsage`) do. Sending `map` instead re-added every entry another device's post-sync
 * prune had removed, for as long as this tab stayed open, and forced that device's next sync to
 * prune-and-PUT again: an `updatedAt` bump not driven by a use, the coarse-activity leak the
 * batching rule exists to limit.
 */
export class UsageTracker {
  private map: UsageMap = {};
  private pending: UsageMap = {};
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
    this.pending = recordUse(this.pending, itemId, now);
    if (this.timer !== null) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.flush();
    }, FLUSH_DEBOUNCE_MS);
  }

  /**
   * Read the server's current copy, decide with planFlush, then store. The re-read is what keeps
   * last-writer-wins from meaning last-writer-DESTROYS: another device's entries survive our
   * flush even though the endpoint itself has no merge semantics.
   *
   * With a `liveItemIds` set (the post-sync point, the ONLY caller allowed to prune — Vault.tsx
   * syncNow) the round runs even with NOTHING buffered (audit H35): the prune is the ledger's
   * growth bound, and a sync almost never lands inside the 30 s debounce window after a use, so
   * gating it behind a dirty buffer left it inert on this client. planFlush keeps a quiet sync
   * write-free (one GET, no `updatedAt` bump).
   *
   * The three server outcomes stay DISTINCT (audit H05): a GET that failed or a blob that would
   * not open is NOT an empty ledger to overwrite — no PUT, the buffer is re-armed, the next flush
   * retries. Only a genuinely absent blob is written without a merge.
   */
  async flush(liveItemIds?: ReadonlySet<string>): Promise<void> {
    const mine = this.pending;
    if (Object.keys(mine).length === 0 && !liveItemIds) return;
    this.pending = {};
    try {
      let server: ServerLedger;
      try {
        const res = await this.client.getUsage();
        server = res.sealedUsage
          ? { kind: "present", map: parseUsage(fromUtf8(await this.account.openUsage(res.sealedUsage))) }
          : { kind: "absent" };
      } catch {
        // Offline / HTTP failure on the GET, or a present blob that would not open under our key
        // — the two cases spec 02 §8.2's MUST is about. NOT "no ledger yet": that is the null
        // branch above.
        server = { kind: "unreadable" };
      }
      const put = planFlush(server, mine, liveItemIds);
      if (put === null) {
        // Skipped the write on purpose — keep the uses for the next round. A null plan on a
        // READABLE copy means there was simply nothing to write (quiet prune).
        if (server.kind === "unreadable") this.pending = mergeUsage(mine, this.pending);
        return;
      }
      // The display view follows what was stored: another device's newer stamps show up, and a
      // pruned entry no longer lingers in this tab to be re-sent (H79).
      this.map = put;
      await this.client.putUsage(await this.account.sealUsage(utf8(serializeUsage(put))));
    } catch {
      // Re-arm: a failed flush must not silently drop the session's recorded uses. Reachable for a
      // server refusal only because putUsage rides text() and REJECTS on a non-2xx (audit H34).
      this.pending = mergeUsage(mine, this.pending);
    }
  }

  /** Stop the timer. Callers flush FIRST if they want the pending uses stored — dispose alone
   *  deliberately performs no network call, because it runs on lock and sign-out paths. */
  dispose(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.map = {};
    this.pending = {};
  }
}
