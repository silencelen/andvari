import type { ItemCheck, ItemDoc } from "../api/types";
import type { VaultItem } from "../vault/store";
import { parseSavedUri } from "../vault/urimatch";

/**
 * Vault-health STALENESS — which logins are oldest, least recently used, and least recently
 * confirmed to still work (design docs/design/2026-08-22-login-health-staleness-verification.md).
 *
 * Pure and React-free, the duplicates.ts/healthRows idiom, so staleness.test.ts pins every
 * decision below without a render. Health.tsx renders and writes; nothing is decided there.
 *
 * TWO SIGNALS, DELIBERATELY DIFFERENT IN KIND — the whole design turns on not conflating them:
 *
 *  - `updatedAt` is the SERVER clock (spec 02 §1), trustworthy for ordering, and means "last
 *    CHANGED" — nothing more. It bumps on a rename, a note tweak, a dupeAck write, a conflict
 *    materialization; a bulk import restamps an entire vault. It is therefore NEVER presented
 *    as "password age", and it never decides staleness alone. (`login.passwordHistory` cannot
 *    rescue this: spec 02 §3 reserves it with exactly one writer, so an absent history means
 *    nothing at all.)
 *  - `check` is the CLIENT clock and means "a human confirmed this" (spec 02 §3). Advisory
 *    only — a future `at` is clamped, never trusted, because in a shared vault it can come
 *    from another member's skewed (or hostile) device.
 *
 * Usage is INJECTED, not read here (`lastUsedAt` on the input row). Usage lives in the
 * server-synced sealed usage ledger (spec 02 §8.2 — every unlocked client writes it, so a copy
 * on the phone counts here) that this module deliberately knows nothing about, so the ranking
 * is identical whether or not a ledger is readable on this install.
 */

/** Verdicts that mean "this login needs attention NOW" — the actionable half of the vocabulary.
 *  An UNRECOGNIZED result is deliberately NOT failing: spec 02 §3 makes the vocabulary open, and
 *  a future client's verdict must degrade to "checked, verdict unknown", never to a red row. */
const FAILING: ReadonlySet<string> = new Set(["bad", "gone", "blocked"]);

export function isFailing(result: string | undefined): boolean {
  return result !== undefined && FAILING.has(result);
}

const DAY_MS = 86_400_000;
const SIX_MONTHS_MS = 182 * DAY_MS;
const YEAR_MS = 365 * DAY_MS;

/** The snooze the "couldn't complete" verdict offers (design §4). One knob, named. */
export const SNOOZE_MS = 30 * DAY_MS;

/** Scanning buckets. Ordered as declared — `RANK` below depends on this being the priority order. */
export type StaleBucket = "failing" | "never" | "over-year" | "six-to-twelve" | "recent";

const RANK: Record<StaleBucket, number> = {
  failing: 0,
  never: 1,
  "over-year": 2,
  "six-to-twelve": 3,
  recent: 4,
};

export interface StalenessRow {
  itemId: string;
  vaultId: string;
  name: string;
  username: string;
  /** First saved WEB uri, verbatim — the "open site" target. Same rule and same reason as
   *  duplicates.ts: only a web uri is navigable (an androidapp:// entry is not). */
  firstUri?: string;
  /** Server clock. "Last changed", never "password age" — see the header. */
  updatedAt: number;
  /** From the injected local ledger; undefined = no local record, which is NOT "never used". */
  lastUsedAt?: number;
  check?: ItemCheck;
  /** `check.at` clamped to `now` — the skew guard. Undefined when never checked. */
  checkedAt?: number;
  bucket: StaleBucket;
  /** Under an unexpired `check.until`. Filtered from the default view, never deleted. */
  snoozed: boolean;
}

export interface StalenessOptions {
  /** Injected local-usage lookup (spec 02 §8.2). Omit entirely on an install with no ledger. */
  lastUsedAt?: (itemId: string) => number | undefined;
  /** Injected clock so the tests are not wall-clock dependent. */
  now?: number;
  /** Include snoozed rows (the "show snoozed" toggle). */
  includeSnoozed?: boolean;
}

function bucketFor(checkedAt: number | undefined, result: string | undefined, age: number): StaleBucket {
  if (isFailing(result)) return "failing";
  if (checkedAt === undefined) return "never";
  if (age > YEAR_MS) return "over-year";
  if (age > SIX_MONTHS_MS) return "six-to-twelve";
  return "recent";
}

/**
 * The staleness table, ordered worst-first. The ordering is EXPLAINABLE BY CONSTRUCTION rather
 * than a weighted score: a score would be unarguable-with and would quietly encode judgements
 * the user never agreed to. Three tiers, each with its own honest tie-break:
 *
 *   1. failing verdicts   — most RECENT first (a fresh failure is the most actionable thing here)
 *   2. never checked      — oldest `updatedAt` first (the only age signal such a row has)
 *   3. everything checked — oldest `checkedAt` first (longest since a human confirmed it)
 *
 * Name is the final tie-break throughout, so equal stamps keep a stable alphabetical order
 * (the VaultListView "recent" rule).
 */
export function stalenessRows(items: VaultItem[], opts: StalenessOptions = {}): StalenessRow[] {
  const now = opts.now ?? Date.now();
  const rows: StalenessRow[] = [];

  for (const it of items) {
    if (it.doc.type !== "login") continue; // notes and cards have no login to verify
    const check = it.doc.check;
    // Skew clamp (spec 02 §3): a client-clock `at` from the future is displayed and ordered as
    // "just now" rather than being allowed to sort above every genuine entry.
    const checkedAt = check ? Math.min(check.at, now) : undefined;
    const age = checkedAt === undefined ? 0 : Math.max(0, now - checkedAt);
    const snoozed = check?.until !== undefined && check.until > now;
    if (snoozed && !opts.includeSnoozed) continue;

    rows.push({
      itemId: it.itemId,
      vaultId: it.vaultId,
      name: it.doc.name || "(untitled)",
      username: it.doc.login?.username ?? "",
      firstUri: (it.doc.login?.uris ?? []).find((u) => parseSavedUri(u)?.kind === "web"),
      updatedAt: it.updatedAt,
      lastUsedAt: opts.lastUsedAt?.(it.itemId),
      check,
      checkedAt,
      bucket: bucketFor(checkedAt, check?.result, age),
      snoozed,
    });
  }

  return rows.sort((a, b) => {
    const ra = RANK[a.bucket];
    const rb = RANK[b.bucket];
    if (ra !== rb) return ra - rb;
    if (a.bucket === "failing") return (b.checkedAt ?? 0) - (a.checkedAt ?? 0) || a.name.localeCompare(b.name);
    if (a.bucket === "never") return a.updatedAt - b.updatedAt || a.name.localeCompare(b.name);
    return (a.checkedAt ?? 0) - (b.checkedAt ?? 0) || a.name.localeCompare(b.name);
  });
}

/** Counts for the Health tiles. Derived from the SAME rows the table shows, so a tile can never
 *  disagree with the list under it. */
export function stalenessSummary(rows: StalenessRow[]): { unchecked: number; failing: number } {
  return {
    unchecked: rows.filter((r) => r.bucket === "never").length,
    failing: rows.filter((r) => r.bucket === "failing").length,
  };
}

/** duplicates.ts RoleFor — the server-enforced write gate, re-declared structurally rather than
 *  imported so this module stays leaf-level. */
export type RoleFor = (vaultId: string) => string | null;

export interface CheckPlan {
  /** The single item write to hand to store.save(). ONE write per verdict — §7 caps
   *  item_versions at 10 per item, so a chatty writer here would evict real edit history. */
  write?: { itemId: string; doc: ItemDoc };
  /** Shown verbatim when the verdict cannot be recorded. The planDismiss refusal idiom. */
  refusal?: string;
}

/**
 * Compose the doc for one recorded verdict. Pure: composed HERE so the tests pin exactly what
 * ships, and so Health.tsx only ever renders and calls store.save().
 *
 * A SKIPPED item never reaches this function — skipping writes nothing at all, by design.
 *
 * `okAt` carries forward (spec 02 §3): an `ok` verdict stamps it to now, any other verdict
 * copies the prior value unchanged, so "last worked in March, failed in August" survives in one
 * small object without an array.
 */
export function planCheck(
  items: VaultItem[],
  itemId: string,
  result: string,
  now: number,
  roleFor: RoleFor,
  snoozeMs?: number,
): CheckPlan {
  const item = items.find((it) => it.itemId === itemId);
  // The list refreshes itself on every applied sync, so a vanished item is a race, not an error.
  if (!item) return { refusal: "That item changed under you — the list refreshes on its own; try again." };
  if (item.doc.type !== "login") return { refusal: "Only logins can be checked." };
  // A reader's write would be refused by the server anyway (spec 02 §4: roles are
  // server-enforced). Refuse it HERE, with the reason, rather than letting it fail as an error.
  if (roleFor(item.vaultId) === "reader") {
    return { refusal: "This login is in a vault you can only view — ask the vault's owner to record a check." };
  }

  const prior = item.doc.check;
  const check: ItemCheck = { at: now, result };
  const okAt = result === "ok" ? now : prior?.okAt;
  if (okAt !== undefined) check.okAt = okAt;
  if (snoozeMs !== undefined) check.until = now + snoozeMs;

  return { write: { itemId, doc: { ...item.doc, check } } };
}

/** Clear a snooze so the item returns to the list immediately ("unsnooze"). Keeps the verdict —
 *  only the horizon goes — because the verdict is still the last true thing a human observed. */
export function planUnsnooze(items: VaultItem[], itemId: string, roleFor: RoleFor): CheckPlan {
  const item = items.find((it) => it.itemId === itemId);
  if (!item) return { refusal: "That item changed under you — the list refreshes on its own; try again." };
  if (roleFor(item.vaultId) === "reader") {
    return { refusal: "This login is in a vault you can only view — ask the vault's owner to record a check." };
  }
  if (!item.doc.check?.until) return {}; // nothing to do, and nothing worth a write
  const { until: _dropped, ...rest } = item.doc.check;
  return { write: { itemId, doc: { ...item.doc, check: rest } } };
}
