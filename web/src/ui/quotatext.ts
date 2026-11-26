import type { QuotaUse } from "../api/wire";
import type { Shortfall } from "../vault/quota";
import { fill, OWNER_OUT_OF_SPACE, QUOTA_LINE, QUOTA_OVER_BYTES, QUOTA_OVER_ITEMS, QUOTA_OVER_VAULTS, QUOTA_SHORT } from "./copy";
import { humanSize } from "./format";

/** Spec 03 §14.4: what the screens say about the account's own use and limits. Pure, so tests read the very sentences. */

const count = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

/** One limit passed, and by how much. */
function overText(s: Shortfall): string {
  switch (s.quota) {
    case "accountBytes":
      return fill(QUOTA_OVER_BYTES, humanSize(s.by), humanSize(s.limit));
    case "items":
      return fill(QUOTA_OVER_ITEMS, count(s.by, "item", "items"), count(s.limit, "item", "items"));
    case "ownedSharedVaults":
      return fill(QUOTA_OVER_VAULTS, count(s.by, "shared vault", "shared vaults"), count(s.limit, "shared vault", "shared vaults"));
    default:
      return fill(QUOTA_OVER_ITEMS, String(s.by), String(s.limit));
  }
}

/**
 * The check before a move or an import found the account short: the approved out-of-space entry, then which limits and
 * by how much, and that the operator can raise them. Nothing started.
 */
export function quotaShortText(limits: readonly Shortfall[]): string {
  return `${OWNER_OUT_OF_SPACE} ${fill(QUOTA_SHORT, limits.map(overText).join(" and "))}`;
}

/** Settings' one line of used and limit for each of the four meters; null (nothing shown) when the server gave none. */
export function quotaLineText(q: QuotaUse | null): string | null {
  if (q === null) return null;
  return fill(
    QUOTA_LINE,
    humanSize(q.accountBytes.used),
    humanSize(q.accountBytes.limit),
    String(q.items.used),
    String(q.items.limit),
    String(q.ownedSharedVaults.used),
    String(q.ownedSharedVaults.limit),
    String(q.openLinks.used),
    String(q.openLinks.limit),
  );
}
