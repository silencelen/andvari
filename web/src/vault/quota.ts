import type { QuotaMeter, QuotaName, QuotaUse } from "../api/wire";

/**
 * Spec 03 §14.4, "The check before a large copy": the web twin of core `QuotaCheck` (core/client/items/QuotaCheck.kt).
 * Made on the `quota` of a FRESH `GET /sync` (VaultStore.quota() after a sync), before "Move everything to a new vault",
 * an import, or a copy into another vault the account owns.
 */

/** What one large copy writes into vaults the account owns: B bytes, N items, V a new shared vault, M its metaBlob length. */
export interface CopySize {
  readonly bytes: number;
  readonly items: number;
  readonly newSharedVault: boolean;
  readonly metaBytes: number;
}

/** A copy's size; throws for a negative or fractional figure, or a metaBlob without a new vault (a mistake of the caller). */
export function copySize(bytes: number, items: number, newSharedVault = false, metaBytes = 0): CopySize {
  for (const n of [bytes, items, metaBytes]) if (!Number.isSafeInteger(n) || n < 0) throw new RangeError("a copy's size is a whole number, never negative");
  if (!newSharedVault && metaBytes !== 0) throw new RangeError("only a new vault has a metaBlob");
  return { bytes, items, newSharedVault, metaBytes };
}

/** One limit the copy would pass: the meter as served, what the copy adds, and by how much it is short (at least 1). */
export interface Shortfall {
  readonly quota: QuotaName;
  readonly used: number;
  readonly limit: number;
  readonly adds: number;
  /** `used + adds - limit`, exact to 2^53 − 1 and capped there. */
  readonly by: number;
}

export type QuotaRoom =
  /** Every limit the copy grows has room. The server's refusal stays authoritative (spec 03 §14.4, point 1). */
  | { readonly kind: "room" }
  /** No numbers, or numbers that cannot be meters: nothing is known, never room. The app starts and the server decides. */
  | { readonly kind: "unknown" }
  /** Short: the app does not start. [limits] in the order accountBytes, items, ownedSharedVaults; never empty. */
  | { readonly kind: "short"; readonly limits: readonly Shortfall[]; readonly first: Shortfall };

/**
 * Short when any limit the copy grows would be passed: `accountBytes.used + max(B, M) > limit`, `items.used + N > limit`,
 * `ownedSharedVaults.used + V > limit`. A limit the copy does not grow (it adds 0) is never short; landing exactly on a
 * limit is room. The sums are exact (BigInt), so no figure wraps round to room.
 */
export function quotaRoom(quota: QuotaUse | null, size: CopySize): QuotaRoom {
  if (quota === null) return { kind: "unknown" };
  const limits: Shortfall[] = [];
  const check = (name: QuotaName, m: QuotaMeter, adds: number) => {
    if (adds <= 0) return;
    const excess = BigInt(m.used) + BigInt(adds) - BigInt(m.limit);
    if (excess > 0n) limits.push({ quota: name, used: m.used, limit: m.limit, adds, by: excess > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(excess) });
  };
  check("accountBytes", quota.accountBytes, Math.max(size.bytes, size.metaBytes));
  check("items", quota.items, size.items);
  check("ownedSharedVaults", quota.ownedSharedVaults, size.newSharedVault ? 1 : 0);
  return limits.length === 0 ? { kind: "room" } : { kind: "short", limits, first: limits[0]! };
}

/**
 * The check before a large copy found the account short (spec 03 §14.4): nothing was written, and the work did not start.
 * [limits] says which limit and by how much (never empty). The server's own refusal part-way stays a separate answer.
 */
export class QuotaShortError extends Error {
  constructor(readonly limits: readonly Shortfall[]) {
    super(`not enough room on the server: ${limits.map((l) => `${l.quota} short by ${l.by}`).join(", ")}`);
    this.name = "QuotaShortError";
  }
}

/** The blob length an item of [plaintextBytes] has as sent: unpadded base64url of the envelope (42 bytes + plaintext). */
export function sealedBlobLength(plaintextBytes: number): number {
  return Math.ceil((4 * (42 + plaintextBytes)) / 3);
}

/** An attachment's stored size (spec 03 §14.4: the upload's body less its 24-byte header): plain + 17 per 64 KiB chunk. */
export function storedAttachmentSize(plainBytes: number): number {
  return plainBytes + 17 * Math.ceil(plainBytes / 65_536);
}
