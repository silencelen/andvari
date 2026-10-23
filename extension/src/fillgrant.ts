// The popup's one-shot LOGIN fill grant (security review 2026-10, A13 q39), as a pure predicate so its redemption rule
// is tested by behaviour (A13 review I5), not only pinned in background.ts's source.

/** One popup fill grant: the item the user picked, the tab's top-level origin at mint, and its expiry. */
export interface LoginGrant {
  itemId: string;
  origin: string;
  expiresMs: number;
}

/**
 * May a reveal() for [itemId] from a document whose browser-set origin is [senderOrigin] redeem [grant] at [now]? Only
 * for the very item, before expiry, and only from the origin the grant was minted for: an undefined sender origin
 * fails closed. (background.ts adds the rest: top frame only, one-shot, voided by a navigation.)
 */
export function loginGrantRedeemable(grant: LoginGrant | undefined, itemId: string, senderOrigin: string | undefined, now: number): boolean {
  return grant !== undefined && grant.itemId === itemId && grant.expiresMs > now && typeof senderOrigin === "string" && senderOrigin === grant.origin;
}
