/**
 * The service worker's reveal decision, as a chrome-free leaf `node --test` can pin
 * (revealgate.test.ts). background.ts's `reveal()` computes the inputs and routes through here.
 *
 * Security review 2026-10 (root cause B): `explicit` used to be OR-ed ahead of the host match for
 * EVERY sender, on the theory that a content script only set it on a trusted click in our closed-
 * shadow dropdown. That click was the weak link: the dropdown's host element is page DOM, so a page
 * could make it transparent or paint a decoy over it and steer two genuine clicks into a cross-site
 * reveal. A tab sender's `explicit` therefore buys nothing any more — a page frame gets a secret
 * only when its browser-set origin host-matches the item, or by redeeming the one-shot grant the
 * POPUP mints (`fillFromPopup`), i.e. after the user confirmed the item in extension-owned UI the
 * page can neither draw over nor script.
 *
 * The popup (no tab) keeps `explicit`: its copy and reveal buttons are that extension-owned UI.
 */
export interface RevealGateInput {
  /** The sender has a tab, i.e. it is a content script in some page frame. */
  fromTab: boolean;
  /** The request asked for the explicit (host-unbound) path. */
  explicit: boolean;
  /** The item's saved URIs match the sender's host (browser-set origin for a tab sender). */
  hostMatched: boolean;
}

/** "allow" hands the secret out; "needs_grant" means only a live one-shot popup grant can. */
export function revealGate(i: RevealGateInput): "allow" | "needs_grant" {
  if (i.hostMatched) return "allow";
  if (i.explicit && !i.fromTab) return "allow";
  return "needs_grant";
}
