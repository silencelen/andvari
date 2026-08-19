/**
 * Web route structure (owner dev-note 2026-08-19; ROADMAP "Web route structure") — the
 * top-level views' hash fragments. The vault was a single route: every view lived at `/`, so a
 * refresh or a bookmark always landed back on the home list. Now the CURRENT VIEW is mirrored
 * into `location.hash` and read back at mount, which runs AFTER the unlock gate — so a refresh
 * on `#/health` unlocks and returns to Health.
 *
 * Deliberate boundaries, each load-bearing:
 *  - VIEWS ONLY. A selected item id, an open editor, or a search query in the URL would persist
 *    vault metadata into browser history at rest (and cross-device history sync). Layers stay
 *    behind the useBackGuard sentinel and die with a reload.
 *  - Hash fragments, not paths: the fragment never reaches the server, so nothing new lands in
 *    ktor/Cloudflare access logs, and no SPA-fallback route or cache rule exists to get wrong.
 *  - MIRROR, not navigation: every hash write is a replaceState (the back guard owns the ONE
 *    history-entry dance; see useBackGuard, which this module deliberately knows nothing about).
 *    Hand-editing the address bar does not navigate — bookmarks and refresh are the feature.
 *  - The fragment namespace is shared: enroll links ride the hash until captureEnrollFromLocation
 *    strips them, and `#recover` boots the recovery flow (Welcome.tsx). The `#/` prefix keeps
 *    routed views syntactically distinct from both, and neither of those two ever round-trips
 *    through viewToHash.
 *
 * Pure and window-free so the node-only test setup pins every mapping.
 */

/** The routed views — must stay in lockstep with Vault.tsx's View union (pinned in routes.test.ts). */
export const ROUTED_VIEWS = ["vault", "sharing", "health", "settings", "admin", "trash"] as const;
export type RoutedView = (typeof ROUTED_VIEWS)[number];

/** The home view is the BARE url (no fragment) — "#/vault" would make the common case ugly. */
export function viewToHash(view: RoutedView): string {
  return view === "vault" ? "" : `#/${view}`;
}

/** Total: any unknown/garbage/enroll/#recover fragment is the home view, and the admin view is
 *  gated on the caller actually being an admin — a bookmarked `#/admin` on a non-admin account
 *  degrades to the vault list instead of mounting a view the switch would render as nothing. */
export function hashToView(hash: string, isAdmin: boolean): RoutedView {
  const name = hash.startsWith("#/") ? hash.slice(2) : "";
  const view = (ROUTED_VIEWS as readonly string[]).includes(name) ? (name as RoutedView) : "vault";
  return view === "admin" && !isAdmin ? "vault" : view;
}
