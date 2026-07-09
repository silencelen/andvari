/**
 * The typed message protocol between popup ⇄ service worker ⇄ content script.
 * THIS FILE IS THE CONTRACT — background.ts implements the SW side, content and
 * popup consume it. Keep additive; every request carries `type`, every response
 * is a plain JSON-able object (structured-clone crosses the runtime boundary).
 *
 * ZK invariants encoded here:
 *  - A secret (password/TOTP) leaves the SW only via `reveal`, and only when the
 *    requesting page's host matches the item's saved uris — OR under a one-shot
 *    fill grant minted by an explicit user click in the popup (`fillFromPopup`).
 *  - List/match responses never carry passwords — name/username/uris only.
 *  - Locked state is FIRST-CLASS: list calls answer `{locked:true}` rather than
 *    pretending "no matches", so the UI can render an honest locked state.
 */

/** A listable login — safe subset, never the password. */
export interface MatchItem {
  itemId: string;
  name: string;
  username: string | null;
  /** true when the item's uris matched the requesting host (vs a search-all row). */
  siteMatch: boolean;
  hasTotp: boolean;
}

export interface RevealedSecret {
  username: string | null;
  password: string | null;
  /** Current TOTP code when the item carries login.totp (so fill can auto-copy it). */
  totpCode: string | null;
}

export interface PendingSave {
  host: string;
  username: string;
  /** set → this is an UPDATE of an existing item's password, not a new login */
  updatesItemId: string | null;
  updatesItemName: string | null;
}

export type Req =
  | { type: "status" }
  | { type: "unlock"; email: string; password: string }
  | { type: "lock" }
  | { type: "ping" }
  /** Content: logins whose uris match `host` (state-aware). */
  | { type: "matches"; host: string }
  /** Popup/content: all logins, optionally filtered by a query (name/username/uri contains). */
  | { type: "allItems"; query?: string }
  /** Secret for a fill. `host` = the requesting page's host. The SW hands out the secret
   *  only when (a) the item's uris match `host`, (b) a one-shot popup grant covers it, or
   *  (c) `explicit` is set — the user picked the item from the search-all list rendered in
   *  OUR closed-shadow UI. Trust model: pages cannot send runtime messages to this SW (no
   *  externally_connectable) and cannot reach into the closed shadow root; the content
   *  script additionally requires `isTrusted` events on fill/save clicks. */
  | { type: "reveal"; itemId: string; host: string; explicit?: boolean }
  /** Popup: user explicitly picked an item to fill into the active tab → SW mints a
   *  one-shot grant for (tabId,itemId) and forwards {type:"fillItem"} to that tab. */
  | { type: "fillFromPopup"; itemId: string }
  /** Content: page captured a submitted credential. SW decides save-vs-update and
   *  stores it as the pending save for the tab (survives navigation). */
  | { type: "capturedCredential"; url: string; username: string; password: string }
  /** Content (on load) / popup: is there a pending save to (re-)offer for this tab? */
  | { type: "pendingSave" }
  /** Content/popup: resolve the tab's pending save. */
  | { type: "resolvePendingSave"; action: "save" | "dismiss" }
  /** Append https://<host> to an item's login.uris (additive; preserves the tail). */
  | { type: "linkUri"; itemId: string; host: string }
  | { type: "generate" }
  /** Popup: live TOTP code for an item's detail row. */
  | { type: "totp"; itemId: string }
  /** Content (each frame load): report host so the SW can badge the tab. */
  | { type: "pageInfo"; host: string };

export type Res<T extends Req["type"]> = T extends "status"
  ? { unlocked: boolean; count: number; email: string | null }
  : T extends "unlock"
    ? { ok: boolean; error?: string }
    : T extends "lock"
      ? { ok: true }
      : T extends "ping"
        ? { ok: boolean; serverTime?: number; error?: string }
        : T extends "matches"
          ? { locked: boolean; matches: MatchItem[] }
          : T extends "allItems"
            ? { locked: boolean; items: MatchItem[] }
            : T extends "reveal"
              ? { ok: boolean; secret?: RevealedSecret; error?: string }
              : T extends "fillFromPopup"
                ? { ok: boolean; error?: string }
                : T extends "capturedCredential"
                  ? { ok: boolean; pending?: PendingSave }
                  : T extends "pendingSave"
                    ? { pending: PendingSave | null }
                    : T extends "resolvePendingSave"
                      ? { ok: boolean; error?: string }
                      : T extends "linkUri"
                        ? { ok: boolean; error?: string }
                        : T extends "generate"
                          ? { password: string }
                          : T extends "totp"
                            ? { ok: boolean; code?: string; secondsLeft?: number }
                            : T extends "pageInfo"
                              ? { matchCount: number; locked: boolean }
                              : never;

/** SW → content (chrome.tabs.sendMessage): fill this item now (popup-granted). The
 *  content script performs its normal `reveal` round-trip with its own host — the SW
 *  honors it via the one-shot grant, keeping a single secret-egress path. */
export type TabMsg =
  | { type: "fillItem"; itemId: string }
  /** SW → content: (re-)offer the tab's pending save banner (e.g. after navigation). */
  | { type: "offerPendingSave"; pending: PendingSave };

/** Typed sendMessage helper both UIs use. */
export function send<T extends Req["type"]>(req: Extract<Req, { type: T }>): Promise<Res<T>> {
  return chrome.runtime.sendMessage(req) as Promise<Res<T>>;
}
