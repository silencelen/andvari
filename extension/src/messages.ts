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
 *  - List/match responses never carry passwords — name/username/uris only. Card lists
 *    carry a MASKED identity line ("Visa ••4242"), never the number/expiry/CVV.
 *  - A card secret leaves the SW only via `revealCardField` — popup-only (the SW refuses
 *    tab senders), one field per request, straight to a clipboard write. The in-page fill
 *    path has NO route to card data (in-page card fill is deferred behind the
 *    frame-origin egress contract — cards design 2026-07-09).
 *  - Locked state is FIRST-CLASS: list calls answer `{locked:true}` rather than
 *    pretending "no matches", so the UI can render an honest locked state.
 */

/** A listable login — safe subset, never the password. */
export interface MatchItem {
  itemId: string;
  name: string;
  username: string | null;
  /** Saved site uris (non-secret — the popup detail view renders them as sanitized links).
   *  NOT a secret egress: uris are addresses, not credentials (contract note above). */
  uris: string[];
  /** true when the item's uris matched the requesting host (vs a search-all row). */
  siteMatch: boolean;
  hasTotp: boolean;
}

/** A listable card — masked identity ONLY (SW-computed); `has*` flags let the popup render
 *  copy buttons without ever holding the fields themselves. */
export interface CardItem {
  itemId: string;
  name: string;
  /** "Visa ••4242" / "Card ••4242" / "card" — derived from the decrypted number SW-side. */
  subtitle: string;
  hasNumber: boolean;
  /** true only when the stored halves compose to MM/YY (card.ts composeShortExpiry). */
  hasExpiry: boolean;
  hasCvv: boolean;
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
  /** the existing item's username, shown in the Update banner so a user can tell a password
   *  change from a wrong-account merge (auto-saved items are named after the host). */
  updatesItemUsername: string | null;
}

/** Unlock outcome code — set by background.ts's unlock mapper, rendered as canonical copy by the
 *  popup (extension/src/errors.ts). Codes cross the seam; user-facing sentences live only in the
 *  surface (design decision 4). `network` is a fetch rejection; `unknown` is the catch-all. */
export type UnlockCode =
  | "bad_credentials"
  | "totp_required"
  | "upgrade_required"
  | "identity_mismatch"
  | "kdf_policy"
  | "server_error"
  | "network"
  | "unknown";

/** Save-failure code for a resolved pending save — mapped to copy by the surface (never the raw
 *  SW error string, which used to leak "locked"/"save failed (conflict)" into the banner). */
export type SaveErrorCode = "locked" | "conflict" | "failed";

export type Req =
  | { type: "status" }
  | { type: "unlock"; email: string; password: string }
  | { type: "lock" }
  | { type: "ping" }
  /** Content: logins whose uris match `host` (state-aware). */
  | { type: "matches"; host: string }
  /** Popup/content: all logins, optionally filtered by a query (name/username/uri contains). */
  | { type: "allItems"; query?: string }
  /** Popup: all cards for the copy-only Cards group (query filters name/subtitle). */
  | { type: "cardItems"; query?: string }
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
  /** Popup ONLY (the SW refuses senders with a tab, i.e. content scripts): one card field
   *  for a copy — the value goes straight to the popup's clipboard write, never into a page
   *  or the popup DOM. Cards are deliberately not uri-bound, so there is no host gate; the
   *  gate is the explicit click on a copy button in OUR popup plus the unlocked session. */
  | { type: "revealCardField"; itemId: string; field: "number" | "expiry" | "cvv" }
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
  | { type: "pageInfo"; host: string }
  /** Surface → SW: a secret was just copied — arm the SW backstop clipboard-clear alarm (E1-4).
   *  The surface's own local timer covers the popup-open / in-page cases; this backstop survives
   *  the popup closing on focus loss (the dominant flow). Answers the effective policy seconds. */
  | { type: "scheduleClipboardClear" }
  /** Popup: is a newer extension version published to /downloads? Non-secret and vault-free —
   *  the SW answers whether locked or not (the check reads only the public downloads manifest). */
  | { type: "updateStatus" };

export type Res<T extends Req["type"]> = T extends "status"
  ? {
      unlocked: boolean;
      count: number;
      email: string | null;
      /** Rescue-issued temporary password in effect — the popup shows a persistent nudge (E1-6). */
      mustChangePassword: boolean;
      /** Why the last lock happened, for the F26 reason line above the unlock form (E1-7);
       *  null unless the most recent lock was an idle autolock. */
      lockNotice: { kind: "idle"; seconds: number } | null;
    }
  : T extends "unlock"
    ? { ok: boolean; code?: UnlockCode; error?: string }
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
                      ? { ok: boolean; code?: SaveErrorCode; error?: string }
                      : T extends "linkUri"
                        ? { ok: boolean; error?: string }
                        : T extends "generate"
                          ? { password: string }
                          : T extends "totp"
                            ? { ok: boolean; code?: string; secondsLeft?: number }
                            : T extends "pageInfo"
                              ? { matchCount: number; locked: boolean }
                              : T extends "cardItems"
                                ? { locked: boolean; items: CardItem[] }
                                : T extends "revealCardField"
                                  ? { ok: boolean; value?: string; error?: string }
                                  : T extends "updateStatus"
                                    ? {
                                        current: string;
                                        /** non-null ONLY when a strictly-newer build is published (SW-validated) */
                                        latest: string | null;
                                        chromeUrl: string | null;
                                        firefoxUrl: string | null;
                                      }
                                    : T extends "scheduleClipboardClear"
                                      ? { ok: boolean; clearSeconds: number }
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
