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
 *  - A card secret leaves the SW two ways, both explicit-user-action gated: (1) `revealCardField`
 *    — popup-only (the SW refuses tab senders), one field per request, straight to a clipboard
 *    write; (2) `revealCardForFill` — the S3 in-page fill path, redeemable ONLY by the exact frame
 *    that detected the card form, bound to browser-set `sender.origin` + `sender.frameId` + a live
 *    top-origin recheck, one-shot (design 2026-07-10-extension-card-fill). Neither ever routes a
 *    card value into a `snapshots`/save-banner path.
 *  - A card PAN ENTERS the SW only via `captureCard` (G2 save-card, the reverse of `reveal`): the
 *    content script reads a detected card form's OWN inputs on a trusted submit gesture, NEVER the
 *    CVV. The SW gates it same-origin (`sender.origin === topOrigin(tabId)`), holds the PAN in a
 *    module-scope Map (never a persisted `TabState`, so a lock never writes it at rest), and answers
 *    the MASKED PendingCardSave (no number). Resolving it seals a card doc at CARD_FORMAT_VERSION.
 *  - Locked state is FIRST-CLASS: list calls answer `{locked:true}` rather than
 *    pretending "no matches", so the UI can render an honest locked state.
 */
import type { CardFieldKind } from "./detect";

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
  /** Tier 2 §6 copy parity: gates the cardholder-name copy button (appended — additive rule). */
  hasName: boolean;
}

export interface RevealedSecret {
  username: string | null;
  password: string | null;
  /** Current TOTP code when the item carries login.totp (so fill can auto-copy it). */
  totpCode: string | null;
}

/** S3 in-page card fill: the values a `revealCardForFill` redemption returns — composed SW-side,
 *  and ONLY for the kinds the detected form declared ([A2]/egress step 4: "CVV only if a CVV
 *  field was detected"). Held strictly function-local in the content script; never snapshotted,
 *  never rendered ([A6]). v2 (Tier 1 §6): the expiry HALVES ride INDEPENDENTLY — a parseable
 *  month with a junk year still fills month-only targets; combined targets need both. cardfill.ts
 *  `CardFillValues` is this shape's structural twin (the pure leaf must not import this
 *  chrome-typed file) — keep them in lockstep. */
export interface CardFillFields {
  number?: string;
  /** Composed MM/YY (CardNormalize parity) — BACK-COMPAT only: the fill adapters use the halves
   *  below; this survives for the popup copy path and pre-v2 receivers. */
  expiry?: string;
  name?: string;
  cvv?: string;
  /** Canonical "MM" (card.ts padMonth), independent of the year half. */
  expMonth?: string;
  /** yearTo2/yearTo4 of the stored year, independent of the month half. */
  expYear2?: string;
  expYear4?: string;
  /** SW-derived brand id ("visa"…), NEVER a stored field. [T9] double-gate: composed ONLY when the
   *  form declared cardtype AND cardnumber — the zero-new-information argument (the same response
   *  already carries the PAN) must never depend on a future registry shape. */
  brand?: string;
  /** G3 [X3-A4d]: stored billing postal code — present ONLY when the chosen form declared
   *  cardpostal. Filled verbatim (alphanumeric; no digit-strip). */
  postalCode?: string;
}

/** Why an in-page card fill wrote NOTHING (parity with FillFailCode; the copy lives in the
 *  surface). `no_form` = the granted frame had no live card form; `not_allowed` = a redemption
 *  origin/frame/top-origin check refused. */
export type CardFillFailCode = "locked" | "not_allowed" | "no_form" | "no_fields" | "unreachable";

/** The content script's honest card-fill outcome (F9, Tier 1 §5) — `card` = EVERY declared kind
 *  landed (read-back verified); `partial` = some landed, some didn't; `nothing` as before. A kind
 *  with no derivable value (absent stored field, unparseable half, no option match, fit-guard
 *  skip, read-back mismatch) files in `missedKinds` — the popup names them so the copy buttons
 *  can cover the gap. Set iff filled === "nothing": `code`. */
export interface CardFillOutcome {
  filled: "card" | "partial" | "nothing";
  filledKinds: CardFieldKind[];
  missedKinds: CardFieldKind[];
  code?: CardFillFailCode;
}

/** Cut M (v2 #14): why a fill wrote NOTHING — crosses the seam as a code (the user-facing
 *  sentences live in errors.ts fillErrorCopy, per the error canon). `locked`/`not_allowed`
 *  come from the SW's reveal gate; the rest are the content script's own ground truth. */
export type FillFailCode =
  | "locked" //        vault locked before the secret could be revealed
  | "not_allowed" //   reveal refused (host mismatch, expired grant, unknown item)
  | "no_form" //       no fillable login form in the page (or it left the DOM)
  | "no_fields" //     a form exists but none of its fields matched the secret's parts
  | "no_secret" //     the item carries neither username nor password
  | "unreachable"; //  SW/content messaging failed mid-flight

/** Cut M (v2 #14): the content script's HONEST fill outcome — exactly which parts landed in
 *  the page's fields. The old contract reported message DELIVERY as success; this is what the
 *  dropdown toast and the popup's "Fill this page" verdict are built from. */
export interface FillOutcome {
  filled: "both" | "username" | "password" | "nothing";
  /** Set iff filled === "nothing". */
  code?: FillFailCode;
}

/** G2 save-card capture (design 2026-07-23 §G2 [X2-A3]) — the card fields the content script reads
 *  from a detected card form's OWN inputs on a trusted submit gesture, Luhn-gated content-side, and
 *  sends to the SW via `captureCard`. This is the ONE page→SW PAN egress (the reverse of `reveal`):
 *  the full number crosses so the SW can offer to save/update a card doc. NEVER the CVV — the CVV is
 *  write-only from the vault ([X2-A3] capture set = number/expMonth/expYear/cardholderName/postalCode?).
 *  Halves are canonical: expMonth "MM" (padMonth), expYear 4-digit (yearTo4). */
export interface CaptureCardFields {
  number: string;
  expMonth: string;
  expYear: string;
  cardholderName: string;
  postalCode?: string;
}

/** [X2-A7] the MASKED public shape of a pending card save — what the SW hands the in-page banner.
 *  OMITS `number` (and expiry/CVV): the raw PAN never leaves the SW (pinned like the [A9] card-fill
 *  egress anchors). `cardSubtitle` is the SW-computed identity line ("Visa ••4242"); `updatesItemId`
 *  is set when the captured PAN matches an existing card (an UPDATE of expiry/name, not a new card). */
export interface PendingCardSave {
  host: string;
  cardSubtitle: string;
  updatesItemId?: string;
  updatesItemName?: string;
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
  | "totp_required" // 0.16.3: no longer a dead-end — flips the popup to the code field
  | "totp_bad_code" // wrong/replayed code on the retry (authKey already proven at challenge time)
  | "totp_rate_limited" // 429 on the retry — too many attempts
  | "totp_expired" // the 5-min challenge fused / the SW was evicted → sign in again
  | "totp_enroll_required" // restricted session (instance requires TOTP, user not enrolled) → web vault
  | "aborted" // a server switch / lock landed mid-sign-in — the popup silently re-renders, no error
  | "upgrade_required"
  | "identity_mismatch"
  | "kdf_policy"
  | "server_error"
  | "network"
  | "unknown";

/** Save-failure code for a resolved pending save — mapped to copy by the surface (never the raw
 *  SW error string, which used to leak "locked"/"save failed (conflict)" into the banner). */
export type SaveErrorCode = "locked" | "conflict" | "failed";

/** Extension quick-unlock Tier B (spec 01 §8.4). Redeem-failure code — mapped to copy by the popup.
 *  `wrong_pin` carries the remaining attempts; `expired` = past the 24 h window (blob kept, use the
 *  master password); `exhausted`/`corrupt`/`stale_uvk` = the blob was wiped (re-enroll after a full
 *  unlock); `revoked`/`kdf_policy` = a full wipe + full sign-in; `not_armed`/`aborted` = a benign race. */
export type PinUnlockCode =
  | "wrong_pin"
  | "expired"
  | "exhausted"
  | "not_armed"
  | "corrupt"
  | "stale_uvk"
  | "revoked"
  | "network"
  | "server_error"
  | "identity_mismatch"
  | "kdf_policy"
  | "aborted";

/** Why the PIN entropy floor rejected an enrollment PIN (breaker A2⊕B8) — the popup renders a nudge. */
export type PinWeakReason = "too_short" | "digits_need_length" | "trivial";

/** Quick-unlock enrollment-failure code. `weak_pin` additionally carries a `reason`. */
export type EnrollCode = "locked" | "must_change_password" | "need_full_unlock" | "weak_pin";

/** Biometric quick-unlock redeem failure (0.17.0). No `wrong_pin`/`exhausted` — a hardware-held
 *  full-entropy PRF secret has no offline oracle, so there is no attempt budget. `bio_cancelled` =
 *  the OS ceremony was cancelled / timed out / the passkey was deleted (record KEPT, retry allowed);
 *  the remaining codes are the byte-identical server-dance outcomes shared with the PIN lane. */
export type BioUnlockCode =
  | "bio_cancelled"
  | "not_armed"
  | "expired"
  | "corrupt"
  | "stale_uvk"
  | "revoked"
  | "network"
  | "server_error"
  | "identity_mismatch"
  | "kdf_policy"
  | "aborted";

/** Biometric enrollment refusal (0.17.0). `bio_unsupported` = no platform authenticator / no PRF;
 *  `bio_cancelled` = the enroll ceremony threw (nothing written — amendment 3). */
export type EnrollBioCode = "locked" | "must_change_password" | "need_full_unlock" | "bio_unsupported" | "bio_cancelled";

export type Req =
  | { type: "status" }
  | { type: "unlock"; email: string; password: string }
  /** Popup: finish a TOTP-gated sign-in with the authenticator code (0.16.3). Follows an `unlock`
   *  that answered `totp_required`; the SW holds the already-derived keys so no second KDF runs.
   *  Renders ONLY in the popup (chrome-extension://), never a page — same law as the PIN. */
  | { type: "unlockTotp"; code: string }
  /** Popup: abandon a pending TOTP challenge ("start over" / bad-code cap) — drops the in-memory keys. */
  | { type: "cancelTotp" }
  | { type: "lock" }
  /** Explicit full sign-out (a new popup action) — clears everything INCLUDING the quick-unlock blob
   *  + co-key + retained tokens (spec 01 §8.4; distinct from `lock`, which may arm quick unlock). */
  | { type: "signOut" }
  /** Popup: redeem an armed quick-unlock with the PIN (spec 01 §8.4). Renders ONLY in the popup
   *  (chrome-extension://), never a page — breaker B7. */
  | { type: "unlockWithPin"; pin: string }
  /** Popup: enroll a quick-unlock PIN over the in-memory UVK (only while unlocked; refused while
   *  mustChangePassword). Never carries key material — the SW holds the UVK (breaker B1). */
  | { type: "enrollQuickUnlock"; pin: string }
  /** Popup: redeem an armed BIOMETRIC quick-unlock (0.17.0) — the SW opens the WebAuthn connector
   *  window, runs the ceremony, and does the same server dance as `unlockWithPin`. No payload; the
   *  UVK never leaves the SW. Renders ONLY in the popup (breaker B7). */
  | { type: "unlockWithBio" }
  /** Popup: enroll biometric quick-unlock over the in-memory UVK (only while unlocked; same gates as
   *  `enrollQuickUnlock`). Opens the connector for the create()+PRF ceremony. Never carries key material.
   *  (Platform capability is probed IN the popup via isUserVerifyingPlatformAuthenticatorAvailable —
   *  a page context WebAuthn query the SW can't make — so there is no separate capability message.) */
  | { type: "enrollQuickUnlockBio" }
  /** Popup: turn quick unlock off — a full wipe, no auth gate (§8.1 parity). */
  | { type: "disableQuickUnlock" }
  /** Popup: the one-time post-unlock offer card was dismissed (durable, storage.local — breaker B7). */
  | { type: "dismissQuickUnlockOffer" }
  /** Options page ONLY: the explicit "Remove data for this server" action (design §4.2/B2-7 — the
   *  ONLY destructive per-origin path; a server switch PRESERVES the old origin's namespace). Purges
   *  exactly `origin`'s namespaced keys (quick-unlock/PIN co-key + cached channel state) everywhere,
   *  touching no other origin. `origin` is a raw/canonical origin string; the SW re-canonicalizes it. */
  | { type: "purgeServerData"; origin: string }
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
   *  gate is the explicit click on a copy button in OUR popup plus the unlocked session.
   *  Tier 2 §6: `"name"` joins the union (copy parity — every surface copies number/expiry/
   *  name/CVV); additive, same popup-only guard + doc.type==="card" gate. */
  | { type: "revealCardField"; itemId: string; field: "number" | "expiry" | "name" | "cvv" }
  /** Content: page captured a submitted credential. SW decides save-vs-update and
   *  stores it as the pending save for the tab (survives navigation). */
  | { type: "capturedCredential"; url: string; username: string; password: string }
  /** Content (G2 [X2-A3]): a card form was submitted under a trusted gesture — the frame's OWN card
   *  inputs, Luhn-gated content-side, NEVER the CVV. The SW re-Luhns, discards any capture whose
   *  `sender.origin !== topOrigin(tabId)` ([X2-A2] same-origin gate — a cross-origin/PSP frame never
   *  drives a save), and offers a save/update against the tab's `pendingCardSave` slot. Carries the
   *  PAN (the reverse of `reveal`); the answer is the MASKED PendingCardSave, never the number. */
  | { type: "captureCard"; fields: CaptureCardFields }
  /** Content: resolve the tab's pending card save (G2). */
  | { type: "resolvePendingCardSave"; action: "save" | "dismiss" }
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
  | { type: "updateStatus" }
  /** Content (per frame, passive, S3): ALL of this frame's same-origin card forms, document
   *  order across [document, …shadow roots] (Tier 2 §2/§3). METADATA ONLY — kinds, never values,
   *  and [A2] NO page-controlled host (the SW binds frame identity to browser-set
   *  `sender.origin`; a `msg.host` would be a spoofable offer-manufacture input). `forms:[]` ⇒
   *  the frame's card forms went away and its record is cleared. [U14]: this REPLACED Tier 1's
   *  `fields: CardFieldKind[]` — a design-authorized breach of the additive rule; the SW
   *  discards any persisted pre-update `{fields}` record on read (fail-closed, rescan restores). */
  | { type: "cardFormInfo"; forms: CardFieldKind[][] }
  /** Popup ONLY (the SW refuses tab senders): may the Cards group show a Fill button for the
   *  active tab, and to which origin? `fillable` iff a recorded card form's origin equals the
   *  tab's CURRENT top-level origin (SW-derived from `tab.url` under `activeTab`, [A4]). */
  | { type: "cardFillOffers" }
  /** Popup ONLY: user clicked Fill on a card row → the SW mints a one-shot CARD grant (a store
   *  SEPARATE from login `grants`, [A5]) bound to (tabId,itemId,frameId,origin) and forwards
   *  {type:"fillCard"} to that ONE frame. */
  | { type: "fillCardFromPopup"; itemId: string }
  /** Content (S3 redemption): the granted frame redeems its card fill. The SW verifies, all
   *  fail-closed-on-undefined ([A3]): a live card grant for (tabId,itemId); `sender.frameId ===
   *  grant.frameId`; `sender.origin === grant.origin`; and `grant.origin` still equals the tab's
   *  current top-level origin (re-fetched). Success consumes the grant and returns the declared
   *  fields ONCE; any failure consumes nothing. */
  | { type: "revealCardForFill"; itemId: string };

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
      /** Quick-unlock Tier B sub-state (spec 01 §8.4). `armed` = locked-armed + redeemable (the popup
       *  shows the PIN field on the locked screen); `enrolled` + `offerDismissed` drive the unlocked
       *  Settings toggle + the one-time offer card; `attemptsRemaining` for the "N tries left" copy. */
      quickUnlock: { enrolled: boolean; armed: boolean; attemptsRemaining: number; offerDismissed: boolean; kind: "pin" | "biometric" | null };
      /** 0.16.3: a TOTP-gated sign-in awaiting the code (SW-memory only, so a reopened popup — the
       *  common case, since copying a code from an authenticator app closes it — re-renders the code
       *  field). Outranks the armed-PIN view. Null when there's no live challenge (or the SW evicted). */
      totpPending: { email: string; expiresAt: number } | null;
    }
  : T extends "unlock"
    ? { ok: boolean; code?: UnlockCode; error?: string }
    : T extends "unlockTotp"
      ? { ok: boolean; code?: UnlockCode; error?: string }
      : T extends "cancelTotp"
        ? { ok: true }
        : T extends "lock"
          ? { ok: true }
      : T extends "signOut"
        ? { ok: true }
        : T extends "unlockWithPin"
          ? { ok: boolean; code?: PinUnlockCode; attemptsRemaining?: number }
          : T extends "enrollQuickUnlock"
            ? { ok: boolean; code?: EnrollCode; reason?: PinWeakReason }
            : T extends "unlockWithBio"
              ? { ok: boolean; code?: BioUnlockCode }
              : T extends "enrollQuickUnlockBio"
                ? { ok: boolean; code?: EnrollBioCode }
            : T extends "disableQuickUnlock"
              ? { ok: true }
              : T extends "dismissQuickUnlockOffer"
                ? { ok: true }
                : T extends "ping"
        ? { ok: boolean; serverTime?: number; error?: string }
        : T extends "matches"
          ? { locked: boolean; matches: MatchItem[] }
          : T extends "allItems"
            ? { locked: boolean; items: MatchItem[] }
            : T extends "reveal"
              ? /** Cut M (v2 #14): failures carry a seam code (additive) so fill surfaces can
                 *  render canon copy — `error` stays debug-only detail, never rendered. */
                { ok: boolean; secret?: RevealedSecret; code?: "locked" | "not_allowed"; error?: string }
              : T extends "fillFromPopup"
                ? /** Cut M (v2 #14): `ok` is the FILL outcome, not delivery — true only when the
                   *  content script reports it actually wrote into a field. `outcome` is the full
                   *  verdict; `code` is set on every failure (additive fields, same shape). */
                  { ok: boolean; outcome?: FillOutcome; code?: FillFailCode; error?: string }
                : T extends "capturedCredential"
                  ? { ok: boolean; pending?: PendingSave }
                  : T extends "captureCard"
                    ? /** G2: `pending` is the MASKED offer (no PAN); absent when the capture was
                       *  discarded (cross-origin frame, non-Luhn, dedupe, locked). */
                      { ok: boolean; pending?: PendingCardSave }
                  : T extends "resolvePendingCardSave"
                    ? { ok: boolean; code?: SaveErrorCode; error?: string }
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
                                        /** M-D4b / UQUIET-read: the fail-closed-QUIET update-channel reason
                                         *  (unverified/stale/…), or null. Rendered as ONE muted popup line, never a
                                         *  banner/nag. Mutually exclusive with `latest` (an offer supersedes it). */
                                        quietReason?: string | null;
                                      }
                                    : T extends "scheduleClipboardClear"
                                      ? { ok: boolean; clearSeconds: number }
                                      : T extends "cardFormInfo"
                                        ? { ok: boolean }
                                        : T extends "cardFillOffers"
                                          ? {
                                              fillable: boolean;
                                              origin: string | null;
                                              /** Tier 2 §6 [U21]: the tab's registry holds ≥1 card form but NO frame is
                                               *  origin-eligible (PSP-iframe checkout). SW-derived from browser-set
                                               *  per-frame origins vs the top origin — never page data. The popup renders
                                               *  the neutral explainer and NEVER a Fill button in this state. */
                                              crossOriginFormsOnly: boolean;
                                            }
                                          : T extends "fillCardFromPopup"
                                            ? { ok: boolean; outcome?: CardFillOutcome; code?: CardFillFailCode; error?: string }
                                            : T extends "revealCardForFill"
                                              ? { ok: boolean; fields?: CardFillFields; error?: string }
                                              : T extends "purgeServerData"
                                                ? { ok: boolean }
                                                : never;

/** SW → content (chrome.tabs.sendMessage): fill this item now (popup-granted). The
 *  content script performs its normal `reveal` round-trip with its own host — the SW
 *  honors it via the one-shot grant, keeping a single secret-egress path. Cut M (v2 #14):
 *  the receiver answers a FillOutcome via sendResponse, which the SW relays to the popup. */
export type TabMsg =
  | { type: "fillItem"; itemId: string }
  /** SW → content: (re-)offer the tab's pending save banner (e.g. after navigation). */
  | { type: "offerPendingSave"; pending: PendingSave }
  /** SW → content (S3): fill this card into the granted frame's card form. Sent to ONE frameId
   *  only; the frame redeems via `revealCardForFill` (the value round-trip), never receiving the
   *  card values on this message. Tier 2 [U12]: `sig` is the grant's kind-signature
   *  (`kinds.join(",")` of the chosen form) — the receiver fills the FIRST form (document order)
   *  whose CURRENT signature equals it; no match → `no_form`, NEVER an index fallback. */
  | { type: "fillCard"; itemId: string; sig: string }
  /** SW → content (S3 §7, broadcast to ALL frames — [T5] popup fast-path): drop the sig sentinel
   *  and caches, then re-report the frame's card form NOW. [T4]: the receiver resets lastCardSig
   *  FIRST — bfcache restores JS state on a back-navigation, so without the reset the rescan's
   *  own report is swallowed by its own sig guard and the offer is lost for the document's life.
   *  Answers `{ok:true}` (delivery signal only — the report rides its own cardFormInfo). */
  | { type: "rescanCardForms" };

/** Tier 2 §2 [U11] — the SW's grant-target choice over the eligible registry entries, factored
 *  PURE and exported here (background.ts is chrome-bound at module eval and has no test harness,
 *  so the suite imports the chooser from this chrome-free-at-import contract file — §9).
 *  Frame 0 wins whenever it holds ANY eligible form (Tier-1 rule, unchanged — a same-origin
 *  sub-frame must never out-bid the visible top checkout by kind-count); only when frame 0 has
 *  none does the richest eligible sub-frame win (most distinct kinds in its richest form; tie →
 *  lowest frameId). Richest-FORM selection (most distinct kinds; tie → first in document order)
 *  applies WITHIN the chosen frame. Empty input / no forms anywhere → null. */
export function chooseCardTarget(
  frames: ReadonlyArray<{ frameId: number; forms: CardFieldKind[][] }>,
): { frameId: number; kinds: CardFieldKind[] } | null {
  const richestForm = (forms: CardFieldKind[][]): CardFieldKind[] | null => {
    let best: CardFieldKind[] | null = null;
    let bestN = 0; // an empty form (0 distinct kinds) never wins — a grant with no kinds fills nothing
    for (const f of forms) {
      const n = new Set(f).size;
      if (n > bestN) {
        best = f;
        bestN = n; // strict > keeps the FIRST on ties — document order
      }
    }
    return best;
  };
  const top = frames.find((f) => f.frameId === 0 && f.forms.length > 0);
  if (top) {
    const kinds = richestForm(top.forms);
    return kinds ? { frameId: 0, kinds } : null;
  }
  let chosen: { frameId: number; kinds: CardFieldKind[] } | null = null;
  let chosenN = -1;
  for (const f of [...frames].sort((a, b) => a.frameId - b.frameId)) {
    const kinds = richestForm(f.forms);
    if (kinds === null) continue;
    const n = new Set(kinds).size;
    if (n > chosenN) {
      chosen = { frameId: f.frameId, kinds };
      chosenN = n; // strict > + ascending sort keeps the LOWEST frameId on ties
    }
  }
  return chosen;
}

/** Typed sendMessage helper both UIs use. */
export function send<T extends Req["type"]>(req: Extract<Req, { type: T }>): Promise<Res<T>> {
  return chrome.runtime.sendMessage(req) as Promise<Res<T>>;
}
