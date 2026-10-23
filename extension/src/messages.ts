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
 *  - `allItems` answers the POPUP only (security review 2026-10). It used to answer any injected
 *    frame, because the in-page dropdown's "Search all logins…" rendered the whole inventory in a
 *    closed shadow root; that in-page search could be clickjacked into a cross-site fill, so it now
 *    hands off to the popup and no page frame needs the inventory any more. A tab sender gets an
 *    empty list. `matches` stays answerable from pages — it is host-scoped and the dropdown needs it.
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
 *  - The C1 in-page card chip messages (`cardChipOffer`/`openPopupForCards`, design
 *    2026-07-26) carry NO VALUES IN EITHER DIRECTION. The requests have no members at all
 *    ([A2]/[S7]: a page-controlled member is the shape already struck once — every input the SW's
 *    gate reads is browser-set `sender.origin`/`sender.frameId`/`sender.tab.id`), and the answers
 *    are booleans only — no item name, no count, no masked identity, no origin echo, no kinds.
 *    The chip is a SIGNPOST: it mints nothing, and every card value still leaves the SW only
 *    through the popup-minted one-shot `revealCardForFill` ([A5] unchanged).
 *  - Locked state is FIRST-CLASS: list calls answer `{locked:true}` rather than
 *    pretending "no matches", so the UI can render an honest locked state.
 *  - WHO MAY SEND WHAT (security review 2026-10, A14): sendergate.ts classifies every `Req` type as
 *    content-sent or extension-page-only, and the SW's dispatch refuses an extension-page-only type
 *    from any sender whose `sender.url` is not one of this extension's pages, before the handler
 *    runs (the per-handler checks below stay). Adding a type here without classifying it there
 *    fails `tsc` and the extension suite.
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
  /** G21 (2026-08-30 audit): the item lives in a READER-role vault — the server denies every push
   *  against it (Service.kt role=="reader" ⇒ Forbidden). The page-side surfaces (popup, content)
   *  can't see vault roles, so this flag is the ONE signal they read to suppress WRITE offers a
   *  reader can never complete — the popup TOTP paste-add and the search-all URI-link offer —
   *  instead of surfacing an action that dead-ends in a refusal. SW-side writableItem() stays the
   *  honest backstop. SW-computed (toMatchItem), never page-supplied. */
  readOnly: boolean;
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
  /** Security review 2026-10, branch A11 (q14): the DESTINATION vault's name (decrypted under a held key; null when
   *  it does not decrypt), and whether that vault is not the in-force personal vault. Optional: a pending persisted
   *  by an older worker lacks them (the banner then names no vault and treats an update as shared). */
  vaultName?: string | null;
  vaultShared?: boolean;
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
  | "keys_damaged" // H67: the account's stored wrappedUvk isn't a readable envelope — terminal, not credentials
  | "kdf_policy"
  | "bad_wire_id" // A11 (c18): a login answer with malformed session ids (A10 grammar) — tampering class, terminal
  | "server_error"
  | "network"
  | "unknown";

/** Save-failure code for a resolved pending save — mapped to copy by the surface (never the raw
 *  SW error string, which used to leak "locked"/"save failed (conflict)" into the banner). */
export type SaveErrorCode = "locked" | "no_personal_vault" | "conflict" | "rejected" | "failed";

/** TOTP-add failure code (setTotp, design 2026-08-12) — mapped to copy by the
 *  surface. `exists` = the add-only contract refused a replace; `not_allowed` = a tab sender (the
 *  write is popup-only — security review 2026-10 retired the page lane); `invalid` = the shared
 *  normalize + parse gate rejected the secret; `read_only` (G21) = a reader-role vault the server
 *  would refuse the push against — the honest SW backstop for the suppressed page-side offer. */
export type TotpAddCode = "locked" | "no_personal_vault" | "invalid" | "exists" | "not_allowed" | "conflict" | "failed" | "read_only";

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
  | "keys_damaged" // A13 (q38): the served account-key blob is not a readable envelope — terminal, blob kept
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
  | "keys_damaged" // A13 (q38): the served account-key blob is not a readable envelope — terminal, blob kept
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
  /** A5b (security review 2026-10, root cause A): the popup confirms that the personal vault changed (a served
   *  wrap named another vault than this browser's). Extension pages only; mints nothing. */
  | { type: "personalAcceptChange" }
  /** A6 fix round (A5b LOW-1 parity): load who the server reports on the NEW personal vault; "Use new" is
   *  offered (and accepted by the SW) only after this succeeded for that vault. Extension pages only. */
  | { type: "personalDescribeChange" }
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
  /** Popup: the one-time post-unlock offer card was dismissed (durable, the worker's trusted store — breaker B7). */
  | { type: "dismissQuickUnlockOffer" }
  /** Options page ONLY: the explicit "Remove data for this server" action (design §4.2/B2-7 — the
   *  ONLY destructive per-origin path; a server switch PRESERVES the old origin's namespace). Purges
   *  exactly `origin`'s namespaced keys (quick-unlock/PIN co-key + cached channel state) everywhere,
   *  touching no other origin. `origin` is a raw/canonical origin string; the SW re-canonicalizes it. */
  | { type: "purgeServerData"; origin: string }
  /** Options page + popup (security review 2026-10, A15): the origin the worker dials, a pre-A15 server choice
   *  awaiting re-confirmation through the Trust Gate (display only — never dialed), and whether this browser can
   *  keep a server choice at all (false when IndexedDB is unavailable, e.g. Firefox's permanent private browsing).
   *  Pages never read the trusted store themselves; they ask here. Extension pages only. */
  | { type: "serverInfo" }
  /** Options page ONLY (A15): commit a server origin after the Trust Gate's Connect (the grant gesture). The worker
   *  canonicalizes, writes its trusted store and runs the origin-clean switch (§4.1) before answering. This message
   *  is the ONLY way the server choice changes; a storage write is no longer a switch. */
  | { type: "setServerUrl"; url: string }
  /** Options page (A15): drop the pre-A15 server suggestion without connecting to it ("not mine"). */
  | { type: "forgetLegacyServer" }
  | { type: "ping" }
  /** Content: logins whose uris match `host` (state-aware). PASSIVE ([K13]): the dropdown's
   *  open-query rides the same trusted focusin a page can drive with HTMLElement.focus(), so it
   *  must never re-arm the idle autolock — the pick (`reveal`) is the user-activity signal. */
  | { type: "matches"; host: string }
  /** Popup ONLY: all logins, optionally filtered by a query (name/username/uri contains). A tab
   *  sender gets an empty list (contract header). */
  | { type: "allItems"; query?: string }
  /** Content, SIGNUP FORMS ONLY: is this just-typed password already used by another login?
   *  UNLOCKED-ONLY by design: answering it while locked would require a membership oracle over the
   *  vault's PASSWORDS, which is strictly more disclosure than the locked compartment already
   *  carries (see content.ts checkPasswordReuse for the full argument). Security review 2026-10:
   *  NOTHING comes back to the page side — `ok` only says the ask was received. A hit is kept
   *  SW-side for the tab and shown on the toolbar badge and in the popup (`reuseNotice`). */
  | { type: "passwordReuse"; password: string }
  /** Popup ONLY: the active tab's pending reuse warning, if any (consumed by the read). A tab
   *  sender gets null — the count must never reach a page frame. */
  | { type: "reuseNotice" }
  /** Popup: all cards for the copy-only Cards group (query filters name/subtitle). */
  | { type: "cardItems"; query?: string }
  /** Secret for a fill. The SW hands out the secret only when (a) the caller's host matches the
   *  item's uris, (b) a one-shot popup grant covers it, or (c) the POPUP sets `explicit` — its own
   *  reveal/copy buttons, extension-owned UI with no tab. The matched host is the browser-set
   *  `sender.origin`'s host for TAB senders ([A2], fail-closed on a missing/opaque origin); `host`
   *  is read only from the popup, which has no tab and reads `activeTabHost()`.
   *  Security review 2026-10 (root cause B): `explicit` from a TAB sender is IGNORED. It used to be
   *  checked ahead of the host gate for the in-page search-all pick, on the theory that a trusted
   *  click inside our closed shadow root could not be steered; it could — the shadow HOST is page
   *  DOM, so a page could make the dropdown transparent or paint a decoy over it. A cross-site fill
   *  into a page now needs (b): the user confirms the item in the popup, which mints the grant.
   *  The decision lives in revealgate.ts. Trust model otherwise unchanged: pages cannot send runtime
   *  messages here (no externally_connectable), and the content script requires `isTrusted` events
   *  that pass the in-page visibility guard (visibilityguard.ts) on fill/save clicks. */
  | { type: "reveal"; itemId: string; host: string; explicit?: boolean }
  /** Popup ONLY (the SW refuses senders with a tab, i.e. content scripts — the grant is minted for
   *  whatever tab is ACTIVE, which need not be the sender's): user explicitly picked an item to
   *  fill into the active tab → SW mints a one-shot grant for (tabId,itemId) and forwards
   *  {type:"fillItem"} to that tab's top frame. */
  | { type: "fillFromPopup"; itemId: string }
  /** Popup ONLY (the SW refuses senders with a tab, i.e. content scripts): one card field
   *  for a copy — the value goes straight to the popup's clipboard write, never into a page
   *  or the popup DOM. Cards are deliberately not uri-bound, so there is no host gate; the
   *  gate is the explicit click on a copy button in OUR popup plus the unlocked session.
   *  Tier 2 §6: `"name"` joins the union (copy parity — every surface copies number/expiry/
   *  name/CVV); additive, same popup-only guard + doc.type==="card" gate. */
  | { type: "revealCardField"; itemId: string; field: "number" | "expiry" | "name" | "cvv" }
  /** Content: page captured a submitted credential. SW decides save-vs-update and
   *  stores it as the pending save for the tab (survives navigation). PASSIVE (F01): a submit is
   *  page-DRIVEABLE — `form.requestSubmit()` fires one with isTrusted true and no user gesture —
   *  so it must never re-arm the idle autolock; the user's own signal is `resolvePendingSave`.
   *  The capture itself needs a fresh gesture content-side (consumeLoginGesture): a trusted
   *  click/Enter, or the SW's own `fillItem` delivery — a popup fill is a user click this document
   *  cannot see, and the sites that auto-submit on fill are exactly the ones that would lose the
   *  banner without it. */
  | { type: "capturedCredential"; username: string; password: string }
  /** Content (G2 [X2-A3]): a card form was submitted under a trusted gesture — the frame's OWN card
   *  inputs, Luhn-gated content-side, NEVER the CVV. The SW re-Luhns, discards any capture whose
   *  `sender.origin !== topOrigin(tabId)` ([X2-A2] same-origin gate — a cross-origin/PSP frame never
   *  drives a save), and offers a save/update against the tab's `pendingCardSave` slot. Carries the
   *  PAN (the reverse of `reveal`); the answer is the MASKED PendingCardSave, never the number. */
  | { type: "captureCard"; fields: CaptureCardFields }
  /** Content: resolve the tab's pending card save (G2). Frame-gated like the login twin: only
   *  the frame captureCard recorded (or the popup) may save/dismiss — any other frame is
   *  answered "nothing pending" ([X2-A2] resolve half). */
  | { type: "resolvePendingCardSave"; action: "save" | "dismiss" }
  /** Content (on load, TOP FRAME) / popup: is there a pending save to (re-)offer for this tab?
   *  The SW answers sub-frames `{pending:null}` — the metadata (host/username/vault-item names)
   *  belongs to the top frame that captured it. [K13]-adjacent: PASSIVE (fires on every load, so
   *  an auto-refreshing tab must not defer the idle autolock). */
  | { type: "pendingSave" }
  /** Content/popup: resolve the tab's pending save. Resolvable ONLY by the frame that captured
   *  it (or the popup) — the card entry's frame rule, mirrored. */
  | { type: "resolvePendingSave"; action: "save" | "dismiss" }
  /** Content (unlock-prompt, design 2026-08-12): the banner's Save click answered `locked`, so
   *  the banner asks the SW to SUMMON the unlock screen via `chrome.action.openPopup()` instead
   *  of only naming it. EXACTLY this literal — no members ([A2]-adjacent: the SW reads only
   *  browser-set sender fields). The side effect is bound to a GENUINE locked offer: the SW opens
   *  nothing unless this tab holds a live pending save, resolvable by this frame, while the vault
   *  is locked. `opened` is the honest resolution of that ONE call ([K14]: on Firefox it is
   *  EXPECTED to reject and the banner's toolbar sentence is the primary path there). NON-passive:
   *  it rides the banner's isTrusted Save click, i.e. genuine user activity. */
  | { type: "openPopupForSave" }
  /** Append https://<host> to an item's login.uris (additive; preserves the tail). A vault WRITE:
   *  a TAB sender may only link ITS OWN host (`host` must equal the browser-set `sender.origin`'s
   *  host — [A2], fail-closed on a missing/opaque origin), so a page-side caller can never make an
   *  item match a site the user never visited. Popup senders (no tab) are unrestricted. */
  | { type: "linkUri"; itemId: string; host: string }
  | { type: "generate" }
  /** Popup: live TOTP code for an item's detail row.
   *
   *  `forCopy` marks the ONE send that is a user action rather than a render: the chip's click
   *  handler (copyTotp), which puts the code on the clipboard. Everything else on this message is
   *  the popup's 1 s ticker refreshing every visible chip, which is why "totp" is in PASSIVE_MSGS.
   *  H69 (2026-09-13 audit) needs the two told apart before the SW can count a copied code as a
   *  use (spec 02 §8.2, the G37 rule the other three clients already follow): recording on every
   *  answer would stamp lastUsedAt on every TOTP item, once a second, for as long as the popup is
   *  open — which would not fix the staleness signal, it would delete it. A page cannot forge the
   *  flag: the handler refuses any sender with a tab before it is read. */
  | { type: "totp"; itemId: string; forCopy?: true }
  /** Popup ONLY (the SW refuses tab senders): add a one-time-code secret to a login item that
   *  has NONE (TOTP-add lane, design 2026-08-12). ADD-ONLY BY CONTRACT — the extension never
   *  replaces or removes an existing login.totp (that stays a web-vault edit); the SW enforces
   *  this regardless of what any surface renders. `totp` is the user's paste, raw: the SW runs
   *  the shared normalizeTotp + parse-accept gate itself (a surface's validation is a
   *  convenience, never the gate). */
  | { type: "setTotp"; itemId: string; totp: string }
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
  /** Content (C1 chip, design 2026-07-26 §C2): may THIS frame render the offer chip? EXACTLY this
   *  literal — **no `host`, no `kinds`, no `frameId` member** ([A2]/[S7]). A page-controlled member
   *  would be an offer-manufacture input; the gate reads only browser-set sender fields (origin ===
   *  the recorded top-frame origin, frameId STRICTLY 0 — [S1] never the badge's fail-OPEN
   *  `frameId === undefined ||` disjunct). Answers two booleans, nothing else. [S3]: `fillable`
   *  carries NO vault condition — chip presence is a function only of facts the page already has,
   *  or a hit-test on the closed-shadow host would become a live vault-state monitor. [K13]: joins
   *  PASSIVE_MSGS — page script can fire *trusted* focus at frame rate, so this stream is not user
   *  activity and must never defer the idle autolock. */
  | { type: "cardChipOffer" }
  /** Content (C1 chip, §C4): the chip was clicked under a trusted gesture → the SW ATTEMPTS
   *  `chrome.action.openPopup()`. Mints nothing, selects nothing, enumerates nothing ([A5] — the
   *  card grant stays a popup-only mint); FORBIDDEN: `tabs.create`/`windows.create` of popup.html.
   *  `opened` is the honest resolution of that ONE call and claims nothing more ([K14]: on Firefox
   *  it is EXPECTED to reject, and the content script's toolbar toast is the primary path there).
   *  NON-passive: it rides a real isTrusted click, i.e. genuine user activity. */
  | { type: "openPopupForCards" }
  /** Content: the in-page dropdown's "Search all logins…" row was activated under a trusted,
   *  visibility-guarded gesture → the SW ATTEMPTS `chrome.action.openPopup()`, where the user
   *  searches and fills (cross-site fills are confirmed in extension-owned UI only — security
   *  review 2026-10). The chip's contract verbatim: no members, mints nothing, selects nothing,
   *  enumerates nothing, `opened` is the honest result of the one call (EXPECTED to reject on
   *  Firefox, where the content script's toolbar toast is the primary path). NON-passive. */
  | { type: "openPopupForSearch" }
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
      /** A5b: a served personal-vault record names another vault than this browser's; it keeps saving to its
       *  own until the user confirms (popup notice). */
      personalChange: boolean;
      /** A5b LOW-3 (A6): the notice naming both the current and the new vault; null when nothing pends. */
      personalChangeText: string | null;
      /** A9 review MEDIUM-1: the pending record is a PROPOSAL (this browser never confirmed a personal vault). */
      personalProposal: boolean;
      /** Root cause A §1.7 (A6): shared vaults whose grant has no UVK wrap yet — the extension never opens a
       *  grant seal (Q8), so they wait for a full client ("open andvari to review"). */
      waitingGrants: number;
      /** Root cause A §5.1 INV-HOME (A1b): rows the last snapshot sent under the wrong vault (not applied). */
      wrongVault: number;
      /** A15: while LOCKED, the email this browser last signed in with (non-secret; prefills the form). Kept by the
       *  worker in its trusted store — the popup no longer writes storage.local. Null while unlocked. */
      rememberedEmail: string | null;
    }
  : T extends "personalAcceptChange"
    ? { ok: boolean; code?: "locked" | "none" | "storage" | "not_allowed" | "need_full_unlock" | "unverified" | "coholders_not_loaded" }
  : T extends "personalDescribeChange"
    ? { ok: boolean; code?: "locked" | "none" | "not_allowed" | "coholders_unavailable"; coHoldersLine?: string }
  : T extends "unlock"
    ? { ok: boolean; code?: UnlockCode; error?: string }
    : T extends "unlockTotp"
      ? { ok: boolean; code?: UnlockCode; error?: string }
      : T extends "cancelTotp"
        ? { ok: boolean } // ok:false only when the A14 sender gate refused (nothing was done)
        : T extends "lock"
          ? { ok: boolean }
      : T extends "signOut"
        ? { ok: boolean }
        : T extends "unlockWithPin"
          ? { ok: boolean; code?: PinUnlockCode; attemptsRemaining?: number }
          : T extends "enrollQuickUnlock"
            ? { ok: boolean; code?: EnrollCode; reason?: PinWeakReason }
            : T extends "unlockWithBio"
              ? { ok: boolean; code?: BioUnlockCode }
              : T extends "enrollQuickUnlockBio"
                ? { ok: boolean; code?: EnrollBioCode }
            : T extends "disableQuickUnlock"
              ? { ok: boolean }
              : T extends "dismissQuickUnlockOffer"
                ? { ok: boolean }
                : T extends "ping"
        ? { ok: boolean; serverTime?: number; error?: string }
        : T extends "matches"
          ? { locked: boolean; matches: MatchItem[] }
          : T extends "passwordReuse"
            ? { ok: boolean }
          : T extends "reuseNotice"
            ? { count: number } | null
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
                            : T extends "setTotp"
                              ? { ok: boolean; code?: TotpAddCode; error?: string }
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
                                              : T extends "serverInfo"
                                                ? { url: string; legacy: string | null; trustedStore: boolean }
                                              : T extends "setServerUrl"
                                                ? { ok: boolean; url?: string; code?: "invalid" | "storage" | "not_allowed" }
                                              : T extends "forgetLegacyServer"
                                                ? { ok: boolean }
                                                : /** C1 §C2 [S7]: the branch matches ONLY these two booleans — no `string` type is
                                                   *  admitted here, so an "origin"/"name"/"subtitle" field can never be added to the
                                                   *  chip's answer without editing this contract line first. */
                                                  T extends "cardChipOffer"
                                                  ? { fillable: boolean; locked: boolean }
                                                  : /** C1 §C4: the honest resolution of the ONE openPopup attempt — nothing else. */
                                                    T extends "openPopupForCards"
                                                    ? { opened: boolean }
                                                    : /** Unlock-prompt (2026-08-12): the same one-call honesty as the card twin. */
                                                      T extends "openPopupForSave"
                                                      ? { opened: boolean }
                                                      : /** Security review 2026-10: the search-all hand-off, same one-call honesty. */
                                                        T extends "openPopupForSearch"
                                                        ? { opened: boolean }
                                                        : never;

/** SW → content (chrome.tabs.sendMessage): fill this item now (popup-granted). The
 *  content script performs its normal `reveal` round-trip with its own host — the SW
 *  honors it via the one-shot grant, keeping a single secret-egress path. Cut M (v2 #14):
 *  the receiver answers a FillOutcome via sendResponse, which the SW relays to the popup. */
export type TabMsg =
  | { type: "fillItem"; itemId: string }
  /** SW → content: (re-)offer the tab's pending save banner (e.g. after navigation). */
  | { type: "offerPendingSave"; pending: PendingSave }
  /** SW → content frame 0 (unlock-prompt, 2026-08-12): the approved pending save the user
   *  clicked Save on while locked just LANDED on unlock — show the confirmation toast. Sent
   *  ONLY when a write actually happened (a 2a-suppress commits silently: toasting "saved"
   *  over nothing-written would be a lie). Carries nothing — the sentence lives content-side
   *  (errors-canon rule: the SW never ships user-facing text). */
  | { type: "pendingSaveCommitted" }
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
  | { type: "rescanCardForms" }
  /** SW → content frame 0 (C1 [S4b] repair nudge): re-send `pageInfo` NOW. `pageInfo` fires once at
   *  content init, so the SW's recorded `topOrigin` — the chip gate's and the V4 badge's ONLY
   *  origin source — is unrecoverable after an MV3 idle-death or a lock's `tabs.clear()` erase.
   *  Sent (rate-limited, ≤1/tab/2 s) exactly when the gate fails for a MISSING record, never on a
   *  refusal: a real cross-origin/stale-origin answer must not be retried into existence. Carries
   *  no payload and needs no answer — the repair rides the frame's own `pageInfo` round-trip. */
  | { type: "reportPageInfo" };

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
