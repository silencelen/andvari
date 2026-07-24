# Card autofill — GATED items G1–G4 (design + breaker verdict)

**Status: BREAKER-VETTED 2026-07-24 — 4 lenses (G1-PSP, G2-save-card, G3/G4, cross-cutting).**
Per-item verdict: **G1 = DO-NOT-BUILD (stays gated, structural); G2/G3/G4 =
BUILD-WITH-AMENDMENTS** (all [X*] amendments folded below). Owner ratified building the gated
items; the gate found G1 unbuildable and the other three buildable with binding changes.
On top of Tiers 1–3 (`4ded308`, `2abb0a3`, `c2ab855`).

**Build order (SEQ-N1): ONE version-bumped release train — G3 → G2 → G4.** G3 is the
widest-blast-radius/lowest-risk (cross-platform vault schema); G2 is the ext-only egress
addition; G4's permission change forces the store re-review that efficiently also covers G2's
egress amendment. Versions: extension trio 0.17.0 → **0.18.0** (G2+G4); fleet
(core/android/desktop/web) 0.19.1 → **0.20.0** (G3). Building + committing the code is this
session; the actual store/downloads/APK PUBLISH stays the owner's signed-hardware deploy step
(ops checklist §Release).

---

## G1 — Cross-origin PSP iframe fill — **DO-NOT-BUILD (stays gated)**

The breaker pass proved G1 has **no safe binding** — a structural impossibility, not a
patchable gap. Recorded so it is never re-attempted without new browser primitives:

- The attacker's `js.stripe.com` frame and the merchant's real one are **indistinguishable to
  the extension**: same attested `sender.origin`, same (top, psp) pair, same frame-id space;
  the only difference is the publishable key, which lives inside the frame's own JS and is
  invisible to any chrome/DOM API. `frameIds` distinguishes frames by browser id, never by
  merchant account (G1-B2, critical).
- The **exactly-one-frame ambiguity guard is defeated by suppress-and-replace**: an attacker
  with same-origin-to-top execution (XSS, or a same-origin widget) removes the merchant's real
  number iframe and injects one attacker-keyed `js.stripe.com` frame → count = 1 → the guard
  PASSES → the PAN fans out to the attacker's hidden frame → tokenized to the attacker's Stripe
  account, while the confirmation shows the trusted merchant origin (G1-B1, critical).
- The **threat bar is BELOW full XSS**: binding only to the TAB top origin (not the frame's
  parent chain) lets a `js.stripe.com` frame nested inside a malicious *embedded third-party
  widget* (an ad/analytics iframe the merchant legitimately includes) join the fan-out with no
  merchant compromise at all (G1-B3, high). PSP iframe isolation exists precisely to protect
  the PAN on a merchant page that embeds untrusted third parties; G1 removes that protection.
- The multi-frame same-PSP-origin fan-out is the NORMAL case (Stripe Elements = one iframe per
  field), so the ambiguous set is the default, not an edge.

**Copy-fallback (Tier 2 [U21] explainer) stays the PSP posture.** G1 is only buildable if a
future browser primitive lets the extension bind a fill to the specific frame the user's
interaction targeted, or attests the merchant account behind a PSP frame. Neither exists.

---

## G2 — Save-card capture (L8) — BUILD-WITH-AMENDMENTS

Content→SW card values at submit; the extension CREATES a card doc for the first time. Egress
bounded hard; every amendment binding.

- **Capture set:** `{number, expMonth, expYear, cardholderName, postalCode?}` — **NEVER the
  CVV** (write-only from the vault). Read from the frame's OWN detected card inputs.
- **[X2-A2] SW-side same-origin gate (content can't know the top origin).** The content script
  runs in ALL frames, so a Stripe/Braintree per-field NUMBER iframe (`js.stripe.com`, a
  single number input = a "card form") could emit `captureCard{number}` — a bogus partial-PAN
  save. The content script cannot enforce same-origin (top origin is SW-side only). **The SW
  `captureCard` handler discards any capture whose `sender.origin !== topOrigin(tabId)`** — a
  cross-origin/PSP frame never drives a save.
- **[X2-A3][X2-A4b] Trusted one-shot gesture, SEPARATE from the login submit wiring.** Capture
  fires on an `isTrusted` click of a submit-like control or `isTrusted` keydown-Enter (NOT the
  login `captureNow` submit listener, which is deliberately un-`isTrusted`-gated for
  `requestSubmit()`). A `lastTrustedGestureConsumed` flag makes it one-shot per gesture; a
  kept submit-event path fires ONLY when an unconsumed trusted gesture is <1 s old AND consumes
  it immediately (never a free 1 s window). Our own fill events are `!isTrusted` → never
  self-capture.
- **[X2-A1] `pendingCardSave` is a MODULE-SCOPE `Map`, NEVER a `TabState` field.** `persistTabs`
  (background.ts:1006-1008) serializes the ENTIRE tabs map to `storage.session` on every state
  change — a `TabState.pendingCardSave` would write the PAN at rest across a lock (the exact
  [iii] hazard). Declared beside `cardGrants`:
  `Map<number, {host, number, expMonth, expYear, cardholderName, postalCode?, frameId, updatesItemId?}>`.
  The full PAN lives ONLY here, SW-side.
- **[X2-A2b] Explicit clears — never rely on `ensureLoaded`.** `pendingCardSave.clear()` in
  `doLock` beside `cardGrants.clear()` (bg:1046); `pendingCardSave.delete(tabId)` in the
  `onUpdated` `"loading"` handler beside `cardGrants.delete(tabId)` (bg:891) and in `onRemoved`
  (bg:915).
- **[X2-A4] Single-slot per tab (anti-spam).** A new capture REPLACES, never queues — at most
  one "Save this card?" offer per tab regardless of PAN variation. The one-shot gesture gate is
  the sole spam guarantee; the dedupe key is recorded SYNCHRONOUSLY before any `await` in the
  handler ([X2-A5], so a click+submit double-fire can't both pass).
- **[X2-A5b] UPDATE spreads the existing doc AND card — never a fresh object.**
  `{ ...existing.doc, card: { ...existing.doc.card, expMonth, expYear, cardholderName } }`
  (number = the matched digits). `securityCode` is neither read from capture nor written — the
  stored CVV and any unknown keys survive. Match = `digitsOnly(number)` equality to an existing
  card.
- **[X2-A6] `CARD_FORMAT_VERSION = 2` (new in format.ts).** New-card seal floors at it (NOT
  `putNewLogin`'s LOGIN_FORMAT_VERSION); update floors at `Math.max(CARD_FORMAT_VERSION,
  target.formatVersion)` via a card-aware seal path (not the login `putExisting`, whose
  "never writes card docs" invariant G2 lifts — revise its comment + pin together).
- **[X2-A7] Masked public shape.** `publicPendingCard(p)` → `{host, cardSubtitle,
  updatesItemId?, updatesItemName?}` ONLY; `messages.ts PendingCardSave` OMITS `number`; the
  banner shows `cardSubtitle` ("Visa ••4242"). The raw PAN never leaves the SW (pinned like the
  [A9] egress anchors — the card-save banner message body contains no raw-PAN field).
- **[X2-N2] Luhn gate** = a NEW `card.ts` leaf (`luhnValid`, `CardNormalize` parity) — the ext
  ships no Luhn today; content-side gate before `captureCard`.
- **[v] A7 preserved** ([X2-N1] confirmed independent): the login capture stays suppressed on
  card forms; the card banner replaces the (already-suppressed) login banner.

## G3 — Billing ZIP / postal — BUILD-WITH-AMENDMENTS

A typed `postalCode: String?` on `CardData` — serializer-verified cross-version-safe ([X3-N1]:
`ExtrasOverlaySerializer` round-trips it; every card writer spreads/`copy()`; 0.2.x can't
touch fv2). No formatVersion bump. Fill kind `cardpostal` / core `CC_POSTAL`, but the audit's
"anchor-gated like CVV" is NOT sufficient — the binding rules:

- **[X3-A1] (i) Shipping-suppressor guard** (per-string, [T10] gift-guard shape, both engines):
  a `cardpostal` verdict whose producing string's tokens also whole-run-match `{ship, shipping,
  delivery, deliver, recipient, lieferung, liefer, livraison, envio, spedizione}` is suppressed
  to `none` (terminal for that string) — billing zip must never fill/overwrite a shipping zip
  on a mixed single-form checkout. **(ii) Fail-closed on ambiguity:** if MORE than one field in
  the anchored form (ext) / frame cluster (core) survives as CC_POSTAL, fill NONE and do not
  declare the postal kind. Tokens: `billingzip, billingpostal, cardpostal, cardzip, avszip,
  postalcode` (prefixed billing* forms win; bare `postalcode` only in the anchored gap).
- **[X3-A2] No postal AUTOFILL HINT, either engine.** CC_POSTAL is name/id/label TOKEN-RUN only;
  NO entry in core `CARD_HINTS` (FieldClassifier.kt:68), ext `CARD_HINTS` (detect.ts:70), or
  `AUTOCOMPLETE_HINT_MAP`; `NEGATIVE_HINTS` stay byte-identical on all three. Shared vector:
  `autocomplete="postal-code"` inside an anchored card form → NOT cardpostal (accepted safe
  miss — the hint is ambiguous billing-vs-shipping).
- **[X3-A3] `cardpostal` is login-INERT in `formlessGroups`** (the [W7] inert remainder, like
  selects/cardtype-radios — never needed for PAN-CVV cohesion), attaching post-formation by
  container. Pin: a card-free formless page (username+password+nearby `postal_code`) groups
  IDENTICALLY before/after G3 (login bit-identity at the grouping level, not just the verdict).
- **[X3-A4] Force the four silent-gap sites** (adding CC_POSTAL breaks NO compile check — that's
  the hazard): (a) refactor `isCardKind` to an exhaustive `when(this)` (no `else`) so the enum
  addition is compile-forced; (b) replace the `!` at detect.ts:104 with a lookup that THROWS at
  module init on an unmapped vector kind; (c) a CC_POSTAL fill leg in `cardfill.json` consumed
  by BOTH engines (`textFor` + `deriveCardWrite` fit-guard) so a missing core branch reds
  CardFillVectorTest; (d) `revealCardForFill` gains `declared.has("cardpostal")` composition.
- Editors + copy: web/desktop/android card editors gain a postal field; copy parity.
- Login bit-identity pins: urimatch.json standalone-`postalcode`-stays-NEGATIVE_HINT;
  cardform.json postal-without-PAN-anchor → not CC_POSTAL, shipping-suppressor, ambiguity.

## G4 — Context menu + keyboard command — BUILD-WITH-AMENDMENTS

Data-free discovery; both merely OPEN the popup (no in-page picker, no new egress).

- **[X4-A1] `commands` is a top-level KEY, not a permission** — the permission delta is
  `contextMenus` ONLY. manifest.json + manifest.firefox.json: add `"contextMenus"` to
  `permissions`; add a top-level `"commands": {"_execute_action": {"description": "Open
  andvari"}}` (default unbound; user assigns in chrome://extensions/shortcuts). NO named
  fallback command (redundant with `_execute_action`). Manifest-diff pin: contextMenus in
  permissions, commands as a KEY, nothing else changed.
- **[X4-A2] `chrome.action.openPopup()` needs a real degrade.** Bump `minimum_chrome_version`
  to `"127"` in the same release (Chrome 127 auto-holds updates from older browsers, killing
  the degrade path) OR wrap `openPopup` in try/catch with an explicit NO-OP. **FORBID
  `tabs.create`/`windows.create` of popup.html** — the popup computes offers against the ACTIVE
  tab; opened as a tab it would see itself and break the sole-grant-surface assumption.
- **[X4-A3] Idempotent menu registration** at every background load (top-level, not
  onInstalled-only — Chrome/Firefox event-page persistence differs): `contextMenus.removeAll()`
  then `create({id, title: "andvari", contexts: ["editable"]})`; `onClicked` → `openPopup()`.
  ([X4-N1]: `contexts:["editable"]` carries no page CONTENT, but note it widens the SW's
  wake surface — acceptable.)

## Release train + gate + pins

- **[X4-A4] Version bumps** (verify.sh + version.test.ts + package.mjs enforce these):
  extension **manifest.json + manifest.firefox.json + package.json → 0.18.0** (package.mjs);
  fleet **core AndvariApi ANDVARI_CLIENT_VERSION + android versionName + desktop packageVersion
  + web client.ts → 0.20.0** (verify.sh version-consistency). `minimum_chrome_version` → 127.
- **Pins:** new `psp.ts` is NOT built (G1 gated). G2: the `pendingCardSave`-is-a-module-Map +
  masked-public-shape + no-raw-PAN-in-banner + SW-same-origin-gate + CARD_FORMAT_VERSION source
  anchors (no runtime harness). G3: shipping-suppressor + ambiguity + login-bit-identity vector
  cases; the isCardKind-exhaustive-when + detect.ts-throws + both-engine-fill-leg
  non-vacuity. G4: manifest-diff pin. All Tier-1/2/3 pins preserved.
- verify.sh unchanged (it already gates every touched suite + version consistency); full gate
  green before commit; release content.js re-checked (G2 capture + Luhn leaf + G3 postal ≈
  +2–3 KiB → ~44 KiB vs the 60 KiB cap).
- **Ops checklist (owner deploy, OUTSIDE the gate — the release the campaign deferred):**
  AMO-sign the Firefox xpi + append `firefox-updates.json`; merge the `browserExtension` entry
  into the server `/downloads` manifest; enqueue the Chrome zip via the cws-push-queue; build +
  publish the fleet 0.20.0 (APK with a fresh `ANDVARI_VERSIONCODE`, deb/MSI signed on PRESTIGE);
  the two new permissions trigger a Chrome/AMO re-review — release notes state both are
  "open andvari from the page/keyboard; neither reads page content."

## Review-fold record (2026-07-24, find→refute over the G2/G3/G4 build diff)

5 confirmed findings, **all LOW, 0 critical/high, 0 verifier deaths** — the G2 egress amendment
held. The 4 REFUTED were exactly the security concerns worth raising (the dedupe key holding
the PAN, cross-scope capture from an unrelated submit, a standalone postal classifying as
cardpostal, a banner-window PAN leak) — all checked and cleared. Folded: the Android
`winningSignal` diagnostic label now names `refine:postal-promotion` vs `refine:csc-demotion`;
the [X3-A1](ii) ambiguity fail-close extracted to a shared exported `postalIsAmbiguous` so the
production `buildCardForm` line and the pure test share ONE count predicate (no hand-mirror);
`openPopup` gained `?.catch(() => {})` for the present-but-rejecting degrade; the stale
`putNewLogin` "only ever creates logins" comment updated for G2's card seal. Three Tier-2/3
pins tripped and were re-scoped deliberately (the tripwire working): [U12]'s span end-anchor
tightened to the G2 boundary (the sig-match-only security assertion intact), [U17] 4→5 for the
G2 capture keydown, [W7] gained the `cardpostal` inert clause.

## Non-goals (still)

G1 (no safe binding); configurable PSP origins; capturing the CVV on save; storing a full
billing ADDRESS (only the postal code); a real in-page card picker; localized-month
abbreviations (Tier 3 [W5]).
