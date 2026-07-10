# Extension in-page card fill (S3) — design

**Status:** draft → breakers. **Precondition being discharged:** the cards design
(2026-07-09) deferred in-page card fill behind "the frame-origin egress contract (grant
redeemable only by the frame that detected the card form, origin shown in the popup row)".
This doc IS that contract, made concrete.

## Honest scope

Same-origin card forms only. A card form is **eligible** iff it lives in a frame whose
origin equals the tab's **top-level origin** (exact origin equality — scheme+host+port; NOT
eTLD+1: cards are not uri-bound, so there is no saved-host relation to lean on; the gate is
structural). Cross-origin PSP iframes (Stripe Elements, Adyen, Braintree — a large share of
real checkouts) are **excluded by design** and keep today's copy-from-popup path; the popup
says so contextually ("this checkout embeds its card form — copy instead") rather than
showing a Fill button that silently does nothing. `about:blank`/`srcdoc` frames inherit
their creator's origin per spec, so a top-origin-created helper frame is genuinely eligible;
a sandboxed frame has an opaque origin (`"null"`) and is **never** eligible.

## The egress contract (normative)

Card data leaves the SW **only** through this sequence, one field-set per explicit user
action:

1. **Detection (per frame, passive):** `content.ts` classifies card forms with new
   card-field rules in `detect.ts` (token-bounded, mirroring core `CardForm` — `cc-*`
   autocomplete first-class, no substring `pan`/`exp`; the CVV-negative save rule is
   already live). It reports `{type:"cardFormInfo", fields:[kinds], host}` — **metadata
   only, never values**. The SW records per-tab: `{frameId, origin: sender.origin,
   fields}`; top-frame-only badge/state untouched.
2. **Offer (popup only):** the Cards group shows a **Fill** button on a card row iff the
   active tab has a recorded card form whose `origin` equals the tab's current top-level
   origin (computed SW-side from `chrome.tabs.get(tab).url`). The row shows that origin
   under the button — the user sees exactly where the card will go. No in-page card
   picker exists (the popup is the trusted surface; an in-page card UI would widen the
   egress surface for zero household benefit).
3. **Grant:** the click mints a one-shot grant `{tabId, itemId, frameId, origin, expires
   (30 s)}` — the login-grant machinery with two extra bindings (frameId + origin). The SW
   then sends `{type:"fillCard", itemId}` to **that frameId only**.
4. **Redemption:** the frame's content script round-trips `{type:"revealCardForFill",
   itemId}`. The SW verifies, in order: a live grant for (tabId, itemId); `sender.frameId
   === grant.frameId`; `sender.origin === grant.origin`; **and** `grant.origin` still
   equals the tab's *current* top-level origin (re-fetched — a navigation between click
   and redemption voids the fill). Any failure consumes nothing and answers
   `{ok:false}`; success consumes the grant and returns exactly the fields the detected
   form declared (number / expiry composed MM-YY per `CardNormalize` parity / name / CVV
   only if a CVV field was detected). Values go straight into the frame's inputs through
   the existing login-fill value-setter (framework-event compatible); nothing is logged,
   nothing persists, the content script holds values only inside the fill call.
5. **Locked vault:** no session → no Fill buttons (the popup already renders locked
   state); a grant cannot exist without an unlocked SW.

Trust model deltas vs the login path: the login `reveal` is gated on **host-match ∨
grant ∨ explicit**; card reveal has **no host relation** — it is *grant-only*, and the
grant carries strictly more binding (frameId + origin + top-origin recheck). Pages cannot
message the SW (no `externally_connectable`); a hostile cross-origin sub-frame can neither
receive `fillCard` (targeted frameId) nor redeem (origin + frameId mismatch); a hostile
SAME-origin sibling frame redeeming the grant gets only what the user explicitly sent to
that origin — same-origin is the browser's own trust boundary, we do not invent a finer one.

## Build shape

- `detect.ts`: card field kinds (`cardnumber`, `cardexpiry`, `cardexpmonth`, `cardexpyear`,
  `cardname`, `cardcvv`) via the autocomplete map + token rules; a form is a card form iff
  it has a number field. Consume the shared card-classify vectors where representable in
  DOM terms (extension harness — new `detect.cards.test.ts`).
- `messages.ts`: `cardFormInfo` (content→SW, metadata), `cardFillOffers` (popup→SW: which
  card rows may show Fill for the active tab + the origin string), `fillCardFromPopup`
  (popup→SW, mints grant), `revealCardForFill` (content→SW, redemption). Res types carry
  no secrets except the redemption's field payload.
- `background.ts`: per-tab card-form registry (cleared on nav/tab close alongside the
  existing tab state); the grant map gains the two bindings; `updateStatus`-style purity —
  the registry holds kinds + origin only.
- `content.ts`: fill executor reusing the login fill's input-setting; CVV filled last;
  form left unsubmitted (the user submits).
- Version ×3 → **0.9.0**, package (tests + content.js cap already gate), publish + manifest
  merge at the checkpoint. Web/Android/desktop untouched. CHANGELOG under Unreleased-ext.
- **IBAN/bank-account item type:** separate one-page scope addendum
  (`docs/assess/2026-07-iban-scope.md`), decision-only, parked for owner ratification.

## What the review must attack

The origin bindings (all five verification steps), the navigation race, opaque-origin
frames, the metadata-only claim on every new message, CVV egress rules, grant lifetime and
single-use, and whether the detection rules can misclassify a login form as a card form
(fill would then put a card number into a visible field — the CVV-negative precedent cuts
the other way here).
