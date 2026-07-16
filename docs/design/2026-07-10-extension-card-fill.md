# Extension in-page card fill (S3) — design

**Status:** **BREAKER-VETTED 2026-07-13 — verdict GO-WITH-AMENDMENTS; build-ready next
session.** All ten binding amendments from the breaker pass are folded into the body below
(marked **[A1]**…**[A10]**); per-amendment dispositions in the final section. Residual
accepted risk: "user clicks Fill on a hostile same-origin top page" is the explicit-pick
trust model the login path already ships. **Precondition being discharged:** the cards
design (2026-07-09) deferred in-page card fill behind "the frame-origin egress contract
(grant redeemable only by the frame that detected the card form, origin shown in the popup
row)". This doc IS that contract, made concrete.

## Honest scope

Same-origin card forms only. A card form is **eligible** iff it lives in a frame whose
origin equals the tab's **top-level origin** (exact origin equality — scheme+host+port; NOT
eTLD+1: cards are not uri-bound, so there is no saved-host relation to lean on; the gate is
structural). Cross-origin PSP iframes (Stripe Elements, Adyen, Braintree — a large share of
real checkouts) are **excluded by design** and keep today's copy-from-popup path; the popup
says so contextually ("this checkout embeds its card form — copy instead") rather than
showing a Fill button that silently does nothing.

**[A1]** `about:blank`/`srcdoc` frames inherit their creator's origin per spec, but they
are **UNSUPPORTED here regardless**: the content script's init gate —
`if (location.hostname !== "") init();` at the foot of `content.ts` — never runs in
empty-hostname frames, so a card form in such a helper frame is never detected and never
fillable (fail-closed). An earlier draft called top-origin-created helper frames "genuinely
eligible"; the code contradicts that claim, and the code wins. S3 keeps the init gate
unchanged. Loosening it to reach those frames would be net-new attack surface this review
has NOT cleared — it requires hostile-parent fixtures as its own reviewed change. A
sandboxed frame has an opaque origin (`"null"`) and is **never** eligible.

## The egress contract (normative)

Card data leaves the SW **only** through this sequence, one field-set per explicit user
action:

1. **Detection (per frame, passive):** `content.ts` classifies card forms with new
   card-field rules in `detect.ts` (token-bounded, mirroring core `CardForm` — `cc-*`
   autocomplete first-class, no substring `pan`/`exp`; the CVV-negative save rule is
   already live). It reports `{type:"cardFormInfo", fields:[kinds]}` — **metadata only,
   never values, and [A2] no page-controlled `host` field**. The frame's identity binds
   exclusively to browser-set `sender.origin`, recorded SW-side; a `msg.host` would be a
   spoofable input for zero benefit — a hostile sub-frame could send `host=legit-top` to
   manufacture an offer. Every later comparison (offer eligibility, `grant.origin`, both
   redemption origin checks) uses that recorded `sender.origin`, and the host string the
   popup displays is derived from it SW-side. The SW records per-tab
   `{frameId, origin: sender.origin, fields}`; top-frame-only badge/state untouched.
2. **Offer (popup only):** the Cards group shows a **Fill** button on a card row iff the
   active tab has a recorded card form whose `origin` equals the tab's current top-level
   origin (computed SW-side from `chrome.tabs.get(tab).url`). The row shows that origin
   under the button — the user sees exactly where the card will go. No in-page card
   picker exists (the popup is the trusted surface; an in-page card UI would widen the
   egress surface for zero household benefit). **[A4]** `tab.url` is readable here under
   **`activeTab` alone**, granted by the popup being open — `activeTabHost()` in
   `popup.ts` already reads `tab.url` this way today; the manifest deliberately has **no
   `tabs` permission** (`permissions: storage/activeTab/alarms/offscreen`,
   `host_permissions` server-only). Pinned hard constraint: any future change that needs
   `tab.url` OUTSIDE the popup-open→redemption window requires the `tabs` permission = a
   permission bump = a re-review of this contract.
3. **Grant:** the click mints a one-shot grant `{tabId, itemId, frameId, origin, expires
   (30 s)}` — the login-grant *pattern* with two extra bindings (frameId + origin), but
   **[A5] held in a store SEPARATE from the login `grants` map**. That map is
   `Map<tabId, {itemId, expiresMs}>` — single-slot per tab — so sharing it would let a
   card grant clobber a live login grant (and vice-versa) and let one path's redemption
   consume the other's. Use a separate store (or a composite key with a `kind`
   discriminant) and a **distinct redemption handler** (`revealCardForFill`) that only
   ever matches `doc.type === "card"` — the login `reveal()` must never consume a card
   grant, nor the reverse. The SW then sends `{type:"fillCard", itemId}` to **that
   frameId only**.
4. **Redemption:** the frame's content script round-trips `{type:"revealCardForFill",
   itemId}`. The SW verifies, in order: a live *card* grant for (tabId, itemId);
   `sender.frameId === grant.frameId`; `sender.origin === grant.origin`; **and**
   `grant.origin` still equals the tab's *current* top-level origin (re-fetched — a
   navigation between click and redemption voids the fill; **[A4]** the re-fetch reads
   `tab.url` under the same per-tab `activeTab` window, and a test asserts the recheck
   actually reads the URL). **[A3]** Every check **fails CLOSED on undefined**: S3 is the
   extension's FIRST reliance on `sender.origin` (zero uses in `extension/src` today;
   manifest floors are Chrome 109 / Firefox 121), so — `sender.origin` undefined →
   refuse; `sender.frameId` undefined → refuse; `chrome.tabs.get(tabId).url` empty or
   unreadable → refuse. `undefined === undefined` must never pass, a missing URL is never
   a match, and a fixture asserts each refusal individually. Any failure consumes nothing
   and answers `{ok:false}`; success consumes the grant and returns exactly the fields
   the detected form declared (number / expiry composed MM-YY per `CardNormalize` parity
   / name / CVV only if a CVV field was detected). Values go straight into the frame's
   inputs through the existing login-fill value-setter (framework-event compatible);
   nothing is logged, nothing persists, the content script holds values only inside the
   fill call.
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
  it has a number field. **[A8]** Card kinds fire only in the `legacy == NONE` gap —
  parity with core `FieldClassifier`, whose card-keyword fallback "fires ONLY in the
  legacy==NONE gap" — so existing login verdicts stay bit-identical. Consume the shared
  card-classify vectors where representable in DOM terms (extension harness — new
  `detect.cards.test.ts`).
- **[A7] Card classification MUST gate the CAPTURE/SAVE path, not just fill.** Confirmed
  latent bug in shipped 0.13.0: the extension's `CVV_TOKENS = ["cvv","cvc","csc"]`
  (`detect.ts`) is narrower than core `CSC_DEMOTION` (which adds `securitycode`,
  `cardverification`), and `suppressSave` fires only for a lone password whose name/id
  passes `isCvvNameOrId` — so a same-doc checkout with `<input type="password"
  name="securityCode">` beside a text `cardnumber` field yields `suppressSave = false`,
  and capture offers to SAVE PAN-as-username + CVV-as-password. S3's card rules fix this
  ONLY if a form classified as a card form (it has a CC-number field) is **excluded from
  the login capture/save path** — extend `suppressSave` into a formKind gate. Explicit
  build requirement + fixture; without it, adding card kinds shifts capture behavior
  unpredictably.
- `messages.ts`: `cardFormInfo` (content→SW, metadata, **[A2] no `host` member**),
  `cardFillOffers` (popup→SW: which card rows may show Fill for the active tab + the
  SW-derived origin string), `fillCardFromPopup` (popup→SW, mints grant),
  `revealCardForFill` (content→SW, redemption). Res types carry no secrets except the
  redemption's field payload. The popup-only card messages keep the existing popup-sender
  guard shape (`sender.tab !== undefined → refuse`, as `background.ts` does today for
  popup-only paths) so a page can never invoke minting or offer enumeration.
- `background.ts`: per-tab card-form registry (cleared on nav/tab close alongside the
  existing tab state); **[A5]** the card-grant store is separate from `grants` (see
  §Egress step 3) with its own redemption function; `updateStatus`-style purity — the
  registry holds kinds + origin only.
- `content.ts`: fill executor reusing the login fill's input-setting (`setValue`); CVV
  filled last; form left unsubmitted (the user submits). **[A6] The card executor MUST
  NOT call `updateSnapshot` or touch `snapshots`.** `fillForm` deliberately calls
  `updateSnapshot(live)` to feed the SAVE engine (its synthetic events are `!isTrusted`,
  which the capture listeners ignore, so it feeds the engine directly); reusing that
  wiring would put PAN/CVV into the `snapshots` WeakMap and make them save-bannerable.
  Revealed card fields stay strictly function-local (mirroring `fillForm`'s `s`
  parameter), used synchronously, never stored module-scope, never snapshotted —
  fill-once, no persist, implicitly cleared with the call frame.
- **[A9] Egress pins in `web/src/extension-pins.test.ts`** (source-substring anchors in
  the style of the existing `adItem(` pins — no extension harness needed) for the most
  safety-critical new lines: `sender.frameId === grant.frameId`; `sender.origin ===
  grant.origin`; the top-origin re-fetch; the one-shot grant delete; and the
  `sender.tab !== undefined → refuse` guard on the new popup-only card messages. Also:
  the existing pin `isCvvNameOrId("securityCode") === false` was written to break when
  `detect.ts` gains full CSC demotion (its comment already says the fuller set "arrives
  with the deferred in-page card-fill slice") — update it deliberately as part of [A7],
  not as collateral.
- **[A10] Byte budget — non-issue; keep the gate.** `CONTENT_JS_CAP = 60 KB` in
  `extension/package.mjs`, content.js ~20.5 KB today; card classification reuses the
  existing `tokens`/`tokenMatch` plus a small hint/keyword map and the fill executor —
  comfortably under cap. Requirement: card detection imports NO background-only module
  (`psl.ts` / the PSL blob) — the cap already enforces this; keep the import graph clean
  and the gate on.
- Version ×3 → next ext minor (manifest is at 0.13.0 as of this pass — the draft's
  "0.9.0" target predates four shipped cuts), package (tests + content.js cap already
  gate), publish + manifest merge at the checkpoint. Web/Android/desktop untouched except
  the [A9] pins file. CHANGELOG under Unreleased-ext.
- **IBAN/bank-account item type:** separate one-page scope addendum
  (`docs/assess/2026-07-iban-scope.md`), decision-only, parked for owner ratification.

## What the review must attack

The origin bindings (all five verification steps — **each fail-closed-on-undefined case
individually, [A3]**), the navigation race, opaque-origin frames, the metadata-only claim
on every new message, CVV egress rules, grant lifetime and single-use, **grant-store
isolation ([A5]: login-grant clobber and cross-redemption in both directions)**, **the
capture/save gate for card forms ([A7])**, and **misclassification in both directions
([A8])**: (a) a pure login form (username+password) must NEVER surface a card Fill offer;
(b) a card form must never route PAN into a non-CC field. Hostile/edge fixtures: a login
field named `cardnumber`, a coupon field named like a PAN, cardholder-name-as-username,
and the [A7] bug shape (`<input type="password" name="securityCode">` beside a text
`cardnumber` field). The CVV-negative precedent cuts the other way here: misclassifying a
login form as a card form would put a card number into a visible field.

## Breaker pass 2026-07-13 — verdicts and dispositions

**Verdict: GO-WITH-AMENDMENTS** — build S3 next session. The core frame-origin egress
contract (grant bound to frameId + `sender.origin` + top-origin recheck, popup-only
trusted UI, no `externally_connectable`) is fundamentally sound: a hostile cross-origin
injected iframe can neither receive `fillCard` (targeted frameId) nor redeem (origin +
frameId mismatch, all fail-closed), and the nav race is covered by the redemption-time
re-fetch. No amendment is a NO-GO; the residual "user clicks Fill on a hostile
same-origin top page" risk is the explicit-pick trust model the login path already ships.

**Pinned as-designed (do not weaken):**

- **R1** — the fill offer lives in the popup (browser chrome), not in-page →
  unspoofable/unclickjackable; the origin shown is browser-provided `tab.url`, never
  page-controlled. Feasible today: `activeTabHost()` in `popup.ts` already reads `tab.url`
  under `activeTab`.
- **R2** — grant-only (no host relation), one-shot, 30 s, targeted to ONE frameId. This
  generalizes (rather than copies) the login grant's frame-0-only binding — the
  `isTopFrame` gate in `reveal()` (`background.ts`) — so a same-origin sub-frame card form
  keeps eligibility while every other frame still cannot redeem.
- **R3** — the same-origin-as-top EXACT-origin gate (not eTLD+1) is the right call for
  non-uri-bound cards.
- **R4** — no in-page card picker → card fill never opens an in-page Enter/dropdown
  surface, so the `dropdownWillConsumeEnter` seam (`content-ui.ts`) is NOT reopened; the
  synthetic `setValue` events are `!isTrusted`, which the capture listeners in
  `content.ts` already ignore.

**Amendment dispositions** (all ten BINDING; each folded into the body above):

| # | Disposition (one line) | Folded into |
|---|---|---|
| A1 | about:blank/srcdoc "genuinely eligible" claim STRUCK — the init gate (`location.hostname !== ""`) makes empty-hostname frames unreachable; keep the gate unchanged, document them UNSUPPORTED | §Honest scope |
| A2 | Frame identity binds to browser-set `sender.origin` ONLY; page-controlled `host` dropped from `cardFormInfo`; display host derived SW-side | §Egress step 1; §Build `messages.ts` |
| A3 | Every redemption check fails CLOSED on undefined (`sender.origin`, `sender.frameId`, `tab.url`) — first-ever `sender.origin` reliance in the extension; fixture per refusal | §Egress step 4; §Attack |
| A4 | The `activeTab`-only `tab.url` dependency is documented + pinned: needing `tab.url` outside the popup-open→redemption window = `tabs` permission bump = re-review; test the recheck reads the URL and fails closed | §Egress steps 2 + 4 |
| A5 | Card grants get a SEPARATE store (login `grants` is single-slot per tabId) + a distinct `revealCardForFill` matching `doc.type === "card"` only — no clobber, no cross-redemption | §Egress step 3; §Build `background.ts`; §Attack |
| A6 | The card fill executor never calls `updateSnapshot` / touches `snapshots` — PAN/CVV stay function-local and can never become save-bannerable | §Build `content.ts` |
| A7 | Card-form classification gates CAPTURE/SAVE (formKind extends `suppressSave`) — fixes the confirmed 0.13.0 latent PAN/CVV-save bug (`securityCode` sits outside ext `CVV_TOKENS` but inside core `CSC_DEMOTION`) | §Build `detect.ts` (own bullet); §Attack |
| A8 | Misclassification fixtures BOTH directions; card kinds fire only in the `legacy == NONE` gap (core `FieldClassifier` parity) so login verdicts stay bit-identical | §Build `detect.ts`; §Attack |
| A9 | Five egress pins added to `web/src/extension-pins.test.ts` (frameId check, origin check, top-origin re-fetch, one-shot delete, popup-sender guard); the `isCvvNameOrId("securityCode")===false` pin breaks BY DESIGN with A7 — update it deliberately | §Build pins bullet |
| A10 | Byte budget non-issue — keep the `CONTENT_JS_CAP` gate; card detection must import no background-only module (PSL) | §Build byte-budget bullet |

**Non-blocking (framing kept as-is):** a hostile SAME-origin sibling frame redeeming the
grant gets only what the user explicitly sent to that origin, and same-origin XSS stays
out of scope — the browser's own trust boundary; no finer one is invented.

## Post-build review follow-up (2026-07-15 find→refute, LOW — documented, not fixed)

The `Fill → <origin>` **label** cached in the popup (`popup.ts loadUnlocked`) can go stale if
the tab performs a full same-tab *navigation* while the popup stays open (the design only ruled
out an active-tab *change*, not a same-tab nav). **Egress is unaffected** — `fillCardFromPopup`
re-derives the live top origin and re-filters eligible frames, and `revealCardForFill` re-checks
`sender.origin`/`sender.frameId`/live-top-origin, so a card can only ever fill into the tab's
*current* top-origin same-origin frame; only the *displayed* origin can lag. Low exploitability
(a legitimate site won't self-navigate to an attacker origin), so this is deferred rather than
fixed now. If tightened later (R1's "the user sees exactly where the card will go" premise): have
the popup re-query `tab.url` on `chrome.tabs.onUpdated` for its active tab, or re-derive the label
at render time, and clear the offer if the origin changed.
