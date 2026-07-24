# Card autofill Tier 2 — signals, multi-form, shadow DOM, fill fidelity, platform parity (design)

**Status: BREAKER-VETTED 2026-07-23 — 3 lenses (egress/security, correctness/regression,
parity/platform/gate), verdict GO-WITH-AMENDMENTS ×3; all binding amendments [U1]–[U22]
folded into the body.** Implements Tier 2 of the 2026-07-23 audit (§6) on top of Tier 1
(shipped `4ded308`): F6, F12, F14, F15, F17, F18, F21, F22, F24, F25, F32, F34 + tokenizer
alignment. **L8 (save-card capture) stays DESIGN-ONLY — it amends the S3 metadata-only
egress pin and must not be built until its own breaker pass.** Standing rules: S3 egress
intact for L1–L7 (`cardFormInfo` stays KINDS-only; labels/options/maxlength are frame-local
control metadata), login verdict bit-identity except the TWO deliberate, vectored changes
(§1.4 demotion widening — swept: ZERO urimatch flips; §3 shadow login enablement), versions
unbumped, every Tier-1 pin preserved (survival map in §9).

Amendment log (breaker pass): [U1] `creditcard` → trailing lowest-priority group (bare-name
only — `credit_card_cvv` etc. must NOT collapse to PAN) · [U2] drop
`securitynumber`/`verificationnumber` (SSN/OTP false positives) · [U3] drop `cid` (run-match
hits `c_id`) · [U4] drop bare `expires`; `holdername`/`titular` kept as documented
collateral · [U5] label sources classified PER-STRING, never concatenated · [U6] label
bounds + cache · [U7] `el.labels`/getRootNode mechanics; label-poisoning accepted +
vectored · [U8] ordered `[ {kind, keywords} ]` vector encoding, both engines assert
sequence equality · [U9] core tokenizer gains the digit boundary at its two card call
sites · [U10] vocab-sweep pins added · [U11] frame-0 preference RESTORED (richest-form only
within the chosen frame) · [U12] sig-mismatch ABORTS (no index fallback) · [U13]
collision-free registry sig · [U14] [A3] extended to sig/kinds; old persisted shape
discarded · [U15] declared = grant.kinds, pinned · [U16] shadow sweep on childList ticks
only; caps keep partial results; per-root observers, hard cap · [U17] retargeting covers
focusin/click/input/keydown; submit + activeElement are documented residuals · [U18]
empty-only re-assert; event-order source pin · [U19] split-PAN concatenation verify;
fit-guard governs the fallback; Android split gap named · [U20] dataset headroom
eligibility-gated + pure-factored · [U21] neutral explainer copy; re-query diffs the flag ·
[U22] Android editor warning accepts parseable combined input.

## 1. L1 — Label/placeholder/aria signals + vocabulary + tokenizer alignment (F6/F22)

### 1.1 The label signal (extension)

`collect()` gathers, per field (input AND select), the label SOURCE STRINGS — `aria-label`
attr · `el.labels` texts (native: covers `<label for>` and wrapping labels, root-scoped —
never `document.querySelector`, which is wrong under shadow scoping and id escaping [U7]) ·
each `aria-labelledby` id resolved via `el.getRootNode().getElementById` (one string per
target, listed order) · `placeholder`. **[U5] Each source string is classified SEPARATELY —
per-string tokenization, per-string verdict, per-string [T10] gift guard, first card verdict
wins. Concatenation is FORBIDDEN: a token run must never span a source boundary**
(aria-label "Rewards card" + placeholder "Number of points" would otherwise fabricate a
`cardnumber` run). **[U6] Bounds: a source string longer than 60 chars or 8 tokens is
IGNORED** (help-sentence labels over-match — "…cannot be combined with card number
payments"); label extraction is cached per element in a WeakMap invalidated per sweep
generation (a form-sized wrapping label must not cost O(subtree) per field per tick).

Classification order per field (card path only, in the `classify()==none` gap): autocomplete
hints → name tokens → id tokens → **label source strings (weakest, last, in the order
above)**. Selects: same, through `classifyCardSelect` (which gains the label param — [U11
parity note]). The label strings NEVER leave the content script ([A2]: the wire stays
kinds-only under the §2 forms array — verified against `classify()`'s signal surface, which
structurally cannot see labels).

**Accepted + vectored [U7]:** `<label for>`/`aria-labelledby` legitimately cross subtree
boundaries, so a distant (or attacker-authored, same-origin) label can make an in-gap text
field on a login page classify `cardnumber` — the form then gains a card Fill offer and A7
save-suppression. This is same-origin misclassification with NO cross-origin egress (fill
still requires the explicit popup pick), accepted; a vector pins the exact behavior so it is
a choice, not an accident.

### 1.2 Core + Android lockstep (F22)

Core `FieldSignal` += `labelText: String? = null` (appended LAST; all construction sites are
named-arg — re-verified post-Tier-1). Core carries ONE label string (Android has one:
`ViewNode.hint`, read NOWHERE today — grep-verified; `signalOf` never reads a placeholder
attr, so no double-feed). `classify()` step 4 adds the label pass after the id retry, same
gap/type restrictions, per-string terminality. `StructureParser` feeds `hint` as labelText.
`CardVectorSupport.vectorFieldSignal` += labelText (omission fails loud). Ablation
`winningSignal` gains no label leg (label-won fields report "combined" on the status screen
— accepted, diagnostic-only).

### 1.3 Vocabulary widening (ONE normative ordered list)

The keyword groups become **[U8] an ORDERED array of `{kind, keywords}` pairs** whose
normative copy lives in `cardfill.json` `tables.keywords`; group order is load-bearing
(month/year before generic exp — and the [U1] trailing group below). **Both engines assert
SEQUENCE equality** (kinds AND order AND contents): core `CARD_NAME_KINDS` goes
`private`→`internal` with a list-equality assert in `CardFillVectorTest` (the existing
per-key tables assert would stay silently green — the vacuity trap); ext's table MOVES into
`cardfill.ts` `TABLES.keywords` (detect.ts imports it) so the existing whole-object
`deepEqual` covers it.

Additions (whole-token-run; every cut below is a breaker finding, not taste):

- number: `ccno, kartennummer, kreditkartennummer, numerocarte, numerotarjeta, numerocartao`
- cvv: `cvn, cardcode, xcardcode, verificationvalue, cardverificationcode,
  cardverificationvalue, cryptogramme, pruefnummer, kartenpruefnummer, codigoseguridad`
  — **[U2] `securitynumber`/`verificationnumber` DROPPED** (run-match captures
  `social_security_number`, `phone_verification_number`; pinned as `none` vectors);
  **[U3] `cid` DROPPED** (run-match makes `cid` == `c`+`id` — `c_id` customer-id fields)
- expiry: `expiredate, expirydate, validthru, validthrough, goodthru, goodthrough,
  validuntil, ablaufdatum, gueltigbis, dateexpiration, vencimiento` — **[U4] bare `expires`
  DROPPED** (`session_expires`/`offer_expires`)
- exp-month: `expirymonth, cardmonth`; exp-year: `expiryyear, cardyear`
- name: `holdername, cardholdername, cardholdersname, titulaire, titular, karteninhaber` —
  `holdername`/`titular` matching `account_holder_name` (ACH blocks) is documented accepted
  collateral (name-into-name, harm ≈ 0)
- **[U1] `creditcard` rides a NEW TRAILING group `{kind: cardnumber}` appended AFTER every
  other group (including cardtype)** — it fires only when no specific kind matched, so
  `credit_card` (bare) → number while `credit_card_cvv/…_expiry/…_type/…_holder_name` keep
  their specific verdicts (negative vectors pin all four; without this ~50 `credit_card_*`
  composites collapse to PAN, mis-arm the split-PAN pre-pass, and poison richest-form
  counting).

ASCII only. (Correction [F7-correctness]: the "non-ASCII as separators" rationale is
ext-only — core tokens() is Unicode-letter-aware; outcome for ASCII vocab is identical.)
i18n number tokens get i18n gift suppressors: `GIFT_SUPPRESSORS` += `cadeau, geschenk,
regalo` (else `numeroCarteCadeau` anchors).

### 1.4 Tokenizer alignment (swept)

Core's `tokens()` gains the letter↔digit boundary. Call-site enumeration (verified): exactly
two — steps 2 (CSC demotion) and 4 (card keywords + gift guard) via `toks`/`idToks`;
`legacyClassify` is substring-based and untouched; the old glued tokenizer then has ZERO
callers and is deleted (no dead "kept for login" fiction). **Sweep executed by two
independent breakers: ZERO flips across urimatch.json (classify 22 / classifyCard 52 /
classifyCardFreeRegression 24); exactly ONE cardform flip — the Tier-1 divergence case
(`cardNumber2` → `cc-number`, formKind → `card`), which is the alignment working.** Pin
updates: that cardform case (name + expected + formKind), the detect.ts `tokens()` doc
comment (divergence paragraph → parity), the detect.cards.test.ts comment. **[U10] New
classifyCard vectors, each RED on today's tree:** `expiry_year → cc-exp-year`,
`expiry_month → cc-exp-month` (vocab), `htmlType:password nameOrId:cvv2 → cc-csc` (the
demotion widening — the ONE legacy-verdict change, protective), `htmlType:tel
cardNumber2 → cc-number` (alignment). Residual recorded: an anchorless lone `cvv2` password
still diverges (core demotes field-locally; ext only form-level) — pre-existing seam, parity
pins must not claim otherwise.

## 2. L2 — Multi-form + frame targeting (F12)

- Wire: `cardFormInfo` becomes `{ forms: CardFieldKind[][] }` (all card forms per frame,
  document order, kinds only). Registry per frame: `{ origin, forms }`. **[U13] idempotence
  sig = `JSON.stringify(forms)`** (a `join(",")` over nested arrays would alias
  `[[a,b]]` ≡ `[[a],[b]]` and swallow structural changes). **[U14] the SW discards a
  persisted pre-update `{fields}` record shape on read (fail-closed; rescan restores).**
- **[U11] Frame choice: frameId 0 wins whenever it holds ANY eligible form (Tier-1 rule,
  unchanged — a same-origin sub-frame must never out-bid the visible top checkout by
  kind-count); only when frame 0 has none, the richest eligible sub-frame (tie → lowest
  frameId). Richest-FORM selection (most distinct kinds; tie → first in document order)
  applies WITHIN the chosen frame.** Pinned (frame-0 preference anchor).
- The grant stores the chosen form's **kinds array + kind-signature** (`kinds.join(",")` —
  single-level, unambiguous). `fillCard` carries the signature. **[U12] The content script
  fills the FIRST form (document order) whose current signature equals the grant's; NO
  match → abort `no_form` — never an index fallback** (kinds drift only when the form
  structurally changed; filling a changed form is "wrong beats nothing"). Identical-sig
  twins: document-order-first, accepted + documented (a reorder among identical-sig forms is
  a harmless retarget). **[U14] [A3] extension: undefined/missing sig or kinds at any check
  → refuse.** **[U15] `revealCardForFill`'s declared-kinds gating reads `grant.kinds`**
  (never a frame union — a union could satisfy [T9]'s cardnumber+cardtype gate across TWO
  forms and compose `brand` for a PAN-less form; pinned). Bonus closed: the Tier-1 live
  registry read let a mint→redeem rescan widen egress; grant-frozen kinds end that.

## 3. L3 — Shadow DOM (F14)

- Root discovery via TreeWalker + `chrome.dom.openOrClosedShadowRoot(el)` /
  `el.openOrClosedShadowRoot` / `el.shadowRoot`, recursive. Caps: depth ≤ 8, roots ≤ 64
  (document order, first-64), visited ≤ 20k — **[U16] per sweep; hitting a cap stops
  DISCOVERY but keeps everything found**. **The sweep runs only on childList-bearing ticks**
  (attribute toggles cannot create shadow roots; attribute ticks reuse the cached root
  list — else the walk is ~130k API calls/s worst case). `attachShadow`-on-existing-element
  stays invisible until the next childList tick — accepted residual.
- `scanForms()`/`reportCardForm()` iterate `[document, …roots]`. **[U16] One observer per
  root** (childList + the attribute filter — the pinned literal `attributeFilter: ["class",
  "style", "hidden"]` must survive verbatim), hard-capped at 64 live, reconciled per sweep:
  observers whose root's host left the DOM are disconnected (per-observer disconnect — a
  shared observer has no per-root unobserve).
- **[U17] Retargeting: `e.composedPath()[0]` replaces `e.target` in FOUR paths — focusin,
  click-reopen, the input listener (snapshot capture), and the keydown Enter-capture** (all
  currently `instanceof`-gated on the retargeted host, silently dead for shadow fields).
  DOCUMENTED RESIDUALS: the `submit` listener (submit does not compose — shadow form
  submits stay uncaptured) and the mutation auto-open's `document.activeElement` (= host).
  Scope claims, honest: OPEN-shadow logins gain dropdown + fill + input-capture;
  CLOSED-shadow gets popup-driven fill only (composedPath truncates at closed boundaries —
  the extension's own dropdown host relies on exactly that, content-ui dismiss logic
  verified safe). **Pin: shadow-free pages are byte-identical** (roots = [document];
  `composedPath()[0] === e.target` in light DOM).

## 4. L4 — Fill event fidelity + split PAN (F17/F18)

- `setValue` (shared with login fill, DELIBERATE — the fidelity gap bites logins too;
  Bitwarden ships the same pattern): focus → `keydown` → native write → `input`
  (insertReplacementText) → `keyup` → `change`. Key events carry no key identity. **[U18]
  NO blind re-assert; ONE re-assert only when the read-back is EMPTY** (a masker's reformat
  is success under [T7] canonical verify; a masker that re-clears after the single re-assert
  ends as a truthful miss — accepted residual). Documented: synthetic untrusted keystrokes
  are a new page-visible signal on login sites (fraud heuristics — Bitwarden precedent);
  capture stays `isTrusted`-gated so our own events never self-trigger it; the Enter-capture
  is keyed to a trusted `Enter` and cannot fire from these. Verified: no existing test/pin
  asserts the old event order — the new event-order pin (source-regex in extension-pins;
  content.ts is not node-testable) is the first.
- Card path only: after the last write (CVV-last kept), dispatch `blur` + `focusout` on the
  last-written field, **inside the `filling` bracket** (before the `finally` reset).
- Split PAN (F18), `applyCardFill` pre-pass: >1 `cardnumber` INPUT → if every box declares
  maxLength 1..8 AND the sum ≥ PAN length → sequential digit chunks (final box may take a
  short remainder — 4-4-4-4 and Amex 4-6-5 fall out). **[U19] Verify the CONCATENATION of
  all boxes' digitsOnly against the full PAN (per-box chunk equality as the fast path)** —
  auto-advance maskers redistribute digits across boxes. Otherwise (some box lacks
  maxLength): the whole-PAN write goes to the FIRST box and **the fit-guard governs** (a
  declared-but-insufficient box set nulls the write → truthful miss; the fallback is only
  reachable for undeclared-maxLength shapes). §10 records the Android gap: `CardFill.plan`
  still fills every CC_NUMBER field with the full PAN — the Android split leg is Tier 3.

## 5. L5 — Android: DATE leg + dataset headroom (F21/F32)

- `AUTOFILL_TYPE_DATE = 4` (verified against AOSP View constants). `Value.DateMs(ms)` —
  sealed: the ONE exhaustive `when` (DatasetBuilder) stops compiling until it maps
  `AutofillValue.forDate` (good; assembleDebug gates it). CC_EXP only; epoch ms of
  (year, month, day 1) UTC via pure days-from-civil in core. Vector pins (computed):
  1970-01-01→0 · 2024-02-01→1706745600000 · 2027-02-01→1801440000000 ·
  2032-12-01→1985472000000 · 2000-03-01→951868800000 · 2099-12-01→4099766400000. Day-1
  semantics noted: a validator comparing against *today* mid-expiry-month may read it as
  past — industry convention, accepted.
- **[U20] Headroom (F32): reserve ONLY when the card path actually runs** — `ccFields`
  non-empty AND the browser trust gate passes AND ≥1 vault card plans non-empty. Mechanics:
  count buildable card datasets FIRST, then cap logins at
  `MAX_DATASETS - min(builtCards, 3)`; the reserve can never trim below what cards consume
  nor starve logins for zero cards. Factored pure
  (`internal fun loginDatasetCap(builtCards: Int): Int`) + unit-tested — framework `Dataset`
  can't be unit-constructed, so without the pure factoring this lane has no
  red-when-reverted test.
- F20 (compat-mode) stays device-gated, out of tier.

## 6. L6 — PSP explainer + copy parity (F15/F24)

- `cardFillOffers` += `crossOriginFormsOnly: boolean` — true iff the tab's registry holds
  ≥1 card form but NO frame is origin-eligible. Popup renders, in that state, **[U21]
  capability-framed NEUTRAL copy (never "this checkout…" — the signal is
  attacker-assertable by any embedded frame and must not vouch the page is a checkout):**
  "Andvari can't auto-fill payment forms embedded from another site. Use the copy buttons
  instead." **Pins: no Fill button ever renders in this state; the popup's delayed re-query
  diffs `crossOriginFormsOnly` too** (a late PSP-frame report must surface the explainer).
  Popup-trust argument, recorded: the boolean is SW-derived from browser-set per-frame
  `sender.origin` vs `topOrigin`, never crosses to a page, and is the same class of fact as
  "this tab has a login form" — acceptable metadata for trusted chrome. Fail-quiet caveat:
  un-granted pages never inject → signal false → no explainer (acceptable).
- Copy parity: popup gains cardholder-name copy (`revealCardField` union += `"name"` —
  additive: popup-only guard + `doc.type==="card"` gate verified; `CardItem` += `hasName`);
  web Vault card view + desktop + Android detail gain expiry copy (composeShortExpiry — the
  read-only/non-copy expiry rows become copy rows). End-state: every surface copies
  number/expiry/name/CVV.

## 7. L7 — Editor hardening + vector completion (F25/F34)

- Desktop + Android card editors: a month field containing a COMBINED expiry ("07/27",
  "07/2027") is parse-assisted via `parseExpiry` into both halves at save; a non-blank
  still-unparseable half BLOCKS the save with an inline message. Current-state corrections
  (verified): desktop already live-warns but drops (warns-but-drops, not silent); Android
  warns at MainActivity:2054 — **[U22] that warning's predicate must accept
  parseExpiry-parseable combined input** (else it lies mid-typing "07/27" that a part won't
  be saved while parse-assist will rescue it).
- `card.json` composeShortExpiry: only the half-blank/both-blank shapes are NEW (junk-month
  and 3-digit-year cases already exist — deduped).

## 8. L8 — Extension save-card capture (F30) — DESIGN-ONLY, breaker gate REQUIRED

Scope when built (NOT in this tier): capture `{number, expMonth, expYear, cardholderName}` —
NEVER the CVV — on card-form submission, Luhn-gated content-side, into a `pendingCardSave`,
offered via the top-frame banner, deduped against existing cards (match → expiry/name update
offer). Breaker-mandated build pins, folded now so the eventual pass inherits them: **(i)
capture gates on a RECENT TRUSTED user gesture** (the submit listener is deliberately not
isTrusted-gated for requestSubmit — a synthetic-submit storm must not drive capture), with
per-(host, PAN) dedupe against banner spam; **(ii) `pendingCardSave` holds the PAN in MEMORY
ONLY, dropped on lock and navigation — never an unencrypted PAN in storage.session across a
lock**; **(iii) it is a store SEPARATE from `snapshots`/`cardGrants` — L8 is the only new
card-value path and the L1–L7 [A6] no-snapshots pin stays intact; (iv) the login-credential
save path STAYS suppressed on card forms (the original A7 bug class) even as the card banner
replaces it.** Page-learns-nothing holds (captured values are the page's own; the risk
surface is the vault-side write path, which (i)–(iii) fence).

## 9. Gate + pins

- **Vectors:** `cardfill.json` — `tables.keywords` as the ORDERED groups array [U8]; NEW
  single-consumer sections `dateLeg` (core-only) and `splitPan` (ext-only) — the existing
  tsOnly flag has no inverse, so mixed sections would red the wrong engine. `cardform.json`
  — label-signal cases (label-only PAN/CVV/expiry, gift-label suppression per-string,
  label-vs-name precedence, the [U7] label-poisoned login-form case, per-string
  no-concatenation negative), the flipped alignment case, `labelText` in vectorFieldSignal.
  `urimatch.json` classifyCard — the [U10] four (each red today). Negative vocab vectors:
  `credit_card_cvv→cc-csc`, `credit_card_expiry→cc-exp`, `credit_card_type→cc-type`,
  `creditCardExpirationMonth→cc-exp-month`, `social_security_number→none`,
  `phone_verification_number→none`, `c_id→none`, `session_expires→none`. `card.json`
  half-blank composeShortExpiry.
- **Ext tests:** per-string label classification, bounds, cache; multi-form sig encode +
  first-sig-match + abort; split-PAN chunk table (4-4-4-4, 4-6-5, short remainder, missing
  maxLength → fit-guard); walker bounds (factored pure over stubs per detect.cards.test.ts
  conventions); richest-form chooser factored pure + exported (no bg harness exists).
- **extension-pins:** KEEP (lane obligations): grant redemption anchors, popup-only guards
  (first statement), [A4] onUpdated (`st.cardForms` name, `cardGrants.delete`), [T9] regex
  (variable stays `declared`, ONE `fields.brand =` site), `asCardFillOutcome` "partial",
  `lastCardSig` decl + rescan-order regex, `attributeFilter` literal, [A6] spans — **L2/L4
  helpers MUST be placed inside the existing span anchors (`cardTargetOf`→`maybeOpen`;
  `nativeValueSetter`→`let filling = false`) or the no-snapshots assertions silently lose
  coverage; `maybeOpen` must not be renamed.** ADD: frame-0 preference [U11]; grant-sig
  fail-closed + `grant.kinds` read [U12/U15]; `composedPath()[0]` in the four retargeted
  paths [U17]; empty-only re-assert + event order [U18]; `crossOriginFormsOnly` no-Fill
  [U21]; sig-encoding JSON.stringify [U13].
- **Core/Android tests:** CARD_NAME_KINDS internal + sequence-equality assert [U8];
  labelText in CardVectorSupport; `loginDatasetCap` unit test [U20]; dateLeg consumption;
  the [U10] urimatch consumers are the existing vector tests.
- **verify.sh unchanged** (confirmed — every touched suite already gated). Byte budget:
  estimated +5–8 KiB minified → ~41–44 KiB vs the 60 KiB cap (packaging-time gate; Tier-1
  release was 35.9 KiB) — re-verify at package; new content modules import no PSL ([A10]).

## 9b. Review-fold record (2026-07-23, find→refute over the built diff)

10 confirmed findings folded (5 refuted, 0 verifier deaths). The load-bearing catch: the L3
shadow sweep discovered the extension's OWN closed-shadow UI root (`chrome.dom` pierces closed
roots), observed it, and self-sustained a ~150 ms dropdown re-render loop in the multi-step
auto-open window — fixed with `isOwnUiHost` (content-ui.ts) excluded from the sweep +
`[U16]` own-host pin (no runtime test can see it — jsdom has no `chrome.dom`). Also:
split-PAN skips empty trailing chunks so the closing blur/[U18] re-assert aim at a written
box; `chooseCardTarget` never selects an empty form (a grant with no kinds fills nothing);
core `FieldSignal.labelText` records the deliberate un-bounded-hint choice ([U6] is an
ext-only scrape defense — a ViewNode hint is a short control hint); stale CardFill DATE-leg
and blur/[U18] comments corrected. The [U7] label-poisoned case is pinned `formKind: mixed`
(CardForm.refine returns MIXED for a card+login cluster — the field-level cc-number verdict
is what [U7] mandates; no refine-rule change).

## 10. Out of scope (Tier 3+)

L8 build (own breaker pass); Android compat-mode trace (F20); **Android split-PAN leg**
(CardFill.plan still whole-PAN-per-field — named per [U19]); in-page card prompt / badge /
context menu / shortcut; cross-origin PSP fill; ASCII-folding for accented labels;
radio-button card types; billing ZIP; localized month names beyond en; `attachShadow`
retro-detection between childList ticks; closed-shadow focus-driven dropdowns.
