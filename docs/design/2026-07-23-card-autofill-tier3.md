# Card autofill Tier 3 — Android split-PAN, i18n, radio card-type, discovery badge (design)

**Status: BREAKER-VETTED 2026-07-23 — 3 lenses (security/egress+scope, correctness/regression,
parity/platform/gate), verdict GO-WITH-AMENDMENTS ×3; all binding amendments [W1]–[W14] folded
below.** Tier 3 of the 2026-07-23 audit is NOT homogeneous — the audit itself split it. This
tier BUILDS four safe, egress-neutral, self-contained lanes (V1–V4); the security-posture and
vault-scope items stay DESIGN-ONLY (§5), gated behind owner ratification / their own breaker
pass. On top of Tier 1 (`4ded308`) + Tier 2 (`2abb0a3`). Versions unbumped. Nothing in V1–V4
changes the S3 egress contract, and only V4 touches the toolbar action (no new permission).

Amendment log: [W1] split-PAN ineligible-multibox fallback = FIRST box only, rest suppressed
(core re-created the full-PAN-into-every-box bug + diverged from shipped ext) · [W2] split
chunk-planning is a SHARED both-engine vector (not parallel single-consumer — lockstep vacuity)
· [W3] ASCII-fold is a shared explicit char→STRING digraph table, NO runtime NFD (NFD forks on
ß/ø/æ/œ and can't emit the German ue/oe/ae the shipped vocab needs) · [W4] ext folds at the
`cardKindFromTokens` chokepoint, NOT inside shared `tokens()` (which feeds isCvvNameOrId →
suppressSave, a login-capture verdict); core may fold at tokens() (card-only call sites) · [W5]
localized months = FULL NAMES ONLY for de/fr/es/pt/it/nl (abbreviations deferred — the collision
surface), authored folded, matched post-fold; committed collision test vs all listed locales +
en + same-locale · [W6] fold applied inside the month-name pass before firstLetterRun · [W7]
radios re-scope [T1]: formlessGroups partitions on LOGIN-ELIGIBILITY, not `instanceof
HTMLInputElement` · [W8] radios get a dedicated collect arm (never login `classify()`) +
cardtype-ONLY classifier · [W9] radio fill = new "radio" target tag, `.checked` write +
`.checked` verify, NEVER `setValue`/text `verifyLanded` (that path falsely reports filled) ·
[W10] radio group enumerated from the CardForm's own refs, never document-wide by `name` · [W11]
radio filled LAST (synthetic click fires PAGE listeners → may submit/navigate/detach; card-DATA
egress stays neutral) · [W12] N radio refs collapse to one group fill · [W13] Kotlin
tables-equality de-vacuified (nested map flattened to composite keys; per-lane non-vacuity
feature cases) · [W14] V2a gets the Tier-2-style zero-flip urimatch sweep (folded CSC term can
newly demote); V4 badge added (audit-recommended, permission-free).

## Why the split (unchanged from the vetted draft)

- **Safe mechanical (BUILD, V1–V4):** Android split-PAN parity gap (Tier 2 §10); i18n
  classification (ASCII-fold + localized month names, audit F6); radio card-type; a per-tab
  discovery badge (audit §6 — the one discovery affordance that is permission- and egress-free).
- **Security-posture (GATED, §5):** cross-origin PSP fill (fills a THIRD-PARTY origin); L8
  save-card capture (amends the S3 metadata-only pin). Owner ratification / own breaker gate.
- **Vault-scope (GATED, §5):** billing ZIP (expands what the vault stores).
- **Un-buildable here:** F20 compat-mode trace (needs a device).

## V1 — Android split-PAN leg (closes the Tier-2 §10 parity gap)

Core `CardFill.plan` (CardFill.kt:96) gives every CC_NUMBER field the full PAN via `textFor`.
Mirror the extension's chunk-PLANNING (`cardfill.ts` `splitPan`) into core; Android has no
read-back so the verify half (`verifySplitPanLanded`) stays ext-only.

- **Shared pure helper [W2]:** extract `CardNormalize.splitPanChunks(pan, maxLengths):
  List<String>?` in core, byte-mirroring ext `splitPan(pan, maxLengths): string[] | null` —
  sequential digit chunks when boxes>1 AND every `maxLength ∈ 1..8` AND `Σ maxLength ≥ PAN
  digits`; box_i ← next maxLength_i digits, final box a short remainder; else null. Both engines
  assert this against ONE shared `splitPan` vector section (the read-back verify is the only
  ext-only piece).
- **`plan()` pre-pass**, per frame cluster, AFTER the anchor gate (CardFill.kt:98-101, so
  hostile-iframe zero-fill holds): collect the cluster's CC_NUMBER fields with `autofillType ==
  TEXT` (a LIST/DATE CC_NUMBER is never a PAN box → falls to its own skip). If >1 and
  `splitPanChunks` returns non-null → emit `Planned(index, Text(chunk))` for each NON-EMPTY
  chunk (an empty trailing chunk emits nothing), and **exclude every one of those boxes from the
  subsequent `planField` loop**. **[W1] If >1 CC_NUMBER TEXT box but the split is ineligible
  (undeclared maxLength), fill the FIRST such box only (whole-PAN, fit-guarded) and suppress
  `planField` for the rest** — never full-PAN-into-every-box (the bug V1 exists to kill; matches
  ext `content.ts` panBoxes[0]-only). A single CC_NUMBER box is unchanged.
- **[W2] Vectors:** shared `splitPan` (chunk arrays: 4-4-4-4/16, 4-6-5/15 Amex, short remainder
  [W-NOTE: 4×maxLen-4 over 15 digits = 4-4-4-**3**, NOT empty; an empty trailing chunk needs
  all-but-last capacity ≥ digits, e.g. [8,8,8]/15 → box3=""], single-box → whole PAN, mixed
  declared/undeclared → null). Core-only `splitPanPlan` pins the plan() integration: the
  ineligible-2-undeclared-box case (box0 filled, box1 SKIPPED — [W1]) and a multi-cluster case
  (hostile 2nd frame, lone split box → zero-fill, per-cluster after the anchor gate). Non-vacuity:
  a fit-guard-would-miss-but-splitter-fills case reds if the pre-pass is removed.

## V2 — i18n classification (audit F6)

### V2a — ASCII-fold (shared digraph table [W3][W4])

Today `tokens()` treats non-ASCII as a separator, so "Prüfnummer" → `[pr, fnummer]` and the
shipped German keyword `pruefnummer` never matches. **The fold is a shared explicit char→STRING
table (NOT `normalize("NFD")`)** — NFD forks: it leaves ß/ø/æ/œ/ł/đ/ı undecomposed (JS keeps
them; a hand table would fold them → divergence) AND it emits `ü→u`, which cannot reach the
shipped `ue/oe/ae` German vocab. The table:

```
German digraphs (REQUIRED for gueltigbis/pruefnummer/kartenpruefnummer):
  ß→ss  ä→ae Ä→ae  ö→oe Ö→oe  ü→ue Ü→ue
Non-decomposable Latin (decided EXPLICITLY, both engines identical — never left to NFD):
  æ→ae  œ→oe  ø→o  ð→d  þ→th  ł→l  đ→d
Accented (single-letter): à â á ã å ā→a · ç ć č→c · é è ê ë ē→e · í î ï ì ī→i · ñ ń→n ·
  ó ô õ ò ō→o · ú û ù ū→u · ý ÿ→y   (uppercase forms map identically; everything else passes)
```
Both engines compile the SAME table (JS drops NFD entirely — parity by construction). Applied:
- **ext [W4]: at the `cardKindFromTokens` chokepoint (detect.ts:189), NOT inside `tokens()`** —
  `tokens()` also feeds `isCvvNameOrId` → `buildLoginForm.suppressSave` (a login-capture
  verdict); folding there would change it. Covered card-path callers: `classifyCardField`
  name+id, `classifyCardSelect` name+id, `cardKindFromLabels` per-source-string, the V3 radio
  classifier. `demoteCsc`/`isCvvNameOrId` are deliberately NOT folded (shared with suppressSave).
- **core:** `tokens()`'s only call sites are the card steps 2+4, so core folds inside `tokens()`
  (or an equivalent card-path chokepoint); `legacyClassify`'s substring `in nameId` stays
  byte-identical → login verdicts unchanged. **[W14] Run the Tier-2 §1.4 zero-flip sweep**
  (classify/classifyCard/classifyCardFreeRegression) — a folded accented CSC term newly demoting
  a password is a legacy-verdict touch; pin the intended result, keep the fold off legacyClassify.
- **[W3] Vector `tables.asciiFold`** (char→string), asserted by BOTH engines over an input set =
  (every char the table maps) ∪ (the non-decomposables ß ø æ œ ł đ ð þ ı İ) ∪ (the accented
  chars in the de/fr/es/pt/it/nl vocab) — the non-decomposables are the pin that reds a
  `ø→o`-style fork.
- **Honest scope:** the fold reaches accented SINGLE tokens (German compounds "Prüfnummer",
  "Kartennummer", the run "Gültig"+"bis" → `gueltig`+`bis` = `gueltigbis`) and accented name/id
  attributes. It does NOT reach multi-word Romance LABELS ("Numéro **de** carte" → the `de`
  breaks the contiguous run) — connector-token skipping is a deliberate future item, not this
  tier.

### V2b — localized month-name select matching [W5][W6]

Tier 1 [T3] made non-en month lists a safe miss (en-only, letter-run EQUALITY — the fi
`marraskuu` guard). V2b adds FULL month names (abbreviations DEFERRED — the collision surface)
for de/fr/es/pt/it/nl, authored in the FOLDED alphabet — folded with the SAME asciiFold table
the matcher applies, so German umlauts take the digraph form (März→`maerz`, NOT `marz`; the
option string and the table entry must fold identically or nothing matches):
- `tables.monthNamesByLocale` (locale → 12 folded full names), both engines assert.
- Match: in the month-name pass ONLY, ASCII-fold the option string before `firstLetterRun`
  (passes 1–2 stay on the raw option so digit lists are unaffected [W6]); month M matches iff
  the folded first letter-run EQUALS a full name in ANY listed locale. Pass-major [T2] and
  numeric-first ordering preserved; `listIndexFor`/`selectIndexFor` consult all locales' full
  names in the single name pass.
- **[W5] COMMITTED collision test** (Kotlin + TS, not a scratch check): after the fold, assert
  no (locale, month) full name equals a DIFFERENT month's full name in ANY listed locale, its
  OWN locale, OR the Tier-1 en table. (Correctness-verified today: de/fr/es/pt/it/nl full names
  have zero cross-month collisions — every near-match is a same-month cognate; the test guards
  future locale edits.)

## V3 — Radio-button card-type (extension-only)

Some checkouts present the brand as a radio group. Android needs NOTHING (a native `RadioGroup`
is `AUTOFILL_TYPE_LIST` → existing `listIndexFor` CC_TYPE; a bare `RadioButton` is
`AUTOFILL_TYPE_TOGGLE` → `planField` `else→null`, safe skip). Extension:

- **[W8] `collect()` dedicated radio arm** (before the `NON_FILLABLE_TYPES` skip): a radio is
  collected ONLY when a cardtype-ONLY classifier (name/id/label tokens or `cc-type` hint, tighter
  than SELECT_CARD_KINDS — a `cardMonth`/`expiryYear` radio must NOT classify) yields `cardtype`.
  It NEVER calls the login `classify()` (hard `kind:"none"`, `textLike:false`) — else a
  `name=rememberLogin` radio would poison the login pool. A non-cardtype radio stays skipped.
- **[W7] `formlessGroups` re-scope:** partition the login-cluster pool on LOGIN-ELIGIBILITY
  (`input-backed AND (kind !== "none" || textLike)`), NOT `instanceof HTMLInputElement` — selects
  AND cardtype radios are the login-inert remainder, attached post-hoc by container. [T1]
  re-scoped to "login-inert-control-blind." Pin: a formless password beside a cardtype radio
  group groups byte-identically to today.
- **[W9][W10] Fill:** a new **"radio" target tag** (`cardTargetOf` returns it for
  `input.type==="radio"`), so a radio NEVER reaches `deriveCardWrite`/`setValue`/text
  `verifyLanded` (that path sets `.value` and falsely verifies "filled" on an unselected group).
  The radio branch builds synthetic options `[{value: radio.value, text: adjacentLabel}]` from
  **the CardForm's own collected cardtype refs for this group** (never a document-wide `name`
  re-query — a colliding name in another block must not be reached), reuses the pure
  `radioIndexFor(options, brand)` (factored into `cardfill.ts`, mirroring `selectIndexFor`,
  vector-pinned [T14]), then sets `group[i].checked = true` + dispatches `click`/`input`/`change`
  inside the `filling` bracket ([A6]-safe). `verifyLanded` for a radio = `winner.checked === true`.
- **[W11] Filled LAST** (after every text field): a synthetic `click` fires PAGE listeners (they
  don't require `isTrusted`) and runs the radio's default action — a brand-radio/ancestor handler
  may advance/submit/navigate/re-render and DETACH unfilled PAN/expiry inputs. Card-DATA egress
  stays neutral (brand only, [T9]-gated), but V3 is "card-data-egress-neutral, adds a
  synthetic-click surface." Pin: a radio whose click submits must not fire before PAN/expiry are
  written.
- **[W12]** N group members each classify cardtype → N refs; collapse to ONE group fill (dedupe
  at collect or executor) so the click fires once and sig churn is bounded.
- **Vectors:** ext `detect.cards` (radio→cardtype both directions — `radio name=shipping` → none)
  + `cardfill` `radioIndexFor` cases (value match, label match, no-match → no check).

## V4 — Per-tab discovery badge (audit §6; permission- and egress-free)

The audit recommended shipping data-free discovery now; the badge is the one G4 item that needs
no permission. When the active tab has an eligible same-origin card form recorded (the
`cardFillOffers` fillable signal, SW-derived from per-frame `sender.origin` — the same source as
`crossOriginFormsOnly`, zero card data), set a small `chrome.action` badge indicator so a
card-only page (no login match) is no longer silent. Cleared on navigation with the card
registry (the [A4] `onUpdated` "loading" handler) so a stale "card here" badge never persists.
Coexistence with the existing login-match badge is resolved in the build (login count takes
precedence if both apply; the card indicator shows only when there is no login badge) — the build
lane reads the current badge code and reports if a clean coexistence isn't available. No wire,
permission, or egress change.

## 5. GATED — design-only, NOT built this tier (recommended defaults recorded)

- **G1 — Cross-origin PSP iframe fill.** *Keep the exclusion; if pursued: per-frame one-shot
  grants bound to the **(top-origin, PSP-frame-origin) PAIR** against a short allowlist of known
  PSP origins, minted only from the popup, confirmation rendered in trusted chrome showing the
  **top origin the user recognizes** (attested `sender.origin` proves a frame is `js.stripe.com`,
  NOT that it is the user's merchant's Stripe account — a malicious merchant can embed a real
  Stripe iframe bound to the attacker's key; origin-allowlisting alone cannot tell the accounts
  apart).* Own breaker pass mandatory.
- **G2 — L8 save-card capture.** Design-only from Tier 2 §8 (submit-capture, never CVV,
  memory-only pending PAN dropped on lock, store-isolated, trusted-gesture-gated). Amends the S3
  metadata-only egress pin — own breaker pass.
- **G3 — Billing ZIP / postal.** *If pursued: ride `CardData.extras` (`postalCode` key, no
  formatVersion bump); a `cardpostal`/`cardzip` kind MUST be card-anchor-gated (fill only inside a
  form with a CC_NUMBER anchor, mirroring CVV/`suppressSave`) — never a name-token match anywhere,
  or it leaks the postal code off standalone shipping/newsletter zip fields.* Expands vault scope
  → owner call.
- **G4 — Context menu + keyboard command.** The badge ships (V4); `contextMenus` + `commands` are
  data-free but a MANIFEST PERMISSION BUMP = store re-review → bundle with the next
  permission-bearing release. A real in-page card PICKER stays rejected (popup-only grant held).

## 6. Un-buildable

F20 (compat-mode browsers) needs an on-device trace; documented, not built.

## 7. Gate + pins

- Vectors: `cardfill.json` — shared `splitPan`, core-only `splitPanPlan`, `tables.asciiFold`
  (both assert), `tables.monthNamesByLocale` (both assert), `radioIndexFor` cases;
  `cardform.json` — accented-label→cardnumber (reds if fold removed), localized-month fill (reds
  if locale tables removed), radio→cardtype + negative (radio name=shipping → none). urimatch.json
  — the [W14] fold sweep results if any flips. NO `card.json` change.
- **[W13] Kotlin tables-equality de-vacuified:** `tablesMatchTheNormativeVectorCopy`
  (CardFillVectorTest.kt:38-43) is a hand 1-level comparator — `monthAbbreviationsByLocale` is
  DEFERRED so it stays 1-level; `asciiFold` (char→str) and `monthNamesByLocale` (locale→list)
  extend the existing pattern; add a KEY-SET assert so a future vector table can't be added
  without a Kotlin mirror. Each new-table constant on `CardFill`/`FieldClassifier`.
- Tier-1/Tier-2 pins: cardnumber stays the SOLE anchor (V1 fills cardnumber boxes; V3 adds
  cardtype, a non-anchor; V2 is classification-only) → [U16] own-host, [U17] retarget, frame-0
  preference, [T9] brand double-gate untouched. Re-scope: **[T1]** (login-eligibility partition,
  [W7]), **[T15]** instanceof invariant (radios are login-inert inputs — the slot filters exclude
  by kind/textLike; the formlessGroups partition stops treating input-ness as login-ness),
  **[U8]/[T14]** tables assert ([W13]). Add pins: radio-never-`setValue` ([W9]), radio-filled-last
  ([W11]), V4 badge state, the V2a fold chokepoint (ext folds at cardKindFromTokens, not tokens()).
- verify.sh unchanged; full gate green before commit; release content.js re-checked (fold table +
  6-locale full-name tables + radio ≈ +2.5–4 KiB → ~42–43 KiB vs the 60 KiB cap).

## 7b. Review-fold record (2026-07-23, find→refute over the built diff)

24 confirmed findings folded (5 refuted, 0 verifier deaths). The load-bearing catch (HIGH,
found by three reviewers independently): the [W7] predicate as designed demoted MORE than the
enumerated remainder — tel/number-typed card inputs (kind none, textLike false, admitted to
collect() via cardKind alone) fell out of the formless clustering pool, splitting the shipped
password-CVV↔PAN clusters (no demotion, no CVV fill, [A7] save-suppression lost its anchor).
The design's formula was faithfully implemented and still wrong — fixed: the inert remainder
is EXACTLY selects + cardtype radios (`cardKind !== null && type !== "radio"` keeps every
other card input eligible), with a tel-PAN grouping pin. Also folded: the V4 badge read
`tab.url` outside the popup window (contradicting the pinned [A4] constraint even though the
broad host grant made it work) — rewired to the RECORDED top-frame `sender.origin` (pageInfo),
sync, cleared with the registry, and clearing the badge when locked; the [W5] collision test
gained the en ABBREVIATIONS in its universe, a fold-fixed-point assertion, and a TS mirror
(it was Kotlin-only); the shared `splitPan` vector pins single-box→null (the pure helper's
contract — the plan-level whole-PAN fill is the `splitPanPlan` pin, reconciled in §V1); the
[U6] label budget counts the FOLDED token stream; stale `_doc`/comment claims corrected.
Recorded deviations, accepted: [W9]'s "radio target tag" is implemented as `isRadioRef`
filtering ahead of `deriveCardWrite` (same invariant, pinned); [W14]'s "folded CSC term can
newly demote" is VACUOUS — `CSC_DEMOTION` is ASCII-only, so the fold cannot change step 2
(the zero-flip sweep pins it); the closing blur targets the last DATA field, with the radio
group firing after it (deliberate — the click is the radio's own commit); the core/ext
fold-placement divergence (tokens() vs cardKindFromTokens) was assessed honest three ways —
no realistic input diverges.

## 8. Out of scope (beyond Tier 3)

G1–G4 builds (each its own gate); F20; localized month ABBREVIATIONS ([W5] deferred);
connector-token Romance-label matching (the V2a limit); `attachShadow` retro-detection between
childList ticks; a real in-page card picker.
