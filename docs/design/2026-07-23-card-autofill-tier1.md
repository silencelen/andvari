# Card autofill Tier 1 — selects, card type, expiry adaptation, truthful fill (design)

**Status: BREAKER-VETTED 2026-07-23 — 3 lenses (egress/security, correctness/regression,
cross-platform parity), verdict GO-WITH-AMENDMENTS ×3; all binding amendments [T1]–[T16] are
folded into the body below.** Implements Tier 1 of the 2026-07-23 card autofill audit
(`2026-07-23-card-autofill-audit.md`): findings F1, F2, F3, F5, F7, F8, F9, F10, F11, F13,
F16, F28, F29 (+ the F19 month-name pass, pulled forward for lockstep). Everything stays
INSIDE the S3 egress contract (`2026-07-10-extension-card-fill.md`): detection reports remain
metadata-only (field kinds), values still leave the SW only through the one-shot
origin+frameId-bound `revealCardForFill` grant, the popup remains the sole offer surface.
Versions unbumped; ships with the next release train.

Amendment log: [T1] formless clustering counts inputs only (was: a shipped-CVV-fill
regression) · [T2] select matcher is PASS-major (core parity; option-major ships the
placeholder-outrank bug) · [T3] month-name = letter-run equality, never prefix (fi
`marraskuu` ≠ March) · [T4] rescan resets the sig (bfcache would defeat it) · [T5] popup
fast-path (no unconditional 250 ms) · [T6] broadcast `.catch` · [T7] canonical read-back
compare · [T8] selects write by INDEX · [T9] `brand` double-gated on cardnumber+cardtype ·
[T10] gift guard binds to the verdict-producing string · [T11] `"partial"` plumbed through
`asCardFillOutcome`/`fillCardRow` · [T12] core CSC demotion gains htmlId · [T13] core CC_TYPE
matching folds value+text passes · [T14] normative `tables` vector section + isCardKind
partition test · [T15] [A4]/[A6]/[A10] re-pins · [T16] separator sniff anchored; 7-char
placeholder-corroborated.

## 0. Invariants (unchanged, re-pinned)

- Login `classify()` verdicts stay bit-identical on every existing vector (urimatch.json
  classify + classifyCardFreeRegression). Card changes live only in the legacy==NONE gap.
- Login GROUPING stays bit-identical on card-free pages and on all `<form>`-owned groups
  ([T1] makes formless grouping input-blind to selects, see §1).
- `cardFormInfo` carries kinds only — never values, labels, options, or maxlengths.
- A card form requires a card-number anchor that is an **`<input>`** — a `<select>` can never
  anchor (nor be) a PAN/CVV/name field.
- Fit-guard philosophy everywhere: partial beats wrong; a value that cannot be represented
  faithfully in the target is skipped, never truncated. A read-back mismatch leaves the
  page's residue in place (never auto-clear — the field may hold user-typed data) and files
  the kind as missed.
- [A6] holds in the rewritten executor: the card fill path never calls `updateSnapshot` /
  touches `snapshots` — pinned by a source anchor ([T15], §11).
- [A4] holds: the new `tabs.onUpdated` handler reads ONLY `changeInfo.status` — never
  `changeInfo.url`/`tab.url` (pinned, [T15]). Precedent: the shipped `status === "complete"`
  listener (background.ts:853) already runs permission-less.
- [A10] byte budget: `cardfill.ts` + tables land in content.js (currently ~28.2 KiB of the
  60 KiB cap — refresh the stale "~20.5 KB" comments while there); `cardfill.ts` imports no
  background-only module (no PSL).
- No new permissions; manifest untouched.

## 1. Extension: `<select>` collection + classification (F1 detection half)

`detect.ts`:

- `collect()` queries `"input, select"`. Selects: skip `disabled`, `!isVisible`, and
  `select-multiple` (only `select-one` qualifies). `readOnly` stays input-gated (selects have
  no `readOnly`).
- `Field.input` widens to `FillableControl = HTMLInputElement | HTMLSelectElement` (property
  name stays `input`). `CardFormFieldRef.input` widens identically. **Narrowing mechanism
  [T15]: `LoginForm`'s username/password/newPasswords slots stay `HTMLInputElement`; every
  discharge is an `instanceof HTMLInputElement` guard (runtime-safe — selects are hard-set
  `kind:"none"` so they never reach those slots); `as HTMLInputElement` casts are FORBIDDEN
  in this lane** (a cast would compile a select into `setValue`, which throws).
- Selects NEVER enter the login pool: `kind` hard-set `"none"`, `textLike=false`,
  `isNewPassword=false` — `classify()` is not consulted for selects.
- **[T1] `formlessGroups` becomes select-blind at the clustering stage:** the per-password
  ancestor-climb early-stop (`contained.length > 1`) counts **input-backed Fields only**
  (`x.input instanceof HTMLInputElement`), so every shipped grouping decision is
  bit-identical. After the groups form, each select Field attaches to the FIRST group whose
  container `.contains()` it (document order), else the root leftover group. (Without this,
  a formless `<div><select expMonth><select expYear><input type=password cvv></div>` row
  next to a PAN row splits the cluster and kills the shipped CVV fill + demotion.)
- New `classifyCardSelect(nameOrId, htmlId, hints): CardFieldKind | null` — autocomplete
  hints first (same normalized `CARD_HINTS` map), then name/id token runs (§8 order) — but
  the verdict is **restricted to the select-meaningful kinds** `{cardexpmonth, cardexpyear,
  cardexpiry, cardtype}`; any other card verdict returns null. No `CARD_FALLBACK_HTML_TYPES`
  check (input vocabulary); no `classify()` gap-gate (a select is definitionally not a login
  credential).
- `fieldSignalOf` generalizes to both element kinds (autocomplete handling identical;
  `htmlType` for selects = `el.type`).

## 2. New kind: `cardtype` / `CC_TYPE` (F2)

- Ext `CardFieldKind` += `"cardtype"`. Core `FieldKind` += `CC_TYPE`; `isCardKind` += CC_TYPE
  (partition-tested, [T14] §11).
- Hints: `cc-type` normalizes to `cctype` → add to ext + core `CARD_HINTS`.
- Name/id tokens (whole-token-run, both engines): `cardtype, cctype, cardbrand, ccbrand,
  cbtype` — new group appended to `CARD_NAME_KINDS` (no run-overlap with existing groups).
- Value source is the **derived brand** (`brand(number)` / `CardNormalize.brand`), never a
  stored field. Text targets get `brandLabel(brand)` ("Visa"); selects/spinners get option
  matching (§4/§9). Unknown IIN → no brand → kind missed, never guessed.
- **[T9] Egress gate:** `brand` is composed in `revealCardForFill` ONLY inside
  `declared.has("cardtype") && declared.has("cardnumber")` — the zero-new-information
  argument (the same response already carries the PAN) must never depend on a future
  registry shape; pinned (§11). Android silent-skip inventory for a forgotten port:
  `textFor`/`listIndexFor`/`isCardKind` all degrade silently — hence the partition test +
  vector branches ([T14]).

## 3. Gift-card negative guard (F13)

In the **name/id token path only** (ext `classifyCardField`/`classifyCardSelect` + core
step 4): when a `cardnumber`/`CC_NUMBER` verdict is produced, evaluate the suppression set
`{gift, egift, voucher, loyalty, coupon}` **against the same token list (name OR id) that
produced the verdict** [T10] — a garbage `name="acct"` + `id="giftCardNumber"` must suppress
off the id tokens. Suppress-only and anchor-only: other kinds untouched; without an anchor
the form never qualifies. The autocomplete-hint path is NOT guarded (an explicit `cc-number`
hint is the site's own claim — Chromium parity). Noted shipped-behavior change: a
gift-card+password form regains the login save banner (pre-S3 behavior — the [A7]
suppression keyed off the now-suppressed anchor); deliberate.

## 4. Fill executor rewrite (F1 fill half, F7/F10/F11, F16, F19)

New **pure leaf module `extension/src/cardfill.ts`** (no chrome imports, node-tested), the TS
twin of core `CardFill`'s value layer:

- `monthTextFor(v, maxLength)`: canonical "MM"; `maxLength===1` → null.
- `yearTextFor(v, maxLength, placeholder)`: `maxLength===2` → YY; `maxLength===4` → YYYY;
  else placeholder mentions `yyyy` (case-ins) → YYYY, mentions `yy` → YY; default **YYYY**
  (core parity — a deliberate flip of the shipped always-YY slice) with fit-guard shrink to
  YY when 4 doesn't fit and 2 does.
- `expiryTextFor(v, maxLength, placeholder)` (combined targets; needs BOTH halves):
  maxLength 4 → `MMYY`; 5 → `MM<sep>YY`; 6 → `MMYYYY`; **7 → placeholder-corroborated
  [T16]: mentions `yyyy` → `MM<sep>YYYY`, mentions `yy` → `MM<sep>YY` (the 7-char " MM / YY "
  space-mask case), no placeholder → `MM/YYYY` (Chromium table)**; ≤3 → null; null/≥8 →
  placeholder sniff (`yyyy` → `MM<sep>YYYY`, else `MM<sep>YY`). **[T16] `<sep>` comes from an
  ANCHORED pattern `/m{1,2}\s*([-/.])\s*y/i` on the placeholder** (never a bare
  contains-check — "e.g. 12/28" must not select "."), default "/", honored in every
  separator-bearing branch.
- `numberTextFor` / `cvvTextFor` / `nameTextFor`: stored value (number digits-only) with the
  fit-guard (longer than declared maxLength → null, never truncate).
- `selectIndexFor(kind, options: {value,text}[], v): number | null` — core `listIndexFor`
  semantics on value+text DOM options. **[T2] PASS-MAJOR (core parity): passes 1→5 are the
  outer loop; within a pass, options in document order; within an option, `value` then
  `text`; the earliest pass with any match wins.** (Option-major would let a digit-bearing
  placeholder "Month (12)" outrank the real "12" row — core's `CardFillTest` pins exactly
  this.) Passes:
  1. whole-parse: `padMonth(x)===MM` / `yearTo4(x)===YYYY`;
  2. digit-extraction: `padMonth(digitsOnly(x))` / `yearTo4(digitsOnly(x))`;
  3. month-name (month kind only) **[T3]: extract the option's FIRST maximal ASCII-letter
     run (leading digits/punctuation skipped, lowercased); month M matches iff that run
     EQUALS fullName(M) or EQUALS an abbreviation of M — abbreviation set `jan feb mar apr
     may jun jul aug sep sept oct nov dec`. Prefix matching is FORBIDDEN (fi "marraskuu"
     starts with "mar" but is November — it must degrade to a safe miss; pinned as a
     negative vector).**
  4. combined `cardexpiry` selects: `digitsOnly(x)` equals `MMYY` or `MMYYYY`;
  5. `cardtype`: normalize (lowercase, strip non-alphanumerics) — exact-match against the
     brand's FULL synonym set (labels and value codes alike), else CONTAINS the brand's
     primary word. Synonyms (normative copy lives in the `tables` vector section, [T14]):
     visa `{visa, vi, v, 001}`; mastercard `{mastercard, mc, 002}`; amex `{amex,
     americanexpress, ax, amx, 003}`; discover `{discover, disc, di, 004}`. Contains-words:
     `visa`, `mastercard`, `americanexpress`, `amex`, `discover`.
- Option reading pinned [T8]: `opt.value` (the DOM's attr-absent→text fallback is wanted —
  it makes the value pass ≡ text pass on label-only options, which is what keeps the
  `shared` vector section coherent; those vectors encode options as single strings).
- `verifyLanded(kind, control, intended)` (F16): immediate read-back. **[T7] month/year/
  expiry compare CANONICALIZED (padMonth/yearTo4/parseExpiry of the read-back vs the
  intended halves)** — a masker auto-expanding "07/27"→"07/2027" or stripping a leading zero
  is a successful fill, while truncation ("07/20") still fails; number/cvv compare
  digitsOnly-equal; name/type text compare trimmed case-insensitive. Selects:
  `selectedIndex === chosen`. Accepted residual (documented): read-back is point-in-time — a
  framework revert after this tick goes unseen; a duplicate-value select that lands a
  different index files as missed (truthful, fail-safe).
- DOM notes for the content-side executor: `el.maxLength` is `-1` undeclared → null.
  **[T8] Selects are written BY INDEX via the native `HTMLSelectElement.prototype`
  `selectedIndex` setter** + the same composed `input`/`change` pair (React's change-event
  path for selects reads `target.value` at event time — no value-tracker dependency; a
  `.value` write would bind to the FIRST option with a duplicate value and trip the verify).
  Input writes stay on the existing `setValue`. CVV-last preserved; the `filling` flag
  brackets everything.

`content.ts` `applyCardFill` becomes: per field ref, derive the desired write from
`CardFillFields` + target metadata (adapters above); write; `verifyLanded`; accumulate.

## 5. Truthful outcome (F9)

`CardFillOutcome` becomes `{ filled: "card" | "partial" | "nothing", filledKinds:
CardFieldKind[], missedKinds: CardFieldKind[], code?: CardFillFailCode }` — `card` = every
declared kind landed; `partial` = both non-empty; `nothing` as today. A kind with no
derivable value (absent stored field, unparseable half, no option match, fit-guard skip,
read-back mismatch) lands in `missedKinds`. **[T11] `asCardFillOutcome`
(background.ts:2206) must explicitly accept `"partial"`** — as shipped it rejects unknown
shapes, which would turn every partial into `ok:false "unreachable"` AFTER the fields
already landed — **and `fillCardRow` (popup.ts:762) switches on `r.outcome.filled`, not
`r.ok`**: `"card"` → close (today's behavior); `"partial"` → popup STAYS OPEN with "Filled
number, name — couldn't fill expiry, card type. Copy instead:" (kind labels: number / expiry
[dedupe the three expiry kinds] / name on card / security code / card type) — the row's copy
buttons are already beneath it. Both pinned (§11).

## 6. `CardFillFields` v2 (F7/F10/F11 wire half)

```
{ number?, name?, cvv?,            // as today
  expMonth?,                       // canonical "MM" (padMonth), independent of year
  expYear2?, expYear4?,            // yearTo2/yearTo4 of the stored year, independent of month
  expiry?,                         // composed MM/YY (back-compat; popup copy path unchanged)
  brand? }                         // ONLY when cardtype AND cardnumber declared ([T9])
```
`revealCardForFill` composes halves **independently** (a parseable month with a junk year
still fills month-only targets). ext `card.ts`: **`yearTo4` must be WRITTEN (it does not
exist there), `padMonth` exported** — byte-parity with core `CardNormalize` /
web `vault/card.ts`, pinned against the existing `card.json` sections.

## 7. Rescan + registry hygiene (F8/F28)

- `content.ts`: `lastCardSig: string | null = null` — the first `reportCardForm` after
  injection ALWAYS sends, including empty (clears the SW's stale record for the new
  document). SW side [T4-adjacent]: when an empty report deletes nothing, skip the
  `persistTabs()` write (avoids a per-frame-per-navigation storage write).
- MutationObserver gains `attributes: true, attributeFilter: ["class", "style", "hidden"]`
  under the existing 150 ms debounce (CSS-toggle reveals re-scan; the sig guard stops
  redundant sends). Noted: the attribute path re-walks `findCardForms(document)` at most
  ~6×/s on animation-heavy pages — bounded, metadata-only.
- New tab message `{type:"rescanCardForms"}`: handler **[T4] resets `lastCardSig = null`
  FIRST** (bfcache restores JS state — without the reset, a back-navigation's rescan is
  swallowed by its own sig guard and the offer is lost for the document's life), drops
  `formsCache`, runs `reportCardForm()`, responds `{ok:true}`.
- SW **[T5], revised at review-fold**: `cardFillOffers` ALWAYS answers immediately off the
  registry and fires the broadcast — the original miss-path inline wait sat on the popup's
  critical path on every card-less open; the POPUP owns freshness with one delayed (~350 ms)
  re-query that re-renders when the offer state changed. `fillCardFromPopup` keeps a
  miss-path broadcast + 250 ms + re-read (grant minting needs the record NOW), and its HIT
  path fires NO background broadcast — a rescan racing the grant redemption could
  delete/replace the declared-kinds record between mint and redeem; the one-shot fill path
  has no "next query" to keep fresh (safer than the original [T5] letter; rationale
  in-source). **[T6] every broadcast carries `.catch(() => {})`** (`tabs.sendMessage`
  REJECTS on receiver-less tabs — chrome://, PDFs — on a large fraction of popup opens).
  Residual (documented): a frame busier than the re-query window shows no offer on that open.
- SW: `chrome.tabs.onUpdated` — on `changeInfo.status === "loading"`, delete that tab's
  `cardForms` and `cardGrants` entries. **Reads ONLY `changeInfo.status`** ([A4], pinned
  [T15]). bfcache back-navigations don't re-fire content init — the [T4] rescan reset is
  what restores the offer there. Subframe re-navigations are covered by the sentinel fix
  (the fresh frame's first report always sends).

## 8. name+id both-checked, card path only (F5/F29)

- Ext: `collect()` passes the element's `id` alongside; `classifyCardField(sig, htmlId?)` /
  `classifyCardSelect` run the token pass over `htmlNameOrId` first, then over `htmlId` when
  it produced no card verdict (gift guard evaluated per-string, [T10]). `fieldSignalOf` and
  the login path are byte-untouched. `demoteCsc` and the two `isCvvNameOrId` suppression
  call sites check name and id independently (suppression-side widening is fail-safe).
- Core: `FieldSignal` gains `htmlId: String? = null` — **appended LAST** (no positional
  constructions exist in-tree; verified). `classify()` step 4 retries the card keyword
  groups over `tokens(htmlId)` when the `htmlNameOrId` pass found nothing. **[T12] step 2
  (CSC demotion) also widens: demote when the CSC token-match fires on `htmlNameOrId` OR
  `htmlId`** — without this, `<input type=password name=field_7 id=cardCvc>` demotes on the
  extension but Android offers the vault password into the merchant's CVV box. Bit-identity
  holds: `htmlId` is null on every existing vector and pre-change call site. Steps 1 and 3
  untouched.
- Android `StructureParser`: `htmlNameOrId` stays `name ?: id ?: idEntry`; `htmlId` = the
  html `id` attr iff a `name` attr exists (else it already rode `htmlNameOrId`; an EMPTY
  `name=""` counts as existing — that's precisely the shadowing case, vectored §11).

## 9. Core `CardFill` (F7 + CC_TYPE + month names)

- `textFor(CC_EXP)` gains the maxLength table of §4 (4→MMYY, 5→MM/YY, 6→MMYYYY,
  7→MM/YYYY, ≤3→null, null/≥8→MM/YY); the existing final fit-guard stays as backstop.
  (Core has no placeholder signal — the placeholder-corroborated branches are ext-only;
  the shared vectors mark placeholder cases TS-only.)
- `textFor(CC_TYPE)` (TEXT nodes) = `brandLabel(CardNormalize.brand(number))`, fit-guarded.
- `listIndexFor` gains: **[T13] CC_TYPE branch = TS's value-pass and text-pass FOLDED over
  the single Android option string** (normalize → exact-match against the FULL synonym set
  including value codes like `001`, else contains-primary-word) — Android/WebView may expose
  either texts or values in `autofillOptions`, core cannot tell which; and the en month-name
  pass under the [T3] letter-run-equality rule (localized month lists degrade to a safe
  miss — never a wrong month).
- The synonym/month/abbreviation tables' NORMATIVE copy lives in `cardfill.json`'s `tables`
  section ([T14]); each engine asserts its compiled-in table EQUALS the vector's (one
  `assertEquals` core-side, one `deepEqual` ext-side) — drift on either side reds that side.

## 10. Fresh-install grant banner (F3)

- `popup.ts` init: `permissions.contains({origins: [BROAD_ORIGIN_PATTERN]})` → when false,
  un-hide a one-line banner ("Autofill is off — turn on for all sites") whose button calls
  `chrome.permissions.request({origins: [BROAD_ORIGIN_PATTERN]})` directly (a popup click is
  a valid gesture). On grant, hide the banner — the existing background
  `permissions.onAdded` listener (background.ts:778) re-registers the content scripts;
  `excludeMatches` vault protection is enforced at registration and is untouched by the
  grant. Nothing else needed.
- `options.ts`: a status line "Autofill injection: on / off (all-sites permission)".
- Firefox: identical flow (its per-origin CTA already exists; this adds the broad one).

## 11. Vectors + pins (gate — every rule below must be RED when its rule is removed)

- `spec/test-vectors/cardform.json` (refine): new cases — `cc-type` hint; `cardtype` name
  token; gift suppression (`giftCardNumber` → not CC_NUMBER → form not CARD); **gift-on-id**
  (garbage name + `id="giftCardNumber"` → suppressed, [T10]); htmlId fallback recovery
  (garbage name + classifiable id) **including the EMPTY `name=""` variant**; regression:
  all existing cases byte-stable. NOTE: never write a shared vector assuming hint-vs-login-
  name conflicts agree across engines (core checks CARD_HINTS before legacy; ext gap-gates —
  pre-existing seam).
- New `spec/test-vectors/cardfill.json`:
  - `tables` — the normative synonym/contains/month/abbreviation tables ([T14], both
    engines assert equality);
  - `shared` — label-only select options (single strings) + the text adapters (expiryText
    maxLength table, yearText, monthText, month-name pass incl. the `Marraskuu` NEGATIVE,
    the placeholder-never-outranks case, CC_TYPE label+code matching): both engines consume
    and must agree; placeholder-signal cases are marked TS-only;
  - `domSelect` — value≠text option pairs (CyberSource `001` codes, `V`/`VI` values,
    "01 - January"): TS engine only.
- Core: `CardFillTest` (or a new `CardFillVectorTest`) **gains cardfill.json consumption**
  (today it is vector-less — without this the core half of lockstep is vacuous);
  `CardVectorSupport.vectorFieldKind` += `"cc-type"`, `vectorFieldSignal` += `htmlId`;
  **[T14] the isCardKind PARTITION test**: `FieldKind.values().filter{isCardKind} ==
  [CC_NUMBER, CC_EXP_MONTH, CC_EXP_YEAR, CC_EXP, CC_NAME, CC_CSC, CC_TYPE]`.
- `extension/src/detect.cards.test.ts`: selects, cardtype, gift guard (both strings), id
  fallback — both misclassification directions; plus a grouping-level case for the [T1]
  formless "expiry-selects + password-CVV row, PAN in sibling row" layout (DOM-shaped stub
  or extracted pure grouping check).
- `extension/src/cardfill.test.ts` (new): vector consumption (`../../spec/test-vectors/`
  via the `fileURLToPath` idiom of urimatch.vectors.test.ts), tables `deepEqual`, hand edges.
- `web/src/extension-pins.test.ts` — structural anchors ([T15]/[T9]/[T11]/§7): the card
  `onUpdated` handler references `changeInfo.status` and not `.url`; `cardForms`+`cardGrants`
  deletion on the `"loading"` path; content.ts anchors for `attributeFilter: ["class",
  "style", "hidden"]`, `lastCardSig: string | null = null` (and the rescan reset),
  `"rescanCardForms"`; the [A6] pin (no `updateSnapshot(`/`snapshots` in the
  cardfill/applyCardFill path); the [T9] brand-guard (`cardnumber` check precedes the brand
  write); `asCardFillOutcome` accepts `"partial"`. Behavior pins: ext `padMonth`/`yearTo4`
  against the existing `card.json` sections (web twin already exports both).
- verify.sh needs NO changes (all touched suites already gated); gradle vector-input dirs
  already invalidate on spec edits.

## 12. Out of scope (Tier 2+, deliberately)

Label/placeholder/aria signals; i18n vocabulary (incl. localized month names — [T3] makes
them a safe miss); multi-form/richest-frame targeting; shadow DOM descent; split 4-box PAN
distribution; key-event fidelity/blur; Android DATE leg + compat-mode trace; PSP-iframe
explainer + copy parity; save-card capture (egress-pin amendment required); radio-button
card types; billing ZIP; StructureParser `winningSignal` ablation htmlId (diagnostic-only);
**tokenizer alignment** — the ext letter↔digit boundary makes "cardNumber2"-style names
classify in the extension but not core (both behaviors pinned; aligning core touches shipped
step-2 demotion semantics and needs its own vector sweep — fold into the vocabulary lane).

## 13. Review-fold record (2026-07-23, find→refute over the built diff)

12 confirmed findings folded: the CC_TYPE matcher's ext twin was single-pass
(exact-OR-contains per option) vs core's exact-across-all-options-then-contains — a
cross-engine fork the vectors couldn't see; split into two real passes + two ordering-pin
vectors added (brand-enumerating header / "Visa Electron" before the exact row). Per-kind
outcome aggregation (a kind counts filled when ANY twin instance landed);
`asCardFillOutcome` validates the kind arrays; partial-copy labels are disjoint (missed side
owns shared labels); `cardFillOffers` immediate-answer + popup re-query (above); core-side
gift-terminality vector; stale comments in detect.ts (the "suppression-only" tokens claim),
CardFill.kt header, SaveExtractor/DatasetBuilder refreshed. Gift-suppression terminality
parity across engines was verified clean by three independent reviewers.
