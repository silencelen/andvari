# Card autofill audit — 2026-07-23

Cross-platform audit of payment-card ("wallet") autofill, driven by two reported symptoms (2026-07-23): **(1)** cards do not prompt for autofill on some forms; **(2)** manual fill on those forms fills only part of the card — expiration date and/or card type are left empty.

Evidence base: adversarially verified code findings against this tree; primary-source research of Bitwarden (`bitwarden/clients` @ main) and Chromium (`components/autofill` @ main); a behavior survey of 1Password/Dashlane/Safari; and an empirical run of a 37-pattern real-checkout corpus (Chromium heuristics captures + platform templates + PSP docs) through Andvari's **actual** classifier stack (`extension/src/detect.ts`, `urimatch.ts`, `card.ts` imported directly). All file:line citations were verified against the tree at audit time.

---

## 1. Executive summary

**Both symptoms reproduce mechanically and are fully root-caused.** Corpus bottom line: the popup Fill offer appears on 21/31 same-origin checkout patterns (10 get no offer at all; 6 more are cross-origin PSP iframes, excluded by design but with no explanation shown), and only **40/143 card-purpose fields (28%) fill correctly**.

**Symptom 2 — "expiry and/or card type left empty" — has three stacked causes:**

- **`<select>` elements are never collected, classified, or fillable in the extension** (F1). `collect()` queries `querySelectorAll("input")` only, `CardFormFieldRef` is `HTMLInputElement`-typed, and `setValue` writes through `HTMLInputElement.prototype`'s value setter. Since `buildCardForm` needs only a card-number *input* anchor, the classic checkout shape — PAN input + month/year (and type) dropdowns, which dominates legacy/enterprise first-party checkouts (12 of 14 captured merchant forms) — still gets a popup Fill offer; number/name/CVV land and the dropdowns are silently skipped. This is the single largest cause (42 of the 103 corpus field misses). The needed option matcher **already exists in-repo**: core `CardFill.listIndexFor` implements it for Android and was never ported.
- **No card-type/brand field kind exists on any platform** (F2). Neither extension `CardFieldKind` nor core `FieldKind` has a type/brand member, no name/hint tokens exist for it, and `CardFillFields` carries no brand — so "Card type: Visa/Mastercard…" controls never fill anywhere (0/9 in the corpus), even though the stored card already persists a derived `brand` and `brand()` is shipped on every surface for display.
- **Expiry is composed once as a fixed `"MM/YY"` with no per-target adaptation** (F7, F10, F11). The extension slices that string (year can never be 4-digit; combined targets never get MMYY/MM-YYYY variants); Android core's fit-guard makes a combined `maxlength=4` MMYY input receive *nothing*; and `composeShortExpiry` returns null on a half-present/unparseable stored expiry, silently dropping expiry from both fill and popup copy. All of this is then hidden by F9: any one field landing reports full success and closes the popup.

**Symptom 1 — "no prompt on some forms" — is part design, part detection:**

- **By design, cards have no in-page prompt at all** (F4, pinned by the S3 egress contract: the popup is the sole Fill surface). There is also no compensating affordance — no per-tab badge for card forms, no context menu, no keyboard command — so on *every* card form the product is silent until the user opens the toolbar popup. Detection failures and this design are indistinguishable to the user.
- **Detection misses kill even the popup offer** on 10/31 same-origin patterns: `name` shadows a meaningful `id` (F5), labels/placeholders/aria are never consulted and the token vocabulary is narrow and English-only (F6), checkout steps revealed by class/style toggles are never rescanned (F8), shadow DOM is never descended (F14), only the first card form per frame is reported (F12) with a gift-card false-anchor hazard (F13), and the login classifier can steal "account"-named PAN fields (F26).
- **Cross-origin PSP iframes** (Stripe/Shopify/Braintree/Adyen/Square — the majority of modern checkouts by volume) are excluded by the S3 contract; the design-promised "this checkout embeds its card form — copy instead" popup message was never implemented (F15), so these read as broken rather than as policy.
- **A fresh Chrome install on the default server never obtains the broad host grant** (F3): the only `permissions.request` call site is the options-page server-*switch* gesture, so on a new profile the content script injects nowhere — cards **and** logins silently dead, no banner, no hint.

Android is genuinely strong (shipped select/spinner fill, fit-guards, cert-pinned trust, Luhn-gated save) but shares the no-brand-kind, month-name-spinner, MMYY, and signal-poverty gaps, and compat-mode browsers likely never card-prompt (F20, needs device trace).

---

## 2. How the AAA products do it

**Detection signals.** Chromium regex-matches **label and name** per field (name falls back to id in Blink's `NameForAutofill`), where "label" is anything scrapeable near the field — `<label>`, placeholder, aria-label, preceding text runs, table headers — with localized pattern sets per page language and a min-form gate (≥3 distinct fillable types for heuristics-only). Bitwarden walks a per-field attribute priority list — `autoCompleteType`, `data-stripe`, `htmlName`, `htmlID`, `title`, label-tag, placeholder, label-left/top, `data-recurly` — so a useless name can never shadow a meaningful id or label. Dashlane replaced its rules engine with an on-device ML classifier (F-score ~92% across EN/FR/DE).

**Element coverage.** Bitwarden collects `input, textarea, select, span[data-bwautofill]`, snapshots each select's options (normalized text + raw value), records maxLength and all `data-*` attributes, pierces open **and closed** shadow roots (`chrome.dom.openOrClosedShadowRoot`), injects `all_frames: true`, and re-collects under an attribute-filtered MutationObserver plus an IntersectionObserver so hidden-then-revealed fields qualify. Chromium's renderer extracts input/select/textarea natively, flat-tree included.

**Expiry format adaptation.** Everyone stores canonical month + 4-digit year and adapts at fill time. Chromium parses format guidance out of placeholder/label (`mm(\s?[/-]?\s?)?(y{2,4})`, localized aa/jj/rr variants) and applies a max_length table — 4→MMYY, 5→MM/YY, 6→MMYYYY, 7→MM/YYYY — refusing to fill what cannot fit. Bitwarden derives month padding, year length (yy/yyyy attr hints or maxLength 2/4), delimiter, and even year-first ordering from the field's own attributes, converting stored years 2↔4-digit in both directions.

**Select filling.** Chromium detects month/year selects **structurally from option contents alone** (12/13 options whose last is "12"; three consecutive years among values/texts) — zero label signal needed — and fills by parsing option values then texts: locale month names, 0-based lists, placeholder-first 13-option lists, index-valued lists, last-two-digit year bridging. Bitwarden matches normalized option text OR raw value and substitutes the option's `value` as the payload; no match → no fill, never garbage.

**Card type / brand.** Chromium's `CREDIT_CARD_TYPE` has no regex at all: a select is a type field iff its options contain "Visa"/"Mastercard" as whitespace-insensitive substrings, and fill tries exact → substring → an "AmEx" alias. Bitwarden treats brand as a first-class bucket (`cc-type, card-type, card-brand, cc-brand, cb-type`) filled by option matching against its fixed brand list; 1Password/Dashlane derive brand from the PAN (BIN) where needed.

**Cross-origin PSP iframes.** All three fill them. Chromium flattens frame trees in the browser process under origin policies (and *wipes* main-frame number/CVC classifications when a PSP subframe holds them, per PCI reality). Bitwarden injects into PSP frames and fills per-frame, gating unmatched origins behind a confirm dialog. 1Password documents an explicit cards-only cross-origin exception, compensated by an un-spoofable confirmation prompt.

**Prompt UX.** Inline, on field focus, is table stakes: 1Password's in-field icon + inline menu, Dashlane's D-icon, Bitwarden's inline menu with brand + last-4 (shipped 2024), Chromium/Safari native dropdowns with masked previews — plus context menus (Bitwarden has a dedicated Autofill-card submenu) and assignable shortcuts (`autofill_card` command). No mainstream product is popup-only for cards. All require an explicit user gesture per fill.

**Save UX.** Capture-on-submit "Save this card?" is the norm (1Password, Dashlane, Safari; Bitwarden via an inline "save as new card"), with per-field typed-value capture. CVV storage policy varies (Safari: never).

**Event fidelity.** Bitwarden brackets each write with keydown/keyup KeyboardEvents, re-asserts the value if listeners perturbed it, then dispatches bubbling input + change, with a 20 ms inter-op delay; one plain `element.value =` path covers input, textarea, and select uniformly. Chromium fills through the browser's native value model, invisible to page JS.

**Post-fill verification.** Bitwarden re-reads the element value after its simulated events and re-assigns on drift — success means the value *survived*. Chromium verifies through its own preview/fill model. Neither reports a fill it did not observe.

---

## 3. Andvari today

**Extension (Chrome MV3 + Firefox, shared source).** Login fill: in-page focus dropdown + popup Fill, save/update banner, generator, TOTP auto-copy on fill. Card fill (S3): content script reports card-form **metadata only** (kinds, no values) for `findCardForms(document)[0]`; popup is the sole offer surface; one-shot origin+frameId-bound grant; `revealCardForFill` composes number (digits-only), `"MM/YY"` expiry, name, CVV per declared kinds; executor writes inputs only, CVV last, via the native `HTMLInputElement` setter + untrusted input/change. Same-origin frames only; PSP iframes fall back to popup copy (number/expiry/CVV — no cardholder). No card create/edit/save in the extension. Detection signals: autocomplete hints + `input.type` + `name || id` tokens; English-only vocabulary; no label/placeholder/aria/maxlength; childList-only rescan.

**Android (Autofill service + shared Kotlin core).** Real, shipped card support: all `AUTOFILL_HINT_CREDIT_CARD_*` + W3C `cc-*` hints, name/id token fallback (same lists as the extension, deliberately pinned in parity), spinner/LIST fill via `AutofillValue.forList` with a two-pass numeric option matcher, maxLength fit-guard (skip-not-truncate), inline IME chips + dropdown, locked-path unlock-and-refill, `SAVE_DATA_TYPE_CREDIT_CARD` capture with Luhn gate and richest-cluster anchoring, cert-pinned browser trust. Gaps: numeric-only option matching, no DATE leg, no brand kind, `getHint()`/placeholder never read, compat-mode browsers unproven.

**Web vault.** Full card editor (month/year selects, per-half canonicalization), copy for cardholder/number/CVV (not expiry), brand badge display, CSV import. No page filling (not its job).

**Desktop (Compose).** Vault + editor + copy surface (cardholder/number/CVV; expiry display-only); free-text expiry editor silently drops an unparseable half at save. No OS-level fill (industry-typical).

---

## 4. Gap matrix

| Dimension | Andvari | Bitwarden | Chromium | 1Password |
|---|---|---|---|---|
| Detection signals | autocomplete + `name\|\|id` tokens only; English-only; name shadows id | Priority walk: autocomplete, data-stripe, name, id, title, labels, placeholder, data-recurly | Label (incl. placeholder/aria/nearby text) + name(→id), localized regexes, server crowdsourcing | Proprietary heuristics over labels/attrs; ML-assisted |
| Element coverage | `input` only; no shadow DOM; first form per frame | input+textarea+select+span; open+closed shadow roots; all forms/frames; IntersectionObserver | input/select/textarea natively, flat tree, all forms | Comparable to Bitwarden |
| Expiry format adaptation | Fixed `"MM/YY"`; year always 2-digit; no maxlength/placeholder use; Android has fit-guard but no MMYY | Attr-driven mm/yy/yyyy + maxLength; delimiter + order inference; 2↔4-digit both ways | Placeholder/label format regex + max_length table (4/5/6/7); refuses ill-fitting fills | Canonical month+YYYY, per-target transform |
| Select filling | Extension: none. Android: numeric value/text two-pass (no month names, no DATE) | Option text (normalized) OR value; month/year candidate lists; no-match → no fill | Structural select detection + value-then-text, month names (16 locales), 0-based/index/2↔4-digit handling | Fills selects incl. month-name options |
| Card type / brand | No kind on any platform; brand stored but display-only | First-class bucket (cc-type/card-type/…), option-value substitution from brand list | Select-only, option-substring "Visa"/"Mastercard" + AmEx alias at fill | BIN-derived brand, best-effort select match |
| Cross-origin PSP iframes | Excluded by contract; copy fallback (promised explainer UI unshipped) | Filled (all_frames, per-frame scripts, untrusted-origin confirm) | Filled natively (browser-process frame flattening) | Filled — explicit cards-only cross-origin exception + confirmation |
| Prompt UX | Popup-only; no in-page prompt, badge, context menu, or shortcut for cards | Inline menu on focus (brand+last-4), context-menu card submenu, shortcut | Native inline dropdown with masked previews | In-field icon + inline menu; opt-in confirmation prompts |
| Save UX | Android checkout save only; extension has none (by-design metadata pin) | Inline "save as new card" from typed values | Browser save-card prompt (refuses unparseable expiry) | Save/Update prompt on submit, on by default |
| Event fidelity | focus + native setter + untrusted input/change; no key events; last field never blurred | keydown/keyup bracket + value re-assert + input/change, 20 ms delays | Native value model — no synthetic events needed | Simulated user-like input events |
| Post-fill verification | None — write attempt counts as filled | Re-read + re-assert after events | Browser-verified | Confirms via its own fill pipeline |
| Platform coverage | Ext (Chrome/Firefox) + Android autofill + web/desktop copy surfaces; no iOS | Ext + Android + iOS + desktop | Chrome everywhere | Ext + Android (Chrome/Brave) + iOS 18 system fill |

Architectural note: `CardFill.kt:8-12` states the extension "is expected to consume the same plan" as Android — the extension instead reimplemented the value layer without the three things that make the Android path robust (LIST/option matching, the maxLength fit-guard, canonical 4-digit year with adaptive shrink). Most fill findings below are deltas against an in-house, vector-tested reference implementation that already exists.

---

## 5. Findings

Severity bar: **high** = mainstream checkout pattern fails / reported symptom directly caused; **medium** = common-but-not-majority pattern fails or misleading UX; **low** = niche/polish; **info** = context/by-design baseline. Flags: **[by-design]** = deliberate documented behavior that still produces a symptom; **[UNVERIFIED]** = plausible, not adversarially verified against the tree/device.

| ID | Sev | Surface | Finding | Flags |
|---|---|---|---|---|
| F1 | high | extension | `<select>` never collected/classified/fillable — expiry/type dropdowns invisible; select-based checkouts get a Fill that lands only inputs (detect.ts:244, content.ts:61) | |
| F2 | high | all | No card-type/brand field kind anywhere — type selects/inputs never fill though brand is stored+derivable (detect.ts:55, FieldClassifier.kt:11) | |
| F3 | high | ext-Chrome | Broad `https://*/*` grant only requested in the options server-switch gesture — fresh installs on the default server get **no injection anywhere**, silently (grantflow.ts:26, manifest.json) | |
| F4 | high | extension | Cards have no in-page prompt (popup is the sole Fill surface) and no compensating affordance — badge, context menu, and shortcut all absent (content.ts:234) | [by-design] |
| F5 | high | ext+android | `name \|\| id` shadowing: a generic/garbage name hides a classifiable id, killing anchors and fields (detect.ts:209; StructureParser.kt:173) | |
| F6 | high | ext+core | Signal poverty: label/placeholder/aria/maxlength never consulted; narrow English-only token vocabulary — conventionally-labeled and non-English checkouts undetectable (detect.ts:79-86) | |
| F7 | high | core/android | Combined-expiry hardcoded MM/YY + fit-guard: `maxlength=4` MMYY inputs receive **nothing**; MM/YYYY gets a rejectable value (CardFill.kt:92-98) | |
| F8 | high | extension | Attribute-only reveals never rescanned (childList-only observer; popup open never triggers a rescan) — CSS-toggle accordion checkouts never offer (content.ts:467-482) | |
| F9 | med | extension | Partial fill reports full success — any one field landing ⇒ `{filled:"card"}` ⇒ popup closes silently; no per-kind outcome vocabulary (content.ts:216, popup.ts:762) | |
| F10 | med | extension | Expiry ships only as composed `"MM/YY"`; standalone year targets always get 2-digit; no maxlength/placeholder/pattern adaptation — inverse of core's yearTo4+fit-guard (content.ts:179-182) | |
| F11 | med | extension | `composeShortExpiry` all-or-nothing: half-present/unparseable stored expiry silently drops fill **and** popup copy; even standalone month/year inputs are slices of the composed string (background.ts:2285, card.ts:91) | |
| F12 | med | extension | First-card-form-only reporting + blanket frameId-0 preference — multi-form pages (gift card first, two card blocks) misreport or mistarget (content.ts:157, background.ts:2230) | |
| F13 | med | extension | Gift-card false anchor: `GiftCardNumber` token-run-matches `cardnumber` — bogus Fill offer writes the real PAN into a merchant gift-card field (detect.ts:80) | |
| F14 | med | extension | Shadow DOM never descended — only `document` is ever passed to `findCardForms`/`findLoginForms`; web-component checkouts invisible (detect.ts:383, content.ts:45/157) | |
| F15 | med | extension | Design-promised PSP-iframe explainer ("this checkout embeds its card form — copy instead") never implemented — Stripe-style checkouts show a bare copy-only row with no explanation (popup.ts:734) | |
| F16 | med | extension | No post-fill verification — a write the page's framework reverts still counts as filled (content.ts:199-203) | |
| F17 | med | extension | Event fidelity: untrusted input(insertReplacementText)+change only; no key events; last-filled field (CVV) never blurred — key-driven maskers and blur validators miss the fill (content.ts:66-71) | |
| F18 | med | extension | Split 4-box PAN: every box classifies `cardnumber` and each receives the full 16-digit PAN (content.ts:197) | |
| F19 | med | android | LIST option matching is numeric-only — month-name-only spinners ("January"/"Jan"/localized) never match; combined CC_EXP on LIST has no matcher (CardFill.kt:112-127) | |
| F20 | med | android | Compat-mode browsers (Samsung Internet, Edge): a11y-synthesized structures carry none of the html signals card classification requires — likely no card prompt at all (autofill_service.xml) | [PLAUSIBLE — needs on-device trace] |
| F21 | med | core/android | `AUTOFILL_TYPE_DATE` expiry fields unconditionally skipped — no `forDate` leg (CardFill.kt:73-77) | |
| F22 | med | android | PAN anchor signal gap: `ViewNode.getHint()`/placeholder never read + thin PAN keywords, while the CC_NUMBER anchor gates the entire form → total silence on placeholder-only forms (StructureParser.kt:165-192) | |
| F23 | med | all | Card model has no billing postal/ZIP — US AVS ZIP boxes never filled (types.ts:552; spec 02 scoping) | [partly by-design] |
| F24 | med | all | Copy parity: popup (the designed PSP fallback) lacks cardholder copy; web/desktop/Android lack expiry copy — no single surface can copy all card fields (popup.ts:748; Vault.tsx:1019; Ui.kt:2269; MainActivity.kt:1849) | |
| F25 | med | desktop+android | Editors silently drop an unparseable expiry half at save (warn-not-block), producing the half-cards F11 then can't fill or copy (Ui.kt:2574; MainActivity.kt:2102) | [by-design] |
| F26 | med | ext+core | Login-classifier steal + keyword gap: "account"-named PANs undetectable (offer lost; login fill can target the PAN box); opaque-named password CVVs remain login-dropdown targets (urimatch.ts:130/156, detect.ts:161) | |
| F27 | low | ext+core | [A8] gap-rule steal narrow case: hint-less text fields whose name both token-matches a card keyword and substring-matches a login positive (userCardNumber, userNameOnCard) (detect.ts:161) | [by-design parity gate] |
| F28 | low | extension | Card-form registry not cleared on navigation + `lastCardSig=""` sentinel suppresses the new document's empty report — stale same-origin Fill offers survive (background.ts:853, content.ts:152-161) | |
| F29 | low | android | Android mirror of F5: `attr("name") ?: attr("id")` — opaque server names hide classifiable ids (StructureParser.kt:173) | |
| F30 | low | extension | No browser card capture — S3 metadata-only egress pin; asymmetric vs Android checkout save now that card creation is enabled product-wide | [by-design] |
| F31 | low | core | `cc-given-name`/`cc-family-name` unmapped — split cardholder fields stay empty | [UNVERIFIED] |
| F32 | low | android | Card datasets share the MAX_DATASETS=10 cap after logins — login-heavy MIXED forms can squeeze cards out | [UNVERIFIED] |
| F33 | low | core | Brand IIN table lacks JCB/Diners/UnionPay/Maestro (all three ports) | [UNVERIFIED] |
| F34 | low | spec | Vector gaps: no select/LIST card-form vectors, thin `composeShortExpiry` set, no shared fill-executor adaptation pins binding TS to core | [UNVERIFIED] |
| F35 | low | extension | Login popup Fill is top-frame-only while the card path is frame-aware — same-page inconsistency | [UNVERIFIED] |
| F36 | low | extension | Popup card row: dead click affordance ("Copy card details" title, no handler), no card detail view | [UNVERIFIED] |
| F37 | low | extension | Password-typed CVV boxes still open the **login** dropdown (fill deliberately unchanged; only capture is suppressed) | [UNVERIFIED] |
| F38 | low | ext-Firefox | S3 depends on `sender.origin` with silent fail-closed — unproven on release Firefox; if absent, cards never offer there with no breadcrumb | [UNVERIFIED] |
| F39 | info | extension | `about:blank`/`srcdoc` helper frames never run the content script (init hostname gate, amendment [A1]) | [by-design] |
| F40 | info | extension | Cross-origin PSP iframes (Stripe/Shopify/Braintree/Adyen/Square) give a silent no-offer — correct per contract, but it is the modal modern checkout and currently indistinguishable from a bug (see F15) | [by-design] |
| F41 | info | android | Positive baseline: Android card support is real, shipped, and safety-engineered (cert-pinned trust, hostile-iframe zero-fill, Luhn-gated save, fit-guards) — gaps are breadth, not architecture | |
| F42 | info | android | No TOTP assist after an Android login fill (extension auto-copies) — cross-surface ceremony mismatch | [UNVERIFIED] |

### F1 — `<select>` elements never collected, classified, or fillable (high, extension)

**Detail.** `collect()` iterates `root.querySelectorAll("input")` only (detect.ts:244); `HTMLSelectElement` appears nowhere in `extension/src`. `CardFormFieldRef.input` is typed `HTMLInputElement` (detect.ts:415-418) and `setValue` binds the value setter from `HTMLInputElement.prototype` (content.ts:61), so a select could not be written even if collected. `CARD_FALLBACK_HTML_TYPES` (detect.ts:91) would also type-gate selects out of the name-token path. Because `buildCardForm` requires only a card-number **input** anchor, PAN-input + expiry/type-select checkouts still detect, the popup offers Fill, and `applyCardFill` writes number/name/CVV while the dropdowns silently keep their placeholders — symptom 2 verbatim. The declared-kinds gate compounds it: with no expiry kind declared, `revealCardForFill` (background.ts:2285-2288) never even composes an expiry. The S3 design doc documents excluding cross-origin PSP iframes; it never mentions selects — this is an oversight, not policy, and the Android surface *does* fill selects, proving product intent.

**Evidence.** detect.ts:244 `for (const input of root.querySelectorAll("input"))`; content.ts:61 `Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!`; corpus: 42/143 field misses are uncollected selects; 14 of 21 offered patterns are select-based; a bare one-line select inclusion recovers 0 fields (type-set + setter + vocabulary all needed). Andvari's own web editor renders expiry month as a `<select>` (Vault.tsx:1711).

**Fix.** Collect `input, select` in one query; add select types to the card fallback set (card path only — `classify()` already returns none for selects, so login verdicts stay bit-identical); widen `CardFormFieldRef` to `HTMLInputElement | HTMLSelectElement`; add a select branch to the executor that ports core `CardFill.listIndexFor` (padded/unpadded month, month-name pass, 2/4-digit year, value-then-text matching), set `selectedIndex` and dispatch input+change. Entirely inside the S3 contract: selects contribute kinds-only metadata; values still ride only the one-shot `revealCardForFill` round-trip. Pin with shared `cardform.json`/`cardfill.json` vectors run by both core and a new TS executor test.

### F2 — No card-type/brand kind on any platform (high, all)

**Detail.** `CardFieldKind` (detect.ts:55) and core `FieldKind` (FieldClassifier.kt:11) have no type/brand member; `CARD_HINTS`/`CARD_NAME_KINDS` carry no `cc-type`/`cardtype`/`cardbrand` tokens; `CardFillFields` (messages.ts:61) has no brand member; `CardFill.listIndexFor` matches only month/year. So the "Card type" select common on airline/utility/government/legacy-gateway checkouts (corpus: Macy's, Walgreens, Keurig/CyberSource, eFollett, United, Magento) never fills — 0/9 in the corpus — and on sites that require it, an otherwise-complete fill dead-ends the submission. The value already exists twice over: `CardData` persists a derived `brand` and `brand()`/`brandLabel()` ship on every surface for display.

**Fix.** Add a `cardtype`/`CC_TYPE` kind (hint `cctype`; name tokens `cardtype, cctype, cardbrand`, guarded to card-anchored clusters); egress `brand` only when the kind is declared (derived from the PAN the form already receives — zero new secret surface); fill selects by matching option value **then** text against a small synonym table (visa/vi/VISA, mastercard/mc, amex/"american express", discover/di — corpus shows site codes like `V`, `VI`, `001`, index values), text targets get `brandLabel`. Land core + extension in lockstep with shared vectors. Depends on F1 for select-based type fields; independently real for text/radio type fields and Android LIST nodes.

### F3 — Fresh Chrome installs never obtain the broad host grant (high, ext-Chrome)

**Detail.** The autofill content script is registered dynamically for all http/https, but Chrome injects only into **granted** origins. The manifest grants only the default server origin install-time (which registration then excludeMatches); `https://*/*` sits in `optional_host_permissions`, and the only `permissions.request` call site is `requestServerGrants()` — invoked solely from the options-page server-*switch* Connect gesture (options.ts:94). A fresh profile on the shipped default server never performs that gesture: sign-in and copy work, but the content script injects **nowhere** — no card reports, no login dropdown, `cardFillOffers` answers `{fillable:false}` — and `shouldRouteToOptions` checks only the per-origin grant (held), so no CTA ever appears. Installs updated in place from the pre-optional-permission era retain the grant, masking the bug on long-lived profiles.

**Fix.** On popup load, `permissions.contains({origins:["https://*/*"]})`; when false, render a one-line "Enable autofill on all sites" banner whose click calls `permissions.request` (popup clicks are valid gestures). Add an Options status line ("Autofill injection: on/off"). Verify affected profiles via chrome://extensions → Site access.

### F4 — No in-page card prompt and no compensating affordance (high, extension, by-design)

**Detail.** `maybeOpen → formFor` resolves LoginForms only (content.ts:234); the S3 doc pins "no in-page card picker" (R4) with the popup as the sole trusted offer surface. That posture is sound — but the suite ships **zero** discovery affordance: the toolbar badge is login-match-count only (blank on card-only sites), there is no `contextMenus` permission, no `commands` key (not even `_execute_action`), and no card detail view in the popup. Every competitor prompts at the field. To a user, "focus the card field, see nothing" *is* symptom 1, on working and broken forms alike.

**Fix (contract-preserving).** (a) Set a per-tab action badge when an eligible same-origin card form is recorded; (b) add a context-menu entry and an `_execute_action` shortcut that merely open the popup; (c) optionally a data-free in-page nudge ("Cards: open Andvari to fill") rendered by the extension's own UI with no picker and no value path. Any real in-page picker is a full egress-contract review item — see Design decisions.

### F5 — `name || id` shadowing (high, extension + Android)

**Detail.** `fieldSignalOf` sets `htmlNameOrId: input.name || input.id || null` (detect.ts:209); Android mirrors it (`attr("name") ?: attr("id")`, StructureParser.kt:173). A generic or garbage name fully hides a classifiable id, and no other signal exists to recover it. Corpus-verified consequences: a captured drugstore checkout loses its **only** PAN anchor (`name="addcardnumber"` glued-token hides `id="wag-cko-pm-in-cc-num"`) → no offer at all (symptom 1); a captured Apple form's literal `name="null"` hides `...security-code` → CVV lost; `name="name"` hides `id="ccName"` → cardholder lost (symptom 2). The harness confirmed all three recover when the id is classified.

**Fix.** Classify name and id independently (first non-null card verdict wins), applied in the `classify()==none` card gap so login verdicts stay bit-identical; fix core in lockstep (shared vectors) since parity is pinned.

### F6 — Label/placeholder/aria never consulted; narrow English-only vocabulary (high, extension + core)

**Detail.** Card classification consumes only autocomplete hints + `input.type` + `name||id` tokens; `FieldSignal` has no label/placeholder/aria/maxlength member at any layer. 16 of 22 harness classification misses are label/placeholder-carried meaning (Gravity-Forms `input_2_1`, bank-style `field_7`, React generated ids) — structurally unreachable today. Vocabulary misses are mechanical: `creditCard` tokenizes to [credit,card] and matches nothing → no anchor → no offer; CVV aliases `cid/cardcode/securityvalue/securitynumber/verification_value/x_card_code` and name aliases `holdername/cardholdersname` all miss; i18n coverage is zero (German/French/Spanish corpus patterns: no offer). Chromium's tables are multilingual regexes over name+id+label+placeholder+aria; Bitwarden reads labels/placeholders as first-class.

**Fix.** (a) Widen token groups (creditcard, accountnumber-in-card-context, CVV aliases above, holdername variants, and a starter i18n set: kartennummer, numerocarte, cryptogramme, pruefnummer, titular…); (b) add a label signal (associated `<label for>`, wrapping label, aria-label, placeholder) to the **card path only**, extracted content-side (DOM-local — still metadata-only to the SW, S3 untouched), fed through the existing tokenizer; maxlength as an expiry-year tiebreaker. Core in lockstep.

### F7 — Combined expiry: MMYY targets get nothing; MM/YYYY gets a rejectable value (high, core/Android)

**Detail.** `textFor(CC_EXP)` always composes 5-char `"MM/YY"`; the fit-guard (CardFill.kt:96-98) then refuses any value longer than the declared maxLength, and its only adaptation is CC_EXP_YEAR-only — so a combined input with `maxlength=4` (separator-free MMYY, which the save path itself accepts) receives **nothing**, silently. MM/YYYY targets get `"MM/YY"`, which strict validators reject. Reachability verified end-to-end (StructureParser reads html maxlength → DatasetBuilder → CardFill). Chromium keys the format off max_length exactly here (4→MMYY, 5→MM/YY, 6→MMYYYY, 7→MM/YYYY).

**Fix.** Select format by declared maxLength in `textFor(CC_EXP)`: 4→MMYY, 5→MM/YY, 6→MMYYYY, ≥7/null→MM/YY (MM/YYYY when a placeholder/pattern signal lands later). Pure-core, vector-testable, no egress impact. The extension executor needs the same adaptation (F10).

### F8 — Attribute-only reveals never rescanned (high, extension)

**Detail.** `reportCardForm()` runs at init and from a MutationObserver watching `{ childList: true, subtree: true }` only (content.ts:467-482). Checkouts that pre-render the card block hidden and reveal it via class/style/hidden toggles (payment-method radios/accordions) produce attribute mutations only: `collect()`'s visibility gate excluded the fields at scan time and no rescan ever fires. Nothing on the popup-open path forces one either — `cardFillOffers` reads the stored registry without pinging the tab. Logins self-heal via focusin; cards have no event-driven rescan at all. Scope: pure CSS-toggle reveals over pre-rendered nodes (framework mount/unmount checkouts do fire childList and heal).

**Fix.** On `cardFillOffers` (popup open — the only moment the offer matters), send a `rescanCardForms` tab message and await fresh `cardFormInfo` before answering. Optionally add `attributes:true, attributeFilter:["class","style","hidden"]` behind the existing 150 ms debounce. Also cheap: rescan cards on input focusin (idempotent via `lastCardSig`). Fix the `lastCardSig` init sentinel while there (F28).

---

## 6. Remediation plan

All quick wins and medium lanes fit **inside** the S3 egress contract: detection stays metadata-only (kinds; labels/placeholders/options are control metadata that never leaves the frame), values still ride only the one-shot origin+frameId-bound `revealCardForFill` grant.

### Tier 1 — QUICK WINS (days)

1. **Selects end-to-end** (F1): collect `input, select`, widen the card fallback types, port `CardFill.listIndexFor` to the TS executor with a select setter (selectedIndex + input/change). Single biggest win — turns ~14 corpus partial-fill patterns into full fills.
2. **`cardtype` kind driven by brand** (F2): new kind + declared-kinds-gated `brand` on the wire + synonym option matcher; core `CC_TYPE` in lockstep.
3. **Expiry halves + format adaptation** (F7/F10/F11): put canonical `expMonth`/`expYear4`/`expYear2` (plus composed `expiry`) in `CardFillFields`; executor picks per target by maxLength/placeholder (year: 4-digit default, shrink on maxLength≤2/YY hints — matching core); core `textFor(CC_EXP)` gains the maxLength table; fill each half independently so half-cards fill what they have.
4. **`name` AND `id` both-checked** (F5/F29): first non-null card verdict wins, card path only, extension + core + shared vector.
5. **Truthful partial-fill reporting** (F9/F16): per-kind `filledKinds`/`missedKinds` with post-write read-back (rAF covers maskers); popup closes only on empty miss set, otherwise stays open with "Filled number and name — couldn't fill expiry. Copy it instead:" and the copy buttons. Matches the login path's existing Cut-M truthfulness contract.
6. **Missing-grant banner** (F3) and **popup-open rescan + nav-clear sentinel** (F8/F28).
7. **Gift-card negative guard** (F13): suppress the cardnumber verdict when gift/voucher/loyalty/coupon precedes the token run — fail-safe, suppress-only.

### Tier 2 — MEDIUM LANES (1-2 weeks each)

- **Label/placeholder/aria signal extraction + vocabulary/i18n widening** (F6), card path only, core+extension lockstep, seeded from the Chromium/Bitwarden keyword tables and the corpus miss list; Android additionally consumes `ViewNode.getHint()` (F22).
- **Multi-form support** (F12): report all card forms per frame (kinds-only arrays), pick the richest form (most distinct kinds) or the last-focused one, prefer the richest frame instead of blanket frameId 0; carry a form index in the grant.
- **Mutation/shadow coverage** (F8 attribute filter, F14): bounded open-shadow-root walk feeding each root into the existing `find*` functions.
- **Event fidelity + split PAN** (F17/F18): keydown/keyup bracket per write, final blur after CVV, distribute the PAN across multi-box groups by maxLength (Amex 4-6-5).
- **Android card lanes**: month-name pass in `listIndexFor` (F19), `Value.Date`/`forDate` leg (F21), compat-mode verification via the on-device debug ring then honest documentation or hint-based classification (F20), dataset-cap headroom for cards (F32).
- **Copy parity + PSP explainer** (F15/F24): `crossOriginFormsOnly` flag on `cardFillOffers` driving the promised "this checkout embeds its card form — copy instead" line; add cardholder copy to the popup and expiry copy to web/desktop/Android.
- **Save-card capture in the extension** (F30): requires amending the metadata-only egress pin (values must leave the content script on submit) — design amendment first, mirroring Android's SaveExtractor (Luhn gate, first-value-per-kind, canonicalization).
- **Editor hardening** (F25): parse-assist (`parseExpiry` on the month box) or block-save on an unparseable non-blank half; **shared vectors** (F34): `cardfill.json` executor pins + `composeShortExpiry` half-empty cases, binding TS and Kotlin.

### Tier 3 — DESIGN DECISIONS

**In-page card prompt vs popup-only egress.** *Recommendation: keep the popup as the sole grant/fill surface, but ship data-free discovery (badge, context menu, shortcut, optional anonymous in-page nudge) now, and treat a real in-page picker as a separate, breaker-review design.* The S3 rationale is sound: an in-page picker is page-adjacent UI that would have to carry item identities into a world where the page controls layout and focus, and the one-shot origin+frameId-bound grant is anchored to a popup click precisely so no page event can mint one. But the shipped state fails users in a different way — total silence — and the corpus shows silence is the dominant *perceived* failure even where fill works. A badge/nudge carries zero card data and zero new egress, closes most of the perception gap, and preserves the invariant that only a user gesture in trusted chrome reveals anything. If usage data later shows the popup hop still loses users at checkout, design an offer-only in-page chip (no names, no data, click opens the popup) before ever considering a picker.

**Cross-origin PSP iframes.** *Recommendation: keep the exclusion for now; make it legible (F15 explainer + complete popup copy set); schedule a scoped design for per-PSP-frame fill as the eventual competitive requirement.* The exclusion is the strictest posture of the four products surveyed and is defensible: filling into a frame whose origin is a third party breaks the "grant bound to the origin the user sees" model, and 1Password/Bitwarden compensate with confirmation dialogs that are themselves a phishing-surface trade-off. But PSP iframes are the majority of modern checkout volume — permanently excluding them caps the feature's usefulness at the legacy half of the web. A future design can stay true to S3's spirit: per-frame one-shot grants bound to the *iframe's* browser-attested origin against a short allowlist of known PSP origins, minted only from the popup, with the confirmation rendered in trusted chrome. Until then, the copy fallback must actually work (cardholder copy included) and say why it is the fallback.

---

## 7. Appendix

### A. Empirical corpus run (37 patterns, real classifier stack; stored card month=07 year=2027)

Harness imports `classifyCardField`/`demoteCsc`/`classify`/`composeShortExpiry` from the tree and reproduces `fieldSignalOf`/`buildCardForm`/`cardValueFor`/`applyCardFill` exactly.

| Pattern | Offer? | Correct/card fields |
|---|---|---|
| Amazon mobile add-card | OFFER | 1/4 |
| Apple Store mobile checkout | OFFER | 1/4 |
| Macy's payment page | OFFER | 2/5 |
| Walgreens add-card | NO-OFFER (anchor: name shadows id) | 0/4 |
| Wayfair payment | OFFER | 3/5 |
| JCPenney mobile guest | OFFER | 1/3 |
| HSN (ASP.NET WebForms) | OFFER | 2/4 |
| Keurig (CyberSource) | NO-OFFER (login steal + vocab) | 0/6 |
| eFollett (type select) | OFFER | 1/6 |
| Dick Blick (+gift-card trap) | OFFER | 2/5 |
| Harry & David | BOGUS OFFER (gift-card false anchor — PAN into gift field) | 0/2 |
| United.com (ASP.NET MVC) | OFFER | 3/6 |
| Alaska Air (two card blocks) | OFFER | 1/5 |
| Virgin America (id-less) | NO-OFFER (vocab) | 0/5 |
| WooCommerce core CC | OFFER | 3/3 |
| Magento 2 cc-form | OFFER | 1/5 |
| Gravity Forms CC | NO-OFFER (label-only) | 0/5 |
| BigCommerce optimized | OFFER | 4/4 |
| ASP.NET utility biller | OFFER | 2/4 |
| Stripe Card Element | NO-OFFER (cross-origin, by design) | 0/3 |
| Stripe Payment Element | NO-OFFER (xo-design) | 0/3 |
| Stripe Checkout hosted (same-origin) | OFFER | 4/4 |
| Braintree Hosted Fields | NO-OFFER (xo-design) | 0/3 |
| Adyen custom card | NO-OFFER (xo-design; same-origin holderName also missed: vocab) | 0/4 |
| Square Web Payments | NO-OFFER (xo-design) | 0/1 |
| Shopify checkout | NO-OFFER (xo-design) | 0/4 |
| Authorize.net SIM/DPM | OFFER | 2/3 |
| Cleave.js combined mask | OFFER | 3/3 |
| Combined MMYY maxlength=4 | NO-OFFER (anchor) | 0/1 |
| Combined MM/YYYY | NO-OFFER (anchor) | 0/1 |
| PAN split across 4 inputs | OFFER (full PAN into each box) | 0/4 |
| Expiry-select value/text matrix | NO-OFFER (anchor) | 0/3 |
| Placeholder-only React (autocomplete-annotated) | OFFER | 3/3 |
| autocomplete=off opaque names (bank style) | NO-OFFER (label-only) | 0/4 |
| German checkout | NO-OFFER (i18n) | 0/5 |
| French/Spanish checkout | NO-OFFER (i18n) | 0/4 |
| Net-a-Porter (2-digit year selects) | OFFER | 1/5 |

**Aggregates.** Offer: 21/31 same-origin (68%); 21/37 overall. Fields: 40/143 correct (28%). Miss causes by field count: 42 select-never-collected · 17 cross-origin PSP (by design) · 16 label/placeholder never consulted · 6 no PAN anchor (multi-step fragments) · 6 name/id token vocab · 5 no card-type kind · 4 format (MM/YY into MMYY/MM-YYYY; PAN into 4-char boxes) · 3 name-shadows-id · 2 login-classifier steal · 3 wrong-target/mis-target/non-input-widget.

**Verified working (keep pinned):** autocomplete-hint path (cc-number/cc-exp/cc-csc, incl. password-typed CVV via negative-hint ordering) — WooCommerce/BigCommerce/Stripe-Checkout/placeholder-React fill 100%; `demoteCsc` rescues name-recognizable password CVVs on anchored forms; CVV-last ordering; one-shot grant plumbing and fail-closed origin checks match the design doc; CouponCode correctly ignored.

### B. Method inventory matrix

Egress (item → form/clipboard):

| Method | ext-Chrome | ext-Firefox | Android | Desktop | Web |
|---|---|---|---|---|---|
| In-page/inline prompt, login | yes | yes | yes (datasets, inline+menu) | no | n/a |
| In-page/inline prompt, card | no (by design) | no | yes (wallet posture, spinner LIST fill, fit-guard) | no | n/a |
| Popup/app Fill, login | yes (frame 0 only) | yes | n/a | no | no |
| Popup/app Fill, card | yes (S3; same-origin; inputs only) | unproven (`sender.origin`) | n/a | no | no |
| Copy user/pass/CVV | yes | yes | yes | yes | yes |
| Copy TOTP | yes (+auto on fill) | yes | detail only | yes | yes |
| Copy card number | yes | yes | yes | yes | yes |
| Copy card expiry | **yes (only surface)** | yes | no | no | no |
| Copy cardholder | **no** | no | yes | yes | yes |
| Fill/copy card brand | no (kind absent product-wide) | no | no | display only | display only |
| Context menu / shortcut | none | none | n/a | n/a | n/a |

Capture (form → vault):

| Method | ext | Android | Desktop | Web |
|---|---|---|---|---|
| Login save/update banner | yes | yes (trust-gated) | manual only | manual only |
| Card save from checkout | **no** (A7 suppresses the login banner on card forms; nothing replaces it — by-design egress pin) | yes (SAVE_DATA_TYPE_CREDIT_CARD, Luhn gate, richest-cluster anchor) | n/a | n/a |
| Card create/edit UI | no | yes | yes | yes |
| Import | no | yes | yes | yes (incl. cards) |

Chrome vs Firefox is a single source tree; differences are manifest-level, behaviorally identical except the F38 `sender.origin` question.
