# In-page card chip (C1) — the field-anchored card affordance

**Status: DRAFT — breaker review pending.** Owner-triggered by a failed real-world checkout test
(2026-07-26: "suggested card autofill not working on eBay/Amazon"). Root cause was NOT a
regression: cards have never had an in-page prompt — `formFor` (content.ts:152) matches only
username/password/newPassword, so `maybeOpen` never fires on a card field. The audit called this
F4; the Tier-3 §5 G4 decision explicitly reserved this build: *"If usage data later shows the
popup hop still loses users at checkout, design an offer-only in-page chip (no names, no data,
click opens the popup) before ever considering a picker."* This is that chip.

On top of the shipped card stack (ext 0.18.0 / fleet 0.20.0, `c2279ea`).

## The one-sentence contract

**The chip carries ZERO data and mints NO grant — it is a signpost that opens the popup.** Every
card value still leaves the SW only through the one-shot, origin+frameId-bound
`revealCardForFill` redemption minted by a click in the popup (S3 unchanged, [A2]/[A5]/[A9]
untouched). This is strictly LESS page-adjacent information than the shipped login dropdown,
which renders saved usernames in-page.

## Why this is safe (the security argument, stated so the breaker can attack it)

- **Spoofing is worthless.** A page can already draw a fake andvari dropdown; for logins that is a
  real phishing lever (a fake picker could harvest a click into a fake form). For the chip it buys
  the attacker *nothing*: the chip's only action is "open the extension popup," and the popup is
  trusted chrome the page cannot draw, read, or script. A user who clicks a spoofed chip and then
  fills from the REAL popup is exactly as safe as one who clicked the toolbar icon.
- **Clickjacking is worthless** for the same reason — the click performs no fill.
- **No new egress.** The chip's render input is a single boolean (`fillable`) plus a lock state.
  No item names, no counts, no masked identity, no origin echo. (A count would leak "how many
  cards this user has" to nothing — the page cannot read our closed shadow root — but it is
  excluded anyway on the zero-data principle.)
- **Fingerprinting: unchanged class.** The page can observe our shadow host appear on focus, i.e.
  detect "andvari is installed." The shipped login dropdown already does this on every login
  field. The chip is focus-triggered (not a passive beacon) and shows only where a card form was
  already detected.

## C1 — trigger (content.ts)

A NEW path parallel to `maybeOpen`, deliberately not routed through `formFor` (login-only):

- On `focusin` (and the click-reopen path) whose retargeted target is a **`FillableControl`**
  (`HTMLInputElement | HTMLSelectElement`, **excluding `input[type=radio]`** — a brand radio is a
  poor anchor) belonging to THIS frame's detected `CardForm`. Reuse the SHIPPED
  `cardFormForInput` (content.ts:495) — do not add a twin resolver. **[K16]** expiry month/year
  and card type are routinely `<select>`; a user who tabs into the expiry select first must still
  get the chip.
- **[K1] LOGIN PRECEDENCE (binding — the original "a field cannot be both" claim was FALSE):**
  the chip fires **only when `formFor(input) === null`**. A card kind fires in the
  `classify()==none` gap, and those same `kind:"none"` fields are exactly the login pool's
  `textLike` username-fallback candidates — so on a `type=password`-CVV checkout `buildLoginForm`
  already yields `{password: <cvv>, username: <nameOnCard>}` and the login dropdown opens there
  TODAY. Without this rule both surfaces render on one anchor. `formFor` reads the per-frame
  `scanForms` cache, so the check is one cached lookup.
- **[K2] `allCardForms()` MUST be cached.** It is uncached today (content.ts:490) — a full
  document + up-to-64-shadow-root re-classify. Moving it to every focusin would re-scan on every
  tab stop. Add `cardFormsCache: CardForm[] | null` mirroring `formsCache`: one scan per animation
  frame, **cleared in `onMutations` beside `formsCache = null`** (content.ts:751 — the rAF clear
  never fires in a throttled background tab, so `onMutations` is the real self-heal) and by
  `rescanCardForms`. `cardFormForInput`, `cardFormNear`, `reportCardForm` and the chip all read
  through it (a net win for the shipped G2 paths too).
- **[K3] Dedupe, chip-private:** a `lastChip {input,t}` 400 ms focusin+click pair guard. An
  Esc-dismissed chip sets a per-field sentinel that suppresses the *focusin* trigger but NOT a
  fresh click on the same field; the sentinel clears on focusout. **[K4] The chip owns `lastChip`
  and `suppressChipUntil` — it never reads or writes the dropdown's `lastOpen`/`suppressOpenUntil`**
  (sharing them would let an Esc'd chip suppress the LOGIN dropdown for 400 ms).
- **[K5] `filling` is re-read at RENDER time, not only at trigger time** — `applyCardFill` focuses
  each field (trusted focusin per field); a request issued before a fill and answered after
  `filling` flips back would pop a chip on top of a just-completed fill.

## C2 — the fillability gate ([A4]-safe, reuses the V4 badge mechanism)

New message `{type:"cardChipOffer"}` (content → SW). The SW answers
`{fillable: boolean, locked: boolean}` where fillable requires ALL of:

1. `sender.origin` is a string, non-empty, not `"null"`, **and [S1] `sender.frameId === 0`
   STRICTLY** (fail-closed, [A3]). The chip MUST NOT reproduce the shipped badge's
   `frameId === undefined || frameId === 0` disjunct (background.ts:1503) — that is a fail-OPEN
   admission, tolerable for a badge repaint, not for a per-frame render decision.
2. **`sender.origin === st.topOrigin`** — the recorded TOP-frame origin from `pageInfo`
   (background.ts:1506). **[A4]-safe: browser-set `sender.origin` on both sides, NO `tab.url`
   read.** Consequence: a cross-origin PSP frame is never fillable → no chip (the G1 exclusion;
   the popup shows the copy-instead explainer).
3. the tab has a recorded card form for that frame.

**[S3] Condition 4 ("session holds ≥1 card item") is DELETED — it was a privacy leak AND made the
locked chip unreachable.** `document.elementFromPoint()` **retargets to the closed-shadow host**,
so a page can hit-test the anchor's neighbourhood to learn a chip is present and, by scanning
x-coordinates, its WIDTH. With vault state feeding presence and a locked/unlocked copy split,
chip presence encodes "this vault holds ≥1 card" and chip width encodes **live lock state** — and
because page script can force `HTMLElement.focus()` (which fires *trusted* focus events) at frame
rate, that is not a one-shot disclosure but a **continuous vault-state monitor**: a hostile
merchant can detect the instant the user unlocks and time a fake overlay to it. Therefore:
**chip presence is a function ONLY of facts the page already possesses** (origin gate + this
frame's card form), and **`.chip` has a FIXED width identical in both states** (a single `width`
in the token block, never `max-content`), so the two variants are indistinguishable by hit-test.
Accepted + documented residual: "andvari is installed", now extended to card-only pages that
carry no login field — a genuinely new page class (the manifest has no `web_accessible_resources`,
so today nothing renders there).

**[S2] The nav clear is async — close the window.** The `status==="loading"` handler deletes
`st.topOrigin` only AFTER `await ensureLoaded()` (background.ts:964), so between navigation-start
and that microtask the map still holds the PREVIOUS document's top origin. Add a module-scope
`topOriginPendingClear = new Set<number>()`, added **synchronously** in the loading listener
(beside `cardGrants.delete(tabId)`) and removed after the async delete; the gate answers
`{fillable:false}` for any tab in that set.

**[S4] Record lifecycle — persist + self-heal (this also fixes a SHIPPED bug).** `st.topOrigin`
is written without `persistTabs()` (background.ts:1503-1508), so it dies on MV3 SW idle-death
(~30 s) and is never rewritten (`pageInfo` fires once at init, content.ts:926; `rescanCardForms`
re-sends only `cardFormInfo`). **That is a live defect in the shipped V4 badge, not just a chip
problem: the card dot silently stops appearing after the SW idles.** Fixes, both binding:
(a) the `pageInfo` topOrigin write calls `persistTabs()`;
(b) when the gate fails for MISSING RECORD (`st.topOrigin` undefined, or no `cardForms` entry —
the post-lock and post-idle states), the SW answers `{fillable:false}` **and repairs**: a
`{type:"reportPageInfo"}` message to frame 0 (the content script re-sends `pageInfo`) plus the
existing `broadcastRescanCardForms(tabId)`, rate-limited to one repair per tab per 2 s. Both are
permission-free. This makes the locked chip reachable without weakening `doLock`'s erase
(`tabs.clear()`, background.ts:1102, stays).

`locked: true` (vault locked) still yields a chip — copy reads "Unlock to fill card" — mirroring
the login dropdown's shipped `kind:"locked"` state. Nothing about the vault contents is disclosed.
(Noted asymmetry: the V4 badge deliberately does NOT paint while locked, so the chip becomes the
only locked-state card affordance. Kept for consistency with the dropdown.)

**[K13] `cardChipOffer` joins `PASSIVE_MSGS`** (background.ts:127). Page script can fire *trusted*
focus at will, so this is a page-driven message stream — treating it as user activity would let a
focus-loop defer the idle autolock indefinitely. `openPopupForCards` stays NON-passive (it rides a
real isTrusted click). Recommended: cache the gate answer per document for ~2 s / until the next
`reportCardForm` sig change, so a focus storm is one SW wake rather than N. A stale `locked:false`
is harmless — the popup is the truth.

**[K12] Staleness guard (the round-trip is async; the design had none):**
```
let chipGen = 0;
if (filling) return;
const target = el, gen = ++chipGen;
const r = await safeSend({ type: "cardChipOffer" });
if (gen !== chipGen) return;                 // superseded by a newer focus
if (filling) return;                         // [K5] a fill started/finished in flight
if (!r?.fillable || !target.isConnected) return;
if ((target.getRootNode() as Document | ShadowRoot).activeElement !== target) return;
showCardChip(target, { locked: r.locked }, …);
```
The last line is load-bearing: **`document.activeElement` is the shadow HOST for a field inside a
shadow root** — writing it that way would silently disable the chip on exactly the shadow-DOM
checkouts Tier 2 was built for. Use `getRootNode().activeElement`.

## C3 — the surface (content-ui.ts)

`showCardChip(anchor, state, handlers)` beside the existing exports, in the SAME closed shadow
root (so `isOwnUiHost` already excludes it from the [U16] shadow sweep — verify, do not assume).

- **Content: the sigil + one label.** Unlocked → `Fill card with andvari`; locked → **[S6]**
  `andvari is locked — click the andvari toolbar icon` (mirroring the shipped locked-dropdown
  announcement, content-ui.ts:560-566). That wording is load-bearing anti-phishing: it teaches
  *unlocking happens in browser chrome, never in-page*. `Unlock to fill card` teaches the opposite
  and — since the page controls the anchor position — a page could place the REAL chip flush
  against a page-drawn "master password" box. NO card identity, NO item name, NO count, NO origin,
  and **no "recognized"/"saved for this site" framing**: cards are NOT URI-bound (S3 §Honest
  scope), so the chip appears identically on a phishing checkout and the real one — any copy
  implying verification is a lie the extension cannot back.
- **[S10] Structural anti-phishing invariant:** no andvari in-page surface may EVER contain a
  password/PIN/passphrase input, in any state, on any path. Pinned: the whole of `content-ui.ts`
  contains no `type="password"`. This is what bounds every habituation argument — the chip may
  teach "in-page andvari UI exists"; it must never be able to teach "andvari asks for the master
  password in-page".
- **[S5] Activation discipline:** the click listener binds to the chip element **inside the closed
  shadow root** — NEVER to `hostEl` (a page-reachable node; `hostEl.click()` would fire a
  host-bound listener) — and begins `if (!e.isTrusted) return;`, matching every shipped path.
- **[K6] Renders into `ui()`'s EXISTING root — exactly one `attachShadow` call site in
  content-ui.ts (pinned).** `isOwnUiHost` is an IDENTITY test against the single `hostEl`; a
  second host would be pierced by `chrome.dom.openOrClosedShadowRoot`, join `shadowRoots`, get an
  observer, and — since `OBSERVE_OPTS` includes `attributeFilter:["class","style","hidden"]` —
  turn every re-anchor `style` write into an observed mutation: the Tier-2 self-observation loop,
  worse. If a second host is ever required, `isOwnUiHost` becomes a Set test in the same commit.
- **[K11] Geometry (a pill, not the dropdown):** anchor to the field's inline-END edge
  (`r.right - w`; inline-start under `direction: rtl`), clamped to
  `[8, innerWidth - w - 8]`, and prefer ABOVE the field — below collides with both the browser's
  native autofill list and the site's own suggestion popup. Do NOT inherit `positionDropdown`'s
  `min-width:260px`/left-clamp. `position: fixed` + `z-index: 2147483647` + the `--anv-*` token
  block (self-sealed vs page CSS, CSP-safe via `adoptedStyleSheets`).
- **[K7] Re-anchor** joins the existing capture-phase `scroll`/`resize` handler, **coalesced into
  ONE `requestAnimationFrame` per burst** (a `rafPending` flag) — never a `getBoundingClientRect()`
  per scroll event. Without this a `position:fixed` chip stays pinned to the viewport while the
  field scrolls away (worse than not showing it).
- **[K10] Never takes focus:** `role="button"`, **NOT tabbable**; activation is
  mousedown + `preventDefault()` + act, so focus stays in the page field (the dropdown's shipped
  discipline). If focus-based dismissal is kept it must exempt `e.relatedTarget === hostEl`.
  Announced via the existing polite live region; `prefers-reduced-motion` already honored.
- **[K8] Dismissal:** `Esc`, outside click, anchor scrolled out of view, focusout,
  **`popstate`/`hashchange`** (SPA route change), and **`onMutations` when the live chip's anchor
  is `!isConnected`** (an SPA step-swap with no scroll/resize would otherwise leave it floating —
  a latent dropdown bug the chip must not inherit). One live chip at a time (module slot, cleared
  like `closeDropdown`).
- **[K9] Shared-host dismissal discriminator:** the document-level mousedown keeps
  `path.includes(hostEl) → return` for BOTH surfaces (closed-root truncation makes a chip click
  indistinguishable from a dropdown click at document level); each surface dismisses itself from
  its own in-root handler, and the chip's activation calls `closeCardChip()` before messaging the
  SW. If the chip's `Esc` joins `ui()`'s keydown capture, its early return becomes
  `if ((!dropdownEl && !chipEl) || !e.isTrusted) return;` and the `Escape`/`Tab` branches must NOT
  run `closeDropdown()` / set `suppressOpenUntil` when only a chip is live.
- **[K-label] The chip's label must never match `SUBMIT_TEXT_RX`** (detect.ts:339) — a future label
  like "Continue with saved card" would turn our own chip into a G2 submit gesture. Pinned.

## C4 — the action

**[S-BREAK3] REFRAMED so the feature does not DEPEND on an API we cannot measure here.** Both
breakers flagged `chrome.action.openPopup()` from a message handler as unverifiable without a
two-engine spike (no user activation crosses extension messaging; `handle()` awaits before
dispatch; Firefox 121+ historically requires an input handler). Rather than gate the build on a
spike this environment cannot run, the chip is specified as an **INDICATOR whose click ATTEMPTS a
shortcut**:

- **The chip's primary value is disclosure** — telling the user "andvari can fill this card here",
  which today they have NO way to learn at the field (audit F4). That value is 100% independent of
  `openPopup`.
- **If `openPopup` resolves** → the popup opens, one click, done.
- **If it rejects or is absent** (the expected Firefox path) → the toast names the destination.
  Still strictly better than today's silence.

So the worst case is a chip that says "click the toolbar" — an improvement, not a regression — and
the real-world behavior gets OBSERVED after ship rather than blocking it. Recorded as an open
question, not a hidden assumption.

Chip click → `{type:"openPopupForCards"}` → the SW attempts `chrome.action.openPopup()`.
**FORBIDDEN: `tabs.create`/`windows.create` of popup.html** — the popup computes offers against
the ACTIVE tab and would see itself. **[S9] Before calling, the SW verifies
`sender.tab?.active === true`** (and the tab's window is current); otherwise `{opened:false}` —
`openPopup()` targets the focused window's active tab, so a click delivered from a
no-longer-active tab would open a trusted surface pointed at a different origin than the one the
user clicked in. The handler reads NO `tab.url` ([A4], pinned).

**[K14] The G4 shape is NOT reusable verbatim, and the gesture context is definitively dead.**
G4's line is fire-and-forget (`void …openPopup?.()?.catch(()=>{})`, background.ts:684) — it
discards the result, which an honest `{opened}` answer needs. More importantly G4's call site is
`contextMenus.onClicked` (a gesture-carrying SW event) whereas the chip's is `runtime.onMessage`,
and **`handle()` does `await ensureLoaded()` before dispatch (background.ts:1360)** — so even a
propagated gesture would be dead. Chrome 127+ (the bumped `minimum_chrome_version`) does not
require one; **Firefox (`strict_min_version 121.0`) historically DOES require a user-input
handler, so on Firefox this call is expected to REJECT and the toast is the PRIMARY path there,
not a fallback.** The design owns that rather than discovering it in the field. The chip is still
a strict improvement on Firefox: today a card field offers no andvari affordance at all.

```ts
case "openPopupForCards": {
  const fn = (chrome.action as unknown as { openPopup?: () => Promise<unknown> }).openPopup;
  if (typeof fn !== "function") return { opened: false };          // absent → honest false
  try { await fn.call(chrome.action); return { opened: true }; }   // resolve ⇒ opened
  catch { return { opened: false }; }                              // reject ⇒ not opened
}
```
Resolution is the only signal either engine gives; treat it as authoritative and **claim nothing
more**. On `opened:false` the content script toasts the design's sentence verbatim —
**`"Open andvari from the toolbar to fill this card"`** — honest under every failure mode (absent
API, rejected call, no focused window), naming no keystroke that may not be bound. **Never toast
on `opened:true`** (the popup now covers the page; a toast under it is noise) and never toast
optimistically before the answer.

## C5 — what this deliberately does NOT do

No item list, no card picker, no fill from the page, no grant minted in-page, no autofill on
focus, no chip on cross-origin PSP frames, no chip for logins (they have the dropdown), and no
change to `revealCardForFill` or any grant path. If a future ask is "let me pick a card without
opening the popup," that is the rejected in-page picker and needs its own breaker pass.

## Gate + pins

**[K15] "All Tier-1/2/3 pins preserved" was FALSE — `[U17]` provably cannot be.** It counts
code-shaped retarget sites (`extension-pins.test.ts:347`, currently 5); a new focusin/click branch
makes 6. Binding resolution: focusin becomes
`const t = e.composedPath()[0] ?? null; maybeOpen(t); void maybeCardChip(t);` and the click
listener reuses its existing `const t` — **count stays 5** — and `:348`'s positive anchor is
rewritten to `/"focusin",[\s\S]{0,160}?maybeOpen\(t\)[\s\S]{0,80}?maybeCardChip\(t\)/` with a
comment naming why the literal-argument form was retired. That is the tripwire working, not a
weakening.

**Placement rules that keep the remaining span pins green (binding):**
- `[A6]`/`[W9]`: do NOT move or rename `let filling = false` (content.ts:212), `function
  cardTargetOf(`, or `function maybeOpen(` — all are span anchors (`spanOf` throws on reorder).
  Chip module state (`chipEl`, `chipAnchor`, `chipGen`, `lastChip`, `suppressChipUntil`) is
  declared **after** `let filling = false`, never between it and `nativeValueSetter`.
- `[U12]`: the chip's field→form resolver must NOT sit between `function cardFormBySig(` and
  `function applyCardFill(`, nor between `async function fillCardIntoForm(` and the
  `// ---- G2 save-card capture` banner — **any** `[0]` in those spans (including
  `composedPath()[0]`) reds the negative assertions. Correct home: beside `cardFormForInput`
  (content.ts:495).
- `[V4]`: place `cardChipOffer` **inside** the `refreshTabBadge` → `/** Popup ONLY:` span, so that
  span's existing negatives (`not.toContain("await topOrigin(")`, `not.toMatch(/tab\.url/)`)
  enforce the [A4] discipline on the new gate for free.
- `[U15]`: the C2 gate must not build a set named `declared` (exactly-one pin) — it uses
  `eligibleCardFrames(tabId, top).length > 0` + `session.items.some(i => i.doc.type === "card")`.

**[S7]/[S8] Security pins (make the bad shapes TYPE ERRORS, not review catches):** the
`cardChipOffer` REQUEST literal in messages.ts is exactly `{ type: "cardChipOffer" }` — no `host`,
no `kinds`, no `frameId` member ([A2]: a page-controlled member is the shape already struck once);
its Res branch matches only `{ fillable: boolean; locked: boolean }` (no `string` type in the
branch); `showCardChip`'s state parameter is typed `{ locked: boolean }`; the
`showCardChip`→`closeCardChip` span reads no `state.` member other than `state.locked` and builds
its labels from string LITERALS (no template literal, no `.textContent =` from a non-literal); the
`openPopupForCards` span references neither `cardGrants` nor `session.items` nor `doc` (the click
MUST NOT pre-mint, pre-select, or enumerate — [A5] stays a popup-only mint); and **[S8] the chip
handler contains neither `tab.url` nor `topOrigin(`** (the existing [A4] pin is scoped to the
`onUpdated` handler and the [V4] pin to `refreshTabBadge` — neither would catch a new handler, and
this is the exact defect class the Tier-3 review-fold caught in the badge: a `tab.url` read that
works on broad-grant installs and silently fails on per-site grants).

**New pins (the old (a)/(c) were unenforceable prose):** a `showCardChip`→`closeCardChip` span
containing none of `MatchItem|CardItem|subtitle|number|cvv|expiry|postal|brand`; the
`showCardChip(anchor, state: { locked: boolean }` signature; **`attachShadow(` appears exactly
once** in content-ui.ts ([K6]); an `openPopupForCards` span with no `tabs.create|windows.create`
and a literal `return { opened: … }`; the two message shapes carrying no value fields;
`"cardChipOffer"` present in `PASSIVE_MSGS` ([K13]).

- `formFor`/`maybeOpen`/login-dropdown behavior otherwise unchanged (the chip is a parallel path).
- verify.sh unchanged. **Bundle: measured, not estimated** — RELEASE `dist/content.js` is
  **46,719 B** against `CONTENT_JS_CAP = 61,440` → **14.4 KiB headroom**; a ~2 KiB chip is
  comfortable. Caveat: `UI_CSS` is a template literal esbuild does NOT minify, so chip CSS costs
  full byte weight; the cap is enforced at package time only (`verify.sh` does not run it).

## Found en route (OUT OF SCOPE — separate line item)

On a `type=password`-CVV checkout the **login dropdown already opens on the CVV and cardholder-name
fields today** ([K1]'s mechanism), because `suppressSave` gags only the capture path, not
`maybeOpen`. That is a shipped UX bug independent of this feature and deserves its own fix.
