# A1 — accessibility across all four clients (design, 2026-07-11) → web/android/desktop 0.15.0, extension 0.11.0

> Input: 45 adversarially-confirmed findings (2026-07-11 quad-sweep at HEAD `d69af1c`) —
> 23 in `a1-findings.json` (web 9 / android 6 / desktop 8, incl. the sweep's only P1
> `a11yweb-01`) + 22 in `a1-extension-findings.md` (0 P1 / 9 P2 / 13 P3). This batch makes
> andvari usable by household members who rely on a screen reader (TalkBack / VoiceOver /
> NVDA / Java Access Bridge), keyboard-only navigation, or larger text / higher contrast —
> older members most of all. **Zero server changes, zero core/crypto changes, zero wire or
> storage-format changes.** Every fix is additive UI markup, a semantics modifier, a focus
> hint, or a colour token. The four clients' a11y is fully independent — **there is NO shared
> seam and NO pinned cross-file contract** (§Builder split says so explicitly); the only
> four-way coupling is the release-version lockstep, handled once at ship.

## Ground truth — the static-read caveat that shapes the whole design

Every one of the 45 findings is a **static code-read**. No rendered-DOM pass, no live TalkBack
run, no Access-Bridge trace was taken. That is fine for *locating* the gaps (a null
`contentDescription`, a placeholder-only input, a `color=error` on `errorContainer` are all
true in source) but it means a green *static* gate can lie: a live region that is not in the
accessibility tree at the moment its text changes is silent even though the `role="status"`
attribute is present; a `Modifier.semantics { liveRegion }` that compiles announces nothing if
the Composable never recomposes on the state it guards. So this design states, per pattern,
**how each fix is actually confirmed** — static string assertion, *computed* contrast ratio,
or a named runtime smoke — and §Test-harness reality pins which patterns have NO automated
proof at all (Android has no unit harness; desktop is not even in `verify.sh`). Builders and
the verify step must treat "the attribute is in the markup" and "the screen reader speaks it"
as two different claims.

The house also learned this the hard way: **display-state lifts need their gates lifted too**,
**frame-stale Compose `enabled` flags are a recurring race class**, and **check imports before
adding** — the android/desktop semantics APIs below are genuinely absent today (grep-verified),
so every idiom names its import.

## 1 — Cross-client principles (the 6 the 45 findings collapse into)

| # | Principle | WCAG anchor |
|---|-----------|-------------|
| **P1** | **Every input is programmatically named.** A control's visible label is *associated* with it (`for`/`id`, wrapping, or a merged Compose row), so a screen reader speaks the label when the control is focused — never "edit box, blank". A bare checkbox/radio/switch beside sibling text is a P1 failure: the text is neither the control's name nor part of its hit target. | 1.3.1, 4.1.2, 2.5.5 |
| **P2** | **Every async status/error surface is a live region.** Anything that appears/changes without a view change — error strips, "copied ✓", import progress, the 426 banner, lock notices, a 2FA-code clipboard fallback — announces itself. | 4.1.3 |
| **P3** | **Every icon-only / value-only control has a stable accessible name (and speaks its state).** Reveal toggles say "Show/Hide", copy buttons say "copy", and a control whose visible text is a live value (a TOTP code, a password) does not re-announce every second nor name itself with the secret. | 1.1.1, 4.1.2 |
| **P4** | **Focus never silently drops to `<body>`, and every operable target is keyboard-reachable.** A view/layer/lock change moves focus to a real element; an inline confirm swap doesn't strand focus; menus release Tab; clickable rows are real buttons; dialogs open with a field focused. | 2.1.1, 2.4.3, 2.4.7 |
| **P5** | **State is never conveyed by colour (or a `title` tooltip) alone.** Connectivity, selected tab/nav, expanded/pressed, countdown — each carries a text or ARIA-state alternative reachable by AT, keyboard, and touch. | 1.4.1, 4.1.2 |
| **P6** | **Text and UI-boundary contrast meet WCAG AA.** Body/label text ≥ 4.5:1; the visual boundary *required* to identify a control ≥ 3:1 — verified by *computed* ratio, not by eye. | 1.4.3, 1.4.11 |

### Finding → principle map (all 45, nothing orphaned)

| Principle | Web | Android | Desktop | Extension |
|-----------|-----|---------|---------|-----------|
| **P1** label/association | a11yweb-01 | a11yand-03 | a11ydesk-03, a11ydesk-07 | 1a, 1b |
| **P2** live region | a11yweb-02 | a11yand-01, a11yand-04 | — *(none confirmed)* | 2a, 2b, 2c, 2d, 6d |
| **P3** icon/value name + state | a11yweb-07, a11yweb-09 | a11yand-02, a11yand-05, a11yand-06 | a11ydesk-02, a11ydesk-08 | 3a, 3b, 3c, 3d, 3e |
| **P4** focus / keyboard | a11yweb-06, a11yweb-08 | — | a11ydesk-04, a11ydesk-05, a11ydesk-06 | 4a, 6a, 6b, 6c |
| **P5** no colour-alone | a11yweb-04, a11yweb-05 | — | — | 5a, 5b, 5c |
| **P6** contrast | a11yweb-03 | — | a11ydesk-01 | 7a, 7b, 7c |

Count: 9 + 6 + 8 + 22 = 45. (Android has no confirmed contrast or colour-alone finding; desktop
has no confirmed live-region or colour-alone finding — the catalog still defines those idioms
so future surfaces inherit them.)

## 2 — Per-client pattern catalog (verified against the real API + existing conventions)

Each idiom cites **one canonical example the builder copies** and the exact new import where the
convention is new. Grep confirmed the finders' "zero" claims: web has **zero `useId`, zero
`htmlFor`, zero `aria-live`**; android has **zero `semantics`/`Role`/`toggleable`/`liveRegion`
imports**; desktop has **zero `FocusRequester`/`semantics`/`Role`**. These are new house
conventions — defined once here.

### 2.1 Web (`web/src/ui/`, React 18.3.1, vitest node-env)

Existing good conventions to mirror: the labeled icon-button at **`Vault.tsx:507-513`**
(`aria-label` + `title` + `aria-hidden` SVG) and the wrapping `.check` label at
**`Welcome.tsx:397-399`**. The `.field` idiom today is a *bare sibling* label
(`Welcome.tsx:98-101`: `<div className="field"><label>Master password</label><input/></div>`) —
that is exactly the P1 gap.

**P1 — the `Field` helper (new, `web/src/ui/Field.tsx`).** `label` CSS is already
`display:block` (`styles.css:123`), so a `for`/`id` pair is a drop-in for the ~70 `.field`
blocks:

```tsx
import { cloneElement, type ReactElement, type ReactNode, useId } from "react";
export function Field({ label, children }: { label: ReactNode; children: ReactElement }) {
  const id = useId();                                    // React 18 SSR-stable id
  return <div className="field"><label htmlFor={id}>{label}</label>{cloneElement(children, { id })}</div>;
}
```

`label` is `ReactNode` so the copy-flash sibling survives (`Vault.tsx:888`
`<label>Password {flash && <span className="copy-flash">copied ✓</span>}</label>`). Mechanically
replace `.field` blocks in `Welcome.tsx`, `Settings.tsx`, `ExportPanel.tsx`, `Admin.tsx`,
`Devices.tsx`, `Sharing.tsx`, `Vault.tsx` (incl. the editor fields `Vault.tsx:1513-1515`). Two
controls have no label element at all and take `aria-label` instead of `Field`: the vault search
input (`Vault.tsx:489` → `aria-label="Search vault"`) and the Sharing member-role `<select>`
(`Sharing.tsx:408` → `aria-label={\`Role for ${m.email}\`}`).

**P2 — the `Msg` live region (new, `web/src/ui/Msg.tsx`).** Replaces the ~30 inline
`.msg err`/`.msg info` divs:

```tsx
export function Msg({ kind, children }: { kind: "err" | "info"; children: ReactNode }) {
  return <div className={`msg ${kind}`} role={kind === "err" ? "alert" : "status"}>{children}</div>;
}
```

`role="alert"` (assertive) for errors, `role="status"` (polite) for info. Separately:
`role="status"` on the 426 banner (`App.tsx:218`) and the copy-flash span (`Vault.tsx:888`);
wrap the import-progress label (`Vault.tsx:2075-2081`) in `aria-live="polite"` **announcing only
on mount + completion, not per tick** (throttle, or SR spam).

**P3 — icon/value names.** Copy `Vault.tsx:507-513`. TOTP control (`Vault.tsx:1323`):
`aria-label={\`One-time code ${code.replace(/\s/g, "")} — copy\`}` on the button, `aria-hidden="true"`
on the ring (`:1324`, updates every second — must NOT be a live region). Health rows
(`Health.tsx:136`): add `role="button"` + `aria-label={\`Open ${r.name}\`}` (the focus ring at
`styles.css:310-312` was already built for these rows).

**P4 — `aria-current`/menu-Tab.** Export menu (`Vault.tsx:797` `onMenuKey`): add
`else if (e.key === "Tab") setOpen(false);` — close without `preventDefault`, Tab proceeds (WAI-ARIA
menu-button pattern). Focus-return on confirm-swap/layer-transition (a11yweb-06) is the one web
item that is **not** static-testable (it is `useEffect` + `.focus()`, and `renderToStaticMarkup`
runs no effects) → **deferred to A1b** (§3).

**P5 — state text.** Conn dot (`Vault.tsx:370`): add `role="status"` + `aria-label={title}` to the
`.who` span (or a visually-hidden twin) so the flip is announced. Selected nav/tab:
`aria-current={view === v ? "page" : undefined}` on navBtn (`Vault.tsx:333`); `aria-pressed={tab === "signin"}`
on the Welcome tabs (`Welcome.tsx:163-164`) and Admin tabs (`Admin.tsx:27`).

**P6 — contrast tokens (`styles.css` only; computed, pinned).** Dark `:17`
`--ink-faint #6f6752 → #8d8370` (**5.00** on `--bg`, **4.59** on `--bg-raised`). Light `:41`
`--ink-faint #9a8f74 → #786c50` (**4.51** on `--bg` — the tight one; **4.88** on `--bg-raised`).
Light link/`--gold`: darken `:42 --gold #9a7420 → #7d5e14` (**5.26** on `--bg`, **5.68** on
`--bg-raised`) and **re-verify the other `--gold` consumers** (`:82,:105,:235,:250,:294`) still
read acceptably on their surfaces. Dark `--gold` link stays (7.73 on `--bg-raised`, passes). *Do
not* use the finder's rejected `#8a8069/#7d7156`.

### 2.2 Android (`app-android/src/main/kotlin/io/silencelen/andvari/app/`, Compose + Material3)

Canonical labeled example: **`MainActivity.kt:709`** `Icon(Icons.Default.FileUpload, "import CSV")`
— contentDescription is the **positional 2nd arg** of `Icon`. New imports this batch (all absent
today): `androidx.compose.ui.semantics.semantics`, `.liveRegion`, `.LiveRegionMode`,
`.clearAndSetSemantics`, `.Role`, `.stateDescription`, `androidx.compose.foundation.selection.toggleable`,
`.selectable`.

**P2 — live regions.** `Modifier.semantics { liveRegion = LiveRegionMode.Assertive }` on the
ErrorBar `Card` (`:378`); `LiveRegionMode.Polite` on the NoticeBar `Card` (`:390`), `InlineError`
`Text` (`:1916`), and the enroll verdict `Text`s (`:503`/`:506`). Route the inline validation lines
(e.g. `:487`) through `InlineError` so the announce lives in one place.

**P1 — toggleable/selectable rows.** Move the interaction onto the row and null the control's own
handler so Compose merges the sibling `Text` as the name *and* gives the whole row a ≥48dp target
(fixes the touch-target shrink too):

```kotlin
Row(Modifier.padding(top = 8.dp).toggleable(value = fpOk, enabled = shortOk, role = Role.Checkbox,
      onValueChange = { fpOk = it }), verticalAlignment = Alignment.CenterVertically) {
    Checkbox(fpOk, onCheckedChange = null, enabled = shortOk); Text("This fingerprint matches…")
}
```

Sites: `Checkbox`/`Role.Checkbox` at `:508-511`, `:1779-1781`, `:1786-1788`; `selectable`/`Role.RadioButton`
+ `RadioButton(onClick = null)` at `:1383-1385` and `SharingScreen.kt:633-636`; `toggleable`/`Role.Switch`
+ `Switch(onCheckedChange = null)` at `:1957-1963` and `AutofillStatusScreen.kt:265-275`.

**P1/P4 — the disabled-consent reason (a11yand-04).** On the enroll checkbox row add
`Modifier.semantics { if (!shortOk) stateDescription = "Type the 16 sheet characters above first" }`;
apply to the F57 ReSealCard gate (`:577-579`) **[breaker-corrected: ReSealCard has NO checkbox and NO
verdict Text — its gate is a disabled `PrimaryButton(enabled = ok && !ui.busy)` at :578; target the
hint there, see AM-5]**. (The `enabled=shortOk` flag is ~~a frame-stale gate — recompute it in the
same scope~~ **[breaker-corrected: `shortOk` (:465) is an inline-recomputed `val`, not `remember`ed —
already correct; no recompute needed]**.)

**P3 — reveal names + value-node hygiene.** Reveal toggles (`:2015`, `:2038`):
`Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, if (show) "Hide $label" else "Show $label")`
— the description doubles as the shown/hidden state. TotpRow (`:1410-1413`): on the copy `TextButton`
set `Modifier.semantics { contentDescription = "One-time code, double-tap to copy" }`; wrap the
per-second countdown `Text` in `Modifier.clearAndSetSemantics {}` (stable — preferred over the
experimental `invisibleToUser()`) so it stops re-announcing. AutofillStatus StatusRow/KeyValue
(`AutofillStatusScreen.kt:394`, `:408`): `Modifier.clearAndSetSemantics {}` on the decorative "●"
`Text`, and `Modifier.semantics(mergeDescendants = true) {}` on the Row so each reads as one
"label: yes/no" stop.

No contrast finding on Android → **no token edit** (Material3 defaults are already AA on this palette).

### 2.3 Desktop (`app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/`, Compose-for-Desktop)

Canonical labeled example: **`Ui.kt:377-382`** `Icon(Icons.Default.FileUpload, "import passwords")`
(positional). The F72 keyboard doctrine is written at **`Ui.kt:2189-2196`**: Enter attaches to a
form's single-line *field* (never a container); Escape MAY wrap a whole dialog. The house helpers
already exist — **reuse, don't reinvent**: `Modifier.submitOnEnter(submit)` (`Ui.kt:2202`) and
`Modifier.dismissOnEscape(dismiss)` (`Ui.kt:2210`), already threaded through the shared `Field`
(`:2218`) and `Secret` (`:2225`). **Access-Bridge honesty:** on the Windows MSI, AT reaches Compose
via the Java Access Bridge; on the Linux deb, via AT-SPI. Both surface Compose semantics — the
findings below are **our** gaps (null descriptions, no focus, no field labels), *not* Access-Bridge
platform limits, so all are in scope.

**P6 — error contrast (a11ydesk-01; computed, pinned).** `Main.kt:36-46` sets `error` but not
`errorContainer`/`onErrorContainer`, so those inherit Material3 defaults. Painting `color=error` on
`errorContainer` gives **dark 2.56:1 / light 4.48:1** (both fail/borderline). Fix: switch
`color = MaterialTheme.colorScheme.error → onErrorContainer` at `Ui.kt:92, 137, 828, 886` (+ the Icon
tint `:881`) → **dark ~7.17:1 [breaker-corrected: was "5.34"; 5.34 is Error80 #F2B8B5, but M3 dark
onErrorContainer is Error90 #F9DEDC = 7.17] / light 12.77:1** (M3 default pairs, no palette add). **At
`:828` change ONLY the `warn`-true branch (`error`→`onErrorContainer`); the `else secondary` sub-expression
stays — it is on a default `surface`, not `errorContainer` (see breaker AM-8).** The dismiss
`TextButton` (`:138`) renders `primary` gold on `errorContainer` (**4.10:1**, fails) →
`ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onErrorContainer)`.
`Ui.kt:891` already uses `onErrorContainer` — that is the house rule these align to.

**P3 — reveal names + busy button.** `Secret`/`CopyRow` reveal (`Ui.kt:2228`, `:2239`):
`Icon(…, if (show) "hide value" else "show value")`. `Primary` while busy (`:2262-2265`) replaces its
text with a bare spinner → render the `Text` alongside the indicator, or add
`Modifier.semantics { contentDescription = text; stateDescription = "working" }` to the
`CircularProgressIndicator`.

**P1 — search label + checkbox rows.** Search field (`Ui.kt:428`): add `label = { Text("Search vault") }`
(keep the placeholder). Bare checkbox rows (`Ui.kt:302`, `:2004`, `:2011`): the Android P1 idiom
verbatim — `Row(Modifier.toggleable(value, role = Role.Checkbox, onValueChange = …)) { Checkbox(onCheckedChange = null); Text(...) }`
(new imports `androidx.compose.foundation.selection.toggleable`, `androidx.compose.ui.semantics.Role` —
desktop has none today). This ports web F80 (bare ExportPanel checkbox labels) to desktop, which
`docs/v6-backlog.md:139` scoped web-only.

**P4 — F72 keyboard affordances (a11ydesk-04).** The 0.14.0 vault-management flows missed them:
`.submitOnEnter(save)` on the Rename field (`Ui.kt:1126`, carrying its existing
`!busy && name.trim().isNotEmpty()` gate); `.dismissOnEscape(cancel)` on the Rename editor Column
(`:1125`) and DeleteVaultControl Column (`:1222`) — matching MoveCopyControl (`:1542`).
Enter-to-delete stays absent (destructive) — correct.

**P4 — initial focus (a11ydesk-06, BOUNDED slice in A1).** Desktop has **zero** `FocusRequester`,
so Unlock opens with focus on nothing — every unlock is a Tab-hunt into the password field, defeating
F72's "most-repeated interaction" optimization (`Ui.kt:327-329`). New convention: an optional
`autoFocus` on the shared `Field`/`Secret` (`:2218`/`:2225`):

```kotlin
val fr = remember { FocusRequester() }
LaunchedEffect(Unit) { fr.requestFocus() }
// …Modifier.focusRequester(fr) on the first field
```

(imports `androidx.compose.ui.focus.FocusRequester`, `.focusRequester`). Wire it on the first field of
Unlock (`:340`), SignIn (`:223`), Enroll, and the typed-entry dialogs (TOTP Confirm `:2152`, backup
passphrase, typed-confirm delete). **Focus-return/restoration on close is NOT in this slice → A1b.**

**P4 — keyboard scroll of expanded help (a11ydesk-05).** Give each ImportHelp source a **focusable
header** (`Ui.kt:507-517`, and the preview buckets `:549-596`) so `Tab` + `bringIntoView` traverses
past the dialog height — the low-risk structural fix. The custom `onPreviewKeyEvent`
PageUp/PageDown scroll driver is the heavier alternative → A1b only.

### 2.4 Extension (`extension/`, MV3 popup + content script) — same idioms as web

The popup is DOM, but there is **no jsdom** and the tokens in `popup.css` are **ported verbatim from
`web/src/ui/styles.css`** (identical `--ink-faint #6f6752`), so the contrast fix is literally web's.
The whole extension has exactly one ARIA attribute today (`role="button"` on the login row,
`popup.ts:216`).

**P1 — labels.** `#search` (`popup.html:54`, placeholder-only "Search the hoard…") and the injected
"Search all logins" input (`content-ui.ts:327-331`): add a visually-hidden `<label>` or `aria-label`.
(`#email`/`#password` are already correctly `<label for>`-associated — the pattern exists.)

**P2 — live regions.** The shared `#msg` strip (`popup.html:82`, `popup.ts:41-46 showMsg`) carries
wrong-password, ping, and F26 lock lines and is silent. In `showMsg`:

```ts
m.hidden = false;                                         // present in the a11y tree BEFORE the text change
m.setAttribute("role", kind === "err" ? "alert" : "status");
m.textContent = text;
```

Order matters (the static-read caveat): a `role="status"` region must be in the tree *before* its
text mutates, or the first message is dropped; unhide → set role → set text. Also: `role="status"` on
`#update` (`:16`); `role="alert"` (or focus-on-appear) on `#must-change` (`:27`); one
`aria-live="polite"` region for copy flashes (`#gen-flash` `:63`, TOTP "copied" `popup.ts:483`); and
`role="status"` on the content-script toast root (`content-ui.ts:478-491`) — **assertive** for the
clipboard-fail fallback that shows a 2FA code only in a 5-second toast (a11yext-6d, a real safety gap).

**P3 — icon/value names.** `actBtn` (`popup.ts:388`): set `aria-label` to the (currently overridden)
`title` so username vs password copy are distinguishable. `totpChip` (`:460`):
`aria-label="Copy one-time code"` + `aria-hidden` the live digit span. `#gen-toggle` (`:55`):
`aria-label="Password generator"` + `aria-hidden` the "⚄" glyph. `#gen-pass` (`:60`):
`aria-label="Copy generated password"`.

**P4 — focus on relock (a11yext-4a).** `relocked()` (`popup.ts:147-150`) hides the unlocked view
without moving focus → focus falls to `<body>`. The other transitions are already clean (open →
`#email`; list → detail → Back; detail → list → `#search`), so this is **parity, not rework**: add
`el("email").focus()` in `relocked()` + announce via the `#msg` live region.

**P5 — colour-alone state.** `#conn` dot (`popup.html:11`): `role="img"` + updating `aria-label`, or a
visually-hidden text twin (the `title` on a non-interactive `<span>` is unreliable to AT and
unfocusable). TOTP ring (`popup.css:276-278`, `popup.ts:522`): a visually-hidden "N seconds left" or
`role="progressbar"` `aria-valuenow` driven by `--p`. `#gen-toggle` (`:55`, `popup.ts:619-624`): add
`aria-expanded` + `aria-controls="generator"`.

**P6 — contrast (`popup.css`; computed).** `7a` text: bump `--ink-faint → #8d8370` dark / `#786c50`
light **(identical to web — keep the two token files in sync)**; covers `label :100`,
`.section-label :181`, `.kdf .cap :168`, `.link.dim :289`, `.muted :291` (4.5–5.0:1). `7b` placeholder:
the real fix is the P1 label; additionally set `input::placeholder { color: var(--ink-dim); }` (`:108`)
→ dark ~6.3:1, light high. `7c` UI-boundary borders (`--edge` at ~1.2–1.5:1) → **owner/defer** (§3):
the treasury hairline can't reach 3:1 without a visible redesign.

## 3 — Scope triage: the A1 cut line

**A1 ships the S-sized mechanical fixes across all four clients** — labels, `contentDescription`,
live regions, contrast tokens, `aria-current`/`selected`, toggleable rows, icon names, min-touch. They
are high-volume, low-risk, and mostly static- or contrast-testable. **The M-sized interaction/focus
reworks get their own care in a named follow-up, A1b — "interaction & focus rework".**

| Finding | Size | Verdict | Why |
|---|---|---|---|
| a11yweb-01…05, 07, 08, 09 | S–M | **A1** | Mechanical markup; static- or contrast-testable |
| a11yand-01…06 | S–M | **A1** | Mechanical semantics; compile + TalkBack smoke |
| a11ydesk-01, 02, 03, 04, 07, 08 | S | **A1** | Token / reveal / reuse existing helpers / label / busy-name |
| a11ydesk-05 | S | **A1** (structural) | Focusable help headers; custom key-scroll variant → A1b |
| a11ydesk-06 | M | **A1 (bounded) + A1b** | Ship initial-focus on auth screens/dialogs; focus-return → A1b |
| a11yext-1a/1b, 2a–2d, 3a–3d, 4a, 5a–5c, 6d, 7a, 7b | S | **A1** | Mechanical markup / live region / contrast |
| **a11yweb-06** | M | **A1b** | Focus-return on confirm-swap/layer-transition; effects run under no web test harness |
| **a11yext-6a + 6b** | M | **A1b** | In-page dropdown keyboard nav (roving tabindex + `role=listbox/option`); the **popup is a full keyboard alternative** so it is not blocking; container `role` (6b) must travel with the operable options or it misleads |
| **a11yext-6c** | M | **A1b** + **owner Q** | In-page save prompt as `alertdialog` + focus — needs a UX call (below) |
| **a11yext-3e** | P3 | **A1b** | Row nested-`<button>` restructure is entangled with the row/detail interaction model; row already works |
| **a11yext-7c** | S-token | **owner/defer** | Cannot reach 3:1 without an aesthetic change (below) |

**No findings are dropped** — all 45 are legitimate AA/usability gaps. The two lowest-value / most
awkward (a11ydesk-05's keyboard-scroll edge; a11yext-3e's name-noise) are flagged "defer-and-reassess"
— droppable in A1b only if the fix proves disproportionate to the audience.

### Owner decisions — SETTLED 2026-07-11

- **7c (boundary contrast) — RESOLVED: owner chose option (iii), defer to a high-contrast mode
  (A2).** A1 ships the text-contrast tokens only (7a/7b); the treasury-hairline UI-boundary
  outlines stay as-is. Builder X does NOT touch `--edge`/border tokens this cut.
- **a11ydesk-06 (desktop focus) — default taken: ship the BOUNDED initial-focus slice** (focus
  the first field on Unlock/SignIn/Enroll + typed-entry dialogs); focus-return → A1b.
- **a11yext-6c (in-page save-prompt focus) — defers to A1b regardless; the focus-steal-vs-
  announce question is an A1b decision** (recommended default there: announce-only, no steal,
  keep timers). Not an A1 concern.

Original framing kept below for the A1b record.

1. **a11yext-6c — should the in-page save/update prompt *steal* keyboard focus to its primary button
   when it appears, and should announcing it *pause* the 30 s/20 s auto-dismiss?** Stealing focus helps
   a blind member find "Save this login?" (today it vanishes before they can Tab to it) but yanks focus
   from a sighted member mid-typing — a genuine tradeoff. *Recommended default:* announce via a polite
   off-screen live region on show, **no** focus steal, keep the timers; revisit if a real user reports
   the prompt is missed. This feeds A1b.
2. **a11yext-7c — UI-boundary contrast vs the treasury aesthetic.** Even the strongest tasteful edge
   (`#5c5236` dark / `#a99a72` light) reaches only ~2.1–2.8:1 against the deliberately near-invisible
   hairline fills — WCAG 1.4.11 wants 3:1. Options: (i) accept a visibly heavier 3:1 border (a design
   change the designer must bless), (ii) ship a stronger-but-still-<3:1 edge as a partial improvement
   (does not meet AA), or (iii) **defer to a dedicated high-contrast / large-text mode (A2)**.
   *Recommended default:* (iii) — a partial bump neither meets AA nor is worth an aesthetic regression;
   the cleanly-hittable text tokens (7a/7b) still ship in A1.
3. **a11ydesk-06 cut line (soft).** A1 ships the *bounded* initial-focus slice (focus the first field on
   Unlock/SignIn/Enroll + typed-entry dialogs) and defers focus-return to A1b. If the owner prefers
   symmetry with web (defer *all* desktop focus to A1b), that is a one-line scope move — flagged so it is
   a choice, not an accident. *Recommended:* ship the bounded slice — it is additive, low-risk, and the
   single highest-value keyboard win for the target user.

## 4 — Test-harness reality per platform (verified by reading build files)

| Client | Harness (verified) | What IS provable automatically | What is smoke-ONLY |
|---|---|---|---|
| **Web** | vitest, **`environment: "node"`** (`web/vitest.config.ts`) — **no jsdom, no @testing-library**. House pattern: `renderToStaticMarkup(createElement(C, props))` + string assertions (`Devices.test.ts:125`, `QrSvg.test.ts:32`) | **Static aria**: label `for`/`id` association, `role=status/alert`, `aria-current`, `aria-pressed`, `aria-label` (assert the rendered HTML string). **Contrast**: pure ratio unit test parsing `styles.css`. | **Focus** (a11yweb-06): effects/`focus()` don't run under `renderToStaticMarkup` → keyboard smoke only. Live-region *announcement* (vs the attribute) → NVDA smoke. |
| **Android** | **Zero test deps** in `build.gradle.kts` (no `ui-test-junit4`, no test/androidTest source set). `verify.sh:28` gate = **`:app-android:assembleDebug` (compile only)** | **Nothing about semantics** is asserted. Compile catches missing imports (the "check imports" lesson). | **All** contentDescription/liveRegion/toggleable correctness → **TalkBack smoke** (no unit harness exists). |
| **Desktop** | **Zero test deps, no test source set, and `app-desktop` is NOT in `verify.sh` at all** | **Nothing** — no gate runs. Contrast is proven by **computed ratio, pinned in this doc** (§2.3) + a `Main.kt`/`Ui.kt` comment. | Everything: builder must run **`./gradlew :app-desktop:compileKotlin`** locally (recommend adding it to `verify.sh` — a cheap win), then **Access-Bridge (Windows MSI) / AT-SPI+Orca (Linux deb)** smoke. |
| **Extension** | `node --test "src/**/*.test.ts"` (`package.json:10`), node v22 runs `.ts` directly; existing `contrast`-free suites | **Contrast**: pure `node --test` parsing `popup.css` (new `extension/src/contrast.test.ts`, mirror web). Any extracted pure helper. | DOM aria (role attrs, live-region wiring, `relocked()` focus) → **load-unpacked + NVDA (Chrome/Edge)** smoke. |

**Contrast is computable → pin it as a unit test on every client with a token file** (web `styles.css`,
extension `popup.css`). The test reads the token file, extracts the `:root` + light-media hex values,
computes the WCAG relative-luminance ratio for each (token, surface) pair, and asserts against the
values pinned in §2 (web: `≥4.5` on both surfaces for `--ink-faint`, the light-link pairs; extension:
same). Android has no token change; **desktop has no harness** so its ratios are pinned in this doc and
in a code comment, verified by the `scratchpad/contrast-a1.js` script the values were derived from
(dark ~7.17 [breaker-corrected: was "5.34" — wrong M3 token; #F9DEDC on #8C1D18 = 7.17] / light 12.77
for `onErrorContainer`; both pass AA, fix sound).

**The concrete smoke, per client** (this is the *only* proof for focus + actual announcement, so it is
mandatory, not optional):

- **Web (NVDA, Chrome):** unlock screen — Tab lands on a *named* password field; type a wrong password →
  the error is *spoken* (not just present); open an item → every editor field speaks its label; copy a
  field → "copied" is spoken; switch nav → the active view is announced (`aria-current`).
- **Android (TalkBack):** enroll — the match/mismatch verdict is spoken as you type; the consent row reads
  "This fingerprint matches…, checkbox, not checked" and the *whole row* toggles; a reveal button reads
  "Show/Hide password"; a TOTP row does not re-announce every second; an autofill-status line is one stop.
- **Desktop (Access Bridge on the owner's Windows MSI build):** Unlock opens with the password field
  focused; a reveal button is named; the rename field submits on Enter and both editors close on Escape;
  an error strip is legible (contrast).
- **Extension (NVDA, Chrome load-unpacked):** wrong master password is spoken; the search field is named;
  copy buttons say "copy username"/"copy password" distinctly; the generator toggle says "Password
  generator, collapsed/expanded"; an idle relock returns focus to the email field.

## 5 — Builder split (4 fully disjoint builders; NO shared seam)

Unlike E1, **each client's accessibility is independent — there is no shared file, no cross-file symbol,
and no pinned name contract.** The only four-way coupling is the release-version lockstep (§6), which is a
single prep edit, not a code seam. Each builder runs its own gate at handback and touches only its own
tree.

- **Builder W — web.** `web/src/ui/` — **new** `Field.tsx`, `Msg.tsx`; edits to `Welcome.tsx`,
  `Settings.tsx`, `ExportPanel.tsx`, `Admin.tsx`, `Devices.tsx`, `Sharing.tsx`, `Vault.tsx`, `Health.tsx`,
  `App.tsx`. **Theme/token file: `web/src/ui/styles.css`** (a11yweb-03). **New tests:** `Field.test.ts`
  (label/id association via `renderToStaticMarkup`), `contrast.test.ts` (parse `styles.css`). Gate:
  `npx vitest run && npx tsc --noEmit`.
- **Builder A — android.** `app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt`,
  `AutofillStatusScreen.kt`, `SharingScreen.kt`. **No token file.** Gate: `./gradlew :app-android:assembleDebug`
  + TalkBack smoke.
- **Builder D — desktop.** `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt` (all fixes);
  **`Main.kt` only if** the owner opts for the palette-consistent `errorContainer` override instead of the
  M3 default (a11ydesk-01 — the canonical fix is `onErrorContainer` in `Ui.kt`, no `Main.kt` edit). Gate:
  `./gradlew :app-desktop:compileKotlin` (run manually — not in `verify.sh`) + Access-Bridge smoke.
- **Builder X — extension.** `extension/popup.html`, `extension/src/popup.ts`, `extension/src/content-ui.ts`
  (6d toast live region only — 6a/6b/6c/3e defer). **Theme/token file: `extension/popup.css`** (7a/7b).
  **New test:** `extension/src/contrast.test.ts`. Gate: `npm run typecheck && npm test`.

Builders W, D, and X each also bump their own release-version constant (§6). No builder edits another's
files; no `renderToStaticMarkup` fixture is shared; the extension `contrast.test.ts` and web
`contrast.test.ts` are independent copies of the same 20-line luminance helper (parity by convention, not
by import — there is no build path between the trees).

## 6 — Version bump + ship (multi-surface)

**Bump: minor.** web/android/desktop 0.14.2 → **0.15.0**; extension 0.10.0 → **0.11.0**. Justification:
accessibility is a distinct *new capability class* (the product becomes usable by screen-reader,
keyboard-only, and low-vision members), additive, with **zero wire/format/schema change** and nothing
removed — the only visible deltas are slightly stronger faint-text contrast and larger toggle hit-targets,
both improvements. Patch would under-signal a whole new usability surface; the house precedent for a
themed additive batch is E1's extension minor (0.9.0 → 0.10.0). Minor it is.

**Version-lockstep gate (`verify.sh:14-21`) requires core = android = desktop = web.** Bump all four in
one prep edit so the gate never goes red mid-batch:

1. `core/src/commonMain/kotlin/io/silencelen/andvari/core/client/AndvariApi.kt:81` — `ANDVARI_CLIENT_VERSION`
   (the SSOT; `DESKTOP_VERSION` and `SERVER_VERSION` alias it)
2. `app-android/build.gradle.kts:28` — `versionName`
3. `app-desktop/build.gradle.kts:29` — `packageVersion`
4. `web/src/api/client.ts:40` — `CLIENT_VERSION`

**The extension versions independently** — its three hand-edited sites move to 0.11.0 on their own track,
untouched by the lockstep gate: `extension/manifest.json:5`, `extension/manifest.firefox.json:4`,
`extension/package.json:3` (its `version.test.ts` already asserts the three agree).

**CHANGELOG (owner-voice, house style — a `## 0.15.0` cross-platform entry + a `### browser extension
0.11.0` subsection):**

> ## 0.15.0 — andvari for everyone: screen readers, keyboards, and bigger, clearer text (2026-07-11, cross-platform cut)
>
> This release makes andvari usable by family members who navigate with a screen reader, use only a
> keyboard, or need larger, higher-contrast text — including our older members.
>
> - **Every field now says its name.** A screen reader used to read the sign-in, item-editor, sharing,
>   and settings boxes as blank "edit boxes"; now each speaks its label, and search boxes and the member-
>   role picker are named too.
> - **The app speaks up when something happens.** Wrong-password and error messages, "copied ✓", import
>   progress, and lock notices are now announced instead of appearing in silence.
> - **Buttons that were just icons now have names** — show/hide-password, copy, one-time-code, and the
>   password generator — and a one-time code no longer reads out its digits over and over.
> - **Tapping a label works** (the checkbox/switch and its text are now one target, and a comfortable
>   size for larger fingertips), the active screen and tabs are announced, and connectivity is no longer a
>   colour-only dot.
> - **Faint helper text and links now meet contrast standards** in both light and dark themes.
> - **Desktop:** unlocking now starts with your cursor already in the password box, rename saves on Enter
>   and dialogs close on Escape, and the error banners are readable.
>
> ### browser extension 0.11.0 — the same accessibility pass reaches the popup
>
> - The popup's fields are named, its status and error line and "copied" confirmations are announced, its
>   icon buttons (copy, reveal, the generator die) have real names, and its faint text meets contrast in
>   both themes. Locking after idle now returns your cursor to the email box. (Keyboard navigation of the
>   in-page autofill dropdown, and the in-page "Save this login?" prompt, land in a follow-up — the popup
>   already covers those flows for keyboard and screen-reader users.)

**Ship path per surface:**

- **Web (this cycle's live deploy):** `ops/deploy.sh` — builds the web dist (and, harmlessly, the
  unchanged server jar), stages on heimdall, `pct push`/tars into **CT 122**, restarts `andvari.service`.
- **Extension:** `npm run package` → `artifacts/andvari-extension-{chrome,firefox}-0.11.0.zip` → scp to
  heimdall → `pct push 122` both zips into `/opt/andvari/downloads/` → **MERGE (never overwrite)** the
  `browserExtension` key into `/opt/andvari/downloads/manifest.json` via the read-modify-write python
  pattern (preserving the `linux`/`windows` keys) → chown → verify
  `https://andvari.taila2dff2.ts.net/downloads/manifest.json` shows all three keys.
- **Android APK / desktop deb + MSI — OWNER release steps (noted, not performed here):** the Android APK
  (`assembleRelease`, signed via `~/.andvari/keystore.properties`) and the desktop `packageDeb` /
  `packageMsi` are owner-driven build+publish steps; this design does not build them. Their contrast/focus
  fixes are proven only by the owner's build + the Access-Bridge/TalkBack smoke in §4.

## 7 — Out of scope (A1 does NOT do)

- **Native iOS / VoiceOver** — there is no iOS client.
- **The deferred interaction reworks → A1b:** web focus-return on confirm-swap/layer-transition
  (a11yweb-06); the extension in-page autofill dropdown keyboard navigation (a11yext-6a/6b); the in-page
  save-prompt `alertdialog`+focus (a11yext-6c); the login-row nested-button restructure (a11yext-3e); the
  desktop focus-return/restoration remainder of a11ydesk-06 and the custom key-scroll variant of
  a11ydesk-05.
- **Extension UI-boundary contrast (a11yext-7c) and any "high-contrast / large-text mode" → A2** (owner
  decision above) — A1 does the cleanly-achievable *text* contrast only.
- **200%-zoom / reflow (WCAG 1.4.10) audit** — a rendered-viewport pass, not a static one; no finding
  confirmed it and A1 takes no runtime reflow measurement.
- **Adding a jsdom / @testing-library harness to web, or a Compose `ui-test-junit4` harness to
  android/desktop** — a build-infra change of its own; A1 works within the harnesses that exist
  (`renderToStaticMarkup` for web static aria, compile+smoke for the natives) and is honest where the only
  proof is a manual screen-reader pass.
- **Server, core/crypto, wire protocol, storage format** — untouched; a11y is a pure client-UI concern.
- **`prefers-reduced-motion`, focus-visible restyling, and skip-links** — not in the confirmed finding set;
  candidate for a later cycle.

## Breaker amendments (BINDING, 2026-07-11)

Method: every cited line re-read at HEAD `d69af1c`; all contrast ratios independently recomputed
(WCAG relative-luminance, `scratchpad/contrast-check.js`); ARIA/Compose announce behavior applied
against the design's own "green static gate can lie" premise. These override the body above where
they conflict. Each names the concrete failure it prevents.

### BLOCKERS (as-written the fix does nothing / regresses / fails the gate)

- **BL-1 — web P2 polite live regions are SILENT (the design's own #1 risk, un-mitigated for web).**
  Every `.msg` site is `{cond && <div className="msg …">{text}</div>}` — *conditional mount*
  (grep-verified: Settings.tsx:173-174,281-282, Welcome.tsx:96, Vault.tsx:962/1046/1129/1209/2073,
  Sharing.tsx:271… + ~25 more). Mechanically wrapping them in `<Msg>` preserves the conditional
  mount, so the live region **enters the DOM already populated**. `role="alert"` (errors) *is*
  announced on insertion → the error path is fine. But `role="status"` (every `.msg info`, the
  copy-flash "copied ✓" span Vault.tsx:888, the 426 banner App.tsx:218, the Settings TOTP info line)
  is **polite**, and a polite region inserted already-populated is **not reliably announced** (NVDA
  especially) — copy-confirmation, enrolled-✓, and lock notices go silent. The vitest string-assert
  sees `role="status"` and passes → green gate lies. `.msg` has **no `:empty` rule** (styles.css:152),
  so "just always-render `<Msg>`" also regresses (empty padded/bordered boxes everywhere). *Fix that
  works:* drive polite announcements from a **persistent** live region — one always-mounted
  visually-hidden `<div role="status" aria-live="polite">` announcer per screen, present (empty) in
  the a11y tree at first paint, into which text is **mutated** (the extension's persistent `#msg`
  pattern). Keep the visible `.msg` box conditional for sighted users; the *announcement* must not
  ride a conditionally-mounted node. (role="alert" errors may stay conditional.)

- **BL-2 — web `Field` mis-associates (or breaks the gate) on ~10 of the enumerated `.field` blocks.**
  `cloneElement(children, { id })` only names the control when the single child **is itself a
  labelable element**. It is not, for: (a) `.secret-row`-wrapped fields — the `id` lands on the
  wrapping `<div>` and `<label htmlFor>` to a non-labelable element **associates with nothing** (still
  "edit box, blank"), yet `Field.test.ts`(bare input)+`tsc` stay green — Vault.tsx:878, 887, 909, 918,
  927, 937 (detail) and the editor password `.secret-row` inside 1523; (b) `PasswordField`
  (Vault.tsx:1274) which takes only `{value}` and **never forwards `id`** to its inner `<input>` → id
  dropped; (c) the **multi-child** editor Password field (Vault.tsx:1523 = `.secret-row` +
  `{confirmGen && <span>}` + `<StrengthBar>`) → passing 3 children to `children: ReactElement` **fails
  `tsc` mid-batch** (or, if coerced, `cloneElement` misbehaves). *Fix:* apply `Field` ONLY to blocks
  with a single labelable child (Welcome.tsx:98 master-pw, editor Name 1513 / Username 1519 / Website
  1535 / TOTP 1541 / Vault-`<select>` 1502, Notes 949, Website-detail 927→`<input>`). For secret-row /
  `PasswordField` / multi-child blocks, put the `id` on the actual inner `<input>` (Field can't help)
  or use `aria-label`; **read-only Detail display rows (878-949) are out of scope** (they are not
  form inputs). Do NOT issue the blanket "mechanically replace the ~70 `.field` blocks."

### AMENDS (binding corrections)

- **AM-1 — web `--gold` darken flattens the primary-button gradient.** Light `--gold → #7d5e14`
  equals light `--gold-bright #7d5e14`, so `button.primary`'s `linear-gradient(180deg, --gold-bright,
  --gold)` (styles.css:139) becomes a **solid fill** in light mode. The design's re-verify list
  (:82,:105,:235,:250,:294) OMITS :139. Not a contrast fail (button text stays ~6:1) but an aesthetic
  regression. Prevent it: use a **separate `--link` token** (#d0a94a dark / #7d5e14 light) on `.link`
  (:257) and leave `--gold` untouched — also sparing the conic TOTP ring (:250), `.tag.brand` (:235),
  `.tone-mid` (:294).

- **AM-2 — no `visually-hidden` utility class exists** in `styles.css` or `popup.css` (grep: zero),
  yet BL-1's announcer, the web conn-dot twin (a11yweb-04), the extension search `<label>` (1a/1b),
  the extension conn twin (5a) and TOTP "N seconds left" (5b) all need one. **Define `.visually-hidden`
  once per token file** (absolute + 1px clip-rect). Without it builders improvise inconsistent inline
  styles or fall back to `aria-label` (wrong for the conn dot — see AM-3).

- **AM-3 — web conn-dot `aria-label={title}` on `.who` clobbers the userid AND still won't announce.**
  `.who` (Vault.tsx:370) contains the `.dot` + the `.userid` email; `aria-label` overrides its
  accessible name → the **email stops being announced**, and changing `aria-label` on a live region
  does **not** trigger a polite announcement (live regions fire on subtree TEXT mutations, not
  attribute changes) → the flip is silent regardless. Use the **visually-hidden text twin inside
  `.who`** (its textContent changes on flip → announces; email intact) — needs AM-2.

- **AM-4 — Android side-effecting toggle handlers must move whole.** The idiom's example
  `onValueChange = { fpOk = it }` is a bare state-set, but the quick-unlock Switch
  (MainActivity.kt:1957-1963: `onCheckedChange` → `vm.enrollQuickUnlock(activity)` /
  `vm.disableQuickUnlock()`) and the AutofillStatus debug Switch (AutofillStatusScreen.kt:265-274 →
  `AutofillDebugLog.setDebugUntil(ctx,v)`, which purges the ring file) carry real effects. Moving to
  `toggleable`, the **entire existing lambda** must become `onValueChange` and the **`enabled` guard**
  (`activity != null && !ui.busy`) must move from the `Switch` to the `toggleable` — else the toggle
  flips visual state but never enrolls/disarms (dead control).

- **AM-5 — Android a11yand-04 mis-references the ReSealCard.** MainActivity.kt:554-580 (ReSealCard)
  has **no checkbox and no match/mismatch verdict Text** — its only gate is
  `PrimaryButton(enabled = ok && !ui.busy)` (:578). Target the "why disabled" hint at that **disabled
  button** (stateDescription/contentDescription); there is no verdict line for a liveRegion. Also:
  `shortOk` (:465) and `ok` (ReSeal) are already inline-recomputed `val`s (not `remember`ed), so the
  "frame-stale gate — recompute in same scope" caution is a **no-op** — do not add `derivedStateOf`
  churn.

- **AM-6 — Android live regions are conditionally composed; the smoke must prove FIRST appearance.**
  ErrorBar (:376 `if (msg != null) Card`), NoticeBar (:388), InlineError (:1915) and the enroll
  verdict Texts (:502-506, inside `if (shortOk)`/`if (!shortOk)`) **enter composition already
  carrying text**. Compose `liveRegion` may not announce on a node's *first appearance* (only on text
  changes to an already-present node) — version/TalkBack-dependent. The §4 TalkBack smoke must
  explicitly assert the **null→text** case is spoken (not just text-to-text); if it isn't, hoist the
  `liveRegion` modifier onto a stable always-composed ancestor with the text mutated in.

- **AM-7 — extension toast live region must sit on the PERSISTENT root, not the ephemeral node.**
  `showToast` (content-ui.ts:478-491) does `createElement("div")` + append-populated each call. A
  `role`/`aria-live` on that fresh node is populated-on-mount: the **assertive** 2FA-fallback
  (a11yext-6d) still announces (assertive/alert insertion works — the safety case holds), but general
  polite toasts won't. Put the region on the persistent `ui()` root and append toast text into it.
  Add the 2FA-fallback **"code is spoken"** assertion to the §4 extension smoke — it is the
  safety-critical path and is not currently listed.

- **AM-8 — desktop `onErrorContainer` at Ui.kt:828 must touch ONLY the warn branch.**
  LifecycleNoticesBanner (:816-828) is `Card(containerColor = if (warn) errorContainer else default)`
  + `Text(color = if (warn) error else secondary)`. Only the `warn`-true branch is on `errorContainer`
  → change **only** `error → onErrorContainer` there; the `else secondary` sits on a default `surface`
  and must stay (onErrorContainer on surface would be wrong-colored / low-contrast). The other three
  sites (92, 137/138, 881/886) are correctly on `errorContainer` — verified.

- **AM-9 — desktop `FocusRequester` composition race, with no harness to catch a crash.**
  `LaunchedEffect(Unit) { fr.requestFocus() }` can dispatch **before** the `Modifier.focusRequester(fr)`
  node is attached/placed → `IllegalStateException: FocusRequester is not initialized`, likeliest in
  the conditionally-shown typed-entry dialogs (TOTP Confirm Ui.kt:2149, backup passphrase,
  typed-confirm delete). Desktop has **no test harness and is not in `verify.sh`**, so a crash surfaces
  only at owner runtime — on Unlock, the most-used screen. Guard it (`runCatching { fr.requestFocus() }`
  or a placement check) and set `autoFocus = true` on **exactly one** field per screen (multiple
  requesters race, last-wins). It does NOT fight `submitOnEnter` (orthogonal key handler) — that is
  fine as-is.

- **AM-10 — desktop pinned dark contrast figure is off (fix still passes).** The pinned "dark
  5.34:1" for `onErrorContainer` on `errorContainer` derives from Error80 `#F2B8B5`; the actual
  Material3 dark `onErrorContainer` is Error90 `#F9DEDC` → **~7.17:1** (light `#410E0B` on `#F9DEDC` =
  12.77 is correct). Both pass AA, so the fix is sound — but §4 makes this pinned number the desktop's
  *only* proof-of-record (a code comment); write **~7.17 dark** (or "≥5.3, exact value M3-token
  dependent"), not 5.34 as exact.

- **AM-11 — path nit:** §4/§6 cite bare `verify.sh`; the file is **`scripts/verify.sh`**. The line
  numbers are right (14-21 version gate greps `ANDVARI_CLIENT_VERSION`/`versionName`/`packageVersion`/
  `CLIENT_VERSION`; :28 android compile; desktop absent — all verified), only the path prefix is
  missing.

### Attacked and LEFT INTACT (survived — do not change)

Version lockstep: the 4 bump sites are correct and are exactly what the gate greps; `SERVER_VERSION`
(server/App.kt:70) and `DESKTOP_VERSION` (app-desktop/Platform.kt:18) genuinely `= ANDVARI_CLIENT_VERSION`
(bumping :81 carries them); the extension's 3 sites are independent and guarded by `version.test.ts`
(asserts all three) + `package.mjs`. • Contrast: web/ext `--ink-faint #8d8370` dark = 5.00/4.59 on
`--bg`/`--bg-raised`, `#786c50` light = 4.51/4.88, light `--gold #7d5e14` = 5.26/5.68 — all recomputed,
all ≥4.5; web has **no `::placeholder` rule** so `--ink-faint` never lands on `--bg-input` (the 4.27
surface). • Android: reveal fix has `label`+`show` in scope (SecretField/CopyRow); `clearAndSetSemantics`
on the countdown Text is a leaf → strips no sibling; `mergeDescendants` on StatusRow/KeyValue is safe
(no interactive child); semantics/toggleable/Role imports are genuinely absent; **FLAG_SECURE**
(MainActivity.kt:103-107) is a window flag untouched by any semantics fix (and TalkBack works on secured
windows). • Desktop: `submitOnEnter`/`dismissOnEscape` reuse is correct; Rename/Delete/Move/search sites
verified; Primary-busy semantics sound. • Web: `aria-current` on navBtn (:333, real `<button>`),
`aria-pressed` on tabs, menu-`Tab`-close (:797), TOTP `aria-label`+`aria-hidden` ring (:1320), and the
search/select `aria-label` special cases (not `Field`) all hold. (Minor caution, not amended: don't route
per-keystroke validation through a `role="alert"` `Msg` — assertive re-announce spam; current err sites
are all submit-time.)
