# N3b — universal importer (design-lite, 2026-07-11, owner-ratified)

> Owner: *"is there a point to specifying different browsers with each their own import popup,
> or can we have a universal importer, and just specify to the user that its universal"* →
> survey (session agent, 2026-07-11) → *"go ahead with the universal importer after N3."*

## Ground truth (from the survey — evidence in the session log)

The parser is ALREADY universal: all three clients pass only bytes to the shared header-sniffing
parser (core `CsvImport.parse` + web twin `csv.ts`), 5 format adapters serve 8 UI sources,
"header detection stays authoritative over whatever source the user PICKED" (csv.ts:178-179),
Chrome/Edge/Brave/Opera are indistinguishable by design, wrong picks are harmless, the preview
already shows "detected X export". The pick feeds ONLY: per-source export steps, two safety
notes (1Password-8 version, LastPass download-don't-copy), and the pick-vs-detected mismatch
hint. Cost: ~490 lines across 6 files, ~254 of them THREE independently-drifting step-copy
tables (already divergent for Edge). Desktop lacks the wildcard entirely and forces a pick it
ignores.

## The change (all three clients, cut as 0.14.1)

One universal import screen replaces the 8-source grid + per-source steps screens:

- **Entry unchanged** (web import icon / Android import icon / desktop FileUpload button).
- **The universal screen:** title "Import passwords (CSV)"; the honest line — *"Works with
  password exports from Chrome, Edge, Brave, Opera, Firefox, Bitwarden, 1Password 8 or newer,
  LastPass, and Safari — the file itself decides how it's read."*; the existing plaintext-CSV
  warning (unchanged, load-bearing); a **primary "Choose file…" action** going straight to the
  picker (the Android-0.10.1 wildcard behavior, now the only path); and a **collapsible "How do
  I export from…?" help block** — the ONE surviving per-source surface: 8 sources × their 2-3
  export-navigation steps, carrying the 1Password-8 version note and the LastPass
  download-don't-copy note inside their entries. Collapsed by default.
- **After the pick: nothing changes.** Same parse, same preview ("detected {format} export"
  label stays), same S2 destination picker, same F75 dedupe, same report buckets, same retry.
- **Deletions:** the per-source grids/steps screens (web `IMPORT_SOURCES` UI + steps + grid,
  Android `ImportSourceDialog`'s 8-way list + steps screens, desktop `ImportSourceFlow`), the
  `OTHER_SOURCE` special case (the universal screen IS "other"), the `expects[]`/mismatch-hint
  machinery on all three ("This file looks like X rather than Y" dies — no pick exists), and
  desktop's non-null `source` parameter on `importFromFile`.
- **`unrecognized_header` copy becomes universal** and absorbs the 1Password bespoke hint:
  one message on all three clients — *"This file isn't a recognized password export. Make sure
  you exported a CSV (not JSON or a zip) — and if it came from 1Password, that you're on
  1Password 8 or newer."* (The old per-pick hint keyed on a pick that no longer exists.)
- **Help-table single-sourcing:** the per-source steps move to ONE shared table in core
  commonMain (`ImportHelp.kt`: source label + steps + optional note), consumed by BOTH natives
  (kills the Android/desktop duplication — F82 hoist precedent); web keeps its own table as the
  usual non-KMP twin, content-aligned with core's in the same cut. Three drifting copies → two
  pinned ones. While unifying, reconcile the drifted step text once (pick the accurate menu
  path per browser, current as of 2026-07; note in the table that steps are best-effort docs,
  not contracts).

## Pins (breaker attention here)

1. **Parser/adapters/vectors UNTOUCHED.** `CsvImport.kt`, `csv.ts`, `import.json`,
   `import-foreign.json`, all format tests: zero diffs. The change is UI + client state only.
2. **The plaintext warning and the content-based mangle heuristic survive verbatim** (both are
   source-independent already).
3. **Android import robustness is not regressed:** the SAF picker path, the 0.10.1 fragment-pin
   crash fix, the import parse robustness caps, and the S2 destination step are entry-point
   downstream — the universal screen must land on the EXACT same picker/parse/preview calls the
   wildcard path uses today (it becomes the only path; the per-source paths converge into it).
4. **State teardown:** each client's import-flow state fields (pick/source/steps stage) shrink —
   audit every cancel/lock/signOut/dismiss path that referenced the deleted stages (web
   importView state machine, Android UiState import fields + sheet dismissal, desktop
   `ImportSourceFlow` state) so no dead stage can strand the flow.
5. **`docs/design/2026-07-09-guided-importers.md` is amended, not deleted** — a dated
   supersession note at the top pointing here (the guided-steps content it specified lives on
   inside the help block).
6. **Preview labels:** `FORMAT_LABEL`/`importFormatLabel`/`formatLabel` stay (they're
   format-keyed).
7. Detail: desktop's AWT FileDialog title "Import passwords CSV" stays; web's single
   `accept=".csv,text/csv,text/plain"` input stays.

## Amendments (adversarial breaker, 2026-07-11 — no blockers; 3 AMENDs + notes)

**A-webError:** the deleted web steps branch is `parseErr`'s ONLY render site (Vault.tsx:2154)
— the universal screen MUST carry the error slot (`{parseErr && <div className="msg err">…}`)
and a Cancel affordance (today only the grid branch has one; the steps branch leaned on
"← back to vault"). Without this, pick-bad-file → nothing visibly happens. (Natives are safe —
their error is an always-mounted dialog.)

**A-androidError:** Android's sheet closes BEFORE the picker, so the error dialog renders
context-free — the honest line is NOT on screen at error time (it is on web). The universal
`unrecognized_header` string on Android must KEEP a short recognized-source enumeration
(today's generic copy has one); do not lean on the honest line being visible.

**A-docs:** the migration runbook goes stale — `docs/runbooks/real-secrets-migration-day.md`
lines ~59-62 ("all 8 guided sources supported", "pick the matching source (guided steps)")
must be rewritten to the universal flow, and `docs/PLAN-autonomous-2026-07c.md`'s "guided
import per member" line likewise. Both belong to WS-core+web. (ROADMAP/CHANGELOG/PICKUP-v9
mentions are dated history — leave.)

**Sizing honesty (reframe):** fleet net is ≈ −180 lines, not −490 (web's 85-line steps table
survives as the help-block twin; core ImportHelp adds ~100 back). The justification is drift
3→2 pinned tables + the desktop-wildcard fix + mismatch-machinery removal — not raw line count.

**Notes folded:** keep the picker MIME as `arrayOf("*/*")` on Android (narrowing to text/csv
hides mislabeled CSVs from providers reporting octet-stream — both current paths share one
picker lambda, MainActivity.kt:762); web CSS — `.source-grid`/`.source-card` die with the grid
but `.steps` SURVIVES (the help block keeps `<ol className="steps">`); desktop's
`friendlyImport` null-branch is already dead code (both callers pass non-null) and dies whole
with the param; the universal line naming Safari is VERIFIED (Apple header rides the 1P
detector, pinned vector `apple-safari-via-1password`; the 1P-8 distinguisher is the `otpauth`
column, reject vector `onepassword-old-shape`); Android's stale-`importSource`-after-cancelled-
picker wrinkle dies with the field (a point in favor).

## Workstreams (after 0.14.0 ships; disjoint)

- **WS-core+web:** `core/.../client/ImportHelp.kt` (NEW shared table) + web (`Vault.tsx` import
  section + `styles.css` grid rules) + the guided-importers doc amendment.
- **WS-android:** `MainActivity.kt` (ImportSourceDialog → universal sheet) +
  `AndvariViewModel.kt` (import source state shrink).
- **WS-desktop:** `Ui.kt` (ImportSourceFlow → universal screen) + `DesktopState.kt`
  (`importFromFile` signature + enum removal, consuming core `ImportHelp`).

Gates: verify.sh + `:app-desktop:classes` + find→refute review (standard). Ship 0.14.1 full
fleet, snapshot-first, byte-verified.
