# IA Tier-2 Cut 2 — P4 notice/banner unification + P5 Android update parity (2026-07-10)

Owner-ratified (docs/design/2026-07-10-ia-regroup.md Tier 2). Cut 1 shipped 0.12.0. This cut
carries the two pieces that needed their own care: P4 (opinionated — changes the daily surface)
and P5 (feature — Android has no update/426 handling at all).

## P5 — Android update-available + 426 parity (build straight; it's proven on desktop)

Desktop has both; Android has NEITHER (a 426 today falls through to a generic dismissable error
toast — silently swallowed). Port the desktop pattern exactly:
- **`checkForUpdate(baseUrl)`** for Android (desktop's is JVM-only in Platform.kt): GET
  `$baseUrl/downloads/manifest.json`, decode the shared `DownloadsManifest`, take the **linux**
  entry?? no — Android needs its own version source: **compare `manifest.linux`?** No. Android
  is not linux/windows/extension. The manifest has `linux`/`windows`/`browserExtension` — **no
  android key.** So Android's update check has NO manifest entry to read (the APK ships via
  devstore/`latest.json`, not `/downloads/manifest.json`). **DECISION: P5 ships the 426 blocking
  screen ONLY on Android** (the real gap — a server minVersion pin currently swallows silently);
  the "update-available" nudge is DEFERRED for Android until there's a manifest key or a
  devstore-`latest.json` reader (filed). Desktop update-available stays as is. This keeps P5
  honest — don't invent an android manifest entry that the release pipeline doesn't publish.
- **426 blocking screen (the actual gap):** add `UiState.upgradeRequired: String?`; a new
  `catch (e: UpgradeRequiredException)` in the VM's op/error path sets it (ahead of the generic
  ApiException handling); render an early-return blocking screen at the top of `AndvariApp`
  (before the MustChange banner + screen switch), mirroring desktop Ui.kt:57-66 — sigil +
  "Update required" + the devstore/download hint. Copy points at the devstore (where Android
  updates come from), not `/downloads`. No in-process recovery (update + relaunch), same as
  desktop. Core already throws the typed 426 (AndvariApi.kt:71/180-183); Android just wasn't
  catching it.

## P4 — one notice system, one idiom, collapse-don't-hide

### The problem (recon-quantified)
Worst case BEFORE the first vault row: web ≈ 3 fixed banners + K lifecycle rows; **Android ≈ 7
cards + QuickUnlock + K lifecycle + M incoming**. Three visual idioms on web (`.banner`
full-strip, `.msg` box, `.sheet`+inline-borderLeft). Android renders lifecycle notices AND
incoming transfers on BOTH the vault list and Sharing (duplicated).

### The SAFETY INVARIANT (the breaker's north star)
**Collapse is not hide.** Every break-glass item stays reachable in ≤1 action from a
persistent, prominent signpost that shows its severity and count. Specifically:
- **CRITICAL items are NEVER collapsed** — they render directly, always visible:
  `mustChangePassword` (a live temp password the user must replace), a lifecycle **anomaly**
  (`transfer-anomaly`/`anomaly`/`replay-denied` — a "server may be misbehaving" security
  signal), and an **incoming ownership transfer** (a decision only the user can make). These
  are rare AND must-see AND usually singular.
- **FYI break-glass items collapse** behind one attention disclosure: `escrowStale` re-seal
  (already "Later"-able), `needsUpdate` (fv fail-closed, informational), unopenable-vault
  (informational). Collapsed to: "⚠ N things need attention ▾"; the disclosure is ALWAYS
  visible while N>0 (it is a signpost, not a dismiss), one tap reveals each item in the unified
  idiom with its unchanged action.
- **Benign lifecycle notices** (`deleted`/`removed`/`left`/`restored`/`transfer-complete`,
  info-tone, dismissable) stay as lightweight dismissable rows — they're daily-tolerable, not
  break-glass. `ErrorBar`/`NoticeBar` op-feedback toasts are unchanged (ephemeral, not notices).

### Placement + de-dup
- The attention area (critical-direct + FYI-disclosure) renders ONCE in the global slot above
  the view/screen switch — so it shows on every surface, exactly once (web already does this
  for lifecycle; **Android STOPS rendering lifecycle notices + incoming transfers on Sharing**
  — SharingScreen.kt:201-202 removed, they live only in the global area now). Web incoming
  transfers move from Sharing-only into the global attention area too (so they're seen from the
  vault, not just when you visit Sharing — a small improvement).
- ReSealCard/UnopenableVaultWarning/needsUpdate move OFF the vault-list body into the FYI
  disclosure (their bodies/actions re-parented verbatim — the re-parent rule).

### One idiom
- Web: everything in the attention area uses the `.msg`/`.msg.err`/`.msg.info` boxed family
  (drop `.banner` full-strip + the two inline `borderLeft` accents). A new `.attention`
  wrapper for the collapsible container. Critical items = `.msg.err` tone; FYI = `.msg.info`.
- Android: one `AttentionCard` composable wrapping the items; critical = errorContainer,
  FYI-disclosure = a single default Card with a count header + expand. Desktop: it already
  folds everything into one `NoticeBar` + the few list banners; light touch — unify its
  ReSeal/needsUpdate into the same disclosure idiom for parity, but desktop's stack is already
  small (no lifecycle list, no Sharing), so desktop is mostly unchanged.

### Re-parent rule (as before)
The BODIES + ACTIONS of every moved banner (ReSealBanner/Card, UnopenableVaultWarning,
IncomingTransferCard, the needsUpdate copy, mustChange) are byte-identical; only their wrapper
+ placement change. deleteId/re-seal/transfer flows untouched. No store/core/server logic.

### Version + gates
Native behavior change (Android 426 screen + banner reshuffle) → **×4 → 0.13.0**; web rides.
verify.sh + :app-desktop:classes + review with a dedicated SAFETY lens ("name any state where a
must-see item is not visible within one action"). Breaker pass on THIS doc first (P4 only — P5
is proven-pattern parity).

## BREAKER AMENDMENTS (folded in — build to these; the classification was unsafe as first drawn)

The breaker's verdict: the daily stack is mostly GENUINELY must-see, not hide-able. P4's real,
safe value is **de-dup + one idiom + a SMALL collapse of only the truly-FYI items** — not a big
"hide the stack." Revised:

- **A1 (S1): escrowStale re-seal is CRITICAL-DIRECT, never collapsed.** It means recovery is
  ALREADY broken (escrow sealed to a dead key) → silent permanent loss on a later forgotten
  password. It keeps its own always-visible card (its body/action unchanged).
- **A2 (S2): needsUpdate DYNAMICALLY PROMOTES.** When `items.isEmpty() && needsUpdateCount>0`
  (fail-closed items are excluded from `items()`, so the banner is the ONLY explanation for an
  apparently-empty vault) render it DIRECT, not collapsed — else a user re-imports thinking data
  is gone. When it's a minority, it may collapse.
- **Revised classification** — CRITICAL-DIRECT (always visible): mustChangePassword, escrowStale
  (A1), lifecycle **anomaly** (`transfer-anomaly`+`anomaly` ONLY — see A5), incoming transfer
  offers, needsUpdate-when-it-empties-the-vault (A2). FYI-COLLAPSE (behind one disclosure, only
  when ≥2 present so it actually declutters): needsUpdate-when-minority, unopenable-vault. If
  fewer than 2 FYI items exist, render them direct (no pointless disclosure).
- **A3 (M2): the disclosure counts ISSUES (categories), not item totals** ("2 notices ▾", never
  "53 things"); escrowStale is out of it entirely (A1).
- **A4 (M1): a11y** — the disclosure toggle reuses the ExportMenu idiom (real `<button>`,
  `aria-expanded`, accessible name carrying count; Android contentDescription). No dead
  pressed-state class (the DN-2 trap).
- **A5 (M3): `replay-denied` is BENIGN** (warn=false, "your role may have changed"; web has no
  case for it) — it stays a benign dismissable lifecycle notice, NOT routed to any critical/
  anomaly path (which on web has no body for it).
- **A6 (M4): web's attention area stays INSIDE Vault.tsx** (above its internal view switch), NOT
  hoisted to App.tsx — mustChange's "Go to Settings →" uses Vault-local `setView`.
- **A7 (confirmedSound, THE highest-risk build invariant): the Android de-dup requires hoisting
  BOTH the critical-direct area AND the FYI disclosure ABOVE `when(screen)` in AndvariApp**, so
  Sharing (and every screen) still shows a just-arrived transfer. Removing SharingScreen.kt:
  201-202 is ONLY safe once that hoist is in — never delete the Sharing copy while incoming-
  transfer still lives in VaultScreen. Sharing keeps its owner-side pending-offer chip +
  TransferControl (not lifecycle notices).
- **A8 (S3.1): P5 — `backgroundSync`'s catch must handle 426.** The 5-min poll / ON_RESUME is
  the MOST FREQUENT contact and its `catch (Throwable)` swallows the 426 into a generic toast,
  never reaching the block. Add `if (t is UpgradeRequiredException) { upgradeRequired = …;
  return }` there too (not only the op path).
- **A9 (S3.2): the Android 426 block screen HAS AN ESCAPE** — unlike desktop's dead-end, it
  includes "Sign out / change server" (signOut/setBaseUrl don't depend on being past the block).
  This also defuses S3.3 (a spurious proxy/CDN bare-426 can't permanently brick). Core
  errorFrom's bare-status arm is left alone this cut (the escape hatch suffices; tightening it
  to require `err.error=="upgrade_required"` is filed as a follow-up — it's a core change touching
  desktop too).

## Build scope note (owner chose "Tidy + tiny collapse", 2026-07-10)

On implementing: **P4 is Android-focused.** Web's daily-surface banners are already a coherent
2-idiom system (`.banner` persistent attention + `.msg` dismissable notices) and web never
duplicated incoming/lifecycle across surfaces the way Android does — so there's nothing to
de-dup and no over-stacking on web; forcing a web idiom change would be cosmetic churn on a
taste-sensitive surface for no win. Desktop already folds everything into one `NoticeBar` (no
Sharing, no lifecycle list) — also fine. So P4 touches **Android only**: the de-dup (A7 hoist +
remove SharingScreen dups), the one-`AttentionCard` idiom, the safe collapse (A1/A2/A3), a11y
(A4). Web/desktop take the version bump only. **Sequencing: P4-Android and P5 both edit
`AndvariApp` + `AndvariViewModel` — build P4-Android AFTER P5 lands (no concurrent edits to the
same files); honor A7 (hoist BOTH groups above `when(screen)`) as the #1 rule.**

## Open question for the breaker (ANSWERED above — kept for the record)
Does auto-not-collapsing CRITICAL items correctly handle the transition where an FYI item
becomes critical (it can't — the classes are static per source), and does the count on the
disclosure stay exact as items resolve/arrive via WS sync mid-view? And: with incoming
transfers moved global, does the Sharing screen still make sense (it loses its offer cards —
acceptable, since the global area shows them everywhere including on Sharing)?
