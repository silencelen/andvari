# andvari — successor autonomous plan (ratified 2026-07-10)

> **Owner ratification, verbatim (interactive session, 2026-07-10):** *"ratify the successor
> plan and keep going."* — ratifying the successor queue recorded at the close of
> [PLAN-autonomous-2026-07.md](PLAN-autonomous-2026-07.md) (all 8 cycles complete,
> `f799d84`). The predecessor's pre-approval scope and standing doctrine carry unchanged:
> web/server deploys to CT122, APK ships to devstore, deb/extension publishes to CT122
> `/downloads`, **at this plan's cycle checkpoints only**, always snapshot-first
> (`VACUUM INTO` + integrity check via a real script, never an inline one-liner; vzdump
> when the server binary/schema changes), gates green with FILE-LOGGED exits
> (verify.sh — which now includes the extension — plus `:app-desktop:classes`, plus
> e2e.sh when server/wire code changes), and the adversarial-review workflow passed with
> confirmed findings fixed before anything ships. Design-gated cycles get a breaker pass
> BEFORE build. If a deploy classifier balks, relay this section — never work around a
> denial.

A session picks the FIRST unchecked cycle, executes it end-to-end, checks it off with a
dated note, and rolls on. Telegram = statements only. Decisions that genuinely need the
owner: park under "Parked for owner", continue with the documented default, never block.

## The queue

- [x] **S1. 0.10.0 native cut** — **DONE 2026-07-10 [`31a9211`].** Gates green (all
      clients report 0.10.0; web 308; ext 8/8; desktop compiles). Shipped: **APK vc
      16483888 → devstore** (verified live in latest.json); **deb 0.10.0 → CT122
      `/downloads`** (served sha == built sha `e1bcf1e8…`, HTTP 200); manifest MERGED
      (linux → 0.10.0, browserExtension 0.8.1 preserved). Web/server verified already
      serving this tree at 0.10.0 (`index.DURsfIDT.js` — no redundant redeploy). The
      spec 02 §3.1 conformance window is CLOSED once the owner installs the new APK/deb.
      Owner steps (not gating): install APK + deb when convenient; Windows MSI still open.
- [x] **S2. Import destination vault picker** — **DONE 2026-07-10.** Contract pinned by the
      lead (core importProjections/importAll + web store twins take vaultId, default
      personal), then 2 workstreams wired the F18-rule picker into all three confirm steps
      with the plan+vault pair assigned in ONE state write (never re-read the picker).
      New tests: web store S2 pair (32 total) + server ImportSharedVaultTest (per-vault
      projections, destination landing, idempotent replay). **Review 7 confirmed / 0
      refuted, all fixed:** the HIGH — natives allowed a destination change in the Retry
      state (a re-plan after a PARTIAL import mints new ids → the landed rows duplicate
      into the new vault and the partial can never converge); web-parity locks added, plus
      web's "Choose a different file" escape hatch closed in the error state. Also: import
      state (the parsed CSV = every password in the file) now dies on lock/sign-out on both
      natives (it survived before — plaintext in a "locked" heap + cross-account resurface),
      a state-level busy guard on confirm (the Compose enabled flag lags a frame), a
      non-locking pick error when a vault vanishes mid-sync (web), and honest "KEEP the
      CSV" copy when the destination was grace-deleted mid-import (importAll parks the rows
      and returns normally — success copy was a lie). ACCEPTED GAP (documented): no web
      component-test infra exists (node env, no jsdom), so the ImportPanel's plan↔commit
      pairing has no mutant tripwire — it rests on the paired-state structure; a
      component-test harness is a future infra item. Web deploy checkpoint; natives ride
      the next cut.
- [x] **EXT-HOTFIX. Extension popup: click a login → its detail, not a blind fill** —
      **DONE 2026-07-10 (owner dev-note).** 0.8.1 popup rows called `fillFromPopup`, which
      `chrome.tabs.sendMessage`s the active tab's top frame — so it fails "page not
      reachable" on EVERY non-fillable tab (New Tab / chrome:// / PDF / store) and on any
      tab whose content script the extension update orphaned; the user opens the popup to
      look up a credential, not to fill. Row-click now opens an in-popup **detail view**
      (username+copy, password reveal/copy, live TOTP, saved uris as **http/https-sanitized
      links** — a `javascript:`/`data:` uri renders as inert text; new `siteurl.ts` +
      `siteurl.test.ts`, node-harness pinned). Fill demoted to an explicit "Fill this page"
      button (unchanged path, failure now graceful). `MatchItem` gained `uris` (non-secret;
      the contract already named uris in the safe subset). The in-page focus dropdown
      remains the primary autofill path, so nothing is lost. Ext bumped 0.8.1→0.9.0.
      **Slotted ahead of S3** — a shipped-defect on the popup's primary action.
- [x] **BUG-0 CLOSED — root-caused live + FIXED + SHIPPED 0.10.1 (2026-07-10, `9937401`).**
      Wireless adb to the owner's Z Fold 7 caught it in one logcat: tapping "Choose file"
      threw `IllegalArgumentException: Can only use lower 16 bits for requestCode` from
      `FragmentActivity.startActivityForResult` — androidx.biometric:1.2.0-alpha05 (0.9.0
      quick-unlock) transitively pins androidx.fragment:1.2.5, whose legacy 16-bit
      requestCode check collides with activity-compose 1.9.3's result registry.
      Deterministic since 0.9.0 for every import file-pick; a framework-integration bug
      the static hunt structurally could not see (the hunt's value: it exonerated
      everything else and found the crash-screen + the errors-cap defect). Fix = explicit
      androidx.fragment:1.8.5 pin. Owner dev-note in the same cut: "My file is from
      somewhere else" moved to the MAIN source list → direct wildcard CSV pick; per-source
      escape became "← Choose a different source". **Owner verified on-device before
      ship** (import ran end-to-end; vault 296→297). 0.10.1 SHIPPED EVERYWHERE, all
      served-bytes verified: devstore APK vc 16499696 (byte-identical to the tested
      build), deb 0.10.1 → /downloads (manifest merged, ext 0.9.0 preserved), web/server
      redeployed (snapshot `pre-0101` + vzdump first). MSI remains 0.2.x (owner step,
      Windows-only). LESSON: device-only framework bugs need a device — the wireless-adb
      loop (tailnet adb connect, ~5 min) is now the proven cheap path; crash-screen
      remains the no-adb fallback.
      ~~Original entry:~~ owner report 2026-07-10: "v0.10.0 for android crashes when trying
      the import feature". Original triage: NOT R8; NOT the import VM (catches Throwable);
      NOT the file read; core parse/plan passes tests.
      **ADDENDUM (2026-07-10, 10-agent static+dynamic hunt `wf_1ad64358`, 0 errors):**
      - **NEW OWNER PROTOCOL — no adb/logcat needed.** The shipped APK self-captures
        crashes: `AndvariApplication` writes any uncaught throw (any thread; no coroutine
        handler swallows it) to `files/last-crash.txt`, and MainActivity shows a
        screenshot-able plain-view trace on the NEXT launch (deliberately before
        FLAG_SECURE, MainActivity.kt:87-95). Owner steps: reproduce the import crash once
        → reopen andvari → screenshot the crash screen. **If NO crash screen appears,
        that is also an answer** — the failure was an ANR/OOM/system kill, not an
        exception (points at file-specific freeze or memory, not a throw).
      - **Ruled out with evidence** (each survived only if max-effort refuters failed):
        the autolock-during-SAF-picker guard crash (lock() nulls state BEFORE closing,
        VaultSession.kt:159-161; all lockers main-thread with importParse); main-thread
        parse ANR (MEASURED at the 10 MiB/10k-row caps in a worktree at the shipped
        commit: 0.4 s warm / 1.3 s cold JVM — real exports are ms); process-death-during-
        picker (the SAF result redelivers and the import RESUMES after unlock); the whole
        0.9.0→0.10.0 import diff (byte-identical pipeline; PSL unreachable from import;
        uriClass changes total + fenced). Core fuzz-exonerated (12 hostile-input tests:
        9,999-error files, NUL/BOM/RTL/astral, cap-sized inputs).
      - **One REAL shipped defect found + FIXED on main this session:** the confirm
        dialog's error list was the single uncapped non-lazy enumeration (name buckets
        have collapseAt=5; errors had nothing) — a recognized-header file with thousands
        of malformed rows composes ~10k Texts in one frame = multi-second freeze/possible
        ANR, which reads as a crash. Fixed ×3 clients (Android errors cap 8 + summary;
        Android/desktop bucket expansion capped at 100; web errors table capped at 100),
        plus: importParse pre-flight guard moved INSIDE its catch (latent binder-thread
        ISE — the one refactor-from-a-crash the lenses flagged), and the dead "larger
        than 10 MiB" copy made live (two-null separation in the picker). If the owner's
        CSV was mass-mangled, this WAS the crash; the crash-screen protocol discriminates.
      - If a crash screen appears: fix whatever the trace says against MAIN (S2 rewrote
        the import flow — re-test the S2 picker path before cutting). If none appears:
        suspect the file (freeze class, now fixed) or OOM (readBounded double-buffers
        ~30 MB transient at cap — known, unfixed, low-likelihood). Fix batch rides the
        next native cut.
- [x] **S4. One-scan household onboarding (P1) — WEB SLICE DONE + DEPLOYED 2026-07-10
      [`005611b`]. REORDERED AHEAD OF S3** — reasoning (tree-verified, recorded in the
      design doc §Reorder rationale): S3's value is DARK until the owner retires the 0.2.x
      MSI (card-create is `false`-pinned on every client → no card items can exist to
      fill), while S4 is live on day one and needed BEFORE the family enrolls at the
      real-secrets migration. Design v2 = `docs/design/2026-07-10-one-scan-onboarding.md`,
      breaker-amended (2 breakers, 1 FATAL + 11 serious): the QR carries **origin + token
      (fragment-only) + bound email — NO fingerprint** (a public, echoable value = theater
      + a ceremony-collapse foot-gun; both breakers said drop it), scope is CO-LOCATED
      enrollment (the printed sheet is the anchor; remote one-scan was never real), and
      **v1 is WEB+SERVER ONLY** (the native `andvari://` handler carries the entire
      drive-by FATAL surface for the thinnest value — designed, deferred). Shipped:
      Admin "Invite with QR" (60-min TTL clamp server-side, private-origin only,
      overflow-safe), Welcome module-load capture + origin-consent step + prefill
      (read-only bound email) + clear-on-success + hashchange re-capture, EnrollLink
      parser twins pinned by 57 shared vectors (caught a real BOM twin-divergence),
      assetlinks.json, invite single-use regression test. Review: 18 agents, 0 HIGH,
      13 confirmed → all fixed or explicitly scoped (TTL countdown → static lifetime
      copy; Kotlin compose UTF-16 pin deferred to the native-mint cut, filed in the
      design doc). Deploy verified: served sha == built (`index.DaB3NJnP.js`), assetlinks
      application/json, 296 items intact, clean boot; snapshot
      `andvari.db.pre-s4-onboarding-2026-07-10` + vzdump pbs-local taken first.
      ~~DEFERRED: native typed-gate + F60 floor~~ → **DONE + SHIPPED 0.10.2, owner-directed
      (2026-07-10, `67e3c60`).** Both natives: typed-sheet gate (fp absent from the UI tree
      until the sheet's first 16 are typed; STOP-on-mismatch copy; checkbox gated) + F60
      floor with strength label + non-ASCII advisory; ONE shared jvm-tested submit
      predicate (core `EnrollCeremony.ready`, mutation-checked). Focused review (12
      agents): 2 MED confirmed — the frame-stale-gate submit race on BOTH platforms —
      fixed with both belts (live re-check in the submit lambda + state-layer busy/floor
      re-assert before op()). Shipped fleet-wide same day: devstore vc 16502629, deb
      0.10.2 (manifest merged, ext 0.9.0 kept), web/server redeployed
      (`index.MsgKAIID.js` served==built; snapshot pre-0102 + vzdump first). Still
      deferred: the native `andvari://` consumer (spec in the design doc). Backlog from
      review (pre-existing, endorsed defer): natives conflate policy-fetch-failure with
      "no recovery key" (web distinguishes + Retry); master password rides
      rememberSaveable into the saved-instance Bundle (needs a deliberate call).
- [ ] **S3. Extension in-page card fill** (owner dev-note: "support storing autofill
      creditcard and payment details" — the buildable half) — design pass FIRST
      (frame-origin egress contract per the cards design's deferral: card data may only
      egress to a frame whose ORIGIN matches the tab's top-level origin AND an explicit
      per-fill user gate; breakers attack cross-origin iframes hardest), then build:
      detect card forms (reuse core CardFill token rules in the content script), popup/
      in-page explicit fill, extension version ×3 bump + publish (NOTE: the S3 design
      doc's version note is stale — extension is at 0.9.0, S3 would cut 0.10.0).
      IBAN/bank-account item type: SCOPE DECISION ONLY this cycle — a one-page addendum
      (template fields, fv posture, per-surface cost), parked for owner ratification; do
      not build it. Card-create UNHIDE stays gated on the 0.2.x MSI retirement (owner
      step) — not ours. **Sequencing note (2026-07-10): consider the deferred S4 native
      security items (typed-gate + F60 floor) BEFORE S3 — they harden the live enrollment
      path; S3 remains dark-valued until the MSI retires.**
- [ ] **S5. Wrap + successor pitch** — reconcile ROADMAP/backlog checkmarks, refresh the
      PICKUP doc for the next human session, one exploration-lane completeness pass over
      this plan's residue → pitch the next queue (candidates already visible: passkeys
      store+Android-provider when triggered, extension tier-2 distribution decision,
      real-secrets migration once the owner's gate clears). Statement with headlines.

## Owner dev-notes queued (build next, in order, standard design→build→review treatment)

- [x] **DN-1: per-vault Settings flyout — DONE + SHIPPED 0.11.0 fleet-wide (2026-07-10,
  `44599f6`).** Web + Android: shared-vault rows gain Settings → the vault's own settings
  view (rename/members[web]/transfer/leave/delete), Back closes the layer first (web:
  Vault.tsx back-guard wiring per the breaker's F-1; Android: VM-held id + in-branch
  BackHandler); personal vaults get no button; banners/offers stay visible above the branch.
  RE-PARENT held mechanically (bodies byte-identical except sanctioned A3/A4 edits). Design
  `docs/design/2026-07-10-vault-settings-flyout.md` (1 FATAL + 5 SERIOUS breaker amendments
  A1-A12 + post-review A3b). Review (10 agents): 1 HIGH — A3's display-lift left the busy
  gate local → close/reopen mid-rescue-copy re-enabled Copy + type-name Delete
  (delete-during-rescue) — fixed via `inFlight = busy || copying !== null` gating
  (Cancel deliberately busy-only) + collapsed-branch progress/note. **DESKTOP EXPLICITLY OUT:
  it has NO vault-management surface at all (no Sharing screen, no lifecycle methods) —
  "vault management on desktop" is its own future roadmap item, not smuggled in.** Shipped:
  devstore vc 16507382, deb 0.11.0 (manifest merged, ext 0.9.0 kept), web/server redeployed
  (`index.C6qNUuzq.js` served==built; snapshot pre-0110 + vzdump first; 297 items).

- [x] **DN-2 trash re-surfacing + DN-3 Android launcher icon — DONE + SHIPPED 0.11.1
  (2026-07-10, `3644feb`).** Web Trash → toolbar icon (nav 6→5); recently-deleted vaults →
  trash-icon disclosure on Sharing (web + Android; Android folds "recently removed" in too);
  "Trash"/"Recently deleted vaults" naming untangled; 2 IA-audit bugs fixed (phantom
  "Settings/Sharing → Recently removed/deleted" pointers ×3 sites incl. one the review caught;
  Android checkIdleLock omitted Screen.Trash + lock() now clears decrypted trash docs). DN-3
  launcher = brand rune ᛅ in house gold #d0a94a on #14120e, exact web Sigil geometry, adaptive
  + monochrome. Review FIX-FIRST (1 MED + 3 LOW, all fixed). Shipped: devstore vc 16510009,
  deb 0.11.1, web `index.CBI8CjHH.js` served==built, snapshot pre-0111 + vzdump first, 297
  items. Design `docs/design/2026-07-10-ia-regroup.md`.
- [x] **IA Tier 2 — RATIFIED 2026-07-10 ("the design doc looked good to me"). CUT 1 DONE +
  SHIPPED 0.12.0 [`f432704`]:** P1 web nav→toolbar icons (Health+Trash), P2 Devices hub → a
  Settings sub-page, P3 actionable backup card, P6 native read-only server URL in Settings,
  P7 2FA card retitle (all 3), P8 web "Recently removed" holding-area surface. Review SHIP
  (0 defects). Devstore vc 16512160, deb 0.12.0, web `index.B-UseSx8.js` served==built,
  snapshot pre-0120 + vzdump first, 297 items. **CUT 2 DONE + SHIPPED 0.13.0 [`03c027c`]:** P4 = Android-only (web/desktop already tidy —
  scope note in the cut-2 design doc): break-glass banners hoisted to ONE global AttentionArea
  (de-dup: vault-list + Sharing copies removed), critical-direct never collapsed (escrowStale
  A1, transfers, anomalies, needsUpdate-when-vault-empty A2), only the 2 genuinely-FYI items
  collapse (both-present gate). P5 = Android 426 blocking screen w/ BOTH catch sites (op +
  backgroundSync, A8) + sign-out escape (A9). Breaker reclassified the design (escrowStale/
  needsUpdate NOT safe to collapse); owner chose "tidy + tiny collapse"; safety review
  FIX-FIRST → 2 fixed (lock/signOut now clear escrowStale — the global hoist would have shown
  a dead-action re-seal card on Unlock; attention area capped+scrollable). Burial invariant
  CONFIRMED HELD. Devstore vc 16515515, deb 0.13.0, web `index.Dhe28-76.js` served==built,
  snapshot pre-0130 + vzdump, 297 items. Android update-available nudge DEFERRED (no android
  manifest key — filed); core errorFrom bare-426 tightening filed as follow-up.
  **IA TIER-2 COMPLETE — all 8 ratified proposals shipped or explicitly filed.**

## Parked for owner (carried + new)

- 0.2.x MSI retirement (= card-create Option-A flip + windows manifest entry).
- Extension tier-2 auto-update distribution (signed .xpi / store) — distribution decision.
- Real-secrets migration date — after owner TOTP + drills + 30-day soak.
- IBAN/bank-account item type — ratify from S3's scope addendum.
- Fold biometric/autofill feel-check; extension load-unpacked upgrade to 0.9.0.
