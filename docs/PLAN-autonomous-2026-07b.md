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
- [ ] **BUG-0 (OPEN, blocked on owner): Android 0.10.0 import crash** — owner report
      2026-07-10: "v0.10.0 for android crashes when trying the import feature"; owner
      offered wireless debugging. Triage so far (session 2026-07-10): NOT R8 (release
      isMinifyEnabled=false — debug gate is representative); NOT the import VM
      (importParse/importConfirm catch Throwable → importError); NOT the file read
      (runCatching + bounded); the preview composable is fully null-guarded; core
      parse/plan/import passes jvm + server tests; only import-path code changed
      0.9.0→0.10.0 is the cycle-6 uriClass `j:` fix (non-throwing) + normalizeHost A5.
      Suspect: Compose-layer or device/SAF-specific — NEEDS THE LOGCAT. adb is installed
      on huginn; when the owner supplies pair `IP:port` + code + connect `IP:port`:
      `adb pair`, `adb connect`, `adb logcat` (filter `AndroidRuntime:E`), reproduce, fix,
      ship 0.10.1 APK (deploys pre-approved). NOTE: main has moved past the shipped APK
      (S2 rewrote the import flow + picker) — reproduce the fix against MAIN and re-test
      the whole S2 import path before cutting 0.10.1.
- [ ] **S3. Extension in-page card fill** (owner dev-note: "support storing autofill
      creditcard and payment details" — the buildable half) — design pass FIRST
      (frame-origin egress contract per the cards design's deferral: card data may only
      egress to a frame whose ORIGIN matches the tab's top-level origin AND an explicit
      per-fill user gate; breakers attack cross-origin iframes hardest), then build:
      detect card forms (reuse core CardFill token rules in the content script), popup/
      in-page explicit fill, extension version ×3 bump + publish. IBAN/bank-account item
      type: SCOPE DECISION ONLY this cycle — a one-page addendum (template fields, fv
      posture, per-surface cost), parked for owner ratification; do not build it.
      Card-create UNHIDE stays gated on the 0.2.x MSI retirement (owner step) — not ours.
- [ ] **S4. One-scan household onboarding (P1)** — the exploration walk's default pick,
      ratified with this plan. Design + breakers first (enrollment currently rides
      invite tokens + manual server URL entry; the QR carries server origin + invite
      token + fingerprint commitment — NEVER key material; attack: QR shoulder-surf,
      token TTL/single-use, MITM origin substitution vs the pinned recovery fingerprint),
      then build: owner web "Add family member" surface mints QR; Android scans it
      (camera permission — new), prefills enroll; desktop/web paste-link fallback.
      Review + ship checkpoint (web deploy + APK if Android changed).
- [ ] **S5. Wrap + successor pitch** — reconcile ROADMAP/backlog checkmarks, refresh the
      PICKUP doc for the next human session, one exploration-lane completeness pass over
      this plan's residue → pitch the next queue (candidates already visible: passkeys
      store+Android-provider when triggered, extension tier-2 distribution decision,
      real-secrets migration once the owner's gate clears). Statement with headlines.

## Parked for owner (carried + new)

- 0.2.x MSI retirement (= card-create Option-A flip + windows manifest entry).
- Extension tier-2 auto-update distribution (signed .xpi / store) — distribution decision.
- Real-secrets migration date — after owner TOTP + drills + 30-day soak.
- IBAN/bank-account item type — ratify from S3's scope addendum.
- Fold biometric/autofill feel-check; extension load-unpacked upgrade to 0.8.1.
