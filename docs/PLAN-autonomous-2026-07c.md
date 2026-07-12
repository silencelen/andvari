# andvari — successor plan (RATIFIED 2026-07-10)

> **Owner ratification, verbatim (interactive session, 2026-07-10):** *"continue, then ratify
> the successor plan and keep going."* The predecessor (`PLAN-autonomous-2026-07b.md`) is
> complete — every queue item shipped or explicitly re-filed; 2026-07-10 closed with NINE cuts
> on the day (0.10.0 through 0.13.0 + the extension hotfix), zero reverts, every deploy gated,
> adversarially reviewed, snapshot-first, and byte-verified. **The predecessor's pre-approval
> scope + standing doctrine carry unchanged:** checkpoint-only deploys to CT122/devstore,
> snapshot-first (real `VACUUM INTO` script + integrity check; vzdump when the jar/schema
> changes), file-logged gates (never `| tail`), breaker-before-build for designs,
> find→refute-verify review with confirmed findings fixed before ship, Telegram statements only.
> A session picks the FIRST unchecked cycle, runs it end-to-end, checks it off with a dated
> note, rolls on. Decisions that genuinely need the owner: park, continue with the documented
> default, never block. **First cycle: N1 (real-secrets readiness).**

## The honest headline

The product is now feature-rich and battle-reviewed — but **the vault still holds zero real
household secrets.** Everything gates on the real-secrets migration, and most of what remains
there is owner-clock (TOTP enroll, drills, the 30-day soak, the migration date itself). The
queue below therefore leads with the one cycle that CONVERTS owner-clock into a checklist —
and keeps feature work in trigger-gated lanes so the soak window stays quiet.

## Proposed queue

- [x] **N1. Real-secrets readiness — DONE 2026-07-10 (`bd798b9`; checkbox recorded late).**
      `docs/runbooks/real-secrets-migration-day.md` shipped with the live CT122 gate probe:
      escrow genesis + backups + admin account verify READY; **the ONE hard blocker before
      real secrets = server-TOTP enrollment (totp_enrolled=0)**; soak-account seeding
      deliberately owner-clock (needs the printed sheet). Migration steps updated to the
      universal importer in the 0.14.1 cut. Every remaining go/no-go line is a named owner
      action.
- [x] **N2. Residue hardening batch — DONE, SHIPPED 0.13.1 (2026-07-10, `b68ed1d`).**
      All seven items closed in one cycle: bare-426 body-code-only (+ new AndvariApiErrorTest);
      EnrollLink twins reject lone surrogates + astral/`composeRejects` shared vectors; native
      policy-fetch honesty + Retry ×2 (desktop `updateServer` now re-probes — B5); master-pw
      + confirm out of the Bundle (TOTP deliberately saveable); F49 janitor prunes 6 tables
      (30d changes-fence keyed to the tombstone constant, MAX(rev) floor — breaker-caught
      BLOCKER — atomic advance, 410 contract now LIVE, closes the 30-89d deletion-resurrection
      window; 6 new JanitorTests; spec 02 §7 + 03 §11 updated); F26 lock reasons ×2 (F22
      dropped-with-reason — no native roster; re-surfaces inside N3); web post-delete note
      lifted + transition-based clear. Review: 6 findings → 5 confirmed → all fixed (incl. the
      Android setBaseUrl change-time clear + the null-policy reset-block dead-end + the 4th
      frame-stale sighting on desktop enroll). Gates verify/desktop/e2e all EXIT=0; snapshot
      `pre-0131` + vzdump before deploy; served bytes hash-verified (web bundle, deb sha,
      manifest merge). **Newly filed from this cycle:** (a) skeletal-tombstone rows vs
      `purgeOldItemTombstones` collision — purgeVault's "retained indefinitely" skeletons are
      in fact GC'd at 30d (pre-existing, WS-D find; needs a vault-filter or a spec truth fix);
      (b) web/extension have NO 426 gate at all (dormant until a pin is armed; small "reload
      to update" nudge when touched next); (c) item-editor secret fields in `rememberSaveable`
      (password/totp/cardNumber/CVV) — parked for owner below.
- [x] **N3. Desktop vault management — DONE, SHIPPED 0.14.0 (2026-07-11, `32ae161`).**
      Full Android-parity Sharing surface on desktop (list + per-vault settings: rename/
      transfer/delete w/ typed-confirm + rescue; leave; trash disclosure) + the global
      AttentionArea desktop was MISSING (notices/transfers/F20 were silently dropped —
      offers to a desktop-only member were invisible) + friendlyError map on all desktop ops.
      Breaker: 1 BLOCKER (async writes epoch-guarded — cross-account PII leak) + 8 AMENDs, all
      landed. Review 5→5 confirmed → 2 real defects fixed pre-ship (rescue-copy single-flight;
      editor composes the global ErrorBar). Snapshot pre-0140 + vzdump; all bytes verified
      (web sha, deb sha, APK vc 16534588). **Android backports filed → H1.**
- [x] **N3b. Universal importer — RATIFIED 2026-07-11** ("go ahead with the universal importer
      after N3"). Design + breaker DONE (`docs/design/2026-07-11-universal-importer.md`, no
      blockers, 3 AMENDs folded); BUILD IN FLIGHT as this line lands — one universal import
      screen ×3 clients, per-source export help demoted to a collapsible block (core-shared for
      natives), mismatch machinery deleted, desktop wildcard fixed. Cut 0.14.1.
- [x] **H1. Hardening backports — DONE, SHIPPED 0.14.2 (2026-07-11, `fb875b4`).**
      Android B1 epoch guards + full copyOpVaultId gate (incl. the Android-only discovery:
      the gate must publish into VaultSession.setOperationInProgress — TWO idle observers);
      autofill compat XML for Samsung/Edge + "Browser support" card (Chrome = user setting,
      documented in-app); web reload-to-update banner; tombstone truth fix via resolution (B)
      with the updatedAt restamp (the "30d" was a random 0-30d before) + the two-legged fence
      argument written honestly in all three prose sites (review's one confirmed LOW). Review
      4 dimensions → 1 LOW confirmed (docs) → fixed; 3 dimensions clean. Stretch
      (syncing/busy split) deliberately cut — re-filed to the residue ledger. Fold
      verification steps: toggle andvari off/on as the autofill service after installing
      0.14.2, then test Samsung/Edge (dropdown, not keyboard chip) + flip Chrome's setting.
- [x] **R1. Migration rehearsal — DONE 2026-07-11.** `scripts/migration-rehearsal.sh` (NEW,
      re-runnable, trap-cleaned): the runbook's 13 machine-verifiable legs green on a local
      throwaway server — scratch genesis + canary proof, bootstrap admin w/ real typed-sheet
      gate, server-TOTP 0→1 (gate-1 probe), bootstrap stripped, invite→member enroll + reuse
      refusal, pre-import VACUUM snapshot, 25-row Chrome CSV through the REAL client code
      (23 imported + TOTP/note/dedupe spot-checks), re-import = 0/24 alreadyInVault
      (§Rollback proven), full break-glass recovery w/ an imported canary, public-origin
      TOTP refusal/acceptance. REHEARSAL_PASSED in 81s. **Real finding:** the same-IP login
      rate-limiter (5/min public) can block a break-glass login for ~60s after normal
      sign-ins — runbook item 2 now warns (wait 60s, mint the code fresh). Report:
      `docs/drills/migration-rehearsal-2026-07-11.md` (script-covered vs owner-only table).
      No cut — docs+tooling only, CT122 untouched.
- [x] **O1. Ops rider — DONE 2026-07-11.** `andvari-purge-stalled` rule created (provisioning
      API — the grafana MCP token still 401s; the netplan service-account token works) and
      verified evaluating `health=ok` against the live series alongside the other three
      Andvari rules (all ok = the monitor sanity pass). Spec doc status updated in place.
- [x] **X1. Exploration quad-sweep — DONE 2026-07-11.** Queue was empty; probes showed
      nothing moved; owner picked ALL FOUR standing exploration candidates ("all 4"). One
      find→refute→critic Workflow pass @ `e6f3ccb` (70 agents, 0 errors): **85 confirmed /
      3 refuted**. Full ledger: `docs/assess/2026-07-11-quad-sweep.md`. Same session: all
      **39 doc-only truth fixes applied** (spec 00–06 + spec/psl/README + README + ROADMAP +
      a dated ia-cut2-banners-update deviation note). **Scale @ 10k = clean bill** (import 9.1 s, cold
      sync 532 ms / 5.2 MB, search p50 ≤ 12 ms, janitor < 4 ms, server VmHWM 601 MB under
      load — no action). The 0.14.0/0.14.1 design docs + N2/H1 shipped-claims checks came
      back clean. 10 standalone code items filed in the ledger (sharpest: spec07-1 web
      export silently drops VK-less vaults instead of enumerating them in
      skipped.undecryptable; spec02-1 metaV regression check unimplemented on all clients;
      spec03-01 no global request-body limit; spec01-f61 KDF-upgrade re-key is
      Android-only).
- [x] **E1. DONE — SHIPPED extension 0.10.0 (2026-07-11, `fd8d4a8`, pushed).** Extension
      hardening (was: cut ext 0.10.0).
      All 10 items landed (13 findings; 3 merge pairs): E1-1 identityPub derive-and-compare
      (spec 01 §5 tripwire, hard-fault before decrypt) · E1-2 X-Andvari-Client `extension`
      token + minimal 426 surface (min-version net can now reach the extension, zero server
      change) · E1-3 error taxonomy (codes cross the seam, copy in new chrome-free errors.ts,
      verbatim web ladder) · E1-4 clipboard auto-clear (layered local timers + SW alarm
      backstop; Chrome offscreen, Firefox event-page) · E1-5 locked-save copy + post-unlock
      re-offer · E1-6 rescue-password nudge · E1-7 F26 lock-reason line · E1-8 TOTP
      determinism backport + native totp.json execution · E1-9 refresh transient-keep +
      consume-persist-guard (no spent-token resurrection → refresh_reuse) · E1-10 -scripting.
      Doctrine ran full: design (`docs/design/2026-07-11-extension-hardening.md`) → breaker
      (1 BLOCKER — offscreen empty-string execCommand silently no-ops; + 8 binding
      amendments, all folded pre-build) → 2 Opus builders, disjoint files + pinned seam
      (first Fable pair died on a credit limit mid-build; B's partial finished not
      discarded) → gates (tsc clean, node --test 30/30, build+package emit offscreen) →
      find→refute review (6 dims → refuter each; the security dim re-run after a misfire) =
      **0 confirmed defects** → snapshot-first ship (manifest backed up `manifest.json.bak-
      pre-ext-0100`; NO vzdump — zero server/jar/schema touch) → byte-verified served zip
      shas (chrome 9f7cf3d3…, firefox e651f8d7…) + manifest 0.10.0 with `linux` 0.14.2
      preserved + healthz 200 → pushed. Telegram statement sent. **Owner step unchanged:
      load-unpacked the 0.10.0 build (was 0.9.0).** ~10 S items, one module, security-adjacent (ledger §E1): X-Andvari-Client
      header + a minimal 426 surface (today a min-version pin can NEVER gate the extension);
      clipboard auto-clear (spec 01 §8 says every client); TOTP determinism backport + run
      spec/test-vectors/totp.json; identityPub mismatch check on unlock (spec 01 §5 MUST);
      error taxonomy ({error,message} parse + canonical unreachable-server copy); locked-save
      re-offer; mustChangePassword surface; refresh killed only on definitive 401/403 (web-B7
      mirror); drop the unused "scripting" permission; F26 lock-reason parity. Recommended
      FIRST of the two proposed batches.
- [x] **A1. DONE — SHIPPED web/android/desktop 0.15.0 + extension 0.11.0 (2026-07-11, `5963a17`,
      pushed). Accessibility batch ×4 clients.**
      45 adversarially-confirmed findings (the quad-sweep's 23 web/android/desktop + a new
      22-finding extension a11y sweep), 6 cross-client principles (label association, live
      regions, icon names, focus, no-colour-alone, contrast), ZERO server/core/wire/storage
      change. Design `docs/design/2026-07-11-accessibility-a1.md`. Doctrine ran full: design →
      breaker (2 BLOCKERS — the silent-polite-region trap [BL-1] + the Field div-mis-association
      [BL-2] — + 11 binding amendments, all folded pre-build) → 4 fully-disjoint Opus builders
      (no shared seam; one misfired→relaunched) → per-client gates → find→refute review (5 dims:
      1 confirmed P3 [desktop dismiss-button contrast twin] fixed + 1 refuted) → verify.sh GREEN
      (lockstep 0.15.0 ×4, Kotlin/android/web 352/extension 35) + desktop compileKotlin green →
      shipped: web via ops/deploy.sh (served index sha == build, healthz 200) + extension zips +
      manifest MERGE (0.11.0, linux 0.14.2 preserved, served shas verified). **Owner call: 7c
      UI-boundary contrast → high-contrast mode (A2).** **Deferred → A1b (named follow-up):**
      web focus-return on inline-confirm/layer-transition (a11yweb-06); extension in-page
      autofill dropdown keyboard-nav + save-prompt alertdialog (6a/6b/6c); the login-row
      nested-button restructure (3e); desktop focus-RETURN remainder. **Owner steps:** APK
      (assembleRelease + keystore) + desktop deb/MSI builds; the manual screen-reader smoke
      (NVDA web/ext, TalkBack android, Access-Bridge desktop) — the ONLY proof of actual
      announcement (static gates prove markup, not spoken output). GOTCHA logged: NEVER wrap
      `scripts/verify.sh` in an outer `flock` — it flocks the gradle lock internally →
      self-deadlock (cost ~1h this run). 23 confirmed findings incl. the sweep's only P1 — web has
      zero programmatic label association; zero live regions on web AND Android; contrast
      failures in both themes; desktop has no focus management at all (ledger §A1). Wants its
      own design pass (per-client semantics patterns) + breaker before build; fold in the
      extension-a11y gap (ledger critic #5/6).
- [ ] **N4. (TRIGGER: owner retires the 0.2.x MSI) Card-create Option-A flip + S3 (M).**
      The flip ceremony from the cards design §build-order (flip `CARD_CREATE_ENABLED` ×2 +
      unhide, windows manifest entry, verify old-MSI absence), THEN S3 extension in-page card
      fill (its design doc exists; breakers not yet run; version notes stale — ext is 0.9.0).
      Until the trigger: nothing (S3 value stays dark without creatable cards).
- [ ] **N5. (TRIGGER: a household site pushes passkey-first) Passkeys O1+O2 (L).**
      Per `docs/assess/2026-07-passkeys.md`: ES256/COSE spec-01 amendment first, store-as-fv3
      item (cards precedent), then the Android CredentialProviderService (API 34+) — the one
      surface that's both sanctioned and useful. Not before the trigger; not during the soak.
- [ ] **N6. (TRIGGER: a daily iPhone user hurting) iOS PWA polish (S).**
      Per `docs/assess/2026-07-ios.md` option 1: manifest + app-shell SW polish only; native
      iOS stays parked behind demonstrated demand.
- [ ] **N7. Exploration lane (pitch-only until ratified separately).**
      Standing candidates from the persona walk, unchanged: **P2 warm owner-held member escrow**
      (L — trust-model change, spec 04/05 amendment + consent UX; explicitly NOT during the
      soak) and **P3 escrow-free guest tier** (M-L — public-origin threat-model expansion the
      owner must sign); plus the Steward ops panel horizon. A fresh persona walk after the
      family is ACTUALLY enrolled would re-rank these on real usage.

## Parked for owner (the complete current list)

- Server-TOTP enrollment on CT122 (blocks break-glass sign-in; N1 will verify live state).
- Windows MSI rebuild (`ops/windows-build.md`; desktop 0.14.2 in-tree, fielded MSI 0.2.x —
  now ~12 releases behind; retiring it is ALSO the N4 trigger). *(Version corrected
  2026-07-11 by the quad-sweep — chg-1.)*
- PBS-restore / min-version-pin / backup-verify drills; the 30-day soak; the migration date.
- Extension: load the 0.9.0 build (load-unpacked); the tier-2 distribution decision
  (signed .xpi + update_url vs a store listing).
- IBAN/bank-account item type: ratify or drop (scope addendum pending from S3's cycle).
- Feel-checks on the Fold: enrollment ceremony (0.10.2), settings flyout (0.11.0), trash
  icons + launcher icon (0.11.1), notices/AttentionArea (0.13.0), lock-reason line +
  policy-Retry (0.13.1).
- Item-editor secrets in Android's saved state (N2 follow-on): the editor keeps item
  password/TOTP/card number/CVV in `rememberSaveable` — same Bundle-exposure class the
  0.13.1 master-password fix closed, but flipping it means a fold/rotation loses a
  half-typed item (the longest-typing surface; the in-code comment calls it deliberate).
  Owner call: accept the exposure or accept the data-loss trade.

## Residue ledger

The full 33-item reconciled residue (sources + sizes) lives in the 2026-07-10 wrap notes; the
queue above consumes items 1-31 either directly (N1-N3), by trigger (N4-N6), or leaves them
explicitly parked. Nothing from the sweep was dropped silently.
