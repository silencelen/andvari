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

- [ ] **N1. Real-secrets readiness cycle (M) — the milestone unblock.**
      Live-verify every gate item against CT122 (server-TOTP enrolled? drill artifacts current?
      backup freshness? escrow canary?); seed the synthetic soak accounts if absent; write
      `docs/runbooks/real-secrets-migration-day.md` — the step-by-step for migration day
      (old-manager export → guided import per member → spot-verify counts/TOTP/attachments →
      old manager to read-only for 60 days → deletion ceremony), including the rollback story;
      finish with a **go/no-go checklist where every remaining line is an owner action with its
      command/screen named.** Ship = docs + any small verification tooling; no product change.
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
- [ ] **H1. Hardening backports batch (approved 2026-07-11)** — Android epoch-guards +
      copy-gate backports (the N3 breaker/review holes exist on Android too); skeletal-
      tombstone truth fix; web "reload to update" nudge; **autofill browser reach** (Z Fold
      report 2026-07-11: only Brave dispatches by default — Chrome needs its "Autofill using
      another service" setting [user step, pin already static]; Samsung/Edge need
      compatibility-package XML from us + one-tap trust; add a "Browser support" card to
      Autofill status). Stretch: desktop syncing/busy split. Cut 0.14.2.
- [ ] **R1. Migration rehearsal (approved 2026-07-11)** — the real-secrets runbook executed
      end-to-end on a LOCAL throwaway server (scratch escrow; no live-CT mutation, no auth
      manufacturing); output = runbook amendments + re-runnable harness + "rehearsed ✅" in the
      go/no-go. Docs+tooling, no cut unless bugs surface.
- [ ] **O1. Ops rider (approved)** — apply the ready-to-apply purge-stall Grafana alert
      (metric live since the 0.8.0-era deploy) + andvari monitor sanity pass; verify the rule
      attaches to a live series.
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
- Windows MSI rebuild (`ops/windows-build.md`; desktop 0.13.0 in-tree, fielded MSI 0.2.x —
  now 7+ releases behind; retiring it is ALSO the N4 trigger).
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
