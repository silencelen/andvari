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
- [ ] **N2. Residue hardening batch (S-M) — one cycle, one review.**
      The filed items that are ours: core `errorFrom` bare-426 tightening (require
      `upgrade_required`; touches desktop — regression-test both); the `EnrollLink.compose`
      UTF-16 surrogate twin-pin; native policy-fetch-failure vs "no recovery key" honesty +
      Retry (web parity); master-password OUT of `rememberSaveable` (decide fold-loss vs
      Bundle-exposure and implement); F49 janitor pruning for sessions/changes/mutations/audit/
      hibp_cache/invites; the F22/F26 tiny residues; the web dead post-delete toast. Cut as
      0.13.x/0.14.0 by content.
- [ ] **N3. Desktop vault management (L) — the biggest parity gap.**
      Desktop has NO Sharing surface (no lifecycle, no members view, no per-vault settings,
      no recently-deleted/removed) — flagged in DN-1 and deliberately not smuggled in. Port the
      Android screens over the shared engine (the engine already carries everything; this is
      UI + DesktopState wiring). Design-lite (mirror the reviewed Android shapes) + full review.
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
  icons + launcher icon (0.11.1), notices/AttentionArea (0.13.0).

## Residue ledger

The full 33-item reconciled residue (sources + sizes) lives in the 2026-07-10 wrap notes; the
queue above consumes items 1-31 either directly (N1-N3), by trigger (N4-N6), or leaves them
explicitly parked. Nothing from the sweep was dropped silently.
