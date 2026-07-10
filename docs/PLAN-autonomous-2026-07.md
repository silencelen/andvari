# andvari — standing autonomous plan (ratified 2026-07-10)

> **Owner ratification, verbatim (interactive session, 2026-07-10):** *"deploys pre approved
> for this plan. continue with it all … this brings us into compliance with our roadmap and
> development goals."*
>
> Scope of the pre-approval: web/server deploys to CT122, APK ships to devstore, and
> deb/extension publishes to CT122 `/downloads`, **at this plan's cycle checkpoints only**,
> and **always** under the standing doctrine — DB `VACUUM INTO` snapshot (+ vzdump when the
> server binary/schema changes) BEFORE any server touch, verify.sh + `:app-desktop:classes`
> (+ e2e.sh when server/wire code changed) green with FILE-LOGGED exit codes, and the
> adversarial-review workflow passed with confirmed findings fixed, before anything ships.
> If a future session's deploy classifier still balks, relay this section and ask — never
> work around a denial.

This file is the SSOT for the current autonomous run. A session picks the FIRST unchecked
cycle, executes it end-to-end (build → gates → review → fix → commit → push → ship at the
checkpoint), checks it off with a dated note, and rolls to the next. The house operating
doctrine (PICKUP-v9 §operating mode + §gotchas) applies to every cycle. Anything that grows
user-visible scope beyond what's written here still gets a one-paragraph owner heads-up
(statement, via Telegram) before the build — but does not wait for a reply.

**Runs in parallel on the owner's clock (not gating, not ours to do):** the real-secrets
gate (owner server-TOTP enrollment → drills → 30-day soak); the 0.7.0 owner steps (Windows
MSI build — which also retires the 0.2.x desktop and flips the Option-A card-create gates —
Fold autofill re-run, extension load-unpacked). Nudge by Telegram statement at most once
per cycle boundary if still open.

## The queue

- [x] **1. QW-3 landing** — **DONE 2026-07-10 [`666dba7`].** 3-lens review: 2 confirmed
      (MEDIUM: the new F12 hard-lock timer made a latent race deterministic —
      SaveConfirmActivity never mirrored its in-flight save into the process-wide
      operationInProgress flag, so the timer could close the engine under a running save →
      failed save + duplicate-on-retry; LOW: bind()/hydrate throw paths leaked the
      token-holder). Both fixed; 0 refuted. Gates green. Also synced the web + extension
      `urimatch.ts` NEGATIVE_HINTS mirrors for F11 (cross-module seam the vector caught).
      Natives ride the 0.9.0 cut (cycle 3).
- [x] **2. Quick-unlock (F84 + F61)** — **DONE 2026-07-10** (design+breakers `c06c978`,
      build+review `b987680`). Breakers: 0 fatal / 9 serious → amendments A1–A10. Build review:
      3 LOW confirmed, 0 refuted; the MAX-effort core-crypto lens found NOTHING (UVK boundary
      held). Notables: A3 closed a pre-existing hole (autofill-only process never purged on a
      definitive 401 → a revoked device kept opening the cached vault offline forever); A5
      blocks F61's silent re-key while `mustChangePassword` (it would clear the flag
      server-side while the admin-known temp password stayed live); A2 hardened to fail closed
      cross-boot without a server-attested time anchor. Owner step (not a gate): on-device
      biometric feel-check.
- [ ] **2-OLD (superseded, kept for the record). Quick-unlock (F84 + F61)** — the owner-requested cycle. Order: spec pass FIRST
      (spec 01/05 additions: cacheAllowed gating, the at-rest wrapped-secret row in the
      threat model, the F61 KDF-upgrade-on-full-unlock rule + its quick-unlock interplay,
      the periodic-full-password rule) → design doc + 2-breaker pass → build (core
      `Account.unlockWithUvk` ≈15 lines; Android BiometricPrompt + Keystore AES-GCM wrap of
      the UVK, invalidated on biometric enrollment change; wire into AutofillUnlockActivity
      + MainActivity unlock) → adversarial review (key-handling lens at max) → commit.
      **Windows/desktop quick-unlock stays DEFERRED** (backlog: past the MSI refresh).
      On-device biometric feel-check = owner step at the end, not a blocker.
- [ ] **3. Cut 0.9.0 natives** — version bump ×4 (verify.sh consistency gate), CHANGELOG,
      APK → devstore (`scripts/ship.sh release`), deb → `/downloads` + manifest merge
      (linux entry only unless the extension changed), full gates on the release commit
      first. Ships quick-unlock + the QW-2/QW-3 native fixes together. Telegram statement.
- [ ] **4. skipti-loose-ends** — F18 vault picker for NEW items on both natives (kills
      "silently lands in Personal"; core `saveWithUploads(vaultId)` exists) + vault-name
      tags on rows/detail + desktop Move/Copy (F19 parity); F20 member transparency; LC-1.
      Web deploy checkpoint only if web files changed; else commit-only.
- [ ] **5. Extension update-available signal** (owner dev-note 2026-07-10, tier 1) — SW
      version-check against `/downloads/manifest.json` (cached, ~daily), popup badge +
      "download & reload" pointer, Devices-hub line. NO silent reinstall (unpacked Chrome
      forbids it); tier 2 (signed .xpi update_url / store distribution) stays a ROADMAP
      item needing an owner decision. Bump extension version ×3 (package.mjs drift-guard),
      rebuild zips, publish to `/downloads` + manifest merge at the checkpoint.
- [ ] **6. eTLD+1 / PSL matching** — UriMatch upgrade both impls: registrable-domain
      matching (login.example.co.uk ↔ example.co.uk) with a vendored, size-bounded PSL
      snapshot (document staleness posture) or a curated-suffix fallback — DESIGN CHOICE
      inside the cycle, breaker-passed; vector file extension (its own new section/file;
      existing vectors byte-frozen); extension + web + core in lockstep. This changes
      match behavior — the design doc must pin the no-loosening invariant (never match a
      DIFFERENT registrable domain) and the review must attack it.
- [ ] **7. Web polish pack** — vault-list virtualization >~500 items (hand-rolled window
      per the F56 addendum recommendation, React-profiler note in the commit); PROD-1
      (audit appender wiring — verify what's actually unreferenced, fix or document);
      SB-4 client debt (F71, F82 — land before any next spec-07 change — F80 cosmetics
      last). Web deploy checkpoint.
- [ ] **8. Assess-only docs + exploration pass** — `docs/assess/2026-07-ios.md` (honest
      feasibility: KMP core vs crypto/keystore/autofill surfaces) and
      `docs/assess/2026-07-passkeys.md` (what passkey support would even mean for a
      household ZK vault; store-vs-provide split). Plus ONE exploration-lane pass (persona
      product walk or idea tournament grounded in the tree) → top-3 pitches with honest
      costs, written to docs/, Telegram statement with the headline. No build without a
      ratified follow-up plan.

## Standing rules for this run

- One cycle at a time; never leave a cycle half-done at a session boundary without
  updating THIS file + the memory fact file with exact state.
- Every ship checkpoint: snapshot first, gates green (file-logged exits, test-XML counts
  for new suites), review passed, CHANGELOG/docs true, then ship + verify served bytes.
- Telegram = statements only. Decisions that genuinely need the owner: park in this file
  under "Parked for owner", continue with the documented default, never block.
- Update ROADMAP/backlog checkmarks + the memory fact file at each cycle close; diary
  at session close.

## Parked for owner (running list)

- Extension tier-2 auto-update distribution (signed .xpi + update_url vs Chrome Web
  Store) — needs a distribution decision; tier 1 ships regardless.
- Real-secrets migration date — after owner TOTP + drills + 30-day soak.
- 0.2.x MSI retirement (= the card-create Option-A flip trigger).
