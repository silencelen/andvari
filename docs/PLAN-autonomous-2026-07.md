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
- [x] **3. Cut 0.9.0 natives** — **DONE 2026-07-10 [`b538e69`].** Version bump ×4 + CHANGELOG;
      gates green (a `:server:test` WS-ticket timeout on the first run was a load flake —
      re-ran isolated 98/98, then a clean full verify before cutting). Shipped: APK vc
      16451100 → devstore; `.deb` 0.9.0 + manifest merge → CT122 `/downloads` (extension entry
      preserved at 0.7.0); server+web redeployed at 0.9.0 (DB snapshot `pre-090`, schema v5
      untouched, 296 items intact). Windows MSI remains the owner step.
- [x] **4. skipti-loose-ends** — **DONE 2026-07-10** (LC-1 `1f8903c`; F18/F19/F20 in the
      follow-up commit). LC-1 moved the denial verdict from provenance ("was it a replay?")
      to state ("is the vault held?") — the tests pin both behaviours but honestly do NOT
      reproduce the race (documented in `LifecycleReplayLossTest`'s KDoc). The F18/F20
      workstreams' structured reports came back degenerate ("probe", retry-cap) while the
      TREE was real — salvaged by reading the code, not the reports; a trailing lambda in
      `DesktopState.moveOrCopyItem` had bound to `finalSync: Boolean` instead of
      `onProgress` and only `:app-desktop:classes` (NOT in verify.sh) caught it.
      4-lens review: **1 confirmed / 0 refuted** — the "you were added to X" notice fired on
      the OWNER's own vault on a second device (owner grants carry a UVK-opened `wrappedVk`,
      so `heldBefore` is false); fixed with a `roleFor === "owner"` skip + a test verified to
      FAIL with the guard reverted (mutation-checked). Web tests 294 → 295, gates green.
- [x] **5. Extension update-available signal** — **DONE 2026-07-10.** Pure `isNewerVersion`
      (fails closed on malformed; unit-tested via Node's built-in runner — new `npm test` in
      extension/, node 22 native TS, tsconfig excludes `*.test.ts`) + SW `checkForUpdate`
      (daily `updatecheck` alarm + onInstalled/onStartup + throttled wake IIFE; fetches the
      PUBLIC `/downloads/manifest.json`, stores non-secret `updateInfo` in storage.local,
      20h throttle, transient failure never clears a real signal, `updateStatus` re-validates
      vs the installed version so no stale nag after an in-place update) + popup banner (both
      views, Firefox/Chrome zip by UA) + Devices-hub posture line. **Toolbar badge deliberately
      NOT used** — `pageInfo` already owns the per-tab match-count badge; an update badge would
      collide. Version bumped ×3 (0.7.0→0.8.0, drift-guard satisfied). 3-lens review: **0
      confirmed / 1 refuted** (the refuted one — updateStatus re-arming autolock — collapsed
      because an unlocked popup open already re-arms via matches/allItems). Tier 2 (signed
      .xpi update_url / store distribution) stays parked for owner. Deploy checkpoint: web +
      extension zips → `/downloads` + manifest `browserExtension.version` → 0.8.0.
- [x] **6. eTLD+1 / PSL matching** — **DONE 2026-07-10.** Full vendored PSL (10,230 rules,
      snapshot 2026-07-09, ICANN+private) → `scripts/gen-psl.py` → three generated data
      files; three-state resolver (REGISTRABLE/PUBLIC_SUFFIX/UNKNOWN, explicit rules only —
      no implicit `*`); match = exact → R-SUFFIX-BARE (bare suffix exact-only BOTH roles) →
      R-EQ (both known → registrable equality) → R-OLD (any unknown → old rules bit-for-bit;
      `.lan`/`.local` untouched). **Breakers 1 FATAL / 8 SERIOUS / 4 MINOR pre-build →
      amendments A1–A12** (the FATAL: exact-rule-membership tightening missed all 283
      wildcard-derived suffixes — `us-east-1.compute.amazonaws.com` kept filling every EC2
      tenant; fixed by the discriminated resolver). All 25 frozen vectors byte-preserved; 47
      new shared vectors incl. the extension's FIRST native vector run (cycle-5 harness).
      verify.sh now gates the extension (A7); package.mjs refuses failing tests + caps
      content.js 60KB (A8 — verified 20.0KB, PSL rides only the SW bundle). **Build review
      13 raised → 11 confirmed / 2 refuted, all 11 fixed:** normalizeHost made IDEMPOTENT
      ×3 (www-loop-strip + single-colon port rule — the extension double-normalizes and
      diverged from core on www.www/IPv6 hosts; IPv6 sites had silently stopped filling),
      Kotlin isIpLiteral ASCII-only (unicode-digit parity gap), csv uriClass `j:` verbatim
      class ×2 (A5 junk would false-merge on re-import), package.mjs glob (not a hardcoded
      file list), gen-psl whitespace-split + charset whitelist, spec §3.1 staleness wording
      honest (private-section gap = Bitwarden-parity, not "never widens"), versions bumped
      ×4 → 0.10.0 (no second behaviorally-different "0.9.0" can ever field), A8 doc wording.
      Gates green at 0.10.0. Checkpoint: web deploy + extension 0.8.1 publish.
- [x] **7. Web polish pack** — **DONE 2026-07-10.** PROD-1 was found ALREADY SHIPPED
      (`0eebbfd`, appender + boot-assert test — verified, not re-done). Two parallel
      workstreams (disjoint files, honest reports this time): [web] hand-rolled window
      (virtual.ts ~25 lines + 9 vitest cases, engages >500, page stays the scroller,
      10k items ≈ 200 DOM nodes vs 70k) + all 7 F80 items (ViewHeader, .check, carded
      hero, .item.static, keyboard Health rows, SVG sigils, email in appbar); [native]
      F71 (editor closes only via onSaved, inline error + upload progress, atomic
      attachment writes, overwrite confirms, core saveWithUploads onProgress) + F82
      (ExportPlanner twins DELETED → one jvmShared copy, union shape with android's
      BackupRequest; SyncEngine envelopes()/vaultRows()/grants() read surface; carried
      private-cache refs gone from BOTH natives). **Review 6 confirmed / 0 refuted, all
      fixed** — the HIGH: F71's designed retry WEDGED on `attachment_id_taken` (retry
      re-encrypts with a fresh secretstream header → sha differs → server dedup refuses
      the once-minted id forever); fixed by treating id_taken for our own refs as
      already-committed (save + gesture legs) PLUS a `newItemId` draft param so a NEW
      item's retry reuses the first attempt's id (else `attachment_mismatch` at push) —
      2 new server-integration tests, MUTATION-CHECKED. Also: Cancel busy-gated,
      dedicated saveError (backgroundSync's global error no longer paints inside the
      editor), useLayoutEffect first-frame fix, overflow guard at accessibility fonts,
      focus-past-overscan documented as the accepted react-window-parity tradeoff.
      Gates green (web 308, extension 8/8 inside verify.sh, desktop compiles). Web
      deploy checkpoint; F71/F82 ride the 0.10.0 native cut.
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

## Owner dev-notes queued (post-cycle-8 candidates)

- **Import destination vault picker** (dev-note 2026-07-10): *"when importing data from an
  external csv or password manager, the user should have the option to choose which vault
  they are imported into."* Today the guided importers commit everything to the Personal
  vault — the import-flow sibling of the F18 "silently lands in Personal" fix (cycle 4).
  Scope: a writable-vault picker (same choices rule as F18: personal + owner/writer shared,
  shown when >1 choice) on the import CONFIRM step, web + Android + desktop; core commit
  path takes the vaultId (per-import, not per-row, for v1). Note: the vault-dedupe pass
  (F75) currently fingerprints against the whole vault set — re-check its scoping when the
  destination is a shared vault. Natural pairing with the card/payment cycle pitch below.

- **Card / payment autofill+storage** (dev-note 2026-07-10): *"support storing autofill
  creditcard and payment details."* State check: card **storage + UI + Android card
  autofill + extension copy-only Cards popup shipped in 0.7.0** — but card-CREATE is dark
  everywhere (Option A) until the 0.2.x MSI retires, so from the owner's seat it doesn't
  exist yet. The genuinely-new work: (a) flip card-create when the MSI retires (checklist
  in the cards design doc §build-order — an owner step + a small unhide pass), (b)
  extension IN-PAGE card fill, deliberately deferred behind the frame-origin egress
  contract (cards design 2026-07-09) — needs its own breaker-passed design cycle, (c)
  possibly non-card payment types (IBAN/bank account) as a new item template — scope
  decision. Next session: pitch these three as a cycle with honest costs.
