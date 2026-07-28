# andvari — Roadmap

Where andvari is, what gates real-secret migration, and where it goes next. Living doc.
**The SSOT for *state* is the git history + `CHANGELOG.md`** — when this file and a commit
disagree, the commit wins. This is the SSOT for *direction* only.

> **Reading this file.** Sections are dated campaign records, kept rather than deleted so the
> reasoning stays auditable. Done work is marked with ~~strike-through~~ + a **DONE `<date>`**
> and a commit; anything unmarked is genuinely open. Reconciled against git 2026-07-27.
>
> **Two conventions in the older sections.** (1) Paths under `ops/` and `docs/{assess,pentest,recon,drills}/`
> were never in this repository — they are the reference instance's private, out-of-tree operational
> area; read them as "recorded elsewhere", not as broken links. (2) `CT122` and similar names are that
> one instance's host labels, not part of the product; andvari is endpoint-agnostic and every client
> works with any server (spec 00 "System shape", `docs/self-hosting.md`).

## Public-release trust & attestation campaign — 2026-07-16 (partly landed; see status)

> **Status 2026-07-27.** The flip happened — the repository is public and the owner forks were
> taken: **F1** landed (`LICENSE` + `LICENSING.md`), **F2** landed (full history published), and
> **W3 is largely in place** (`.github/workflows/codeql.yml`, `scorecard.yml`,
> `gradle-wrapper-validation.yml`, `.github/dependabot.yml`, `SECURITY.md`). **Still open:**
> W1 whitepaper, W2 wire-egress harness, W4 artifact provenance (note GitHub Actions cannot run
> release builds on this account — releases are published by hand from a build host), W5 fuzzing,
> W6 external audit, W7 posture-doc publication. Lane text below is the original plan, unedited.

The outward-facing trust layer for the public flip: what proves to a stranger that the crypto
does what we say and that any server operator sees exactly spec 02 §5 and nothing more. Design:
**`docs/design/2026-07-16-trust-attestation-strategy.md`** (DRAFT for owner ratification, 4
announced-default owner forks: F1 license = GPLv3 clients + AGPLv3 server · F2 = publish full
history · F3 = GitHub Releases canonical for client artifacts, `/downloads` = household mirror
[needs reconciling w/ pivot B2-4] · F4 = publish sanitized audit reports). Companions it does
NOT re-decide: the multi-tenant pivot (`2026-07-15-multi-tenant-endpoints.md`, owner-locked) and
the secret scan (`docs/assess/2026-07-16-public-release-secret-scan.md`, SAFE-AFTER-TREE-FIXES —
its §4 MUSTs + the pivot's tailnet-scrub gates block the flip itself).

Lanes for the orchestrator (each with stated gates in the design doc):
- **W1 whitepaper** — assemble from specs 00–07 post-genericization; embeds the §5 table, the
  R3/R4/T6 caveats, and the PCI/SOC-2 non-applicability statements.
- **W2 wire-egress harness (flagship)** — proxy-instrumented all-flows run asserting every
  outbound field against the spec 02 §5 whitelist, fail-closed on unknowns; in `tools/` + CI;
  self-hosters can run it against their own endpoint. Non-vacuity gate: RED on a planted leak.
- **W3 repo security tooling** (at flip) — CodeQL, Dependabot, secret scanning + push
  protection, SECURITY.md + security.txt + VDP/GHSA, OpenSSF Scorecard, per-release SBOM.
- **W4 artifact provenance** — Actions release builds w/ SLSA attestations + signed sha256SUMS
  over the existing GPG/Authenticode chain; reproducibility = long-tail, MSI stays manual.
- **W5 fuzzing/differential** — Jazzer on import/vault/wire/backup parsers; Kotlin↔TS↔@noble
  differential fuzz off the shared vector corpus; ClusterFuzzLite.
- **W6 external audit path** (owner-gated, post-flip) — OSTIF application once public; scoped
  Cure53-class engagement (~$15–50k, specs 01/02/04 + core + client crypto twins + dynamic ZK
  verification) when real external users exist; report published verbatim.
- **W7 posture-doc publication** — sanitized pentest/compliance reports after identifier scrub
  + finding closure.

Sequencing: W1 (after the pivot §10 DOCS sweep) + W2/W5 can build pre-flip; W3/W4 + F1/F2
execute at the flip; W6/W7 post-flip.

## 0.17.0 campaign — 2026-07-14 (a wide multi-wave sweep; SHIPPED to the tree, DEPLOY per §ship)

One orchestrated campaign closed most of the open 2026-07 queue in module-disjoint parallel waves
(each cut: breaker where risky → build → find→refute review → per-module gate → commit). **Not yet
deployed to CT122 / not yet a native release** at time of writing — see the deploy/ship steps.

- **recovery-cut-2 + the cross-device recovery race** (design `2026-07-13-recovery-confirm-binding.md`,
  schema **v8**): a confirm is now bound to a server-minted opaque `pieceId` and every setup clears
  `recoveryConfirmed`, so two devices racing the capture gate can never leave the flag attesting an
  uncaptured piece (silent-total-loss class, closed). Native **self-recovery screens** (android +
  desktop forgot-password) shipped; natives route recovery through the shared core `AndvariApi` (no
  more raw Ktor); native capture gate + waived toggle. `escrowPolicy` persisted onto the user +
  surfaced on `AdminUserSummary` so a required-member-missing-escrow is a flagged anomaly.
- **UI-audit action-plan #23–#26** (report `2026-07-12-frontend-ui-audit.md`): household-voice error
  copy (shared core `HouseholdCopy`, natives mapped off it) · motion/progress layer + `prefers-reduced-motion`
  · Auto/Light/Dark theme override (Linux desktop no longer stuck light) · tofu-proof SVG runes on ext
  + Compose · desktop startup update-check unfreeze · the TOTP-display + copy-flash + forgot-password
  web fixes. (**#27 platform-fit stays design-only** — `docs/design/2026-07-13-platform-fit.md`.)
- **MV3 live-sync** (design `2026-07-13-ext-live-sync.md`): the extension holds an unlock-scoped
  WebSocket so a peer edit lands in ~1–2 s, with the 5-min poll retained as backstop.
- **Hardening 3b**: global request-body cap (closes the 8 MiB unauth-buffer pentest finding; attachment
  + WS + item-restore exemptions) · recovery-cli refuses a server-URL arg + dated sheet · cross-impl
  importer determinism (metaV keep-newer + BOM/digit parity, twin-tested).
- **H2 client manifest-verify** (design `2026-07-13-signed-updates.md` §M): desktop `Platform.kt` +
  extension `background.ts` now fetch raw bytes + `.sig`, verify Ed25519 against the pinned key BEFORE
  parse, seq-ratchet + staleness, **fail-closed-quiet** — this closes open H2 item 2 below.
- **KDF auto-upgrade parity** (spec01-f61): web + desktop now silent-re-key toward the org's KDF cost
  after a full sign-in (android already did), fired sign-in-only to never clear a must-change temp pw.
- **Card creation flipped live** (Option A; 0.2.x MSI retired).

**Deferred / follow-ups (documented, not dropped):** native admin-fingerprint-confirm (needs a native
admin surface) · web forced-theme cold-load FOUC (cosmetic; a same-origin boot script) · ~~surface the
extension's fail-closed-quiet update state in the popup (§M-D4b)~~ **DONE 2026-07-15 (`0b9f608`) —
`updateStatus` carries `quietReason`, rendered as one muted popup line** · the determinism metaV-regression
warning is console-only (a user-facing banner needs a UI pass) · a cross-device `recoverySelfSetup`
race noted earlier is superseded by the piece-binding above. **web-offline durable cache** = SHIPPED
(S1–S6 built+verified, DEPLOYED to CT122 2026-07-15; `docs/design/2026-07-13-web-offline-cache.md`) —
encrypted IndexedDB twin of the native cache, offline unlock + reads, durable persist-gated write
queue; unit suite + live e2e (`scripts/e2e.sh` PHASE C: A2 ciphertext-only, offline unlock, torn-cache
resync, queued flush) green; web-only, no wire/schema/version change; ~~ON by default for private/
tailnet origins, opt-in-only on the public break-glass origin~~ — **that origin gate was replaced
the same week by the 2026-07-15 pivot: the cache is now opt-in on EVERY origin, default OFF, with a
one-time migration adopting standing pre-pivot caches (spec 02 §8.1, spec 05 T3).**

## Security pentest 2026-07-13 — remediation status + open H2 items

Whole-fleet adversarial pentest (`docs/pentest/2026-07-13-comprehensive-pentest.md`): **0 crit / 2
high / 8 med**. All fixable compliance gaps SHIPPED + DEPLOYED (each breaker'd → find→refute reviewed →
verified): **H1/L1** client-side KDF floor, **M2** refresh-revocation CAS, **M3** CF-Connecting-IP
trust scoping, **M6** backup-cli PAN/CVV redaction, **L6** identityPub tampering parity, **M8**
revoked-session WS teardown. **H2** (signed updates) load-bearing OS-signing DONE — MSI Authenticode +
deb GPG (ceremony 2026-07-14, `docs/runbooks/release-signing-keys.md`).

**Both H2 items are now CLOSED:**
1. ~~**Extension store-signing — DO FIRST.**~~ **DONE.** The extension publishes to the
   **Chrome Web Store (unlisted)** +
   **Firefox AMO (self-distribution signing)**, so store-signed auto-updates replaced the
   integrity-free self-hosted zips. `scripts/publish-extension.sh` pushes BOTH stores in one
   command (Chrome Publish API + `web-ext sign`) — landed `ecfc10a` 2026-07-17, with `f37f313`
   adding the Chrome push queue for releases that outpace store review. The live CWS item id and
   AMO addon id are recorded in the runbook. Runbook + listing copy + privacy policy:
   `docs/runbooks/extension-store-publishing.md`. **Standing per-release step, easy to skip:**
   any release that changes `/downloads/manifest.json` must re-sign it with a bumped `seq` —
   see the runbook's "Then RE-SIGN the downloads manifest".
2. ~~**Client manifest-verify wiring — secondary / defense-in-depth.**~~ **DONE 2026-07-14 (0.17.0
   campaign).** Desktop `Platform.kt` + extension `background.ts` now fetch the manifest as raw bytes +
   its detached `.sig`, verify Ed25519 against the pinned key (single-sourced to `core UpdateVerify.PINNED`)
   BEFORE parse, enforce `seq`-ratchet + a `signedAt` staleness window, and **fail closed quiet** (never
   a fabricated nag). Design `docs/design/2026-07-13-signed-updates.md` §M. **Remaining ops (owner):** a
   per-release `update-signer sign` on the workstation to produce `/downloads/manifest.json.sig` +
   `seq`/`signedAt` fields — until then the clients correctly fail-closed-quiet (no nag). Small follow-on:
   surface that quiet/unverified state in the extension popup (§M-D4b).

## Frontend/UI design audit 2026-07-12/13 — remediation campaign (~22 of 27 SHIPPED)

First dedicated design/UX audit of all five surfaces (web · extension · android · desktop · server-email).
Method + full findings + the merged prioritized backlog ("action plan v2", the SSOT for the item numbers
below): **`docs/design/2026-07-12-frontend-ui-audit.{md,html}`** (run 1 = 131 verified findings; a *blind
replication* found +69 substantive; ≈200 unique combined). Each cut = breaker (where risky) → build →
find→refute review → per-module gate → commit; **web+server are DEPLOYED @ `3b76797`, natives are code-only
pending a release**.

**Shipped (git `6439dc1`..`3b76797`):**
- **Foundation** — one design language was re-declared in 5 hand-synced token files; now light-theme AA +
  focus tokens (v2 #1), the full Material3 color schemes on both Compose clients (#11), and a **token-lockstep
  test** parsing all 5 sources so drift can't ship again (#12).
- **Trust & data-loss** — one-tap-discard confirms on editor cancel / sign-out / version-restore (#3); the
  desktop "un-skippable" recovery ceremony was silently skippable by the app's own idle lock (**silent total
  loss**) — now a native §F.9 vault-entry gate keyed off the durable server `recoveryConfirmed` flag (#15); the
  web editor dirty-guard + auto-lock pre-warning (#16); recovery capture-gate paste-block (#7).
- **Secret hygiene & platform fit** — `KeyboardType.Password` on every secret field + web autocomplete (#4);
  Android SDK-35 insets + IME-reachable Unlock (#5); desktop window max-width/min-size/decouple sync from the
  user-op busy flag + HTTP timeouts (#9/#17); lazy vault lists (#19).
- **Wayfinding & first-contact** — forgot-password signposts on every locked surface (#6); surfaced autofill +
  vault-context (#20); the **invite email** is now branded, **names the inviter**, is posture-accurate about
  recovery, and states its fuse — with `emailStatus` for debuggability (#2/#21); web/server hygiene:
  favicon/theme-color, noscript/boot, robots, security headers (#8/#22).
- **Feedback & a11y** — truthful clipboard/copy disclosure (#10); the extension autofill dropdown got
  truthful fill-outcomes + full keyboard/listbox semantics (#14/#18); enroll accepts a pasted link (#13).

**Remaining — one item. #23–#26 all shipped in the 0.17.0 campaign** (see that section above, which
this list predated and contradicted until 2026-07-27):
- ~~**#23** household voice + error-string sweep~~ **DONE 0.17.0** — shared core `HouseholdCopy`,
  natives mapped off it.
- ~~**#24 remainder** motion/progress layer + `prefers-reduced-motion` + the desktop update-check
  UI freeze~~ **DONE 0.17.0.**
- ~~**#25** tofu-proof SVG runes on the extension + Compose~~ **DONE 0.17.0.**
- ~~**#26** user theme override (Auto/Light/Dark)~~ **DONE 0.17.0** — Linux desktop is no longer
  stuck light.
- **#27** platform-fit roadmap (L, needs design): extension quick-unlock tier, desktop menu bar + Ctrl+L,
  CMP screen-reader verification. **Mostly overtaken — two of three landed:** the extension
  quick-unlock tier shipped separately (`6d18faa` PIN-wrapped Tier B per spec 01 §8.4, then the
  biometric WebAuthn-PRF lane in **extension** 0.17.0, `2cb7847`), and the desktop menu bar +
  Ctrl+L panic lock shipped (`Main.kt:134-147`, citing the same platform-fit design §2). What is
  genuinely left is the **Compose screen-reader verification** — a verification pass, not a build.
  Design: `docs/design/2026-07-13-platform-fit.md`.

**Cross-cut follow-ups — closed:**
- ~~**Cross-device `recoverySelfSetup` race**~~ **DONE (0.17.0 campaign, `Service.kt:530-537`).**
  Superseded by the recovery-confirm piece-binding: self-setup now commits/rotates the piece and
  clears `recoveryConfirmed` to 0 in the SAME tx (marked "§F.9 round-3 fix" in the code), so a 2nd
  device's setup can no longer leave the flag attesting the 1st device's stranded phrase.
- ~~**TOTP detail "invalid" forever** for a bare-base32 / imported secret~~ **DONE.** There is now
  ONE shared normalize — core `Totp.normalize` (spec 06 §9.2), byte-exact with web `normalizeTotp`
  and "delegated to by every editor and import adapter (private copies are deleted)"; the web detail
  view normalizes before parsing (`Vault.tsx:1456`).
- **Native release** — this was a 0.16.0-era note and no longer describes the tree. Current fielded
  state is tracked in `CHANGELOG.md`, not here.

## v5 refinement cycle — batches B1–B8 SHIPPED (2026-07-07)

A 14-lens recon (168 raw → 84 deduped findings) drove eight reviewed batches, all shipped
same-day (each: gates → high-effort adversarial review → fix → deploy): web vault-chrome +
honest connectivity dot (owner gripe 4); the nightly-backup hotfix (silently dead since
night 2, verified fixed on CT122); **Android autofill resurrected** (four kill switches +
the Autofill Status diagnostic screen; owner protocol `docs/autofill-fold-debugging.md`);
web error-truthfulness; release/update-version truth (MSI rebuild now safe); the sole-admin
lockout guard + ZK-table/spec truth + vector-pinned derivations; **session & sync
integrity** (single-flight refresh — the device-revoking `refresh_reuse` race — lock
semantics, cross-tab lock, WS-down polling, tamper/rollback guards on web); **native
data-safety** (fold-proof editing, argon2 off the UI thread, FLAG_SECURE, clipboard
hygiene, locked-screen sign-out revocation, hand-typeable TOTP, reader-role gating, the
"N items need an app update" banner). Full narrative: CHANGELOG ~~"Unreleased"~~
"0.5.0-era refinement batches" section (the heading it now lives under).

**Cycle wrap (2026-07-08):** the **Skipti** shared-vault lifecycle **SHIPPED in 0.5.0**
(design `docs/design/2026-07-07-shared-vault-lifecycle-skipti.md`; schema v4 live on CT122
with a pre-migration snapshot). The finding tail is **triaged into `docs/v6-backlog.md`**
(9 already-fixed / 19 quick-wins / 8 fold-ins / 8 standalone / 1 won't-fix — the honest v6
work queue). Round-2 recon (live-WS, MSI wire-compat, attachments E2E, prod parity,
autofill, lifecycle cross-slice + persona walks, all findings adversarially verified) ran
2026-07-08 — report in `docs/recon/`. **Owner-actionable now:** update the Android app
(devstore vc 16260489) and run the Fold autofill protocol; rebuild the MSI (now safe —
fixes the 0.2.x edit-corruption); enroll server-TOTP (the v6-QW1 QR makes it a
camera-scan — do it right after the QW1 deploy).

## Where we were at 0.4.0 (2026-07-06) — historical snapshot, kept for the feature trail

v1 is feature-complete and deployed (CT 122). **0.4.0 (same day, v4 cycle)** adds: spec 07
export/backup (`.andvari` container + CSV w/ totp round-trip + `backup-cli`), enforced
auto-lock + policy clipboard-clear, the spec 02 §3 unknown-field round-trip fix
(ExtrasOverlaySerializer + itemdoc.json vector; also fixed live favorite/passwordHistory/
multi-URI edit-loss bugs), web WS auto-reconnect + native foreground/5-min polls, delete
confirmations, user_lookup audit-PII fix, escrow upload validation + offline canary
`verify`, typed 426 surface + drill docs, and the Kuma healthz push monitor. The 0.3.0
line added, on top of the shipped P0–P4 core (ZK crypto, sync, attachments, server-TOTP,
admin, break-glass):

- **Hardening batch** — the 2026-07-06 self-audit's remaining LOW/INFO items: trusted-proxy
  client IP, per-user upload caps, WebSocket single-use ticket auth (no token-in-URL),
  audit-meta PII removal, prelogin params uniformity, CSP tightening. (Deployed.)
- **Family sharing** — shared vaults with `crypto_box_seal` member grants, owner-managed
  membership, out-of-band **seed-derived** fingerprint verification, web Sharing UI +
  native identity codes. Removal is revocation-only in v1 (see R7 below). (Deployed.)
- **Durable offline cache** (spec 02 §8) — native clients persist ciphertext envelopes +
  cursor + queue + accountKeys in per-account SQLite; offline unlock; crash-durable queue.
- **CSV import** (spec 06) — Chrome/Edge + Firefox, 100% client-side, idempotent retry.
- **Android autofill** (fill-only) — matching + classification are vector-tested `:core`;
  the AutofillService app ships with 0.3.0.

Every feature preserved the zero-knowledge invariant (the server still sees exactly the
spec 02 §5 table); each was adversarially reviewed before deploy.

## The gate to real secrets (owner + ops — BLOCKS migration)

The code is ready. These operational steps are not, and must complete **in order** before
importing any real password:

1. ~~**Air-gapped escrow-genesis ceremony**~~ **DONE 2026-07-07.** keygen ran air-gapped on
   prestige; canary make+verify PASSED from the printed sheet; CT122 pinned + restarted and
   now serves fingerprint `b26efdd3eafc9dad…` (TEST key `e3c0418f…` retired, backed up).
   Seed on 2 sheets + USB, offline only. Owner-verified canary at
   `/etc/andvari/escrow-canary.b64`. The pre-swap TEST account is already gone — CT122 reads
   `users=1, escrow=1` (owner only), so `recovery-cli verify` is all-PASS.
2. ~~**Enroll the first admin**~~ **DONE** (bootstrap token consumed + stripped; owner admin
   enrolled against the real key). **Still open: enroll server-TOTP** (web → Settings) —
   break-glass public login is impossible without it, and CT122 shows it not yet enrolled.
3. ~~**Windows MSI rebuild** on the owner box (fielded MSI still 0.2.x)~~ **DONE — the 0.2.x MSI
   was retired at 0.17.0** (`0dd0d63`, 2026-07-14; the card-create Option-A unhide was explicitly
   gated on that retirement and fired). MSI builds remain a manual, owner-run step (jpackage/WiX
   on a Windows box — `scripts/build-windows.ps1`) with Authenticode signing per
   `docs/runbooks/release-signing-keys.md`; the *current* fielded desktop version is tracked in
   `CHANGELOG.md`, not here.
4. **On-device smoke tests** — attachments + TOTP on the Fold + desktop; the autofill Fold-7
   checklist (design §6.4); a CSV dry-run with a synthetic export; a shared-vault invite
   round-trip web↔Fold with the printed-sheet fingerprint check.
5. ~~**Uptime monitor** on `/healthz`~~ **DONE 2026-07-06** — the server exposes an unauthenticated
   `/healthz`; wire whatever the instance already runs at it. (The reference instance uses a
   *push*-style monitor because its prober cannot reach the server's VLAN directly; the useful
   property is that it also dead-mans — if the prober itself dies, the missed heartbeat alerts.)
6. **Drills:** a restore of the server's DB + blobDir from the instance's own backups;
   ~~**escrow-recovery drill** with the air-gapped key (recover a throwaway account
   end-to-end)~~ **DONE** (0.6.0-era, a passed drill; `scripts/recovery-drill.sh` automates the
   exercise against a scratch server); **min-version-pin exercise** (bump `minVersion`, confirm
   all three clients block writes and show the upgrade path); **backup-verify drill** (export a
   `.andvari` → `backup-cli` verify/dump/extract, then quarterly).
7. **30-day soak** with synthetic secrets across 3 devices (web + Fold + desktop).
8. **Migrate**, then keep the old manager **read-only for 60 days** before deleting it.

## P6 — next horizon (post-real-secrets)

Prioritized; each is additive and back-compatible.

- **Quick-unlock** (spec 01 §8) — Android Keystore-wrapped UVK + biometric; Windows Hello /
  DPAPI + PIN on desktop. The single integration point on Android is `AutofillUnlockActivity`
  (hook already noted). `androidx-biometric` is already catalogued. **Android side DONE
  0.9.0 (F84); Windows/desktop DPAPI still deferred.**
- ~~**Autofill save-flow ("Save to andvari?")**~~ **DONE 0.7.0** (onSaveRequest +
  SaveConfirmActivity; web via extension) — *owner-requested 2026-07-07.* v1 is
  fill-only; add `SaveInfo` on the FillResponse + `onSaveRequest` so that when the user
  types credentials (or a card, below) andvari has no record for, it offers **"Save to
  andvari?"** and creates the item. Android first (SaveInfo/SaveCallback + a confirm
  activity that unlocks if needed); web save happens through the browser extension. Pairs
  naturally with the Autofill Status diagnostics already shipped (B2) and with cards.
- **Cards / wallet items + card autofill** — *owner-requested 2026-07-07.* **DESIGN GATE SETTLED
  2026-07-09** via a 4-design tournament × 12 breakers × judge: full contract in
  `docs/design/2026-07-09-cards-wallet.md`. Verdict: `ItemDoc + card: CardData?`, `type:"card"`,
  all ciphertext; **cards seal at formatVersion 2 (per-doc floor)** backstopped by a ~10-line
  **server monotonic-formatVersion guard** — NOT type-gate-at-fv1. Decisive code-verified reason:
  the fielded **0.2.x MSI is pre-ExtrasOverlay** and has an automatic pull-side conflict-rewrite
  that would silently strip an fv1 card with no user action; fv2 makes that a refused+audited
  `fv_downgrade` write instead of data loss. Autofill: 6 new `FieldKind`s, CVV demotion +
  token-bounded keywords (no substring "pan"/"exp"), per-frame-cluster card datasets, explicit
  trust gate. Extension: popup Cards + copy only this batch (in-page checkout fill deferred behind
  a frame-egress contract). **One owner decision** (rollout timing A/B) is in the design doc's last
  section; default A (card-create dark until the 0.2.x MSI is retired). Target release 0.7.0.
  **STATUS 2026-07-09: ALL PHASES COMPLETE — 0.7.0 CUT.** Phases 1-2 (`4ab5049`/`ed7b531`,
  server+web DEPLOYED CT122), 3+5 native UI (`106096f`), 4 Android autofill (`3255c1f`),
  6 extension (`f68abcb`), release cut (APK devstore, .deb + extension zips /downloads).
  Card-create DARK on every client per Option A — flip checklist in the design doc, fires
  when the 0.2.x MSI is retired. Owner steps: Windows MSI, Fold autofill re-run, extension
  load-unpacked. Deferred at the time: ~~in-page extension card fill (frame-egress contract)~~
  **DONE 2026-07-15 (`0b9f608`, the S3 slice + its A1–A10 egress amendments)**;
  ~~combined-expiry LIST dropdowns~~ **DONE 2026-07-23 (card-autofill Tier 1, `4ded308`)** —
  `<select>` expiry month/year and card type now fill, per CHANGELOG 0.20.0; Skipti honesty line
  placement on natives (still open, cosmetic).
  **Owner dev-note 2026-07-10 (re-request): "support storing autofill creditcard and payment
  details."** Storage/UI/Android-autofill shipped above, and the rest has since landed too:
  (1) ~~the Option-A unhide flip~~ **DONE 2026-07-14 (`0dd0d63`)** — card-create is live on every
  client; (2) ~~extension in-page card fill behind a breaker-passed frame-origin egress design~~
  **DONE 2026-07-15 (`0b9f608`)**, extended 2026-07-23/26 by the card-autofill campaign
  (`4ded308`/`2abb0a3`/`c2ab855`/`3087988`) and the in-page card chip (`59d523f`); (3) scope
  decision on non-card payment types (IBAN / bank account) as a new template — **still open, and
  it is a product decision, not a build.**
- **Browser extension** — *owner-requested 2026-07-07 (reaffirmed).* Reuses the `:core`/web
  `UriMatch` + `FieldClassifier` (already built + vector-tested for exactly this) and the
  same-origin API; carries the web save-flow. Chromium + Firefox. Go/no-go spike:
  libsodium-WASM under an MV3 service-worker CSP + host_permissions vs. CORS. *(SHIPPED
  0.6.1/0.7.0 — the item below is the open follow-on.)*
- **Extension self-update / update-available signal** — *owner dev note 2026-07-10.* The
  self-hosted, load-unpacked extension has no store-update path, so a newer version on
  CT122 `/downloads` is invisible to an installed copy today. Two honest tiers: (1) **cheap,
  do first** — the SW periodically fetches `/downloads/manifest.json` (already carries the
  `browserExtension` version), compares to its own `MAX_ITEM_FORMAT_VERSION`-adjacent version
  const, and surfaces an "update available → download & reload" badge in the popup + Devices
  hub (no silent reinstall — Chrome forbids it for unpacked). (2) **real auto-update** — a
  signed Firefox `.xpi` with an `update_url` + `updates.json` on CT122 auto-updates natively;
  Chrome needs the Web Store or an enterprise `update_url` + CRX (owner call whether store
  distribution is wanted). Start with (1); it's ~a version-check + popup surface reusing the
  manifest the Devices hub already reads. **Tier 1 DONE (extension 0.8.0, `201428b`);
  tier 2 stays parked.**
- **Owner-signed grants** (Ed25519 signing identity) — closes F16 fully: grants and lifecycle
  ops carry a sender signature under a per-account signing key, so a malicious server can no
  longer inject vaults/credentials or forge a transfer even to a client that holds no VK. The
  0.5.0 lifecycle proofs (spec 03 §11) remove the *server* from the forgery set; this removes
  keyholders too. A new signing identity touches enrollment/escrow/every grant path — hence
  deferred here, not into v5.
- **VK lazy rotation on member removal** (closes accepted risk R7) — the next online writer
  re-keys the vault and re-seals grants; removed members lose access to future ciphertext,
  not just server delivery. Needs a rotation protocol fenced against concurrent writers.
  **Trigger extended (v5): also fire after an ownership transfer and after a restore whose
  vault had members removed before the delete.**
- ~~**ItemDoc unknown-field round-trip**~~ **DONE in 0.4.0** (ExtrasOverlaySerializer + the
  `itemdoc.json` vector) — a future additive field now survives a mixed-fleet edit, so new
  optional ItemDoc fields are safe to add.
- ~~**eTLD+1 / PSL matching** for autofill (v1's label-boundary rule is strictly safer but
  misses sibling-subdomain matches)~~ **DONE 0.10.0 (`5587d8c`)**; **Digital Asset Links**
  for the native-app-with-web-creds case (v1 uses `androidapp://` exact + a browser
  allowlist) — still open.
- **iOS client** (KMP `:core` already targets it in principle; not wired) — assessed
  2026-07-10 (`docs/assess/2026-07-ios.md`: defer native; PWA-polish default; trigger = a
  daily iPhone user hurting from no system autofill).
- **Passkeys / WebAuthn** — evaluate as a credential type; large — assessed 2026-07-10
  (`docs/assess/2026-07-passkeys.md`: defer-with-trigger; store-as-fv3 + Android
  CredentialProvider is the pre-agreed shape; trigger = a household site pushing
  passkey-first).

## Onboarding & reach (owner-requested 2026-07-07 — near-term product polish, mostly UI)

- ~~**TOTP enrollment QR code**~~ **SHIPPED 2026-07-08 (batch v6-QW1)** — Settings enrollment
  renders the otpauth URI as a scannable QR (vendored zero-dep `qrcode-generator@1.4.4` under
  `web/src/vendor/`, hashes pinned, decode-proven with a scratch jsqr round-trip; copy fields
  kept as fallback). Native parity still later (enrollment happens on web today).

- ~~**"Get andvari on your other devices" hub**~~ **SHIPPED 2026-07-08 (batch v6-QW1)** —
  Settings section: this browser, devstore Android (with install QR, tailnet-only labelled),
  Windows MSI via `/downloads/manifest.json` (honest "not published yet" until the owner
  publishes; no extension row until one exists). Hidden on the public break-glass origin
  (shared `isPrivateOrigin` — since removed by the 2026-07-15 endpoint-agnostic pivot). The batch
  also shipped the Skipti purge-visibility gauges (`andvari_vaults_deleted_pending` /
  `_purge_overdue`); ~~the matching stall alert is an ops follow-up~~ **applied 2026-07-11
  (`408b31a`)**. Both gauges are on `/metrics` for any instance to alert on.
- **Guided per-source importers** — replace the single generic "CSV upload" with named,
  instructioned flows: "Import from Chrome / Edge / Brave / Opera" (all export the *same*
  Chromium CSV the current importer already parses — so this slice is mostly a friendlier
  picker + per-source "how to export" steps, small), then "Import from Firefox / Bitwarden /
  1Password / LastPass" (each needs a new format adapter — medium each; the importer already
  has an `ImportFormat` seam). Cross-platform (web + natives). Eases the switch away from a
  previous manager — the natural companion to the vault-lifecycle work (people arrive, people
  leave). Do the Chromium-family UI first as a quick win; add adapters incrementally.
  **DONE 2026-07-09 — 0.8.0 release.** All 8 sources guided on web+Android+desktop (desktop
  gained the whole import flow); Bitwarden/1Password/LastPass adapters on both impls,
  vector-pinned (`import-foreign.json`); F75 vault-aware dedupe (personal-vault scope,
  zero-destruction, refuse-not-degrade); F56 measured at 10k + three server fixes applied
  (pull UNION-ALL rewrite, GC out of the DB lock, tombstone partial index — addendum doc).
  Deferred, recorded in the design doc: LastPass template parsing, 1pux adapter, pull
  paging (recommend-only), web list virtualization at >500 items.
  **Owner dev-note 2026-07-10 — import destination vault picker:** imports currently
  commit to the Personal vault only; the user should choose the destination vault
  (writable vaults, F18 picker semantics) at the confirm step, web + natives, per-import
  for v1. F75 dedupe scoping must follow the chosen vault. Tracked in
  `docs/PLAN-autonomous-2026-07.md` §"Owner dev-notes queued". **DONE (S2, 0.10.1,
  `c9a0d4d`).**
  **Superseded 0.14.1 (2026-07-11):** the per-source picker described above was folded into
  ONE universal import screen (`docs/design/2026-07-11-universal-importer.md`) — the parser
  always keyed off file headers, never the pick; only the per-source "how do I export?"
  help survives (core `ImportHelp` + its web twin). The adapters/dedupe/perf work stands.

- **Owner dev-note 2026-07-12 — "email this invite" checkbox on the invite-user flow.**
  Add an opt-in checkbox to the Admin invite form (`InviteForm`, `web/src/ui/Admin.tsx:284`,
  beside the existing `isAdmin` + QR options) that, when checked, ALSO emails the invitee their
  enroll link (`composeEnrollLink` — the same link the QR encodes) instead of the admin only
  handing the token over by hand. **Not a UI-only tweak — the real cost is net-new server email
  capability:** andvari has ZERO mail infra today (grep-confirmed; invites are deliberately
  hand-delivered out-of-band), so this needs an SMTP client + config + a credential in
  `andvari.env` + an email template on CT 122, plus a client→server flag on `createInvite`
  (`server/.../AdminService.kt:32`). Size **M–L** (server capability), not S.
  **Threat-model note (must be weighed before build):** emailing the enroll link widens the
  invite-delivery surface — the token lands in an inbox + the mail provider's hands, weakening
  today's out-of-band delivery (R3-adjacent). Mitigating facts: enrollment still requires typing
  the printed-sheet recovery fingerprint (spec 04 §2(3)), so an emailed link alone cannot
  complete enrollment; keep the checkbox **default-OFF** (secure-by-default), and consider a
  short invite TTL for emailed invites (the QR-invite precedent, `QR_INVITE_TTL_MINUTES`).
  Cross-check whether emailed invites should be limited to the private origin. Pitch-until-ratified
  (exploration/N7 lane); no build without the owner signing the mail-surface tradeoff.
  **STATUS 2026-07-12: RATIFIED (owner chose "email the token, hardened") + DESIGNED + BREAKER-VETTED
  — build-ready, gated on OWNER OPS.** Full design + the binding breaker findings (2 BLOCKERs + 8
  amendments) in `docs/design/2026-07-12-email-invite.md`. Relay = the household **M365 tenant**
  (`smtp.office365.com:587`, from a no-reply `@monahanhosting.com`). The breaker's threat-model
  correction: the printed-sheet fingerprint is PUBLIC and does NOT bind a token holder (per cut 2),
  so the emailed token is a bearer credential contained only by a forced ≤60 min TTL + private-origin
  + public-register-refused. Owner chose to **land the vetted design now + build as a focused next
  pass** (the code is inert until the ops below). **OWNER OPS (the long pole):** (1) a no-reply M365
  mailbox with SMTP AUTH enabled (or a Graph app-registration); (2) a VLAN-2 outbound firewall rule
  CT122 → `smtp.office365.com:587`; (3) `ANDVARI_SMTP_*` + `ANDVARI_INVITE_BASE_URL` (a CANONICAL
  origin — no trailing slash/`:443`/uppercase, or every emailed link is DOA) in `andvari.env`.
  Next-session build: EmailSender(SMTP, TLS-required) + `createInvite(sendEmail)` reusing
  `core.EnrollLink.compose` + address-validation (B1) + boot base-URL self-test (B2) + off-thread
  send + rate-limit + spec/05 R8 + tests → find→refute → ship flag-OFF.

- **Owner dev-note 2026-07-12 — collapse "Invite" + "Invite with QR" into ONE "Invite" button
  that shows the QR by default (with the token).** Today `InviteForm`
  (`web/src/ui/Admin.tsx:284,305`) has a `withQr` fork: a plain invite (72 h TTL) vs a QR invite;
  the result view shows the token, and the QR only when that path was chosen. Target: a single
  Invite action whose result always renders the enroll QR **and** the token/link together, so the
  admin can hand over whichever is convenient. Size **S** (mostly UI — merge the two buttons,
  always compose+render the QR in the result). **The one real decision — invite TTL:** QR invites
  currently get a SHORT TTL on purpose (`QR_INVITE_TTL_MINUTES`, `Admin.tsx:261`) because a
  photographed QR can't be revoked. If EVERY invite now shows a QR, every invite is photographable
  → the safe default is to give **all** invites the short TTL (or make TTL an explicit field), and
  the QR-can't-be-revoked warning copy should show on every invite. Decide the TTL policy before
  building. Pairs naturally with the "email this invite" note above (same form; if both land, the
  result offers token + QR + optional email in one flow).

- ~~**Owner dev-note (BUG) 2026-07-12 — password-only re-auth autofill creates a DUPLICATE item.**~~
  **DONE 2026-07-12 (`2e5f34a`)** ("password-only re-login no longer creates a
  duplicate", extension 0.12.0 + Android). Both surfaces the note asked to check were fixed:
  the extension resolves a save target from the site's existing items and drops the offer when the
  submitted password already matches (`background.ts:2840-2841`), and Android's
  `SaveConfirmActivity.resolveStages` skips the login stage on an unchanged re-login — its code
  calls it "the dup-registration suppress" (`SaveConfirmActivity.kt:185`). Original note kept below
  for the reasoning trail.
  Symptom (owner, live): on a site whose re-login form shows ONLY a password field, the owner
  autofills the password from an andvari suggestion and submits; andvari's save-offer then asks
  to "save this login?" as if it's new, and accepting creates a SECOND item (password-only)
  alongside the original (username+password) — two registrations for the same site. **Root-cause
  hypothesis:** the save-offer doesn't recognize the submitted password came FROM / matches an
  existing item for that origin, so a password-only submit (no username to match on) is
  classified as a new credential. **Fix direction:** before offering "save as new," dedup the
  submitted creds against existing items for the site — if the password matches an existing
  item's password (and/or the fill originated from an andvari autofill of that item), SUPPRESS
  the save-offer or offer **update** instead of create; treat username-absent password-only
  submits as an update to the matching item, never a new one. **Likely areas:** extension save
  detection (`content.ts` / `content-ui.ts showSaveBanner` + the background save path) AND Android
  autofill `SaveConfirmActivity` / save-offer logic — check both; the owner hit it via a browser
  fill. **Size S–M, P2 (data hygiene — silently clutters the vault with dupes).** Verify against
  the shipped save-flow before designing.

- ~~**Owner dev-note (enhancement) 2026-07-12 — accelerate live cross-client sync via a change
  push.**~~ **DONE 0.17.0** — MV3 live-sync shipped (design `docs/design/2026-07-13-ext-live-sync.md`):
  the extension holds an unlock-scoped WebSocket, so a peer edit lands in ~1–2 s, with the 5-min poll
  retained as a backstop. Exactly the use case the note described (edit in the web vault, see it in
  the extension without a manual refresh). Original note kept below for the reasoning trail.
  **Owner want:** when a member changes an item, push an update notice to the OTHER remote
  clients on that vault so they pick it up quickly (use case: edit in the web app because it's
  easier to navigate → want the extension to reflect it without a manual refresh). **Current
  state to verify:** the server already has a WebSocket notify path (spec 03 §WS notify) that the
  web client uses for live updates; the **extension (MV3 service worker) most likely does NOT
  hold a live WS** (SW eviction makes a persistent socket hard) and refreshes on popup-open /
  poll instead. **Fix direction:** extend the live-notify to the extension — an MV3-safe WS that
  reconnects on SW wake (or a lighter push/alarm that triggers a sync) so a peer change lands
  fast; confirm the natives (Android/desktop core `SyncEngine`) also consume the WS notify vs
  poll. **Size M** (server notify infra exists; the MV3 SW WS lifecycle is the real work — pairs
  with the extension's existing WS-down-poll handling). No data-model change; pure freshness.

## Horizons & cycle doctrine (2026-07-08 brainstorm — the spine behind the queues)

**The organizing gate is the real-secrets migration.** Features are cheap before it and
risky after it, so the order of everything above is: (1) *before migration* — the recovery
path must be real and drilled (escrow re-seal F57, the F59 admin button + 2am drill doc,
native mustChangePassword F58), the public origin hardened (QW-1: F50/F52/F55), the
password floor raised (F60); (2) *during the 30-day soak* — features that convert mistakes
into trust: **item history & undelete on the existing `item_versions` data** (the v6
exploration tournament's 4-of-5-lens convergence; the server already archives every
overwrite and delete that no client can reach), plus the daily-delight queue
(cards+save-flow, importers — which are the migration tooling itself, quick-unlock);
(3) *after* — the compounding security milestones.

**Far horizons, in rough order of when they become real:**
- **Owner-signed grants** (already under P6) is the "security story complete" milestone —
  treat it as its own cycle with a Skipti-grade design tournament.
- **Emergency access / dead-man escrow** ("Arfi" tournament pitch): the 10-year household
  story. Honest blocker its breaker found: andvari has no out-of-band channel to deliver a
  veto-window notice — design that channel (likely via household ops, not the ZK server)
  before the feature.
- **Passkeys:** store-as-item + extension bridge is the realistic first slice; full
  WebAuthn custody stays "evaluate". Jumps the queue the moment household sites push
  passkeys hard.
- **Post-quantum, narrowly:** the escrow sheets are the decades-lived secret — a PQ-hybrid
  seal (X25519+ML-KEM) for escrow blobs is the one early PQ investment worth making;
  everything else waits for libsodium.
- **Steward panel / self-judging health** (tournament pitch): backup freshness, drill
  staleness, canary age as green/amber/red in Admin — the F38 lesson generalized.
  Companion: a generated, printed "household recovery booklet" (paper is the last-resort DR).
- **Explicit non-goals** (scope discipline): multi-household federation, cloud hosting, HA.
  One household, one home server, belt-and-suspenders backups — that constraint is why the
  ZK design stays auditable.

**Cycle doctrine (constitutional):** every cycle ships one *trust* feature, one
*daily-delight* feature, and one hardening/debt batch from `docs/v6-backlog.md`; wide
solution spaces get a design tournament; every diff gets the high-effort adversarial
review before deploy (5-for-5 catching data-loss past green gates); recon re-runs after
each cycle. Small reviewed batches, additive wire, docs true as you go.

## Accepted risks (signed off; not P6 work unless revisited)

- **R7** removed shared-vault member keeps decryption capability for ciphertext they held
  until VK rotation (P6). **R3** the escrow key holder can decrypt every account (it *is* the
  recovery feature). **R1** JVM/JS can't guarantee secret zeroization. **R4** server sees
  traffic metadata + membership topology. **R5** single server per instance (offline-first +
  the operator's backups, not HA). **R6** TOTP seeds co-located with passwords. Full text:
  `spec/05-threat-model.md`.

## Operational cadence (once real secrets are in)

Written for the reference instance; a self-hoster should read it as the *shape* of the cadence
and substitute their own tooling.

- **Backups:** a daily off-box snapshot of the server's data directory, plus a nightly
  `VACUUM INTO` for a clean, consistent DB copy. Quarterly restore drill — a backup nobody has
  restored is a hypothesis.
- **Escrow:** annual presence-verification of both printed sheets + the USB; annual canary
  verify + drill (spec 04 §4); re-ceremony + full re-escrow + item re-key on any suspected
  compromise.
- **Monitoring:** an uptime check on `/healthz`, and alerts on the metrics the server already
  exports — no metrics arriving at all, an auth-failure burst, a break-glass origin left armed
  longer than expected, and the purge-stall gauges. Ship the audit log off-box: it is only
  tamper-*evident* if a copy lives somewhere the server cannot rewrite.
- **Security:** re-run the hardening self-audit before each major feature that touches the
  server or crypto.
- **Releases:** `scripts/verify.sh` + `scripts/e2e.sh` green, then, per surface:
  **server + web** → `scripts/publish-image.sh <ver>` (multi-arch GHCR image; self-hosters pull
  it); **extension** → `extension/package.mjs` then `scripts/publish-extension.sh` (Chrome Web
  Store + AMO), **followed by re-signing `/downloads/manifest.json` with a bumped `seq`**;
  **desktop** → `scripts/build-windows.ps1` on a Windows box + Authenticode, and the signed deb;
  **Android** → the signed APK. Signing keys and the per-release ceremony:
  `docs/runbooks/release-signing-keys.md`. Keep the crypto vector files byte-identical;
  regenerate only the new one per feature (`spec/test-vectors/README.md`).

## Dependency upgrade lanes (Dependabot triage 2026-07-17)

The public flip woke Dependabot; 16 PRs were triaged — minors + security applied on main
(`e64f91d`/`25c4986`/`8d00b7e`), the majors below deferred into deliberate lanes. Each has a
matching `ignore:` rule in `.github/dependabot.yml` — **lift the ignore when its lane opens.**
Full per-family analysis lives in the closed PRs' comments (#5 #7-#16 #19).

1. **Crypto (web):** `libsodium-wrappers-sumo` 0.7.15 → 0.8.4 — the sodium/WASM engine; bump +
   DELETE the deprecated `@types/libsodium-wrappers-sumo` stub, audit `src/crypto/sodium.ts`
   init/API parity, full byte-locked vector gate in isolation.
2. **Crypto (native):** `lazysodium` 5.2.0 + `jna` 5.19.1 — swaps bundled libsodium 1.0.18→1.0.20;
   also update the hardcoded coords in `core/build.gradle.kts`; JVM vector suite PLUS an on-device
   Android smoke (JVM tests never load the .aar natives). jna ≥5.17 = 16KB-page .so (Android 15/16 win).
3. **React 19 (web):** react + react-dom + both @types atomically (each alone is peer-broken);
   fix the v19 type churn under `tsc --noEmit`; re-verify renderToStaticMarkup-based a11y tests.
4. **vite 8 + vitest 4 (web):** must move together with `@vitejs/plugin-react`'s major (Dependabot's
   solo-vite PR left an internally inconsistent lockfile — never merge that shape). Rolldown +
   lightningcss change every produced byte → re-run the release string-scan after.
5. **TS 7 / tsgo (web+ext):** engine replacement; pin the same 7.x in both, and equivalence-check
   the gate (run 5.9 and 7.x side-by-side, diff diagnostics) before trusting it — exit 0 proves
   compatibility, not equal strictness.
6. **AGP 9 toolchain (atomic):** gradle-wrapper 9.6 + AGP 9.3 + shadow 9.6 + the Kotlin cluster
   (kotlin 2.4.x, coroutines/serialization 1.11, kotlinx-datetime 0.8 — port SyncEngine off
   `kotlinx.datetime.Instant`, compose-multiplatform 1.11, ktor 3.5) as ONE commit — no
   intermediate state builds. Then stage 3: compileSdk/targetSdk 36 (+ platform-36 on the build
   host) → compose-bom 2026.06 → re-derive the androidx fragment/activity/biometric pin lattice
   by hand (no alphas on the unlock path). Re-run the in-container Docker build (it downloads the
   wrapper independently).
