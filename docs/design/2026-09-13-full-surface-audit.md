# Full-surface audit — every platform at 0.26.3

**Status: REMEDIATED 2026-09-13 — 102 of the 108 fix-plan rows landed on `main` in four commits after
this report (not pushed; the owner's release-cadence call), plus one defect the fresh gate found
(H139); the gate is green on a real execution and every fix was re-read adversarially. §8 is the
closure record; the §5 "Plan" column is the intent at report time.** As the two predecessors learned,
a report becomes a liability the moment its subject moves.

- **Tree audited:** `39bf594` (tag `v0.26.3` — fleet 0.26.3, extension 0.26.0), 2026-09-12/13.
- **Gate baseline:** `scripts/verify.sh` EXIT=0 at `39bf594` before a line was changed — web vitest
  1084 passed / 9 skipped, extension 305 tests across 26 files, Android compile + unit gate green.
  **Caveat, found by the audit itself (§7):** every Kotlin task was a Gradle UP-TO-DATE read — the same
  tree had passed the gate at the 0.26.3 cut on 2026-09-03 and nothing in the inputs had changed, so the
  result is legitimate but not a fresh execution. The remediation gate below runs with `--rerun-tasks`.
- **Predecessors:** `docs/design/2026-08-13-full-surface-audit.md` (0.21.0 → 0.22.0, F-series) and
  `docs/design/2026-08-30-full-surface-audit.md` (0.26.1 → 0.26.2, G-series). Both closure ledgers, the
  standing DO-NOT-CHASE list and the "refuted — do not re-find" sets were handed to every lane as
  standing context, so this audit's budget went to the 0.26.2 remediation itself (did it land, did it
  hold), the 0.26.3 native-loader change, and the surfaces no predecessor lane had read.

## 1. Scope and method

Twenty-two read-only lanes, each a module-and-dimension pair: the sixteen of the 08-30 design (core
crypto and key hierarchy; server and the zero-knowledge invariant; per-client security for web,
extension, Android and desktop; the vault-health engines; the usage ledger end to end; autofill and
field classification; sync, sharing and lifecycle; copy-that-outran-the-code; accessibility; code
quality and performance; test-and-gate integrity; public docs; supply chain, CI and the release path),
plus **three regression lanes** that walked every G01–G65 row and the §6 closures to its production call
site, **two polish lanes** (web + extension, Android + desktop), and **one live release-integrity lane**
that fetched the served manifest, ranged every artifact, verified the signature against the pinned key
and compared the GitHub release, AMO and the devstore index against the tag.

A **completeness critic** then read every lane's coverage note against the diff since `a233ce6` and the
predecessors' defect classes, and named four gaps that became four more lanes: the two non-Kotlin crypto
implementations and the Android actuals (never read by any prior lane); **running things** — the gate,
`scripts/e2e.sh`, `tools/vector-gen` and a local server for live wire probes (every prior lane was
read-only; the 08-13 note that `e2e.sh` needs real credentials is stale — it self-provisions);
import/export and the `.andvari` backup container (spec 06/07, the F08/F34/F31 recurrence check); and the
recovery ceremony, enrolment links and the update-signer trust root.

Every critical or high finding went to **three independent verifiers with different lenses** — a fresh
read of the code, an impact-and-severity review, and a concrete trace or reproduction — with two of
three required to survive and "refuted" the default under uncertainty. Every medium went to one
fresh-read verifier. Lows were not verified (they are marked as such in the ledger and re-read before
any fix). The verification debt this leaves is recorded in §7.

**Raw output:** 26 lanes → 169 findings → 2 refuted (§7) → 167 → **138 distinct** after cross-lane
dedupe → **0 critical, 4 high, 49 medium, 85 low**. Plans: 108 fix, 25 owner, 3 needs-verification,
2 defer. Of the 08-30 remediation, **34 fixes HELD outright, 20 HELD with residue, 8 landed PARTIALLY,
0 are missing** (§6).

*Mechanics, for the record:* the run was paused and resumed across usage windows with a drain sentinel
every agent checks before it starts; every lane result and verifier verdict was persisted to disk, so no
finding was lost to a pause. Final run: 113 agents, 0 errors, 86 minutes.

## 2. Verdict

**The crypto core is still sound.** No critical finding. No plaintext or key reaches the server, no authentication bypass, no zero-knowledge violation, no nonce reuse, no non-constant-time secret comparison, no format downgrade. This time the two non-Kotlin engines and the Android actual were read as well: the envelope, AD, HKDF, sealed-box and shared-grant constructions are byte-identical across all three implementations and the 0.25.0 usage-key re-bind is correct on each. The nearest thing to a crypto defect is a parity slip in the extension's Argon2 twin — an unfloored `memBytes/1024` that lets every libsodium client enrol while the extension can never sign in (H16) — and a usage-ledger flush that overwrites the household's ledger with one session's buffer when it cannot open the server copy, against spec 02 §8.2's MUST (H05). Neither leaks a secret.

**The defining pattern this time is the half-landed remediation.** The 08-30 fixes were re-read at their call sites and none is missing — but many stopped at the first leg. G23 landed as copy without a state machine, so the natives now *say* the save is queued while the queued item never appears and a retry lands a duplicate (H18), and the sentence is false outright on an in-memory cache (H17). G12 defers the background lock under an in-flight op and nothing ever re-fires it (H08). G10 bounded two of thirteen legs (H10). G04's prune is wired on all four clients and inert on two of them because a dirty-gate runs first (H35), and the natives feed it the wrong keep-set (H36). G03 is closed on the lock paths and open on three sign-out seams (H33). The G18 tripwire recognises only the textual shape that was deleted (H40). And 48 of the ~57 fixes carry no regression test (H41).

**Two 0.22.0 fixes regressed by later additions.** F01's page-driveable-message hole is reopened by the 0.23.0 `passwordReuse` message, which any granted page can fire to hold the extension unlocked indefinitely (H01) and, while unlocked, use as a vault-wide password-membership oracle (H02) — the two highs. F35's owner-only store directory is reopened by 0.26.3's diagnostics `mkdirs()` on every fresh POSIX install (H11).

**The 0.26.3 native-loader change is right where it counts and wrong around the edges.** The loader itself checks out under javap: resource paths match lazysodium's jar layout and `jdk.zipfs` is in the jlink image. Its diagnostics wrapper is where the defects live: a self-check that detects the load failure and then waves the user through to 'Sign-in failed. Please try again.' (H15); a log that promises no vault material and writes exception messages that include an attachment's name (H58); a per-launch DLL leak with the extraction failure swallowed silently (H81); no test on any of its three seams (H89); and no door to the log it writes (H126). Machinery built, never connected — again.

**The safety net is thinner than its green.** The gate baseline for this tree was a Gradle UP-TO-DATE read — every Kotlin test result predates the commit. There is no CI test job at all, so a Dependabot PR that swaps a crypto dependency is mergeable with zero tests run (H39); the tree's own Scorecard standard is red (H44); e2e phases pass vacuously (H96). Against that: for the first time in three audits e2e.sh was run and held, SIGKILL idempotency included, and the live wire probes confirmed four read-lane claims (H03, H07, H76, H111). The sync wedge (H03) — one dangling attachment ref and the device never syncs again until a sign-out that discards every other queued edit — is the household's data-loss risk this round, confirmed on the wire.

## 3. The four highs

**H01 — passwordReuse is page-driveable and not in PASSIVE_MSGS, so any granted page re-arms the extension's idle autolock at will — F01 reopened by a 0.23.0 message** (extension; `extension/src/background.ts:162`). content.js runs allFrames. A page (or any cross-origin iframe on it) renders two `<input type=password>` (detect.ts classifies that as a signup form with both as newPasswords), sets `.value` to a fresh ≥4-char string, and calls `input.focus(); input.blur()`. The UA dispatches a trusted focusout; the content script's gate (`isTrusted`, `shouldAskReuse`) passes because every input it checks is page-controlled; `passwordReuse` reaches the SW; `handle()` sees a live session and a non-passive type and calls `armAutoLock()`. Repeating this every few minutes holds the vault unlocked indefinitely with nothing on screen (count 0 draws no toast). The F01 rule the tree states at background.ts:151-160 — 'page-DRIVEABLE is the whole test' — was applied to capturedCredential in 0.22.0 but never to the reuse-alert message added in 0.23.0, and the PASSIVE_MSGS pins (extension-pins.test.ts:558-575, 1210-1215) assert only specific members, so this absence is green.

*Fix:* Add "passwordReuse" to PASSIVE_MSGS with the F01 rationale (the SW cannot see a gesture, so it must classify by reachability), and extend the extension-pins PASSIVE_MSGS assertion to `toContain('"passwordReuse"')`. Independently gesture-gate the ask content-side (see extension-security-2) so a page cannot even reach the SW with it.

**H02 — While unlocked, the same passwordReuse path is a vault-wide password-membership oracle readable by hit-testing the closed-shadow toast** (extension; `extension/src/content.ts:892`). For each candidate password P: set the page-authored new-password field to P, `focus()` then `blur()` (trusted focusout), then poll `document.elementFromPoint(innerWidth/2, innerHeight-30)` for ~50 ms: it returns the extension's host `<div>` (a page-reachable node the page can identify by elimination — it is the only element the page did not create, and the [S3] comment already treats this retargeting as a live channel) only when the reuse toast rendered, i.e. only when `count > 0`. The only per-field dedupe is `lastAsked !== value`, so a monotonically changing guess passes every time; there is no SW-side throttle, sender gate, or PASSIVE classification, and the toast is 5 s but is replaced on each showToast. A cross-origin ad iframe has its own content script instance and its own hostEl, so it can run this entirely inside itself. Throughput is one SW round-trip per guess (tens to hundreds per second).

*Fix:* Gate the ask on a REAL typing gesture the page cannot forge, the login-gesture idiom: record a per-field 'typed' mark only from trusted `input`/`keydown` events on that field (the existing capture-phase `input` listener at content.ts:1189-1197 already sees them), require it in shouldAskReuse (`typedByUser: boolean`), and clear it on fill. A page can set `.value` and drive trusted focus, but it cannot dispatch a trusted keystroke. Add a SW-side belt: refuse `passwordReuse` from sub-frames (`sender.frameId !== 0` → `{locked:false,count:0}`) and rate-limit per tab (one answer per ~1 s, like CHIP_OFFER_MIN_GAP_MS). Pin the gesture gate in extension-pins.test.ts beside the existing G19 'gates BEFORE the send' assertion. If the owner would rather not keep an oracle at all, drop the count to a boolean and answer only after a trusted keystroke — the warning copy already distinguishes 1 vs N only cosmetically.

**H03 — A queued put with a dangling attachment ref 400s the whole push batch and no engine drops the row — the device never syncs again until sign-out, which wipes every other queued edit** (core, web, server, android, desktop; `core/src/commonMain/kotlin/io/silencelen/andvari/core/client/SyncEngine.kt:1310`). The server turns a stale attachment reference into a thrown 400 that fails the entire batch, and both sync engines treat any push rejection as transient (rows stay queued, drain precedes pull). A definitively-rejected row therefore blocks the queue forever: every sync throws at the same row, the pull behind it never runs, and the error copy tells the user to 'try again' — which repeats identically. Nothing in the tree distinguishes a poison row from an offline blip.

*Fix:* Server: make a missing/mismatched attachment ref a per-mutation result (e.g. status 'denied' with a new audit meta 'attachment_gone:…', or a new 'rejected' status carrying `serverItem` when a tombstone exists) instead of throwing for the batch — spec 03 §5 amendment; keep the throw only for structurally-bad requests. Clients (both twins): in the drain, treat a definitive 4xx that is not 401/426/429 as a poison verdict for THAT batch — bisect or push rows one at a time, drop the rejected row durably with the C2 pre-edit revert and the 'write-refused' notice (web already has both; core mints a notice). History restore on all clients: strip attachment refs not present on the LIVE item before the put (the Trash restore already strips all refs — SyncEngine.kt:262, store.ts:2095-2101). Add a core + web test: queued put with a vanished attachment → row dropped, pull still runs.

**H04 — Change-password forms never capture the NEW password on either autofill client, so a generated secret is written to the site and never learned by the vault** (extension, app-android; `extension/src/content.ts:864`). Both clients pick the FIRST/non-new password field as 'the password' for capture. Real change-password forms (GitHub, Google, Microsoft, most frameworks) order current-password first and hint it, so the captured value is the OLD password. On the extension the 2a rule (same password as the stored item) suppresses the banner with no UI at all; the generator path compounds it because the generated value goes only into `newPasswords`, which the snapshot never reads. The dropdown offers 'Use a strong password' on exactly these forms (content.ts:789 `isSignup: f.isSignup` → content-ui.ts:733 renders the row when isSignup, and isSignup is true whenever a new-password hint exists).

*Fix:* Extension: give LoginForm a capture target — `capturePassword = newPasswords[0] ?? password` — and have updateSnapshot/captureNow read `newPasswords` first when any is non-empty (keep the fill target as the primary); update the F01-era pins accordingly. Android: SaveExtractor already holds each node's FieldSignal — prefer the first PASSWORD node whose normalized hints contain `newpassword`/`new-password` over the first PASSWORD node (or add a NEW_PASSWORD kind in core and map it to PASSWORD at the fill seam). Add a shared vector/DOM test: current-password + new-password form → captured password == new. Fix the SaveExtractor.kt:225 comment.

## 4. Owner decisions

Twenty-five findings are calls for the owner rather than clear defects, and are named here rather than
fixed silently. Each carries its options in the ledger detail; the one-line summary:

- **H14** — self-host topology: adopt an operator-declared ANDVARI_TRUSTED_PROXY_CIDRS (default loopback) or document network_mode: host; either way self-hosting.md option 2, bringup.sh's hint and the env template are rewritten to match.
- **H37** — offline double-edit conflict copies: server-side same-device-same-batch sequencing (spec 03 §5 amendment) or client-side per-item queue coalescing; the web fake server must model global revs regardless.
- **H39** — no CI test job: run the JS suites in Actions (verify-js.yml drafted) with Kotlin staying local for memory, or record in ROADMAP that pre-merge tests are deliberately absent.
- **H43** — ghcr.io/silencelen/andvari: publish 0.26.3 and flip the package public (only the owner's account can); until then stop calling the image 'public' in README/self-hosting/CHANGELOG.
- **H46** — CHANGELOG 0.26.3 extension icons: cut extension 0.26.1 (icons only) via publish-extension.sh, or amend the sentence to 'ships with the next extension release'.
- **H48** — offline-copy promise: qualify the copy ('in a tab you already have open') on both surfaces, or ship the deferred D1 service-worker shell with the 426-pin interplay designed.
- **H64** — usage-key derived from the server-labelled personal vault: ratify the cheap refusal (never adopt a sealedVk-delivered grant as personal) now, and decide whether spec 02 §4 moves `type` inside the authenticated vaultMeta.
- **H65** — hintless `<input type=password name=otp>`: amend spec 02/urimatch.json so a NAME_NEGATIVE token overrides htmlType=password in all three engines, or record the residual in the F11 note; add the vector either way.
- **H66** — pasted enroll-link rfp: align Android with desktop (ignore until an app-link/QR scan gives provenance) or accept on both with honest affirm copy; then correct the 2026-07-15 record.
- **H67** — damaged wrappedUvk copy: approve a distinct terminal sentence and instruction for a structurally-unopenable account row instead of 'wrong master password'.
- **H84** — SQLite synchronous=NORMAL: switch to FULL (one fsync per commit) or keep NORMAL and document the trade in spec 02 §7 / self-hosting.md's backup section.
- **H85** — duplicated F61 KDF re-key: approve the hoist into core jvmShared (the G39 class of refactor on a security routine).
- **H94** — Android crypto actual never vector-graded: provide an emulator/device leg in the release checklist for an instrumented vector run.
- **H100** — Dependabot PR #57 / alerts #13–#15: dismiss with a lane-4 citation and close, or open lane 4 deliberately (vite 8 + vitest 5 + plugin-react together).
- **H103** — binding shipped installers to the tag: where the bundle.json.commit assertion lives (PRESTIGE post-condition vs huginn watcher) and whether -AllowOffTag is acceptable; record jar/MSI non-reproducibility in the runbook now.
- **H105** — Android-less releases: pick the explicit opt-out signal for devstore (marker asset, release-body token, or fall-back to the newest release with latest.json) and record 0.26.3's state in CHANGELOG/ROADMAP.
- **H106** — 'Android isn't published yet' on the reference instance: let the reference manifest carry an android entry pointing at devstore (watcher allow-list + release-spec change) or change the row copy to something true.
- **H107** — /downloads retention on CT122: decide what old installers stay reachable; then the manifest backups leave the web root and the rule goes into prune-artifacts.sh.
- **H117** — design §4 post-`bad` offer: build the 'open the item' offer row (web, then Android) or add a shipped-state correction block as G47 did.
- **H130** — .deb metadata: state the maintainer address, copyright holder line and whether licenseFile may also add a license page to the MSI.
- **H134** — extension Appearance: whether options.html grows a Light/Dark row mirroring the web's data-theme (the token-derived plates and reduced-motion block are mechanical and can go ahead).
- **H135** — window.confirm on sign-out and offline-copy wipe: ratify converting both to the inline two-step arm.
- **H136** — web app manifest: depends on the brand-geometry choice (H138) for the 192/512 icons; sits beside the D1 decision (H48).
- **H137** — print stylesheet scope: hide secrets under @media print with a recovery-reveal exception, or a one-line 'secrets are hidden when printing' notice.
- **H138** — brand geometry: one stave geometry for the tile icons and the wordmark (regenerate favicon/.ico/.png/icon16–128), or document the tile variant as deliberate; add the mark to the web appbar or drop it from the popup headers.

## 5. Disposition ledger

One hundred thirty-eight distinct findings, ordered by real-world risk to a household. `reg Fnn/Gnn`
marks a regression of, or residue from, a previously-closed finding. Plan is the intent at report time.

| ID | Sev | Area | Modules | Finding | Plan |
|---|---|---|---|---|---|
| H01 | high | security | extension | passwordReuse is page-driveable and not in PASSIVE_MSGS, so any granted page re-arms the extension's idle autolock at will — F01 reopened by a 0.23.0 message _(reg F01)_ | fix |
| H02 | high | security | extension | While unlocked, the same passwordReuse path is a vault-wide password-membership oracle readable by hit-testing the closed-shadow toast | fix |
| H03 | high | code-quality | core, web, server, android, desktop | A queued put with a dangling attachment ref 400s the whole push batch and no engine drops the row — the device never syncs again until sign-out, which wipes every other queued edit | fix |
| H04 | high | usability | extension, app-android | Change-password forms never capture the NEW password on either autofill client, so a generated secret is written to the site and never learned by the vault | fix |
| H05 | medium | security | core, web, extension, spec | Usage-ledger flush overwrites the server ledger with one session's buffered uses whenever the server copy cannot be fetched or opened — violating spec 02 §8.2's MUST, on all three twins | fix |
| H06 | medium | security | web, core, spec | The only production caller of member removal never mints the removal proof, so every legitimate removal reaches the victim as a 'server may be misbehaving' anomaly | fix |
| H07 | medium | security | server | The 426 min-version pin is not enforced on PUT /account/password, PUT /escrow/self or PUT /usage — three routes that persist client-produced ciphertext | fix |
| H08 | medium | security | app-android | G12 landed half: lockFromBackground defers under an in-flight op but nothing re-fires the lock when the op ends, so backgrounding mid-sync leaves the vault unlocked for the whole idle window _(reg G12)_ | fix |
| H09 | medium | security | app-android | The design's autofill-overlay lock-on-background exemption never landed: an overlay's own finish() seals the session it just opened whenever MainActivity's composition is alive | fix |
| H10 | medium | security | app-desktop, core | G10 landed on two legs only: all thirteen op{} sites, including save-with-attachments, the move/copy gesture and the import push, still hold busy over unbounded HTTP and defer the idle auto-lock indefinitely _(reg G10)_ | fix |
| H11 | medium | security | app-desktop | 0.26.3's DesktopDiagnostics creates ~/.andvari-desktop with a bare mkdirs() before the store exists — every fresh POSIX install regresses F35 to 0755 and diagnostic.log is created at the umask _(reg F35)_ | fix |
| H12 | medium | security | app-android, app-desktop | Web's CR-02 300 s idle cap on the self-recovery reset step has no native twin — the UVK-equivalent recovery secret stays in memory indefinitely on Android and desktop, even backgrounded | fix |
| H13 | medium | security | extension | Multi-step lastUsername is remembered per tab with no host, so a password-only submit on another site is captured under the previous site's username and lands as a wrong-account 'Save new' | fix |
| H14 | medium | security | deploy, docs, server | The documented own-front → 127.0.0.1:8080 self-host topology never presents a loopback peer inside the container, so every client shares one rate-limit key and one audit IP and the doc's remedy cannot work | owner |
| H15 | medium | usability | app-desktop, core | The 0.26.3 startup crypto self-check detects a native-libsodium load failure and only logs it: the user is waved through to the password field and told 'Sign-in failed. Please try again.' | fix |
| H16 | medium | usability | extension, server, spec | The extension's Argon2id twin passes memBytes/1024 unfloored to @noble, so a policy memBytes that is not a KiB multiple lets every libsodium client enrol while the extension can never sign in and blames the user | fix |
| H17 | medium | usability | core, app-desktop, app-android | SAVE_OFFLINE promises 'your save is queued' on every native client bound to InMemoryVaultCache (desktop's default consent-off state, org-forbid Android), where lock, quit or background-lock discards the queue _(reg G23)_ | fix |
| H18 | medium | usability | core, android, desktop | G23 landed as copy only: the natives say 'your save is queued' but the queued item never appears in the list and the editor stays open, so the user re-creates or re-saves and the queue lands duplicates _(reg G23)_ | fix |
| H19 | medium | usability | core, app-android, app-desktop, server | A native import chunk over the 8 MiB push cap is durably enqueued before it is sent, so the 413 leaves it at the head of the queue and every later sync re-sends it until sign-out | fix |
| H20 | medium | usability | extension | The extension discards the server's displaced version on a conflicting update and tells the user the save did not happen although the server applied it | fix |
| H21 | medium | usability | app-android, core | Android writes the stored password into every password-classified field — new-password and confirm boxes included — so picking a login on a change-password page fills the old password into the new fields | fix |
| H22 | medium | usability | core, web, extension, app-android | A saved URI with international characters never matches the punycode host every browser reports — no twin converts either side and the PSL resolver treats non-ASCII as UNKNOWN | fix |
| H23 | medium | usability | app-android, app-desktop | Android and desktop CSV export preflights show no per-vault line and no shared-vault opt-out — every VK-held shared vault's passwords are written into the plaintext CSV unannounced, unlike web's ExportPanel | fix |
| H24 | medium | usability | web, app-android, app-desktop, docs, tools/recovery-cli | The admin escrow-recovery ceremony's final step (upload the recovery-cli bundle) has no surface in any shipped client while self-hosting.md says 'upload the result in the admin panel' | fix |
| H25 | medium | usability | server, web | Admin device list and count treat every signed-out device as live and revocable forever: logout never stamps devices.revokedAt and the janitor never prunes devices | fix |
| H26 | medium | usability | web, app-android | The breach column keeps asserting a verdict about a password that no longer exists: the scan cache is keyed by itemId and never invalidated when the password changes (web until reload, Android until lock) _(reg G35)_ | fix |
| H27 | medium | usability | app-android | Android's 'Account gone' verdict records and advances with no delete offer; web (G27) and design §4 offer 'Move to Deleted items' naming the item | fix |
| H28 | medium | usability | app-android | Android's verification run has no Copy username / Copy password controls, and the ViewModel helper built for them (healthClipboardSeconds) has zero production callers | fix |
| H29 | medium | usability | app-android | Android has one run entry point over the whole ranking where web has three; startVerifyRun has no queue parameter so a single login cannot be checked without skipping through everything | fix |
| H30 | medium | accessibility | web, android | The verification run advances silently on web and Android: the next login's name and position are announced to nobody, and Android's in-dialog refusal has no live region | fix |
| H31 | medium | accessibility | android | Android's G26/G58 closure rides a conditionally-composed NoticeBar that enters composition already populated — the shape the a11y design's AM-6 flags as unproven — while CHANGELOG 0.26.2 says users 'now hear' it _(reg G26)_ | fix |
| H32 | medium | accessibility | android | The G24 'Refresh' custom action sits on the LazyColumn container TalkBack skips in linear navigation, so pull-to-refresh is still gesture-only for screen-reader users _(reg G24)_ | fix |
| H33 | medium | code-quality | extension, app-android, web | G03 was closed on the natives' lock paths and desktop sign-out only: extension doLock nulls the tokens after firing the flush, and Android and web sign-out revoke the session before the flush runs _(reg G03)_ | fix |
| H34 | medium | code-quality | web | Web's putUsage rides raw(), which never throws on non-2xx, so a 400/413/5xx/401 is treated as a landed flush and the session's uses are dropped — the re-arm catch is unreachable for a server refusal | fix |
| H35 | medium | code-quality | web, extension | On web and the extension the post-sync prune runs only when the buffer is dirty, so the G04 growth bound fires only if a sync lands inside the debounce window — effectively unwired on the two clients with no native sibling _(reg G04)_ | fix |
| H36 | medium | code-quality | app-android, app-desktop, core | The natives' post-sync prune keep-set is engine.items() — the decrypted working set — so usage for live items this device cannot read is pruned on every sync; web and the extension fold those ids in _(reg G04)_ | fix |
| H37 | medium | code-quality | core, web, server, android, desktop, tests | Editing the same item twice offline produces a junk '(conflict)' copy of the intermediate draft on reconnect on every queueing client, because the second queued put's baseItemRev can never match the global rev — and the web test asserting 'no spurious copy' runs against a per-item-rev fake | owner |
| H38 | medium | code-quality | web | A live bell that rings during an in-flight pull joins it and its rev is discarded, so a peer change committed during that pull stays invisible until the next unrelated bell or manual Sync | fix |
| H39 | medium | supply-chain | .github/workflows, scripts/verify.sh, docs/ROADMAP.md | There is no CI test job at all — every Dependabot PR, including ones swapping crypto/native dependencies, is mergeable with zero tests run; the only pre-merge signal is the JS CodeQL leg | owner |
| H40 | medium | supply-chain | scripts/ci, .github/workflows | The G18 CodeQL emptiness tripwire fires only on the one textual shape that was removed; list-form matrices, a second job or the `java` alias all pass it green (measured against four scratch variants) _(reg G18)_ | fix |
| H41 | medium | tests | app-android, app-desktop, web, extension, server, core | Of the ~57 0.26.2 fixes only nine touched a suite; seven untested ones are security controls (G10, G11, G12, G13, G14, G49, G51) that can regress green today | fix |
| H42 | medium | tests | core, web, spec | vaulthealth.json grades what the engines derive but not what they write: no merge-doc comparison, no planKeep/planDismiss/planCheck/planUnsnooze cases, roleFor=null throughout — so the two engines can drift green on everything they persist | fix |
| H43 | medium | supply-chain | deploy, scripts/publish-image.sh, docs/self-hosting.md, Dockerfile | The documented self-host install path cannot complete: ghcr.io/silencelen/andvari is not anonymously pullable, so bringup.sh's default docker pull (and compose's image ref) fails for every stranger | owner |
| H44 | medium | supply-chain | web/package-lock.json, extension/package-lock.json, .github/workflows/scorecard.yml | The tree's own stated standard — a clean OpenSSF Scorecard vulnerability check — is red (6/10, four OSV ids, alert #23): two are one merge (PR #56) away, two came in with the G17 web-ext pin and have no upstream fix | fix |
| H45 | medium | supply-chain | .github/dependabot.yml, .github/workflows/codeql.yml | The github-actions Dependabot ecosystem has no groups:, so codeql-action init and analyze are bumped in separate PRs that each fail CI (PRs #53/#54 confirmed) and would redden CodeQL on main if merged alone | fix |
| H46 | medium | release | extension, docs | CHANGELOG 0.26.3 tells users the browser-extension icons were refreshed, but no extension build carrying them is published on any channel — CWS, AMO and /downloads all serve 0.26.0 | owner |
| H47 | medium | release | scripts, docs | The seq 12 manifest publish left no record in the watcher's log or the Telegram audit log — run by hand against the skill's rule, one minute before the cron tick would have done it | fix |
| H48 | medium | polish | web, docs | Offline-copy copy promises 'you can open it even when the server can't be reached' while the design's own D1 divergence says the web shell cannot load offline (no service worker) — true only in an already-open tab | owner |
| H49 | medium | polish | web | The global uppercase-letterspaced label rule is never scoped out of label.check / label.inline-check, so every sentence-length consent acknowledgment renders as multi-line ALL CAPS and its emphasis words are erased — the 2026-07-12 action item #8 never landed | fix |
| H50 | medium | polish | web | The staleness run's 'Move to Deleted items' button carries className="danger", defined nowhere, so the one destructive control in the confirm row renders as a raw unstyled browser button | fix |
| H51 | medium | polish | web, extension | Only button.primary has a disabled style; every disabled ghost button, link-button, select and input on web and in the popup looks and hovers exactly like an enabled one | fix |
| H52 | medium | polish | web | Web input placeholders fall back to the UA default at ~2.4:1 on the light theme; the popup fixed the identical twin (a11y 7b) and web never got the port | fix |
| H53 | medium | polish | web | The web item Detail renders the website as a read-only text box — no 'open site' link, no copy, only uris[0] — while the extension detail, the run card and the Duplicates checker all offer a safeSiteHref link | fix |
| H54 | low | security | app-android | On Android 10/11 a Back-button exit disposes the composition-scoped lock observer before ProcessLifecycleOwner's deferred ON_STOP fires, so the vault stays unlocked in-process with its idle ticker dead | fix |
| H55 | low | security | app-android | G11 residue: the untrusted-caller launder nulls SavedCredentials.webDomain but not SavedCard.webDomain, so a card-only capture from an untrusted app still names the claimed domain in the 'Unlock to save' subject _(reg G11)_ | fix |
| H56 | low | security | app-android | The last-resort crash reporter persists unscrubbed exception messages to a backup-domain file and renders them on the next launch without FLAG_SECURE | fix |
| H57 | low | security | android | G64 residue: the autofill-picker excursion arm has no expiry, so on a device where the picker does not stop the activity the one-shot survives and exempts the user's next genuine backgrounding from lock-on-background _(reg G64)_ | needs-verification |
| H58 | low | security | app-desktop | The 0.26.3 diagnostic log claims to hold no vault material, but op() writes every caught throwable's message chain and stack trace to a cleartext, unbounded file — one app-minted message interpolates an attachment's name and kotlinx JSON errors quote input | fix |
| H59 | low | security | extension | 'Remove data for this server' omits the known-logins digest record KLKEY, so the origin's HMAC key and (site, username) digest set survive the one path that promises to erase that origin's state | fix |
| H60 | low | security | tools/recovery-cli | recovery-cli recover writes the upload bundle — carrying tempAuthKey, the account's live login credential until the forced change — at the default umask, unlike update-signer's 0600 discipline | fix |
| H61 | low | security | server, spec | GET /admin/users/{id}/escrow — step 1 of the takeover-capable admin recovery ceremony — writes no audit row although spec 03 §7 says every admin call is audited, and POST /admin/recovery runs argon2 with no rate bucket | fix |
| H62 | low | security | server | register() persists vaultId, metaBlob, wrappedVk, wrappedUvk, identityPub, encryptedIdentitySeed, displayName and device name/platform with no shape or size gate — the same fields createSharedVault UUID-checks and requireB64-bounds | fix |
| H63 | low | security | scripts/publish-extension.sh, docs/runbooks/extension-store-publishing.md | The G17 fix moved the store credentials from the uid-private environment onto child-process command lines (world-readable /proc/*/cmdline): CWS secret + refresh token on curl -d, the AMO JWT secret on web-ext --api-secret _(reg G17)_ | fix |
| H64 | low | security | core, web, spec | The usage-ledger key is derived from whichever held vault the server labels type=personal, so a hostile server can relabel a member-granted shared vault and have the ledger sealed under a key other members hold | owner |
| H65 | low | security | core, web, extension, spec | The F11 password-into-one-time-code rule covers only hinted OTP boxes: a hintless <input type=password name=otp> classifies PASSWORD in all three engines because the legacy rule returns on htmlType before the NAME_NEGATIVE check | owner |
| H66 | low | security | app-android, app-desktop, docs | A pasted enroll link's rfp is honored on Android (required-affirm) and deliberately ignored on desktop ('a paste has no provenance') — opposite security postures on identical input, and the 2026-07-15 record says Android cannot receive an rfp at all | owner |
| H67 | low | usability | core, web | Structural refusals of the server-supplied wrappedUvk (bad base64, unknown envelope version, too short) collapse into 'wrong master password' at core and copy layers, so a corrupt or foreign-version account row reads as a forgotten password | owner |
| H68 | low | usability | app-desktop | Desktop's trust-gate http caution says 'traffic to this server can be read on the network' for every http:// origin including 127.0.0.1 — the F27 loopback/LAN split was applied to Android only | fix |
| H69 | low | usability | extension | The extension popup's one-time-code copy records no usage while web, Android and desktop all count a copied TOTP as a use (the G37 rule) — the fourth client never came in line _(reg G37)_ | fix |
| H70 | low | usability | extension | G21's reader gate reads vault roles captured at unlock; the 5-minute resync refreshes items but not roles, so a member demoted mid-session keeps being offered Update/TOTP-add and gets the pre-G21 'try again' _(reg G21)_ | fix |
| H71 | low | usability | core, android, desktop | The web store's F20 'You were added to “X”' notice has no native twin: core's notice kinds stop at deleted/removed/left/anomaly/restored/transfer, so a phone or desktop member learns of a new shared vault only by noticing a new picker entry | fix |
| H72 | low | usability | app-android | Android's merge, keep-this-one, not-duplicates, restore and unsnooze complete with no feedback, and a merge that fails after the survivor save maps to the generic save sentence — web states each outcome and names the partial-merge state | fix |
| H73 | low | usability | web | Web discards the entire breach scan when any single prefix range fails, while Android keeps the ranges that succeeded, renders the rest as '—' and neutralizes the tile — the reference client is the laxer one | fix |
| H74 | low | usability | web | Web's breach-scan failure names an internal the user cannot act on ('the HIBP relay'); the Android twin says 'the service' | fix |
| H75 | low | accessibility | android | The G62 fix distinguishes a clean 0 from an incomplete-scan 0 on the Android Breached tile by colour alone, so a screen reader hears 'Breached: 0' for both; web carries the state as text | fix |
| H76 | low | release | server, web | The SPA is served with no Cache-Control at all and a missing hashed asset falls through to a 200 index.html, so a heuristically-cached index.html after a release can strand the tab on the 'unsealing…' placeholder | fix |
| H77 | low | performance | web | The web importer reads the whole picked file with file.arrayBuffer() before the 10 MiB gate, so a mis-picked multi-GB file freezes or crashes the tab instead of producing the 'larger than 10 MiB' message; both natives stream through readBounded | fix |
| H78 | low | performance | app-android | G07 residue: DuplicatesTab AEAD-decrypts every vault name once per member row per recomposition and VerifyRunDialog re-derives the full staleness ranking on every recomposition; web memoizes both _(reg G07)_ | fix |
| H79 | low | code-quality | web | Web's flush payload is its whole in-memory map, not the buffer the twins send, so every bare web flush resurrects entries the natives pruned and forces the next native sync to prune-and-PUT again | fix |
| H80 | low | code-quality | core | MK, authKey, wrapKey and the identity seed are never wiped after enroll/unlock/recover, while the sibling backup path wipes MKx/exportKey as spec 07 requires — the gap is uniform across all three twins | fix |
| H81 | low | code-quality | app-desktop | NativeSodium.prepare() leaks one extracted libsodium.dll per launch on Windows (deleteOnExit cannot unlink a mapped DLL) and swallows every extraction failure with no diagnostic line, so the silent fallback 0.26.3 was written to avoid leaves no trace | fix |
| H82 | low | code-quality | server | clientIp()'s no-forwarded-header fallback is Ktor's remoteHost (a reverse-DNS lookup), not the socket address the spec names — loopback audit rows read 'localhost' (probed live) and every un-forwarded new peer performs a blocking PTR lookup in the rate-limit path | fix |
| H83 | low | code-quality | tools/backup-cli, core | backup-cli verify promises per-attachment failures are 'collected, never fatal' but a manifest fileKey that is not valid base64url throws outside the per-entry catch and aborts the whole verify | fix |
| H84 | low | code-quality | server | PRAGMA synchronous=NORMAL under WAL means a push the server already answered 'applied' can be lost on power/kernel failure before the next checkpoint, together with the idempotency journal that would let the client re-apply it | owner |
| H85 | low | code-quality | app-desktop, app-android, core | The F61 KDF re-key — a security-critical ~40-line routine — is hand-duplicated between Android's KdfReKey.maybeUpgrade and an inline desktop copy whose justifying comment the G39 hoist has since invalidated | owner |
| H86 | low | code-quality | web, core | Three exported helpers ship in production bundles with zero production callers: hasPatternWeakness (dead in both twins), web base32Encode (whose extension twin was already deleted) and Devices.tsx windowsRowState (a test-only shim) | fix |
| H87 | low | code-quality | web/package-lock.json, scripts/verify.sh | web/package-lock.json's root version is 0.24.0 while web/package.json is 0.26.3 — three fleet bumps unrefreshed — and the version gate that exists for this pattern checks only package.json (npm ci still works: drift only, measured) | fix |
| H88 | low | tests | core, app-desktop, app-android | The G03 mechanism — teardown flush completing before the transport closes — is not what UsageRecorderCoreTest tests (it never passes `then`), and its no-write assertion can pass vacuously _(reg G03)_ | fix |
| H89 | low | tests | app-desktop, core | 0.26.3 shipped with no test on any of its three seams (NativeSodium.prepare, DesktopDiagnostics, the core sodium.path property), and its 'best-effort, falls back' contract is only true for extraction failures — a load failure with the property set has no fallback | fix |
| H90 | low | tests | extension, web | The G19 pins hold for what they name but pin storage lines, not call sites: dropping refreshKnownLogins() from persistSession or isKnownLoginWhileLocked() from capturedCredential stays green, and the TOTP challenge's memory-only residency has no pin _(reg G19)_ | fix |
| H91 | low | tests | web, app-android | Two source-text pins claim a sweep they do not perform: the KLKEY residency pin only sees the inline spelling, and the Android excursion-arm pin counts begin() in raw source including comments without tying any arm to its launch | fix |
| H92 | low | tests | core, web, extension, spec | UsageLedger.parse already drifts from its two TS twins (string-typed numbers accepted; one nested field empties the whole ledger instead of one entry) and no shared vector pins ledger parse/merge/serialize | fix |
| H93 | low | tests | extension, spec | The extension's shared-grant open (the third SharedGrant twin, inlined in buildVaultKeys) omits the 32-byte VK guard both siblings enforce and is the only twin not graded by sharedgrant.json | fix |
| H94 | low | tests | core, app-android | The Android crypto actual (lazysodium-android 5.1.0 with its own bundled libsodium) is never run against spec/test-vectors: there is no Android test source set, so the artifact the phone ships is graded only by proxy through the JVM build over a different native binary | owner |
| H95 | low | tests | tools/vector-gen, spec/test-vectors, scripts/verify.sh | The committed export.json corpus predates schema v9 (no dupeAck/check in payloadUtf8 while the generator emits them), so the README's 'differs on every run by construction' hides a third generator-vs-corpus divergence | fix |
| H96 | low | tests | scripts/e2e.sh, web/src/e2e | Each e2e.sh phase reports '3 tests passed' while two return early as vacuous passes, and e2e.sh prints 'E2E PASSED' without asserting any phase executed — the collected-nothing trap verify.sh guards against | fix |
| H97 | low | tests | server | Four server tests order concurrent behaviour by wall-clock sleeps with tight margins and are expected to fail red under host load | needs-verification |
| H98 | low | supply-chain | Dockerfile, web, extension, CONTRIBUTING.md | npm lifecycle scripts are never disabled — the image build, the contributor path and the release-tool install all run every dependency's install hooks, and no .npmrc sets ignore-scripts | fix |
| H99 | low | supply-chain | scripts/publish-image.sh, deploy | The self-host container has no verifiable identity: buildx provenance disabled, image unsigned, no digest published, compose on floating :latest, caddy:2 undigested while the Dockerfile digest-pins its own bases | fix |
| H100 | low | supply-chain | .github/dependabot.yml, web/package.json, docs/ROADMAP.md | Dependabot PR #57 is the exact shape ROADMAP lane 4 says never to merge (a solo vitest major without vite/plugin-react), and the three vitest alerts behind it are devDependency-only noise | owner |
| H101 | low | supply-chain | core | core's Android target hardcodes the lazysodium-android and JNA versions beside a catalog that already declares both, with a comment promising they match and nothing checking that they do | fix |
| H102 | low | release | scripts, docs/runbooks/release-signing-keys.md | No script produces the GitHub release, so its asset layout is retyped per release and drifts (v0.26.3 native-name deb with served-name signature, v0.26.2 the opposite, runbook verify command matching neither); SHA256SUMS is unsigned _(reg G16)_ | fix |
| H103 | low | release | scripts/prestige-release.ps1, scripts/signandvari.ps1, docs/runbooks/release-signing-keys.md | Nothing binds a shipped MSI/deb to the release tag: the ceremony accepts any -Ref, bundle.json's commit is never checked by the publisher, and the desktop jar hash is non-reproducible — recorded only in session memory | owner |
| H104 | low | release | scripts, docs | 0.26.2 release-record gaps: SHA256SUMS-0.26.2.txt omits the AMO-signed .xpi the live manifest points at, and two byte-different MSIs were published under one filename (seq 10 → 11 re-cut) with no in-tree record _(reg G16)_ | fix |
| H105 | low | release | docs, scripts | The deliberate Android-less 0.26.3 release is unrecorded in-tree and has turned devstore's 'no latest.json — SKIPPING' safety alarm into a standing every-15-minute warning, so a genuinely forgotten latest.json next release is indistinguishable | owner |
| H106 | low | release | web, scripts | On the reference instance the web 'Get andvari on your other devices' card says the Android app 'isn't published yet' while the devstore channel is live — and the watcher's pinned ALLOWED_CHANGE_KEYS means the reference manifest can never carry an android entry | owner |
| H107 | low | release | scripts, docs | CT122's public /downloads has no retention policy: operator manifest backups, two still-valid signed manifest pairs from seq 3–4, every deb since 0.6.0 including unsigned ones and the known-broken 0.26.2 MSI — 4.6 GB on a 16 GB rootfs | owner |
| H108 | low | release | deploy | bringup.sh --caddy never arms ANDVARI_FORCE_HSTS and prints the HSTS reminder only on the non-caddy branch, although the env template says HSTS is 'always right behind the caddy overlay' | fix |
| H109 | low | professionalism | spec, docs, scripts | The CHANGELOG says the doc-leak scan 'covers the whole public tree'; it scans docs/ plus five root files for three literals, and the normative spec — unscanned — names the operator's private hosts in MUST-level text _(reg G55)_ | fix |
| H110 | low | docs | docs/runbooks/release-signing-keys.md, scripts/signandvari.ps1 | The signing-keys runbook's channel-state paragraph rotted again within one release of its G48 rewrite (seq 9 / 0.26.1 vs the wire's seq 12 / 0.26.3), and the automated check it proposes is still unbuilt _(reg G48)_ | fix |
| H111 | low | docs | spec, server | spec 03 describes three server behaviours the code does not have: a wrong TOTP code answering 401 totp_required (probed: it answers invalid_credentials), a {"type":"policy"} WebSocket frame, and a two-tier body cap | fix |
| H112 | low | docs | docs, tools/recovery-cli, server, core | Recovery-path copy that outran the code: self-hosting.md claims a per-email backoff on /recovery/self/* the server deliberately lacks, and four sources cite docs/drills/ files not in the public tree without the 'recorded elsewhere' note | fix |
| H113 | low | docs | spec | Spec 07's intro still says break-glass-origin web sessions SHOULD hide both export entry points — a rule the 2026-07-15 multi-tenant design deleted and plan.ts records as removed | fix |
| H114 | low | docs | spec, web, extension, core | The vector-provenance manifest rewritten for G56 names consumers that do not exist (an extension member-recovery suite, web crypto.vectors/totp.vectors tests) while omitting a real one, and three comments cite a skipped PoC as the parity proof _(reg G56)_ | fix |
| H115 | low | docs | scripts, spec | The vector-corpus count was corrected in spec/test-vectors/README.md (17 of 24) but verify.sh's sibling statement still says '16 of the 22' _(reg G56)_ | fix |
| H116 | low | docs | core | Wire.kt's UsageResponse doc says clients use updatedAt to decide staleness; no client reads it and the accepted two-device race has no precondition to hang off | fix |
| H117 | low | docs | docs | Design §4 promises 'Wrong password → offers: open the item / generate a new password' and lists run-card copy controls Android does not have; no client offers anything after a bad verdict | owner |
| H118 | low | docs | docs, android | An undated, un-bannered owner-only debugging protocol sits in the current-facing docs/ root, opens with a claim false at HEAD ('the autofill service is fill-only') and tells the reader to run a script that does not exist _(reg G05)_ | fix |
| H119 | low | docs | docs | The Wave-4 promotion runbook still presents itself as an un-run owner gate two months after 0.19.0 executed it, and the signing-keys runbook cites a docs/drills/ record not in the tree with no 'recorded elsewhere' note _(reg G42)_ | fix |
| H120 | low | docs | extension, docs | extension/README pins the extension at '0.25.0 as of this writing' (manifest is 0.26.0) and, with the store runbook, still describes the icons 0.26.3 replaced _(reg G43)_ | fix |
| H121 | low | docs | docs | v6-backlog still records passwordHistory as written by no client and F54's web policy-frame handler as existing — both false at HEAD and contradicted by other in-tree records _(reg G45)_ | fix |
| H122 | low | polish | extension, core, web | The weakened-KDF security sentence, declared a byte-twin across the three canons, ends 'contact your admin' in the extension and 'contact your administrator' in core and web | fix |
| H123 | low | polish | app-android, web | The G31 all-snoozed staleness empty state was written twice with different sentences although the Android fix cites 'web's twin' _(reg G31)_ | fix |
| H124 | low | polish | extension, app-android | Auto-saved and site-linked logins always store https://<host> even when the capture came from an http page (the F27-supported loopback/intranet posture), so 'open site' points at an origin that does not exist | fix |
| H125 | low | polish | app-android | The Android app displays its version nowhere, so a phone user cannot answer 'which version are you on?' for a 426 upgrade, a bug report or the CHANGELOG's own guidance; desktop's About dialog does | fix |
| H126 | low | polish | app-desktop, docs | The 0.26.3 diagnostic log is machinery with no door: nothing in the UI, About, CHANGELOG or docs names ~/.andvari-desktop/diagnostic.log, and it appends a full stack trace per failure with no cap or rotation | fix |
| H127 | low | polish | app-desktop | The G22 Trash reader-gate landed with three treatments: web and Android hide the buttons and append ' · view only', desktop keeps them visible-but-disabled with a separate sentence | fix |
| H128 | low | polish | app-desktop | Desktop's launch-time PendingReconcileDialog makes the destructive choice its dismiss path — Escape, click-away and the dismiss button all discard — and labels it bare 'Discard', where Android names what it reverts to | fix |
| H129 | low | polish | app-android, app-desktop | Android's auth and recovery screens are full-bleed columns with no width cap, so on a Fold inner display or tablet the email/password fields stretch ~800dp wide; web caps the auth card at 440px | needs-verification |
| H130 | low | polish | app-desktop | The shipped .deb carries placeholder metadata — Maintainer: silencelen <Unknown>, Categories=Unknown, License: Unknown, Section: misc — because build.gradle.kts sets none of the Linux fields | owner |
| H131 | low | polish | web | Date/relative-time formatting drifts across sibling surfaces, ago() emits '1 years ago', and version history shows a year-less 'July 14' for saves that can be years old | fix |
| H132 | low | polish | web | Loading and empty states are rendered in four idioms across the web views (Busy dial vs bare text, four casings, EmptySigil vs .muted lines) | defer |
| H133 | low | polish | web, extension | Micro-copy drift: two back-glyphs and casings, 'Id'/'Ip' audit headers, popup empties without terminal punctuation, mixed-case extension page titles | defer |
| H134 | low | polish | web, extension | Stylesheet-parity drift between web and the popup: error/info plates tinted with hard-coded dark-palette hex (including the retired #cf6b5a) in both themes, no reduced-motion block in popup.css, and the popup ignores the web's forced Light/Dark preference | owner |
| H135 | low | polish | web | Two destructive confirms (sign-out and the offline-copy wipe) use native window.confirm while every other destructive path uses the inline two-step idiom the Editor's own comment calls house style | owner |
| H136 | low | polish | web | The web app ships an apple-touch-icon and theme-color but no web app manifest, so 'Add to Home screen' yields a bare shortcut with no name, icon, theme or standalone display | owner |
| H137 | low | polish | web | There is no print stylesheet: a revealed password, the live TOTP code, card number and the whole Health table print as-is with Ctrl+P | owner |
| H138 | low | polish | web, extension, app-desktop, docs | The brand mark ships in two geometries (14-unit inset stave on the tile icons, 18-unit wordmark stave in BrandSigil, the popup headers and the Android launcher) and the web appbar is the one header with no mark | owner |
| H139 | medium | code-quality | web, extension, spec | The WebSocket client reported "open" on the 101 upgrade before the server had registered the socket with its notifier, so a rev bell for a change committed in that window rang nobody — found by the wave-3 gate's fresh e2e run under load, not by any lane; fixed on both clients (onOpen on the first echoed pong, spec 03 §6) | fix |

## 6. Did the 08-30 fixes hold?

Status is the regression lanes' verdict at the call site; **HELD (residue)** means the regression lane confirmed the fix where it was applied and another lane found the fix incomplete — the H row carries the remainder.

| G | Status | H | Note |
|---|---|---|---|
| G01 | HELD | — | five ExternalExcursion.begin() sites, pin at 5 |
| G02 | HELD | — | consume-on-first removedGrant, finally-delete |
| G03 | HELD (residue) | H33, H88 | natives' lock paths bounded; extension lock and Android/web sign-out seams still race; the test never exercises `then` |
| G04 | PARTIAL | H35, H36 | wired on all four clients; inert behind the dirty gate on web/extension, wrong keep-set on the natives |
| G05 | HELD (residue) | H118 | guide corrected; an undated owner-only doc in docs/ root still claims fill-only |
| G06 | HELD | — | spec 02 §5/§8.2 + Wire.kt say usageKey |
| G07 | HELD (residue) | H78 | top-level derivations memoized; per-row vaultInfos() and verifyCurrent() are not |
| G08 | HELD | — | privacy policy names the usage record (live-page mirror is out of scope — refuted) |
| G09 | HELD | — | CoreLog wired to META_REPLAY_NOTICE |
| G10 | HELD (residue) | H10 | download/backup/csv legs bounded; the other op{} legs are not |
| G11 | PARTIAL | H55 | login webDomain laundered; SavedCard.webDomain is not |
| G12 | PARTIAL | H08 | deferral present; re-fire absent |
| G13 | HELD | — | observer above the 426 early return |
| G14 | HELD | — | sender.tab gate on totp |
| G15 | HELD | — | safeSiteHref at Health and Staleness |
| G16 | HELD (residue) | H102, H104 | served-deb hash check present; GH release layout still hand-typed, 0.26.2 SUMS omits the xpi |
| G17 | HELD (residue) | H63 | web-ext pinned, lock synced, --no-install; credentials now ride argv |
| G18 | HELD (residue) | H40 | leg retired, tripwire runs first; tripwire is shape-bound |
| G19 | HELD (residue) | H90 | pins real for the lines they name; call sites unpinned |
| G20 | HELD | — | classify vector run real (5/5 executed) |
| G21 | HELD (residue) | H70 | readOnly rides MatchItem; roles go stale after resync |
| G22 | HELD | (H127 treatment drift) | reader-gated on web/Android/desktop; desktop's treatment differs |
| G23 | HELD (residue) | H17, H18 | copy landed; queued item never projected, and the sentence is false on an in-memory cache |
| G24 | HELD (residue) | H32 | customAction present, on a node TalkBack skips |
| G25 | HELD | — | HealthLine feeds the Announcer |
| G26 | HELD (residue) | H31 | web Announcer; Android NoticeBar is the unproven AM-6 shape |
| G27 | HELD | — | gone offer names item, announced |
| G28 | HELD | — | skip link intercepted, main tabIndex -1 |
| G29 | HELD | — | honest wipe-scope sentence |
| G30 | HELD | — | clamped clearSeconds rendered |
| G31 | HELD (residue) | H123 | both empty states keep the toggle; sentences differ |
| G32 | HELD | — | merge confirm names vaults |
| G33 | HELD | — | refusal shown, run does not advance |
| G34 | HELD | — | explainer says cross-device |
| G35 | HELD (residue) | H26 | absent keys render '—'; changed-since-scan still asserts |
| G36 | HELD | — | temp renamed to survivor first |
| G37 | HELD (residue) | H69 | desktop TotpRow onUsed; the extension popup never came in line |
| G38 | N-A | — | deferred by owner |
| G39 | HELD | — | UsageRecorderCore hoisted, adapters thin |
| G40 | N-A | — | deferred by owner |
| G41 | PARTIAL | H111 | server cap real; spec 03 cap sentence stale |
| G42 | HELD (residue) | H119 | both cite the design doc; Wave-4 runbook still reads as un-run |
| G43 | HELD (residue) | H120 | lockstep claim gone; version literal and icon description stale |
| G44 | HELD | — | passwordHistory attribution corrected |
| G45 | HELD (residue) | H121 | F51/F54 halves fixed; two other rows false at HEAD |
| G46 | HELD | — | sealedVk TODO gone |
| G47 | HELD | — | design carries the correction |
| G48 | PARTIAL | H110 | prose re-rotted within one release; probe never built |
| G49 | HELD | — | restoreItem validates refs (unpinned — H41) |
| G50 | HELD | — | createTempFile rw------- via ownerOnly |
| G51 | HELD | — | requireDomainSafe on both twins (unpinned — H41) |
| G52 | HELD | — | decrypt guards key+header, test pins |
| G53 | HELD | — | sha256 matches gradle.org |
| G54 | N-A | — | deferred by owner (moving-target zip) |
| G55 | PARTIAL | H109 | scope widened; still three literals, spec unscanned |
| G56 | PARTIAL | H114, H115 | README fixed; verify.sh count and the consumers column stale |
| G57 | HELD | — | visually-hidden Actions th |
| G58 | HELD (residue) | H31 | 'Run finished' via the same conditionally-composed NoticeBar |
| G59 | HELD | — | copy names both causes |
| G60 | HELD | — | verdicts curated |
| G61 | HELD | — | tiles snoozed-excluded on both |
| G62 | HELD (residue) | H75 | neutral tone for sighted users; colour-only for AT |
| G63 | HELD | — | saveAttachmentTo maps exportError |
| G64 | PARTIAL | H57 | armed with clear-on-refusal; arm has no expiry |
| G65 | HELD | — | unlock tail returns DEVICE_PROBLEM |

Two 0.22.0-era fixes regressed outside the G range: **F01 → H01** (reopened by the 0.23.0 `passwordReuse` message) and **F35 → H11** (reopened by 0.26.3's `DesktopDiagnostics.mkdirs()`). HELD: 34 · HELD (residue): 20 · PARTIAL: 8 · N-A: 3 · MISSING: 0.

## 7. Refuted — do not re-find — and verification debt

Two lane findings were refuted by their verifiers:

- **docs-professionalism-1** — "the store-linked live privacy page still carries the pre-usage-ledger
  text". The in-repo policy (`docs/legal/privacy-extension.md`) carries the G08 language; the live
  mirror is the reference instance's out-of-tree web root, not this repository. *Operator follow-up,
  not a repo finding:* re-render the mirror per `docs/runbooks/extension-store-publishing.md`.
- **gap-run-gate-and-live-server-1** — "a correct password with no TOTP code writes no audit row". The
  branch is real (`Service.kt` `totp_required`), but it fires on every first step of every 2FA login,
  so it is not the anomalous "attacker has the password" event the finding claimed; the wrong-code and
  replay siblings that do mean that are audited.

**Verification debt, stated plainly:** the 60 single-lens medium verdicts ran on a smaller model than
the finders and confirmed 59 of 60. That rate is far below the 5–19 % refutation the two predecessors
saw, and should be read as *weaker corroboration* than the eight three-lens verdicts, not as a cleaner
finding set. The remediation re-reads every medium at its call site before changing it, and the
post-fix connectedness recheck is adversarial. The lows (85) are lane claims only.

## 8. Closure (2026-09-13)

**Landed on `main` after the report commit `e947528`: `d2b2ad7` wave 1 · `a658d64` wave 2 · `e82ec73`
wave 3 · `3077d83` extension parity for H139. Not pushed. Gate GREEN on a real execution
(`gradlew --rerun-tasks`, 66/66 tasks executed, 0 UP-TO-DATE): core 525, server 233, desktop 120,
tools 37, Android 172 + assembleDebug, web vitest 1236 passed / 9 skipped, extension 362, `e2e.sh`
3/3 phases each with a passing test, doc-leak scan + self-test, PowerShell gate, lockfile gate.**

- **Wave 1** — seven directory-owned lanes (extension, web, Android, desktop, core, server, spec/docs/
  scripts) in parallel, chained into twelve parts; 70 rows landed with a pin per behaviour change.
  Three rows correctly skipped: H24 on the natives (no admin surface exists) and H10 in core (no core
  leg — the bounds belong at the desktop call sites, where they landed).
- **Wave 2** — four cross-cutting clusters with exclusive file ownership across modules: sync/offline
  (H03 H17 H18 H19 H38 H71), usage ledger (H05 H33–H36 H79 H88), URI matching (H22 H124), vectors and
  twin pins (H42 H92 H93 H95 H114 H115), plus the two deferred documentation parts; 37 rows.
- **Wave 3** — the cross-wave hand-offs (H92 core parse, H80 web zeroization twin, H111, H112, H33),
  the H41 regression pins (five new `RegressionPins0262` suites, security controls first, red-when-
  reverted where a seam exists), the gate run fresh, and then **an adversarial re-read of every fix
  by eleven independent reviewers at its production call site: 49 findings, 0 disputed, 48 fixed,
  1 deferred.** The re-read earned its cost: it found helpers built and never called (core
  `passwordFillTargets`, `nativeSodiumFallbackCause`), legs that never landed (the extension is a
  push client and had not learned the new `rejected` status; the PASSIVE_MSGS membership pin H01
  asked for; the H02 typed-gesture mark was never consumed; the backup's attachment download was the
  one busy leg still unbounded; `kdfSalt` was the one register field left unvalidated), one fix that
  would have bricked an instance with an already-persisted non-KiB KDF policy (the server now heals it
  on read), one that crossed a registrable domain (a UTS46-mapped spelling; `normalizeHost` now rejects
  it and displays U-labels), and pins that pinned nothing. Gate 2 was green on its first fresh run.

**Final disposition of the 108 fix rows: 102 fixed, 6 partial.** H19 (byte-bound batches landed; a
plan-time "row too large to sync" import-report entry is an owner call); H44 (the web lock is bumped;
exercising it needs an operator `npm ci` with `NODE_ENV` unset — R30); H47 (the watcher's log-of-record
fix is committed in its mirror of record, deployment is an operator step); H104 (the same-bytes SUMS
mechanism landed in `scripts/gh-release.sh`; re-uploading `SHA256SUMS-0.26.2.txt` with the .xpi digest
is an owner action on a published release); H109 and H126 (their last leg is a CHANGELOG sentence,
carried into the next release's entry below).

**H139 — found by the fresh gate, not by any lane.** `scripts/e2e.sh` phase A failed under load: the
web client reported the WebSocket "open" on the 101 upgrade, but the server registers the socket with
its notifier only when the route body runs, so a bell for a change committed in that few-millisecond
window rang nobody — and the notifier has no replay. Both clients now report open on the first echoed
`pong`, which the server can only send after `notifier.register()` (spec 03 §6 amended; the
extension's binding design doc amended in the same places; three red-when-reverted tests per client).
Twenty-six lanes read this code and none saw it; running the drill did. That is the argument for the
CI test job (H39) in one paragraph.

**Owner decisions (§4) are unchanged: 25 rows.** Operator steps before the next cut, in order:
1. `cd web && NODE_ENV=development npm ci --ignore-scripts && npx vitest run && npm run build` — the
   only unverified change in the tree (R30, the browserslist/caniuse lock bump).
2. Deploy the manifest watcher from its mirror of record (H47); close Dependabot PR #56 as superseded
   and confirm Scorecard alert #23 clears on the next run (H44); re-upload the 0.26.2 SUMS with the .xpi
   line (H104); flip the ghcr package public or stop calling it public (H43).
3. On the phone: the TalkBack smokes for H09, H31, H32 (overlay unlock then a second fill; breach-scan
   and run-finished announcements; the "Refresh" custom action in the Actions menu).
4. At the cut: the `signandvari` read-back (H110) and `scripts/gh-release.sh` (H102) run live for the
   first time — both are proven only by parse and dry-run; record the image digest in the release body
   (H99); the next CHANGELOG entry (draft below) carries H109/H126's sentences.

**Verification stance, stated plainly.** Everything above was executed, not inferred: two fresh gate
runs with per-suite counts, every re-read finding re-tested by the closing agent, the extension parity
fix proven red-when-reverted. What is *not* proven: H110 and H102 (dry-run only), the device smokes,
and R30. The single-lens verification debt of §7 was paid by the eleven-reviewer re-read: of 49
findings it raised, none was disputed by the closing agent.

**Draft changelog for the next cut** (house voice; the owner sets the version):

> *A full audit of every platform, the third, found no crypto defect and a long list of the same shape
> as last time: a fix that shipped its first leg and not its last. The serious ones: a browser page
> could keep the extension unlocked and probe the vault for a password; one bad attachment reference
> could stop a device syncing until you signed out; a change-password form saved the old password
> instead of the new one; and a change made in the same instant a device reconnected could go
> unnoticed until the next one. All fixed, on every client, with a test for each.*
>
> - **Extension:** a page can no longer hold the vault unlocked or test passwords against it; the
>   reuse check now needs you to actually type. Card updates that conflict keep both versions.
> - **Sync:** a stale attachment reference is refused for that one item instead of blocking
>   everything behind it; big imports are sent in bounded batches; a change made while a device was
>   reconnecting is caught up on every client.
> - **Autofill:** change-password forms save the new password on the phone and in the extension; the
>   phone no longer fills the old password into the new-password box; sites with international names
>   match the way browsers spell them.
> - **Offline saves** on the phone and desktop now appear in the list immediately and the message is
>   true for the kind of vault you have; the "last used" ledger never overwrites the household's copy
>   with one device's guess, and is trimmed after every sync.
> - **Honesty and polish:** the desktop app stops at start if its encryption library will not load and
>   says so, instead of "Sign-in failed"; admin device counts distinguish signed-out from live;
>   diagnostic logs are owner-only, bounded and documented (`~/.andvari-desktop/diagnostic.log` is safe
>   to delete); dozens of copy, contrast, focus and screen-reader fixes across all four clients.
> - **Under the hood:** master-key material is wiped after use on web as on the natives; the server
>   heals a mis-sized KDF policy and bounds every registration field; the doc-leak, PowerShell and
>   lockfile gates got fixtures; 0.26.2's fixes got the regression tests they shipped without. Full
>   report: `docs/design/2026-09-13-full-surface-audit.md`.

## 9. What this audit says about the next one

- Half-landed remediation — the fix's copy, gate or first leg shipped and its state machine, re-fire, remaining legs or pin did not: H08, H10, H17, H18, H33, H35, H36, H40, H41.
- Regression by later addition — a control written for the set of messages, files or paths that existed at the time, reopened by something added afterwards: H01/H02 (passwordReuse after F01), H11 (DesktopDiagnostics after F35), H57 (G64 arm), H59 (KLKEY after the purge path).
- A refusal answered by 'try again' or 'wrong password' — a permanent local or structural failure rendered as the user's fault: H15, H16, H17, H20, H67, H68.
- A queue that cannot drain — a definitive server refusal leaves a row at the head of the sync queue and every later sync replays it: H03, H19, with H37 as the same shape producing junk instead of a wedge.
- Web is the reference and the natives lag it, now on the health run, recovery, export and lifecycle notices — and occasionally the reverse: H12, H23, H27, H28, H29, H71, H72 (natives lag); H68, H73 (web is the laxer one).
- A gate that reports more than it ran — green from UP-TO-DATE reads, vacuous passes, shape-bound tripwires and line-pins that miss the call site: H39, H40, H41, H88, H90, H91, H96, H97.

Three things for the next audit to carry forward. First, **a fix is not landed until its last leg is**:
the defining pattern this time was remediation that shipped its copy, its gate or its first leg and
stopped — the next remediation wave should end with a per-finding "which legs, which clients, which
test" checklist before it is called closed, which is what §8 will record. Second, **a control written
for the set of things that existed at the time needs a pin that fails when the set grows**: both
regressions of 0.22.0 fixes (H01, H11) were reopened by additions, not edits. Third, **the safety net
needs a CI test job** (H39): a gate that is only ever run locally, from a warm cache, on the machine
that made the change, is a gate whose green is an assertion about the operator's discipline, not about
the tree.
