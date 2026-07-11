# andvari v6 backlog

> **Provenance.** The v5 recon (2026-07-07) produced **84 findings**. The eight shipped v5 batches (B1–B8) plus the Skipti shared-vault lifecycle (0.5.0) consumed ~39 of them directly. The remaining **45 candidates** were each independently re-verified against the current tree (**HEAD `1f0fcdb`**) on **2026-07-08**; this document is the honest ranked disposition of every one of them. Nothing is silently dropped — all 45 F-ids appear below exactly once as a primary entry.

**Summary of verdicts:** 9 findings turned out to be **already consumed** by v5/Skipti (several fixed by name — the code cites F22/F26/F27/F29/F31 in comments). 19 survive as **quick wins** (all effort-S), grouped here into three concrete reviewable batches by surface. 8 **fold into planned v6 queue items** (skipti-loose-ends ×3, quick-unlock ×2, and one each for totp-qr-hub, importers, extension-spike). 8 need **standalone batches** (grouped into four proposals). 1 is a defensible **won't-fix**. Several "yes" verdicts came back *partial* — the sections below say exactly which half died.

> **Update 2026-07-08:** QW-1 shipped (fleet unified at 0.5.0) and **round-2 recon ran** (`docs/recon/2026-07-08-round2-recon.md`). Recon verified the v5/Skipti set is sound and added **6 findings the static F-id triage couldn't reach** — see the new **§6**. Three are P1 silent-data-loss / broken-recovery paths (**ATT-1, PDD-1, PRC-1**) now grouped as a **pre-migration integrity batch**.

---

## 1. Consumed by v5/Skipti after all (9)

No remaining work. Listed for traceability; residual polish noted inline.

| id | title (condensed) | where fixed |
|----|----|----|
| **F13** | Shared-vault lifecycle missing at every layer (immortal vaults, owner gripe 1) | **Skipti 0.5.0** end-to-end: delete + 7d grace/restore, leave, two-phase transfer, rename — `App.kt:430-464`, `Service.kt:607/663/726/809/841`, `Janitor.kt`, spec 03 §11 + lifecycleproof vectors, web+Android UI, full test coverage. Residue tracked as `skipti-loose-ends`. |
| **F14** | Disabled/lost owner permanently orphans a shared vault | **Skipti**: escrow recovery reactivates the account with grants+ownership intact (`AdminService.kt:92`), then transfer/delete applies; admin-forced transfer *deliberately rejected* as F16 forgery class (design doc Q2, spec 03 §11, `ops/runbooks/vault-succession.md`). |
| **F15** | Vault rename impossible at every layer | **Skipti**: owner-only `PUT /vaults/{id}/meta` with stale-write guard (`Service.kt:908`), core `buildRenameMeta`/`renameVault`, web `Sharing.tsx` RenameHeader (tagged "F15"), Android rename, tests. |
| **F22** | Members list shows disabled accounts as normal | **Skipti rider** — code literally says "F22 rider": member status returned additively (`Service.kt:484-495`, `Wire.kt:236-238`), web badges disabled + excludes from transfer picker. *Optional polish: mirror the badge on Android members screen.* |
| **F26** | Lock/auto-lock/revocation dump to full sign-in with zero explanation | **B7** — `App.tsx:25-118` keeps the session, lands on Welcome-back unlock with reason lines ("Locked.", "Locked in another tab.", revoked vs expired). *Tiny residue: native lock screens show no reason line — ride-along polish only.* |
| **F27** | Locking one tab leaves other tabs unlocked | **B7** — BroadcastChannel `andvari-lock` + storage-event sign-out propagation, code annotated "F27" (`App.tsx:100-170`). |
| **F29** | No sync path when the WebSocket can't connect | **B7** — degraded-mode HTTP poll, manual "Sync now", dot = wsUp && syncOk, single-flight sync (`Vault.tsx:140-164`, `store.ts:270`). Exceeded the original proposal. |
| **F31** | Web skips identityPub cross-check + rev-regression guard | **B7** — both spec-MUST guards ported with typed errors (`account.ts:135-150`, `store.ts:165-172, 310-325`) and dedicated tests. |
| **F53** | Concurrent conflict-copy materializers cascade junk copies | **v5** — deterministic conflict-copy ids (sha256-derived, spec 03 §5, vector-pinned in `conflictcopy.json`) + skip-if-exists on both platforms. A vanishing residual race yields one bounded converged copy, not a cascade — belongs to round-2 recon *only if* it ever manifests. |

---

## 2. Quick wins (19, all effort-S) — three proposed QW batches

Ranked by value:effort inside each batch. Every item is self-contained; batches are grouped by surface so one reviewer can hold the whole diff.

### QW-1 — "Server hardening & truth" (server, combined effort ~M as one batch)

> **DONE — shipped 2026-07-08** (per §7.1 below; round-2 recon verified the batch live
> rather than re-finding it).

The server now fronts a public break-glass origin; these close availability and spec-truth gaps in one pass.

- **F50** *(yes, medium)* — Unauth login runs 64MiB argon2id per request with per-IP limits only → IP-spread OOM. **Fix:** global `Semaphore(2-4)` in `ServerCrypto` around verify/hashVerifier, tryAcquire-with-timeout → 429; optional global `login:*` window. ~20 lines + unit test.
- **F51** *(yes, medium)* — `/downloads/{file}` slurps whole installers into heap (`App.kt:126-128`); the attachment route right below already streams. **Fix:** switch `respondFileContent` to `respondFile`/`respondOutputStream` + contentLength, reuse at the SPA fallback.
- **F52** *(yes, medium — slightly worse post-Skipti: ~14 awaited call sites now)* — WS dirty-bell fanout awaited inline, sequential, no send timeout; one wedged socket stalls saves up to ~60s. **Fix:** SupervisorJob scope in Notifier, non-suspending fire-and-forget fanout, `withTimeoutOrNull(2s)` per session, close on timeout.
- **F55** *(yes, medium)* — hardening pack: no TOTP confirm/disable limiter, HIBP bad prefix → 500 + stack trace, no nosniff/Referrer-Policy, RateLimiter windows never evict, login_fail audit only for known emails. **Fix:** `limiter.allow("totp:{userId}")`, BadRequest for bad HIBP prefix, two headers, opportunistic window eviction, uniform login_fail audit.
- **F28** *(partial, medium)* — web already sends a stable `installId` (B7) but the server ignores it and inserts a clone device row per sign-in; B7's lock-keeps-session removed the daily amplifier, so growth is slower than the original claim. **Fix (the remaining half):** nullable `devices.installId` column + upsert branch in `issueSession`; admin list ordered by `lastSeenAt DESC`; optional janitor prune.
- **F54** *(partial, low)* — the keepalive leg is FIXED (30s server ping shipped in v5, spec updated); remaining: `notifyRevoked` has zero callers and no `policy` frame producer, while spec 03 §6 promises both and web `client.ts:546` handles a frame that never arrives. **Fix:** ring notifyRevoked + close sockets from disableUser/revokeDevice/refresh-reuse; either add notifyPolicy or amend spec 03 §6.

### QW-2 — "Web daily-UX & spec truth" (web, combined effort ~M as one batch)

> **DONE 2026-07-09 (additive on 0.8.0, not yet deployed).** F60 master-password floor
> (score≥3, enforced at enroll + change-password incl. forced-change, non-ASCII SHOULD-warn,
> `strength.test.ts`), F79 search (notes + all URIs + card identity, web+desktop+Android),
> F76 Back-guard (`useBackGuard` steps through layers instead of leaving the SPA), F64
> session-TTL admin fields (clamped ≥1), F78 masked editor password + Generate-overwrite
> confirm. F59 was already shipped; F75's copy is now TRUE post-importers (no change). 3-lens
> adversarial review: 1 MEDIUM (F76 sentinel leak on lock-while-deep) found + fixed. Web
> deploy to CT122 pending owner go (no version bump; native F79 rides the next APK/deb).

- **F60** *(yes, medium)* — master password floor is length≥8 while throwaway backup exports demand score≥3; spec 05 T8 claims enforcement that doesn't exist. **Fix:** `estimateStrength` score≥3 in Welcome enrollment + Settings change-password (covers the forced-change path), non-ASCII SHOULD-warn per spec 01 §1. *Do before real secrets migrate.*
- **F79** *(yes, medium)* — search ignores notes and every URI after the first; desktop matches name+username only. **Fix:** two one-line predicate extensions (`Vault.tsx:169`, desktop `Ui.kt:199`); optionally mirror on Android.
- **F75** *(yes, medium)* — export panel promises re-import dedupe that doesn't exist (import panel says the opposite; `planImport` never consults the vault). **Fix now:** one-line copy correction in `ExportPanel.tsx:403` + test (error-truth doctrine). The vault-aware merge half folds into **importers** (see §3).
- **F76** *(yes, medium)* — zero history-API usage; browser/gesture Back exits the SPA from anywhere, costing an argon2 unlock. **Fix:** sentinel `pushState` + popstate handler that steps view/detail/modal state back instead of leaving (~50 lines, not the full router the original M estimate assumed).
- **F59** *(partial, medium)* — recovery step 1 tooling: the "no doc exists" half is now FALSE (`ops/runbooks/vault-succession.md` shipped with Skipti); still missing: Admin "Download escrow blob" button, `docs/drills/account-recovery-drill.md`, and actually running the drill (ROADMAP step 6, pre-migration). **Fix:** button + `getUserEscrow()` client call + drill doc + one scratch-server exercise.
- **F64** *(yes, medium value, trivially small)* — session access/refresh TTLs are live policy knobs with no Admin UI fields. **Fix:** two `numField` rows in `Admin.tsx`, clamp >0.
- **F78** *(yes, low)* — editor password field is bare plaintext; Generate silently overwrites typed input. **Fix:** editable masked PasswordField + auto-reveal and confirm-overwrite on Generate; the length/class popover can wait.

### QW-3 — "Native robustness" (Android + desktop, combined effort ~M as one batch)

> **DONE 0.9.0 (`b538e69`, PLAN-07 cycle 1).**

- **F58** *(yes, medium)* — `mustChangePassword` completely unwired on Android/desktop; a recovery temp password stays silently live. **Fix (the finding's own minimum):** propagate the flag from login into session state, blocking banner directing to the web app; full native change-password screens deferred.
- **F72** *(yes, medium)* — no Enter-to-submit anywhere on desktop, including the unlock screen (the most-repeated interaction). **Fix:** `onPreviewKeyEvent` Enter→submit on Unlock/SignIn/Enroll/TOTP/backup dialogs, Escape→dismiss. Pure `Ui.kt`.
- **F74** *(yes, medium)* — background sync hijacks the shared `busy` flag (Save greys out mid-typing; offline = tens of seconds locked UI); enroll builds-closes-rebuilds an OkHttp client and leaks the second; signIn leaks on generic throws; desktop TOTP spinner spins forever beside its own error. **Fix:** separate `syncing` flag, try/finally-`.use` on clients, tri-state TOTP status with Retry.
- **F11** *(yes, medium)* — FieldClassifier: `onetimecode` missing from negative hints (passwords offered into OTP boxes — andvari's own Welcome TOTP field is the pattern), `personname`→USERNAME, idEntry gated to API 30 (minSdk 29, so that sub-part only helps Android 10). **Fix:** hint-set edits + ungate + classify vectors in `urimatch.json` (harness already exists).
- **F81** *(yes, medium — original effort overstated; B8/Skipti already plumbed roleFor/vaultId into DesktopState)* — desktop can't create a note and shows no shared-vault badge. **Fix:** "+ Note" button (Editor already branches on type) + gold vault-name label when `vaultId != personalVaultId`.
- **F12** *(yes, low — honest hygiene, serve-gate already holds)* — autofill-only process never hard-locks; keys linger in RAM after idle. **Fix:** `Handler.postDelayed` at autoLockMs+slack calling `getIfFresh()` from AutofillUnlockActivity/service, respecting the in-flight-op deferral, skip when autoLockMs==0.

---

## 3. Fold into v6 queue items (8)

Each planned feature batch inherits this checklist — the fold-ins are part of its definition of done.

### → skipti-loose-ends (natural Skipti follow-through; machinery all exists now)

- **F18** ✅ **DONE 2026-07-10** (cycle 4) — vault picker for NEW items on Android + desktop (writable vaults only; shown only when `itemId == null` and >1 choice), vault-name tags on rows/detail, desktop Move/Copy via core `runGesture`. Core `saveWithUploads` computes `effectiveVault = existing?.vaultId ?: vaultId ?: personal`, so an existing item can never be re-homed. *(was: partial, M, medium)* — vault picker for NEW items on natives + vault-name tags. Explicitly deferred by the Skipti design doc ("the F18 vault-picker batch"); severity dropped since Android F19 move/copy shipped, but "silently lands in Personal" is still fully true on desktop, half-true on Android. **Fix:** vault dropdown on new-item editors (core `saveWithUploads(vaultId)` param already exists), vault tag on rows/detail, port MoveCopyControl to desktop for F19 parity.
- **F20** ✅ **DONE 2026-07-10** (cycle 4) — read-only roster for any grant-holder, `added` notice kind (never on since=0/resync, never for a reinstated, personal, or **owned** vault, once per vault), persistent undecryptable-grant warning that self-clears. *(was: yes, M, low)* — member transparency: non-owners can't see the roster (server already allows it), no "added to vault" notice kind, undecryptable grants silently swallowed. **Fix:** read-only roster for member-role vaults, `added` LifecycleNotice kind (mirror transfer-complete dedup), persistent "can't open this shared vault on this device" warning row. Skipti built the notice pipeline and member panels this reuses.
- **F49** *(partial, M, low)* — retention: the item_versions 10-cap sub-claim is fixed and spec 02 §7 now documents tombstone-GC dormancy as deliberate (v5), but sessions/changes/mutations/audit/hibp_cache/invites still grow forever. **Fix:** extend the Skipti Janitor (the exact host machinery the finding asked for) with a low-risk pruning pass; leave tombstone GC dormant until the spec'd convergence test exists — do not bundle.

### → totp-qr-hub

- **F77** ✅ **DONE (v6-QW1, 2026-07-08)** *(yes, M, medium)* — server-TOTP enrollment is copy-a-base32-by-hand, no QR anywhere in web/src; gates break-glass sign-in (server-TOTP still not enrolled household-wide). **Fix:** build the dependency-free QR encoder ONCE in the hub (byte-mode, EC-M, canvas/SVG, CSP-safe) and reuse it to render the otpauth URI in Settings enrollment, keeping copy fields as fallback.

### → importers

- **F56** ✅ **DONE (0.8.0 perf pack)** *(partial, M, medium)* — the client sync-mutex/cursor-regression leg is FIXED (B7 syncMutex + web single-flight). Remaining four legs (OR-joins defeating rev indexes, orphan GC holding the DB lock across filesystem walks, unvirtualized web list, unpaged pull) only bite at 10k-import scale — exactly the importers batch's territory, where a 10k synthetic DB is the natural test fixture. **Fix:** measure first, then split OR-pulls, move file deletes post-commit, window the vault list, additive `more` paging flag if warranted.
- *(F75's second half — vault-aware import dedupe — also lands here; the copy fix ships now in QW-2.)*

### → quick-unlock (p6)

- **F84** ✅ **DONE (0.9.0 quick unlock)** *(yes, M, medium)* — this IS the quick-unlock scoping assessment and all its claims still hold: unlock is password-only, androidx-biometric catalogued but unwired, no `unlockWithUvk`, AutofillUnlockActivity hook in place. **Plan:** spec pass first (cacheAllowed gating, at-rest secret row in spec/05, KDF-bypass mitigation), ~15-line `Account.unlockWithUvk`, BiometricPrompt + Keystore AES-GCM wrap; Windows DPAPI+PIN deferred past the MSI refresh.
- **F61** ✅ **DONE (0.9.0 KDF upgrade)** *(yes, M, low)* — spec 01 §7 KDF-upgrade flow implemented in no client; dormant until the (never-raised) policy floor changes, and implementing it before quick-unlock would leave biometric-only users permanently un-upgraded — the finding itself says so. **Fix:** silent same-password re-key on full-password unlock when account params < policy, paired with quick-unlock's periodic-password rule. Interim: one-line "deferred" note in spec 01 §7 so the spec stops overstating.

### → extension-spike

- **F83** ✅ **DONE (extension shipped 0.6.1+)** *(yes, L, medium)* — the extension assessment, still accurate: the vector-locked TS layer (urimatch, crypto mirror, framework-light client) exists, no extension work started, and its v5 prerequisite (all-additive wire changes, formatVersion stays 1) was honored by Skipti. **Plan:** 30-min libsodium-WASM-under-MV3-CSP go/no-go first, then Chromium fill-only MVP with `chrome.storage.session` key custody and per-frame origin matching; spec the per-item "don't fill in browser" field additively before shipping.

---

## 4. Standalone batches (8 findings → 4 proposals)

### SB-1 — "Autofill reach" (F09 + F10) — Android, combined M, value medium

Both half-fixed by B2 (fallback row + Autofill Status diagnostics made failures *visible*), both need the same parser/service/trust surface, neither fits a v6 fold target.

- **F09** *(partial)* — `FLAG_MANUAL_REQUEST` still never read; the user's explicit long-press escape hatch returns null exactly when heuristics classify zero fields. **Fix:** detect the flag, surface the focused node as a synthetic target, offer capped clearly-labeled datasets (explicit gesture = consent), keep the trusted-browser domain gate, add a `MANUAL_FALLBACK` trace reason so Autofill Status stays truthful. Needs a deliberate consent/label decision → reviewed batch, not a blind quick win.
- **F10** *(partial)* — B2 fixed discoverability ("From: pkg" + androidapp:// explainer); the authoring half is untouched — both editors still bind only `uris[0]`, so linking an app to a web login means sacrificing its https URI. **Fix:** (1) full uris list read-only + "add another URI" repeater in both editors (this alone makes it workable); (2) "Link a login to this app" picker in the NO_URI_MATCH fallback that appends `androidapp://<pkg>`.

**Why now-ish:** autofill is the app's daily surface and B2's diagnostics will now *show* users these dead ends.

### SB-2 — "Escrow re-seal" (F57) — cross-client, M, value medium

- **F57** ✅ **DONE (0.6.0 — re-seal on all three clients)** *(yes)* — `PUT /escrow/self` is live and validated but web `putEscrow` has zero callers, `AndvariApi` has no escrow method, and no policy re-escrow flag exists — after any recovery-key re-ceremony every account's escrow stays sealed to the dead key; spec 04 §4 presents re-seal-on-unlock as current behavior. **Fix:** compare enrollment fingerprint vs `policy.recoveryFingerprint` on unlock, re-seal via the short-form-verified flow + `putEscrow`; add `escrowSelf` to AndvariApi + Android hookup; re-ceremony integration test. **Cheapest honest interim:** reword spec 04 §4 to "planned".

**Why now:** latent lockout/data-loss path in the household's only forgot-password machinery — land before real secrets migrate, alongside the F59 drill.

### SB-3 — "Item history & field truth" (F62 + F63) — owner decision first, combined M, value medium

These are two halves of one question: does andvari keep password history or not? Decide jointly (PICKUP-v6 already floats "item history & undelete" as a pitch) — either build both or delete both promises.

- **F62** *(yes)* — `passwordHistory` and `favorite` are spec-normative and round-trip-protected on every layer but no client ever writes or displays them; silently losing the previous password on rotation is a mild data-loss hazard. **Fix:** shared append-retired-password helper in :core wired into all three editors + read-only reveal + favorite star; OR one-line spec/02 "reserved" marking.
- **F63** ✅ **DONE (0.6.0 item history & undelete)** *(yes)* — item_versions archives 10 versions per item that no route exposes and no client reads — the spec-promised "password history repair" backstop is unreachable ciphertext. **Fix:** additive grant-checked `GET /items/{id}/versions` + minimal client history/restore panel; OR drop the table, the archive write, and the spec promise together. Keep pruning semantics coherent with the F49 janitor work.

### SB-4 — "Client debt & polish" (F71 + F82 + F80) — combined ~L, do last, freely splittable

Internally sequenced: F71 first (data-loss-adjacent), F82 second (drift trap), F80 whenever (pure cosmetics — cut without guilt).

- **F71** ✅ **DONE (0.10.0 cycle 7, `d7bac42`)** *(yes, M, medium)* — desktop editor closes optimistically before the async save resolves (failed upload discards typed edits + attachment); `saveAttachmentTo` bypasses `writeVerifiedAtomically` (which exports already use); no overwrite confirm on Linux save dialogs; no upload progress (Skipti added `onProgress` to gestures but not `saveWithUploads`). **Fix:** keep editor open until save resolves, route through the atomic helper, exists()-confirm wrapper, optional `onProgress` on saveWithUploads mirroring runGesture.
- **F82** ✅ **DONE (0.10.0 cycle 7, `d7bac42`)** *(yes, M, low)* — ExportPlanner exists in three copies and the two "identical" Kotlin twins have already drifted (android grew BackupRequest in B8; desktop didn't); SyncEngine exposes no cache read surface so both natives carry the engine's private VaultCache (close-ordering hazard papered over). **Fix:** hoist shared planning into core jvmShared, add `envelopes()`/`vaultRows()` pass-throughs, delete the carried cache refs. Land before the next spec-07 change; web `plan.ts` stays (inherent to the non-KMP stack).
- **F80** ✅ **DONE (0.10.0 cycle 7, `d7bac42`)** *(yes, M, low)* — 7 visible web consistency defects (bare ExportPanel checkbox labels, no shared ViewHeader, un-carded boot hero, hover-lifting inert rows, mouse-only Health rows, tofu-risk runic sigils, raw userId in the appbar). **Fix:** one presentation pass — `.check` class, ViewHeader extraction, `.item.static` modifier, keyboard-reachable rows, inline-SVG sigils, email in appbar. Cosmetic-only; the shared component + SVGs push it past S.

---

## 5. Won't-fix (1)

- **F30** — *Web persists the rotating refresh token in localStorage (XSS → multi-day takeover).* **Defense:** signed-off accepted risk (spec 05 R2/T6 — any attacker who can run JS on the origin captures the master password itself, which strictly dominates token theft); B7 deliberately built cross-tab refresh dedup, pair adoption, lock-keeps-session, and revocation signaling ON the persisted pair, so memory-only tokens mean reworking just-shipped machinery plus a device row per tab/reload — not worth M for a tailnet-only household. **Revisit trigger:** if the web client ever goes public beyond break-glass → HttpOnly-cookie refresh (server+web batch); the fix sketch is on file.

---

## 6. Round-2 recon additions (2026-07-08)

Round-2 recon (**`docs/recon/2026-07-08-round2-recon.md`** — 7 adversarial lenses + 4 persona walks against post-Skipti HEAD `1f0fcdb`, prod-parity lens vs deployed `190c627`) confirmed the v5/Skipti fix set is **sound: 0 regressions, byte-clean prod parity, every Skipti seam verified.** It also reached defects the static F-id triage above structurally *could not* — live concurrency races, break-glass *tooling*, boot-time config — surfacing **six new findings** (own id space) plus live corroboration of several F-ids.

### New — not reducible to any F-id above

| id | sev | one-line | disposition |
|----|----|----|----|
| **ATT-1** | ✅ **DONE** (0.6.0-era pre-migration integrity batch; was **P1**) | Concurrent same-`attachmentId` PUTs interleave into one deterministic `.part` inode → committed `row.sha256` matches neither on-disk blob; permanent, silent, undetectable ciphertext loss. **Reproduced live.** | **pre-migration integrity batch.** Fix = unique temp file per upload (`File.createTempFile`); the commit-time row guard already serializes the winner. |
| **PDD-1** | ✅ **DONE** (0.6.0-era pre-migration integrity batch; was **P1**) | Concurrent same-item edit is last-write-wins; client builds the "conflict copy" from the *winner* instead of the returned `serverItem`, so the displaced edit is lost — on web **and** native (parity confirmed). Violates spec 03 §5. **Reproduced two-tab.** | **pre-migration integrity batch.** Fix = materialize copy from `result.serverItem`; mirror in core `SyncEngine`. |
| **PRC-1** | ✅ **DONE** (0.6.0-era pre-migration integrity batch; was **P1**/P2) | `recovery-cli recover` writes `tempKdfParams` as a JSON **string** `"{}"`; server field is a `KdfParams` object under a non-lenient `Json` → admin upload 400s. The household's only forgot-master path breaks at the last step; a non-technical admin is stranded holding a valid temp password. | **pre-migration integrity batch** (recovery must work before real secrets). Fix = emit nested object + round-trip test + concrete admin-authed curl in the runbook. Trivial. |
| **PROD-1** | ✅ **DONE** (`0eebbfd`; was P2) | `logback.xml` nests the `AUDIT` appender *inside* its logger instead of referencing it → "Appender named [AUDIT] not referenced" at boot; **zero** audit lines reach journald/Loki (SQLite `audit` table still written — no data loss, but the tamper-evident off-box copy the Alloy pipeline exists to produce doesn't exist). | QW-1-adjacent server fix (config one-liner + a boot-assert test). |
| **LC-1** | ✅ **DONE 2026-07-10** (`1f8903c`) | Re-delete during restore-replay: the `replayedMutationIds` fast-path skips a member's parked offline edit → **F21's** offline-edit protection defeated. The one place new lifecycle code introduced a loss path. | **skipti-loose-ends** (§3) — Skipti-seam gap, fresh-context follow-through. |
| **MSI-1** | P2 | Desktop MSI sends `X-Andvari-Client: android/0.2.0`; a future `minVersion[android]` pin would 426-wedge the owner's daily desktop. Latent (no pin set today; compile-time default `emptyMap`). | Guard-rail for **quick-unlock / MSI-refresh** — desktop must send its own client id *before* any android pin ships. **In-source DONE** (DesktopState.kt sends `desktop/<ver>`); residual = the fielded 0.2.x MSI until the owner rebuilds. |

### Corroborated (already tracked as F-ids — recon adds live evidence, no new work)
WS-1/WS-2 ↔ **F54** (dead `notifyRevoked` / `policy` frame). PDD-2 ↔ **F79** (search ignores notes + 2nd URI). PDD-4 ↔ **F10** (single-URI editor). PRC-3 ↔ **F57** (dead `PUT /escrow/self`). PRC-2 ↔ **F58** (post-recovery temp password stays live). ATT-2 ↔ the attachment-integrity family. Autofill P3s (AF-2…6) ↔ **F09 / F11 / F12**. The full recon→F-id map is in the report §1 ("Did the v5 fixes hold?").

### → pre-migration integrity batch (NEW, recommended before real-secrets migration)
**ATT-1 + PDD-1 + PRC-1** are three independent *silent data-loss / recovery-broken* paths — all pre-existing (not QW1 regressions), all small, well-scoped fixes. Ship them as **one reviewed server+core batch before real secrets migrate**, on the same gate as the already-identified recovery items (**F57** escrow re-seal, **F59** drill). PROD-1 (audit truth) rides along naturally. This is the concrete "harden before migration" content ROADMAP step 6 was holding a place for.

---

## 7. Recommended order of play

Tied into the ratified v6 queue (**triage → round-2 recon → totp-qr-hub → cards+save-flow → importers → extension-spike**, with skipti-loose-ends and quick-unlock as adjacent lanes):

1. **Now, before real-secrets migration:** **QW-1 (server hardening)** — ✅ **shipped 2026-07-08** (F50/F55 live on the public origin; round-2 recon verified them rather than re-finding them). Remaining pre-migration gate: the **§6 integrity batch (ATT-1 + PDD-1 + PRC-1 + PROD-1)** and the two recovery items **F59 drill + Admin button** (ROADMAP step 6) and **SB-2 escrow re-seal (F57)** — the recovery path must be *real and tested* before secrets migrate; at minimum ship the spec-truth reword.
2. **Round-2 recon** — ✅ **done 2026-07-08** (`docs/recon/2026-07-08-round2-recon.md`): B1–B8 + Skipti + QW-1 all verified sound. Surfaced the **§6 pre-migration integrity batch (ATT-1 + PDD-1 + PRC-1)** — three silent-data-loss / broken-recovery paths that should ship **before real secrets migrate**, folded into step 1's pre-migration gate above. The F53 residual race did **not** manifest; F27 multi-tab held.
3. **QW-2 (web UX)** and **QW-3 (native robustness)** — independent of the feature queue; slot either between recon and totp-qr-hub or as filler between features. F60 (password floor) should not slip past migration.
4. **skipti-loose-ends** (F18, F20, F49) — fresh-context follow-through while the Skipti machinery is warm; naturally pairs with the CT122 snapshot + v4 migration step already tracked.
5. **totp-qr-hub** — inherits **F77** (build the QR encoder once, reuse for enrollment).
6. **cards+save-flow** — no fold-ins from this triage; good moment to put the **SB-3 (F62/F63) history-or-delete decision** to the owner, since both touch what an "item" is.
7. **importers** — inherits **F56** (perf pack, measure at 10k scale) and **F75's** vault-aware dedupe half.
8. **SB-1 autofill reach (F09/F10)** — schedule after round-2 recon confirms B2's diagnostics are truthful in the field; it builds directly on them.
9. **extension-spike** — inherits **F83** wholesale; run the go/no-go spike first.
10. **quick-unlock** — inherits **F84** (the plan) + **F61** (KDF upgrade rides the periodic-password rule).
11. **SB-4 client debt & polish (F71 → F82 → F80)** — last; F82 must land before the next spec-07 change, F80 is cut-anytime cosmetics.

**Traceability check:** 45 in / 45 out — consumed: F13 F14 F15 F22 F26 F27 F29 F31 F53 (9); quick wins: F11 F12 F28 F50 F51 F52 F54 F55 F58 F59 F60 F64 F72 F74 F75 F76 F78 F79 F81 (19); fold-ins: F18 F20 F49 F56 F61 F77 F83 F84 (8); standalone: F09 F10 F57 F62 F63 F71 F80 F82 (8); won't-fix: F30 (1).