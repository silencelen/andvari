# andvari compliance review — 2026-07-15 (posture-vs-docs + OWASP ASVS L2)

> Method: 8 surface auditors checked shipped code against every stated guarantee (spec 00-07, threat-model T-rows, binding design-contract amendments) plus an OWASP ASVS L2 lens; each candidate finding passed an adversarial refuter (default-refuted if unconfirmed). 21 findings survived (1 refuted); 32 agents, 0 errors. Run wf_e40d1b3c-155.

## Executive summary

The zero-knowledge core holds: none of the verified findings breaks vault confidentiality, key custody, or the escrow crypto under the stated threat model, and nothing critical was found. That said, **20 unique findings survived adversarial verification** (21 raw; two reports of the Android enroll fingerprint race merged): **1 high, 4 medium, 12 low, 3 info** — and **16 are violations of guarantees the specs/designs/pentest-remediation record state**, several live in shipped/deployed code today: the web offline-cache persist-gate (WC-6) can silently drop online writes on the build deployed to CT122 on 07-15, extension 0.14.0 still ships the design-acknowledged [A7] CVV/PAN capture bug, the public break-glass origin serves over cleartext HTTP with no HSTS, and three 2026-07-13 pentest items (L10, L11, the M6 help-text half) were never remediated. Severities were sanity-checked against the ZK model (server already untrusted): the T1-hostile-server findings are correctly deflated to low already; the single high (CR-01) is an integrity/data-loss defect independent of server trust and is the only finding demanding an immediate fix. One severity was moved *up* during verification (CR-17: the live origin returns HTTP 200 over cleartext, not just a missing header), and one is flagged as borderline (CR-18: metadata-only leak, kept medium solely because the always-on public tunnel has no CF Access).

## Stated-guarantee violations

**CR-01 · HIGH — In-session cache wipe/forced close turns save()/remove() into silent success (offline-write black hole)**
- Guarantee: WC-6 / design `2026-07-13-web-offline-cache` §B.5 + §D.3 breaker #1 (persist-gated queued-success, "refuse-not-degrade"); WC-13 / §E.4+§E.3.2 (in-session wipe must leave the live session working). §D.2a's caught-no-op rule does **not** cover enqueue-before-send.
- Location: `web/src/vault/store.ts:1932` (enqueue-only send path); contributing: `web/src/vault/idbcache.ts:477/479/551`, `web/src/ui/session.ts:55-58`, `web/src/ui/App.tsx:82`
- Defect: Once the live IdbVaultCache connection is closed (Settings "offline copy" toggle-off / "remove now", org policy wipe at unlock, or browser-forced close), `durable` stays true, `enqueue()` no-ops, `flushQueue()` drains an empty queue, and save()/remove() return success while fully **online** — the mutation is neither pushed, queued, nor refused, and evaporates on reload (deletes resurrect). Window lasts ~3 sync cycles until the 3-strike demotion; deployed to CT122 07-15.
- Fix: Make `enqueue()` report whether the row landed (re-read mutationId in-tx, the setAccountKeys pattern) and fall back to the direct `flushChunk` path when it didn't; add a `demoteCache()` hook on VaultStore called from setOfflineCopyEnabled/wipeVaultCache/applyOrgOfflineCachePolicy and idbcache's onclose/versionchange.

**CR-02 · MEDIUM — Inactivity auto-lock never arms over the recovery-phrase reveal / capture-gate screens**
- Guarantee: KH-22 (all clients enforce autoLockSeconds) as the explicit TM-T4 bound ("unlocked-open device … bounded by auto-lock"); TM-R9 (recovery piece = UVK-equivalent).
- Location: `web/src/ui/App.tsx:261` (timer keyed to `phase.kind === "vault"`); exposed screens `web/src/ui/Welcome.tsx:150-171, 394-424, 876-928`, `web/src/ui/Recover.tsx`
- Defect: The auto-lock resolves to 0 in every non-vault phase, but the capture-gate and enroll-reveal screens render in "unlock"/"welcome" while holding a fully unlocked Account and displaying the raw recovery phrase (committed server-side *before* reveal) with no timeout — the one web surface showing a standing account-takeover credential sits entirely outside the bound spec 05 T4 claims exists.
- Fix: Arm the auto-lock (or a fixed ~5 min timeout) whenever a CaptureHandoff/reveal/secretRef is live; on expiry zero the secret, drop the held Account, land on unlock with a "timed out — fresh phrase next sign-in" notice (the capture gate re-fires safely by design).

**CR-03 · MEDIUM — [A7] CVV/PAN capture gate still absent in shipped extension 0.14.0**
- Guarantee: Cards design 2026-07-09/10 binding amendment [A7] ("card classification MUST gate the CAPTURE/SAVE path"), which itself names this a "confirmed latent bug"; detect.ts's own CVV-negative rationale.
- Location: `extension/src/detect.ts:282` (suppressSave), `:45` (CVV_TOKENS missing `securitycode`/`cardverification`); pin `web/src/extension-pins.test.ts:114`
- Defect: A checkout `password`-typed field named `securityCode` beside a card-number field is captured as a login: PAN can be saved as username, and with an empty captured username plus one saved merchant login, the pending-save resolves to an **update that overwrites the stored password with a CVV** (both paths need user confirmation on the banner; PAN+CVV sit plaintext in chrome.storage.session meanwhile).
- Fix: Ship the A7 slice ahead of/with S3: broaden `isCvvNameOrId` to core CSC_DEMOTION parity and exclude any form containing a detected card-number field from the capture/save path (suppressSave=true); add the [A7] fixture and deliberately update the pins test.

**CR-04 · LOW — PT-L11 unremediated: malformed bodies and bad HIBP prefixes return 500, not 400**
- Guarantee: PT-L11 (pentest 2026-07-13): "Map BadRequest/IllegalArgument→400 (not 500); validate the HIBP prefix" — absent from remediation commit dce4963 and ROADMAP's shipped list.
- Location: `server/src/main/kotlin/io/silencelen/andvari/server/App.kt:284-287` (StatusPages else→500), `server/.../Hibp.kt:19`
- Defect: StatusPages matches only the custom exceptions, so Ktor's BadRequestException (malformed JSON on ~25 receive routes, incl. unauthenticated /auth/*) and Hibp's IllegalArgumentException fall to the else branch → 500 + "unhandled" error-log spam. No body leak (ApiError("internal") only); wrong V7 semantics.
- Fix: Add branches for `io.ktor.server.plugins.BadRequestException`, `ContentTransformationException`, and `IllegalArgumentException` → 400 `ApiError("bad_request")`; validate the HIBP prefix in-route with the custom BadRequest.

**CR-05 · LOW — WS /events revocation re-check is check-then-register (TOCTOU); a socket registered just after a revoke survives teardown**
- Guarantee: PT-M8 / WP-11: revoked devices' live sockets closed and removed; handler "re-validates at (re)connect" (stated verbatim at Service.kt:582-591 and design 2026-07-13-ext-live-sync §224).
- Location: `server/src/main/kotlin/io/silencelen/andvari/server/App.kt:863-884` (check :872, register :876)
- Defect: `deviceHasLiveSession` and `notifier.register` are non-atomic; a socket passing the check pre-commit but registering after `notifyRevoked*`'s fan-out snapshot is never torn down and keeps receiving dirty-bell `{rev}` metadata until disconnect/restart (no vault data — /sync still rejects the revoked token). Untimeable by the attacker; microsecond window.
- Fix: Invert to register-first-then-recheck (unregister+close if revoked), or have `notifyRevoked*` set a per-device revoked marker that `register()` consults.

**CR-06 · LOW — Android enroll lacks the state-layer typed-fingerprint re-assert its desktop twin has (escrow can seal to a fingerprint the user never attested)** *(two independent reports merged — same root cause)*
- Guarantee: ER-2 / spec 04 §2(3) (typed short-form attestation binds the sealed pubkey; "never TOFU from server alone"); TM-T10. Desktop fixed exactly this class at `DesktopState.kt:705-717` ("4th sighting of the frame-stale class").
- Location: `app-android/src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt:914-961` (policy re-read :932, seal :959); UI-only gate `app-android/.../MainActivity.kt:531/646`
- Defect: The typed shortFp never reaches the ViewModel; enrollOp re-reads `_ui.value.policy` at submit time, so a policy refresh landing between the composition-time UI gate and the seal (setBaseUrl re-probe, Activity-recreation re-probe under a rememberSaveable-preserved form) seals org escrow to a server-swapped fingerprint the user never typed — a T10 escrow-redirect if a hostile server times the swap. Very low probability, same odds desktop rated LOW.
- Fix: Mirror desktop: pass `typedShortFp` (and posture) into `vm.enroll`, and inside enrollOp refuse RequiredTyped enrollment unless `Escrow.shortFormMatches(typedShortFp, policy.recoveryFingerprint)` holds against the **same** policy instance being sealed (Android's own resealEscrow already uses this in-op pattern).

**CR-07 · LOW — Silent KDF re-key (F61) never replaces the web durable cache's accountKeys**
- Guarantee: WC-13 / design §E.4 wipe-table ("password change → cached accountKeys REPLACED") + §D.2(c); F61 design §4 step 3 mandates the post-re-key persist; KH-16/TM-T8. Android and desktop both implement it; web alone omits it.
- Location: `web/src/ui/Welcome.tsx:360` (detached `maybeKdfUpgrade` after the :335 old-payload cache seed); `web/src/vault/kdfupgrade.ts:82-95`
- Defect: The upgrade commits changePassword server-side but never re-caches, so the at-rest cache keeps the pre-upgrade (cheaper-to-crack) wrappedUvk/params until the next online unlock — indefinitely on an offline-forever device — defeating T8's purpose for the window. No functional break, no H1 floor bypass.
- Fix: Call `refreshCachedAccountKeys(client, account.userId)` in maybeKdfUpgrade's success path (mirroring Settings.tsx:571). (Note: the finding's aside about desktop is wrong — desktop already refreshes; only web needs the fix.)

**CR-08 · LOW — HIBP breach-cache in localStorage survives sign-out/revocation and bypasses every offline-cache gate**
- Guarantee: VF-13/WC-2 (client-at-rest ⊆ spec 02 §5 server table — spec 02 §8) and WC-13 (§E.4 wipe table; App.signOut is the declared one wipe choke point).
- Location: `web/src/ui/Health.tsx:192` (`andvari:breach-cache:v1`, global key, ungated, no wipe path anywhere)
- Defect: A durable itemId→breach-count map derived from decrypted passwords persists past sign-out/revocation/opt-out/org-policy-off and lands on the public break-glass origin; residue leaks item count plus a password-popularity fingerprint (a 10M+ count marks a top-100 password), and the global key cross-contaminates accounts on shared browsers.
- Fix: Key per-account, gate writes on `webCacheEnabled()`, and remove the key at the App.signOut choke point + all wipe paths — or drop persistence and keep the map in memory for the session.

**CR-09 · LOW — `AccountKeys.escrowFingerprint` is never absent/null for waived members**
- Guarantee: spec 03 §2 (wire-protocol.md:36): "absent/null for a waived member (no org escrow)"; WP-3; reinforced by spec 04 §6.5. Per spec 00's own precedence rule, when code and spec disagree the code is wrong.
- Location: `core/src/commonMain/kotlin/io/silencelen/andvari/core/model/Wire.kt:82` (non-nullable, no default); `server/src/main/kotlin/io/silencelen/andvari/server/Service.kt:552-553` (unconditional populate)
- Defect: The DTO structurally cannot encode the spec-mandated state; every waived member receives the org recovery fingerprint on every login/key-fetch. No secret leaks (fingerprint is public) and no shipped client branches on null, but any client distinguishing waived by `escrowFingerprint == null` — as the spec invites — misclassifies every waived member.
- Fix: Either make the field nullable (`String? = null`, additive-safe) and send null when no escrow row exists, or amend spec 03 §2 to delete the sentence and document that waived posture is signaled by the absence of an escrow row.

**CR-10 · LOW — No compile-time MIN_SEQ floor in update-verify anti-rollback (fresh installs start at seq 0)**
- Guarantee: SU-4 / signed-updates design 2026-07-13 §M-D4(a): "bake a compile-time MIN_SEQ floor to shrink the fresh window" — D4(b) shipped, (a) skipped, never descoped.
- Location: `extension/src/background.ts:474-475`; same gap on desktop (`DesktopSession.kt:52`, `Platform.kt:148`); no MIN_SEQ exists anywhere in code.
- Defect: A T1 server replaying an old validly-signed manifest to a fresh install (or after cleared storage) trivially passes `seq <= 0` and can steer the nag banner toward an older-but-genuine known-vuln build, bounded only by the signedAt window (which itself fails open — CR-11). Nag-only channel; installer signing remains the primary control.
- Fix: `export const MIN_SEQ = <current published seq>` in updateverify.ts (bumped per release) and floor the evaluation with `Math.max(storedSeq ?? 0, MIN_SEQ)`; mirror in core UpdateVerify for desktop.

**CR-11 · LOW — Missing/non-string `signedAt` skips the staleness gate entirely (fail-open); desktop fails closed**
- Guarantee: SU-4 / design §M-D4(b) ("actually consume signedAt … make withholding detectable"); desktop reference fails closed (`Platform.kt:158-164`).
- Location: `extension/src/updateverify.ts:117-123`
- Defect: A validly-signed manifest omitting signedAt bypasses UPDATE_MAX_SIGNED_AGE_MS and returns `accepted` — an eternal-freshness token a T1 server can re-serve forever — and is internally inconsistent (unparseable *string* fails closed, absent value passes). Realistic ops outcome: the signer neither injects nor validates seq/signedAt despite the design §F saying it does. Latent today (H2 dormant, .sig unpublished).
- Fix: Treat missing/unparseable signedAt as stale (mirror desktop), and make update-signer refuse to sign a manifest lacking numeric seq + ISO signedAt.

**CR-12 · LOW — Fail-closed-quiet update state (UQUIET) is write-only; "couldn't verify" is operationally a silent skip**
- Guarantee: SU-3/SU-5 / design §D#2 + §M-D5 (distinct, quiet, non-modal "couldn't verify / stale" state — "never a silent skip"); desktop complies (`DesktopState.kt:213-216` → Ui.kt:2427).
- Location: `extension/src/background.ts:59` (written :468/:482, cleared :490 — zero readers; `Res<"updateStatus">` carries no quiet field)
- Defect: Sig-stripped, stale-replayed, or seq-regressed channels are visually identical to "up to date" on the extension — exactly the forbidden silent skip — and it also hides owner ops mistakes (a permanent quiet seq_regression would never surface). Fail-closed behavior itself is intact.
- Fix: Add `quietReason: string | null` to the updateStatus response read from UQUIET and render one muted popup-footer/settings line, mirroring desktop.

**CR-13 · LOW — PT-L10 unremediated: recovery-cli still echoes the org recovery seed on `recover` and `canary verify`**
- Guarantee: PT-L10 (pentest 2026-07-13): no-echo seed read via `System.console().readPassword()`; ER-1 custody posture. backup-cli got the treatment; recovery-cli — the more sensitive tool — did not (post-pentest commits touched only the URL guard and sheet).
- Location: `tools/recovery-cli/src/main/kotlin/io/silencelen/andvari/recovery/Main.kt:264` (echoing `prompt()`, used at :147 and :184)
- Defect: The base64url seed that can decrypt **every** escrowed UVK is echoed into terminal scrollback of the air-gapped box, exactly the L10 exposure.
- Fix: Add a `readSecret()` mirroring backup-cli's readPassphrase (console readPassword with char[] zeroing, stderr-prompted stdin fallback when piped) at both seed prompts.

**CR-14 · LOW — metaV keep-newer parse rule diverges between Kotlin and web (`2.0`/`2e3`/>2^63 read as 0 vs numeric)**
- Guarantee: The rule pinned verbatim in both impls ("must read identically on every client … or one impl pins while another applies, forking the fleet") — SyncEngine.kt:550-554 / store.ts:1360-1364; divergence verified by execution against the pinned kotlinx 1.7.3.
- Location: `core/.../client/SyncEngine.kt:559` + `core/.../client/Account.kt:547-548` (lexical `toLongOrNull`) vs `web/src/vault/store.ts:1365-1369` + `web/src/vault/account.ts:474-476` (`Number.isInteger` on the parsed value)
- Defect: A metaBlob with `metaV: 2.0` (seal requires a VK holder) reads 0 on Kotlin (replay APPLIES) but 2 on web (replay PINNED + warned), and a rename on top writes 1 vs 3 — the exact fleet-fork in the anti-replay path the rule forbids. Both test suites cover only encodings where the impls agree. No key/plaintext exposure; self-heals on a canonical integer write.
- Fix: Pin one interpretation in all four sites (simplest: make Kotlin match TS mathematically — integral Double, cap 2^53 — or make TS lexical via regex over raw plaintext) and add `2.0`, `2e3`, and a >2^63 literal to both metaV suites as pinned cases.

**CR-15 · INFO — spec 02 §5 ZK-contract table's `users` row omits the v8 plaintext column `users.escrowPolicy`**
- Guarantee: VF-7 / spec 02 §5 ("describes schema v8 EXACTLY … anything not listed appearing server-side in plaintext is a spec violation").
- Location: `server/.../Db.kt:401` vs `spec/02-vault-format.md:209` (disclosed only in the version-history footnote :230-232)
- Defect: A strict schema-vs-table diff — the section's own stated audit mechanism — flags the column. Contract-hygiene drift only: the value is a 2-literal posture flag already disclosed elsewhere; the sibling v8 columns *are* listed.
- Fix: Add `escrowPolicy` to the users row (keeping the footnote as history).

**CR-16 · INFO — PT-M6 residual: backup-cli help/warning text still enumerates only password/TOTP/fileKey**
- Guarantee: PT-M6 fix line explicitly ends "Fix the help text"; commit dce4963 touched only Inspect.kt.
- Location: `tools/backup-cli/src/main/kotlin/io/silencelen/andvari/backup/Main.kt:22-23, :50, :114` (Redact set at Inspect.kt:177 is correct)
- Defect: An operator can run `--secrets` believing card numbers, CVVs, and note bodies (where 2FA backup codes live) stay masked. Fail-safe direction otherwise (default path over-redacts relative to the text).
- Fix: Update all three strings to the full masked set, or derive them from `Redact.SECRET_KEYS` so they can't drift again.

## ASVS L2 gaps (not previously stated)

**CR-17 · MEDIUM — Public break-glass origin serves cleartext HTTP with no HSTS (live-verified; worse than the header gap)**
- Guarantee: ASVS 4.0 L2 V9.1/V14.4 (HSTS + no cleartext on every TLS origin); supports TM-T2.
- Location: `server/src/main/kotlin/io/silencelen/andvari/server/App.kt:316` (pentest-#22 intercept, no HSTS anywhere in repo) + Cloudflare zone config
- Defect: Verification found `http://andvari.monahanhosting.com/` returns **200 serving the full SPA over cleartext** (CF "Always Use HTTPS" off) and https carries no Strict-Transport-Security — on the one origin designed for hostile networks, an on-path attacker gets passive token capture or active JS injection at unlock, which defeats the ZK model client-side; TOTP does not mitigate injection. Severity was raised low→medium on this evidence.
- Fix: Enable CF "Always Use HTTPS" **and** zone HSTS (or append `Strict-Transport-Security: max-age=31536000; includeSubDomains` in the same App.kt intercept gated to `isPublicOrigin`, which alone is insufficient without the redirect); consider preload once stable.

**CR-18 · MEDIUM (borderline low) — /metrics "loopback-only" gate is defeated by proxy TLS-termination; reachable tailnet-wide and via the public tunnel**
- Guarantee: ASVS V7/V1 access control on an endpoint the code declares loopback-only; WP-16.
- Location: `server/.../App.kt:380` (gate) + `server/.../Auth.kt:45-46` (`peerIsLoopback` = raw TCP peer; no ForwardedHeaders plugin)
- Defect: Both front-ends (tailscale-serve, cloudflared) terminate TLS and connect from 127.0.0.1 — by the codebase's own documented design — so `peerIsLoopback()` is true for **every** proxied request; any tailnet device, and the public internet via the always-on no-CF-Access tunnel, can scrape route counts/latencies, JVM internals, and the vault/public-origin gauges. Honest ZK caveat: this is operational metadata only (no vault/credential exposure) and would be low if it were tailnet-only; the unauthenticated public reachability is what holds it at medium.
- Fix: Don't equate loopback peer with trusted scraper: separate loopback-only listener/port the front-ends never forward, or a shared-secret bearer for /metrics, or require the *absence* of forwarded headers; deny /metrics at both ingresses as defense-in-depth.

**CR-19 · LOW — update-signer keygen writes the Ed25519 signing key with umask-default perms before restricting, swallows chmod failure, and silently overwrites**
- Guarantee: ASVS L2 V14 restrictive-permission secret storage; the tool's own "0600 on POSIX" claim (Main.kt:19-20); same TOCTOU class the repo's own PT-L9 flagged (note: the PT-L9 atomic fix has not actually landed anywhere, including desktop session.json — a repeated defect class).
- Location: `tools/update-signer/src/main/kotlin/io/silencelen/andvari/updatesigner/Main.kt:54-58`
- Defect: `writeText` creates the H2 signing root world-readable, then setReadable/setWritable runs inside runCatching with boolean returns discarded (silently ineffective on Windows) while stderr still reports "(0600)"; an existing key at the default path is clobbered without warning. Mitigated by single-owner-workstation posture and the manifest channel being secondary.
- Fix: `Files.createFile` with OWNER_READ|OWNER_WRITE attrs before writing (explicit stderr warning on non-POSIX), refuse to overwrite, fail hard if perms can't be verified; apply the same pattern to desktop session.json while there.

**CR-20 · INFO — Account.enroll hard-codes DeviceInfo platform "android"; desktop enrollments create device/audit rows claiming the wrong platform**
- Guarantee: ASVS V7 audit accuracy + the code's own invariant at core Account.kt:220-222 (platform must match the wire tag).
- Location: `core/src/commonMain/kotlin/io/silencelen/andvari/core/client/Account.kt:302` (consumed at `app-desktop/.../DesktopState.kt:728-735`)
- Defect: Every desktop-*enrolled* device is permanently recorded as platform=android in the device table and AdminDeviceSummary, contradicting the X-Andvari-Client header the same session sends; the 426 gate keys on the header so only audit/inventory accuracy is affected (device *name* still reveals the true OS).
- Fix: Add `platform: String = "android"` to Account.enroll and have desktop pass `desktopPlatform()`.

## Fix priority

1. **CR-01** — web vault-store lane (`web/src/vault/store.ts` + `idbcache.ts` + `ui/session.ts`/`App.tsx`): verifiable enqueue + demoteCache hook. Deployed silent data loss in a password manager — fix first, redeploy CT122 with owner OK.
2. **CR-17** — ops/infra lane (Cloudflare zone toggle + optional `App.kt` header): minutes of work, closes a live cleartext path on the hostile-network origin.
3. **CR-18** — server lane (`App.kt`/`Auth.kt`) + ingress deny at cloudflared/tailscale-serve config.
4. **CR-03** — extension lane (`detect.ts` + extension-pins test): ship the A7 slice standalone, ahead of S3; needs a 0.14.1 store-publish to land.
5. **CR-02** — web UI lane (`App.tsx`/`useAutoLock.ts`/`Welcome.tsx`/`Recover.tsx`): arm auto-lock over live-secret screens.
6. **CR-04 + CR-05** — server lane, one batch (StatusPages branches; register-first WS re-check). Small, closes two pentest-adjacent residuals.
7. **CR-07 + CR-08** — web session lane, one batch (kdfupgrade re-cache one-liner; breach-cache keying/gating/wipe).
8. **CR-06** — Android lane (`AndvariViewModel.kt`/`MainActivity.kt`): mirror the desktop DesktopState.kt:713 re-assert; needs an APK release.
9. **CR-10 + CR-11 + CR-12** — update-channel lane, one batch (extension `updateverify.ts`/`background.ts`/popup + core/desktop MIN_SEQ mirror + signer seq/signedAt validation). Best landed together before the owner publishes `manifest.json.sig` and arms H2.
10. **CR-13 + CR-16 + CR-19** — tools lane, one batch (recovery-cli readPassword; backup-cli strings; update-signer atomic 0600 + overwrite guard).
11. **CR-09 + CR-15** — spec/wire alignment lane (nullable escrowFingerprint *or* spec 03 amendment — pick one side; add escrowPolicy to the spec 02 §5 users row). Doc-and-DTO work, coordinate with the next schema-touching change.
12. **CR-14** — core+web sync lane (pin metaV semantics identically in all 4 sites + add the divergent encodings to both test suites).
13. **CR-20** — core lane (enroll platform param, defaulted): trivial, ride along with any core release.
