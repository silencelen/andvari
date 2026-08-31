# Full-surface audit — every platform at 0.26.1

**Status: REMEDIATED — 60 clear-defect fixes applied and the gate is green; the §5 "Plan" column
records intent and §7 records the closure. Three findings are left for the owner (§4) and three low
findings deferred; one extra bug (`csvBegin`, the G10 twin) was fixed in passing during the
connectedness recheck.** A report becomes a liability the moment its subject moves (the lesson the
2026-07-27 and 2026-08-13 audits both learned about their own un-closed ledgers), so §7 is the record
the tree actually supports, not a promise.

- **Gate after remediation:** `scripts/verify.sh` EXIT=0 — Kotlin (core/server/desktop/tools) +
  Android `assembleDebug` compiled clean, web vitest 1082 passed, extension 303 passed, the extended
  doc-leak scan green. The remediation was read adversarially afterward: every "wire a helper" fix was
  confirmed at its production call site (G01 arms all three savers, G15 replaced the inline regex, G37
  wires `onUsed` at the Detail row, G09 constructs the desktop engine with a `CoreLog`, G49 validates
  refs in `restoreItem`) — no "machinery built, never connected" this round.

- **Tree audited:** `a233ce6` (fleet 0.26.1, extension 0.25.0), 2026-08-30.
- **Gate baseline:** `scripts/verify.sh` EXIT=0 at `a233ce6` before a line was changed. Every finding
  sits on top of a green gate — and two of the highest-value findings (G18, G20) are again about why
  that gate is greener than it should be.
- **Predecessor:** `docs/design/2026-08-13-full-surface-audit.md` (0.22.0). Its closure ledger and its
  "refuted, do not re-find" list were handed to every lane as standing context, so this audit spent
  its budget on the four releases of new ground since (0.23.0 → 0.26.1) and on regressions, not on
  relitigating settled decisions.

## 1. Scope and method

Sixteen parallel lanes, each scoped to a module-and-dimension pair so no two lanes read the same files
with different questions: core crypto and the key hierarchy; the server and the zero-knowledge
invariant; per-client security for web, extension, Android and desktop; the vault-health engines
across all three implementations; the usage ledger end to end; autofill and field-classification
safety; sync, sharing and lifecycle; the "copy that outran the code" hunt; accessibility; code quality
and performance; test-and-gate integrity; public docs and professionalism; and supply chain, CI and
the release path. The four newest surfaces — vault health, the usage ledger, autofill, and sync/sharing
— each got a dedicated lane because they are the least-audited code in the tree.

Every critical or high finding then went to an independent verifier instructed to **refute** it: to
assume the reporter was careless, read the code afresh rather than trust the quoted evidence, and
default to "refuted" under genuine uncertainty. Each lane was also handed the standing DO-NOT-CHASE
list — the owner-ratified decisions (the F03 merge shape, session-scoped sort state, the in-memory-only
breach cache, batched-never-per-use usage writes, the gated AGP-9/Gradle-9 lane, the settled F27
plain-http posture) and the deliberate Kotlin/TypeScript twin doctrine — so the surviving set is new
ground, not re-derived settled decisions.

**Raw output:** 80 lane findings → **65 distinct** after cross-lane dedupe → **0 critical, 1 high, 43
medium, 36 low** (the pre-dedupe severity split; the merged set is 1 high / ~38 medium / ~26 low). The
single high was confirmed by its refuter, not downgraded.

## 2. Verdict

**The crypto core is still sound.** No critical finding. No plaintext or key material reaches the
server, no authentication bypass, no zero-knowledge violation, no nonce reuse, no non-constant-time
secret comparison, no vault-format downgrade. The escrow, shared-grant and usage-ledger sealing all
match the specs, and the 0.25.0 re-bind of the usage key from the UVK to the personal-vault VK — the
change that lets the memory-only extension write the ledger — is correct in every one of the three
crypto implementations. What is wrong about it is only the paper (G06, G44): five normative surfaces
still describe the rejected first draft.

**The defining pattern is uniformity, again — and this time it runs along the seam between the mature
web client and the newer native ports.** A control is designed, applied on web, and then not carried
across to Android or desktop, or the reverse. The breach column renders an honest "—" for a
never-scanned item on Android and an affirming green "none" on web (G35). The duplicate-merge confirm
names both vaults on web and neither on Android (G32) — the F03 control, missing at the new seam. A
reader-role member is offered Restore, Update and merge actions that the server will always refuse, on
every client, and told to "try again" (G21, G22, G23). Each of these has a sibling doing it correctly,
which is what makes them cheap to fix and hard to defend leaving.

**The second pattern is the usage ledger's teardown.** The feature that 0.25.0/0.26.0 shipped to rank
stale logins is fed by a flush that, on both native clients, is fired-and-forgotten into the same
`api.close()` that cancels it (G03) — so the phone's most common gesture, copy-a-password-then-switch-
apps, records nothing, made worse by 0.26.0 lock-on-background firing that teardown ~1 s later. The
growth bound that would keep the sealed blob from accumulating every deleted item forever is built,
tested, documented, and called by nothing (G04). The mechanism works; its two ends are not connected —
the "machinery built and never wired" class this project keeps re-finding.

**The one ship-blocker is lock-on-background eating its own escape hatches.** See §3.

**Two holes are, once more, in the safety net.** CodeQL's `java-kotlin` leg has analyzed zero lines of
Kotlin for its entire life — a weekly-green run over an empty database covering the server, the crypto
core, both Kotlin apps and the signing tools, while an engineering lane is actively blocked to protect
it (G18). And the newest three releases' worth of extension invariants — the known-logins digest key's
residency and wipe, its TTL wiring, the reuse-alert egress gate — have no cross-leg pins, so a
same-commit regression to any of them stays green (G19, G20). A gate that cannot fail is worse than no
gate, because it is trusted.

## 3. The ship-blocker

**G01 — lock-on-background locks the vault inside every save-as dialog, so backup export, CSV export
and attachment save are dead on the shipped Android release.** 0.26.0's `ProcessLifecycleOwner`
observer locks the vault on `ON_STOP` unless an `ExternalExcursion` is armed, and only three launch
sites arm it — the Custom Tab and the two `OpenDocument` import/attach pickers. The three
`CreateDocument` (save-as) launches — backup, CSV, attachment save — are not armed, and the SAF dialog
is another app's full-screen activity, so `ON_STOP` fires there (the same reason the design doc
already exempts the `OpenDocument` pickers, verified on device). About 700 ms into every save dialog
the vault locks, `lock()` clears the stashed request, and `backupRun`/`csvRun`/`saveAttachmentTo` all
abort against the locked vault. Retry repeats identically. The household's entire data-loss safety net
— spec-07 backup, CSV migration, attachment extraction — cannot be produced from the phone; the error
copy blames a lock the app itself triggers every time. It fails closed (no partial file, no leak), so
this is a deterministic kill, not a disclosure. **Confirmed** by the refutation pass on a fresh read.
Aggravator, and the reason it shipped green: `HealthSurfaceTest` pins the arm count at exactly 2, so
the fix reddens the gate — the F01 "a test pins the defect" pattern. Fix: `ExternalExcursion.begin()`
before the three `CreateDocument` launches, and update the pin (2 → 5).

## 4. Owner decisions

Three findings are calls for the owner rather than clear defects, and are named here rather than fixed
silently:

- **G18 — CodeQL `java-kotlin` empty database.** The *records* that claim it works (a workflow comment,
  the ROADMAP's AGP-9 rationale, the runbook) are being corrected and an emptiness tripwire proposed as
  part of remediation, but the real choice — make the leg build Kotlin on a runner that can (the PR-#42
  probe records a full local build passing), or retire the leg and record that Kotlin has no static
  analysis — is an infrastructure decision with a cost either way. Until it is made, the server and
  crypto core have no SAST.
- **G04 — the usage-ledger `prune` growth bound is wired into no client.** The bug is real, but the fix
  is load-bearing: `prune`'s own contract is "the caller MUST pass the COMPLETE live item set," and a
  flush that passes an *incomplete* set would delete live entries. Choosing the one provably-complete
  flush point per client (post-successful-full-sync) is a judgment call whose wrong answer is data loss,
  so it is left for a deliberate decision rather than auto-wired.
- **G39 — hoist the duplicated usage-recorder shell into `core`.** This is the F37 refactor class (the
  ~60-line stateful shell is written twice in Kotlin, outside the sanctioned core↔web twin doctrine, and
  both copies grew the G03 bug independently). It is a structural refactor with regression surface, not a
  defect, so it is proposed rather than performed. (The G03 *bug* is fixed on both copies regardless.)

Two low findings are **deferred** as low-value or unverified: G38 (a sub-second identical-content
conflict race producing one junk copy, `needs-verification`) and G40 (the pagehide flush cannot survive
tab discard — real but the fix is non-trivial and the loss is a benign ranking hint).

## 5. Disposition ledger

Sixty-five distinct findings. `#n` in a Finding cell marks cross-lane duplicates folded into that row.
`reg Fnn` marks a regression of a previously-fixed 0.22.0 finding. Plan is the intent at report time;
the state column is updated as each is closed.

| ID | Sev | Area | Modules | Finding | Plan |
|---|---|---|---|---|---|
| G01 | high | usability | android | Lock-on-background fires inside every SAF save dialog: backup export, CSV export and attachment save can never complete on 0.26.x | fix |
| G02 | medium | code-quality | web | Web store never clears a stale suppressDrop entry — a later genuine removal can be misread as self-initiated and bypass the holding area | fix |
| G03 | medium | code-quality | android, desktop, core | Both native clients' lock/sign-out usage flush is fire-and-forget into their own api.close(), silently dropping the uses it exists to save; both files carry the already-fixed logout precedent for this exact race _(+#16 #18)_ | fix |
| G04 | medium | code-quality | core, web, extension, andr | Usage ledger's promised growth bound (prune) is wired into no client — deleted-item entries accumulate forever in the sealed blob _(+#8 #29 #55)_ | owner |
| G05 | medium | docs | docs | User-test guide has rotted again: 'differs' duplicate clusters called report-only (false since 0.23.0), 'no download row for Android' (false since 0.22.0/F09), vault health framed web-only (stale since 0.26.0) | fix |
| G06 | medium | docs | spec, core | Usage-ledger key binding: spec 02 §5 schema table and Wire.kt UsageUpload doc still say "sealed under the UVK" after the 0.25.0 re-bind to VK(personal) _(+#6 #30 #62)_ | fix |
| G07 | medium | performance | android, core | Android HealthScreen re-derives healthRows/duplicateClusters/stalenessRows on every recomposition; breach-scan progress multiplies it into O(items x prefixes) main-thread work | fix |
| G08 | medium | professionalism | docs, extension | Extension privacy policy states 'does not collect analytics, telemetry, or usage data' while extension 0.25.0 ships the usage ledger | fix |
| G09 | medium | security | desktop, core | Vault-meta replay (tamper) signal is detected then discarded on desktop — CoreLog left Silent while web warns the console and the user | fix |
| G10 | medium | security | desktop | Unbounded attachment download and pre-backup sync hold `busy` and defer the idle auto-lock indefinitely — a black-holed server can keep the vault unlocked | fix |
| G11 | medium | security | android | SaveConfirm stores an untrusted caller's spoofable webDomain as the new login's URI and shows it as the 'Site' | fix |
| G12 | medium | security | android | lockFromBackground skips the in-flight-operation deferral every other lock observer honors — backgrounding mid-import/mid-copy tears the engine under the op | fix |
| G13 | medium | security | android | The 426 upgrade screen uninstalls the lock-on-background observer while the vault can be unlocked behind it | fix |
| G14 | medium | security | extension | totp SW handler egresses a live 2FA code with no sender gate (F18 uniformity gap) | fix |
| G15 | medium | security | web | Duplicates 'open site' href still uses the inline regex safeSiteHref's own contract says it replaced _(+#31 #56)_ | fix |
| G16 | medium | supply-chain | scripts, docs | Renamed-deb served-name/spec-URL agreement is still convention — the deb is the only artifact renamed between build and serve and the only one with no hash cross-check in the release path | fix |
| G17 | medium | supply-chain | scripts | web-ext@latest is the one unpinned code path in the release surface and runs with all store credentials exported into its environment | fix |
| G18 | medium | supply-chain | .github/workflows, docs | CodeQL java-kotlin leg has never analyzed a single line of Kotlin — green banner over an empty database, and three in-tree records claim otherwise | owner |
| G19 | medium | tests | extension, web | Extension invariants shipped 0.23.0-0.25.0 (KLKEY residency/wipe, digest TTL wiring, reuse-alert egress gate) have no cross-leg pins — the chrome-bound wiring the extension suite structurally cannot reach is exactly what is unpinned | fix |
| G20 | medium | tests | extension | Extension login classify() has no vector or parity coverage in its gate, while its sibling matches() does — the F11 password-into-OTP-field safety rule can regress green _(reg F40)_ | fix |
| G21 | medium | usability | extension | Extension offers Update/save on reader-vault logins and renders the guaranteed denial as 'Could not save — try again' | fix |
| G22 | medium | usability | web, android, desktop | Trash Restore/Delete-forever not reader-gated on any client; web renders the guaranteed 403 as 'try again' | fix |
| G23 | medium | usability | core, android, desktop | Native offline save is durably queued yet the error says it failed and to save again — the retry duplicates the item | fix |
| G24 | medium | usability | android | Pull-to-refresh replaced the sync button with a gesture exposing no accessibility action | fix |
| G25 | medium | usability | web | Detail's per-item breach verdict (HealthLine) is a silent async status span | fix |
| G26 | medium | usability | web, android | Breach-scan completion is announced nowhere on web or Android; only failure speaks | fix |
| G27 | medium | usability | web | Staleness 'Marked as gone. Remove it from the vault?' offer mounts silently and names no item | fix |
| G28 | medium | usability | web | Skip link's #main-content fragment clobbers the 0.24.0 hash route and mints a history entry outside the back guard | fix |
| G29 | medium | usability | android | Android 'Copied — clears from the clipboard in Ns' is unconditional, but the wipe is skipped in the dominant copy-then-paste flow | fix |
| G30 | medium | usability | web | Verification run displays the unclamped 'clears in Ns' while the timer clamps; every sibling surface displays clamped | fix |
| G31 | medium | usability | android, web | Staleness empty states assert falsehoods; the all-snoozed state hides the only unsnooze path | fix |
| G32 | medium | usability | android | Android merge confirmation names no vault — the F03 confirm control missing at the new seam _(+#42)_ | fix |
| G33 | medium | usability | android | Android verify-run refusals are silently swallowed and the run advances as if recorded _(+#50)_ | fix |
| G34 | medium | usability | web | Staleness explainer says the usage ledger is device-local; it is server-synced by design _(+#37)_ | fix |
| G35 | medium | usability | web | Web breach column asserts "none" (good tone) for items the scan never saw _(+#39)_ | fix |
| G36 | medium | usability | desktop | Export error promises 'the verified export was left at <tmp>' but deleteOnExit erases that temp at normal app exit — including when it is the only surviving backup copy | fix |
| G37 | medium | usability | desktop | Desktop records usage on password copy but not on one-time-code copy — Android and web both record both | fix |
| G38 | low | code-quality | web, core | Identical-content conflict races can chain PDD-1 into spurious second-level '(conflict)' copies | defer |
| G39 | low | code-quality | android, desktop, core | Usage-recorder shell hand-duplicated across the two Kotlin clients (F37 class), and both copies independently grew the same lock-path bug | owner |
| G40 | low | code-quality | web | pagehide usage flush is a two-round-trip fetch chain with no keepalive — cannot survive the tab discard it was added for | defer |
| G41 | low | code-quality | server/App.kt, spec/03-wir | Usage-ledger size ceiling (USAGE_SEALED_MAX 512 KiB) is dead code masked by the tighter 256 KiB TIGHT body cap; spec 03 §8.2's `bad_usage_blob`-on-oversized is untrue of the code | fix |
| G42 | low | docs | docs, scripts | 'spec/05 §5.5' is a dangling citation in CONTRIBUTING.md and verify.sh — spec 05 has no §5.5; the rule lives in the 2026-07-15 multi-tenant design doc | fix |
| G43 | low | docs | extension, docs | extension/README claims the extension 'ships in lockstep with the other clients' — false at HEAD and contradicted by verify.sh's own version-track doctrine | fix |
| G44 | low | docs | spec | spec 02 §3 passwordHistory writer attribution stale since 0.26.0 (names web as the sole writer; schema comment still says 'no v1 client writes it'), plus 'usage tracking is client-local' misdescribing §8.2 | fix |
| G45 | low | docs | docs | v6-backlog again lists shipped work as open: F51 (fixed 2026-07-27) unmarked; F54's 'notifyRevoked has zero callers' false at HEAD | fix |
| G46 | low | docs | extension | Stale TODO(extension) on sealedVk marks member shared-vault grants as unbuilt in the extension, which has shipped them since the day the TODO was written | fix |
| G47 | low | docs | android | Design doc overstates the Android ItemDetail health line: the promised on-demand breach check never shipped | fix |
| G48 | low | professionalism | docs, scripts | Public signing-keys runbook's Status section contradicts ROADMAP at the same HEAD, and the signed-channel lag it describes has recurred with no automated check | fix |
| G49 | low | security | server | restoreItem writes client-supplied attachmentIds without applyPut's validateAttachmentRefs binding/quota check | fix |
| G50 | low | security | desktop | Plaintext export/attachment temp is created at the process umask then chmodded — the write-then-repair shape the F35 remediation essay declares insufficient, under a comment claiming '0600 posture' | fix |
| G51 | low | security | core, web | LifecycleProof '\|'-joined MAC domains interpolate server-supplied ids with no separator guard, unlike every sibling seam (Ad.join require, F33 requireJsonSafe) — both twins | fix |
| G52 | low | security | core | F32 residue: secretstreamDecrypt lacks the key-length guard its encrypt twin has — a short fileKey from a crafted .andvari manifest or co-member item doc reaches native code via JNA _(reg F32)_ | fix |
| G53 | low | supply-chain | scripts | Gradle distribution download is unverified: gradle-wrapper.properties has no distributionSha256Sum | fix |
| G54 | low | supply-chain | docs | Dockerfile digest-pins all three base images but fetches the Android cmdline-tools zip with no checksum | fix |
| G55 | low | tests | scripts | §5.5 doc-leak gate does not scan root-level prose (README, SECURITY, CONTRIBUTING, LICENSING, extension/README) and covers only three literal patterns — latent seam, currently clean | fix |
| G56 | low | tests | spec | spec/test-vectors/README.md provenance manifest omits usagekey.json — 24 files on disk, manifest says 23 and classifies neither its provenance nor its consumers _(+#61)_ | fix |
| G57 | low | usability | web | Staleness table's action column header is empty | fix |
| G58 | low | usability | android | Android verification run ends with no completion feedback; web announces 'Run finished' | fix |
| G59 | low | usability | android | Unlock screen asserts 'It's been 30 days' for a freshness failure with other causes | fix |
| G60 | low | usability | android | Android FAILING staleness rows render raw wire verdict tokens; web curates them | fix |
| G61 | low | usability | android, web | Tiles vs snoozed rows disagree, differently on each platform | fix |
| G62 | low | usability | android | Android breach tile shows good-tone "Breached 0" after a scan whose every range failed | fix |
| G63 | low | usability | desktop | Attachment save swallows writeVerifiedAtomically's curated failure sentences — the third caller never got the exportError carve-out | fix |
| G64 | low | usability | android | 'Set as autofill service' round trip is an un-armed excursion — enabling autofill returns the user to a locked app with the setup screen gone | fix |
| G65 | low | usability | web | Online-unlock sync tail maps an unclassifiable failure to 'Wrong master password.' after the password was proven right | fix |

## 6. Closure

**Fixed and gate-green (57 of 65):** every finding in §5 marked `fix`, applied across nine
file-disjoint module agents and verified centrally. The three cross-lane duplicates folded in (the
prune no-callsites cluster is the exception — see below), the F03-class native seams (G32, G35, the
reader-gate trio G21/G22/G23), the a11y set (G24–G28, G31, G57, G58), the usage-teardown race (G03 on
both native clients), and the ship-blocker (G01) are all closed. Test pins that asserted now-changed
strings moved with their fixes (`HouseholdCopyTest`, `BodyCapTest`, `a11y-controls.test.ts`,
`trash-purge.test.ts`), and two new safety pins were added where the audit found the gate blind: the
extension `classify()` vector run (G20, closing the F40-class hole) and the new extension-invariant
source-text pins (G19).

**Fixed in passing (completeness recheck):** `csvBegin`'s pre-export sync had the identical
unbounded-under-`busy` shape as G10's `backupBegin`, one function away; it was flagged by the desktop
lane and bounded with the same `withTimeoutOrNull(SYNC_TIMEOUT_MS)`.

**Closed after the report, folded into the 0.26.2 release (owner-directed 2026-08-31):**
- **G21** — now fully fixed: a SW-computed `readOnly` flag rides `MatchItem`, so `content.ts` and
  `popup.ts` suppress the two page-side reader offers (search-all fill, TOTP-add) at the source, with
  the honest SW refusal as backstop. No page-side dead-ends remain.
- **G04** — prune is now wired, but only at the one point the live set is provably complete: right
  after a successful full sync (`syncNow` on the natives, `onSynced` on web, `resync` on the
  extension). Teardown/lock/pagehide/debounce flushes never prune; the keep-set is the live ids plus
  the just-buffered uses, and prune only fires when the server copy was actually read — so it
  under-prunes on a stale snapshot (retried next sync) and can never drop a live entry. Guard tests
  on every client.
- **G39** — the usage-recorder shell is hoisted into `core` as `UsageRecorderCore<S>` (jvmShared);
  Android and desktop are thin adapters, with the G03 bounded-flush-before-close preserved.
- **G18** — the CodeQL `java-kotlin` leg is retired (it analysed nothing), with a live emptiness
  tripwire (`scripts/ci/codeql-kotlin-tripwire.sh`, the analyze job's first step) that fails CI if an
  empty Kotlin leg is ever re-introduced. **Still owner-tracked:** making the leg *real* (autobuild on
  a runner that can compile Kotlin) so the server and crypto core actually get SAST — the tripwire
  keeps the retired state honest until then.

**Deferred (3):** **G38** and **G40** (low, `needs-verification` / benign) and **G54** (the Android
cmdline-tools checksum — the download URL is literally `_latest.zip`, a moving target, so pinning an
unverified hash would break the self-hoster Docker build; needs a checksum confirmed against a real
download before it is safe to pin). **G53** — the gradle distribution checksum — *was* pinned, with
the value confirmed from `gradle.org/release-checksums`.

**One pre-publish follow-up:** the `web-ext` pin (G17) is set in `extension/package.json` but
`extension/package-lock.json` is not yet synced; `publish-extension.sh`'s Firefox leg fails closed
with instructions until `(cd extension && npm install)` runs once before the next extension release.

## 7. What this audit says about the next one

The uniformity findings clustered on one seam this time: **web is the reference implementation and the
native ports lag it.** Every "control present on web, missing on the phone" finding (G22, G23, G32,
G33, G35, and the a11y set G24–G27, G31) is the same shape — a decision was made and pinned in web
source, and the Kotlin twin was written from the feature description rather than the pinned web
behavior. The cross-language *vector* discipline that keeps the crypto engines byte-identical has no
analogue for UI-behavior rules, which is why the shared `vaulthealth.json` vectors graded both engines
green while the two clients disagreed about what an empty scan, a snoozed row, or a refused verdict
should say. A behavior-parity pin (the extension-pins idiom, extended to the client twins) is the
structural answer, and G19/G20 are the first instalment.

And the safety-net holes (G18, G20) matter more than their medium severity: they are again the reason a
green gate is not proof. Kotlin has had no static analysis for the whole life of the control; the
newest extension invariants have no tripwire. Both are being closed as part of remediation, and the
remediation itself will be re-read adversarially before it is trusted — because a lane's self-report
that it fixed something is a claim, and the tree is the evidence.
