# Full-surface audit — every platform at 0.21.0, remediated into 0.22.0

**Status: CLOSED — every finding is shipped, deliberately deferred, or refuted. The closure ledger is
in this file (§5), not in a future session's memory.** The 2026-07-27 audit learned this the hard way:
its own `hygiene-docs--7` was "compliance review published with no closure ledger", and that document
then acquired exactly that defect. A report becomes a liability the moment its subject moves.

- **Tree audited:** `c8a0b78` (fleet 0.21.0, extension 0.21.0), 2026-08-13.
- **Gate baseline:** `scripts/verify.sh` EXIT=0 at `c8a0b78` before a line was changed, and EXIT=0
  again after remediation. Every finding here sits *on top of* a green gate — two of them are about
  why that gate was greener than it should have been.
- **Shipped as:** 0.22.0 / extension 0.22.0.

## 1. Scope and method

Twelve parallel lanes, each scoped to a module-and-dimension pair rather than a topic, so that no two
lanes were reading the same files with different questions: core crypto and key hierarchy; server and
the zero-knowledge invariant; web client security; browser-extension security; Android and desktop
client security; autofill correctness and field-classification safety; usability, flows and failure
copy; accessibility; code quality and optimization; test and gate integrity; public-facing docs and
professionalism; supply chain, CI and release hygiene.

Every critical or high finding then went to an independent agent instructed to **refute** it — to
assume the reporter was careless, read the code afresh, and default to "refuted" under genuine
uncertainty. That pass killed four findings outright (§5) and corrected the mechanism or severity of
several more. The surviving set was deduplicated across lanes, ranked by real-world risk to a
household, and partitioned into file-disjoint remediation waves.

**Raw output:** 81 lane findings → 43 distinct findings after dedupe and refutation → 0 critical,
3 high, 24 medium, 16 low.

Every lane was told the standing DO-NOT-CHASE list from the 2026-07-27 audit (the deliberate
Kotlin/TypeScript twins, the house pattern that extension invariants are pinned from
`web/src/extension-pins.test.ts`, the deliberate `MIN_SEQ` asymmetry, the G1 PSP-iframe
do-not-build), so this audit spent its budget on new ground rather than relitigating settled
decisions.

## 2. Verdict

**The crypto core is sound.** No critical finding, and specifically: no plaintext or key material
reaches the server, no authentication bypass, no zero-knowledge violation, no nonce reuse, no
non-constant-time comparison of a secret, no downgrade path in the vault format. The key hierarchy,
AEAD usage, sealed-box escrow and the shared test vectors match spec 01/02/04 byte for byte, and the
cross-implementation vector discipline is stronger than most commercial products attempt.

**The weakness was uniformity, not design.** The defining pattern of this audit: a control is
designed, documented in a comment or a spec, and then not applied at one seam. Sender-origin binding
on four extension handlers and absent on three. The escrow-polarity gate enforced at register and not
at `PUT /escrow/self`. Rate buckets on six anonymous routes but not on register or refresh. Length
preconditions on encrypt but not decrypt. HIBP shipped in the codebase but never pointed at the master
password. `writeClipboard` guarding copies but not wipes. Each of these had a sibling in the same file
doing it correctly — which is what made them cheap to fix and indefensible to leave.

**The second pattern was copy that outran the code.** Four separate surfaces told the user something
untrue: "clears in 30s" when the wipe had failed, "restoring brings an item back" when attachments
were gone forever, "try again" for refusals that could never succeed, and a strength meter that could
show an affirming tick beside a warning. For a password manager this is the worst failure class,
because the user's first hypothesis is always "I forgot my password" or "my vault is corrupt".

**Two holes were in the safety net itself.** Two Gradle modules holding sixteen security-relevant
tests were neither compiled nor run by the gate, and the extension leg reported success when it
collected zero tests. A gate that cannot fail is worse than no gate, because it is trusted.

## 3. The three ship-blockers

**F01 — a web page could hold the extension's vault unlocked indefinitely.** A hidden form calling
`requestSubmit()` on a timer produced a submit event indistinguishable, to the content script, from a
real sign-in; each one re-armed the idle alarm. Decrypted items, unwrapped vault keys and live tokens
stayed resident with nothing on screen and nothing logged. It defeated the very control the code
hardens against a hostile *server* (the client clamps `autoLockSeconds` so a server cannot switch the
idle lock off). Aggravating factor: a test pinned the defect in place, classifying the credential
capture as passive activity. Fixed by requiring a real trusted gesture before a submit can count, and
the pin was flipped to assert the gate.

**F02 — no anti-automation on any server TOTP route.** Unlimited attempts, no failure audit. An
attacker holding a stolen session could brute-force or, worse, *rotate* the second factor to one they
control — the exact threat the rotation gate was added for. Fixed with per-user buckets, an audit row
on every failure, and a shared budget across the routes that verify the live secret so the limit
cannot be sidestepped by alternating between them.

**F03 — duplicate-merge deleted across vault boundaries.** Clusters spanned vaults with no vault named
anywhere on screen, and the survivor was chosen by recency, so one click could remove a shared
household login for every member. The product's own "Copy to vault" button manufactures exactly those
clusters. Fixed per the owner's decision: cross-vault clusters stay visible but refuse to merge with a
stated reason, every row carries its vault, the confirmation names both vaults, and reader-role copies
are excluded from deletion.

## 4. Owner decisions taken during remediation

Six findings were product calls rather than defects, and were decided explicitly rather than silently:

- **F03 shape** — report-only cross-vault clustering (keep them visible, refuse the merge), over
  scoping clusters per vault, which would have hidden cross-vault duplicates entirely.
- **F31 password floor** — warn, never block, **plus** a k-anonymised breach check on the master
  password and backup passphrase. Only a five-character hash prefix leaves the device, the check fails
  open and silent on any error, and nothing gates submission on the verdict.
- **F30 stale guide** — rewrite `docs/user-test-guide-0.6.0.md` to the current endpoint-agnostic
  topology, over deleting it or freezing it behind a banner.
- **F27 Android plain-http** — verify on real hardware first. The safe half shipped (honest error copy,
  session-drop-before-probe); the posture question of whether to accept such addresses at all is open,
  and the test pin that currently declares them supported was deliberately left untouched.
- **F29(d) password history** — demote from the normative spec. It is unimplemented, so the spec was
  overstating the product.
- **F43 apostrophe normalization** — declined. Rewriting hundreds of shipped user-facing strings and
  every byte-exact pin protecting them, for zero functional benefit, is not a release-time change.

## 5. Closure ledger

41 of 43 findings shipped in 0.22.0. One is partial by owner decision (F27), one deferred by owner
decision (F43). Four lane findings were refuted before reaching this list and are recorded below so a
future review does not re-find them.

| ID | Sev | Area | Modules | Finding | Disposition |
|---|---|---|---|---|---|
| F01 | high | security | extension | Any web page can defer the extension's idle auto-lock forever via gesture-less requestSubmit() | fixed |
| F02 | high | security | server | No anti-automation on any server-TOTP route — the second factor is brute-forceable off a hijacked session, and failures leave no audit row | fixed |
| F03 | high | usability | web | Duplicate-merge clusters and deletes across vault boundaries with no vault named anywhere on the screen — one click can remove a shared household login for everyone | fixed |
| F04 | medium | usability | web,app-android,app-deskto | Trash restore permanently discards attachments and no surface on any client says so, before or after | fixed |
| F05 | medium | security | web | Clipboard auto-clear is unreliable and every copy surface over-promises it: the wipe is swallowed when unfocused, per-mount timers orphan and blank a later copy, and Admin's invite copy bypasses the guarded write entirely | fixed |
| F06 | medium | usability | web,docs | Web vault cannot complete enrollment or sign-in on the documented plain-http self-host, and reports it as a generic "Sign-in failed" | fixed |
| F07 | medium | usability | web | Web sign-out is a one-click unconfirmed wipe of the offline copy; both native clients gate the identical action behind a confirm | fixed |
| F08 | medium | security | web,core,spec | CSV export ships no formula-injection warning although both spec 07 and the writer's own contract say "warn instead" | fixed |
| F09 | medium | usability | web | "Get andvari on your other devices" omits Android entirely while every other platform gets an honest "not published yet" row | fixed |
| F10 | medium | usability | web | Web a11y: unassociated <label> on the two un-skippable recovery gates and the Admin invite output | fixed |
| F11 | medium | usability | web | The entire unlocked web app has no <main> landmark, no <h1>, and no skip link | fixed |
| F12 | medium | usability | web | Async success confirmations in Health, Recover and Sharing are silent to screen readers — the Announcer idiom is applied everywhere else and omitted here | fixed |
| F13 | medium | performance | web | The 144 KiB PSL blob now ships inside the web app's highest-churn entry chunk, and vite.config.ts's chunking rationale is factually wrong | fixed |
| F18 | medium | security | extension | Extension service-worker handlers that mint a fill grant, write to the vault, or release a password are not bound to the caller (fillFromPopup, linkUri, reveal) | fixed |
| F19 | medium | security | server | PUT /escrow/self sits outside the escrow-polarity gate, letting a waived account plant a fake admin backstop | fixed |
| F20 | medium | security | server | Failed logins against unknown or disabled accounts write no audit row, so credential stuffing is invisible to intrusion review | fixed |
| F21 | medium | performance | server | WebSocket dirty-bell fan-out is awaited on the push request path with no per-socket timeout — one member's wedged socket stalls co-members' saves for up to 60 s | fixed |
| F25 | medium | security | app-android,app-desktop,we | Account TOTP enrollment secret is copied through the "non-secret setup material" path — no auto-clear, and on Android no EXTRA_IS_SENSITIVE | fixed |
| F26 | medium | usability | app-android,app-desktop,we | Enrollment refusals render useless or false advice: Android maps no enroll code at all, and `escrow_required` has no curated sentence on any client | fixed |
| F27 | medium | usability | app-android | Android accepts and trust-gates plain-http self-host addresses its own network security config structurally forbids — the switch commits, drops the session, then fails with a misleading "can't reach the server" | partial (owner-gated) |
| F28 | medium | code-quality | app-desktop | Desktop attachment picker reads the whole chosen file into memory on the UI thread before the size check, and leaks the raw exception message to the user | fixed |
| F29 | medium | docs | spec,server,core | The NORMATIVE specs contradict the tree in four places, including one that would reintroduce a rate-limit bypass if a contributor "restored parity" | fixed |
| F30 | medium | professionalism | docs | A checked-in user guide in the public repo says andvari is Tailscale-only, hardcodes the reference instance's private hostnames, and documents version 0.6.0 | fixed |
| F31 | medium | security | core,web,app-android | Master-password and backup-passphrase floors are a length x class proxy with no repetition or breach check, and the shipped HIBP checker is never applied to either secret | fixed |
| F39 | medium | tests | scripts,docs | Two Gradle modules holding 16 security-critical tests are neither run nor compiled by the gate — including the release-signing key's 0600/no-clobber tests and backup extraction's path-traversal sanitizer | fixed |
| F40 | medium | tests | scripts,extension | The extension leg of the gate reports success when it collects zero tests — node --test exits 0 on a no-match glob | fixed |
| F41 | medium | docs | scripts,docs | The CHANGELOG gate only holds for the fleet version, not the independently-tracked extension version — and the public CHANGELOG heading is wrong at HEAD as a result | fixed |
| F14 | low | security | web | Devices card renders server-declared manifest URLs as raw hrefs, bypassing the client's own untrusted-URL rule | fixed |
| F15 | low | code-quality | web | Recovery-pubkey fetch is duplicated as a hand-rolled fetch that bypasses ApiClient's headers and 426 handling | fixed |
| F16 | low | usability | web | The fixed 72px vault row clips the item's only subtitle once a browser minimum font size is set | fixed |
| F17 | low | supply-chain | web | web declares @noble/curves as a devDependency with zero references anywhere in the repository | fixed |
| F22 | low | security | server | /auth/register and /auth/refresh are the only unauthenticated POST routes with no rate bucket | fixed |
| F23 | low | code-quality | server,web | devices.clientVersion is never written — the Admin device list's Client column is permanently empty | fixed |
| F24 | low | professionalism | extension | One user-facing sentence capitalizes the brand as "Andvari" — and it is byte-pinned that way — against 500+ lowercase uses | fixed |
| F32 | low | security | core | Key/nonce length preconditions are enforced on encrypt but omitted on decrypt and the sealed-box path, so a wrong-length key reaches libsodium through JNA | fixed |
| F33 | low | security | core | Escrow and shared-grant canonical JSON payloads are built by unescaped string interpolation of server-supplied identifiers | fixed |
| F34 | low | security | core,web | Backup container parser has no bound on section count — a crafted .andvari file amplifies to ~7x its size in heap before any crypto runs | fixed |
| F35 | low | security | app-desktop | Desktop writes token/key-bearing files at the default umask and chmods them afterwards; the store directory is created world-readable | fixed |
| F36 | low | security | app-android | Android release builds ship the emulator cleartext exemption for 10.0.2.2, a routable RFC1918 address | fixed |
| F37 | low | code-quality | app-android,app-desktop,co | ~100 lines of origin canonicalization is hand-duplicated across the two Kotlin apps although core/src/jvmShared already compiles into both | fixed |
| F38 | low | usability | app-desktop | Desktop copy and reveal controls are not named per field — the Android a11yand-09 rule was not carried across | fixed |
| F42 | low | professionalism | scripts | verify.sh contains a comment that contradicts the gate implemented 20 lines above it | fixed |
| F43 | low | professionalism | extension,core,app-android | Curly and straight apostrophes are mixed across user-facing copy, including two spellings of the same contraction inside one error file | deferred (owner) |

### Refuted by the verification pass — do not re-find

- **`a11y--1`** — The markup observation is literally true (Vault.tsx:1021-1099 Detail secret-rows carry sibling <label>s with no htmlFor, no aria-label; PasswordField at Vault.tsx:1461-1469 names nothing; the sole htmlFor in web/src is Field.tsx:35), but the finding as reported dies on three points.

1) "Detail was simply missed" is REFUTED by a binding design amendment. docs/design/2026-07-11-accessibility-a1.md:
  <br><sub>Originally: Web item Detail — every value field is an unnamed control and every action button is named only "Copy"</sub>
- **`a11y--2`** — The finding's central claim — "focus is stranded on <body> after every item open, **close**, and layer switch", i.e. "every other transition moves none" — is half false, and the half that is false is exactly the half carrying the impact argument.

WHAT I READ

1. The `.wrap` switch is as described (web/src/ui/Vault.tsx:475-604): a mutually-exclusive ternary chain, `openItem` at :342-345 (`closeLay
  <br><sub>Originally: Web vault performs no focus management on view transitions — focus is stranded on <body> after every item open, close, and layer switch</sub>
- **`supply-chain--2`** — The one factual core survives: scripts/publish-extension.sh:60 gates the Chrome zip on `[ -f ]` alone, and nothing in the file rebuilds, re-hashes, or consults git. But every load-bearing part of the argument — the asymmetry, the proposed gate, and the severity — dies on reading.

1. THE ASYMMETRY IS FABRICATED. The headline evidence is that the Firefox leg "cracks the artifact open and asserts it
  <br><sub>Originally: `publish-extension.sh` uploads the Chrome Web Store package with no provenance gate — no rebuild, no clean-tree check, and no assertion that the zip matches the tree</sub>
- **`supply-chain--3`** — The mechanical observations are true but the impact — the part that earns "high" — is false, and one of its two supporting claims is doc-silence inference.

WHAT SURVIVES (verified): `grep -rn '\.asc' --include=*.sh --include=*.ps1 --include=*.kt --include=*.ts --include=*.kts` really does return zero hits; `scripts/release-spec.sh:114-129` resolves and hashes the deb and never signs it; `scripts/
  <br><sub>Originally: The Linux .deb's "load-bearing" GPG signature has no script and no gate anywhere in the release path — and the runbook records the step lapsing for three consecutive releases</sub>

### Still open, deliberately

- **F27 (partial)** — Android accepts a plain-`http` self-host address its own network security config
  then blocks. The misleading "unreachable" copy is fixed and the session is dropped before the probe.
  Whether to accept such addresses at all awaits a reproduction on real hardware; the acceptance pin at
  `Wave3EndpointSwitchTest.kt` is deliberately unchanged until then.
- **F43 (deferred)** — apostrophe glyph normalization across all user-facing copy. Declined at §4.
- **God-file decomposition** — carried forward from the 2026-07-27 audit. This audit looked for
  concrete harm caused by the file sizes and found none, so the deferral stands rather than being
  re-argued.
- **`e2e.sh` is manual-only** — still needs a live server and real credentials, which no audit
  campaign has had.

### Verification debt

Two fixes rest on reasoning rather than observation, and are flagged so nobody mistakes them for
measured facts: the Android plain-`http` exception type (F27, above), and the backup-parser heap
amplification figure in F34, which was not re-derived because the missing section-count ceiling
justifies the fix on its own.

**Correction (2026-08-13).** F16 was listed here when this report was first written, and should not
have been. The remediation did not guess a new stride: it scoped the fixed height to the windowed
path only (`.vault-list--virtual .item`), leaving the plain ≤500-row list on `min-height` so it grows
with the text and cannot clip at any font size, and pinned `ROW_H` and the CSS height to agree by
parsing both sources. The fix therefore does not depend on the disputed geometry being right at all,
and the lane recorded a measured breakdown rather than repeating the audit's arithmetic. A closure
ledger that misreports its own debt defeats the purpose of having one.

## 6. What this audit says about the next one

The two gate holes (F39, F40) matter more than their medium severity suggests, because they are the
reason a green gate was not proof. Both are now closed, and the gate additionally asserts the
extension's version against the CHANGELOG and greps `docs/**` for reference-instance hostnames — the
two specific ways stale claims reached a public repository this time.

The remediation itself was reviewed adversarially before it was trusted, and that pass earned its
keep: it found that three fixes had built machinery and never connected it — a breach-check seam with
no call sites, a CSV warning computed but rendered nowhere, and a finding no lane had claimed at all.
All three were caught before the commit rather than after the release. **A lane's self-report that it
fixed something is a claim, not evidence; the tree is the evidence.**
