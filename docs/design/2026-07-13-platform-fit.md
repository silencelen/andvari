# Platform fit — extension quick-unlock tier, desktop menu bar + Ctrl+L, CMP screen-reader verification (design, 2026-07-13)

**Status: DESIGNED 2026-07-13 — NOT SCHEDULED; next-cycle candidate.** This is UI-audit
action-plan **item 27** (docs/design/2026-07-12-frontend-ui-audit.md, "Platform-fit roadmap",
Effort L): the three pieces of structural friction the audit deliberately fenced off from the
S/M remediation waves because they need design and framework work, not patches. Underlying
findings: extension *"Daily unlock friction: every 15-min idle relock costs a full online
sign-in + ~6 s Argon2id"* (Medium/L), desktop *"Lock posture is weak … Main.kt no lock
hotkey"* (Medium/M), desktop *"Linux (.deb) build has no screen-reader support at all;
Windows requires Java Access Bridge"* (Medium\*/L). Design-only: **no code, spec, or wire
change ships with this doc** — spec deltas are named below and land with the build cut, after
the house breaker pass. Verified against HEAD `6e0d638` (function-name anchors, not line
numbers — several cited files have moved since the audit).

## The shape in one paragraph

Three independent items, deliberately ordered cheapest-first. **(2) Desktop menu bar +
Ctrl+L** is a pure client-side S: a `MenuBar` in the existing `Window` scope plus a consuming
branch in the already-installed `onPreviewKeyEvent`, calling the same ungated
`DesktopState.lock()` the toolbar icon already calls. **(3) CMP screen-reader verification**
is an S/M evidence task, not a build: a headless AT-SPI presence probe plus an attended
Orca/NVDA protocol, whose honest expected outcome ("Linux exposes nothing; the web vault is
the accessible path") gets *documented*, with exactly one in-our-hands remediation lever (the
jlink runtime image omits `jdk.accessibility`, so Windows JAB support is likely broken in the
shipped MSI regardless of user configuration — one `modules()` line). **(1) Extension
quick-unlock** is the real design: a **PIN-wrapped UVK held in `storage.session`**
(session-scoped, never durable), riding a new locked-but-authenticated state that retains the
token pair across lock — turning the 15-minute ritual of master password + ~6 s Argon2id +
full re-login into PIN + ~1 s, while keeping every fail-closed property: wrong PIN falls to
the full master password, five misses wipe the blob, nothing new ever touches the wire, and
the server still never learns quick unlock exists (spec 01 §8 invariant). Hardware-gated
options (WebAuthn/PRF) are honestly *unknown-feasible* under MV3 and are spike-gated, not
promised.

---

## 1. Extension quick-unlock tier

**User story.** Brynn unlocks the extension at 9:00 to fill one login. At 9:20 she fills
another: the popup demands the full master password again and sits on "unsealing your vault —
about 6 seconds" (popup.html's own copy). She does this six times a day. She wants the
Android experience — a quick gesture between full unlocks — without the household's ZK story
quietly rotting.

### Ground truth (verified at HEAD)

- `background.ts unlock()`: **every** unlock is a full online sign-in — `api.prelogin` →
  `assertServerKdfParams` (the pentest-H1 floor) → `deriveMasterKeyAsync` (Argon2id in
  `kdf-worker.ts`, ~6 s at the 64 MiB/ops 3 account params) → `api.login` → unwrap UVK →
  open `encryptedIdentitySeed` → seed-derived `identityPub` hard-compare → `api.sync(0)` →
  build `vaultKeys`/items. The UVK and identity keypair are **locals** — dropped at the end
  of `unlock()`; only `vaultKeys` + decrypted items survive (in SW memory + the
  `SessionSnapshot` in `chrome.storage.session`, which is memory-backed and
  `TRUSTED_CONTEXTS`-scoped).
- `doLock()`: wipes session, tabs, pending saves, and calls `api.setTokens(null, null)` —
  tokens are **forgotten client-side but not revoked server-side** (no logout call; the
  refresh token stays valid on the server until expiry). Idle default
  `DEFAULT_AUTOLOCK_SECONDS = 15 * 60`.
- The extension has **no offline cache and no cached `accountKeys`** by design (E1 doc,
  "attacked and held"); `GET /account/keys` exists on the wire (spec 03: "`accountKeys` as
  in login") and is what the Android UVK path consumes.
- Android precedent (spec 01 §8.1 NORMATIVE; `QuickUnlock.kt`: `isEligible` / `isFresh` /
  `enroll` / `recoverUvk` / `wipe`; core `Account.unlockWithUvk` +
  `uvkCopyForPlatformWrap`): wrap the **UVK only** — never MK/password/wrapKey — in
  hardware, fail every failure to the password, wipe on sign-out/definitive-401/policy-flip,
  periodic full-password rule.

### Option analysis — what MV3 actually offers

| Option | Mechanism | Verdict |
|---|---|---|
| **A. Random session-key wrap** | Wrap the session under a random key; both key and ciphertext live in extension storage | **REJECT.** MV3 has no second compartment: SW memory dies in ~30 s, `storage.session` and `storage.local` are readable by the same principal. A wrap whose key sits beside its ciphertext makes "Locked" pure UI theater — worse than honest, because today's lock is a real erase. |
| **B. PIN-wrapped UVK, session-scoped** (`storage.session`) | Argon2id(PIN) wraps the UVK; blob + attempt counter die at browser exit | **RECOMMEND (v1).** Adds a *something-you-know* the compartment doesn't hold. Honest weakening is narrow and stated below. |
| **C. WebAuthn/PRF-wrapped UVK, durable** (`storage.local`) | `navigator.credentials.get` with the `prf` extension; authenticator-gated key material wraps the UVK | **SPIKE-GATED (tier 2).** The right long-term answer (hardware-gated, Android-posture), but TWO unproven claims: (a) whether an MV3 extension document may call WebAuthn at all — `chrome-extension://` origins have no registrable-domain RP ID, and Chromium/Firefox behavior here must be feature-detected, not assumed; (b) whether the household's actual authenticators (Windows Hello, Android hybrid, security keys) evaluate PRF — platform support is uneven. Build NOTHING on either claim untested. |
| **D. Native-messaging companion** (Bitwarden's biometric model) | Extension ⇄ OS-native host app holds/gates the secret | **REJECT (v1).** Requires shipping and trusting a native host per OS; couples the extension install to the desktop app; the desktop client itself has no OS-biometric integration to lend (spec 01 §8.2 Windows quick unlock is DEFERRED). Revisit only if the C spike fails AND the owner wants hardware gating badly enough to fund a host. |

### Tier B design (the build contract)

**New locked-but-authenticated state (the structural change).** Android's lock ≠ sign-out
split arrives in the extension: when quick unlock is **armed**, `doLock()` keeps a slimmed
snapshot in `storage.session` — `{access, refresh, userId, email, quickUnlock: blob}` — and
destroys everything else exactly as today (vaultKeys, items, tabs, **pending saves — they
hold plaintext page passwords and MUST still die at lock**, grants, badges). When quick
unlock is not armed, `doLock()` stays byte-identical to today. Sign-out (a new explicit
popup action, or definitive 401) clears everything including tokens, as today.

**Enrollment** (popup Settings + a one-time post-unlock offer card, Android
`QuickUnlockOfferCard` idiom): only while unlocked; **refused while
`mustChangePassword=true`** (spec 01 §8.1-A5 parity — never let a rescue-issued temp
password's UVK get armed). User picks a PIN — **minimum 6 characters, any characters, digits
allowed** (entropy floor is honesty, not theater; copy says a word is better than 6 digits).
Blob, sealed with the existing `crypto.ts` AEAD (`open`/seal + a new `adQuickUnlock(userId)`
AAD, `"andvari/v1|ext-quick-unlock|<userId>"`):

```
{ v: 1, salt, kdfParams, iv, ct = AEAD(K_pin, UVK), createdAt, lastFullUnlockAt }
+ sibling storage.session key: attempts remaining (starts 5)
```

`K_pin = Argon2id(PIN, salt, pinParams)` via the existing `deriveMasterKeyAsync` worker.
`pinParams` are chosen at enroll by a one-shot bench targeting **≤ 1 s** on that machine,
floored at **mem ≥ 32 MiB, ops ≥ 2** and recorded in the blob (never below floor on use —
a blob carrying weaker params is treated as corrupt → wipe).

**Quick unlock path** (new `unlockWithPin(pin)` beside `unlock(email, password)`):
`open(K_pin, blob)` → UVK → `GET /account/keys` (existing tokens; refresh may rotate) →
open `encryptedIdentitySeed` under UVK → **the same seed-derived `identityPub` hard-compare
as `unlock()`** (`IdentityMismatchError`, never softened) → `api.sync(0)` → rebuild
vaultKeys/items → session. Total cost ≈ PIN KDF (≤ 1 s) + two round trips. Bonus over
wrapping vaultKeys: holding the UVK + identity again means **new shared-vault grants open on
a quick unlock** (today `armAutoLock`-era resync can't open a brand-new vault until the next
real unlock — the comment above `resync` says so).

**Fail-closed rules (normative for the build; wrong-PIN = full unlock, no oracle):**

| Event | Action |
|---|---|
| AEAD open fails (wrong PIN, tampered/corrupt blob, unknown `v`, sub-floor params — **indistinguishable by design**) | decrement attempts; generic copy "That PIN didn't match — N tries left, or use your master password." No signal distinguishes wrong-PIN from corrupt-blob; nothing reveals partial correctness (AEAD gives none); the PIN never touches the wire, so there is no remote oracle at all |
| Attempts exhausted (5) | **wipe** blob + counter; full master-password unlock is the only path; re-enroll only after a successful full unlock |
| `encryptedIdentitySeed` won't open under the recovered UVK | wipe (stale/foreign UVK); password prompt |
| Seed-derived identityPub ≠ server identityPub | **HARD FAIL** — `identity_mismatch` code, E1-1 sentence, blob **kept** (evidence; Android parity) |
| Definitive 401 on `GET /account/keys`/sync (revoked elsewhere, password changed elsewhere) | wipe blob + tokens → full sign-in (`unlock()`) |
| Network failure | password prompt this time; blob kept (the full path needs the network too — the extension has no offline unlock; unchanged posture) |
| `> 24 h` since `lastFullUnlockAt`, or stamp in the future | password required (blob kept; a successful full unlock re-stamps) |
| Browser exit | `storage.session` evaporates — blob, counter, tokens all gone (the natural ceiling) |
| User disables in Settings | wipe, **no auth gate** (reducing standing secret material is never gated — §8.1 parity) |

**Periodic-full-password analogue:** the durable-blob 30-day rule collapses here to
**min(browser session, 24 h)** — `storage.session` cannot outlive the browser, and the
extension has no F61 re-key path (it never calls `PUT /account/password`), so the rule
serves muscle memory and bounds the locked-state token-retention window only. Clock
handling: `Date.now()` with fail-closed-on-future-stamp; the §8.1 cross-boot server-anchor
machinery is NOT needed (a reboot kills the browser kills the blob).

**Policy gating decision (state it in spec, don't blur it):** `offlineCacheAllowed` gates
**durable vault-opening key material at rest** (the E1/A10 re-scope). A `storage.session`
blob is memory-backed and browser-session-scoped — *not* durable, *not* at rest — and lives
in the same compartment that already holds raw `vaultKeys` while unlocked. **Tier B is
therefore NOT gated on `offlineCacheAllowed`**; a future durable Tier C **IS** (Android
parity), which gives the two tiers a clean, teachable line. `autoLockSeconds` continues to
govern when the lock fires; quick unlock changes only what re-opening costs.

### Security notes / ZK impact (the honest costs)

- **Wire/server story: zero change.** No new endpoints, headers, or fields; the PIN and blob
  never leave the device; T1/T2/T7/T8 untouched. This is the spec 01 §8 invariant and it
  holds by construction.
- **The real narrowing:** on a machine that is *unlocked and has the browser running*, a
  locked extension falls from "master password required" to "6+-char PIN, 5 attempts, then
  wipe." Unlike Android §8.1 there is **no hardware gate**: an attacker who can read the
  browser process / `storage.session` gets a PIN-crackable blob (10^6 digit-PIN space ×
  ~32 MiB Argon2id ≈ GPU-hours, not years) *plus live bearer tokens*. That attacker class is
  T5 (local malware/debugger) — already out of scope for every client — so the **in-scope**
  delta is the human-at-keyboard opportunist, where attempt-wipe holds. Spec 05 gets an
  **A7-extension** block modeled on the existing A7 rows saying exactly this.
- **Token retention across lock** is new client-side state, not new server-side exposure:
  today's `doLock()` already leaves the refresh token *valid server-side* — it only forgets
  it. Retaining it in `storage.session` while locked extends in-compartment lifetime, wiped
  by browser exit / sign-out / definitive 401 / the 24 h rule.
- **Attempt counter is same-compartment and attacker-resettable** — stated plainly (the
  §8.1 "no app-level counter" argument). It exists here anyway because, absent a hardware
  rate limiter, it is the only brake on the in-scope opportunist class; against exfiltration
  it is theater and the PIN entropy floor + session scoping are the actual bounds.
- **Spec deltas at build time:** new **spec 01 §8.4 Extension** (normative; explicitly
  leaves §8.3 "Web: none" standing — the extension is its own platform, per its own
  `X-Andvari-Client: extension/x.y.z` token), spec 05 A7-extension rows, and a
  CHANGELOG/threat-doc note that "lock" on the extension now has two grades (armed vs
  plain). House rule: **2-breaker adversarial pass on this section before build.**

**Effort:** extension **M** (background/popup/messages/errors + tests), core/server/web
**0**, spec **S**. Tier C spike **S** (feature-detect matrix in both browsers + PRF
availability on owner hardware); Tier C build **M–L**, gated on the spike.

**Out of scope (this item does NOT do):** any durable (storage.local) secret without
hardware gating — **explicitly rejected, don't drift into it**; WebAuthn/PRF build (spike
first); native-messaging hosts; offline unlock / offline cache for the extension; biometric
UI claims of any kind; server/wire changes; changing the 15-min default or the household
`autoLockSeconds` knob (that's policy tuning, available today); the locked-view VPN-hint
copy (separate audit item).

---

## 2. Desktop menu bar + Ctrl+L panic-lock

**User story.** Jacob has the desktop vault open when someone walks in. He hits Ctrl+L —
muscle memory from every browser and Bitwarden — and the vault locks. Today that key does
nothing: the only lock is an icon-only button on the Vault screen's toolbar, invisible from
Settings/Sharing/Trash, and the app has no menu bar at all — six unlabeled icons are the
entire command surface.

### Design

**Ctrl+L (the authoritative handler).** `Main.kt` already installs a window-level key
observer: `Window(onPreviewKeyEvent = { state.touch(); false })` — it sees every hardware
key regardless of focus. Extend it:

```kotlin
onPreviewKeyEvent = {
    state.touch()
    if (it.type == KeyEventType.KeyDown && it.isCtrlPressed && it.key == Key.L) {
        state.panicLock(); true            // consume — never reaches a text field
    } else false
}
```

New `DesktopState.panicLock()`: no-op unless signed in (`account != null` — from Welcome/
Unlock/Loading the key does nothing, so a locked app never navigates); otherwise
`lock("Locked.")`. Semantics are **identical to the existing toolbar button** (`IconButton
(onClick = { state.lock() })` in the Vault toolbar, already ungated) — `lock()` closes the
engine/api handles safely, calls `clearVaultClipboard()`, zeroes `pendingRecoverySecret`,
and sets the F26 `lockReason`. **Deliberately unconditional:** unlike `maybeIdleLock()`
(which defers under `busy`/`importBusy`/`copyOpVaultId` and grants an open editor
`editorGraceMs`), a panic lock is an explicit user command — it fires mid-editor and
discards the draft, and mid-recovery-gate (safe since the v2 #15 capture-gate invariant:
the next unlock re-enters the gate with a fresh phrase). The lock-reason copy can say so
when an editor was open, reusing `maybeIdleLock()`'s exact "unsaved changes were discarded"
sentence.

**MenuBar.** Compose Desktop's `FrameWindowScope.MenuBar` (available at the shipped CMP
1.7.3), declared inside the existing `Window {}` block in `Main.kt`, rendering a native/AWT
menu on both target formats (Msi, Deb):

- **Vault** — `Sync now` (Ctrl+R; enabled when signed in; calls `state.refresh()`),
  `Import passwords…` (enabled on the Vault screen; requires hoisting the Vault-local
  `importFlow` flag into a `DesktopState.importRequested` the Vault screen consumes),
  separator, `Lock` (Ctrl+L; enabled when signed in; `panicLock()`), `Sign out…` (routes
  through the confirm dialog the audit's un-confirmed-sign-out finding adds — never a bare
  `state.signOut()`), separator, `Quit` (Ctrl+Q → `exitApplication`).
- **Help** — `Open web vault` (`Desktop.getDesktop().browse(baseUrl)`), `Check for updates`
  (existing `Platform.checkForUpdate(baseUrl)` → surface `updateAvailable` as the normal
  notice; run on Dispatchers.IO — the audit's frozen-startup finding already mandates that
  move), `About andvari` (dialog: `ANDVARI_CLIENT_VERSION` + `desktopPlatform()` +
  configured server URL — the app currently displays its version nowhere).

**One authoritative shortcut site (decision).** Shortcuts are *declared* on menu items via
`KeyShortcut(Key.L, ctrl = true)` etc. — that renders the accelerator text, which is the
discoverability win — but **handling lives solely in `onPreviewKeyEvent`**, which consumes
the event first. AWT accelerator dispatch varies by platform and focus owner; two live
handlers would double-fire. Menu `onClick` calls the same functions (idempotent —
`panicLock()` while locked is a no-op).

### Security notes

No key material, wire, or spec change. Two deliberate stances: (a) panic lock **discards
editor drafts** — explicit user intent outranks the draft, and the idle-lock draft-grace
finding (separate item) is unaffected; (b) `Sign out` in a menu makes a destructive action
*more* reachable, so it lands only behind the confirm dialog (its own audit item — if that
item hasn't shipped yet, the menu item ships disabled-with-tooltip or not at all, never
bare). Ctrl+L is also a11y-positive: the first keyboard path to lock (WCAG 2.1.1) and the
menu gives every toolbar icon a named, traversable equivalent.

**Effort:** desktop **S** (Main.kt + a `panicLock`/`importRequested` pair in DesktopState +
About dialog in Ui.kt). No other platform.

**Out of scope:** OS-global hotkeys (out-of-focus lock), system tray/minimize-to-tray, a
macOS target (no Cmd mappings until one exists — `KeyShortcut(meta=true)` lands with it),
menu-driven editing commands (Cut/Copy/Paste rows), Windows Hello / desktop quick-unlock
(spec 01 §8.2 stays DEFERRED — this item must not be a back door into it), tooltips on the
toolbar icons (separate S item in the audit).

---

## 3. CMP screen-reader verification (desktop)

**User story.** A screen-reader user on Linux installs the .deb because the household uses
andvari. Orca says nothing at all — not even that a window opened. Nobody ever claimed Linux
support, but nobody *stated its absence* either, and the downloads page happily serves the
artifact. The deliverable here is **evidence and honest documentation**, not a build.

### Ground truth (verified)

- Shipped framework: **CMP 1.7.3** (`gradle/libs.versions.toml`,
  `compose-multiplatform = "1.7.3"`), JVM toolchain 17, `targetFormats(Msi, Deb)`
  (`app-desktop/build.gradle.kts`, packageVersion 0.16.0).
- Semantics *exist* in the app (the a11ydesk cut added contentDescriptions etc. throughout
  `Ui.kt`), but semantics only matter if the platform bridge exports them. Compose Desktop
  bridges to the **Java Accessibility API**; JetBrains' documented support surface is
  Windows (via **Java Access Bridge**, user-enabled) and macOS — **Linux/AT-SPI is not
  documented as supported**. The audit flagged this as external-knowledge-to-verify; that
  verification is exactly this item. Expectation to test, not assert: **Orca hears
  nothing.**
- **The one in-our-hands lever, found at HEAD:** the jlink runtime image is minimized —
  `nativeDistributions.modules("java.instrument", "java.management", "java.net.http",
  "java.sql", "jdk.unsupported")` — and does **NOT include `jdk.accessibility`**. Without
  that module the bundled Windows runtime cannot load the Access Bridge **even after the
  user runs `jabswitch /enable`** — meaning our MSI's Windows screen-reader support is
  plausibly broken at the packaging layer today, independent of CMP's capabilities.

### Verification protocol (the build contract for the spike)

**Phase 0 — headless AT-SPI presence probe (runs on the fleet, no human).** On a Linux
box/VM: launch the packaged app under Xvfb with `at-spi2-core` running
(`GTK_MODULES`/`QT_ACCESSIBILITY` not needed — the JVM either registers on the a11y bus or
it doesn't), then dump the desktop's accessible tree with `pyatspi` (or `busctl --user tree
org.a11y.atspi.Registry` / `accerciser` interactively). **PASS** = an accessible application
node for the andvari JVM exposing children with roles/names; **FAIL** = the app is absent
from the registry. A FAIL here is *conclusive* for "nothing is exposed to Orca" — Orca reads
the same bus — and can be captured as evidence (tree dump artifact) without a screen reader
or a human. Also record whether any JVM/CMP **enabling flag** changes the outcome — probe
`javax.accessibility.assistive_technologies` and any `compose.accessibility.*` properties
empirically; JetBrains has historically gated desktop a11y behind system properties, and the
spike records the exact invocation rather than trusting docs.

**Phase 1 — attended Orca pass (only if Phase 0 passes, else skipped as moot).** GNOME +
Orca, three scripted flows with per-flow PASS/PARTIAL/SILENT: **(a) unlock** — Tab to
email/password, labels announced, password field announced as secret, wrong-password error
announced (note: the desktop client currently has zero `liveRegion`s — a separate audit
item — so error announcement may fail even where the tree exists; record which layer
failed); **(b) vault list** — traverse rows, names + roles announced, search reachable;
**(c) editor** — open an item, field labels announced, save outcome announced.

**Phase 2 — Windows.** First **fix-and-verify the runtime**: add `jdk.accessibility` to
`modules(...)`, rebuild the MSI, then `jabswitch /enable` + NVDA, same three flows. Without
the module fix this phase is predetermined to fail and proves nothing about CMP.

### The honest documented outcome (ships regardless of results)

A short `docs/accessibility.md` (linked from README + the downloads page) with a
platform-support matrix filled from the protocol runs, and — assuming Linux FAILs —
this stated limitation, verbatim posture: *"The Linux desktop app does not currently expose
an accessibility tree — screen readers (Orca) cannot read it. This is a limitation of the
UI framework we ship on, not a policy. **The web vault is the accessible path** (it carries
our WCAG AA work), and Windows support requires [documented JAB steps]."* Never imply
support that wasn't demonstrated; date the matrix and pin the CMP version it was measured
against (1.7.3), so a future CMP upgrade re-triggers the protocol.

### Remediation options (grounded in CMP 1.7.3 — no invented capabilities)

1. **Document + web-vault fallback** — ships with the matrix. Effort **S**. This is the
   recommended v1 outcome.
2. **`jdk.accessibility` into the runtime image + Windows JAB doc** — one build line + a
   downloads-page paragraph + a Phase-2 re-run. Effort **S** (desktop/packaging). Do this
   even if NVDA support turns out partial: shipping a runtime that *cannot* load the bridge
   is strictly wrong.
3. **Track upstream, re-verify on CMP upgrades** — Linux/AT-SPI support is framework work
   that does not exist at 1.7.3; the fix arrives (if ever) via a JetBrains release, so file
   it as a watched upstream issue and re-run Phase 0 whenever `compose-multiplatform` bumps.
   Effort **S** recurring; the underlying capability is **not buildable by us** at sane
   cost.
4. **REJECTED: hand-rolling an AT-SPI bridge** (JNI to libatspi mapping Compose semantics)
   — multi-month framework engineering for a household app with an accessible web client.
   Named so nobody re-derives it.

**Effort:** verification **S–M** (Phase 0 scriptable in-fleet; Phases 1–2 need a GNOME box
and a Windows box — owner-attended), documentation **S**, runtime-module fix **S**, Linux
remediation **upstream/blocked** (not ours).

**Out of scope:** any code change to `Ui.kt` semantics (the audit's liveRegion/focus items
are separate), macOS (not a target), promising timelines for upstream Linux support,
switching UI frameworks.

---

## Build-order recommendation

1. **Desktop menu bar + Ctrl+L** (S, desktop-only, no spec delta) — immediate daily-use win,
   zero risk, also the cheapest a11y improvement (first keyboard lock path).
2. **CMP screen-reader verification, Phase 0 + `jdk.accessibility` module fix + the
   documented matrix** (S–M) — evidence before claims; the packaging fix is embarrassing to
   leave un-shipped once known. Attended Phases 1–2 ride the owner's next hands-on window.
3. **Extension quick-unlock Tier B** (M, extension + spec 01 §8.4 + spec 05 rows) — the big
   friction win; **requires the house 2-breaker pass on §1 before build** (it touches the
   lock/erase story, the same class of surface the 07-10 Android breakers amended nine ways).
4. **Tier C spike (WebAuthn/PRF feasibility)** (S) — run alongside 3; its outcome decides
   whether a durable hardware-gated tier is even possible, next cycle.

## Open questions (non-blocking; defaults chosen)

- Tier B PIN scope: per-account or per-install? **Default: per-account** (blob AAD already
  binds userId; the popup is single-account today anyway).
- Should the quick-unlock offer card appear after *every* full unlock until enrolled or
  dismissed-once? **Default: dismissed-once, then Settings-only** (the Android §8 open-
  question default, same reasoning — no nag loop).
- Menu `Import passwords…` on non-Vault signed-in screens: navigate-to-Vault-then-open, or
  disabled? **Default: disabled outside Vault** (no hidden navigation side effects).
- Does the About dialog show the update state inline? **Default: yes if `updateAvailable`
  is already non-null; it performs no network call of its own.**
