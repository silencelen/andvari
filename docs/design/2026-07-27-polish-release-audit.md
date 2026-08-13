# Polish-release audit — full-surface review at 0.20.0 / ext 0.19.0

**Status: CLOSED — every finding shipped, refuted, or deliberately deferred. See the closure ledger below.** Scope: everything shipped, reviewed
from every angle (correctness, security drift, UX parity, copy, accessibility, failure experience,
performance, test quality, code structure, docs, release hygiene). The next release is a **polish
release**: no roadmap items, no new capability — fix, unify, and clean up what already exists.

- **Tree reviewed:** `59d523f` (fleet 0.20.0, extension 0.19.0), 2026-07-27.
- **Gate baseline:** `scripts/verify.sh` EXIT=0 at HEAD (Kotlin + TypeScript green off the shared
  spec/test-vectors; extension suite 247 tests). Every finding below is *on top of* a green gate —
  which is itself one of the findings.
- **Method:** 9 module mappers → 16 review lanes (152 raw findings) → adversarial refute pass
  (46 two-lens refuters on every high finding + 12 batched skeptics on the mediums), then inline
  verification of the batches that died. See §8.
- **Outcome:** 16 high · 64 medium · 72 low. Two findings were killed by the refuters and are
  recorded in §7 so they are not re-found. Ten had their severity or mechanism corrected.

---

## Closure ledger (added 2026-07-30)

**Every finding in this document is accounted for — read this before the tables below.** This audit
drove a four-wave campaign that shipped as release **0.21.0 / extension 0.20.0**, live on every
surface 2026-07-29. The tables further down are the original findings as reported, *not* an open
backlog.

| Disposition | Count |
|---|---|
| Shipped in a build wave | 127 |
| Shipped in the closeout pass (`1b12380`) | 6 |
| Shipped as a side effect of an adjacent lane | 6 |
| Refuted / not defects | 6 |
| Severity reviewed down, left out of scope | 2 |
| Deliberately deferred | 5 |
| **Total** | **152** |

The adversarial layers are why those first rows are trustworthy: a find→refute pass over the *new*
work found 15 confirmed regressions in Wave 1 alone — including that the headline autofill fix was
incomplete — and two independent reviewers returned "fix-first" on the release automation, catching
an inverted trust model and a ceremony that signed an unverified base before either shipped.

### Refuted — do not re-find these

- **`hygiene-release--1`** — Emission-on-sign is the documented designed contract, and the file lands in a local gitignored dir that nothing serves. It was also **not** the cause of the 2026-07-26 unpapered publish, which was a deliberate dual-channel push that skipped the paperwork ritual.
  <br><sub>Originally: publish-extension.sh arms the Firefox auto-update channel on every sign, ungated</sub>
- **`quality-deadcode--12`** — The `UriMatch.normalizeHost` / `CsvImport.nameFallback` split is a deliberate, documented divergence — not duplication to unify.
  <br><sub>Originally: Core host-extraction duplication (UriMatch.normalizeHost vs CsvImport.nameFallback) is real but deliberately divergent and vector-pinned — full unification is the wrong fix</sub>
- **`quality-deadcode--14`** — Refuted-leads ledger: no unused CSS classes, no commented-out code blocks, all extension deps used.
  <br><sub>Originally: Refuted leads: no unused CSS classes, no commented-out code blocks, extension deps all used</sub>
- **`quality-tests--4`** — Both refuters overturned it: the in-page card chip IS pinned, by a dedicated `C1` describe block in `web/src/extension-pins.test.ts` that `verify.sh` runs. The reviewer grepped only `extension/src/*.test.ts` and missed the house pattern — **extension invariants are pinned from the web vitest suite**.
  <br><sub>Originally: Extension 0.19.0 (in-page card chip) is staged and partially shipped — signed xpi built, firefox-updates.json advertising it — with ZERO automated coverage of any chip code</sub>
- **`ux-copy--12`** — Verified **largely deliberate and documented** at `HouseholdCopy.kt:56,108` — the extension popup's shorter "contact your admin" is intentional brevity. A blunt unification would overwrite a recorded decision. The residual is a minor inconsistency inside the canon itself; not worth forking a pinned twin over.
  <br><sub>Originally: 'contact your admin' vs 'contact your administrator' split inside the core canon itself</sub>
- **`ux-parity--8`** — It IS the refuted-leads ledger for that lane, not a defect.
  <br><sub>Originally: REFUTED LEADS (for the refuter's ledger): five mapper observations are not cross-platform divergences</sub>

### Severity reviewed down, left out of scope

- **`bug-server--4`** — Reviewed down to low by its refuter; deliberately left out of scope.
  <br><sub>PUT /escrow/self replaces the org recovery backstop with only a session, while the sibling recovery-write route requires a password re-auth</sub>
- **`bug-web--2`** — Reviewed down to low by its refuter.
  <br><sub>mustChange banner navigation misses three layers — stale invisible layer eats a Back press</sub>

### Still open, deliberately

Decisions, not oversights. Each is either out of scope for a polish release or needs something this
campaign could not provide.

- **God-file decomposition** — `MainActivity.kt` 3067 lines, `Ui.kt` 3228, `background.ts` 3117,
  `Vault.tsx` 2307, `Service.kt` 1426, `SyncEngine.kt` 1387. A standalone project, not polish. Leaves
  were extracted opportunistically where a wave already had the file open.
- **Desktop `Ui.kt` coverage** — no Compose test harness exists in the module. Wave 3 added desktop's
  first *executing*-coroutine harness for `DesktopState` (the existing one deliberately never ran its
  coroutines), but composables remain uncovered.
- **`quality-tests--8`** — The E2E layer is manual-only and decaying (`e2e.sh` is an echo-suggestion inside `verify.sh`). Fixing it needs a live server and real credentials, which this campaign deliberately never had.
- **`quality-tests--9`** — Extension surface wiring (~7.1k lines across background/content/content-ui/popup/connector/offscreen) has no behavioural coverage. Effort L, and it wants a browser harness — out of scope for polish.
- **`ux-copy--10`** — One popup string capitalizes the brand ("Andvari can't auto-fill…"). Low; it is a pinned twin, so changing it costs more than it returns. **Superseded 2026-08-13 (audit F24): fixed after all** — the popup string and its `extension-pins.test.ts` [U21] pin were lowercased in one change, and the pin now reds on the capitalized form, so the sentence quoted here (and in row 141 below, and in `2026-07-23-card-autofill-tier2.md` §6) must not be restored from these records.
- **`ux-copy--8`** — Import-result bucket phrasing diverges across the three importing surfaces. Low, and it touches copy that would want canonizing first.
- **`ux-copy--9`** — Apostrophe style is mixed inside single files against the canon's ASCII convention. Low, cosmetic.
- **Anything needing a real device or a live checkout** — the F20 compatibility trace, and end-to-end
  verification against a real payment form. No amount of static review substitutes for it.

### Found while fixing — NOT in this audit

- **The *transient* import sentence is an un-canonized twin, and has already drifted.** The natives say
  "Import interrupted — press Retry to finish (no duplicates will be created)."; web says something
  different. Same class as `ux-copy--3`, which this campaign moved into the `HouseholdCopy` canon.
  **Undecided:** whether this sentence belongs there too.
- **Neither native refreshes `items` after a FAILED import**, so rows that did land stay invisible until
  the next sync. Previously masked — a transient retry eventually succeeded and refreshed — but now
  reachable via the terminal path added for `ux-error--1`.
- **Private infrastructure names were reachable in public files**: a tailnet hostname and absolute
  build paths in developer-facing scripts, `gradle.properties`, extension console output and the
  store-publishing runbook. Genericized. Dated design and compliance records were deliberately left as
  written, with a banner in `docs/ROADMAP.md` explaining the notation.

### Where each shipped finding landed

| Finding | Sev | Shipped in |
|---|---|---|
| `bug-autofill-ux--0` | H | Wave 1 + fold |
| `bug-cache-lifecycle--0` | H | Wave 1 + fold |
| `bug-ext-gating--0` | H | Wave 1 + fold |
| `bug-server--0` | H | Wave 1 + fold |
| `bug-web--0` | H | Wave 1 + fold |
| `hygiene-docs--0` | H | Wave 2 |
| `hygiene-docs--1` | H | Wave 2 |
| `hygiene-docs--2` | H | Wave 2 |
| `hygiene-docs--4` | H | Wave 2 |
| `hygiene-docs--6` | H | Wave 2 |
| `hygiene-release--0` | H | Wave 2 |
| `quality-tests--0` | H | Wave 2 |
| `quality-tests--1` | H | Wave 2 |
| `quality-tests--2` | H | Same defect as bug-cache-lifecycle--0; fixed there (8b81306) |
| `ux-copy--1` | H | Closeout pass (`1b12380`) |
| `ux-error--0` | H | Wave 1 + fold |
| `a11y-native--0` | M | Wave 2 |
| `a11y-native--1` | M | Wave 2 |
| `a11y-native--2` | M | Wave 2 |
| `a11y-native--3` | M | Wave 3 |
| `a11y-webext--0` | M | Wave 3 |
| `a11y-webext--1` | M | Wave 3 |
| `a11y-webext--2` | M | Wave 3 |
| `a11y-webext--3` | M | Wave 3 |
| `bug-autofill-ux--1` | M | Wave 1 + fold |
| `bug-cache-lifecycle--1` | M | Wave 1 + fold |
| `bug-cache-lifecycle--2` | M | Wave 1 + fold |
| `bug-ext-gating--1` | M | Wave 3 |
| `bug-ext-gating--2` | M | Wave 1 + fold |
| `bug-ext-gating--4` | M | Wave 3 |
| `bug-server--1` | M | Wave 1 + fold |
| `bug-server--2` | M | Wave 1 + fold |
| `bug-server--5` | M | Wave 1 + fold |
| `bug-web--1` | M | Wave 1 + fold |
| `hygiene-docs--10` | M | Wave 2 |
| `hygiene-docs--11` | M | Wave 2 |
| `hygiene-docs--13` | M | Wave 2 |
| `hygiene-docs--3` | M | Wave 2 |
| `hygiene-docs--5` | M | Wave 2 |
| `hygiene-docs--7` | M | Wave 2 |
| `hygiene-docs--8` | M | Closeout pass (`1b12380`) |
| `hygiene-docs--9` | M | Wave 2 |
| `hygiene-release--2` | M | Fixed by scripting the ceremony end to end: `release-spec.sh` + `prestige-release.ps1` (b1ebc17) and the verify-and-publish watcher (netplan 55423a5) — first run end-to-end 2026-07-29 |
| `hygiene-release--3` | M | Wave 2 |
| `hygiene-release--4` | M | Wave 2 |
| `hygiene-release--5` | M | Wave 2 |
| `quality-deadcode--0` | M | Wave 1 + fold |
| `quality-deadcode--1` | M | Wave 2 |
| `quality-deadcode--2` | M | Wave 3 |
| `quality-deadcode--3` | M | Wave 3 |
| `quality-deadcode--5` | M | Wave 3 |
| `quality-deadcode--6` | M | Wave 3 |
| `quality-perf--0` | M | Wave 1 + fold |
| `quality-perf--1` | M | Wave 1 + fold |
| `quality-secdrift--0` | M | Wave 1 + fold |
| `quality-secdrift--1` | M | Wave 1 + fold |
| `quality-secdrift--2` | M | Wave 1 + fold |
| `quality-secdrift--3` | M | Wave 1 + fold |
| `quality-tests--10` | M | Wave 3 |
| `quality-tests--3` | M | Wave 2 |
| `quality-tests--5` | M | Wave 3 |
| `quality-tests--6` | M | Wave 1 + fold |
| `quality-tests--7` | M | Fixed as a side effect — the docs lane added the vector-provenance manifest (1842c9d) |
| `ux-copy--0` | M | Wave 1 + fold |
| `ux-copy--2` | M | Wave 1 + fold |
| `ux-copy--3` | M | Twin pass (1cd59b8) |
| `ux-copy--4` | M | Wave 2 |
| `ux-copy--5` | M | Closeout pass (`1b12380`) |
| `ux-copy--6` | M | Fixed as a side effect — the docs lane rewrote INSTALL.txt (1842c9d) |
| `ux-error--1` | M | Closeout pass (`1b12380`) |
| `ux-error--2` | M | Wave 1 + fold |
| `ux-error--3` | M | Wave 1 + fold |
| `ux-error--4` | M | Wave 3 |
| `ux-parity--0` | M | Wave 2 |
| `ux-parity--1` | M | Wave 3 |
| `ux-parity--2` | M | Wave 3 |
| `ux-parity--3` | M | Wave 2 |
| `ux-parity--4` | M | Wave 3 |
| `a11y-native--10` | L | Wave 2 |
| `a11y-native--4` | L | Wave 2 |
| `a11y-native--5` | L | Wave 3 |
| `a11y-native--6` | L | Wave 2 |
| `a11y-native--7` | L | Wave 2 |
| `a11y-native--8` | L | Wave 2 |
| `a11y-native--9` | L | Wave 2 |
| `a11y-webext--10` | L | Wave 3 |
| `a11y-webext--11` | L | Wave 3 |
| `a11y-webext--12` | L | Wave 3 |
| `a11y-webext--4` | L | Wave 3 |
| `a11y-webext--5` | L | Wave 3 |
| `a11y-webext--6` | L | Wave 3 |
| `a11y-webext--7` | L | Wave 3 |
| `a11y-webext--8` | L | Wave 3 |
| `a11y-webext--9` | L | Wave 3 |
| `bug-autofill-ux--2` | L | Wave 1 + fold |
| `bug-ext-gating--3` | L | Wave 3 |
| `bug-server--10` | L | Wave 3 |
| `bug-server--3` | L | Wave 1 + fold |
| `bug-server--6` | L | Wave 3 |
| `bug-server--7` | L | Wave 3 |
| `bug-server--8` | L | Wave 3 |
| `bug-server--9` | L | Wave 3 |
| `bug-web--3` | L | Wave 3 |
| `bug-web--4` | L | Fixed as a side effect of the Trash N+1 work (b6eba07) |
| `bug-web--5` | L | Wave 3 |
| `bug-web--6` | L | Wave 3 |
| `hygiene-docs--12` | L | Wave 2 |
| `hygiene-docs--14` | L | Closeout pass (`1b12380`) |
| `hygiene-docs--15` | L | Fixed as a side effect — the 1.8 MB HTML twin is no longer tracked (1842c9d) |
| `hygiene-docs--16` | L | Wave 2 |
| `hygiene-docs--17` | L | Wave 2 |
| `hygiene-release--6` | L | Wave 2 |
| `hygiene-release--7` | L | Wave 2 |
| `hygiene-release--8` | L | Wave 2 |
| `hygiene-release--9` | L | Wave 2 |
| `quality-deadcode--10` | L | Wave 3 |
| `quality-deadcode--11` | L | Wave 3 |
| `quality-deadcode--13` | L | Wave 3 |
| `quality-deadcode--4` | L | Wave 2 |
| `quality-deadcode--7` | L | Wave 3 |
| `quality-deadcode--8` | L | Wave 3 |
| `quality-deadcode--9` | L | Wave 2 |
| `quality-perf--2` | L | Wave 3 |
| `quality-perf--3` | L | Wave 3 |
| `quality-perf--4` | L | Wave 3 |
| `quality-perf--5` | L | Wave 3 |
| `quality-perf--6` | L | Wave 1 + fold |
| `quality-perf--7` | L | Wave 1 + fold |
| `quality-secdrift--4` | L | Wave 3 |
| `quality-secdrift--5` | L | Wave 3 |
| `quality-tests--11` | L | Wave 2 |
| `quality-tests--12` | L | Wave 2 |
| `ux-copy--11` | L | Wave 2 |
| `ux-copy--7` | L | Wave 3 |
| `ux-error--5` | L | Wave 2 |
| `ux-error--6` | L | Wave 3 |
| `ux-parity--5` | L | Wave 2 |
| `ux-parity--6` | L | Wave 3 |
| `ux-parity--7` | L | Closeout pass (`1b12380`) |

---

## 1. The headline

Three things matter more than the rest of this document:

1. **Extension 0.19.0 is already in users' browsers, and no record says so.** Both stores serve it;
   the signed download manifest, the CHANGELOG, and the git tags all still say 0.18.0. Close this
   first — it is the difference between "we shipped a build" and "we can say what our users are
   running."
2. **Native ownership-transfer accept has never worked on a durable-cache client.** A four-column
   omission in the SQLite cache means Android and desktop show the consent screen and then fail the
   tap, 100% of the time. It survived because every transfer test runs on the in-memory cache.
3. **The release gate does not cover the desktop app at all** — not even compilation — and the
   shipped extension crypto engine is never asserted against the shared vectors. The gate being
   green has been telling us less than we thought.

Everything else is genuinely polish, and there is a lot of it worth doing.

---

## 2. Ship-blockers

Do these in the polish release. All are upheld by two independent refuters unless noted.

### 2.1 Finish the 0.19.0 release paperwork · `hygiene-release--0` · S

Live, verified 2026-07-27: the Chrome Web Store listing (item `ndhkgfgkbnfieehncjgegcjhfdbhmmbn`)
serves **0.19.0**; `/downloads/firefox-updates.json` advertises **0.19.0** and the linked xpi returns
HTTP 200 at 186 132 bytes, byte-size-identical to the local signed artifact built 07-26 11:31. Yet
`/downloads/manifest.json` is still seq 3 / `browserExtension 0.18.0`, `CHANGELOG.md:3` tops out at
"0.20.0 … extension 0.18.0", and no tag covers `59d523f`.

The runbook (`docs/runbooks/extension-store-publishing.md:208-215`) *mandates* the manifest re-sign
at publish time; it was skipped. There is no client-integrity risk — `background.ts:1371` only offers
an update when the manifest version is newer, so a validly-signed seq-3 manifest read by a 0.19.0
install just reports "up to date" — but the published record is wrong.

**Fix:** write the ext-0.19.0 CHANGELOG entry (use the established "fleet X, extension Y" wording to
dodge the existing `## 0.19.0 (2026-07-17)` fleet heading at `CHANGELOG.md:58`), re-sign
`/downloads/manifest.json` to `browserExtension 0.19.0` at seq 4, tag the release, and lift
`docs/design/2026-07-26-in-page-card-chip.md:3` out of "DRAFT — breaker review pending".

### 2.2 SQLite cache drops every vault lifecycle field · `bug-cache-lifecycle--0` · M

`WireVault` carries four additive lifecycle fields (`pendingTransfer`, `lastTransfer`,
`restoreProof`, `deleteId` — `Wire.kt:216-233`), but the durable cache's `vaults` table has five
columns, `upsertVault` writes five, and `vaults()` reconstructs the record with all four defaulted to
null (`SqliteVaultCache.kt:63-66,143-154`). There is **no in-memory vault map** in the SQLite impl,
so the fields are lost the moment a pull commits — in-session, not merely across restart. Both
natives use this cache by default (`offlineCacheAllowed` defaults true).

Consequences on Android and desktop:

- `acceptTransfer` reads `cache.vaults()…?.pendingTransfer` (`SyncEngine.kt:888`) → always null →
  throws 409 `transfer_not_pending`, **while the consent screen is on-screen** (that screen is fed by
  the separate in-memory `incomingByVault`). Accepting an ownership transfer always fails.
- The owner's "Ownership offer to …" chip never renders (`pendingTransferFor`, `SyncEngine.kt:793`).
- `offerTransfer` computes `seq = lastTransfer.seq + 1` from the dead read → always 1, while the
  server relays `transferSeq + 1` and the proof HMAC binds the client's seq. On any vault with one
  completed transfer the target's verification silently fails and **the offer never surfaces
  anywhere** until its 14-day expiry — the owner meanwhile got a 201 and believes it went out.

Origin: the v2 migration (`2006826`) added `held`/`consumed_delete_ids`/`transfer_seq`/`queue.staged`
and forgot to widen `vaults`. The web twin (`idbcache.ts:656-659`) persists the whole object, so web
is unaffected.

**Fix:** a v3 migration. Prefer a single `wireJson TEXT` column holding the full `WireVault` (the
pattern `putHeld` already uses, and future-proof against the next additive field) over four typed
columns. No backfill is possible — rows self-heal on the next delivery. Pair with §2.3.

### 2.3 `hydrate()` never rebuilds incoming-transfer state · `bug-cache-lifecycle--1` · S

`incomingByVault` is populated only inside `applyTransferState`, which runs only over rows *delivered
in a pull*. `SyncEngine.hydrate` (`:306-329`) rebuilds grants, envelopes and staged denials but never
touches transfer state, and a pending-offer row is not re-delivered while the offer simply pends.
**The web store has the identical gap** (`store.ts:1125-1160`): reload a tab mid-offer and the consent
banner is gone until the owner cancels or re-offers. Fixing §2.2 alone still loses offers on restart.

**Fix:** at the end of `hydrate()`, loop `cache.vaults()` through `applyTransferState(v, noticeable = false)`
— already idempotent per row. Mirror in `web/src/vault/store.ts`.

### 2.4 TOTP re-enrollment has no current-code gate · `bug-server--0` · M

`totpDisable` requires a valid current code before clearing the factor (`Service.kt:354-357`), but
`totpSetup` overwrites `totpPendingSecret` unconditionally on an **already-enrolled** account
(`:336-342` — it reads the user row only to build the otpauth label, never inspecting `u.totpSecret`),
and `totpConfirm` validates against the *pending* secret then writes it over the live one
(`:344-352`). So the guard `totpDisable` enforces is trivially bypassed by rotating instead of
disabling. Both routes are plain `requirePrincipal` and are on the restricted-session allowlist.

**Fix:** in `totpSetup`, when `u.totpSecret != null`, require a valid current code — reuse
`verifyTotpCode` plus the guarded `totpLastStep` consume from the login path so the rotation code
cannot be replayed. Accept the existing `TotpCodeRequest` as an optional body and answer 400
`totp_code_required`; audit it as its own `totp_rotate` type. Add the server test — there is currently
none for TOTP setup on an enrolled account (`quality-tests--6`).

### 2.5 Login dropdown opens on checkout card fields · `bug-autofill-ux--0` · M

This is the owner-reported 2026-07-26 checkout failure, root-caused. On a checkout whose CVV is a
hintless `<input type=password name=cvv>`, the extension's login classifier returns `password`
unconditionally (`extension/src/urimatch.ts:144-145`), while the canonical vector says that exact
signal is `cc-csc` and the Kotlin core demotes it *field-locally* before the password rule
(`FieldClassifier.kt:191`). The extension demotes only at form level inside `buildCardForm`
(`detect.ts:707`), which the login view never consults. Picking a credential fills vault
username/password into CVV and expiry boxes. Android and core are clean.

**Fix:** at the surface layer, **not** in `classify()` (its login vectors are byte-frozen and shared
with web). In `maybeOpen` (`content.ts:686`), after resolving the form, return early when the target
is a card-form member or the form's own password field on a suppressed-save form. Pin it in the
existing extension-pins suite.

### 2.6 Idle autolock is indefinitely deferrable by any web page · `bug-ext-gating--0` · S

`background.ts:1411` re-arms the idle autolock for every message not in `PASSIVE_MSGS`, and
`armAutoLock` overwrites the alarm each call. Two non-passive messages are entirely page-driven:
`matches` (reached via a `focusin` listener gated only on `e.isTrusted` — and `HTMLElement.focus()`
fires a *trusted* focusin, which the repo states itself at `background.ts:127-130`) and `pendingSave`.
A page that refocuses one field every ~500 ms holds the vault unlocked forever. This is the same
vector class the chip commit closed for `cardChipOffer` via `[K13]`.

One refuter corrected the mechanism: it is *easier* to trigger than the finding claimed (a single
field refocused defeats the 400 ms per-input dedupe; no two-input alternation needed), but
`pendingSave` is sent once per top-frame load, not re-fired from the mutation path. Severity settles
at medium-to-high; the fix is one line either way.

**Fix:** add `"matches"` and `"pendingSave"` to `PASSIVE_MSGS` and extend the `[K13]` comment. Real
activity still re-arms via `reveal`, `allItems`, `capturedCredential`, `resolvePendingSave`,
`generate`, `linkUri`, `openPopupForCards` and every popup action. Extend the existing pin at
`web/src/extension-pins.test.ts:536-543`.

### 2.7 The release gate skips the desktop app entirely · `quality-tests--0` · S

`scripts/verify.sh:24-34` runs core, server, recovery-cli, android, web and extension — and **no
`:app-desktop` target at all**, not even a compile. Desktop has three real suites (including
`EndpointSwitchTest`, which stands up an actual header-capturing HTTP server to prove token
isolation) whose results XML is dated 2.5 days before HEAD. "verify.sh is green at HEAD" has been
saying nothing about desktop. The house has already been burned by this exact hole
(`docs/PLAN-autonomous-2026-07.md:61`).

**Fix:** add `:app-desktop:test` to the flock'd gradle line. One line, ~1–2 min of gate time.

### 2.8 The shipped extension crypto engine is never vector-asserted · `quality-tests--1` · S

`extension/src/crypto.ts` — the @noble code that must decrypt items encrypted by the Kotlin/libsodium
clients — is asserted by no vector test in any default gate. The extension suite checks only the four
fence *numbers* and same-engine round-trips. The one byte-parity proof,
`web/src/crypto/noble-extension-poc.test.ts`, is `skipIf(!EXT_POC)` and `verify.sh` sets no env, so it
**runs never**, and its skip comment ("no extension consumer") is stale.

**Fix:** add `extension/src/crypto.vectors.test.ts` asserting `deriveMasterKey` against `kdf.json` and
envelope open/seal against `envelope.json`/`wrap.json`/`seal.json`. Keep the 64 MiB argon case behind
`package.mjs` if it is too slow for every run. Fix the stale comments while there.

### 2.9 Invite email still instructs a network that no longer exists · `ux-copy--1` · S

Every new member's first contact with the product: "Open this link on the **same network as the app**
to create your account" (`InviteEmailBody.kt:54-55` plain text, `:87` HTML). The 0.19.1 copy sweep
touched clients only; server email copy was never swept. On the public reference instance the
sentence is simply false.

**Fix:** "Open the link below to create your account." — optionally with the hedge already used by the
UNREACHABLE twin: "(if your household's server is private, open it from a device that can reach it)".

### 2.10 Desktop leaks raw exception text · `ux-error--0` / `ux-copy--0` · S

Six sites render server-controlled `t.message` straight into the UI — `DesktopState.kt:2341, 2396-2398,
2420, 2467, 2583, 2616` (TOTP status, TOTP ops, backup/CSV sync-preflight, backup run, export run).
These bypass `op()`, whose own `#23` comment claims "the `t.message` fallback is gone for good", and
violate the `HouseholdCopy` house rule that no mapper ever returns `t.message`. Android's twins route
through the canon. One refuter downgraded to medium (the repo's own #23 audit classed the identical
defect as Medium, and these are low-traffic surfaces) — the fix is unchanged.

**Fix:** route all six through `HouseholdCopy::forError`.

### 2.11 Web and extension sign-out never revoke the server session · `bug-web--0` / `quality-deadcode--0` · M

`ApiClient.logout()` exists (`web/src/api/client.ts:319-320`) and has **zero call sites**; the
extension has no logout at all. All three web sign-out paths and the extension's
`doSignOut → doLock("signout")` do only local teardown. Meanwhile `spec/03-wire-protocol.md:132`
mandates that logout revokes the device session, and **both natives already do it** with a 5 s bound
and comments naming the "~30 days" consequence — commit `2725617` shows the project classified this
exact behavior as a bug and fixed it on Android and desktop only.

Refuters corrected severity from high to **medium**: sign-out does clear the token pair locally, so
the lingering session is only exploitable by an attacker who exfiltrated tokens beforehand, it yields
ciphertext under the ZK model, and admin device-revoke exists as a compensating control. Still a real
parity gap, and scope is **web + extension**, not web-only.

**Fix:** call the existing `logout()` on the destructive path in both, mirroring the natives'
best-effort bounded pattern. Do **not** add it to lock — lock deliberately keeps the session.

---

## 3. Experience polish

The cross-platform parity and copy work is where a polish release earns its name. Highlights from
`ux:parity` (9), `ux:copy` (13), `a11y:webext` (13), `a11y:native` (11), `ux:error` (7):

**Parity divergences with no platform reason.** One-tap Generate silently replaces an existing
password on desktop and Android while web deliberately confirms. Sign-out confirmation diverges three
ways — the extension is a one-click unconfirmed full wipe. Extension popup lists render in wire order
while every other surface sorts alphabetically. Desktop's 426 update-required screen is a dead end;
the sign-out escape shipped on Android only. Re-copying the same secret truncates the disclosed
auto-clear window on both natives, already fixed on web and extension.

**Copy.** Beyond §2.9: admin invite-QR copy still says "tailnet" and "LAN address"; `INSTALL.txt`
ships inside every extension zip with pre-store beta-tester framing; the replay-denied lifecycle
notice drifted between web and the natives (each claims to mirror the other); the natives' TOTP setup
labels are the exact developer labels web's #23 sweep renamed; bad-code copy exists in four variants;
"contact your admin" vs "administrator" splits *inside the core canon itself*.

**Accessibility** — the largest untouched surface, and cheap to fix:

- Android has **zero IME actions** anywhere (`grep` for `ImeAction`/`keyboardActions` returns 0), so
  Done/Next never submits or advances any form, including the master-password field.
- Desktop has **zero live regions** (Android has 16 in `MainActivity` alone), so every error, notice
  and "copied" confirmation is silent to Windows screen readers. `docs/accessibility.md:100` already
  flags this as an open audit item.
- Android's `PrimaryButton` replaces its label with a bare spinner while busy, losing the accessible
  name; desktop's twin got exactly this fix (`a11ydesk-08`, `Ui.kt:3212-3214`). The autofill overlays
  have no live regions at all, so a wrong-master-password error is never announced.
- Web: Health table rows put `role="button"` + `aria-label` on `<tr>`, hiding all cell data from
  screen readers. The "pending sync" tag is hardcoded `#8a7a5c`, failing WCAG AA on both themes.
- Extension: in-page banners ignore Escape, have no role, and are reachable only at the end of the
  page's tab order; dropdown rows are mousedown-only, so an AT virtual cursor cannot pick a login —
  a bug the chip already fixed on its own surface.

**Failure experience.** Web clipboard copy fails as an unhandled promise rejection with no feedback
(`Vault.tsx:901-906`); desktop's are the only unguarded AWT clipboard calls (`Platform.kt:203,212` —
`setContents` throws on a busy Windows clipboard, and the surrounding cleaner already uses
`runCatching`); the import-failure catch-all promises "press Retry — no duplicates" for terminal
refusals on all three clients; and core's metaV anti-replay warning — a genuinely security-relevant
signal — goes to a bare `println` that no surface can see.

---

## 4. Structure and code quality

Not release-blocking, but this is the release to spend structural budget in.

**God-files.** `MainActivity.kt` 3 067 lines and `AndvariViewModel.kt` 3 015 (Android); `Ui.kt` 3 228
and `DesktopState` 3 054 with ~70 `mutableStateOf` fields (desktop); `background.ts` 3 117
(extension); `Vault.tsx` 2 307 (web); `Service.kt` 1 426 and `SyncEngine.kt` 1 387. These are the
direct cause of several findings above — the untestable seams, the ~25-field UiState reset duplicated
between `lock()` and `signOut()` (already drifted), the ~10 repeated layer-clearing clusters in
`Vault.tsx` with inconsistent membership. Extract leaves opportunistically alongside the fixes rather
than as a standalone refactor.

**Verified dead code** (each searched repo-wide, definition only): `web/src/vault/urimatch.ts:97`
`matchLogins`, `web/src/crypto/escrow.ts:30` `sealCanary`, `extension/src/totp.ts:45` `base32Encode`,
plus seven more. Note the care needed: each has a live twin elsewhere under the same name, so delete
by path, not by symbol. Also unused: server's `ktor-server-auth` + `ktor-server-rate-limit` (both
hand-rolled in-house) shipping in the fat jar.

**Duplication worth unifying:** three ~95%-identical banner builders in `content-ui.ts`;
`fmtDay` defined twice in web and twice again in desktop; hand-duplicated protocol types
(`BioReq`/`BioResult`) between background and connector **with real drift**.

**Performance** — only the user-feelable ones: web Trash is an N+1 (one sequential `itemVersions` per
deleted item, re-run in full after every restore/purge); the server heap-buffers every installer
download and SPA asset via `file.readBytes` per request; `content.js` sits at 84% of its 60 KiB
budget and the cap comment understates the number by 15 KiB.

---

## 5. Docs and public-repo credibility

The repo went public on 2026-07-17 and the docs never made the trip. This is the cheapest
high-visibility work in the release.

- **`README.md`** is still the homelab-era front door: wrong product description, two nonexistent
  paths, host-specific build instructions.
- **`extension/README.md`** is frozen at v0.6.1 — twelve releases stale — and claims a browser E2E
  harness that does not exist in-tree.
- **The store-facing privacy policy** still promises Tailscale-only communication. This one is
  user-facing and published on both stores.
- **`spec/00` and `spec/05` T2** describe the retired Tailscale-only topology, and `spec/02:398`
  contradicts shipped behavior — these are *normative* documents.
- **`docs/self-hosting.md:46`** tells prospective self-hosters "the source repo is private" — the
  exact inverse of the project's pitch.
- **`docs/ROADMAP.md`** cites a private, out-of-tree memory file as the state SSOT (line 4), presents at
  least four shipped items as open, and prescribes a retired release process.
- **20+ files, including normative `spec/03:535` and `spec/04` §4, reference `ops/` and
  `docs/{assess,pentest,recon,drills}/`** which do not exist here. A refuter corrected the mechanism
  and it matters: full git history (267 commits from the root) shows these directories were **never
  in this repository** — they are the private instance's out-of-tree area, referenced back when the
  repo was household-private. So this is reference rot to retarget or drop, not a scrub to reverse.
- **`v6-backlog.md:145` F30** (refresh token in localStorage) is a signed-off accepted risk whose
  stated premise — "not worth M for a tailnet-only household" — was invalidated by the public pivot.
  Its own revisit trigger ("if the web client ever goes public") has fired. Re-decide and record.
- **Test-vector provenance is overstated:** `README.md:24` and `spec/00:7-9` say vectors are emitted
  by `tools/vector-gen`, but 6 of 22 are not (`card`, `cardfill`, `cardform`, `enrolllink`,
  `import-foreign`, `urimatch-etld1`). Add a provenance note per file.

**Release hygiene:** `verify.sh`'s version gate covers only four fleet literals — the extension trio,
the CHANGELOG heading and `web/package.json` (a never-maintained `0.0.1`) escape it. `dist/` is
2.1 GB of 44 append-only artifacts including a 114 MB ceremony tar; `extension/artifacts/` holds 51
files back to 0.6.1 with byte-identical duplicate names per release.

---

## 6. Suggested release shape

A defensible 0.21.0 / ext 0.20.0:

1. **Paperwork first** (§2.1) — before any code, so the baseline is knowable.
2. **Correctness lane:** §2.2–2.6, §2.11. Each is small and independently testable; the cache
   migration is the only one needing a schema bump.
3. **Gate lane:** §2.7–2.8 plus the Android pure-gate tests (`quality-tests--3`, corrected to medium:
   about half the listed functions are security-relevant, the rest cosmetic). Do this lane *early* so
   the rest of the release ships behind a gate that means something.
4. **Copy + a11y sweep:** §2.9, §2.10, and §3. High user-visible value per hour, low regression risk,
   and the byte-twin discipline already has pins to extend.
5. **Docs sweep:** §5. Independent of all code work — parallelizable.
6. **Opportunistic structure:** §4, only in files the lanes above already touch.

Defer: god-file decomposition as a standalone project, the E2E harness the extension README claims,
and every §7 item.

---

## 7. Do-not-chase ledger

Recorded so a future review does not re-find them.

- **"The in-page card chip is untested" — REFUTED (both lenses).** The chip *is* pinned: a dedicated
  `C1 in-page card chip pins` describe block in `web/src/extension-pins.test.ts` (~10 tests) covers
  the `cardChipOffer` gate, frame-0 strictness, mid-nav refusal, throttle, the zero-data render
  surface, single-`attachShadow`, verbatim copy, and `PASSIVE_MSGS`/`[K13]` membership — and
  `verify.sh` runs it. The reviewer grepped only `extension/src/*.test.ts` and missed the documented
  house pattern (stated verbatim at `web/src/extension-pins.test.ts:21-27`) that extension invariants
  are pinned from the web vitest suite. **Lesson for future reviewers: extension coverage does not
  live in the extension.**
- **"`publish-extension.sh` arms the Firefox channel on every sign" — REFUTED / corrected to low.**
  The emission is real and ungated, but it lands in a local gitignored artifacts dir that nothing
  serves or syncs; hosting is a separate documented manual step. Emission-on-sign *is* the designed
  contract (the runbook says the operator hosts the xpi "along with the firefox-updates.json the
  script emits"). Critically, this was **not** the cause of §2.1: that was a deliberate dual-channel
  publish — the same run pushed Chrome live too — that skipped the paperwork ritual. Gating the
  emission would not have prevented it.
- **Five mapper observations were not real cross-platform divergences** and were refuted in-lane
  (`ux-parity--8` carries the ledger).
- **Not defects, deliberate and pinned:** the `LEGACY_*` match-targets; core's
  `UriMatch.normalizeHost` vs `CsvImport.nameFallback` host-extraction split (documented divergence);
  the extension/core `MIN_SEQ` 0-vs-1 asymmetry; `matches` being classified as re-arming activity was
  documented — though §2.6 still holds, because the *comment* is about intent and the *vector* is
  page-driven.
- **No unused CSS classes, no commented-out code blocks, and all extension deps are used** — swept
  and clean.

---

## 8. Method, coverage, and limits

**Phase 1 — map (9 agents).** One reader per module (core, server, android, desktop, web, extension)
plus docs/spec, an open-items sweep, and release hygiene. Produced architecture maps, key-file
indexes, and 200+ leads.

**Phase 2 — review (16 lanes).** Correctness (cache/lifecycle, server, extension gating, autofill UX,
web), Experience (parity, copy, web+ext a11y, native a11y, failure UX), Quality (perf, tests, dead
code, post-audit security drift), Hygiene (docs, release). Each lane received its module map as leads
and was scoped to polish only. 152 findings, 148 self-rated confirmed.

**Phase 3 — adversarial verify (58 agents, 53 completed).** Every high finding faced two refuters with
different lenses — one re-deriving the mechanism from scratch, one hunting for evidence the behavior
is deliberate (spec, design doc, decision-ID comment, test pin) and scope-checking polish-vs-feature.
Mediums went to 12 batched skeptics. Default verdict on uncertainty was *refuted*.

**Limits, stated plainly:**

- Four medium batches and one high batch died mid-run (monthly spend limit; one API overload). Their
  findings were **not** dropped: 21 were re-verified inline against the tree by the orchestrator
  (marked `(inline)` in Appendix A). Three medium findings remain unverified —
  `bug-ext-gating--4` (biometric host-permission probe), `hygiene-docs--7` (compliance-review closure
  ledger), `hygiene-release--2` (release-ritual scripting) — treat them as reported, not confirmed.
- **The 72 low-severity findings were not put through the refute pass.** They are recorded as reported.
- No finding was fixed. Nothing in the repo was modified by this review except this document.
- Runtime verification was limited to reading code, running the node test suites, and read-only GETs
  against the live download channels. No device testing, no real-checkout E2E, no gradle runs.

---

## Appendix A — all 152 findings

Severity is post-refutation. Verdict `(inline)` = verified by the orchestrator after its agent batch
died. `UNVERIFIED` = reported by the review lane, not put through the refute pass (all lows, plus the
three named in §8).
| # | Sev | Effort | Verdict | Finding | Primary file |
|---|-----|--------|---------|---------|--------------|
| 1 | H | M | UPHELD | Login dropdown opens on checkout card fields; a pick fills vault credentials into CVV/expiry boxes (extension-only; Android/core are clean) | `extension/src/content.ts` |
| 2 | H | M | UPHELD | SqliteVaultCache drops all four WireVault lifecycle fields — native ownership-transfer accept is broken outright, not just across restart | `core/src/jvmShared/kotlin/io/silencelen/andvari/core/client/SqliteVaultCache.kt` |
| 3 | H | S | UPHELD | Idle autolock is indefinitely deferrable by any web page — `matches` and `pendingSave` re-arm the lock on page-driven traffic | `extension/src/background.ts` |
| 4 | H | M | UPHELD | TOTP re-enrollment has no current-code gate, defeating the guard totpDisable enforces | `server/src/main/kotlin/io/silencelen/andvari/server/Service.kt` |
| 5 | H | M | UPHELD | Web and extension sign-out never revoke the server session (desktop/android do) | `web/src/api/client.ts` |
| 6 | H | S | UPHELD | README.md is the homelab-era front door: wrong product description, two nonexistent paths, host-specific build section | `README.md` |
| 7 | H | S | UPHELD | extension/README.md frozen at v0.6.1 (12 releases stale) and claims an E2E harness that does not exist | `extension/README.md` |
| 8 | H | S | UPHELD | Store-facing privacy policy still promises Tailscale-only communication | `docs/legal/privacy-extension.md` |
| 9 | H | M | UPHELD | ROADMAP self-contradicts (≥4 done items presented as open), leaks a private memory-file path, and prescribes a retired release process | `docs/ROADMAP.md` |
| 10 | H | S | UPHELD | spec 00 System shape + spec 05 T2 describe the retired Tailscale-only topology; spec 02:398 contradicts shipped web code | `spec/00-overview.md` |
| 11 | H | S | UPHELD | Ext 0.19.0 is live on every distribution channel with zero release paperwork | `scripts/publish-extension.sh` |
| 12 | H | S | UPHELD | verify.sh (the release gate) never runs — or even compiles — app-desktop; its 3 test suites last ran 2.5 days before HEAD | `scripts/verify.sh` |
| 13 | H | S | UPHELD | The shipped extension crypto engine (@noble) is never vector-asserted in any default gate — cross-engine byte parity rests on a skipped test with a stale rationale | `extension/src/crypto.ts` |
| 14 | H | M | CORRECTED | SqliteVaultCache drops WireVault lifecycle fields on the live row and the only lifecycle test rounds-trips them inside HeldVaultRecord JSON — the blind spot hides a real restart bug | `core/src/jvmShared/kotlin/io/silencelen/andvari/core/client/SqliteVaultCache.kt` |
| 15 | H | S | UPHELD | Invite email still says 'on the same network as the app' — tailnet-era instruction the 0.19.1 sweep missed | `server/src/main/kotlin/io/silencelen/andvari/server/InviteEmailBody.kt` |
| 16 | H | S | UPHELD | Desktop renders raw exception text in TOTP/backup/CSV-export failure paths, violating its own HouseholdCopy #23 canon | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/DesktopState.kt` |
| 17 | M | M | UPHELD (inline) | Android app has zero IME actions — keyboard Done/Next never submits or advances any form | `app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt` |
| 18 | M | S | UPHELD (inline) | Autofill overlay error text is never announced to TalkBack (and uses two different color tokens for the same error) | `app-android/src/main/kotlin/io/silencelen/andvari/app/autofill/AutofillUnlockActivity.kt` |
| 19 | M | S | UPHELD (inline) | Android busy buttons lose their accessible name — the a11ydesk-08 fix shipped on desktop only | `app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt` |
| 20 | M | S | UPHELD (inline) | Desktop has zero live regions — every error, notice, and 'copied' confirmation is silent to Windows screen readers | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt` |
| 21 | M | S | UPHELD | In-page save/card/link banners: Escape does nothing, no role, buttons only reachable at the end of the page's tab order | `extension/src/content-ui.ts` |
| 22 | M | S | UPHELD | Dropdown rows are mousedown-only — AT virtual-cursor activation cannot pick a login, though the chip fixed this exact bug | `extension/src/content-ui.ts` |
| 23 | M | S | UPHELD | Health table rows carry role="button" + aria-label on <tr>, hiding all cell data from screen readers and breaking table semantics | `web/src/ui/Health.tsx` |
| 24 | M | S | UPHELD | "pending sync" tag renders in hardcoded #8a7a5c that fails WCAG AA on both themes and is invisible to the contrast test suite | `web/src/ui/Vault.tsx` |
| 25 | M | S | UPHELD | matches and pendingSave re-arm the idle autolock from page-driven paths — the exact vector [K13] closed for cardChipOffer is open for the login dropdown | `extension/src/background.ts` |
| 26 | M | S | UPHELD | hydrate() never recomputes incoming-transfer state from cached rows — verified offers vanish on restart/reload in BOTH engines | `core/src/commonMain/kotlin/io/silencelen/andvari/core/client/SyncEngine.kt` |
| 27 | M | M | UPHELD | Zero test coverage for the exact seams that broke: cache round-trip of lifecycle-populated vault rows, and engine-level transfer actions | `core/src/jvmTest/kotlin/io/silencelen/andvari/core/client/VaultCacheContractTest.kt` |
| 28 | M | M | UPHELD (inline) | Any frame can forge a login capture (`submit` listener is un-isTrusted-gated on a false premise) and squat the tab's single pending-save slot, suppressing the real Save banner | `extension/src/content.ts` |
| 29 | M | S | UPHELD (inline) | pendingSave / resolvePendingSave / resolvePendingCardSave are tab-scoped but not frame-scoped, and the offer is broadcast to every frame | `extension/src/background.ts` |
| 30 | M | M | UNVERIFIED | Biometric quick unlock: the design-mandated host-permission probe was never implemented, and the popup probes the wrong capability — failures surface as a permanent, wrong "Setup was cancelled" | `extension/src/connector.ts` |
| 31 | M | M | UPHELD | A push batch that throws later rolls back its push_denied audit rows while the Loki line stands — denied-write evidence is suppressible | `server/src/main/kotlin/io/silencelen/andvari/server/Service.kt` |
| 32 | M | S | UPHELD | HIBP relay has no request timeout and reports upstream failures as 400 — a hung upstream wedges the browser breach scan forever | `server/src/main/kotlin/io/silencelen/andvari/server/Hibp.kt` |
| 33 | M | S | CORRECTED | PUT /account/password has no rate bucket, unlike the sibling route doing the same argon2 verify | `server/src/main/kotlin/io/silencelen/andvari/server/App.kt` |
| 34 | M | S | UPHELD | Health view shows stale rows during live sync — memo keyed on never-changing [store] | `web/src/ui/Health.tsx` |
| 35 | M | S | UPHELD (inline) | v6-backlog: F30 accepted-risk premise invalidated by the public pivot; MSI-1 and F49 rows never closed | `docs/v6-backlog.md` |
| 36 | M | S | UPHELD (inline) | CHANGELOG has no ext-0.19.0 entry and the chip design doc still says DRAFT — release-hygiene debt the polish release inherits | `CHANGELOG.md` |
| 37 | M | S | UPHELD (inline) | Test-vector provenance overstated: 6 of 22 vector files have no generator, no manifest says which is which | `spec/test-vectors/` |
| 38 | M | M | CORRECTED | 20+ files, including normative spec 03/04, reference directories scrubbed at the public flip | `spec/03-wire-protocol.md` |
| 39 | M | S | UPHELD (inline) | self-hosting.md claims the source repo is private — inverts the public-flip trust story | `docs/self-hosting.md` |
| 40 | M | M | UNVERIFIED | Compliance review published with an unresolved-looking HIGH and no closure ledger | `docs/compliance/2026-07-15-compliance-review.md` |
| 41 | M | M | UPHELD | Extension store-publishing runbook: stale artifact versions and household/Tailscale listing copy that seeds the live store listings | `docs/runbooks/extension-store-publishing.md` |
| 42 | M | S | UPHELD | INSTALL.txt shipped in every extension zip still frames sideload-from-disk as the product | `extension/INSTALL.txt` |
| 43 | M | M | UNVERIFIED | Release ritual is ~13 un-scripted steps whose glue lives in operator memory | `scripts/verify.sh` |
| 44 | M | S | UPHELD (inline) | verify.sh version gate covers only 4 fleet literals; extension trio, CHANGELOG heading, and web/package.json escape it | `scripts/verify.sh` |
| 45 | M | S | UPHELD (inline) | Public docs reference private-era paths that do not exist in the OSS tree | `README.md` |
| 46 | M | S | UPHELD (inline) | Artifact directories are unbounded append-only logs (2.1 GB dist/, 51-file extension/artifacts/) | `dist/` |
| 47 | M | S | CORRECTED | ApiClient.logout() has zero call sites — sign-out never revokes the server session | `web/src/api/client.ts` |
| 48 | M | M | CORRECTED | Android lock()/signOut() duplicate a ~25-field UiState reset, and signOut has already drifted | `app-android/src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt` |
| 49 | M | M | UPHELD | Three ~95%-identical banner builders in extension content-ui.ts | `extension/src/content-ui.ts` |
| 50 | M | S | UPHELD (inline) | Ten dead public symbols across web/extension/core/server (all verified zero-reference repo-wide) | `extension/src/totp.ts` |
| 51 | M | S | UPHELD | Extension hand-duplicates protocol types with real drift: BioReq/BioResult (background vs connector) and six seam unions (errors.ts vs messages.ts) | `extension/src/background.ts` |
| 52 | M | S | UPHELD | Vault.tsx layer-clearing setState cluster repeated ~10 times with inconsistent membership | `web/src/ui/Vault.tsx` |
| 53 | M | S | UPHELD | Web Trash: sequential per-item itemVersions N+1, re-run in full after every restore/purge | `web/src/vault/store.ts` |
| 54 | M | S | UPHELD | Server heap-buffers every installer download and SPA asset (file.readBytes per request) | `server/src/main/kotlin/io/silencelen/andvari/server/App.kt` |
| 55 | M | S | CORRECTED | Page-forced focus loop defers the idle autolock indefinitely via `matches` — the exact vector the chip commit closed for `cardChipOffer` and left open next door | `extension/src/background.ts` |
| 56 | M | S | UPHELD (inline) | Chip gate throttle replays a stale `fillable:true` across a top-level navigation, voiding the [S2] mid-nav guard | `extension/src/background.ts` |
| 57 | M | S | UPHELD (inline) | `resolvePendingCardSave` is not frame-gated — any frame in the tab can commit or silently dismiss the top frame's pending card save | `extension/src/background.ts` |
| 58 | M | S | UPHELD (inline) | `.chip`'s fixed 46 px height cannot hold the two lines its own comment promises — the locked sentence spills outside the pill and makes the hit-testable region state-dependent | `extension/src/content-ui.ts` |
| 59 | M | S | UPHELD | Three hand-synced Android browser allowlists (core BrowserCertPins ↔ manifest <queries> ↔ autofill_service.xml compat list) have no lockstep assertion | `app-android/src/main/AndroidManifest.xml` |
| 60 | M | S | CORRECTED | Android's extracted-for-testability security gates have zero tests: isFreshPure, clampAutoLockSeconds, enrollReady, cardExpiryBlocked/Assist, effectiveSignupMode, importFormatLabel | `app-android/src/main/kotlin/io/silencelen/andvari/app/QuickUnlock.kt` |
| 61 | M | M | UPHELD | Desktop's async DesktopState flows have zero executed coverage — the QueueDispatcher deliberately never runs coroutines — and Ui.kt (3,228 lines) has none at all | `app-desktop/src/test/kotlin/io/silencelen/andvari/desktop/EndpointSwitchTest.kt` |
| 62 | M | S | UPHELD | No server test covers TOTP setup on an already-enrolled account — and the untested path is a real guard bypass | `server/src/main/kotlin/io/silencelen/andvari/server/Service.kt` |
| 63 | M | S | UPHELD | Vector provenance gap: 6 of 22 vector files are not emitted by tools/vector-gen, three carry no provenance note, and README/spec 00 overstate the generator's coverage | `tools/vector-gen/src/main/kotlin/io/silencelen/andvari/tools/vectorgen/Main.kt` |
| 64 | M | S | UPHELD | The E2E layer is manual-only and decaying: e2e.sh is just an echo-suggestion in verify.sh, recovery-drill.sh is non-executable and cites a scrubbed doc, and 3 web suites skip silently | `scripts/e2e.sh` |
| 65 | M | L | UPHELD | Extension surface wiring (~7.1k lines across background/content/content-ui/popup/connector/offscreen) has zero tests, and README claims a headless-Chromium E2E harness that does not exist anywhere in the repo | `extension/src/background.ts` |
| 66 | M | S | CORRECTED | Desktop still renders raw exception text in six sites, violating the #23 canon it documents | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/DesktopState.kt` |
| 67 | M | S | UPHELD | Web leaks raw wire text in three Vault.tsx catches (413 upload, MoveCopy 403, escrow re-seal) | `web/src/ui/Vault.tsx` |
| 68 | M | S | UPHELD | replay-denied lifecycle notice drifted between web and the natives — each side claims to mirror the other verbatim | `web/src/ui/Vault.tsx` |
| 69 | M | S | UPHELD | Natives' TOTP setup labels are the exact developer labels web's #23 sweep renamed | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt` |
| 70 | M | S | UPHELD | Admin invite-QR copy still says 'tailnet' and 'LAN address' | `web/src/ui/Admin.tsx` |
| 71 | M | S | UPHELD | INSTALL.txt ships inside every extension zip with pre-store, beta-tester copy | `extension/INSTALL.txt` |
| 72 | M | M | UPHELD (inline) | Import confirm on all three clients promises "press Retry — no duplicates" for terminal refusals; both natives also swallow the 426 blocking-screen contract there | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/DesktopState.kt` |
| 73 | M | S | UPHELD (inline) | Web clipboard copy fails silently as an unhandled promise rejection — no feedback, no canon sentence | `web/src/ui/Vault.tsx` |
| 74 | M | S | UPHELD (inline) | Desktop clipboard writes are the only unguarded AWT clipboard calls — a busy Windows clipboard throws out of the Compose click handler | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Platform.kt` |
| 75 | M | S | UPHELD (inline) | Core's metaV anti-replay warning goes to println — invisible on every surface | `core/src/commonMain/kotlin/io/silencelen/andvari/core/client/SyncEngine.kt` |
| 76 | M | S | UPHELD | One-tap Generate silently replaces an existing password on desktop and Android; web deliberately confirms | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt` |
| 77 | M | M | UPHELD | Sign-out confirmation diverges 3 ways; extension is a one-click unconfirmed full wipe | `extension/src/popup.ts` |
| 78 | M | S | UPHELD | Extension popup lists render in wire order; every other surface sorts alphabetically | `extension/src/background.ts` |
| 79 | M | S | UPHELD | Billing ZIP forces a numeric keyboard on web AND Android for an explicitly alphanumeric value; desktop is plain text | `web/src/ui/Vault.tsx` |
| 80 | M | S | UPHELD | Desktop's 426 update-required screen is a dead-end; the A9 sign-out escape shipped on Android only | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt` |
| 81 | L | S | UNVERIFIED | Billing ZIP/postal field forces the numeric keyboard for a value the code itself declares alphanumeric | `app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt` |
| 82 | L | S | UNVERIFIED | Android vault search field is the only client whose search box has no programmatic name | `app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt` |
| 83 | L | S | UNVERIFIED | Desktop TotpRow missed both TOTP a11y fixes Android got: countdown re-announces every second, copy control is named by the secret digits | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt` |
| 84 | L | S | UNVERIFIED | Every Copy button is named just 'Copy' — indistinguishable per field to a screen reader | `app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt` |
| 85 | L | S | UNVERIFIED | Sharing-screen trash disclosure conveys its open/closed state by icon tint alone (P5) on both platforms | `app-android/src/main/kotlin/io/silencelen/andvari/app/SharingScreen.kt` |
| 86 | L | S | UNVERIFIED | maxLines=1 texts default to hard Clip (no ellipsis) — names shear mid-glyph at large font scale; Android vault tag also lacks desktop's width cap | `app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt` |
| 87 | L | S | UNVERIFIED | Vault list rows read decorative noise to TalkBack: the avatar initial duplicates the name's first letter and the trailing type tag can duplicate the subtitle | `app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt` |
| 88 | L | S | UNVERIFIED | Generated password in the popup is unreadable by screen readers — aria-label overrides the password text | `extension/popup.html` |
| 89 | L | S | UNVERIFIED | The ~6 s Argon2id unseal is silent for screen-reader users — busy state has no live region | `extension/src/popup.ts` |
| 90 | L | S | UNVERIFIED | In-page card chip has no keyboard activation path at all | `extension/src/content-ui.ts` |
| 91 | L | S | UNVERIFIED | Live-region ordering rule (popup.ts a11y 2a) is violated by options.ts setMsg and popup renderUpdate — first message risks being dropped | `extension/src/options.ts` |
| 92 | L | S | UNVERIFIED | Popup login rows nest interactive buttons inside a role="button" div; #server-origin puts aria-label on a generic span | `extension/src/popup.ts` |
| 93 | L | S | UNVERIFIED | Web TOTP chip bakes the live code into its accessible name and hides the countdown from AT — opposite of the extension's own documented pattern | `web/src/ui/Vault.tsx` |
| 94 | L | S | UNVERIFIED | Options trust gate drops keyboard focus to <body> on Cancel and on successful Connect | `extension/src/options.ts` |
| 95 | L | S | UNVERIFIED | Connector WebAuthn window never manages focus, and the 900 ms success auto-close can cut off the SR announcement | `extension/src/connector.ts` |
| 96 | L | S | UNVERIFIED | Popup touch/click targets below the 24px WCAG 2.5.8 minimum: .link/.link.dim footer actions and TOTP chips | `extension/popup.css` |
| 97 | L | S | UNVERIFIED | Login dropdown lacks the chip's focusout dismissal — a script-driven focus move leaves a stale dropdown whose capture-phase arrow/Enter keys still act, and it can co-render with the card chip | `extension/src/content.ts` |
| 98 | L | S | UNVERIFIED | `allItems` returns the entire login inventory to any content frame — an undocumented accepted exposure, not a documented one | `extension/src/messages.ts` |
| 99 | L | S | UNVERIFIED | Item restore/purge routes skip both the rate bucket and the version gate their siblings carry | `server/src/main/kotlin/io/silencelen/andvari/server/App.kt` |
| 100 | L | S | CORRECTED | RateLimiter's windows map never evicts — the only unbounded in-memory map left in the module | `server/src/main/kotlin/io/silencelen/andvari/server/RateLimiter.kt` |
| 101 | L | M | CORRECTED | PUT /escrow/self replaces the org recovery backstop with only a session, while the sibling recovery-write route requires a password re-auth | `server/src/main/kotlin/io/silencelen/andvari/server/App.kt` |
| 102 | L | S | UNVERIFIED | Netty request-read timeout still defaults OFF pending a check whose prerequisite shipped; response-write timeout is documented nowhere | `server/src/main/kotlin/io/silencelen/andvari/server/Config.kt` |
| 103 | L | S | UNVERIFIED | envLint validates numeric env vars more loosely than fromEnv parses them, so a lint-clean value can still crash boot or land a nonsense setting | `server/src/main/kotlin/io/silencelen/andvari/server/Config.kt` |
| 104 | L | S | UNVERIFIED | revokeDevice on an unknown deviceId writes a phantom audit row and answers ok | `server/src/main/kotlin/io/silencelen/andvari/server/AdminService.kt` |
| 105 | L | S | UNVERIFIED | Two /api/v1 error responses sit outside the house ApiError taxonomy | `server/src/main/kotlin/io/silencelen/andvari/server/App.kt` |
| 106 | L | S | UPHELD | mustChange banner navigation misses three layers — stale invisible layer eats a Back press | `web/src/ui/Vault.tsx` |
| 107 | L | S | UNVERIFIED | TrashView doc comment claims 'retention is unbounded' — false; server purges at 30 days and the UI copy is correct | `web/src/ui/Vault.tsx` |
| 108 | L | S | UNVERIFIED | Trash loads with one sequential itemVersions round trip per deleted item | `web/src/vault/store.ts` |
| 109 | L | S | UNVERIFIED | TOTP-setup clipboard no-auto-clear is deliberate cross-platform design, not a bug — but web lacks the documenting comment and error handling | `web/src/ui/Settings.tsx` |
| 110 | L | S | UNVERIFIED | Trash and ItemHistory render raw UTC ISO dates, off-by-a-day near midnight and off-idiom | `web/src/ui/Vault.tsx` |
| 111 | L | S | UNVERIFIED | Point-in-time internal docs sit unbannered beside living docs at docs/ top level | `docs/PLAN-autonomous-2026-07.md` |
| 112 | L | S | UNVERIFIED | web/package.json version is a never-maintained 0.0.1 | `web/package.json` |
| 113 | L | S | UNVERIFIED | 1.8 MB frontend-audit HTML twin tracked in the public repo | `docs/design/2026-07-12-frontend-ui-audit.html` |
| 114 | L | S | UNVERIFIED | LICENSING flip checklist carries an unchecked owner-decision box | `LICENSING.md` |
| 115 | L | S | UNVERIFIED | No CONTRIBUTING/verifier path for a repo whose pitch is 'audit us' | `README.md` |
| 116 | L | S | DISPUTED | publish-extension.sh arms the Firefox auto-update channel on every sign, ungated | `scripts/publish-extension.sh` |
| 117 | L | S | UNVERIFIED | Local clone's tag state is stale; tagging happens out-of-band from the build host | `scripts/verify.sh` |
| 118 | L | S | UNVERIFIED | Checksum story is inconsistent across artifact types and the SHA256SUMS file is mis-titled | `extension/artifacts/SHA256SUMS-0.20.0.txt` |
| 119 | L | S | UNVERIFIED | build.sh: dead v1-signature grep, hardcoded apksigner path, and latest.json triple-encodes the build instant | `scripts/build.sh` |
| 120 | L | S | UNVERIFIED | scripts/ dir hygiene: non-executable scripts and a stray __pycache__ | `scripts/recovery-drill.sh` |
| 121 | L | S | UNVERIFIED | Server micro dead code: two unused vaultUsers locals and a redundant sweepOrphans predicate | `server/src/main/kotlin/io/silencelen/andvari/server/Service.kt` |
| 122 | L | S | UNVERIFIED | timeoutSignal and UUID-regex each maintained as acknowledged twins | `web/src/api/client.ts` |
| 123 | L | S | UNVERIFIED | Core host-extraction duplication (UriMatch.normalizeHost vs CsvImport.nameFallback) is real but deliberately divergent and vector-pinned — full unification is the wrong fix | `core/src/commonMain/kotlin/io/silencelen/andvari/core/client/autofill/UriMatch.kt` |
| 124 | L | S | UNVERIFIED | Desktop menu ships a permanently disabled 'Sign out…' item — documented decision, polish candidate is to wire it, not delete it | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Main.kt` |
| 125 | L | S | UNVERIFIED | Refuted leads: no unused CSS classes, no commented-out code blocks, extension deps all used | `web/src/ui/styles.css` |
| 126 | L | S | UNVERIFIED | Unused dependency declarations: server ships ktor-server-auth + ktor-server-rate-limit in the shadowJar; web declares @noble/curves | `server/build.gradle.kts` |
| 127 | L | S | UNVERIFIED | fmtDay duplicated in web (Vault vs Sharing) and again in desktop (DesktopState vs Ui) | `web/src/ui/Vault.tsx` |
| 128 | L | S | UNVERIFIED | SyncEngine uses the magic string "(vault)" 9 times, once as a comparison sentinel | `core/src/commonMain/kotlin/io/silencelen/andvari/core/client/SyncEngine.kt` |
| 129 | L | S | UNVERIFIED | Android duplicated UI blocks: verbatim password-strength feedback and a drifted sign-out confirm dialog | `app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt` |
| 130 | L | S | UNVERIFIED | Web bundle is a single 1.44 MiB chunk (442 KiB gzip) fully re-downloaded every release | `web/vite.config.ts` |
| 131 | L | S | UNVERIFIED | content.js at 84% of its 60 KiB budget and the cap comment understates it by 15 KiB | `extension/package.mjs` |
| 132 | L | S | UNVERIFIED | Extension popup TOTP ticker: serial awaited message per chip, every second | `extension/src/popup.ts` |
| 133 | L | S | UNVERIFIED | Desktop: 1 Hz prefs.json read + full JSON decode while unlocked with no loaded policy | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/DesktopSession.kt` |
| 134 | L | S | UPHELD | RateLimiter.windows never evicts — unbounded per-key memory on a public instance | `server/src/main/kotlin/io/silencelen/andvari/server/RateLimiter.kt` |
| 135 | L | S | UPHELD | policy() re-reads the DB and re-decodes JSON on every access, including per-mutation inside the push tx | `server/src/main/kotlin/io/silencelen/andvari/server/Service.kt` |
| 136 | L | S | UNVERIFIED | The chip's SW-wake mitigation was specified but not built: the throttle is SW-side only, so a focus storm still costs one SW wake per field | `extension/src/content.ts` |
| 137 | L | S | UNVERIFIED | [K8]'s "one dismissal path" is untrue: three content-ui closes bypass content.ts's mirror, so a late offer can repaint a chip the user just dismissed | `extension/src/content-ui.ts` |
| 138 | L | S | UNVERIFIED | Stale meta-comments misdocument the safety net: extension-pins.test.ts claims the extension has no test harness; noble-poc claims no extension uses @noble | `web/src/extension-pins.test.ts` |
| 139 | L | S | UNVERIFIED | Assorted small verified gaps: AndvariApi.uploadAttachment's hand-rolled 401-retry is untested; selfhost caddy fixture missing from server test resources | `core/src/commonMain/kotlin/io/silencelen/andvari/core/client/AndvariApi.kt` |
| 140 | L | M | REFUTED | Extension 0.19.0 (in-page card chip) is staged and partially shipped — signed xpi built, firefox-updates.json advertising it — with ZERO automated coverage of any chip code | `extension/src/content-ui.ts` |
| 141 | L | S | UNVERIFIED | One shipped popup string capitalizes the brand: 'Andvari can't auto-fill payment forms…' | `extension/src/popup.ts` |
| 142 | L | S | UNVERIFIED | Android's duplicated sign-out confirm dialog drifted; desktop sides with one variant | `app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt` |
| 143 | L | S | UNVERIFIED | 'contact your admin' vs 'contact your administrator' split inside the core canon itself | `core/src/commonMain/kotlin/io/silencelen/andvari/core/client/HouseholdCopy.kt` |
| 144 | L | S | UNVERIFIED | Bad-TOTP-code copy exists in four variants; desktop re-types the canon constant as a string literal | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/DesktopState.kt` |
| 145 | L | S | UNVERIFIED | Import-result bucket copy for the same buckets diverges across the three importing surfaces | `web/src/ui/Vault.tsx` |
| 146 | L | S | UNVERIFIED | Apostrophe style is mixed inside single files, against the canon's ASCII convention | `extension/src/errors.ts` |
| 147 | L | S | UNVERIFIED | Android biometric hardware error during quick unlock is completely silent | `app-android/src/main/kotlin/io/silencelen/andvari/app/QuickUnlock.kt` |
| 148 | L | S | UNVERIFIED | Desktop TOTP row renders the literal 'invalid' as a copyable code with a live-looking 30s countdown | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt` |
| 149 | L | S | UNVERIFIED | Re-copying the same secret truncates the disclosed auto-clear window on both natives; web/extension already fixed this exact class | `app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Platform.kt` |
| 150 | L | M | UNVERIFIED | Same date-dialect split (curated "July 14" vs raw UTC ISO) repeated on all three full clients | `web/src/ui/Vault.tsx` |
| 151 | L | S | UNVERIFIED | Web's guided-import help table is a hand-synced twin of core ImportHelp with no lockstep pin | `web/src/ui/Vault.tsx` |
| 152 | L | S | UNVERIFIED | REFUTED LEADS (for the refuter's ledger): five mapper observations are not cross-platform divergences | `server/src/main/kotlin/io/silencelen/andvari/server/Janitor.kt` |
