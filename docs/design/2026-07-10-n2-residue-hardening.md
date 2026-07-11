# N2 — residue hardening batch (design, 2026-07-10)

Seven filed residue items, one cycle, one review, cut as **0.13.1** (hardening/honesty; no wire
change, no new feature surface). Ground truth for every item was re-verified against HEAD
`bd798b9` by a read-only survey before this design; file:line refs below are from that survey.

## Decisions (the short version)

| # | Item | Decision |
|---|---|---|
| 1 | core bare-426 | Drop the `resp.status.value == 426 ||` leg in `errorFrom` — only a body `error == "upgrade_required"` raises `UpgradeRequiredException`. Add the missing core test (both directions). |
| 2 | EnrollLink surrogates | Pin the well-formed astral case with new shared vectors; make BOTH twins **reject ill-formed UTF-16** (lone surrogates) in `compose` with a typed error. |
| 3 | native policy-fetch honesty | Mirror web's finished fix: `policyFetchFailed` flag + Retry on Android **and** desktop; the "no recovery key configured" text only renders after a *successful* fetch returned an empty fingerprint. |
| 4 | master-pw in `rememberSaveable` | Passwords OUT of the Bundle: `MainActivity.kt:423` (sign-in pw), `:444`/`:445` (enroll pw + confirm) → plain `remember`. All other form fields stay saveable. Item-editor secrets FILED, not built (below). |
| 5 | F49 janitor | Extend the sweep: sessions / changes+`oldestRetainedRev` / mutations / audit / invites / hibp_cache, retention constants below, dry-run-respecting, counts in `SweepResult`. Fix the stale header comment. |
| 6 | F22 / F26 | F22: **dropped with reason** — no native roster surface exists to badge; the only native consumer (transfer picker) already filters disabled. Re-surfaces inside N3 (desktop vault mgmt) if a roster is built. F26: plumb a `lockReason` line through both natives (strings pinned below). |
| 7 | web dead toast | **Lift** the post-delete toast to Sharing-level state keyed by vaultId (the existing A3 `copiedNote` pattern) and render it in the list branch. Content is genuinely useful (names the restore window + where). |

## 1. Bare-426 tightening (core; touches both natives)

`AndvariApi.kt:174-186`. Today ANY 426 — including a proxy/captive-portal 426 with a garbage
body — becomes `UpgradeRequiredException` → full-screen brick on Android + desktop. The server's
real pin always sends `ApiError("upgrade_required", …)` (`App.kt:197`), so the body check is
sufficient and the status-code leg is the hazard. Change:

- `errorFrom`: `if (err.error == "upgrade_required") return UpgradeRequiredException(…)` — the
  426 status alone no longer qualifies. Update the in-code comment to say why (intermediary
  426s must not brick the client).
- NEW core test (none exists today): bare 426 + non-JSON body → plain `ApiException` with
  `code == "http_426"`; 426 + `upgrade_required` body → `UpgradeRequiredException`; and (cheap
  extra) a 200-path sanity that `upgrade_required` in an error body on a NON-426 status still
  raises typed (the server contract allows the code to matter more than the status).
- **Noted, NOT built here:** web + extension have no 426 gate at all (`client.ts:84` comment is
  aspirational). Dormant until the owner ever sets a minVersion pin, and the web bundle is
  served by the same server (a reload heals). Filed for a later cycle: a small
  "reload to update" nudge on `upgrade_required` in web.

## 2. EnrollLink UTF-16 surrogate twin-pin (core + web twins + shared vectors)

Verified: no vector in `spec/test-vectors/enrolllink.json` exercises any astral-plane char, and
the twins genuinely diverge on **lone surrogates** in `compose` (Kotlin `encodeToByteArray()`
silently U+FFFD-replaces; ES2019+ `JSON.stringify` escapes as `\udXXX`) — identical input,
different links. Well-formed pairs (emoji) agree by construction but are unpinned.

- **Vectors:** add a `roundTrips` entry with an emoji (4-byte UTF-8) in the email and one in the
  token; add a `parse` vector whose b64 body carries raw 4-byte UTF-8. Both twin test files
  already iterate the JSON, so the pins are free once the rows exist.
- **Rejection:** `compose` in BOTH twins rejects ill-formed UTF-16 input with the same typed
  failure (Kotlin: `encodeToByteArray(throwOnInvalidSequence = true)` wrapped to the twins'
  error convention; TS: a lone-surrogate scan — do NOT rely on `String.isWellFormed`
  availability). Add a `composeRejects` section to the vector JSON pinned by both tests.
- **Call sites:** TS compose is called from `Admin.tsx` (Invite-with-QR) — wrap so a rejection
  surfaces as a friendly inline error, not an exception (defense in depth; a lone surrogate can
  round-trip JSON as `\udXXX`, so "server-validated email" is not a guarantee). Kotlin compose
  has no production caller today (native deep-link deferred) — verify and say so in the test.

## 3. Native policy-fetch-failure honesty + Retry (Android + desktop)

Web is the finished template (`App.tsx policyError` + `Welcome.tsx` Retry +
`errors.ts POLICY_UNAVAILABLE`). Natives today swallow the failure (`runCatching` with no
onFailure — `AndvariViewModel.kt:581`, `:617`; `DesktopState.kt:245`, `:540`) and then claim
"This server has no recovery key configured yet" — a lie that also silently disables the Create
button (`EnrollCeremony.ready` gates on the fingerprint), so the wrong message is the ONLY
feedback.

- Add `policyFetchFailed: Boolean` to Android `UiState` + desktop `DesktopState`.
- Set it on every policy-fetch failure path; clear it on success **and on any deliberate
  server-URL change**.
- Enroll rendering branches three-way: fetch failed → the web-parity message ("Couldn't load the
  server's settings — it may be briefly unavailable. Try again in a moment.") + a **Retry**
  button that re-runs the probe; fetch succeeded + fp empty → the current "no recovery key
  configured" text; fp present → the ceremony as today.
- Parity strings verbatim from `web/src/ui/errors.ts` — do not paraphrase.

## 4. Master password OUT of `rememberSaveable` (Android)

A password manager must not write master passwords into `savedInstanceState` — the Bundle is
system-managed plaintext that can be persisted to disk for activity recreation. The trade is
explicit: a fold/rotation mid-form now clears the password fields (re-typing a password is
annoying but safe; the enroll form's OTHER fields — email, invite, name, typed-fingerprint —
stay saveable, so the long form is not lost wholesale). Unlock (`:552`) is already plain.

- `MainActivity.kt:423` (SignInForm password), `:444` (EnrollForm password), `:445` (confirm) →
  `remember`. Update the adjacent comments — they currently argue FOR saveable; they must now
  state the Bundle-exposure rationale and the deliberate scope (secrets only).
- **FILED, not built (owner decision):** the item editor persists vault-item secrets via
  `rememberSaveable` (`:1139` password, `:1141` totp, `:1146` cardNumber) — same Bundle-exposure
  class, but it was a deliberate anti-data-loss call on the longest-typing surface, and flipping
  it is a UX regression the owner should weigh. Parked-for-owner list gets a line.

## 5. F49 janitor pruning (server)

The resync contract needed for `changes` pruning is FULLY BUILT on both sides (verified):
server `Service.kt:333` throws → 410 `resync_required` when `since < oldestRetainedRev`
(`App.kt:204`); client `SyncEngine` handles 410 → clears cache, full-pulls, PRESERVES the
offline queue (spec 03 §4; `VaultCache.kt:96,142`). The janitor extension:

| Table | Rule (v1) | Why safe |
|---|---|---|
| `sessions` | delete revoked > **90d** ago (+ expired > 90d if an expiry column exists — builder verifies schema) | rows are dead; rotation sets `revokedAt` (`Service.kt:250`) so rotated-away rows age out |
| `changes` | delete `rev < H` where H = the oldest rev younger than **90d**; **atomically** (same transaction) `UPDATE meta oldestRetainedRev = H` | the 410/resync contract makes an aged-out cursor a clean full-resync, never silent loss. If `changes` rows carry no timestamp, the builder derives H from the nearest timestamped source or SKIPS this table with a loud note — no guessing |
| `mutations` | delete > **180d** | dedup journal for lost-response retries; after 180d a replay of an already-applied push degrades to a rev-guard conflict copy (PDD-1 machinery), never silent loss. Generous window per the LC-1 lesson (parked devices replay) |
| `audit` | delete > **365d** | tamper-evidence also ships off-box (PROD-1 fix: logback → journald → Loki); local copy keeps a full year |
| `invites` | delete used > **30d** ago or expired > **30d** ago | dead rows; the admin UI lists only live invites |
| `hibp_cache` | delete rows not refreshed in **45d** | keyspace-bounded but stale; deletion forces a fresh HIBP fetch on next query — a correctness improvement, not just space |

- Retention values = named constants in `Janitor.kt` (no config sprawl); every rule respects
  `janitorDryRun`; per-table counts appended to `SweepResult` and logged.
- Fix the stale header comment (`Janitor.kt:6-8` still claims "NO item-tombstone GC", superseded
  by section (c)).
- Tests: JanitorTest rows-past-horizon deleted / rows-inside kept per table; the changes prune
  test MUST assert `oldestRetainedRev` advanced in the same sweep and that a pull with a
  pre-horizon cursor now 410s (wire the existing ResyncRequired path).

## 6. F26 lock-reason line (both natives; F22 dropped)

Reason strings pinned to web's exact copy (`App.tsx`): manual lock → **"Locked."**; idle/auto
lock → **"Locked after inactivity."** (native-only reason; web has no exact equivalent — this
one is new copy); session expired → **"Your session ended — sign in again."**; device revoked →
**"This device's access was revoked."**

- Android: `lockReason: String?` in UiState, set by `lock()` / idle-lock / the 401-driven
  sign-out paths (map revoked-vs-expired only if the path already distinguishes them — do NOT
  invent a distinction); rendered as a single quiet line on `UnlockScreen` (and the Welcome/
  sign-in screen for the signed-out cases, mirroring web).
- **Clear-the-flag rule (the 0.13.0 lesson):** `lockReason` clears on successful unlock AND on
  successful sign-in AND on any manual navigation away — a stale "revoked" line on a later
  ordinary lock is exactly the escape-hatch bug class this session already hit twice.
- Desktop: same shape in `DesktopState` + `Ui.kt` Unlock.

## 7. Web post-delete toast lift (Sharing.tsx)

The toast at `Sharing.tsx:648-650` never renders: `deleteSharedVault` hard-drops the vault from
the store before returning, so the same React commit unmounts `DeleteVaultControl` (settings
layer keys off `vaults.find(…)` → undefined). Lift per the in-file A3 precedent (`copying` /
`copiedNote`, `Sharing.tsx:40-46`):

- `deletedNote: {vaultId, name, purgeAt} | null` state at Sharing level; `DeleteVaultControl`
  gets an `onDeletedNote` callback instead of local toast state; render the note (same copy,
  same OK-dismiss) in the LIST branch, which stays mounted.
- Verify no interaction with the A2 effect that clears the stale settings id (it runs in the
  same commit — the note must live at the parent, not depend on `settingsVault`).

## Amendments (adversarial breaker pass, 2026-07-10 — 1 BLOCKER, 5 AMENDs; the rest held)

**B1 (BLOCKER, §5 changes prune):** `currentRev = MAX(rev) FROM changes` (Repo.kt:236-237) — the
prune as first designed could delete the MAX(rev) row on an idle server (no row younger than the
horizon), regressing `currentRev` to 0 and wedging every up-to-date client in `409
rev_regression` until the next write. The skipti lifecycle design already made this normative
("never delete the changes row carrying MAX(rev)", 2026-07-07 design §fence; spec 02 §7).
**Fix:** `H = min(oldest rev with at ≥ now − FENCE, MAX(rev))`; delete `rev < H`; when ALL rows
are stale, H = MAX(rev) (retain the newest row, prune below it). Tests MUST pin the idle-server
sweep: MAX row survives, `currentRev` unchanged, an up-to-date cursor pull is a no-op.

**A-fence (chosen alternative to recording a residual hole):** the fence horizon is **30d,
keyed to the item-tombstone purge horizon** — NOT 90d. Rationale: tombstones purge at 30d; with
a 90d fence a device offline 31–89d skips the 410 yet can never learn of deletions whose
tombstones purged — it displays deleted items forever (spec 02 §7 promises the fence prevents
exactly this). Fence-at-30d closes the window: any cursor older than the tombstone horizon
full-resyncs (410 → `sync(0)`, queue + holding preserved — contract verified built on both
sides). Cost: one cheap full pull for >30d-offline devices (household scale: trivial).
`changes` rows are never read for pulls (verified: only INSERT + MAX(rev)), so retention below
the fence serves nothing. Spec 02 §7's activation bullet is amended in this cut to record:
janitor advances `oldestRetainedRev`, invariant (a) floored at MAX(rev), fence = tombstone
horizon, quiet-server test exists.

**B2 (AMEND, sessions):** the design cited the wrong mechanism — rotation does NOT set
`revokedAt` (it stamps `refreshConsumedAt` + INSERTs a fresh row; Service.kt:276-292); a healthy
device accretes ~24 consumed-never-revoked rows/day, so delete-revoked-only prunes almost
nothing. **Mandatory rule:** delete WHERE `(revokedAt IS NOT NULL AND revokedAt < now−90d) OR
(refreshExpiresAt < now−90d)` (columns exist: Db.kt:113-115; an expired refresh chain is dead
regardless of consumed state). Known trade, accepted + recorded: a consumed token replayed >90d
after expiry now yields `invalid_refresh` instead of the `refresh_reuse` theft signal + device
revoke — the token is unusable either way.

**B3 (AMEND, §5 tests):** add the spec 02 §7 invariant-(d) quiet-server convergence test:
delete → idle past horizon → full janitor sweep → (i) up-to-date cursor pulls no-op (no
409/410), (ii) pre-fence cursor 410s → `sync(0)` converges, (iii) `currentRev` never regresses.
Plus the NOTE-8 boundary pin: cursor at H−1 → 410; at H → serves.

**B4 (AMEND, §3 flag semantics):** natives CANNOT copy web's hidden invariant (web nulls policy
on failure; natives must keep last-known policy — offline gates read it). Pin all four:
(1) render order fp-present FIRST (ceremony), then `policyFetchFailed` (retry message), then
the no-key text — web's actual order; (2) the flag is set ONLY by enroll-feeding fetches
(`start`, `setBaseUrl`/`updateServer`, the Retry action) — the unlocked 5-min background poll
does NOT touch it; (3) lock()/signOut() reset blocks CLEAR it (the escape-hatch lesson);
(4) the fourth state (`policy == null && !policyFetchFailed` = probe in flight) renders a
neutral checking/disabled state, never the no-key lie (Android's setBaseUrl probe is async
under a shown Welcome).

**B5 (AMEND, desktop):** `updateServer` (DesktopState.kt:259-262) stores the URL and re-probes
NOTHING — after a URL change the enroll gate verifies against the PREVIOUS server's recovery
key until restart. Add the policy probe to `updateServer` (mirror Android `setBaseUrl`,
including failure → flag). The direct policy setter at DesktopState.kt:335 is part of the flag
audit too.

**B6 (AMEND, §6 strings):** the "device revoked" string is UNREACHABLE on natives (no WS events
client; a dead access token is plain 401 `invalid_credentials`; refresh-failure bodies are
discarded). Natives use exactly three strings: "Locked." / "Locked after inactivity." / "Your
session ended — sign in again." The revoked string is reserved for web parity — do NOT invent
the distinction (two Android comments already bait it: QuickUnlock.kt:467, AutofillUnlock.kt:132).

**Folded builder notes (from the same pass):** janitor sweep = raw `c.exec` inside ONE `db.tx`;
NEVER `repo.setMeta` inside it (nested tx corrupts — Db.tx is not reentrant, the auditOn split
documents the hazard). Mutations >180d put-replay of a tombstone-PURGED item silently
resurrects it as `applied` (`existing == null` → clean INSERT) — same accepted class as
Repo.kt:451-453; one sentence + one test row pins it. hibp rationale corrected: reads already
ignore rows >7d (Hibp.kt:15) — the 45d deletion is space reclaim only. `composeRejects` vector
rows carry lone surrogates as `\udXXX` JSON escapes (raw ones aren't valid UTF-8), shape
`{name,o,t,e}`, new top-level section is additive for both loaders. The Admin.tsx guard also
CLEARS the minted-token panel on compose failure (`setResult` has already run by then;
precedent at Admin.tsx:328-330). §4's FILED editor list must include `:1149` cardSecurityCode
(CVV); the sign-in TOTP field (`:424`) stays saveable DELIBERATELY (30-second-lived code).
Android `lock()` takes a reason parameter (it serves manual, idle-expiry `:1142`, AND the
autofill-gate "locked underneath" branch `:1134-1139` — the last is idle-class); BOTH natives'
lock/signOut reset blocks add `lockReason = null` (desktop signOut today clears NO flags — do
not copy that precedent). Toast copy post-lift: "the trash icon above" (the user is already on
Sharing); clear `deletedNote` if that vault is restored while the note shows.

## Workstreams (disjoint file ownership)

- **WS-A (core + twins + vectors):** `core/.../client/AndvariApi.kt`, `core/.../client/EnrollLink.kt`,
  new/updated core tests, `spec/test-vectors/enrolllink.json`, `web/src/enroll/enrolllink.ts` +
  `enrolllink.test.ts`, the `Admin.tsx` compose call-site guard. (#1 + #2)
- **WS-B (Android):** `AndvariViewModel.kt`, `MainActivity.kt`. (#3 + #4 + #6 Android halves)
- **WS-C (desktop):** `DesktopState.kt`, `Ui.kt`. (#3 + #6 desktop halves)
- **WS-D (server):** `Janitor.kt`, `Repo.kt` (only if new queries need helpers), JanitorTest. (#5)
- **WS-E (web):** `web/src/ui/Sharing.tsx` only. (#7)

WS-A's Admin.tsx touch is the one cross-boundary file — it is NOT owned by WS-E (WS-E owns
Sharing.tsx only), so ownership stays disjoint.

## Gates + ship

`scripts/verify.sh` file-logged (`> log 2>&1; echo EXIT=$?`) + `:app-desktop:classes` by hand +
find→refute review before any cut. Version lockstep ×4 → 0.13.1. Server jar changes (janitor) →
snapshot-first deploy (`VACUUM INTO` script + integrity check + **vzdump** since the jar
changes), then web/server via `ops/deploy.sh`, APK via ship pipeline, deb + manifest MERGE.
Verify served bytes. Telegram statement after.
