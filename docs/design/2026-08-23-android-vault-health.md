# Android vault health — the phone finally reads what it writes

**Status:** DESIGN, owner-ratified 2026-08-23 (five forks answered inline below).
**Target:** 0.26.0.
**Ask it answers (owner, 2026-08-23):** "we have no way to view or utilize our health features in
the mobile release."

Companion it does not re-decide: `2026-08-22-login-health-staleness-verification.md`, whose §7
scoped the first cut to "web + extension assist" and promised Android "a read-only *Last checked*
on item detail in a later cut". This is that cut, and it is **more than read-only** — see §9.

---

## 1. The gap, as the tree actually has it

| Signal | Web | Android today |
|---|---|---|
| Per-item strength / reuse / TOTP | `healthRows` (`Health.tsx`) | **nothing** |
| Vault-wide HIBP breach scan | k-anonymity batched, `Health.tsx:scan` | **nothing** — `breachWarning` runs only on the MASTER password at enroll (`MainActivity.kt:316` `BreachAdvisoryBanner`) and on generator candidates (`:2786`) |
| Duplicate clusters + guided merge | `duplicates.ts` (349 ln) | **nothing** |
| Staleness ranking + verification run | `staleness.ts` (213 ln) / `Staleness.tsx` | **nothing** |
| `check` verdicts | sole writer | preserved losslessly via the extras overlay — **invisible and unwritable** |
| `dupeAck` dismissals | writer | same |
| Usage ledger "last used" | reads and writes | **writes only** |

**That last row is the one that decides this design's shape.** `UsageRecorder.kt` seals and PUTs a
usage ledger on every in-app copy — debounced 15 s, merged, batched exactly as spec 02 §8.2
requires — and the phone has no surface that has ever displayed a single byte of it. The device is
paying the full cost of the feature (crypto, network, a `usage_ledger` row) and receiving none of
its benefit. Shipping the write half without the read half was correct at 0.25.0, when the read
half did not exist on any native client; leaving it that way for a second release would not be.

**`ItemDetail` (`MainActivity.kt:1950`) shows no health signal of any kind.** `Strength` is
imported into that file and used four times — all four on the *master* password or a backup
passphrase, never on a vault item's password.

**Desktop is in the identical position.** `app-desktop/Ui.kt` has no health surface either. §9
scopes it.

## 2. What is already free, and why this is smaller than it looks

- **`core/client/Strength.kt` is already a complete twin of `web/src/ui/strength.ts`.** Same
  exported surface — `estimateStrength`, `entropyProxyScore`, `LABELS`, `patternWarning`,
  `hasPatternWeakness`, `meetsMasterPasswordFloor`, `masterPasswordHasNonAscii` — plus
  `breachCount`, which already does the k-anonymity dance over `AndvariApi.hibpRange`. The
  strength half of vault health needs **no port at all**, only call sites.
- **The usage ledger's native foundation is in:** `core UsageLedger` (merge/record/prune/parse/
  serialize, pinned by `UsageLedgerTest` against the exact JS wire shape), `Account.sealUsage/
  openUsage`, `AndvariApi.usage()/putUsage()`.
- **Every `check` and `dupeAck` ever written on web is already sitting intact in the phone's
  cached docs**, carried by `ExtrasOverlaySerializer` (`Account.kt:60`). Nothing has to be
  migrated or backfilled; the data is there, untyped.

So the work is the *pure logic* plus *a screen*, not plumbing.

## 3. Layer 1 — the core port (shared, and the bulk of the work)

Three TypeScript modules become Kotlin twins in `:core`, following the established
`VaultListView.apply` ↔ `web/src/ui/listview.ts` idiom: **pure, leaf-level, decided in core and
merely rendered by each client.**

| From | To | Carries |
|---|---|---|
| `healthRows` (`Health.tsx:44`) | `core/client/VaultHealth.kt` | strength / reuse / TOTP derivation |
| `web/src/ui/duplicates.ts` | `core/client/Duplicates.kt` | clustering, `planMerge`, `planKeep`, `planDismiss`, and every refusal |
| `web/src/ui/staleness.ts` | `core/client/Staleness.kt` | buckets, worst-first ranking, `planCheck`, `planUnsnooze`, `SNOOZE_MS`, the skew clamp |

Two properties of the source are load-bearing and must survive the port verbatim:

1. **The ranking is explainable by construction, not scored.** Three tiers, each with its own
   honest tie-break (failing → most recent first; never-checked → oldest `updatedAt` first;
   checked → oldest `checkedAt` first; name throughout as the final tie-break). A weighted score
   would be unarguable-with and would encode judgements the user never agreed to. Port the
   `RANK` table, not a heuristic that "feels equivalent".
2. **`isFailing` is a closed set over an open vocabulary.** `bad`/`gone`/`blocked` are failing;
   an **unrecognized** result degrades to "checked, verdict unknown", never to a red row. A
   future client's verdict must not turn the phone red. This is the forward-compat property most
   likely to be lost in a port, because it looks like a defect.

### 3.1 `check` and `dupeAck` become typed on core's `ItemDoc`

They live in `extras` today as raw `JsonElement`. Reading them from an untyped map at three call
sites is how a serialization bug gets written, so promote them:

```kotlin
data class ItemCheck(
    val at: Long,
    val result: String,        // OPEN vocabulary — never an enum, see above
    val okAt: Long? = null,
    val until: Long? = null,
    @Transient val extras: Map<String, JsonElement> = emptyMap(),
)
```

added to `ItemDoc` alongside `dupeAck: String? = null`, **appended last with null defaults** so
every existing positional and `copy()` writer stays bit-identical — the `postalCode` precedent
(`Account.kt:129`). No `formatVersion` bump: these are additive doc-level keys within fv1/fv2.

**The promotion must be a byte-identical round trip.** An item whose `check` currently rides in
`extras` and is re-saved by 0.26.0 must serialize to the same canonical bytes as one saved by
web. `ExtrasOverlaySerializer` makes this directly testable and §10 pins it. Get this wrong and
the failure mode is silent conflict churn across a household, which is far worse than a missing
screen.

### 3.2 Cross-language vectors

`tools/vector-gen` already exists for exactly this. Generate a fixture set — a vault of logins
with contrived `check` stamps, clock skew, snoozes, unknown verdicts, exact and differing
duplicate clusters — and assert **web and core produce the identical ordering and identical
plans**. Phone and laptop disagreeing about which login is worst is a bug nobody would report and
everybody would distrust.

> **DONE (`spec/test-vectors/vaulthealth.json`).** 20-item fixture vault; core
> `VaultHealthVectorsTest` and web `vaulthealth.vectors.test.ts` both green, 7 assertions each,
> first run on the web side. That is the port's real validation: the two suites in §10 were
> ported from one another and could agree with each other while both being wrong about the same
> thing — only a shared corpus catches that. **Order is asserted as a sequence, never a set**, and
> two dedicated cases keep the fixture honest about the forward-compat properties (an unknown
> verdict staying non-failing, a future `check.at` clamping).
>
> ⚠ **Found while adding it: `tools/vector-gen` can no longer reproduce the committed corpus**,
> so following the README's "regenerate; never hand-edit" would have destroyed tests.
> `itemdoc.json` has 11 committed cases and the generator emits 7 (the four dropped include the
> `check`-carrying ones `99fae40` added by hand); `urimatch.json` carries `classifyCard` (65) and
> `classifyCardFreeRegression` (28) keys the generator does not emit **at all**. Generate to a
> scratch directory and copy across only the intended file. Recorded in
> `spec/test-vectors/README.md`; teaching the generator those cases is its own job, not this
> release's. (Separately benign: `seal`/`secretstream`/`sharedgrant`/`export` differ on every run
> by construction — randomized sealing, verified in the decrypt direction.)

## 4. Layer 2 — the Android Health screen

Mirrors web's information architecture (tiles as the always-visible summary, one switchable half
below) without pretending a phone is a table.

- **Tiles:** the same seven counts — Logins, Weak, Reused, Breached, Duplicates, Unchecked,
  Failing. Seven across does not fit a phone; a 2-wide `FlowRow` grid or a horizontally
  scrolling chip row. The tiles derive from **the same rows the tabs show** (snoozed excluded,
  as on web) so a tile can never disagree with the list under it.
- **Tabs:** Passwords / Duplicates / Staleness, the `TabRow` idiom already used by
  `WelcomeScreen` (`MainActivity.kt:536`).
- **Rows, not a table.** Web's `<table>` becomes a `LazyColumn` of cards: name, a strength tag,
  reuse badge, TOTP mark, breach count. Tapping opens the item — the same `onOpenItem` contract.
- **Breach scan:** `Strength.breachCount` per unique password, prefixes fetched once, sequential
  and gentle on the relay, with the same progress affordance ("Scanning… 3/11").

## 5. The verification run — better on the phone than on the web

Web's run is "open the site in a tab, sign in, come back and tell us". On Android the tester and
the thing being tested live in the same place:

**Tap Check → Custom Tab opens the saved web URI → andvari's own autofill service fills it → back
→ the run resumes on the item it left → record the verdict.**

- Adds `androidx.browser` (Custom Tabs). No other new dependency.
- Only a **web** URI is navigable — an `androidapp://` entry is not. Same rule and same reason as
  `duplicates.ts`. An item with no web URI shows **"no saved site to open"**, which is the
  `safeSiteHref` refusal rendering correctly; the browser drill caught this on web and the phone
  inherits the copy.
- **andvari never tries a password for you.** The human signs in; the client records what they
  say happened. This is not a limitation to engineer around — a client that quietly probed sites
  with stored credentials would be doing something nobody asked for.
- Verdict buttons and the two ways to answer nothing (Skip, Stop) all render as **equals**. The
  browser pass on web found the nudge inverted — the four ways to *answer* rendered subordinate
  to the two ways not to. Nothing in a unit suite can see visual weight; do not re-earn that.
- **Opening the site from a run records a use**, as it does on web.

### 5.1 The run leaves the app, and §7 locks on leaving the app

These two decisions collide by construction. The run is an explicit exemption, the same way
`AutofillStatus` already exempts itself from the secure-window flag (`MainActivity.kt:125`). §7
carries the exemption list; it is not an afterthought.

## 6. Layer 3 — the `ItemDetail` health line

Cheapest high-value slice, and the place the usage ledger finally becomes visible: **strength ·
reused in N others · last used · last checked**, on the item already open. `HealthLine`'s
on-demand "check breach exposure" (`Vault.tsx:1701`) comes with it.

**Last used renders "—" when nothing is recorded — never "never used".** Those are different
statements and only one of them is true. See §8.

## 7. Toolbar — pull-to-refresh, and lock-on-background

> **OWNER DECISION (2026-08-23):** drop the refresh icon for pull-to-refresh; **add
> lock-on-background, then** drop the lock icon.

**Refresh → pull-to-refresh.** The vault list is already a `LazyColumn`
(`MainActivity.kt:1558`), `vm.refresh()` already exists, and Compose BOM 2024.12.01 ships
`PullToRefreshBox` in material3 1.3.1 — no new dependency, though it is `@ExperimentalMaterial3Api`
and that opt-in should be deliberate rather than incidental.

**Lock-on-background is a prerequisite, not a nicety.** As the tree stands, `MainActivity`
overrides **only `onCreate`**. Nothing locks on `onStop` or `onPause`. The only two things that
ever lock the vault are the toolbar button and the inactivity timer in `VaultSession`, whose
ceiling is `ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS` = **900 s**. So today, closing the app does
not lock the vault and locking the phone does not lock the vault — both merely stop refreshing
`lastInteractionElapsedMs`, and the vault stays unlocked in memory for up to fifteen minutes.
**Removing the button before adding the background lock would leave the app with no on-demand
lock at all.**

The change: a `ProcessLifecycleOwner` observer → `vm.lock()` on background — process-level, not
Activity-level, so an in-app excursion does not read as leaving. Exempted, explicitly:

- the Custom Tab verification run (§5.1)
- the file picker (CSV import, attachments)
- `AutofillUnlockActivity` / `SaveConfirmActivity`

**Stated cost:** `VaultSession` is shared with the autofill service, so the service will re-prompt
for unlock materially more often. That is the correct trade for a password manager, but it is a
behaviour change the owner will feel daily and it should not arrive unannounced in a changelog.

**Nav placement:** the two removals drop the top bar to four icons (import, sharing, trash,
settings); Health is a comfortable fifth, reached the same way Sharing/Trash/Settings already
are. No bottom nav, no IA restructure in a release already carrying a core port.

## 8. Constraints that must NOT be re-litigated on Android

Every one of these was paid for once already. They are listed so the port does not quietly
re-open them.

1. **The breach cache is IN-MEMORY ONLY, keyed per-account, cleared at the sign-out choke point.**
   CR-08 / WC-13 §E.4 ripped out the `localStorage` version because a map derived from decrypted
   passwords (a >10M count fingerprints a top-100 password) survived sign-out and cross-
   contaminated accounts on a shared browser. On Android the equivalent temptations are
   `SharedPreferences` and the SQLite cache. **Neither.** Process memory beside `VaultSession`,
   dropped by `lock()`, matching the spec 02 §5 wipe table.
2. **Usage writes stay batched, never per-use.** One PUT per copy would turn the blob's own
   `updatedAt` into a keystroke-grade activity trace — the exact leak the single-blob shape
   exists to avoid (spec 03 §3). `UsageRecorder.FLUSH_DEBOUNCE_MS` is already correct; adding
   read paths must not add write paths.
3. **One item write per verdict.** `item_versions` is capped live at the newest 10 per item
   (spec 02 §7); a chatty writer evicts real edit history — the F63 backstop — permanently.
   `planCheck` returns at most one write for exactly this reason.
4. **Absence carries no information.** No recorded use renders `—`. No `check` renders "never
   checked", which is a real statement; no `passwordHistory` renders nothing at all, because
   spec 02 §3 reserves it with exactly one writer.
5. **`updatedAt` is "last changed", never "password age".** Label the column accordingly. A bulk
   import restamps a whole vault and destroys the signal wholesale.
6. **A reader's write is refused in the client, with the reason** — not left to fail as a server
   error (spec 02 §4). `planCheck`/`planKeep`/`planDismiss` all carry refusals; render them.

## 9. Scope of this cut

> **OWNER DECISION (2026-08-23): full parity on Android, writes included.**
> All three tabs, plus merges, dismissals and check verdicts, plus the `ItemDetail` health line.
> The core port is the bulk of the work and is the same size whether one tab renders or three; a
> read-only view that shows four duplicates and refuses to merge them is the "machinery with no
> production call sites" trap this project has already been bitten by once.
>
> **Desktop: core port now, UI next cut.** `app-desktop` has its own Compose Desktop source set
> with no UI sharing with Android, so the desktop screen is a genuine second build rather than a
> recompile. The port serves it; the screen follows. **This must be a tracked backlog entry, not
> an intention** — otherwise §8's own warning applies to us.

**Explicitly out of this cut:**

- **Autofill fills still do not record usage.** The framework gives the service no callback when
  the system fills a dataset — unlike the extension's `reveal()` choke point. `FillEventHistory`
  / `TYPE_DATASET_SELECTED`, read on a subsequent request, is the lead and is its own pass. Until
  then the phone's contribution is copy-driven and partial, and §8.4 is what keeps that honest.
- **Changing the master password on a native client** — still web-only, as `BreachAdvisoryBanner`
  already tells the user.

## 10. Tests that must pin this

- `VaultHealthTest`, `DuplicatesTest`, `StalenessTest` (commonTest) — the twins of
  `health-rows.test.ts`, `duplicates.test.ts`, `staleness.test.ts`, assertion for assertion.
- **`ItemDocCheckRoundTripTest`** — a doc whose `check`/`dupeAck` arrived via `extras` re-
  serializes byte-identically once typed, in both directions, with unknown sibling keys present.
  The single highest-risk item in this design.
- **Cross-language vectors** (§3.2) — web and core produce identical ordering and identical plans
  over the same fixture vault.
- `StalenessTest`: unknown `result` degrades to "checked, verdict unknown"; future `at` clamps;
  `okAt` carries forward across a non-ok verdict; reader-role refusal.
- Android: the breach cache is dropped by `lock()` and never touches `SharedPreferences` or
  SQLite (an instrumentation assertion over the app's own data dir, not a unit mock).
- Android: background → locked, with each exemption verified individually — the Custom Tab run
  survives, the file picker survives, an ordinary home-button press does not.
- On-device pass, `uiautomator dump` + text nodes, **never screenshots** — vault contents.

## 11. Risks, ranked

1. ~~**The `ItemDoc` promotion (§3.1).**~~ **RESOLVED 2026-08-23 (`20a6e77`), and it was
   narrower than this section feared.** `ItemDocCheckRoundTripTest` (10 tests) is green and the
   full core suite passed unchanged. Two things the implementation established:
   - Item docs were **never** byte-identical across clients, so cross-client byte identity was
     never a property to preserve. Web's `JSON.stringify` omits `undefined`; kotlinx with
     `encodeDefaults = true` emits explicit nulls. `ItemDocVectorsTest`'s own KDoc already said
     so — "both shapes are spec-legal". The AD binds userId/vaultId/itemId, not doc bytes.
   - 0.26.0 therefore writes `"check":null` / `"dupeAck":null` on docs that have neither, where
     0.25.0 wrote no key at all. **Benign, and now pinned concretely rather than assumed:**
     nothing in `SyncEngine` gates a push on doc-byte equality (so no spurious writes), web reads
     `null` as falsy exactly like an absent key, and an older native client parks it in `extras`
     and hands it back unchanged. If it ever became intolerable the fix is `explicitNulls = false`
     on the shared config — a whole-doc change, never a per-field one.
2. **Lock-on-background changes daily feel** (§7). More autofill re-prompts. Reversible, but the
   owner should see it in a build before it is in a release.
3. **Two ports of ~560 lines of decision-dense TypeScript.** The comments in `staleness.ts` and
   `duplicates.ts` are not decoration — they record why each tie-break is what it is. Port the
   reasoning with the code.
4. **A lane's self-report is a claim; the tree is evidence.** After the port, grep for
   **production call sites**, not definitions or tests. This project has shipped an HIBP seam
   with zero call sites and a warning computed and rendered nowhere.
