# N3 — desktop vault management (design-lite, 2026-07-11)

Port the **reviewed Android Sharing surface** to desktop over the shared engine. Design-lite
per PLAN-07c: Android's `SharingScreen.kt` + the `AndvariViewModel` sharing slice ARE the
spec — this doc pins scope, the DesktopState contract, desktop-specific decisions, and the
hazards; the builders read the Android source directly for shapes and verbatim copy. Cut as
**0.14.0** (new feature surface). Both ground-truth surveys (Android inventory + desktop/core
map) were run against HEAD `4577f25` and this doc's claims come from them.

## Scope = Android parity, exactly

IN: vaults list with per-vault settings reveal (shared vaults only), owner panel (rename /
transfer / delete with typed-name confirm + rescue-copy), member panel (role line + leave),
trash disclosure (recently-deleted with restore + read-only recently-removed), the copy
status line, and the GLOBAL attention surface desktop is missing: lifecycle-notice banner,
incoming-transfer cards, F20 undecryptable-grant warning (+ the existing ReSealCard joins
them). Post-delete/-copy notices with purgeAt. The `friendlyError` code map.

OUT (Android doesn't have them either — do NOT invent parity): vault creation, member
add/role/remove, member rosters, disabled badges, email lookup. These stay web-only; the
F22 "native roster" residue stays parked (this cycle does not build a roster).

**Why the global pieces are IN:** desktop today drops `engine.notices()`,
`engine.incomingTransfers()`, `engine.heldVaultInfos()` and the F20 count entirely — an
ownership transfer offered to a desktop-only user is INVISIBLE and unacceptable, and notices
die silently with `engine.close()` on lock. This is the real correctness half of the cycle.

## Decisions

1. **Navigation:** new `data object Sharing : DesktopScreen` + `openSharing()/closeSharing()`
   (imperative, like Settings/Trash — no back stack). One `when` branch in `DesktopApp`.
   Entry: a `Icons.Default.Group` IconButton in the Vault header row, placed between import
   and trash (mirrors Android's action order import/sync/sharing/trash/settings/lock as far
   as the existing row allows). `Esc` is NOT wired screen-level (no desktop screen has it);
   the header gets the same "back" TextButton idiom as Settings/Trash, plus the settings
   branch's back goes list-first (Android A11 layering, expressed imperatively:
   `closeVaultSettings` if a settings id is open, else `closeSharing`).
2. **AttentionArea (global):** a new composable in `DesktopApp` ABOVE the screen `when`,
   rendered ONLY when signed in (`screen is Vault/Settings/Trash/Sharing`) — the screen gate
   makes a lock-screen dead-action card structurally impossible (belt), AND `lock()` still
   clears the whole lifecycle slice (braces; the notices die with the engine anyway — 0.13.0
   P4 lesson). Order mirrors Android: ReSealCard (MOVES here from the Vault list) →
   IncomingTransferCards → LifecycleNoticesBanner → F20 UnopenableVaultWarning. Same
   `heightIn(max = 360.dp)` + inner scroll cap. Android's FYI-collapse (needsUpdate minority
   + F20 both present) is NOT ported — desktop has no needsUpdate-as-empty-explanation line
   today; F20 renders plainly. (Recorded as a deliberate simplification.)
3. **State contract (DesktopState, mirrors Android UiState names):**
   `lifecycleNotices: List<LifecycleNotice>` · `incomingTransfers: List<IncomingTransfer>` ·
   `transferOwnerNames: Map<String, String>` · `sharingMembers: Map<String, List<VaultMemberSummary>>` ·
   `deletedVaults: List<DeletedVaultInfo>` · `heldVaults: List<HeldVaultInfo>` ·
   `sharingSettingsVaultId: String?` · `undecryptableSharedVaultCount: Int` ·
   `copyProgress: Pair<Int, Int>?` · `copiedNote: String?` · `copyVaultId: String?` —
   all `mutableStateOf`, private set, defaults empty/null/0.
4. **Ops contract (signatures pinned; bodies mirror `AndvariViewModel` 1:1):**
   `vaultInfos(): List<VaultInfo>` (null-engine → empty) · `pendingTransferFor(vaultId): PendingTransfer?` ·
   `openSharing()` (screen=Sharing, null settings id + copy display state, then reloadSharing) ·
   `closeSharing()` · `openVaultSettings(vaultId)` / `closeVaultSettings()` (both clear copy
   display state, never the in-flight op) · `reloadSharing()` (refreshLifecycle first; then
   members per OWNED shared vault + `engine.listDeleted()`, each fetch `runCatching`, NO busy,
   engine null-guarded per step) · private `refreshLifecycle()` (notices/incomingTransfers/
   heldVaultInfos/F20 count; A2: null a settings id that stops resolving; lazily resolve
   missing transfer owner names via `api.vaultMembers`) · `renameVault(vaultId, newName)` ·
   `deleteVault(vaultId, vaultName)` (op{}; success → `notice` with purgeAt copy) ·
   `copyItemsToPersonal(vaultId)` (NOT op{} — manual `busy=true` held for the WHOLE copy =
   the delete-during-rescue gate; progress via `copyProgress`/`copyVaultId`; success keeps
   copyVaultId to name the note; failure clears both then errors) · `clearCopiedNote()` ·
   `offerTransfer(vaultId, toUserId)` · `cancelTransfer(vaultId)` (owner-cancel AND
   target-decline) · `acceptTransfer(vaultId)` · `leaveVault(vaultId)` ·
   `restoreVault(vaultId, deleteId)` · `dismissNotice(id)` (not busy-gated).
   Lifecycle ops end with `refreshItems(); reloadSharing()` like Android.
5. **friendlyError:** port Android's code map (V:691-708, verbatim strings) into desktop
   `op()`'s catch — known `ApiException.code`s get the friendly string, 429 gets the wait
   message, everything else falls back to `t.message` exactly as today. This upgrades ALL
   desktop ops, deliberately.
6. **Refresh funnel:** `backgroundSync()` and `toVault()` call `refreshLifecycle()` after
   sync (cheap in-memory reads), so offers/notices appear on any screen without opening
   Sharing — Android's funnel. `reloadSharing()` (the network fetches) runs only at
   openSharing + after each lifecycle op (Android A12 eager pattern).
7. **Teardown:** `lock()` + `signOut()` zero the ENTIRE new slice (all §3 fields) — the
   engine's notice memory does not survive lock; stale members/deleted lists must not
   leak across accounts. `clearSecondary()` is not enough on its own; wire the reset where
   the other slices reset.
8. **Typed-name delete confirm:** new inline pattern in the desktop DeleteVaultControl card
   (OutlinedTextField, `enabled = !busy && typed == v.name` on the Delete button) — mirrors
   Android's in-panel flow; nearest desktop precedent is the ReSealCard typed field. All
   copy strings verbatim from Android (including curly quotes around vault names and the
   curly apostrophes inside noticeBody — transcribe, don't retype).
9. **Idle-lock discipline:** `maybeIdleLock` defers only on `busy || importBusy`.
   `reloadSharing` deliberately runs WITHOUT busy (Android pattern; a slow members fetch
   must not freeze the window) → every engine/api touch inside it null-guards (`engine ?:
   return`, per-fetch runCatching) so a mid-flight lock cannot NPE. `copyItemsToPersonal`
   holds busy → the idle lock defers for the whole rescue copy (same as Android).
10. **Memo discipline:** vault-name/infos reads decrypt metaBlobs — UI derives lists under
    `remember(state.items, <slice>)` keys, never per-recomposition raw calls (existing
    UI:354 precedent).
11. **`items` for the delete panel counts:** desktop already exposes `items` — the panel
    computes item/attachment counts exactly like Android (S:456-458).

## Amendments (adversarial breaker, 2026-07-11 — 1 BLOCKER, 8 AMENDs; architecture held)

**B1 (BLOCKER — WS-S): async writes must be epoch-guarded, not null-guarded.** The scope is
the window composition scope; `lock()`/`signOut()` cancel nothing. An in-flight
`reloadSharing`/owner-name fetch resumes after a sign-out→sign-in and its `engine ?: return`
check passes against the NEW account's engine → account A's member emails/deleted vaults
land in account B's session (after teardown already zeroed them); the captured-reference
variant instead hits a closed sqlite cache and an uncaught throw in a composition-scope
coroutine kills the window. FIX: capture `val e = engine; val a = api` at launch, wrap every
enumeration step in `runCatching`, and gate EVERY post-suspension state write with an
identity check (`if (engine !== e) return@launch`) — the pattern desktop `backgroundSync`
must also keep. (Android carries the same latent bug in `reloadSharing`/owner-names —
ticketed as a backport, NOT re-specified here.)

**A-copyGate (WS-S + WS-U): the busy-hold is NOT a delete-during-rescue gate — build a real
one.** Any op run mid-copy (`openTrash`, the sync icon) clears `busy` when IT finishes,
re-enabling Delete while the rescue still runs, and un-deferring the idle lock. New
NON-DISPLAY field `copyOpVaultId: String?` — set at copy start, cleared in the copy's
`finally`, NEVER touched by navigation (unlike the display `copyVaultId`). `maybeIdleLock`
defers while it is non-null; `deleteVault()` refuses while it is non-null; the Delete
button gates `!busy && typed == v.name && copyOpVaultId == null`. (Android has the same
hole — backport ticket, with this field as the shape.)

**A-tick (WS-S + WS-U): memo staleness.** `vaultInfos()` derives from vault/grant rows, not
items — `remember(state.items)` misses vault-set-only changes (a new empty grant, a remote
delete of an empty vault) → ghost rows, gear into a dead vault. New `lifecycleTick: Int`
(private set) bumped at the END of every `refreshLifecycle()`; ALL Sharing-screen derived
lists memo under `remember(state.items, state.lifecycleTick)`.

**A-bars (WS-U):** SharingScreen renders `ErrorBar(state.error)` + `NoticeBar(state.notice)`
at the top, above the branch (Android A6/A7) — desktop bars are per-screen, and without
them every sharing op error and the post-delete purgeAt notice are invisible.

**A-trashIcon (WS-U):** the Sharing header (list mode only) carries a real
`IconButton(Icons.Default.Delete)` trash toggle, tinted when open — two verbatim strings
("Sharing → the trash icon") depend on the icon existing.

**A-funnel (WS-S):** `refreshLifecycle()` is ALSO called from `refreshItems()` (Android
V:1976-1979) and from `backgroundSync`'s FAILURE path when the session isn't torn (a
denied/parked cycle still pushes notices) — not just the success path + toVault.

**A-resolve (WS-U + WS-S):** two load-bearing Android properties are pinned as
requirements: (i) `refreshLifecycle` performs ALL slice writes + the A2 settings-id null in
ONE synchronous (non-suspending) block, with the owner-name fetch in a SEPARATE launch —
one continuation, one recomposition, no torn frame; (ii) the screen resolves
`settingsVault` null-safely per composition and degrades to the list when the id stops
resolving (S:160-164; title falls back to "Sharing").

**A-note (WS-S):** rescue-copy completion while the user is off-Sharing currently loses the
confirmation everywhere — at completion, if `screen !is Sharing`, ALSO mirror the copied
note into the global `notice` (Sharing renders its own `copiedNote` as today).

**A-escrow (WS-S):** desktop `lock()`/`signOut()` gain `escrowStale = false;
escrowFingerprint = ""` — true P4 parity; the screen gate alone was belt without braces.

**Notes folded:** the AttentionArea signed-in gate is an EXHAUSTIVE `when(screen)` (no
`else`, no `is`-chain) so a future screen can't silently skip it. Exactly one `when` over
`DesktopScreen` exists (Ui.kt dispatch) — WS-S's sealed entry breaks Ui.kt compilation
until WS-U lands; the combined gate is the orchestrator's. Manual Lock mid-copy stays
unguarded (parity; degrades safely — error on the Unlock screen; re-running the rescue
after re-unlock may duplicate already-copied items, same as Android process death —
accepted). `busy`-during-poll button flicker is pre-existing desktop-wide behavior —
accepted now; a `syncing` split like Android's V:121-126 is a future item.

## Workstreams (disjoint files, parallel)

- **WS-S — `DesktopState.kt` ONLY:** the `DesktopScreen.Sharing` sealed entry, all §3
  fields, all §4 ops, §5 friendlyError in op(), §6 funnel wiring (backgroundSync/toVault),
  §7 teardown. Must compile standalone (`:app-desktop:classes` will fail until WS-U lands
  the dispatch branch — Kotlin `when` over sealed interfaces in Ui.kt has an `else`? If the
  existing `when (val s = state.screen)` is exhaustive without else, ADDING the sealed entry
  breaks Ui.kt compilation → coordinate: WS-S adds the sealed entry; the combined tree only
  compiles after WS-U. Each agent runs syntax-level checks; the ORCHESTRATOR runs the
  combined gate.)
- **WS-U — `Ui.kt` ONLY:** the `when` branch + header IconButton, `SharingScreen` (list/
  settings branches, VaultListRow with gear on shared rows, OwnerVaultPanel = RenameHeader +
  TransferControl + DeleteVaultControl, MemberVaultPanel = role line + LeaveControl,
  CopyStatusLine, trash disclosure → RecentlyDeletedSection + RecentlyRemovedSection), the
  global AttentionArea (moves ReSealCard invocation from the Vault list into it), all copy
  verbatim from Android `SharingScreen.kt` / VM notice+error strings.

Both builders READ `app-android/.../SharingScreen.kt` + `AndvariViewModel.kt` (the sharing
slice) as the source of truth; this doc only pins scope + the contract above.

## Gates + ship

`:app-desktop:classes` (the primary gate — combined tree) + full `scripts/verify.sh` +
find→refute review (full, it's an L cycle). No server/wire changes expected — if a builder
thinks one is needed, STOP and report. Version lockstep ×4 → 0.14.0, CHANGELOG, snapshot +
vzdump, deploy web/server (rebuilt jar, same behavior), APK ship (lockstep), deb + manifest
MERGE, byte-verify, Telegram statement.
