# DN-1 — per-vault Settings flyout (owner dev-note, 2026-07-10)

**Owner:** "instead of having the setting and config for each vault under the vault list, lets
have the vaults have a 'settings' option on each that brings up a popup/flyout/reveals settings."

**What that is today (recon-mapped, line-cited):** on web, Sharing.tsx renders EVERY owned
vault's full `MemberPanel` (rename + members + transfer + add-member + delete) stacked under
the Vaults sheet simultaneously (`Sharing.tsx:77-84`), plus every member-vault's roster panel
(:82-84). On Android, SharingScreen.kt stacks an `OwnerVaultPanel` card per owned vault below
the Vaults card (`SharingScreen.kt:191-194`). Neither has any selected-vault concept. **Desktop
has NO vault-management surface at all** (no Sharing screen; DesktopState has none of the
lifecycle methods) — nothing to re-parent, so desktop is OUT of DN-1's scope; "vault management
on desktop" is recorded as its own future item (it would be net-new, not a re-layout).

## The principle: re-parent, don't rewrite

The furniture being moved is the Skipti lifecycle UI — flows that earned five data-loss fixes
in their original review. Every moved block keeps its component identity, props, state keys,
store/VM calls, and copy **verbatim**; only the call site changes. The review's primary lens is
"the diff of each moved block is a pure relocation." Specifically preserved (recon-cited):

- web: `store.restoreSharedVault(d.vaultId, d.deleteId)` keeps the deleteId arg (consumed-
  deleteId contract); `copyAllToPersonal` + delete stay two separate user-ordered buttons; the
  delete-honesty block (:587-591), transfer-consent advisory copy (:642-645), AddMember's
  mandatory out-of-band fingerprint gate (:814-826) — all byte-identical.
- android: type-name delete gate (`typed == v.name`, :392-404), copy-first + back-up-first
  buttons (:370-383), `restoreVault(vaultId, deleteId)` (:450), transfer-target filter
  excluding disabled members (:304-305), `enabled = !ui.busy` on every action.

## Target shape

**Web (Sharing.tsx):** the Vaults sheet's rows each gain a **Settings** button (owner vaults
and member vaults alike). Clicking sets a new `settingsVaultId` state → Sharing renders the
per-vault settings VIEW in place of the list (a revealed layer, the house F76 idiom — web has
no modal/portal machinery and the `.menu` dropdown can't hold roster-scale content):
- owner vault → the existing `MemberPanel`, unchanged;
- member vault → `MemberRosterPanel` + `LeaveControl` (Leave moves off the list row into
  settings — the row keeps its role tag);
- a header with the vault name + "‹ Back to vaults"; **Escape/browser-Back closes the layer
  first** — wire into the existing back-guard contract the way Detail/Editor/Export do
  (recon: `deep`/`closeTop`, Vault.tsx:45,154-163; Sharing participates per its existing
  layering). If a background sync deletes/revokes the open vault, the layer closes to the list
  with the store's normal notice (state derives from the vaults list each render — a vanished
  vaultId renders nothing and falls back).
- LIST-LEVEL stays put: incoming transfer offers, undecryptable-grants warning, the Vaults
  sheet, NewVaultForm, RecentlyDeleted.

**Android (SharingScreen.kt):** same reveal pattern, rotation-safe per the house convention
(recon: sheet-open state follows the ViewModel movePicker precedent, NOT plain remember):
- `UiState.sharingSettingsVaultId: String?` + `vm.openVaultSettings(id)` / `vm.closeVaultSettings()`
  (also cleared by lock/sign-out alongside the other transient sharing state);
- the Vaults card rows get a Settings icon (extract the inline row at :174-187 into a
  `VaultListRow(v, onOpenSettings)` composable — the one extraction the move needs);
- settings open → SharingScreen renders the settings view (vault-name title + back arrow +
  `BackHandler`): owner vault → existing `OwnerVaultPanel`; member shared vault →
  `LeaveControl` (+ role line); personal vault → rows get NO settings affordance on either
  platform (personal has no lifecycle ops — rename/delete/leave/transfer are all
  shared-vault verbs; showing an empty settings page is worse than no button).
- List-level stays put: lifecycle notices, incoming transfers, RecentlyDeleted,
  RecentlyRemoved, ExportDialogs host.
- The AlertDialog confirms INSIDE the moved panels (leave/transfer/restore/import idiom)
  compose over the settings view exactly as they composed over the stacked view — no nesting
  change.

**Versions:** Android behavior change → bump ×4 → **0.11.0** (a visible UX reorganization is a
feature cut, not a patch); web rides the same deploy; desktop/extension untouched (desktop
re-reports 0.11.0 via the lockstep).

## Breaker amendments (1 FATAL + 5 SERIOUS + 7 MINOR, all folded in — build to THESE)

- **A1 (F-1, the web wiring — verified against the guard):** `sharingSettingsVaultId` is
  **Vault.tsx state**, passed to Sharing as props. `closeTop` gains
  `if (view === "sharing" && sharingSettingsVaultId) return setSharingSettingsVaultId(null);`
  **BEFORE** the `view !== "vault"` fallback (:162); `deep` unchanged; `navBtn` (:325) clears
  the id like the other layers. A second `useBackGuard` instance anywhere below Vault is
  FORBIDDEN (double-popstate = one Back closes two layers). Escape is NOT part of the
  contract (no layer closes on Escape today) — Back only.
- **A2 (S-1):** derive-only lookup resurrects the layer (delete X in settings → restore X in
  Recently deleted → settings X pops back open). ACTIVELY clear the id when the lookup
  misses (web: effect; Android: in the sync/refresh path), keep the render null-guard for
  the same-frame gap.
- **A3 (S-2, intentional edit — web):** DeleteVaultControl's `{copying, copiedNote}` LIFT to
  Sharing-level state keyed by vaultId (Sharing stays mounted across layer cycles; no
  store.ts change) so closing the layer mid-copy doesn't orphan the rescue-copy progress and
  a reopened panel shows honest state.
- **A4 (S-3, intentional edit — Android):** scope the VM copy state: `copyVaultId` joins
  `copyProgress`/`copiedNote` (set in copyItemsToPersonal, cleared together); a SCREEN-level
  progress/note line renders whenever `copyProgress != null` (visible from list or settings;
  names the vault); `openVaultSettings`/`closeVaultSettings` clear `copiedNote`/`copyProgress`
  per the `openSharing` convention. Fixes both the stuck-busy reopen and the
  cross-vault-authoritative copy note.
- **A5 (S-4):** `openSharing` ALSO nulls `sharingSettingsVaultId` (a fresh Sharing visit
  lands on the list, never inside a stale layer) — plus the two lock/sign-out reset blocks
  (AndvariViewModel:1673-1692 AND :1731-1740, both).
- **A6 (S-5):** Android `ErrorBar` + `NoticeBar` compose ABOVE the list/settings branch —
  an op failure inside settings must not be silent. Web already fine (Vault-level banner).
- **A7 (M-4):** branch boundary pinned: BANNERS stay above the branch (web: incoming
  transfer offers + undecryptable-grants warning; Android: lifecycle notices + incoming
  transfers + Error/Notice bars; ExportDialogs host stays screen-level). LIST-BRANCH-ONLY:
  the Vaults sheet/card, NewVaultForm, RecentlyDeleted, RecentlyRemoved. An arriving
  ownership offer therefore stays immediately visible even with settings open.
- **A8 (M-6):** web "Back up first" leaves Sharing via navBtn → the id clears (A1) → the
  round-trip returns to the vault LIST, both platforms consistent (Android hosts its export
  dialogs in-screen and keeps context — acceptable platform difference, documented).
- **A9 (M-2, known-dead noted):** the web post-delete toast never paints today (the panel
  unmounts in the same commit); pure relocation keeps it dead — NOT fixed this cycle. The
  delete outcome is visible as the vault leaving the list + Recently deleted gaining a row.
- **A10 (M-3):** doubled vault-name headers accepted (settings header + panel H2s) — listed
  as the one cosmetic drift allowed.
- **A11 (M-7):** the Android settings BackHandler composes INSIDE the settings branch
  (last-composed-wins precedence over the screen-level one). AlertDialog confirms keep
  their own window back-dispatch.
- **A12 (sound-8 fence):** `reloadSharing` stays EAGER (members for all owned vaults at
  openSharing + after every op) — transfer-target availability must not become lazy.
- **A3b (from the build review's HIGH — the one trap A3 itself opened):** lifting the copy
  DISPLAY state made the panel unmountable mid-copy, but `busy` stayed local — a reopened
  DeleteVaultControl offered an enabled second Copy AND an enabled type-name Delete while the
  rescue copy still ran (delete-during-rescue, unreachable pre-move). Fix: the panel derives
  `inFlight = busy || copying !== null` and gates copy / back-up / the type-name input /
  Delete on it. **Cancel deliberately stays busy-only** — it merely collapses the sub-panel
  (the copy continues via lifted state); trapping the user mid-copy protects nothing. The
  collapsed branch also renders live copy progress + the completion note (review LOW: the
  opener clears the note, so the collapsed view is where a copy-finished-while-closed is
  learned). Android needs none of this (global ui.busy holds across navigation).

## Regression invariants (the breaker's checklist)

1. Every moved block's diff is a relocation (same JSX/composable body). Any intentional edit
   (the Back header, the Leave re-home) is listed here and nowhere else.
2. The `onChanged`/`refresh` contract (web :31-34) and `ui.busy` gating survive re-parenting —
   a WS-driven repaint or an in-flight op behaves identically with the layer open.
3. Closing the layer NEVER cancels or orphans an in-flight lifecycle op — all such state lives
   in store/VM (recon-verified), and the panels' local confirm toggles are allowed to reset on
   close (same as a re-render reset today).
4. A vault vanishing mid-view (revoked/deleted by another device) degrades to the list, not a
   crash — null-safe lookup of settingsVaultId against the CURRENT vaults each render.
5. deleteId threading, type-name gates, copy-first buttons, consent copy: byte-identical.
6. No store.ts / SyncEngine / server changes AT ALL in this cycle.
