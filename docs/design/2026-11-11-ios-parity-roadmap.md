# iOS app: the road to parity with Android

Date: 2026-11-11. Status: inventory for the owner to order; nothing here is built.

## Goal

The owner's direction: the iOS app reaches function parity with the Android app for creating and editing cards, logins and notes, attachments, shared vaults, import and export, and the rest. This document lists every capability the Android app has, what iOS has today, and what each would take, so the order can be decided.

## How to read the table

- **Android**: what the Android app does, read from its screens (`MainActivity.kt`, `SharingScreen.kt`, `HouseholdScreen.kt`, `HealthScreen.kt`, `AutofillStatusScreen.kt`) and its view model.
- **iOS today**: none, read-only, partial or full.
- **Core**: whether the shared Kotlin core already holds the logic, so iOS needs a controller method and SwiftUI only. "Yes" means the Android view model calls into `core` for it. "View model" means the logic sits in Android's `AndvariViewModel` and has to move into the shared controller first, as the session flows did.
- **Size**: S is a screen or two over existing core calls. M adds controller work or a platform integration. L is a feature with several screens, its own state and tests.
- The iOS controller (`SessionController`) is deliberately narrow today: it exposes logins only. Every row below that says "Yes" for core still needs its actions added to that controller and to the Swift model.

## Must have before the first store publish

| Capability | Android | iOS today | Core | Size | iOS constraint |
|---|---|---|---|---|---|
| Personal vault confirmation | A device that never confirmed its personal vault asks once, shows who else holds it, and confirms or re-designates (`PersonalVaultBanner`, `PersonalVaultCard`) | Full since 2026-11-11 (`PersonalVaultFlow`): the notice at the top of the vault, all six states | Yes | Done | |
| Account deletion | Not in the Android app (done on the web) | None | Server call exists for the web | M | App Store rule: an app that creates accounts must let the person start deletion in the app |
| Demo account for App Review | Not applicable | None | Not applicable | S | A reachable demo server and credentials in the review notes |
| View cards and notes | Full: detail with copy rows, expiry, masked number | Full since 2026-11-11: card detail with reveal and copy; notes were already shown | Yes | Done | |
| Recover an account (email and recovery phrase, then a new master password) | Full (`RecoverScreen`) | Done: from sign-in and unlock; the new-password step ends after 5 idle minutes or on leaving the app | In the controller (`recoverVerify`, `recoverCommit`) | Done | None |
| Clipboard clear by policy | Clears after the server's `clipboardClearSeconds` | Done: the expiry of the local-only pasteboard item is the policy's number, clamped to 1–300 s | Policy is in core | Done | iOS cannot clear the pasteboard later from the background; an expiring item is the mechanism |
| Cancel on "change server" | Yes | Done: Cancel returns to the screen the field was opened from | Controller | Done | None |
| Identity fingerprint | Shown in Household (code and QR) | Code and full fingerprint in Settings; no QR | Yes | Done (QR with sharing) | None |
| Sign-in two-step code | Full | Full | Yes | Done | |
| Trust Gate, enroll, recovery phrase capture | Full | Full | Yes | Done | |
| Logins: add, edit, delete, generator, one-time codes | Full | Full | Yes | Done | |
| System AutoFill, save, Safari extension | Android AutofillService with save | Full (credential provider, save queue, Safari popup, cards in Safari) | Yes | Done | |

## Parity round 1: everyday editing

| Capability | Android | iOS today | Core | Size | iOS constraint |
|---|---|---|---|---|---|
| Create and edit cards | Full editor (number, expiry, CVC, holder, postal code) | Full since 2026-11-11 (pulled forward): add, edit, delete, in the personal vault | Yes | Done | |
| Create and edit secure notes | Full | Done: add (to the personal vault), edit, delete; the text is read on request like a password and never offered to AutoFill | Yes (`saveNote`) | Done | None |
| Choose the vault for a new item; move or copy an item between vaults | Vault picker in the editor; `MoveCopyControl` | Done: a new login, card or note starts in the personal vault and goes to a shared vault only when the person picks it (the editor then says who will see it); an item's detail moves or copies it to another vault this account can write, attachments included, and a retry after a failure never duplicates | Yes (`newItemVaults`, `moveTargets`, `moveOrCopyItem`; the move gesture memo moved out of Android's view model into the controller) | Done | None |
| Trash: restore and purge deleted items | `TrashScreen` | Done: Settings › Trash lists deleted items by name (from their last readable version), restores one to its vault (without attachments) or deletes it for good; a vault the account only reads is view only | Yes (`openTrash`, `restoreFromTrash`, `purgeFromTrash`) | Done | None |
| Item history: view and restore earlier versions | Version list in the editor | Done: an item's detail shows its earlier versions (the server keeps the last 10) with the date, a password shown on request, and Restore after a confirmation; view only in a vault the account only reads | Yes (`openItemHistory`, `restoreItemVersion`) | Done | None |
| Attachments: add, open, save out, delete | `AttachmentRow`, file picker, save to a chosen location | None | Yes (`saveWithUploads`, download with bounds) | L | Document picker and Files app for import and export; Quick Look or the share sheet to open; photo library needs its own picker and usage string; uploads cannot continue in the background, so a large upload must finish while the app is open |
| Lifecycle notices | Banner for vault transfers, removals, restores | Done: the vault screen shows each notice in Android's words (core `LifecycleNoticeCopy`, pinned to Android's `noticeBody` by a test), anomalies as warnings, each dismissable | Yes (`SyncEngine.notices`; the copy moved into core) | Done | None |
| Set up or turn off two-step sign-in | `totpBegin`, `totpConfirm`, `totpDisable` in Settings | Done: Settings › Two-step sign-in shows whether it is on; turning it on takes the master password and shows the key once (QR code, text, Copy, a link to an authenticator) until a code confirms it; turning it off takes a current code | Yes (`loadTwoStep`, `beginTwoStep`, `confirmTwoStep`, `disableTwoStep`) | Done | None |
| Settings parity | Server, auto-lock, quick unlock, autofill status, backup, import, sign out | Face ID, auto-lock (read), lock, sign out | Mixed | S | The AutoFill status screen maps to a pointer at iOS Settings (the app cannot turn itself on as the provider) |

## Parity round 2: households, health, data in and out

| Capability | Android | iOS today | Core | Size | iOS constraint |
|---|---|---|---|---|---|
| Shared vaults: create, rename, delete, restore, leave | `SharingScreen` owner and member panels | None (items in shared vaults are listed and can be filled; nothing can be managed) | Yes | L | None |
| Members: invite, verify by code or QR, roles, remove | `VerifyMemberDialog`, invitations, signed grants | None | Yes | L | Camera access and a usage string for QR verification |
| Ownership transfer: offer, accept, cancel | `TransferControl`, `IncomingTransferCards` | None | Yes | M | None |
| Household contacts and identity pins | `HouseholdScreen` | None | Yes | M | Camera for QR |
| Legacy vault review and re-issue of old grants | `legacyReviewVaults`, `confirmReissue` | None | Yes | M | None |
| Vault health: weak, reused and breached passwords, duplicates, staleness, verify run | `HealthScreen` (four tabs) | None | Yes (`VaultHealth`, `Duplicates`, `Staleness`); breach check needs the network call | L | None |
| Import (CSV from other managers) | `ImportSheet`, parse, choose vault, confirm | None | Yes (`CsvImport`) | M | Document picker; the file is read once and never copied into the app's container |
| Export: encrypted backup and CSV | `BackupPreflightDialog`, `CsvPreflightDialog` | None | Yes (`Export`, `ExportPlanner`) | M | Document picker or share sheet for the destination; a plaintext CSV must go to a place the person chose, never to a temporary file that outlives the export |
| Invite links that switch server | Pending-switch flow (`PendingReconcileScreen`) | Manual Trust Gate first, by design for v1 | View model (Android and desktop disagree on the pending marker) | L | None; the risky part is the shared logic, not the screens |
| Usage recording for staleness | `UsageRecorder` | None | Yes (`UsageRecorderCore`) | S | Extensions cannot write it (no network); only fills made in the app would count unless the queue carries it |

## Not parity, but found on the way

- **Change master password** is not in the Android app either (it is done on the web). If the owner wants it in the apps, it is an M on both.
- **Card fill outside Safari** has no route on iOS: Apple offers third-party providers no card API. Cards are filled in Safari by the extension and copied from the app elsewhere.
- **Password history** has a second writer now (an AutoFill save that replaces a password). Android and the web do not show the field yet.

## Suggested order

Before publish, in this order: personal vault confirmation (it blocks adding logins for some accounts), viewing cards and notes, account deletion and the demo account (both store gates), then the four small ones. Round 1 is led by cards and notes editing, then trash and history, then attachments, which is the only large item in it. Round 2 is led by shared vaults and members, which are one piece of work in two parts.
