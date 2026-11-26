package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.client.items.VaultClosedReason
import io.silencelen.andvari.core.client.items.HeldCopied
import io.silencelen.andvari.core.client.items.HeldDeleted
import io.silencelen.andvari.core.client.items.HeldPick
import io.silencelen.andvari.core.app.AttachmentContent
import io.silencelen.andvari.core.app.AttachmentDraftView
import io.silencelen.andvari.core.app.AttachmentLimitsView
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.CopyProgressView
import io.silencelen.andvari.core.app.CsvImportView
import io.silencelen.andvari.core.app.DeletedVaultView
import io.silencelen.andvari.core.app.ExportFile
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.app.ExportView
import io.silencelen.andvari.core.app.HealthView
import io.silencelen.andvari.core.app.ItemHistoryView
import io.silencelen.andvari.core.app.TrashItemView
import io.silencelen.andvari.core.app.UploadView
import io.silencelen.andvari.core.app.GeneratorSettings
import io.silencelen.andvari.core.app.ItemDetail
import io.silencelen.andvari.core.app.ItemSummary
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.OneTimeCode
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.app.Subscription
import io.silencelen.andvari.core.app.VaultChoiceView
import io.silencelen.andvari.core.app.VaultNoticeView
import kotlinx.coroutines.flow.StateFlow

/**
 * The vault's content as a screen sees it, while the account is unlocked: the list and its search, an item's detail
 * and its secrets on request, the editors, delete, where a new item may go, the notices the item engine raised, and
 * sync. It is the vault half of the old `SessionController`, over the item engine of the new session
 * ([io.silencelen.andvari.core.client.items.ItemEngine]); member names and the shapes of what they answer are the old
 * controller's wherever the meaning did not change, so a screen written against that controller changes as little as
 * possible.
 *
 * **One instance per unlock.** The app API hands out a [VaultContent] only while the account is unlocked and drops it
 * on lock; it is [close]d then, and an intent that finishes after that answers [ActionResult.NotDone] and changes
 * nothing on screen. A new unlock gives a new instance.
 *
 * **State is one immutable [ContentState]**, read with [state], collected with [states] (Kotlin) or observed with
 * [observe] (Swift). Secrets are never in it: a password, a note's text, a card's number and code, a one-time code and
 * an earlier password are read one at a time, on request.
 *
 * **Intents never throw** (a `suspend` intent's cancellation aside): a refusal or a failure is an
 * [ActionResult.Failed] whose message is the sentence to show, from [ContentCopy]. [ActionResult.NotDone] means
 * nothing was done and nothing needs saying (the instance was closed, or the same editor's save already runs).
 *
 * **Under a forked server pin** (design §4.4) the content stays readable from this device's copy and nothing can be
 * saved: [ContentState.serverStopped] is true, no vault is writable, [vaultsForNewItems] is empty, and every intent that
 * would write answers [ActionResult.Failed] with [ContentCopy.SERVER_STOPPED].
 *
 * Call everything from one thread, the main thread in an app. Listeners are called on it.
 *
 * No member has a default argument, an overload or a type parameter, and no name starts an Objective-C method family
 * (`new`, `copy`, `init`, `alloc`), so Swift sees the Kotlin names unchanged (the app API's surface rules).
 */
interface VaultContent {
    /** The current state. */
    val state: ContentState

    /** The states as a flow, for Kotlin callers. Swift uses [observe]. */
    val states: StateFlow<ContentState>

    /** Call [listener] with the current state, then with every later one, until the subscription is closed. */
    fun observe(listener: (ContentState) -> Unit): Subscription

    /** The account locked or signed out: listeners are dropped and every later intent answers [ActionResult.NotDone]. */
    fun close()

    // ---- the list ----

    /** Filter the list ([ContentState.items]) by [query]: the name, the notes, the username, every web address, and a card's brand and last four. */
    fun setQuery(query: String)

    /** An item's detail, without its secrets; null if the item is gone. */
    fun itemDetail(itemId: String): ItemDetail?

    /** One secret field of an item, for an explicit reveal or copy; null if gone or empty. */
    fun revealSecret(itemId: String, field: SecretField): String?

    /**
     * When each earlier password of a login was retired (unix milliseconds), newest first: the index is what
     * [previousPassword] takes.
     */
    fun passwordHistory(itemId: String): List<Long>

    /** One earlier password of a login, by its place in [passwordHistory] (0 is the most recent); null when there is none. */
    fun previousPassword(itemId: String, index: Int): String?

    /** The item's current one-time code; null if it has none. */
    fun oneTimeCode(itemId: String): OneTimeCode?

    /** A new password under [settings]; settings no password can satisfy give the standard ones at the asked length. */
    fun generatePassword(settings: GeneratorSettings): String

    // ---- the editors ----

    /**
     * Add a login ([itemId] null) or save an edit of one. A new login goes to [vaultId] when named (one of
     * [vaultsForNewItems]), else to the personal vault; an edit stays in its vault whatever [vaultId] says.
     * Offline on a durable cache the save is queued: [ActionResult.Ok] with [ContentState.notice] saying so.
     */
    suspend fun saveLogin(itemId: String?, input: LoginInput, vaultId: String?): ActionResult

    /**
     * Add a card or save an edit of one. The number and the code keep their digits only, the expiry is read as a
     * month and a four-digit year (a whole "07/31" typed into the month is split), and the brand is worked out from
     * the number. An expiry that cannot be read is refused, never guessed.
     */
    suspend fun saveCard(itemId: String?, input: CardInput, vaultId: String?): ActionResult

    /** A line to show under a card number while it is typed, or null. */
    fun cardNumberWarning(number: String): String?

    /** Add a secure note or save an edit of one. Its text is a secret, read through [revealSecret] with [SecretField.NOTES]. */
    suspend fun saveNote(itemId: String?, input: NoteInput, vaultId: String?): ActionResult

    /** Delete an item (it goes to the server's trash). Offline on a durable cache the delete is queued. */
    suspend fun deleteItem(itemId: String): ActionResult

    // ---- vaults ----

    /**
     * Where a new item may go: the personal vault first (the default the editors start on), then the shared vaults this
     * account can write, by name. Empty under a stopped server. A shared vault is only ever the person's own choice.
     */
    fun vaultsForNewItems(): List<VaultChoiceView>

    /** The name this device knows [vaultId] by, or null when it is not a vault this account can read here. */
    fun vaultName(vaultId: String): String?

    /** The person has read one notice ([ContentState.vaultNotices]): it goes until something new happens. */
    fun dismissVaultNotice(id: String)

    // ---- attachments (spec 02 §6) ----

    /** What one file, and an item's files together, may come to here: the server's policy, held to this app's ([io.silencelen.andvari.core.app.AttachmentRules]). */
    fun attachmentLimits(): AttachmentLimitsView

    /**
     * An editor opened ([itemId] null: a new item): its files are listed in [ContentState.attachmentDraft], and files
     * can be added and taken off. A new item's id is minted now, so every try of its save uses it.
     */
    fun openAttachmentDraft(itemId: String?)

    /** The editor closed: the files it added go (their encrypted bytes are wiped). */
    fun closeAttachmentDraft()

    /**
     * Add a file to the open editor's item. [name] is what it is called (a path is cut to its last part). The file is
     * held to [attachmentLimits], encrypted under a key of its own and kept in memory, encrypted, until the item's
     * save sends it; [bytes] is zeroed. [ActionResult.NotDone] when no editor is open or its save runs.
     */
    suspend fun addAttachment(name: String, bytes: ByteArray): ActionResult

    /** Take a file off the open editor's item: an added one goes now; a kept one leaves the item at its next save. */
    fun removeAttachment(attachmentId: String)

    /**
     * One file of an item, decrypted, for a preview or to save: the caller keeps it in memory and writes no copy of it.
     * Refused past what this app opens. No bytes and no error: the content was closed meanwhile.
     */
    suspend fun readAttachment(itemId: String, attachmentId: String): AttachmentContent

    // ---- the trash (spec 03 §5.1: a deleted item is kept 30 days) ----

    /** Read the server's trash into [ContentState.trash]. Each item is named from its last readable version. */
    suspend fun openTrash(): ActionResult

    /** The trash screen closed: what was read goes. */
    fun closeTrash()

    /** Bring a deleted item back to its vault, on every device. Its attachments do not come back. */
    suspend fun restoreFromTrash(itemId: String): ActionResult

    /** "Delete forever": the item and its history are removed from every device now. */
    suspend fun purgeFromTrash(itemId: String): ActionResult

    // ---- the owner's "Recently deleted" shared vaults (spec 03 §11.2) ----

    /**
     * Read the shared vaults this account deleted, still in their grace, into [ContentState.deletedVaults]: only those
     * whose deletion this device's verified log shows. Restoring one is the owner's signed `restore`, a vault-log
     * action of the app API; after it, the app API syncs the content and reads this list again.
     */
    suspend fun openDeletedVaults(): ActionResult

    /** The list closed: what was read goes. */
    fun closeDeletedVaults()

    // ---- an item's history (the server keeps its last 10 saves) ----

    /** Read [itemId]'s earlier versions into [ContentState.history], newest first. */
    suspend fun openItemHistory(itemId: String): ActionResult

    /** The history closed: the versions read go. */
    fun closeItemHistory()

    /** One earlier version's password, for an explicit Show; null when it has none or the history is not open. */
    fun historyPassword(itemId: String, rev: Long): String?

    /**
     * Put an earlier version back: an ordinary save of it over the item (the server keeps the version it replaces),
     * without the attachments the item no longer has.
     */
    suspend fun restoreItemVersion(itemId: String, rev: Long): ActionResult

    // ---- moving and copying between vaults ----

    /**
     * The vaults [itemId] can be copied to, and moved to when [canMoveOut]: the writable ones but its own. An item in a
     * vault this account only reads (or that is frozen, failed or withheld) can still be copied out.
     */
    fun moveTargets(itemId: String): List<VaultChoiceView>

    /** Whether [itemId] can be moved out of its vault (a move deletes it there), not only copied. */
    fun canMoveOut(itemId: String): Boolean

    /** The person cancelled moving or copying [itemId]: what an unfinished try kept goes. A lock is not a cancel. */
    fun cancelMove(itemId: String)

    /**
     * Move (copy, then delete the original) or copy [itemId] into [targetVaultId], one of [moveTargets]. Attachments go
     * too. A target that refuses the copy, or an item that changed meanwhile, stops it with the original untouched; a
     * try that did not finish is kept until this content closes, so Try again replays the same ids.
     */
    suspend fun moveOrCopyItem(itemId: String, targetVaultId: String, move: Boolean): ActionResult

    /**
     * [moveOrCopyItem], and the id of the item it made in [targetVaultId] ([MoveMade.madeItemId]): the copy this run
     * made, or the one an earlier try made that this one found there. [MoveMade.result] is exactly what
     * [moveOrCopyItem] answers. A caller that must know which item is the copy reads it here, instead of comparing the
     * target vault before and after.
     */
    suspend fun moveOrCopyItemWithId(itemId: String, targetVaultId: String, move: Boolean): MoveMade

    /**
     * Copy every item of [vaultId] into the personal vault: a shared vault before it is deleted, a vault that is
     * frozen, failed or withheld, or one in the holding area ([ContentState.held]) while it can be read. Copies only:
     * nothing in [vaultId] changes. [ContentState.copying] shows the progress; a retry after a failure converges.
     */
    suspend fun saveVaultItemsToPersonal(vaultId: String): ActionResult

    /**
     * Bring [picks], items this device holds of [fromVaultId] (a vault in the holding area, deleted behind a move's
     * back; or one still open here), each with its files, into [targetVaultId], a vault this account may write. A pick
     * that names an earlier copy ([HeldPick.replaces], in [targetVaultId]) replaces it: the new copy first, then the
     * earlier one deleted, so the item is never in neither; an earlier copy someone changed since is kept
     * ([HeldCopied.earlierKept]). Copies only: nothing of [fromVaultId] changes.
     *
     * A fresh sync first; into a vault the account owns, the room for what is left to copy is checked on it and a
     * shortfall stops the work before anything is sent ([ContentState.space] and the result's sentence say which
     * limit). Safe to run twice: a pick already copied is found, answered with the same [HeldCopied.madeItemId] and not
     * copied again. A lock in the middle leaves no item half-made: the pick in hand is not made, its earlier copy stays,
     * and the next unlock says how far it got. [ContentState.copying] shows the progress.
     *
     * [HeldBrought.made] lists every pick made (or found made) before the run ended, whatever [HeldBrought.result] says.
     * Files the server no longer hands over are left out of their copy, counted per pick and said in the notice.
     *
     * A pick the person deleted on this device, whose deletion was still waiting when the vault closed (queued, or
     * parked with the held copy), is not copied: the deletion is what is carried. Its earlier copy in [targetVaultId], if
     * the pick names one, is deleted as a replaced copy is (into the target's trash; kept when someone changed it
     * since). It is in [HeldBrought.deleted], never in [HeldBrought.made], and the notice counts only the copies made.
     */
    suspend fun bringHeldItemsInto(fromVaultId: String, targetVaultId: String, picks: List<HeldPick>): HeldBrought

    /**
     * The check "Move everything to a new vault" makes before it starts (spec 03 §14.4, design §3.13): a fresh sync,
     * then whether the account has room for every item of [vaultId] this device shows, less [copiedItemIds] (those an
     * earlier run already copied), with their files (a size another member declared is capped at the policy's limit for
     * one file), plus a new shared vault named [newVaultName] (null when the run's new vault exists already). It sends
     * nothing else and changes nothing. NOT_ENOUGH: do not start, say [SpaceCheck.line]; NOT_ENOUGH_ON_DECLARED_SIZES or UNKNOWN:
     * go on, the server decides. Null when the check could not be made (the content closed, or the sync failed: the
     * move would fail the same way).
     */
    suspend fun spaceForMoveEverything(vaultId: String, newVaultName: String?, copiedItemIds: List<String>): SpaceCheck?

    /** The items of a vault in the holding area, read-only; empty when it can no longer be read here. */
    fun heldItems(vaultId: String): List<ItemSummary>

    /**
     * "Remove from this device" (spec 02 §10.6): drop this device's copy of a vault in the holding area, or of a vault
     * that is no longer verified here. It tells the server nothing. A vault still open to this account is left
     * through its history instead (the shared vaults screen).
     */
    fun removeFromDevice(vaultId: String): ActionResult

    /** Rename a shared vault this account owns. The name is encrypted and syncs to every member. */
    suspend fun renameSharedVault(vaultId: String, name: String): ActionResult

    // ---- vault health (design 2026-08-23) ----

    /**
     * The health line of every login with a password, by item id (the current app's line under a row and in a login's
     * view: strength, reuse, last used, and breaches once checked). Built from what this device holds in one pass, with
     * no call; ask once per [state], never once per row. A login with no password has no line.
     */
    fun itemHealth(): Map<String, ItemHealthLine>

    /**
     * The age and last use of every login, by item id, a login with no password included: the current app's line on
     * Health's staleness list ("last used: … · last changed: …", and how long since someone checked it still works),
     * which lists every login, where [itemHealth] follows the passwords list, which lists those with a password. Built
     * from what this device holds in one pass, with no call; ask once per [state], never once per row.
     */
    fun loginAges(): Map<String, LoginAgeLine>

    /** [itemId]'s expiry, if it is a card with one: the label, whether it is over, and the short form for Copy. */
    fun cardExpiry(itemId: String): CardExpiryView?

    /**
     * The brand of a card number as it is being typed ("Visa"), for the editor's label; null while it is not known.
     * [number] is read and not kept.
     */
    fun cardBrandOf(number: String): String?

    /** Open vault health ([ContentState.health]). */
    fun openHealth()

    fun closeHealth()

    /** The screen again from the vault as it is now (an item opened from it may have changed). */
    fun refreshHealth()

    /** List the logins snoozed for now too. The counts at the top never change with it. */
    fun setHealthShowSnoozed(show: Boolean)

    fun dismissHealthMessage()

    /**
     * Check every login's password against known breaches (spec 03 §8, k-anonymity): only the first 5 hex characters
     * of each distinct password's SHA-1 go to the server, and the match is made here. A range that can't be fetched
     * leaves its logins without a verdict, never "none". Closing the screen or this content stops it.
     */
    suspend fun checkBreaches(): ActionResult

    /** Merge copies that have the same password (core's plan: saved sites from every copy are kept). */
    suspend fun mergeDuplicates(signature: String): ActionResult

    /** Keep one of copies with different passwords: the others go to the trash, their passwords into its history first. */
    suspend fun keepDuplicate(signature: String, keepId: String): ActionResult

    /** "Not duplicates": every copy is marked with the group as it is, so it stays quiet until one of them changes. */
    suspend fun markNotDuplicates(signature: String): ActionResult

    /** Put a group marked "not duplicates" back on the list. */
    suspend fun restoreDuplicates(signature: String): ActionResult

    /** Check logins one at a time, from the list as it is shown: all of them, worst first, or only the never-checked. */
    fun startCheckRun(neverCheckedOnly: Boolean)

    fun checkLogin(itemId: String)

    /** Move on without a verdict: nothing is written. */
    fun skipCheck()

    fun stopCheckRun()

    /** What the person found at the site: "ok", "bad", "gone" or "blocked". Only the verdict is written, on the item. */
    suspend fun recordCheck(itemId: String, result: String): ActionResult

    /** Bring a snoozed login back into the list now; its verdict stays. */
    suspend fun unsnoozeLogin(itemId: String): ActionResult

    /** The login just marked as gone, to the trash. */
    suspend fun trashGoneLogin(): ActionResult

    /** "Keep it": the verdict stays recorded; only the offer goes. */
    fun keepGoneLogin()

    /** The offer after "bad", answered: taken ([opening]), the run ends here; declined, only the offer goes. */
    fun answerBadOffer(opening: Boolean)

    // ---- import (spec 06) ----

    /**
     * Read a CSV export and plan its import into the personal vault, against what is already there
     * ([ContentState.csvImport]). [bytes] are zeroed once read. Nothing is sent until [confirmImport].
     */
    suspend fun importCsv(bytes: ByteArray): ActionResult

    /** Import into [vaultId] instead: the plan is made again against that vault's items. Only before the import began. */
    suspend fun setImportVault(vaultId: String): ActionResult

    /**
     * Encrypt and send the planned items into the chosen vault. A failure keeps the plan: Retry sends the same items,
     * under the same ids, so nothing is imported twice.
     */
    suspend fun confirmImport(): ActionResult

    /** Close the import: the parsed file and the plan go. */
    fun closeImport()

    // ---- export (spec 07) ----

    /**
     * Open the export screen for [kind] ([ContentState.exporting]): a sync first (offline, the vault as of the last
     * sync, which the screen says), then what the export would hold, by vault. Nothing is made until the person has
     * chosen a folder ([csvFile], [backupFile]).
     */
    suspend fun openExport(kind: ExportKind): ActionResult

    /** Put a shared vault in the export or leave it out; the personal vault is always in. */
    fun setExportVault(vaultId: String, included: Boolean)

    /** Backup: whether the files attached to its items go in (up to the 64 MiB cap; the rest are named). */
    fun setExportAttachments(include: Boolean)

    fun closeExport()

    /**
     * The CSV for the folder the person chose, once the tick ([acknowledged]) covers the formula cells the screen
     * listed; a vault that changed meanwhile writes nothing and the screen comes back with the new list. Null when
     * nothing is to be written (the screen says why). The bytes are plaintext: write them once, there, and zero them.
     */
    fun csvFile(acknowledged: Boolean): ExportFile?

    /**
     * The backup for the folder the person chose (spec 07 §2): made in memory under [passphrase] (typed twice the
     * same, at least "good"), opened again under it and every file read back before it is handed over. Null when
     * nothing is to be written (the screen says why).
     */
    suspend fun backupFile(passphrase: String, confirm: String): ExportFile?

    /**
     * [backupFile] for a screen that keeps the passphrase in a `CharArray`: both arrays are zeroed before this
     * returns, whatever happens. (The backup format's KDF still takes the passphrase as a string for the moment it
     * runs; that copy is not held past the call.)
     */
    suspend fun backupFileChars(passphrase: CharArray, confirm: CharArray): ExportFile?

    /**
     * The file was written to [folder] as [fileName] and read back the same: the screen says what it holds. [folder]
     * may be "" when the picker names none (Android's document picker); the sentence then leaves it out.
     */
    fun exportSaved(fileName: String, folder: String)

    /** Nothing was saved: the folder could not be written to, or ([written]) the file did not read back and was removed. */
    fun exportNotSaved(written: Boolean)

    // ---- AutoFill: the working set, and the extensions' saves (design 2026-11-09) ----

    /**
     * The logins AutoFill may offer, those matching one of [hosts] (domains or URLs) first. The working set is the
     * vaults of [ContentState.vaults] that are neither frozen nor failed (a withheld vault stays readable, spec 02
     * §10.4); a vault not accepted, or only in the holding area, is never in it. No secret.
     */
    fun fillLogins(hosts: List<String>): List<io.silencelen.andvari.core.app.FillLogin>

    /** Whether [itemId] is a login of the working set for one of [identifiers]: asked before a suggestion is filled. */
    fun fillMatches(itemId: String, identifiers: List<String>): Boolean

    /** The username and password of a login of the working set; null for anything else. */
    fun fillCredential(itemId: String): io.silencelen.andvari.core.app.FillCredential?

    /** The payment cards of the working set, by name. Nothing secret: [fillCardField] releases one field at a time. */
    fun fillCards(): List<io.silencelen.andvari.core.app.FillCard>

    /** One field of a card of the working set: "number", "expMonth", "expYear", "cvv", "name" or "postal"; null otherwise. */
    fun fillCardField(itemId: String, field: String): String?

    /**
     * [fillCredential] for a row that must carry its values BEFORE the person picked anything (Android: a verified
     * browser's rows and a vetted app's own logins, which the platform fills on a pick without asking andvari again). It
     * records NO use: a row offered is not a row used. When the platform says which row the person picked, call
     * [recordFillPicked] for it, once.
     */
    fun fillCredentialUnrecorded(itemId: String): io.silencelen.andvari.core.app.FillCredential?

    /** [fillCardField] recording no use, for the same rows as [fillCredentialUnrecorded]. */
    fun fillCardFieldUnrecorded(itemId: String, field: String): String?

    /**
     * The person picked [itemId] from rows built with [fillCredentialUnrecorded] or [fillCardFieldUnrecorded]: its one use
     * is recorded now (spec 02 §8.2), as [fillCredential] would have, within the same window that makes a card's several
     * fields one use. False, and nothing recorded, when it is not a login or a card of the working set now (or the content
     * is closed).
     */
    fun recordFillPicked(itemId: String): Boolean

    /**
     * [recordFillPicked] for a pick the platform reports later than it happened: the use is recorded at [pickedAtMs], the
     * time of the pick (Unix milliseconds), not the time of this call (spec 02 §8.2: `lastUsedAt` is when the login was
     * used). A time after now is recorded as now, and one before 1970 is not a time: nothing is recorded. The window that
     * makes several releases one use is measured between the pick and the use recorded nearest it.
     */
    fun recordFillPickedAt(itemId: String, pickedAtMs: Long): Boolean

    /**
     * Close [vaultId] for writing on this device with [reason], or open it again with null. The app interface sets it
     * from the moment a vault's deletion is signed and waiting ([VaultClosedReason.DELETION_WAITING]) and clears it
     * when the deletion is stored or dropped. While it is set, every change that would put something into the vault or
     * change something in it (a new item, an edit, a delete, a delete for good, a restore, an import, a move or a copy
     * into it, a move out of it, a file) is refused before anything is sealed, with a line that says why; a copy out
     * stays allowed, and the vault's rows and its entry in [ContentState.vaults] read as not writable. The mark is kept
     * in the account's cache on this device, across a lock and a restart, until it is cleared here or the account's data
     * leaves the device.
     */
    fun markVaultClosedForWriting(vaultId: String, reason: VaultClosedReason?)

    /**
     * What the system's AutoFill suggestions may know (iOS `ASCredentialIdentityStore`): one entry per web address of
     * each login of the working set that has a username. Empty while the policy forbids an offline cache
     * ([ContentHost.offlineCacheAllowed]), so the host then clears the system's copy. No password leaves through here.
     */
    fun credentialIdentities(): List<io.silencelen.andvari.core.app.CredentialIdentity>

    /**
     * Read the extensions' save queue now (the return to the foreground; it is read after every sync too): publish the
     * key they seal to, list what was captured ([ContentState.pendingSaves]) and save by itself what may be
     * ([ContentState.appliedSaves]). A save only ever goes to the personal vault, and only while it is writable here.
     * [ActionResult.NotDone] on a host that gave no queue ([EngineVaultContent] without [ContentKeeping], the fake).
     */
    suspend fun readSaveQueue(): ActionResult

    /** The password of a listed capture, for the person to check before saving it; null when it is gone. */
    fun pendingSavePassword(id: String): String?

    /** Save one listed capture by hand: what its row named, or nothing (the row is shown again as the vault is now). */
    suspend fun confirmPendingSave(id: String): ActionResult

    /** Discard one listed capture: it leaves the queue and nothing is written. */
    suspend fun discardPendingSave(id: String): ActionResult

    /** Take back one automatic save; a login changed since is left alone. */
    suspend fun undoAppliedSave(id: String): ActionResult

    /** Take back every listed automatic save that has not been changed since. */
    suspend fun undoAllAppliedSaves(): ActionResult

    /** The list of automatic saves has been read: it goes, and with it the undo. */
    suspend fun dismissAppliedSaves(): ActionResult

    // ---- sync ----

    /**
     * Sync now, as the person asked ("Synced." or the sentence for what went wrong). The first call after unlock
     * shows this device's copy before it talks to the server.
     */
    suspend fun refresh(): ActionResult

    /**
     * A sync nobody asked for (the event bell, a timer, the return to the foreground): it shows no busy state and no
     * "Synced.", and answers what [refresh] would. [ContentState.sync] says how it went either way.
     */
    suspend fun syncQuietly(): ActionResult

    /**
     * How many saves with files this device keeps to finish and the server does not have: a save whose files could not
     * all go up (no answer, or a lock cut it short), kept under the ids it was given until it is finished after an unlock
     * or its editor is closed. They are not in the item engine's queue, and a sign-out deletes them with the copy, so the
     * count of changes not sent adds them. Null when this content cannot read them now (closed by a lock, or the record
     * is unreadable): this device cannot tell.
     */
    fun keptSavesWaiting(): Int?

    /**
     * How many moves (or copies) into another vault this content keeps to be finished (a lock or a failure cut them short
     * between the copy and the removal of the original). Null when they cannot be read now.
     */
    fun movesWaiting(): Int?

    fun dismissError()

    fun dismissNotice()
}

/**
 * What the vault's content shows now. A new object for every change; [revision] counts them, so a host that only
 * needs to know "something changed" (the app API's snapshot) compares it.
 */
class ContentState internal constructor(
    /** Moves by one with every new state of this [VaultContent]. */
    val revision: Long,
    /** The list, filtered by [query], by name. */
    val items: List<ItemSummary>,
    val query: String,
    /** The vaults this account can read on this device, personal first, then by name. */
    val vaults: List<ContentVault>,
    /** What the item engine raised for the person to read (a vault left or withheld, writes refused, a server misbehaving). */
    val vaultNotices: List<VaultNoticeView>,
    /** How the last sync went. */
    val sync: VaultSyncState,
    /** How many items have a change waiting to be sent (each is marked [ItemSummary.pendingSync] in the list). */
    val queued: Int,
    /**
     * The server is stopped on this device (its card chain forked, design §4.4): what is shown is this device's copy,
     * and nothing can be saved.
     */
    val serverStopped: Boolean,
    /** A sync is running. */
    val syncing: Boolean,
    /** An intent the person started is running. */
    val busy: Boolean,
    /** A failure nobody's intent answered (a quiet sync whose writes were refused). */
    val error: String?,
    /** A line to show once ("Synced.", "Offline — your save is queued …"). */
    val notice: String?,
    /** The trash as last read, while it is open ([VaultContent.openTrash]); null while it is closed. */
    val trash: List<TrashItemView>?,
    /** An item's earlier versions, while its history is open ([VaultContent.openItemHistory]). */
    val history: ItemHistoryView?,
    /** The files of the item an open editor has ([VaultContent.openAttachmentDraft]). */
    val attachmentDraft: AttachmentDraftView?,
    /** A save with new files running: how many went up, of how many. */
    val upload: UploadView?,
    /** "Recently removed": vaults this account no longer has, whose copy this device keeps for 30 days (spec 02 §10.6). */
    val held: List<HeldVaultRow>,
    /** A copy of a vault's items into the personal vault, while it runs ([VaultContent.saveVaultItemsToPersonal]). */
    val copying: CopyProgressView?,
    /** A CSV being imported, while its screen is open ([VaultContent.importCsv]). */
    val csvImport: CsvImportView?,
    /** The export screen, while it is open ([VaultContent.openExport]). */
    val exporting: ExportView?,
    /** Vault health, while its screen is open ([VaultContent.openHealth]). */
    val health: HealthView?,
    /** Logins an extension captured that were not saved by themselves, each with its reason. */
    val pendingSaves: List<io.silencelen.andvari.core.app.PendingSaveView>,
    /** Logins saved by themselves from the queue, each with its undo, until the list is dismissed. */
    val appliedSaves: List<io.silencelen.andvari.core.app.AppliedSaveView>,
    /** The owner's "Recently deleted" shared vaults, newest first, while that list is open; null while it is closed. */
    val deletedVaults: List<DeletedVaultView>?,
    /**
     * The last check before a large copy that has something to say (spec 03 §14.4): NOT_ENOUGH (the import, copy or move was
     * not started: which limit, by how much, and that the operator can raise it) or NOT_ENOUGH_ON_DECLARED_SIZES (it went
     * on, and the server decides). Null when there is nothing to say. It goes at the next check, with the import screen
     * for an import's, and with [VaultContent.dismissError].
     */
    val space: SpaceCheck?,
    /**
     * The account's own use and limits for Settings' storage line (the four meters of the freshest completed sync); null
     * when the server gave none, and Settings then shows nothing.
     */
    val storage: AccountStorage?,
    /** What [notice] is about; null exactly when [notice] is. */
    val noticeKind: ContentNoticeKind?,
    /**
     * With [ContentNoticeKind.LOCK]: each thing a lock cut short before it finished (a save or an import not kept, a copy
     * into a vault with its counts, a move, a delete, a file, a restore), as [notice] says them; empty otherwise. An app
     * needs no line of its own about these.
     */
    val lockCut: List<LockCut>,
    /**
     * This device's copy is being removed for the server's policy (the one try to send what waits runs, then the wipe):
     * the line to show where [serverStopped]'s line would be. Not a stopped server: [serverStopped] is false meanwhile, so
     * keep Save and the other writes offered; each is refused meanwhile with a refusal's own line (a save's: "this change
     * wasn't made", [ContentCopy.COPY_BEING_REMOVED]). Null otherwise.
     */
    val removingLine: String? = null,
)

/** One vault in the holding area ("Recently removed"). */
class HeldVaultRow internal constructor(
    val vaultId: String,
    /** Its name, while its key is still offered here; empty when it can no longer be named. */
    val name: String,
    /** What happened to it and how long its copy stays, in a sentence. */
    val line: String,
    val itemCount: Int,
    /** Its items can still be read and copied out on this device ([VaultContent.heldItems], [VaultContent.saveVaultItemsToPersonal]). */
    val readable: Boolean,
    /** When this device drops its copy (unix milliseconds). */
    val expungeAtMs: Long,
)

/** One login's health on its row or in its view ([VaultContent.itemHealth]): what the Health screen says of it. */
class ItemHealthLine internal constructor(
    val itemId: String,
    /** Core's estimate of its password, in words ("very weak" to "strong"). */
    val strength: String,
    /** Very weak or weak. */
    val weak: Boolean,
    /** How many other logins have this exact password. */
    val reused: Int,
    /** When it was last used, as this account's devices recorded it (Unix milliseconds); null when never recorded. */
    val lastUsedAt: Long?,
    /** Known breaches of its password, from this unlock's check; null without a verdict (not checked, or changed since). */
    val breaches: Long?,
)

/**
 * One login's age and last use ([VaultContent.loginAges]), as the current app's staleness list shows them; a login
 * with no password has one too.
 */
class LoginAgeLine internal constructor(
    val itemId: String,
    /** When it last changed, by the server's clock (Unix milliseconds): "last changed", never the password's age. */
    val changedAt: Long,
    /** When it was last used, as this account's devices recorded it (Unix milliseconds); null when never recorded, which is not "never used". */
    val lastUsedAt: Long?,
    /** When someone last checked it still works (Unix milliseconds, a date ahead of this device's clock taken as now); null when never. */
    val checkedAt: Long?,
    /** How long since that check, or how the last check went ([Staleness.StaleBucket]; never shown as it is spelled). */
    val stale: io.silencelen.andvari.core.client.Staleness.StaleBucket,
    /** Under a snooze that has not run out: the staleness list leaves it out unless asked. */
    val snoozed: Boolean,
)

/** A card's expiry as its view shows it ([VaultContent.cardExpiry]). */
class CardExpiryView internal constructor(
    /** "07/2031", or whichever half the card has. */
    val label: String,
    /** The month is over, by this device's clock and time zone. False when the expiry cannot be read whole. */
    val expired: Boolean,
    /** "07/31", what a checkout's combined box takes, for Copy; null when a half is missing (the row is then read only). */
    val shortExpiry: String?,
)

/** What [VaultContent.moveOrCopyItemWithId] came to. */
class MoveMade internal constructor(
    /** What [VaultContent.moveOrCopyItem] answers for the same call. */
    val result: ActionResult,
    /**
     * The item in the target vault that is the copy: made by this call, or by an earlier try of the same move and found
     * there. Null when no copy is there as this device sees it (refused before the copy, a lock, no answer).
     */
    val madeItemId: String?,
)

/** What [VaultContent.bringHeldItemsInto] came to. */
class HeldBrought internal constructor(
    /** Ok, or the sentence that stopped it (a shortfall of space, a refusal, no answer); NotDone after a lock. */
    val result: ActionResult,
    /** Every pick made, or found made by an earlier run, before the run ended, in the order of the picks. */
    val made: List<HeldCopied>,
    /**
     * Every pick not copied because the person deleted it on this device and the deletion was still waiting
     * ([HeldDeleted]), before the run ended, in the order of the picks; its earlier copy, if named, was deleted unless kept.
     */
    val deleted: List<HeldDeleted> = emptyList(),
    /**
     * How many of [made] were found deleted in the target since an earlier run made them ([HeldCopied.deletedThere]):
     * not copied again, and not copies now; never counted as copied.
     */
    val deletedThere: Int = 0,
)

/** One vault this account can read on this device. */
class ContentVault internal constructor(
    val vaultId: String,
    val name: String,
    /** The account's personal vault; any other is shared, and everyone in it sees what is put there. */
    val personal: Boolean,
    /** `owner`, `writer` or `reader`, as this device verified it. */
    val role: String,
    val access: ContentVaultState,
    /**
     * Why the app interface holds this vault closed for writing on this device ([VaultContent.markVaultClosedForWriting]),
     * or null when it does not. While it is set, [access] is [ContentVaultState.CLOSED_FOR_WRITING] (unless the server is
     * stopped or the vault's history failed, forked or was withheld, which say more), and [closedLine] says why.
     */
    val closedFor: VaultClosedReason? = null,
    /**
     * The line a screen shows beside the vault while it is closed for writing ([closedFor]), the same sentence a change
     * into it is refused with ([ContentCopy.closedForWriting]); null when the vault is not closed.
     */
    val closedLine: String? = null,
) {
    /** Items can be added and changed here. */
    val writable: Boolean get() = access == ContentVaultState.WRITABLE
}

/** What this account may do in a vault, and why not when it may only read. */
enum class ContentVaultState {
    WRITABLE,

    /** This account is a reader of the vault. */
    READER,

    /**
     * The app interface closed the vault for writing on this device ([ContentVault.closedFor] says why: its deletion is
     * signed and waiting): nothing new can be put in it or changed in it here; items can still be copied out.
     */
    CLOSED_FOR_WRITING,

    /** The server stopped serving the vault and no verified reason says why (spec 02 §10.6): this device's copy, read-only. */
    WITHHELD,

    /** An entry of the vault's history failed verification (design §3.9): read-only until it verifies again. */
    FAILED,

    /** The vault's history forked (design §3.9): read-only; items can still be copied out. */
    FROZEN,

    /** The server is stopped on this device (design §4.4): nothing can be saved anywhere. */
    STOPPED,
}

/** How the last sync went. */
enum class VaultSyncState {
    /** No sync finished yet since unlock: the list is this device's copy. */
    NOT_YET,

    /** The last sync finished. */
    SYNCED,

    /** The server could not be reached: the list is this device's copy, and saves wait in the queue ([ContentState.queued]). */
    OFFLINE,

    /** The server answered with an older state than this device has seen (spec 05 T1): nothing of it was applied. */
    ROLLBACK,

    /** The server refused the sync (a session that ended, a newer app needed, a server error). */
    REFUSED,

    /** The server is stopped on this device (design §4.4): nothing is sent or accepted. */
    STOPPED,
}
