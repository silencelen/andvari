package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.Overtaken
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentContent
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.CredentialIdentity
import io.silencelen.andvari.core.app.ExportFile
import io.silencelen.andvari.core.app.FillCard
import io.silencelen.andvari.core.app.FillCredential
import io.silencelen.andvari.core.app.FillLogin
import io.silencelen.andvari.core.app.GeneratorSettings
import io.silencelen.andvari.core.app.ItemDetail
import io.silencelen.andvari.core.app.ItemSummary
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.OneTimeCode
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.app.VaultChoiceView
import io.silencelen.andvari.core.app.content.VaultContent
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlin.coroutines.cancellation.CancellationException

/**
 * An exception that escapes the shared code's work
 * must never take the app down or leave it unusable. One vault's data could make the shared code throw (a vault named
 * with the text of its own key did, until the shared code was fixed); whatever the cause, the app catches it where it starts
 * the work, says "something went wrong with this vault" (a placeholder), and every other vault and the rest of the app
 * go on. Nothing of the exception is kept, shown or logged: not its message, not its class (either can quote what it
 * was working on, a decrypted value included).
 *
 * Two things are never contained here: a cancellation (it is how work ends, and must reach the coroutine machinery),
 * and the shared code's "the keys are gone" ([Overtaken]), which is the lock and is said as the lock.
 */
internal object Contained {
    /** Whether [t] is a fault to contain: neither a cancellation nor the lock. */
    fun isFault(t: Throwable): Boolean = t !is CancellationException && !Overtaken.isLock(t)

    /** What a contained fault says where an answer is shown in place: the placeholder, marked. */
    val wentWrongText: String get() = UiText.ph(Placeholder.VAULT_WENT_WRONG).shown()

    /** The answer a contained fault gives where the caller waits for an [ActionResult]: said in place, never "done". */
    fun failed(): ActionResult = ActionResult.Failed(wentWrongText)
}

/**
 * Where a fault the app contained is said, for work that has no answer shown in place: the shared code's own
 * background work (a sync on a ring, the opening's sync), a redraw, a tap that answers nothing. The process's one model
 * listens ([TrustSeam] sets [sink]); before it exists, or in a test that set none, the fault is still contained.
 */
internal object AppFaults {
    @Volatile var sink: ((vaultId: String?) -> Unit)? = null

    /** Say a contained fault about [vaultId] (null: which vault is not known). Never throws. */
    fun report(vaultId: String? = null) {
        try {
            sink?.invoke(vaultId)
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
        }
    }

    /**
     * For a scope whose work is the shared code's (the engine's own scope, through [io.silencelen.andvari.core.app.engine.AppEngine.main],
     * and the model's): an exception that escapes a coroutine there is contained and said, never a crash. The lock
     * that escapes is the lock: the lock screen is already up, and nothing more is said.
     */
    fun handler(onFault: () -> Unit = { report(null) }): CoroutineExceptionHandler =
        CoroutineExceptionHandler { _, t -> if (Contained.isFault(t)) onFault() }
}

/**
 * The open vault's content as the app's screens and autofill reach it: every call goes to [inner], and a fault that
 * escapes one is contained. A call that answers an [ActionResult] answers [ActionResult.Failed] with the placeholder,
 * said in place by the screen that asked; any other call answers its "nothing" (no detail, no list, no code) and the
 * fault is said once above the screen ([onFault]). The next call is made afresh: nothing is marked broken, so one
 * vault's fault leaves every other vault working, and the same vault works again once its data does.
 *
 * Never contained: the lock ([Overtaken]) and a cancellation, which propagate as before. The calls that hold no work
 * (the state, its flow, observe and close) go straight through.
 */
internal class GuardedContent(
    val inner: VaultContent,
    /**
     * The opening this content belongs to: one per unlock of one account ([TrustModel.content]). The same object when the
     * shared code composes the same account's vault again while it stays open (after the policy's wipe of its copy), so
     * the screens keep what is on show and what was typed; a new one after any lock, sign-out or other account.
     */
    val opening: Any = Any(),
    private val onFault: (vaultId: String?) -> Unit,
) : VaultContent by inner {
    private inline fun <T> quiet(vaultId: String?, fallback: T, block: () -> T): T = try {
        block()
    } catch (t: Throwable) {
        if (!Contained.isFault(t)) throw t
        onFault(vaultId)
        fallback
    }

    private inline fun act(block: () -> ActionResult): ActionResult = try {
        block()
    } catch (t: Throwable) {
        if (!Contained.isFault(t)) throw t
        Contained.failed()
    }

    private inline fun unit(vaultId: String? = null, block: () -> Unit) = quiet(vaultId, Unit, block)

    override fun setQuery(query: String) = unit { inner.setQuery(query) }
    override fun itemDetail(itemId: String): ItemDetail? = quiet(null, null) { inner.itemDetail(itemId) }
    override fun revealSecret(itemId: String, field: SecretField): String? = quiet(null, null) { inner.revealSecret(itemId, field) }
    override fun passwordHistory(itemId: String): List<Long> = quiet(null, emptyList()) { inner.passwordHistory(itemId) }
    override fun previousPassword(itemId: String, index: Int): String? = quiet(null, null) { inner.previousPassword(itemId, index) }
    override fun oneTimeCode(itemId: String): OneTimeCode? = quiet(null, null) { inner.oneTimeCode(itemId) }
    override fun generatePassword(settings: GeneratorSettings): String = quiet(null, "") { inner.generatePassword(settings) }
    override suspend fun saveLogin(itemId: String?, input: LoginInput, vaultId: String?): ActionResult = act { inner.saveLogin(itemId, input, vaultId) }
    override suspend fun saveCard(itemId: String?, input: CardInput, vaultId: String?): ActionResult = act { inner.saveCard(itemId, input, vaultId) }
    override fun cardNumberWarning(number: String): String? = quiet(null, null) { inner.cardNumberWarning(number) }
    override fun cardBrandOf(number: String): String? = quiet(null, null) { inner.cardBrandOf(number) }
    override fun cardExpiry(itemId: String): io.silencelen.andvari.core.app.content.CardExpiryView? = quiet(null, null) { inner.cardExpiry(itemId) }
    override fun itemHealth(): Map<String, io.silencelen.andvari.core.app.content.ItemHealthLine> = quiet(null, emptyMap()) { inner.itemHealth() }
    override fun loginAges(): Map<String, io.silencelen.andvari.core.app.content.LoginAgeLine> = quiet(null, emptyMap()) { inner.loginAges() }
    override suspend fun saveNote(itemId: String?, input: NoteInput, vaultId: String?): ActionResult = act { inner.saveNote(itemId, input, vaultId) }
    override suspend fun deleteItem(itemId: String): ActionResult = act { inner.deleteItem(itemId) }
    override fun vaultsForNewItems(): List<VaultChoiceView> = quiet(null, emptyList()) { inner.vaultsForNewItems() }
    override fun vaultName(vaultId: String): String? = quiet(vaultId, null) { inner.vaultName(vaultId) }
    override fun dismissVaultNotice(id: String) = unit { inner.dismissVaultNotice(id) }
    override fun openAttachmentDraft(itemId: String?) = unit { inner.openAttachmentDraft(itemId) }
    override fun closeAttachmentDraft() = unit { inner.closeAttachmentDraft() }
    override suspend fun addAttachment(name: String, bytes: ByteArray): ActionResult = act { inner.addAttachment(name, bytes) }
    override fun removeAttachment(attachmentId: String) = unit { inner.removeAttachment(attachmentId) }
    override suspend fun readAttachment(itemId: String, attachmentId: String): AttachmentContent = try {
        inner.readAttachment(itemId, attachmentId)
    } catch (t: Throwable) {
        if (!Contained.isFault(t)) throw t
        AttachmentContent("", null, Contained.wentWrongText)
    }
    override suspend fun openTrash(): ActionResult = act { inner.openTrash() }
    override fun closeTrash() = unit { inner.closeTrash() }
    override suspend fun restoreFromTrash(itemId: String): ActionResult = act { inner.restoreFromTrash(itemId) }
    override suspend fun purgeFromTrash(itemId: String): ActionResult = act { inner.purgeFromTrash(itemId) }
    override suspend fun openDeletedVaults(): ActionResult = act { inner.openDeletedVaults() }
    override fun closeDeletedVaults() = unit { inner.closeDeletedVaults() }
    override suspend fun openItemHistory(itemId: String): ActionResult = act { inner.openItemHistory(itemId) }
    override fun closeItemHistory() = unit { inner.closeItemHistory() }
    override fun historyPassword(itemId: String, rev: Long): String? = quiet(null, null) { inner.historyPassword(itemId, rev) }
    override suspend fun restoreItemVersion(itemId: String, rev: Long): ActionResult = act { inner.restoreItemVersion(itemId, rev) }
    override fun moveTargets(itemId: String): List<VaultChoiceView> = quiet(null, emptyList()) { inner.moveTargets(itemId) }
    override fun canMoveOut(itemId: String): Boolean = quiet(null, false) { inner.canMoveOut(itemId) }
    override fun cancelMove(itemId: String) = unit { inner.cancelMove(itemId) }
    override suspend fun moveOrCopyItem(itemId: String, targetVaultId: String, move: Boolean): ActionResult = act { inner.moveOrCopyItem(itemId, targetVaultId, move) }
    override suspend fun saveVaultItemsToPersonal(vaultId: String): ActionResult = act { inner.saveVaultItemsToPersonal(vaultId) }
    override fun heldItems(vaultId: String): List<ItemSummary> = quiet(vaultId, emptyList()) { inner.heldItems(vaultId) }
    override fun removeFromDevice(vaultId: String): ActionResult = act { inner.removeFromDevice(vaultId) }
    override suspend fun renameSharedVault(vaultId: String, name: String): ActionResult = act { inner.renameSharedVault(vaultId, name) }
    override fun openHealth() = unit { inner.openHealth() }
    override fun closeHealth() = unit { inner.closeHealth() }
    override fun refreshHealth() = unit { inner.refreshHealth() }
    override fun setHealthShowSnoozed(show: Boolean) = unit { inner.setHealthShowSnoozed(show) }
    override fun dismissHealthMessage() = unit { inner.dismissHealthMessage() }
    override suspend fun checkBreaches(): ActionResult = act { inner.checkBreaches() }
    override suspend fun mergeDuplicates(signature: String): ActionResult = act { inner.mergeDuplicates(signature) }
    override suspend fun keepDuplicate(signature: String, keepId: String): ActionResult = act { inner.keepDuplicate(signature, keepId) }
    override suspend fun markNotDuplicates(signature: String): ActionResult = act { inner.markNotDuplicates(signature) }
    override suspend fun restoreDuplicates(signature: String): ActionResult = act { inner.restoreDuplicates(signature) }
    override fun startCheckRun(neverCheckedOnly: Boolean) = unit { inner.startCheckRun(neverCheckedOnly) }
    override fun checkLogin(itemId: String) = unit { inner.checkLogin(itemId) }
    override fun skipCheck() = unit { inner.skipCheck() }
    override fun stopCheckRun() = unit { inner.stopCheckRun() }
    override suspend fun recordCheck(itemId: String, result: String): ActionResult = act { inner.recordCheck(itemId, result) }
    override suspend fun unsnoozeLogin(itemId: String): ActionResult = act { inner.unsnoozeLogin(itemId) }
    override suspend fun trashGoneLogin(): ActionResult = act { inner.trashGoneLogin() }
    override fun keepGoneLogin() = unit { inner.keepGoneLogin() }
    override fun answerBadOffer(opening: Boolean) = unit { inner.answerBadOffer(opening) }
    override suspend fun importCsv(bytes: ByteArray): ActionResult = act { inner.importCsv(bytes) }
    override suspend fun setImportVault(vaultId: String): ActionResult = act { inner.setImportVault(vaultId) }
    override suspend fun confirmImport(): ActionResult = act { inner.confirmImport() }
    override fun closeImport() = unit { inner.closeImport() }
    override suspend fun openExport(kind: io.silencelen.andvari.core.app.ExportKind): ActionResult = act { inner.openExport(kind) }
    override fun setExportVault(vaultId: String, included: Boolean) = unit(vaultId) { inner.setExportVault(vaultId, included) }
    override fun setExportAttachments(include: Boolean) = unit { inner.setExportAttachments(include) }
    override fun closeExport() = unit { inner.closeExport() }
    override fun csvFile(acknowledged: Boolean): ExportFile? = quiet(null, null) { inner.csvFile(acknowledged) }
    override suspend fun backupFile(passphrase: String, confirm: String): ExportFile? = quiet(null, null) { inner.backupFile(passphrase, confirm) }
    override suspend fun backupFileChars(passphrase: CharArray, confirm: CharArray): ExportFile? = quiet(null, null) { inner.backupFileChars(passphrase, confirm) }
    override fun exportSaved(fileName: String, folder: String) = unit { inner.exportSaved(fileName, folder) }
    override fun exportNotSaved(written: Boolean) = unit { inner.exportNotSaved(written) }
    override fun fillLogins(hosts: List<String>): List<FillLogin> = quiet(null, emptyList()) { inner.fillLogins(hosts) }
    override fun fillMatches(itemId: String, identifiers: List<String>): Boolean = quiet(null, false) { inner.fillMatches(itemId, identifiers) }
    override fun fillCredential(itemId: String): FillCredential? = quiet(null, null) { inner.fillCredential(itemId) }
    override fun fillCards(): List<FillCard> = quiet(null, emptyList()) { inner.fillCards() }
    override fun fillCardField(itemId: String, field: String): String? = quiet(null, null) { inner.fillCardField(itemId, field) }
    override fun fillCredentialUnrecorded(itemId: String): FillCredential? = quiet(null, null) { inner.fillCredentialUnrecorded(itemId) }
    override fun fillCardFieldUnrecorded(itemId: String, field: String): String? = quiet(null, null) { inner.fillCardFieldUnrecorded(itemId, field) }
    override fun recordFillPicked(itemId: String): Boolean = quiet(null, false) { inner.recordFillPicked(itemId) }
    override fun recordFillPickedAt(itemId: String, pickedAtMs: Long): Boolean = quiet(null, false) { inner.recordFillPickedAt(itemId, pickedAtMs) }
    override fun credentialIdentities(): List<CredentialIdentity> = quiet(null, emptyList()) { inner.credentialIdentities() }
    override suspend fun readSaveQueue(): ActionResult = act { inner.readSaveQueue() }
    override fun pendingSavePassword(id: String): String? = quiet(null, null) { inner.pendingSavePassword(id) }
    override suspend fun confirmPendingSave(id: String): ActionResult = act { inner.confirmPendingSave(id) }
    override suspend fun discardPendingSave(id: String): ActionResult = act { inner.discardPendingSave(id) }
    override suspend fun undoAppliedSave(id: String): ActionResult = act { inner.undoAppliedSave(id) }
    override suspend fun undoAllAppliedSaves(): ActionResult = act { inner.undoAllAppliedSaves() }
    override suspend fun dismissAppliedSaves(): ActionResult = act { inner.dismissAppliedSaves() }
    override suspend fun refresh(): ActionResult = act { inner.refresh() }
    override suspend fun syncQuietly(): ActionResult = act { inner.syncQuietly() }
    override fun dismissError() = unit { inner.dismissError() }
    override fun dismissNotice() = unit { inner.dismissNotice() }
}
