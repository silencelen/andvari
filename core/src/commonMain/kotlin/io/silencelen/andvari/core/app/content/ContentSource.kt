package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.client.DecryptedItemVersion
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.items.CopySize
import io.silencelen.andvari.core.client.items.DeletedVault
import io.silencelen.andvari.core.client.items.QuotaRoom
import io.silencelen.andvari.core.client.items.TrashActionDone
import io.silencelen.andvari.core.client.items.VaultClosedReason
import io.silencelen.andvari.core.model.wire.QuotaUse
import io.silencelen.andvari.core.client.items.HeldCopied
import io.silencelen.andvari.core.client.items.HeldPick
import io.silencelen.andvari.core.client.items.HeldRescue
import io.silencelen.andvari.core.client.items.HeldVaultView
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.MovePlan
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.NewAttachment
import io.silencelen.andvari.core.client.items.SavedItem
import io.silencelen.andvari.core.client.items.SyncReport
import io.silencelen.andvari.core.client.items.VaultView
import io.silencelen.andvari.core.client.items.Written

/**
 * What [ContentController] needs of the item plane: the members of [ItemEngine] it calls, with the engine's own
 * names and answers. [EngineContentSource] forwards to an engine; [FakeVaultContent] has an in-memory one. The
 * contract is the engine's KDoc.
 */
internal interface ContentSource {
    /** Traffic and writes are over for good (a forked pin); reading goes on. */
    val halted: Boolean
    val personalVaultId: String?

    /** Rebuild the working set from this device's copy; sends nothing. */
    suspend fun hydrate()
    fun items(): List<VaultItem>
    fun item(itemId: String): VaultItem?
    fun pendingSyncItemIds(): Set<String>

    /**
     * The items whose change this device sent and the server refused for good since the last call, with the refusal
     * ([io.silencelen.andvari.core.client.items.ItemEngine.takeRefusedForGood]); emptied by the call.
     */
    fun takeRefusedForGood(): Map<String, io.silencelen.andvari.core.client.items.ItemFailure>

    /** Asked before every drain of the queue ([io.silencelen.andvari.core.client.items.BeforeDrain]); null: nothing asked. */
    var beforeDrain: io.silencelen.andvari.core.client.items.BeforeDrain?
    fun vaults(): List<VaultView>
    fun notices(): List<ItemNotice>
    fun dismissNotice(id: String)
    suspend fun sync(): ItemResult<SyncReport>
    suspend fun save(
        itemId: String?,
        doc: ItemDoc,
        vaultId: String?,
        uploads: List<NewAttachment>,
        onProgress: ((done: Int, total: Int) -> Unit)?,
        draftItemId: String?,
        baseItemRev: Long?,
        /** [ItemEngine.save]'s: told when the put is handed to the queue. */
        onQueued: (() -> Unit)? = null,
    ): ItemResult<SavedItem>
    suspend fun remove(itemId: String): ItemResult<Written>

    /** [ItemEngine.sealedPut]; a source without the engine's seal seals nothing. */
    fun sealedPut(mutationId: String, itemId: String, doc: ItemDoc, vaultId: String, baseItemRev: Long, isNew: Boolean): ItemResult<io.silencelen.andvari.core.model.wire.Mutation> =
        ItemResult.Failed(io.silencelen.andvari.core.client.items.ItemFailure.NotAllowed(io.silencelen.andvari.core.client.items.ItemRefusal.VAULT_NOT_OPEN))
    suspend fun uploadEncryptedAttachment(attachmentId: String, itemId: String, vaultId: String, sealed: ByteArray): ItemResult<Unit>
    suspend fun downloadAttachment(ref: AttachmentRef): ItemResult<ByteArray>
    suspend fun itemVersions(itemId: String, vaultId: String): ItemResult<List<DecryptedItemVersion>>
    fun versionDocForRestore(itemId: String, version: ItemDoc): ItemDoc
    suspend fun deletedItems(): ItemResult<List<DeletedItemView>>
    /** A trash row's document for a restore, read when the trash's opening did not ([DeletedItemView.notRead]). */
    suspend fun deletedItemDoc(row: DeletedItemView): ItemResult<ItemDoc?>
    suspend fun restoreDeleted(itemId: String, vaultId: String, doc: ItemDoc): ItemResult<Unit>
    suspend fun purgeDeleted(itemId: String, vaultId: String): ItemResult<Unit>
    /** Trash actions answered as done, kept for the next whole read of the trash where the account's data is kept. */
    fun recordTrashAction(done: TrashActionDone)
    fun trashActionsDone(): List<TrashActionDone>
    fun clearTrashActionsDone()
    /** The app interface's mark on a vault closed for writing ([ItemEngine.markClosedForWriting]); null clears it. */
    fun markClosedForWriting(vaultId: String, reason: VaultClosedReason?)
    fun closedForWriting(vaultId: String): VaultClosedReason?
    suspend fun deletedVaults(): ItemResult<List<DeletedVault>>
    fun planMove(itemId: String, targetVaultId: String, deleteSource: Boolean): ItemResult<MovePlan>
    suspend fun runMove(plan: MovePlan, onProgress: ((done: Int, total: Int) -> Unit)?, finalSync: Boolean): ItemResult<Unit>
    suspend fun rescueToPersonal(vaultId: String, onProgress: ((done: Int, total: Int) -> Unit)?): ItemResult<Int>
    suspend fun rescueHeldToPersonal(vaultId: String, onProgress: ((done: Int, total: Int) -> Unit)?): ItemResult<HeldRescue>
    /** [ItemEngine.heldDocsToBring]. */
    fun heldDocsToBring(fromVaultId: String, targetVaultId: String, picks: List<HeldPick>): List<ItemDoc>
    /** [ItemEngine.bringHeldInto]. */
    suspend fun bringHeldInto(
        fromVaultId: String,
        targetVaultId: String,
        picks: List<HeldPick>,
        onMade: (HeldCopied) -> Unit,
        onProgress: ((done: Int, total: Int) -> Unit)?,
        onDeleted: (io.silencelen.andvari.core.client.items.HeldDeleted) -> Unit,
    ): ItemResult<List<HeldCopied>>
    fun heldVaults(): List<HeldVaultView>
    fun heldItems(vaultId: String): List<VaultItem>
    /** [ItemEngine.vaultDeleted]; a source without the engine's log knows of no deletion. */
    fun vaultDeleted(vaultId: String): Boolean = false
    fun removeFromDevice(vaultId: String): ItemResult<Unit>
    suspend fun renameVault(vaultId: String, newName: String): ItemResult<Unit>
    fun envelopes(): List<SyncItem>
    suspend fun breachRange(prefix: String): ItemResult<String>
    fun importProjections(vaultId: String?): ItemResult<CsvImport.ImportProjections>
    /** [onStopped]: what an import that did not land whole came to, heard before the failure is answered. */
    suspend fun importAll(
        items: List<CsvImport.PlannedItem>,
        onProgress: ((done: Int, total: Int) -> Unit)?,
        vaultId: String?,
        onStopped: (io.silencelen.andvari.core.client.items.ImportStopped) -> Unit,
    ): ItemResult<Unit>

    // ---- the account's own use and limits (spec 03 §14.4) ----
    fun quota(): QuotaUse?
    suspend fun roomFor(size: CopySize): ItemResult<QuotaRoom>
    fun importSize(items: List<CsvImport.PlannedItem>): CopySize
    fun copySize(docs: List<ItemDoc>, fileMaxBytes: Long, newVaultName: String?): CopySize
}

/** [ContentSource] over the item engine of the new session. */
internal class EngineContentSource(private val engine: ItemEngine) : ContentSource {
    override val halted: Boolean get() = engine.halted
    override val personalVaultId: String? get() = engine.personalVaultId
    override suspend fun hydrate() = engine.hydrate()
    override fun items(): List<VaultItem> = engine.items()
    override fun item(itemId: String): VaultItem? = engine.item(itemId)
    override fun pendingSyncItemIds(): Set<String> = engine.pendingSyncItemIds()
    override fun takeRefusedForGood(): Map<String, io.silencelen.andvari.core.client.items.ItemFailure> = engine.takeRefusedForGood()
    override var beforeDrain: io.silencelen.andvari.core.client.items.BeforeDrain?
        get() = engine.beforeDrain
        set(value) { engine.beforeDrain = value }
    override fun vaults(): List<VaultView> = engine.vaults()
    override fun notices(): List<ItemNotice> = engine.notices()
    override fun dismissNotice(id: String) = engine.dismissNotice(id)
    override suspend fun sync(): ItemResult<SyncReport> = engine.sync()
    override suspend fun save(
        itemId: String?,
        doc: ItemDoc,
        vaultId: String?,
        uploads: List<NewAttachment>,
        onProgress: ((done: Int, total: Int) -> Unit)?,
        draftItemId: String?,
        baseItemRev: Long?,
        onQueued: (() -> Unit)?,
    ): ItemResult<SavedItem> = engine.save(itemId, doc, vaultId, uploads, onProgress, draftItemId, baseItemRev, onQueued)
    override suspend fun remove(itemId: String): ItemResult<Written> = engine.remove(itemId)
    override fun sealedPut(mutationId: String, itemId: String, doc: ItemDoc, vaultId: String, baseItemRev: Long, isNew: Boolean) =
        engine.sealedPut(mutationId, itemId, doc, vaultId, baseItemRev, isNew)
    override suspend fun uploadEncryptedAttachment(attachmentId: String, itemId: String, vaultId: String, sealed: ByteArray): ItemResult<Unit> =
        engine.uploadEncryptedAttachment(attachmentId, itemId, vaultId, sealed)
    override suspend fun downloadAttachment(ref: AttachmentRef): ItemResult<ByteArray> = engine.downloadAttachment(ref)
    override suspend fun itemVersions(itemId: String, vaultId: String): ItemResult<List<DecryptedItemVersion>> = engine.itemVersions(itemId, vaultId)
    override fun versionDocForRestore(itemId: String, version: ItemDoc): ItemDoc = engine.versionDocForRestore(itemId, version)
    override suspend fun deletedItems(): ItemResult<List<DeletedItemView>> = engine.deletedItems()
    override suspend fun deletedItemDoc(row: DeletedItemView): ItemResult<ItemDoc?> = engine.deletedItemDoc(row.itemId, row.vaultId, row.deletedAt)
    override suspend fun restoreDeleted(itemId: String, vaultId: String, doc: ItemDoc): ItemResult<Unit> = engine.restoreDeleted(itemId, vaultId, doc)
    override suspend fun purgeDeleted(itemId: String, vaultId: String): ItemResult<Unit> = engine.purgeDeleted(itemId, vaultId)
    override fun recordTrashAction(done: TrashActionDone) = engine.recordTrashAction(done)
    override fun trashActionsDone(): List<TrashActionDone> = engine.trashActionsDone()
    override fun clearTrashActionsDone() = engine.clearTrashActionsDone()
    override fun markClosedForWriting(vaultId: String, reason: VaultClosedReason?) = engine.markClosedForWriting(vaultId, reason)
    override fun closedForWriting(vaultId: String): VaultClosedReason? = engine.closedForWriting(vaultId)
    override suspend fun deletedVaults(): ItemResult<List<DeletedVault>> = engine.deletedVaults()
    override fun planMove(itemId: String, targetVaultId: String, deleteSource: Boolean): ItemResult<MovePlan> = engine.planMove(itemId, targetVaultId, deleteSource)
    override suspend fun runMove(plan: MovePlan, onProgress: ((done: Int, total: Int) -> Unit)?, finalSync: Boolean): ItemResult<Unit> =
        engine.runMove(plan, onProgress, finalSync)
    override suspend fun rescueToPersonal(vaultId: String, onProgress: ((done: Int, total: Int) -> Unit)?): ItemResult<Int> = engine.rescueToPersonal(vaultId, onProgress)
    override suspend fun rescueHeldToPersonal(vaultId: String, onProgress: ((done: Int, total: Int) -> Unit)?): ItemResult<HeldRescue> =
        engine.rescueHeldToPersonal(vaultId, onProgress)
    override fun heldDocsToBring(fromVaultId: String, targetVaultId: String, picks: List<HeldPick>): List<ItemDoc> =
        engine.heldDocsToBring(fromVaultId, targetVaultId, picks)
    override suspend fun bringHeldInto(
        fromVaultId: String,
        targetVaultId: String,
        picks: List<HeldPick>,
        onMade: (HeldCopied) -> Unit,
        onProgress: ((done: Int, total: Int) -> Unit)?,
        onDeleted: (io.silencelen.andvari.core.client.items.HeldDeleted) -> Unit,
    ): ItemResult<List<HeldCopied>> = engine.bringHeldInto(fromVaultId, targetVaultId, picks, onMade, onProgress, onDeleted)
    override fun heldVaults(): List<HeldVaultView> = engine.heldVaults()
    override fun heldItems(vaultId: String): List<VaultItem> = engine.heldItems(vaultId)
    override fun vaultDeleted(vaultId: String): Boolean = engine.vaultDeleted(vaultId)
    override fun removeFromDevice(vaultId: String): ItemResult<Unit> = engine.removeFromDevice(vaultId)
    override suspend fun renameVault(vaultId: String, newName: String): ItemResult<Unit> = engine.renameVault(vaultId, newName)
    override fun envelopes(): List<SyncItem> = engine.envelopes()
    override suspend fun breachRange(prefix: String): ItemResult<String> = engine.breachRange(prefix)
    override fun importProjections(vaultId: String?): ItemResult<CsvImport.ImportProjections> = engine.importProjections(vaultId)
    override suspend fun importAll(
        items: List<CsvImport.PlannedItem>,
        onProgress: ((done: Int, total: Int) -> Unit)?,
        vaultId: String?,
        onStopped: (io.silencelen.andvari.core.client.items.ImportStopped) -> Unit,
    ): ItemResult<Unit> = engine.importAll(items, onProgress, vaultId, onStopped)
    override fun quota(): QuotaUse? = engine.quota()
    override suspend fun roomFor(size: CopySize): ItemResult<QuotaRoom> = engine.roomFor(size)
    override fun importSize(items: List<CsvImport.PlannedItem>): CopySize = engine.importSize(items)
    override fun copySize(docs: List<ItemDoc>, fileMaxBytes: Long, newVaultName: String?): CopySize = engine.copySize(docs, fileMaxBytes, newVaultName)
}
