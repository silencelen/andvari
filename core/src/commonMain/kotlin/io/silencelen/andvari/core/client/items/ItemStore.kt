package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.HeldVaultRecord
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import io.silencelen.andvari.core.model.wire.ItemUpload
import io.silencelen.andvari.core.model.wire.Mutation
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncLogHead
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.trust.TrustGrammar

/** One vault in the holding area (spec 02 §10.6): ciphertext rows and the writes parked with them, never a name or a key. */
class HeldVault(
    val vault: SyncVault,
    val grant: SyncGrant?,
    val items: List<SyncItem>,
    /** A [VaultDeparture.code]. */
    val reason: String,
    val parked: List<Mutation>,
    val expungeAt: Long,
)

/**
 * [ItemEngine]'s view of the offline cache (spec 02 §8) in the `core/model/wire` row types. [VaultCache] and its
 * SQLite implementation are reused as they are; they are still typed over the pre-overhaul `core/model/Wire.kt` rows,
 * whose item, grant and mutation shapes are field-for-field the new ones, so this class is the one place the two meet.
 * When `Wire.kt` goes, [VaultCache] takes the new row types and this adapter becomes a pass-through.
 *
 * The one thing the old vault row cannot carry is the served log head: it is kept beside the row in the cache's
 * client state (`vault.loghead.<vaultId>`), which shares the pull's transaction.
 */
internal class ItemStore(private val cache: VaultCache) {
    val durable: Boolean get() = cache.durable

    fun cursor(): Long = cache.cursor()
    fun setCursor(rev: Long) = cache.setCursor(rev)

    fun upsertItem(row: SyncItem, item: VaultItem?) = cache.upsertItem(row.cached(), item)
    fun deleteItem(itemId: String) = cache.deleteItem(itemId)
    fun allItems(): List<VaultItem> = cache.allItems()
    fun getItem(itemId: String): VaultItem? = cache.getItem(itemId)
    fun envelopes(): List<SyncItem> = cache.envelopes().map { it.wire() }

    fun upsertGrant(grant: SyncGrant) = cache.upsertGrant(grant.cached())
    fun grants(): List<SyncGrant> = cache.grants().map { it.wire() }

    fun upsertVault(vault: SyncVault) {
        cache.upsertVault(WireVault(vault.vaultId, vault.type, vault.rev, vault.metaBlob, vault.createdAt))
        cache.setClientState(LOG_HEAD_PREFIX + vault.vaultId, vault.logHead?.let { "${it.seq}:${it.hash}" })
    }

    fun vaults(): List<SyncVault> = cache.vaults().map { it.wire(servedHead(it.vaultId)) }
    fun vault(vaultId: String): SyncVault? = cache.vaults().firstOrNull { it.vaultId == vaultId }?.let { it.wire(servedHead(vaultId)) }

    private fun servedHead(vaultId: String): SyncLogHead? = cache.clientState(LOG_HEAD_PREFIX + vaultId)?.let { text ->
        val seq = text.substringBefore(':').toLongOrNull() ?: return@let null
        SyncLogHead(seq, text.substringAfter(':'))
    }

    /** Drop a vault's rows from the live view: its grant, its vault row and its items, and the trash's kept envelopes. */
    fun dropVault(vaultId: String) {
        cache.dropVault(vaultId)
        cache.setClientState(LOG_HEAD_PREFIX + vaultId, null)
        forgetTrashedIn(vaultId)
    }

    // ---- the trash's kept envelopes ----
    // When a tombstone is applied, the last envelope this device held of the item (ciphertext, as the cache held it) is
    // kept in the client state, so the trash's row opens from it with no call. They share the pull's transaction, survive
    // a restart and a resync's [clear], and go with the cache when the account leaves the device. At most
    // [TRASH_KEEP_MAX], the oldest kept dropped first; pruned against every whole read of the trash.

    /** Keep [rows] (live envelopes being tombstoned) for the trash; a newer one of the same item replaces the older. */
    fun keepTrashed(rows: List<SyncItem>) {
        val keep = rows.filter { !it.deleted && it.blob != null }
        if (keep.isEmpty()) return
        val newIds = keep.mapTo(LinkedHashSet()) { it.itemId }
        val ids = trashedIds().filterNot { it in newIds } + newIds
        val over = ids.size - TRASH_KEEP_MAX
        if (over > 0) for (id in ids.take(over)) cache.setClientState(TRASH_PREFIX + id, null)
        for (row in keep) cache.setClientState(TRASH_PREFIX + row.itemId, trashJson.encodeToString(WireItem.serializer(), row.cached()))
        setTrashedIds(if (over > 0) ids.drop(over) else ids)
    }

    /** The envelope kept of [itemId] when it was tombstoned here; null when none (never held, dropped, or unreadable). */
    fun trashed(itemId: String): SyncItem? = cache.clientState(TRASH_PREFIX + itemId)?.let {
        runCatching { trashJson.decodeFromString(WireItem.serializer(), it) }.getOrNull()?.wire()
    }

    /** The items whose envelope is kept, oldest kept first. */
    fun trashedIds(): List<String> = cache.clientState(TRASH_INDEX)?.split(',')?.filter { it.isNotEmpty() }.orEmpty()

    /** Remove the kept envelopes of [itemIds]. */
    fun forgetTrashed(itemIds: Collection<String>) {
        if (itemIds.isEmpty()) return
        val gone = itemIds.toHashSet()
        val ids = trashedIds()
        if (ids.none { it in gone }) return
        for (id in ids) if (id in gone) cache.setClientState(TRASH_PREFIX + id, null)
        setTrashedIds(ids.filterNot { it in gone })
    }

    /** Remove every kept envelope of [vaultId] (and any that no longer reads as an envelope). */
    fun forgetTrashedIn(vaultId: String) {
        forgetTrashed(trashedIds().filter { id -> trashed(id)?.vaultId.let { it == null || it == vaultId } })
    }

    private fun setTrashedIds(ids: List<String>) = cache.setClientState(TRASH_INDEX, ids.joinToString(",").ifEmpty { null })

    // ---- trash actions the server answered as done, kept until the next whole read of the trash checks them ----
    // Ids, a flag, the server's deletion time and whether the device saw the item live: no name, nothing secret.

    /** Add [done], replacing an earlier record of the same item; at most [TRASH_DONE_MAX], the oldest dropped first. */
    fun recordTrashDone(done: TrashActionDone) {
        val all = trashDone().filterNot { it.itemId == done.itemId } + done
        setTrashDone(all.takeLast(TRASH_DONE_MAX))
    }

    /** What [recordTrashDone] kept, oldest first; a line that does not read is dropped. */
    fun trashDone(): List<TrashActionDone> = cache.clientState(TRASH_DONE)?.split(',')?.mapNotNull { line ->
        val p = line.split(';')
        val deletedAt = p.getOrNull(2)?.toLongOrNull()
        if (p.size != 4 || !TrustGrammar.isUuid(p[0]) || deletedAt == null) null
        else TrashActionDone(p[0], restored = p[1] == "r", deletedAt = deletedAt, seenLive = p[3] == "1")
    }.orEmpty()

    fun clearTrashDone() = cache.setClientState(TRASH_DONE, null)

    // ---- vaults the app interface closed for writing: vault id and reason, nothing secret ----

    /** Every vault closed for writing here, with its reason; an entry that does not read is dropped. */
    fun writeClosed(): Map<String, VaultClosedReason> = cache.clientState(WRITE_CLOSED)?.split(',')?.mapNotNull { e ->
        val id = e.substringBefore(':')
        val reason = VaultClosedReason.entries.firstOrNull { it.name == e.substringAfter(':', "") }
        if (TrustGrammar.isUuid(id) && reason != null) id to reason else null
    }?.toMap().orEmpty()

    fun setWriteClosed(marks: Map<String, VaultClosedReason>) =
        cache.setClientState(WRITE_CLOSED, marks.entries.joinToString(",") { "${it.key}:${it.value.name}" }.ifEmpty { null })

    private fun setTrashDone(all: List<TrashActionDone>) = cache.setClientState(
        TRASH_DONE,
        all.joinToString(",") { "${it.itemId};${if (it.restored) "r" else "p"};${it.deletedAt};${if (it.seenLive) "1" else "0"}" }.ifEmpty { null },
    )

    /** Wipe rows and cursor for a resync; the queue, the holding area, the item homes and the client state stay. */
    fun clear() = cache.clear()
    fun atomically(block: () -> Unit) = cache.atomically(block)
    fun evictDecrypted() = cache.evictDecrypted()
    fun close() = cache.close()

    fun enqueue(m: Mutation) = cache.enqueue(m.cached())
    fun pending(): List<Mutation> = cache.pending().map { it.wire() }
    fun dequeue(mutationId: String) = cache.dequeue(mutationId)
    fun dropPending(vaultId: String) = cache.dropPending(vaultId)
    fun markStagedDenied(mutationId: String) = cache.markStagedDenied(mutationId)
    fun stagedDenied(): List<Mutation> = cache.stagedDenied().map { it.wire() }

    fun putHeld(h: HeldVault) = cache.putHeld(
        HeldVaultRecord(
            vault = WireVault(h.vault.vaultId, h.vault.type, h.vault.rev, h.vault.metaBlob, h.vault.createdAt), grant = h.grant?.cached(),
            items = h.items.map { it.cached() }, reason = h.reason, verified = true, purgeAt = null, deleteId = null,
            parked = h.parked.map { it.cached() }, expungeAt = h.expungeAt,
        ),
    )

    fun getHeld(vaultId: String): HeldVault? = cache.getHeld(vaultId)?.wire()
    fun heldVaults(): List<HeldVault> = cache.heldVaults().map { it.wire() }

    /** Remove [vaultId]'s held copy, and with it its record of served deletions ([heldDeleted]). */
    fun removeHeld(vaultId: String) {
        cache.removeHeld(vaultId)
        setHeldDeleted(vaultId, emptyList())
    }

    // ---- the deletions served for a held copy's items (spec 02 §10.6) ----
    // The ids of items of [vaultId]'s held copy whose deletion a pull served while the copy was held, each taken out again
    // when a live row of the item is served. Ids only, nothing secret. In the client state, so they share the pull's
    // transaction and survive a restart and a resync's [clear]; they go with the copy ([removeHeld]). The copy itself
    // keeps every item; only putting the vault back leaves these out.

    /** The recorded ids; an entry that is no id is dropped. */
    fun heldDeleted(vaultId: String): Set<String> =
        cache.clientState(HELD_DELETED_PREFIX + vaultId)?.split(',')?.filterTo(LinkedHashSet()) { TrustGrammar.isUuid(it) }.orEmpty()

    fun setHeldDeleted(vaultId: String, itemIds: Collection<String>) =
        cache.setClientState(HELD_DELETED_PREFIX + vaultId, itemIds.joinToString(",").ifEmpty { null })

    fun itemHome(itemId: String): String? = cache.itemHome(itemId)
    fun setItemHome(itemId: String, vaultId: String) = cache.setItemHome(itemId, vaultId)
    fun quarantined(): List<SyncItem> = cache.quarantined().map { it.wire() }
    fun quarantine(row: SyncItem) = cache.quarantine(row.cached())

    private fun HeldVaultRecord.wire() = HeldVault(vault.wire(null), grant?.wire(), items.map { it.wire() }, reason, parked.map { it.wire() }, expungeAt)

    private fun SyncItem.cached() = WireItem(itemId, vaultId, rev, createdAt, updatedAt, deleted, conflict, formatVersion, attachmentIds, blob)
    private fun WireItem.wire() = SyncItem(itemId, vaultId, rev, createdAt, updatedAt, deleted, conflict, formatVersion, attachmentIds, blob)
    private fun SyncGrant.cached() = WireGrant(vaultId, userId, role, wrappedVk, rev, null, signedGrant)
    private fun WireGrant.wire() = SyncGrant(vaultId, userId, role, wrappedVk, rev, signedGrant)
    private fun WireVault.wire(head: SyncLogHead?) = SyncVault(vaultId, type, rev, metaBlob, createdAt, head)
    private fun Mutation.cached() = io.silencelen.andvari.core.model.Mutation(
        mutationId, op, itemId, vaultId, baseItemRev, item?.let { io.silencelen.andvari.core.model.ItemUpload(it.formatVersion, it.attachmentIds, it.blob) },
    )
    private fun io.silencelen.andvari.core.model.Mutation.wire() =
        Mutation(mutationId, op, itemId, vaultId, baseItemRev, item?.let { ItemUpload(it.formatVersion, it.attachmentIds, it.blob) })

    /**
     * The server took [vaultId] away with no verified reason (spec 03 §4): a denial staged meanwhile is replayed when
     * the vault comes back, never judged final. Client state, so it survives a restart with the staged rows.
     */
    fun setTakenAway(vaultId: String, on: Boolean) = cache.setClientState(TAKEN_AWAY_PREFIX + vaultId, if (on) "1" else null)
    fun takenAway(vaultId: String): Boolean = cache.clientState(TAKEN_AWAY_PREFIX + vaultId) == "1"

    internal companion object {
        const val LOG_HEAD_PREFIX = "vault.loghead."
        const val TAKEN_AWAY_PREFIX = "vault.takenaway."
        const val TRASH_PREFIX = "trash.kept."
        const val TRASH_INDEX = "trash.kept"
        const val TRASH_DONE = "trash.done"
        const val WRITE_CLOSED = "vault.writeclosed"
        const val HELD_DELETED_PREFIX = "held.deleted."

        /** The most trash actions kept for their check. */
        const val TRASH_DONE_MAX = 200

        /** The most envelopes kept for the trash; the oldest kept goes first beyond it. */
        const val TRASH_KEEP_MAX = 500
        private val trashJson = kotlinx.serialization.json.Json { ignoreUnknownKeys = true; encodeDefaults = true }
    }
}
