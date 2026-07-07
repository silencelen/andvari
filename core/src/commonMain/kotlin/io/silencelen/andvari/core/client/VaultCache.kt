package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault

/** A decrypted item held in the client (plaintext lives only in memory). */
data class VaultItem(
    val itemId: String,
    val vaultId: String,
    val rev: Long,
    val updatedAt: Long,
    val doc: ItemDoc,
)

/**
 * Offline persistence port for the client (spec 02 §8). The durable impl is
 * [SqliteVaultCache] (jvmShared, both native targets): it stores item envelopes,
 * grant/vault rows, the sync cursor, and the outbound queue — all ciphertext or
 * server-visible metadata (⊆ the spec 02 §5 table); the decrypted working set stays
 * in memory in every impl. [InMemoryVaultCache] remains for tests and web parity.
 *
 * Grants/vaults/items are pull DELTAS over one global rev (spec 03 §4): a client
 * that persists its cursor MUST persist them too, or discard the cursor.
 */
interface VaultCache {
    fun cursor(): Long
    fun setCursor(rev: Long)

    /**
     * [wire] = the server envelope persisted at rest; [item] = the decrypted in-memory
     * view (null when decryption failed or the vault key is unavailable — the envelope
     * is still persisted and retried on the next hydrate, e.g. after an app upgrade or
     * a later-opened shared grant).
     */
    fun upsertItem(wire: WireItem, item: VaultItem?)
    fun deleteItem(itemId: String)
    fun allItems(): List<VaultItem>
    fun getItem(itemId: String): VaultItem?

    /** All persisted ciphertext envelopes — cold-start rehydration input. */
    fun envelopes(): List<WireItem>

    fun upsertGrant(grant: WireGrant)
    fun grants(): List<WireGrant>
    fun upsertVault(vault: WireVault)
    fun vaults(): List<WireVault>

    /** removedGrants (spec 03 §4): purge the grant, the vault row, and all its items. */
    fun dropVault(vaultId: String)

    /**
     * Wipes items/envelopes/grants/vaults and resets the cursor to 0. PRESERVES the
     * queue (spec 03 §4: the offline queue survives a 410 resync and replays on top).
     */
    fun clear()

    /** Runs [block] atomically where the impl can (single SQLite tx); default = plain call. */
    fun atomically(block: () -> Unit) = block()

    fun close() {}

    /** Durable outbound queue — mutations survive restart until the server confirms. */
    fun enqueue(mutation: Mutation)

    /** Enqueue (FIFO) order — conflict-copy pairs rely on it. */
    fun pending(): List<Mutation>
    fun dequeue(mutationId: String)

    /** Drop queued mutations targeting [vaultId] (revoked-membership purge, spec 03 §4). */
    fun dropPending(vaultId: String)
}

/** In-memory cache — no persistence across process death. */
class InMemoryVaultCache : VaultCache {
    private var cursor = 0L
    private val items = LinkedHashMap<String, VaultItem>()
    private val wire = LinkedHashMap<String, WireItem>()
    private val grantRows = LinkedHashMap<String, WireGrant>()
    private val vaultRows = LinkedHashMap<String, WireVault>()
    private val queue = LinkedHashMap<String, Mutation>()

    override fun cursor(): Long = cursor
    override fun setCursor(rev: Long) { cursor = rev }

    override fun upsertItem(wire: WireItem, item: VaultItem?) {
        this.wire[wire.itemId] = wire
        if (item != null) items[wire.itemId] = item else items.remove(wire.itemId)
    }

    override fun deleteItem(itemId: String) { items.remove(itemId); wire.remove(itemId) }
    override fun allItems(): List<VaultItem> = items.values.toList()
    override fun getItem(itemId: String): VaultItem? = items[itemId]
    override fun envelopes(): List<WireItem> = wire.values.toList()

    override fun upsertGrant(grant: WireGrant) { grantRows[grant.vaultId] = grant }
    override fun grants(): List<WireGrant> = grantRows.values.toList()
    override fun upsertVault(vault: WireVault) { vaultRows[vault.vaultId] = vault }
    override fun vaults(): List<WireVault> = vaultRows.values.toList()

    override fun dropVault(vaultId: String) {
        grantRows.remove(vaultId)
        vaultRows.remove(vaultId)
        items.values.filter { it.vaultId == vaultId }.map { it.itemId }.forEach { items.remove(it) }
        wire.values.filter { it.vaultId == vaultId }.map { it.itemId }.forEach { wire.remove(it) }
    }

    override fun clear() {
        items.clear(); wire.clear(); grantRows.clear(); vaultRows.clear(); cursor = 0
    }

    override fun enqueue(mutation: Mutation) { queue[mutation.mutationId] = mutation }
    override fun pending(): List<Mutation> = queue.values.toList()
    override fun dequeue(mutationId: String) { queue.remove(mutationId) }
    override fun dropPending(vaultId: String) {
        queue.values.filter { it.vaultId == vaultId }.map { it.mutationId }.forEach { queue.remove(it) }
    }
}
