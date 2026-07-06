package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.model.Mutation

/** A decrypted item held in the client (plaintext lives only in memory). */
data class VaultItem(
    val itemId: String,
    val vaultId: String,
    val rev: Long,
    val updatedAt: Long,
    val doc: ItemDoc,
)

/**
 * Offline persistence port for the client. The in-memory impl is used for tests and
 * the web-parity path; Android/desktop provide a SQLDelight-backed impl that stores
 * item CIPHERTEXT at rest (decrypting into VaultItem only in memory on load).
 * v1 keeps the decrypted working set in memory regardless; this interface exists so
 * the sync cursor + pending-mutation queue survive process death on native clients.
 */
interface VaultCache {
    fun cursor(): Long
    fun setCursor(rev: Long)

    fun upsertItem(item: VaultItem)
    fun deleteItem(itemId: String)
    fun allItems(): List<VaultItem>
    fun getItem(itemId: String): VaultItem?
    fun clear()

    /** Durable outbound queue — mutations survive restart until the server confirms. */
    fun enqueue(mutation: Mutation)
    fun pending(): List<Mutation>
    fun dequeue(mutationId: String)
}

/** In-memory cache — no persistence across process death. */
class InMemoryVaultCache : VaultCache {
    private var cursor = 0L
    private val items = LinkedHashMap<String, VaultItem>()
    private val queue = LinkedHashMap<String, Mutation>()

    override fun cursor(): Long = cursor
    override fun setCursor(rev: Long) { cursor = rev }
    override fun upsertItem(item: VaultItem) { items[item.itemId] = item }
    override fun deleteItem(itemId: String) { items.remove(itemId) }
    override fun allItems(): List<VaultItem> = items.values.toList()
    override fun getItem(itemId: String): VaultItem? = items[itemId]
    override fun clear() { items.clear(); cursor = 0 }
    override fun enqueue(mutation: Mutation) { queue[mutation.mutationId] = mutation }
    override fun pending(): List<Mutation> = queue.values.toList()
    override fun dequeue(mutationId: String) { queue.remove(mutationId) }
}
