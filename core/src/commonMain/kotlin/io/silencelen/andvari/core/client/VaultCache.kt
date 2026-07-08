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

/** Item history (feature): a decrypted archived version of an item. Plaintext lives only in memory. */
data class DecryptedItemVersion(
    val rev: Long,
    val archivedAt: Long,
    val doc: ItemDoc,
)

/**
 * One soft-hidden removed vault in the holding area (spec 03 §11 / design §6): the vault
 * row, the retained grant blob (normative — held ciphertext is dead bytes without it),
 * the ciphertext item snapshot, and the PARKED mutations replayed on restore/re-add (F21).
 * Ciphertext-only by construction (every field is server-visible wire material — the
 * decrypted name is NEVER stored here; it is re-derived via Account.peekVaultName), so the
 * durable SQLite impl may persist it without widening the spec 02 §8 at-rest surface.
 * [expungeAt]: purgeAt for verified deletes (the server erases then), else +30 days.
 */
@kotlinx.serialization.Serializable
data class HeldVaultRecord(
    val vault: WireVault,
    val grant: WireGrant?,
    val items: List<WireItem>,
    val reason: String, // removed | left | deleted | transferred
    val verified: Boolean,
    val purgeAt: Long?,
    val deleteId: String?,
    val parked: List<Mutation>,
    val expungeAt: Long,
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

    /**
     * Drop the in-memory decrypted working set WITHOUT touching the durable rows —
     * used to reconcile the live view back to disk after a rolled-back [atomically]
     * (the DB is consistent; the caller re-decrypts from [envelopes]).
     */
    fun evictDecrypted() {}

    fun close() {}

    /** Durable outbound queue — mutations survive restart until the server confirms. */
    fun enqueue(mutation: Mutation)

    /** Enqueue (FIFO) order, EXCLUDING staged-denied rows — flushQueue must never re-push
     *  a mutation the server already definitively denied. */
    fun pending(): List<Mutation>

    /** Remove a queue row (any state — pending or staged-denied). */
    fun dequeue(mutationId: String)

    /** Drop queued mutations targeting [vaultId], staged or not (revoked-membership purge,
     *  spec 03 §4 — the lifecycle path first folds them into HeldVaultRecord.parked). */
    fun dropPending(vaultId: String)

    /**
     * Durably mark a queue row as STAGED-DENIED (spec 03 §11 / F21): the server denied it,
     * so it must never be re-pushed as-is, but its fate — parked into the holding area
     * (vault went in-grace) vs. genuinely dropped (real permission denial) — is decided
     * only by a later fresh pull. The durable state closes the crash window between the
     * denial and that pull: process death must not destroy a parkable edit.
     */
    fun markStagedDenied(mutationId: String)

    /** All staged-denied rows (FIFO) — reloaded into the engine's staging map on hydrate. */
    fun stagedDenied(): List<Mutation>

    // ---- vault lifecycle (spec 03 §11): holding area + replay-protection state ----
    // Durable impls persist all of this (the holding area must survive a process restart
    // to keep its ≤7d/30d retention promise; the seq/deleteId sets are replay defenses
    // that lose their meaning if forgotten). None of it is wiped by [clear] — like the
    // queue, it is safety state that must survive a 410 resync.

    /** Insert or replace one held (soft-hidden) vault. */
    fun putHeld(held: HeldVaultRecord)
    fun getHeld(vaultId: String): HeldVaultRecord?
    fun heldVaults(): List<HeldVaultRecord>
    fun removeHeld(vaultId: String)

    /** deleteIds consumed by a verified restore — a later tombstone bearing one is stale. */
    fun addConsumedDeleteId(deleteId: String)
    fun isConsumedDeleteId(deleteId: String): Boolean

    /** Highest transfer seq VERIFIED for a vault (offer/accept replay floor, design §3). */
    fun lastVerifiedTransferSeq(vaultId: String): Long
    fun setLastVerifiedTransferSeq(vaultId: String, seq: Long)
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

    override fun evictDecrypted() { items.clear() } // envelopes (wire) retained for re-decrypt

    override fun enqueue(mutation: Mutation) {
        queue[mutation.mutationId] = mutation
        stagedIds.remove(mutation.mutationId) // re-enqueue returns a row to the pushable state
    }
    override fun pending(): List<Mutation> = queue.values.filter { it.mutationId !in stagedIds }
    override fun dequeue(mutationId: String) { queue.remove(mutationId); stagedIds.remove(mutationId) }
    override fun dropPending(vaultId: String) {
        queue.values.filter { it.vaultId == vaultId }.map { it.mutationId }.forEach { queue.remove(it); stagedIds.remove(it) }
    }
    override fun markStagedDenied(mutationId: String) { if (mutationId in queue) stagedIds.add(mutationId) }
    override fun stagedDenied(): List<Mutation> = queue.values.filter { it.mutationId in stagedIds }

    // ---- vault lifecycle (spec 03 §11) — session-scoped here (no persistence), which is
    // acceptable ONLY where this impl is used: tests, and the policy-forbids-durable-cache
    // mode where NOTHING may persist anyway (spec 02 §8). The SQLite impl is durable.
    private val held = LinkedHashMap<String, HeldVaultRecord>()
    private val consumedDeleteIds = HashSet<String>()
    private val transferSeq = HashMap<String, Long>()
    private val stagedIds = HashSet<String>()

    override fun putHeld(held: HeldVaultRecord) { this.held[held.vault.vaultId] = held }
    override fun getHeld(vaultId: String): HeldVaultRecord? = held[vaultId]
    override fun heldVaults(): List<HeldVaultRecord> = held.values.toList()
    override fun removeHeld(vaultId: String) { held.remove(vaultId) }
    override fun addConsumedDeleteId(deleteId: String) { consumedDeleteIds.add(deleteId) }
    override fun isConsumedDeleteId(deleteId: String): Boolean = deleteId in consumedDeleteIds
    override fun lastVerifiedTransferSeq(vaultId: String): Long = transferSeq[vaultId] ?: 0L
    override fun setLastVerifiedTransferSeq(vaultId: String, seq: Long) { transferSeq[vaultId] = seq }
}
