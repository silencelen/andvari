package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.WireItem

/** A newly attached file awaiting upload: the doc's AttachmentRef + plaintext bytes. */
class PendingUpload(val ref: AttachmentRef, val data: ByteArray)

/**
 * Client sync engine (sibling of web/src/vault/store.ts). Pulls deltas since the
 * cursor, decrypts into the cache, materializes conflict copies client-side (the
 * server can't re-encrypt — spec 03 §5), and pushes mutations with stable ids. The
 * offline queue in [VaultCache] makes pushes crash-durable and retry-idempotent.
 */
class SyncEngine(
    private val api: AndvariApi,
    private val account: Account,
    private val cache: VaultCache,
) {
    fun items(): List<VaultItem> = cache.allItems().sortedBy { it.doc.name.lowercase() }
    fun item(itemId: String): VaultItem? = cache.getItem(itemId)

    /** Push any queued mutations first (crash recovery), then pull deltas. */
    suspend fun sync() {
        flushQueue()
        pull()
    }

    private suspend fun pull() {
        val resp = try {
            api.sync(cache.cursor())
        } catch (e: ApiException) {
            if (e.status == 410) {
                cache.clear()
                api.sync(0)
            } else throw e
        }

        for (grant in resp.grants) {
            if (grant.role.isNotEmpty() && !account.hasVault(grant.vaultId)) {
                runCatching { account.addPersonalGrant(grant) }
            }
        }
        for (vault in resp.vaults) {
            if (vault.type == "personal" && account.hasVault(vault.vaultId)) account.setPersonalVault(vault.vaultId)
        }

        val conflicts = mutableListOf<WireItem>()
        for (item in resp.items) {
            if (!account.hasVault(item.vaultId)) continue
            if (item.deleted) {
                cache.deleteItem(item.itemId)
                continue
            }
            runCatching {
                val doc = account.decryptItem(item)
                cache.upsertItem(VaultItem(item.itemId, item.vaultId, item.rev, item.updatedAt, doc))
                if (item.conflict) conflicts += item
            }
        }
        cache.setCursor(resp.rev)

        for (item in conflicts) materializeConflict(item)
    }

    private suspend fun materializeConflict(item: WireItem) {
        val winner = cache.getItem(item.itemId) ?: return
        val copyId = account.newItemId()
        val stamp = isoDate(item.updatedAt)
        val copyDoc = winner.doc.copy(name = "${winner.doc.name} (conflict $stamp)")
        push(
            listOf(
                putMutation(copyId, item.vaultId, copyDoc, 0),
                putMutation(item.itemId, item.vaultId, winner.doc, winner.rev), // clears the flag
            ),
        )
    }

    fun putMutation(itemId: String, vaultId: String, doc: ItemDoc, baseItemRev: Long): Mutation =
        Mutation(
            mutationId = account.newItemId(),
            op = "put",
            itemId = itemId,
            vaultId = vaultId,
            baseItemRev = baseItemRev,
            item = account.encryptItem(vaultId, itemId, doc),
        )

    fun deleteMutation(itemId: String, vaultId: String, baseItemRev: Long): Mutation =
        Mutation(account.newItemId(), "delete", itemId, vaultId, baseItemRev, null)

    /** Create or update an item, then reconcile. */
    suspend fun save(itemId: String?, doc: ItemDoc) = saveWithUploads(itemId, doc, emptyList())

    /**
     * Blob-first save (spec 02 §6): encrypt + upload every new attachment under the
     * (possibly fresh) itemId, THEN push the item that references them.
     */
    suspend fun saveWithUploads(itemId: String?, doc: ItemDoc, uploads: List<PendingUpload>) {
        val vaultId = account.personalVaultId
        val existing = itemId?.let { cache.getItem(it) }
        val id = itemId ?: account.newItemId()
        for (u in uploads) {
            val enc = Attachments.encrypt(account.cryptoProvider(), Bytes.fromB64(u.ref.fileKey), u.data)
            api.uploadAttachment(u.ref.id, id, vaultId, enc.header + enc.ciphertext)
        }
        push(listOf(putMutation(id, vaultId, doc, existing?.rev ?: 0)))
        pull()
    }

    /** Download + decrypt one attachment (hard failure on any corruption, spec 02 §6). */
    suspend fun downloadAttachment(ref: AttachmentRef): ByteArray {
        val bytes = api.downloadAttachment(ref.id)
        if (bytes.size <= Attachments.HEADER_BYTES) throw CryptoException("attachment response truncated")
        return Attachments.decrypt(
            account.cryptoProvider(),
            Bytes.fromB64(ref.fileKey),
            bytes.copyOfRange(0, Attachments.HEADER_BYTES),
            bytes.copyOfRange(Attachments.HEADER_BYTES, bytes.size),
        )
    }

    suspend fun remove(itemId: String) {
        val existing = cache.getItem(itemId) ?: return
        push(listOf(deleteMutation(itemId, existing.vaultId, existing.rev)))
        pull()
    }

    /** Enqueue durably, attempt to send; a failure leaves it queued for flushQueue(). */
    private suspend fun push(mutations: List<Mutation>) {
        mutations.forEach { cache.enqueue(it) }
        flushQueue()
    }

    private suspend fun flushQueue() {
        val pending = cache.pending()
        if (pending.isEmpty()) return
        val resp = api.push(PushRequest(pending))
        val byId = resp.results.associateBy { it.mutationId }
        for (m in pending) {
            val r = byId[m.mutationId] ?: continue
            // Any definitive server outcome removes it from the queue (idempotent replay
            // returns the original result, so a duplicate is also "done").
            if (r.status != "denied") cache.dequeue(m.mutationId)
        }
        val denied = resp.results.filter { it.status == "denied" }
        if (denied.isNotEmpty()) {
            denied.forEach { cache.dequeue(it.mutationId) } // drop un-retryable
            throw ApiException(403, "denied", "write denied for ${denied.size} mutation(s)")
        }
    }

    private fun isoDate(epochMillis: Long): String {
        val instant = kotlinx.datetime.Instant.fromEpochMilliseconds(epochMillis)
        return instant.toString().substring(0, 10)
    }
}
