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

    /**
     * Rebuild the account + decrypted working set from the durable cache — called once
     * after Account.unlock, before the first sync(). Grants/vaults are pull DELTAS
     * (spec 03 §4): once the cursor moved past them they never re-send, so cold start
     * MUST reconstruct keys purely from persisted rows. Undecryptable envelopes are
     * retried here on every launch (e.g. after an upgrade or a later-opened grant).
     */
    fun hydrate() {
        for (g in cache.grants()) {
            runCatching { account.addGrant(g) } // role applies unconditionally; key opens if missing
        }
        for (v in cache.vaults()) {
            if (v.type == "personal" && account.hasVault(v.vaultId)) account.setPersonalVault(v.vaultId)
        }
        for (w in cache.envelopes()) {
            if (w.deleted || !account.hasVault(w.vaultId)) continue
            runCatching {
                cache.upsertItem(w, VaultItem(w.itemId, w.vaultId, w.rev, w.updatedAt, account.decryptItem(w)))
            }
        }
    }

    /** Close the underlying cache (must precede deleting its DB file — Windows file locks). */
    fun close() = cache.close()

    private suspend fun pull() {
        val since = cache.cursor()
        var resyncing = false
        val resp = try {
            api.sync(since)
        } catch (e: ApiException) {
            if (e.status == 410) {
                // Fetch the replacement snapshot FIRST; the durable cache is wiped only
                // once the full response is in hand (a failed fetch must not leave an
                // empty cache behind — that would regress offline durability).
                resyncing = true
                api.sync(0)
            } else throw e
        }

        // Rollback guards BEFORE anything is applied (spec 05 T1: warn, never delete or
        // overwrite local newer state; spec 03 §4). A non-full response below our cursor,
        // or an unsolicited full snapshot, is a server rollback / replay signal.
        if (!resp.full && resp.rev < since) {
            throw ApiException(409, "rev_regression", "server rev went backwards — possible rollback; local state kept")
        }
        if (resp.full && since > 0 && !resyncing) {
            throw ApiException(409, "rev_regression", "unsolicited full snapshot — possible rollback; local state kept")
        }

        try {
            applyPull(resp, resyncing)
        } catch (t: Throwable) {
            // The DB tx rolled back to a consistent state, but the in-memory working set +
            // Account key map were mutated eagerly. Rebuild them from the (rolled-back)
            // durable rows so the live session matches disk (data is intact; the next sync
            // re-applies the delta since the cursor also rolled back).
            runCatching { cache.evictDecrypted(); hydrate() }
            throw t
        }

        materializeOutstandingConflicts()
    }

    private fun applyPull(resp: io.silencelen.andvari.core.model.SyncResponse, resyncing: Boolean) {
        cache.atomically {
            if (resyncing) cache.clear() // resets cursor + rows; PRESERVES the queue (spec 03 §4)
            for (grant in resp.grants) {
                // Persist UNCONDITIONALLY (ciphertext rows; deltas never re-send) — the
                // in-memory key-open below may fail/skip, hydrate() retries from disk.
                cache.upsertGrant(grant)
                // addGrant applies role changes even when the VK is already held (a role
                // change re-delivers the grant precisely for this).
                runCatching { account.addGrant(grant) }
            }
            for (vault in resp.vaults) {
                cache.upsertVault(vault)
                if (vault.type == "personal" && account.hasVault(vault.vaultId)) account.setPersonalVault(vault.vaultId)
            }
            for (vaultId in resp.removedGrants) {
                cache.dropVault(vaultId)
                cache.dropPending(vaultId) // a revoked member's unsynced edits are discarded (spec 03 §4)
                account.removeVault(vaultId)
            }
            for (item in resp.items) {
                if (item.deleted) {
                    cache.deleteItem(item.itemId)
                    continue
                }
                // Envelope persists even when the VK is missing or decrypt fails — the
                // rev has passed the cursor and will never re-send; hydrate() retries.
                val decrypted = if (account.hasVault(item.vaultId)) {
                    runCatching {
                        VaultItem(item.itemId, item.vaultId, item.rev, item.updatedAt, account.decryptItem(item))
                    }.getOrNull()
                } else null
                cache.upsertItem(item, decrypted)
            }
            cache.setCursor(resp.rev)
        }
    }

    /**
     * Conflict copies derive from PERSISTED state, not a transient in-loop list: a crash
     * between cursor-advance and materialization must not bury a displaced version
     * forever (spec 03 §5). The copy's itemId is deterministic over (itemId, rev) so
     * concurrent/restarted materializers converge on one copy; an already-present copy
     * means someone (possibly us, pre-crash) materialized — skip, the flag-clear is
     * theirs to land.
     */
    private suspend fun materializeOutstandingConflicts() {
        val envelopes = cache.envelopes()
        val known = envelopes.mapTo(HashSet()) { it.itemId }
        for (item in envelopes) {
            if (!item.conflict || item.deleted) continue
            // A reader must not materialize (its push would be denied, spec 03 §5) — the
            // flag waits for a writer/owner on some other device.
            if (account.roleFor(item.vaultId) == "reader") continue
            val winner = cache.getItem(item.itemId) ?: continue // undecryptable → wait
            val copyId = deterministicCopyId(item.itemId, item.rev)
            if (copyId in known || cache.getItem(copyId) != null) continue
            val copyDoc = winner.doc.copy(name = "${winner.doc.name} (conflict ${isoDate(item.updatedAt)})")
            push(
                listOf(
                    putMutation(copyId, item.vaultId, copyDoc, 0),
                    putMutation(item.itemId, item.vaultId, winner.doc, winner.rev), // clears the flag
                ),
            )
        }
    }

    /** UUIDv4-shaped id derived from sha256("conflict|itemId|rev") — stable across retries. */
    private fun deterministicCopyId(itemId: String, rev: Long): String {
        val h = account.cryptoProvider().sha256("conflict|$itemId|$rev".encodeToByteArray()).copyOf(16)
        h[6] = ((h[6].toInt() and 0x0F) or 0x40).toByte()
        h[8] = ((h[8].toInt() and 0x3F) or 0x80).toByte()
        val hex = Bytes.toHexLower(h)
        return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}"
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

    /** Create or update an item, then reconcile. New items go to [vaultId] (default personal). */
    suspend fun save(itemId: String?, doc: ItemDoc, vaultId: String? = null) = saveWithUploads(itemId, doc, emptyList(), vaultId)

    /**
     * Blob-first save (spec 02 §6): encrypt + upload every new attachment under the
     * (possibly fresh) itemId, THEN push the item that references them. An EXISTING item
     * never changes vaults (its blob AD binds to the vault; the server enforces
     * vault_mismatch) — edits always target the item's own vault, wherever it lives.
     */
    suspend fun saveWithUploads(itemId: String?, doc: ItemDoc, uploads: List<PendingUpload>, vaultId: String? = null) {
        val existing = itemId?.let { cache.getItem(it) }
        val effectiveVault = existing?.vaultId ?: vaultId ?: account.personalVaultId
        val id = itemId ?: account.newItemId()
        for (u in uploads) {
            val enc = Attachments.encrypt(account.cryptoProvider(), Bytes.fromB64(u.ref.fileKey), u.data)
            api.uploadAttachment(u.ref.id, id, effectiveVault, enc.header + enc.ciphertext)
        }
        push(listOf(putMutation(id, effectiveVault, doc, existing?.rev ?: 0)))
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
