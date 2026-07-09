package io.silencelen.andvari.server

/**
 * Vault-lifecycle janitor (spec 02 §7 / spec 03 §11; design 2026-07-07 skipti §4 step 6).
 * v1 scope is deliberately narrow: (a) purge vaults past their grace window, (b) expire
 * transfer offers past expiresAt. NO item-tombstone GC, no `changes` pruning, no
 * mutation-dedup trim, no oldestRetainedRev advancement — the general retention machinery
 * stays dormant (its activation preconditions are normative in spec 02 §7).
 *
 * Purge is andvari's first data-destruction code (design §14.1), so every destructive
 * statement re-checks `deletedAt/purgeAt/purgedAt` INSIDE the per-vault tx (closes the
 * purge-vs-restore race even if the single-connection lock is ever relaxed), blob files
 * are unlinked only POST-commit outside the DB lock in small batches (the hourly orphan
 * sweep is the crash backstop), and ANDVARI_JANITOR_DRYRUN turns the whole sweep into
 * log-only for the first armed week.
 *
 * Retained forever: the vault tombstone row (metaBlob blanked), ALL grant rows (key
 * material blanked: wrappedVk='' — the NOT NULL sentinel — and sealedVk=NULL, active and
 * previously-revoked alike), and item rows as ciphertext-free skeletal tombstones
 * (deleted=1, blob=NULL, NO rev bump — revoked members receive nothing; the rows keep the
 * vault_mismatch / edit-over-tombstone fences alive for every stale client forever).
 */
class Janitor(
    private val repo: Repo,
    private val attachments: AttachmentStore,
    private val config: Config,
    private val onChange: suspend (userIds: Collection<String>, rev: Long) -> Unit = { _, _ -> },
) {
    class SweepResult(
        val purgedVaults: List<String>,
        val expiredOffers: List<String>,
        val purgedItemTombstones: List<String>,
        val dryRun: Boolean,
    )

    suspend fun sweep(nowMs: Long = now()): SweepResult =
        SweepResult(purgeDueVaults(nowMs), expireTransferOffers(nowMs), purgeOldItemTombstones(nowMs), config.janitorDryRun)

    // ---- (c) F49: item-tombstone retention (30 days) ----

    /** Hard-delete item tombstones deleted more than 30 days ago (+ their archived versions), so
     *  Trash is bounded. Dry-run aware; failures are logged, never thrown. Returns the purged ids. */
    fun purgeOldItemTombstones(nowMs: Long): List<String> {
        val cutoff = nowMs - 30L * 24 * 3600 * 1000 // 30 days
        val due = repo.db.read { c ->
            c.queryAll("SELECT itemId FROM items WHERE deleted=1 AND updatedAt<?", cutoff) { it.getString(1) }
        }
        if (due.isEmpty()) return emptyList()
        if (config.janitorDryRun) {
            System.err.println("[andvari] janitor DRY-RUN: would purge ${due.size} item tombstone(s) past 30d")
            return emptyList()
        }
        return runCatching { repo.db.tx { c -> repo.purgeOldTombstones(c, cutoff) } }
            .onFailure { System.err.println("[andvari] janitor: item-tombstone purge failed: $it") }
            .getOrDefault(emptyList())
    }

    // ---- (a) vault purge ----

    fun purgeDueVaults(nowMs: Long): List<String> {
        val due = repo.db.read { c ->
            c.queryAll(
                "SELECT vaultId FROM vaults WHERE deletedAt IS NOT NULL AND purgeAt IS NOT NULL AND purgeAt<=? AND purgedAt IS NULL",
                nowMs,
            ) { it.getString(1) }
        }
        val purged = mutableListOf<String>()
        for (vaultId in due) {
            if (config.janitorDryRun) {
                System.err.println("[andvari] janitor DRY-RUN: would purge vault $vaultId")
                continue
            }
            runCatching { if (purgeVault(vaultId, nowMs)) purged.add(vaultId) }
                .onFailure { System.err.println("[andvari] janitor: purge of $vaultId failed: $it") }
        }
        return purged
    }

    /**
     * Purge ONE vault in one tx. Returns false (untouched) when the in-tx re-check finds
     * the vault no longer due — restored, already purged, or not deleted (the fence).
     * Internal so the restore-vs-purge fence is directly testable.
     */
    internal fun purgeVault(vaultId: String, nowMs: Long): Boolean {
        // Every destructive statement carries this guard as an EXISTS clause; the final
        // purgedAt stamp uses it as its own WHERE and must hit exactly one row or the
        // whole tx rolls back.
        val guard = "SELECT 1 FROM vaults WHERE vaultId=? AND deletedAt IS NOT NULL AND purgeAt<=? AND purgedAt IS NULL"
        val files = mutableListOf<String>()
        val purged = repo.db.tx { c ->
            if (c.queryOne(guard, vaultId, nowMs) { 1 } == null) return@tx false
            // Collect blob paths BEFORE deleting the rows; unlink happens post-commit.
            files += c.queryAll("SELECT attachmentId FROM attachments WHERE vaultId=?", vaultId) { it.getString(1) }
            c.exec(
                "DELETE FROM item_versions WHERE itemId IN (SELECT itemId FROM items WHERE vaultId=?) AND EXISTS($guard)",
                vaultId, vaultId, nowMs,
            )
            c.exec("DELETE FROM attachments WHERE vaultId=? AND EXISTS($guard)", vaultId, vaultId, nowMs)
            // Skeletal tombstones: ciphertext gone, rows retained forever, NO rev bump.
            c.exec(
                "UPDATE items SET deleted=1, conflict=0, blob=NULL, blobSize=0, attachmentIds='[]' WHERE vaultId=? AND EXISTS($guard)",
                vaultId, vaultId, nowMs,
            )
            // Blanket wipe of ALL grants' key material — active AND previously-revoked
            // (a removed member's sealedVk must not survive the purge).
            c.exec("UPDATE grants SET wrappedVk='', sealedVk=NULL WHERE vaultId=? AND EXISTS($guard)", vaultId, vaultId, nowMs)
            val stamped = c.exec(
                "UPDATE vaults SET metaBlob='', purgedAt=? WHERE vaultId=? AND deletedAt IS NOT NULL AND purgeAt<=? AND purgedAt IS NULL",
                nowMs, vaultId, nowMs,
            )
            check(stamped == 1) { "vault purge fence failed for $vaultId" } // rolls the tx back
            repo.auditOn(c, "vault_purge", null, null, null, vaultId)
            true
        }
        if (purged) {
            // Post-commit, outside the DB lock, in small batches. Failures are left to the
            // hourly attachment orphan sweep (rows are gone, so the files are orphans).
            files.chunked(UNLINK_BATCH).forEach { batch -> batch.forEach { runCatching { attachments.file(it).delete() } } }
        }
        return purged
    }

    // ---- (b) transfer-offer expiry ----

    suspend fun expireTransferOffers(nowMs: Long): List<String> {
        val due = repo.db.read { c ->
            c.queryAll(
                "SELECT vaultId FROM vaults WHERE pendingOfferId IS NOT NULL AND pendingOfferExpiresAt IS NOT NULL AND pendingOfferExpiresAt<=?",
                nowMs,
            ) { it.getString(1) }
        }
        val expired = mutableListOf<String>()
        for (vaultId in due) {
            if (config.janitorDryRun) {
                System.err.println("[andvari] janitor DRY-RUN: would expire transfer offer on vault $vaultId")
                continue
            }
            val (rev, notify, didExpire) = repo.db.tx { c ->
                // In-tx re-check: an accept/cancel may have raced the due-list read.
                val pending = c.queryOne(
                    "SELECT pendingOwnerId, pendingOfferExpiresAt FROM vaults WHERE vaultId=? AND pendingOfferId IS NOT NULL",
                    vaultId,
                ) { rs -> rs.getString(1) to rs.getLong(2) } ?: return@tx Triple(0L, emptySet<String>(), false)
                if (pending.second > nowMs) return@tx Triple(0L, emptySet<String>(), false)
                val members = c.queryAll(
                    "SELECT userId FROM grants WHERE vaultId=? AND revokedAt IS NULL", vaultId,
                ) { it.getString(1) }.toSet()
                // Shared clear helper (#9): same pending-clear + rev bump (banner re-delivery)
                // as Service's cancel path; the janitor writes its own vault_transfer_expire audit.
                repo.clearPendingOffer(c, vaultId, bumpVaultRev = true)
                repo.auditOn(c, "vault_transfer_expire", null, null, null, "$vaultId:${pending.first}")
                Triple(repo.currentRev(c), members, true)
            }
            if (didExpire) {
                expired.add(vaultId)
                if (notify.isNotEmpty()) onChange(notify, rev)
            }
        }
        return expired
    }

    companion object {
        private const val UNLINK_BATCH = 50
    }
}
