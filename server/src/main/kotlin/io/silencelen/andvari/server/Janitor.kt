package io.silencelen.andvari.server

/**
 * Vault-lifecycle + retention janitor (spec 02 §7 / spec 03 §11; designs 2026-07-07
 * skipti §4 step 6 and 2026-07-10 n2 §5). The sweep set: (a) purge vaults past their
 * grace window, (b) expire transfer offers past expiresAt, (c) purge item tombstones
 * past [ITEM_TOMBSTONE_RETENTION_MS], (d) prune `changes` below the fence AND advance
 * `oldestRetainedRev` in the same tx — floored at MAX(rev) so `currentRev` never
 * regresses (spec 02 §7 invariants (a)+(b)), (e)–(i) prune dead sessions
 * ([SESSION_RETENTION_MS]), the mutation-dedup journal ([MUTATION_RETENTION_MS]),
 * audit rows ([AUDIT_RETENTION_MS]), dead invites ([INVITE_RETENTION_MS]), and stale
 * hibp_cache rows ([HIBP_RETENTION_MS]). The changes fence REUSES the item-tombstone
 * horizon by construction: any cursor old enough to have missed a purged tombstone is
 * behind the fence too, so it gets 410 → full resync instead of resurrecting deletions.
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
        // Per-table prune counts (design 2026-07-10 n2 §5): rows deleted, or — in dry-run —
        // rows that WOULD have been deleted (nothing is deleted, the fence does not move).
        val prunedChanges: Long,
        val prunedSessions: Long,
        val prunedMutations: Long,
        val prunedAudit: Long,
        val prunedInvites: Long,
        val prunedHibp: Long,
        val dryRun: Boolean,
    )

    suspend fun sweep(nowMs: Long = now()): SweepResult = SweepResult(
        purgedVaults = purgeDueVaults(nowMs),
        expiredOffers = expireTransferOffers(nowMs),
        purgedItemTombstones = purgeOldItemTombstones(nowMs),
        prunedChanges = pruneChanges(nowMs),
        prunedSessions = pruneOldSessions(nowMs),
        prunedMutations = pruneOldMutations(nowMs),
        prunedAudit = pruneOldAudit(nowMs),
        prunedInvites = pruneOldInvites(nowMs),
        prunedHibp = pruneStaleHibpCache(nowMs),
        dryRun = config.janitorDryRun,
    )

    // ---- (c) F49: item-tombstone retention (30 days) ----

    /** Hard-delete item tombstones deleted more than 30 days ago (+ their archived versions), so
     *  Trash is bounded. Dry-run aware; failures are logged, never thrown. Returns the purged ids. */
    fun purgeOldItemTombstones(nowMs: Long): List<String> {
        val cutoff = nowMs - ITEM_TOMBSTONE_RETENTION_MS
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

    // ---- (d) F49: `changes` pruning + oldestRetainedRev fence advancement ----

    /**
     * Prune `changes` rows below the fence and advance `oldestRetainedRev` in the SAME tx
     * (spec 02 §7 invariants (a)+(b); design 2026-07-10 n2 §5 + amendments B1/A-fence).
     * The horizon IS [ITEM_TOMBSTONE_RETENTION_MS] — one constant, never split: a cursor
     * that predates the fence also predates every purged item tombstone, so it 410s into
     * a full resync (Service.pull → ResyncRequired) instead of silently keeping deleted
     * items forever. H is floored at MAX(rev): on an idle server (every row stale) only
     * the newest row is retained, so `currentRev` (= MAX(rev)) never regresses — a
     * regression would wedge every up-to-date client in 409 rev_regression until the
     * next write. Rows below the fence serve no reads (pulls only INSERT + MAX(rev) this
     * table). Dry-run counts without deleting and does NOT move the fence.
     */
    fun pruneChanges(nowMs: Long): Long {
        val cutoff = nowMs - ITEM_TOMBSTONE_RETENTION_MS
        if (config.janitorDryRun) {
            val n = repo.db.read { c ->
                val maxRev = c.queryOne("SELECT MAX(rev) FROM changes") { rs ->
                    rs.getLong(1).let { if (rs.wasNull()) null else it }
                } ?: return@read 0L // empty table: nothing to fence
                val h = c.queryOne("SELECT MIN(rev) FROM changes WHERE at>=?", cutoff) { rs ->
                    rs.getLong(1).let { if (rs.wasNull()) null else it }
                } ?: maxRev
                if (h <= repo.oldestRetainedRev(c)) 0L
                else c.queryOne("SELECT COUNT(*) FROM changes WHERE rev<?", h) { it.getLong(1) } ?: 0L
            }
            if (n > 0) System.err.println("[andvari] janitor DRY-RUN: would prune $n changes row(s) and advance oldestRetainedRev")
            return n
        }
        return runCatching {
            val (pruned, from, to) = repo.db.tx { c ->
                val maxRev = c.queryOne("SELECT MAX(rev) FROM changes") { rs ->
                    rs.getLong(1).let { if (rs.wasNull()) null else it }
                } ?: return@tx Triple(0L, 0L, 0L) // empty table: skip the rule entirely
                // H = oldest rev still inside the horizon; if NO row qualifies (idle
                // server) H = MAX(rev), retaining exactly the newest row (B1).
                val h = c.queryOne("SELECT MIN(rev) FROM changes WHERE at>=?", cutoff) { rs ->
                    rs.getLong(1).let { if (rs.wasNull()) null else it }
                } ?: maxRev
                val fence = repo.oldestRetainedRev(c)
                if (h <= fence) return@tx Triple(0L, fence, fence) // never move the fence backwards
                val n = c.exec("DELETE FROM changes WHERE rev<?", h).toLong()
                // Same-tx fence advance (invariant (b)). Raw upsert — NEVER repo.setMeta
                // here: it opens its own tx and Db.tx is not reentrant (a nested tx
                // commits the outer work mid-flight; see the auditOn/audit split in Repo).
                c.exec(
                    "INSERT INTO meta(key,value) VALUES('oldestRetainedRev',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    h.toString(),
                )
                Triple(n, fence, h)
            }
            if (to > from) System.err.println("[andvari] janitor: pruned $pruned changes row(s); oldestRetainedRev $from -> $to")
            pruned
        }.onFailure { System.err.println("[andvari] janitor: changes prune failed: $it") }
            .getOrDefault(0L)
    }

    // ---- (e)–(i) F49: bounded-retention prunes (sessions/mutations/audit/invites/hibp) ----

    /** Shared shape of the simple retention rules: one bounded DELETE, dry-run counts only. */
    private fun prune(table: String, label: String, where: String, vararg args: Any?): Long {
        if (config.janitorDryRun) {
            val n = repo.db.read { c -> c.queryOne("SELECT COUNT(*) FROM $table WHERE $where", *args) { it.getLong(1) } ?: 0L }
            if (n > 0) System.err.println("[andvari] janitor DRY-RUN: would delete $n $label")
            return n
        }
        return runCatching {
            repo.db.tx { c -> c.exec("DELETE FROM $table WHERE $where", *args).toLong() }
                .also { if (it > 0) System.err.println("[andvari] janitor: deleted $it $label") }
        }.onFailure { System.err.println("[andvari] janitor: $label prune failed: $it") }
            .getOrDefault(0L)
    }

    /** (e) Dead sessions: revoked >90d ago, or refresh chain expired >90d ago. Rotation does
     *  NOT set revokedAt (it stamps refreshConsumedAt + inserts a fresh row), so the expiry leg
     *  is what ages out the ~24 consumed rows/day a healthy device accretes (amendment B2).
     *  Accepted trade: a consumed token replayed >90d after expiry now yields invalid_refresh
     *  instead of the refresh_reuse theft-signal + device revoke (unusable either way). */
    fun pruneOldSessions(nowMs: Long): Long {
        val cutoff = nowMs - SESSION_RETENTION_MS
        return prune("sessions", "dead session row(s) past 90d", "(revokedAt IS NOT NULL AND revokedAt<?) OR refreshExpiresAt<?", cutoff, cutoff)
    }

    /** (f) Mutation-dedup journal >180d. Accepted residual: a >180d replay of a put whose item
     *  tombstone was ALSO purged resurrects the item as a clean `applied` INSERT (Service.applyPut
     *  existing==null) — same accepted class as the offline-re-add note on Repo.purgeItem. */
    fun pruneOldMutations(nowMs: Long): Long =
        prune("mutations", "mutation-journal row(s) past 180d", "createdAt<?", nowMs - MUTATION_RETENTION_MS)

    /** (g) Audit rows >365d. The off-box copy ships via logback → journald → Loki (PROD-1),
     *  so the local year is a floor, not the only record. */
    fun pruneOldAudit(nowMs: Long): Long =
        prune("audit", "audit row(s) past 365d", "at<?", nowMs - AUDIT_RETENTION_MS)

    /** (h) Dead invites: used >30d ago, or expired >30d ago (the admin UI lists only live ones). */
    fun pruneOldInvites(nowMs: Long): Long {
        val cutoff = nowMs - INVITE_RETENTION_MS
        return prune("invites", "dead invite row(s) past 30d", "(usedAt IS NOT NULL AND usedAt<?) OR expiresAt<?", cutoff, cutoff)
    }

    /** (i) hibp_cache rows not refreshed in 45d. Reads already ignore rows older than 7d
     *  (HibpRelay.cacheMaxAgeMs / Repo.hibpCached) — this is space reclaim, not correctness. */
    fun pruneStaleHibpCache(nowMs: Long): Long =
        prune("hibp_cache", "stale hibp_cache row(s) past 45d", "fetchedAt<?", nowMs - HIBP_RETENTION_MS)

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

        // Retention horizons (design 2026-07-10 n2 §5 + amendments; named here, no config sprawl).
        /** Item-tombstone retention AND the `changes`/`oldestRetainedRev` fence horizon — ONE
         *  constant BY CONSTRUCTION (amendment A-fence), so the two can never drift apart: a
         *  cursor older than the fence is older than every purged tombstone and full-resyncs. */
        internal const val ITEM_TOMBSTONE_RETENTION_MS = 30 * Service.DAY_MS
        internal const val SESSION_RETENTION_MS = 90 * Service.DAY_MS
        internal const val MUTATION_RETENTION_MS = 180 * Service.DAY_MS
        internal const val AUDIT_RETENTION_MS = 365 * Service.DAY_MS
        internal const val INVITE_RETENTION_MS = 30 * Service.DAY_MS
        internal const val HIBP_RETENTION_MS = 45 * Service.DAY_MS
    }
}
