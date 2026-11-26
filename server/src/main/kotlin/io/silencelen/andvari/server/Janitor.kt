package io.silencelen.andvari.server

/**
 * The janitor (spec 03 §11.1, §15.8, §16.2, §18; spec 02 §7): daily at 04:30 and once after boot.
 *
 * - vaults past their grace are purged, keeping the tombstone and the log for a year; a year after the
 *   purge the log rows go (the vault row stays, so a vault id is never recycled);
 * - expired ownership offers are cleared;
 * - open links past expiry become `expired`, and rows that left `open` 30 days ago are deleted
 *   (`connections` are never touched);
 * - device links past their state's timeout, sign-up codes and tickets, and dead recovery requests go;
 * - item tombstones past 30 days go and the `changes` fence (`oldestRetainedRev`) advances with them;
 * - dead sessions, the mutation journal (180 days), audit rows (365 days) and a deleted account's
 *   pseudonymised rows (90 days after its deletion).
 *
 * Device rows are never pruned (only an account deletion removes them): a device whose secret hash is set
 * must stay a known device (spec 03 §16.8) however long ago its last session died, and a revoked one keeps
 * its row for the devices list.
 *
 * Under `ANDVARI_JANITOR_DRYRUN` nothing is destroyed; each step says what it would do.
 */
class Janitor(private val s: Services) {
    companion object {
        const val ITEM_TOMBSTONE_RETENTION_MS = 30 * Clock.DAY_MS
        const val TOMBSTONE_LOG_RETENTION_MS = 365 * Clock.DAY_MS
        const val LINK_RETENTION_MS = 30 * Clock.DAY_MS
        const val SESSION_RETENTION_MS = 90 * Clock.DAY_MS
        const val MUTATION_RETENTION_MS = 180 * Clock.DAY_MS
        const val AUDIT_RETENTION_MS = 365 * Clock.DAY_MS
    }

    private val dry get() = s.config.janitorDryRun

    fun sweep(nowMs: Long = s.clock.now()) {
        step("vault purge") { purgeDueVaults(nowMs) }
        step("tombstone logs") { prune("vault_log", "vaultId IN (SELECT vaultId FROM vaults WHERE purgedAt IS NOT NULL AND purgedAt<?)", nowMs - TOMBSTONE_LOG_RETENTION_MS) }
        step("offers") {
            if (dry) 0 else s.db.tx { c -> c.exec("UPDATE vaults SET pendingOfferId=NULL, pendingOwnerId=NULL, pendingOfferExpiresAt=NULL WHERE pendingOfferExpiresAt<?", nowMs).toLong() }
        }
        step("links expire") {
            if (dry) 0 else s.db.tx { c -> c.exec("UPDATE links SET state='expired', stateChangedAt=? WHERE state='open' AND expiresAt<=?", nowMs, nowMs).toLong() }
        }
        step("links") { prune("links", "state<>'open' AND stateChangedAt<?", nowMs - LINK_RETENTION_MS) }
        step("device links") {
            prune(
                "device_links",
                """(state='open' AND expiresAt<=?1) OR (state='claimed' AND claimedAt<=?2) OR (state='revealed' AND revealedAt<=?2) OR (state='approved' AND approvedAt<=?2)""",
                nowMs, nowMs - DeviceLinks.STATE_TTL_MS,
            )
        }
        step("signup codes") { prune("signup_codes", "expiresAt<=?", nowMs) }
        step("signup tickets") { prune("signup_tickets", "expiresAt<=?", nowMs) }
        step("recovery requests") {
            prune(
                "recovery_requests",
                """(state='unverified' AND createdAt<=?1) OR (state IN ('verified','fulfilled') AND holdEndsAt<=?2) OR (state='vetoed' AND createdAt<=?3)""",
                nowMs - Assisted.UNVERIFIED_TTL_MS, nowMs - Assisted.AFTER_HOLD_TTL_MS, nowMs - Assisted.AFTER_HOLD_TTL_MS,
            )
        }
        step("recovery mailbox values") { prune("recovery_mailbox_values", "expiresAt<=?", nowMs) }
        step("item tombstones") {
            if (dry) 0 else s.db.tx { c ->
                val cutoff = nowMs - ITEM_TOMBSTONE_RETENTION_MS
                c.exec("DELETE FROM item_versions WHERE itemId IN (SELECT itemId FROM items WHERE deleted=1 AND updatedAt<?)", cutoff)
                c.exec("DELETE FROM items WHERE deleted=1 AND updatedAt<?", cutoff).toLong()
            }
        }
        step("changes fence") { pruneChanges(nowMs) }
        step("sessions") { prune("sessions", "(revokedAt IS NOT NULL AND revokedAt<?1) OR refreshExpiresAt<?1", nowMs - SESSION_RETENTION_MS) }
        // A chain row whose session is gone: pruned above, or deleted by a server of the version before, which does not
        // know the table (spec 02 §5 `session_chains`).
        step("session chains") { prune("session_chains", "sessionId NOT IN (SELECT sessionId FROM sessions)") }
        step("mutations") { prune("mutations", "createdAt<?", nowMs - MUTATION_RETENTION_MS) }
        step("audit") { prune("audit", "at<?", nowMs - AUDIT_RETENTION_MS) }
        step("deleted-account audit") {
            prune("audit", "userId IN (SELECT userId FROM audit WHERE type='account_delete' AND at<?)", nowMs - AccountDeletion.AUDIT_RETENTION_MS)
        }
    }

    private fun step(label: String, block: () -> Long) {
        runCatching(block)
            .onSuccess { n -> if (n > 0) System.err.println("[andvari] janitor${if (dry) " DRY-RUN" else ""}: $label: $n") }
            .onFailure { System.err.println("[andvari] janitor: $label failed: $it") }
    }

    private fun prune(table: String, where: String, vararg args: Any?): Long =
        if (dry) s.db.read { c -> c.count("SELECT COUNT(*) FROM $table WHERE $where", *args) }
        else s.db.tx { c -> c.exec("DELETE FROM $table WHERE $where", *args).toLong() }

    /** Purge every vault whose grace ended (spec 03 §11.1); each in its own transaction that re-checks it is still due. */
    fun purgeDueVaults(nowMs: Long): Long {
        val due = s.db.read { c -> c.queryAll("SELECT vaultId FROM vaults WHERE deletedAt IS NOT NULL AND purgedAt IS NULL AND purgeAt<=?", nowMs) { it.getString(1) } }
        if (dry) return due.size.toLong()
        var n = 0L
        for (v in due) {
            val files = s.db.tx { c ->
                val still = c.queryOne("SELECT 1 FROM vaults WHERE vaultId=? AND deletedAt IS NOT NULL AND purgedAt IS NULL AND purgeAt<=?", v, nowMs) { 1 } != null
                if (!still) return@tx null
                Purge.vault(s, c, v, nowMs, keepLog = true)
            } ?: continue
            s.attachments.unlinkOrphaned(files)
            n++
        }
        if (n > 0) s.db.checkpointTruncate()
        return n
    }

    /**
     * Prune `changes` behind the 30-day horizon and advance `oldestRetainedRev` in the same transaction; the
     * newest row always stays (the fence never passes MAX(rev), so `currentRev` never regresses).
     */
    fun pruneChanges(nowMs: Long): Long {
        val cutoff = nowMs - ITEM_TOMBSTONE_RETENTION_MS
        return s.db.tx { c ->
            val maxRev = c.queryOne("SELECT MAX(rev) FROM changes") { it.longOrNull("MAX(rev)") } ?: return@tx 0L
            val h = c.queryOne("SELECT MIN(rev) FROM changes WHERE at>=?", cutoff) { it.longOrNull("MIN(rev)") } ?: maxRev
            val fence = c.queryOne("SELECT value FROM meta WHERE key='oldestRetainedRev'") { it.getString(1).toLong() } ?: 0L
            if (h <= fence || dry) return@tx 0L
            val n = c.exec("DELETE FROM changes WHERE rev<?", h).toLong()
            c.exec("INSERT INTO meta(key,value) VALUES('oldestRetainedRev',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", h.toString())
            n
        }
    }
}
