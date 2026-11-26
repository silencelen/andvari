package io.silencelen.andvari.server

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AttachmentMeta
import io.silencelen.andvari.core.model.wire.QuotaName
import io.silencelen.andvari.core.model.wire.WireErrors
import java.io.File
import java.security.MessageDigest
import java.sql.Connection
import java.util.concurrent.ConcurrentHashMap

/**
 * Attachment blobs (spec 03 §9, spec 02 §6): `header (24 B) || ciphertext chunks`, streamed to disk and
 * never parsed. Bounded per file (`attachmentMaxBytes`), by the vault owner's account quota (§14.4, with
 * in-flight `.part` bytes counted mid-stream) and by a per-user concurrent-upload cap. Ids are one global
 * namespace; an id that already exists in another vault answers `403 no_grant` and is audited.
 */
class AttachmentStore(private val s: Services) {
    private val dir = File(s.config.blobDir).apply { mkdirs() }

    /** Test hook: the in-flight bytes counted against [ownerUserId]'s quota. */
    internal fun inFlightBytesOf(ownerUserId: String): Long = ownerInFlight[ownerUserId]?.get() ?: 0L

    private class InFlight(max: Int) {
        val sem = java.util.concurrent.Semaphore(max)
    }

    /** The concurrent-upload cap: per uploader. */
    private val inFlight = ConcurrentHashMap<String, InFlight>()

    /**
     * In-flight `.part` bytes: per vault OWNER, whose quota they count against (spec 03 §9).
     * Keyed per uploader, two members uploading into one owner's vault each saw only their own bytes.
     */
    private val ownerInFlight = ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicLong>()

    /** Mutable so a test can force an immediate orphan sweep. */
    var orphanTtlMs = 24L * 3_600_000

    fun file(attachmentId: String): File = File(dir, attachmentId)

    fun maxCipherBytes(plainMax: Long): Long =
        plainMax + ((plainMax + Attachments.CHUNK - 1) / Attachments.CHUNK) * Attachments.STREAM_ABYTES

    class Row(val attachmentId: String, val itemId: String, val vaultId: String, val size: Long, val sha256: String, val createdAt: Long)

    fun rowById(c: Connection, id: String): Row? =
        c.queryOne("SELECT attachmentId,itemId,vaultId,size,sha256,createdAt FROM attachments WHERE attachmentId=?", id) { rs ->
            Row(rs.getString(1), rs.getString(2), rs.getString(3), rs.getLong(4), rs.getString(5), rs.getLong(6))
        }

    suspend fun store(userId: String, attachmentId: String, itemId: String, vaultId: String, body: ByteReadChannel): AttachmentMeta {
        val policy = s.policy.get()
        val maxCipher = maxCipherBytes(policy.attachmentMaxBytes)
        val fl = inFlight.computeIfAbsent(userId) { InFlight(s.config.uploadMaxConcurrentPerUser) }
        if (!fl.sem.tryAcquire()) rateLimited(5_000)
        val digest = MessageDigest.getInstance("SHA-256")
        var header: ByteArray? = null
        var cipherBytes = 0L
        var inFlightAdded = 0L
        var tmp: File? = null
        var bytes: java.util.concurrent.atomic.AtomicLong? = null
        try {
            val (preexisting, ownerRoom, owner) = s.db.read { c ->
                val owner = Quotas.ownerOf(c, vaultId)
                val room = owner?.let { o -> s.policy.quotaOf(c, o).accountBytes - Quotas.ownedBytes(c, o) } ?: Long.MAX_VALUE
                Triple(rowById(c, attachmentId) != null, room, owner)
            }
            val counter = ownerInFlight.computeIfAbsent(owner ?: "vault:$vaultId") { java.util.concurrent.atomic.AtomicLong() }.also { bytes = it }
            val part = File.createTempFile("$attachmentId.", ".part", dir).also { tmp = it }
            part.outputStream().use { out ->
                val buf = ByteArray(64 * 1024)
                val headerBuf = ByteArray(Attachments.HEADER_BYTES)
                var headerFill = 0
                while (true) {
                    val n = body.readAvailable(buf, 0, buf.size)
                    if (n <= 0) break
                    var off = 0
                    if (headerFill < Attachments.HEADER_BYTES) {
                        val take = minOf(Attachments.HEADER_BYTES - headerFill, n)
                        System.arraycopy(buf, 0, headerBuf, headerFill, take)
                        headerFill += take
                        off = take
                        if (headerFill == Attachments.HEADER_BYTES) header = headerBuf
                    }
                    if (n - off > 0) {
                        val delta = (n - off).toLong()
                        cipherBytes += delta
                        if (cipherBytes > maxCipher) throw ApiException(413, WireErrors.ATTACHMENT_TOO_LARGE)
                        if (!preexisting) {
                            inFlightAdded += delta
                            if (counter.addAndGet(delta) > ownerRoom) quotaExceeded(QuotaName.ACCOUNT_BYTES)
                        }
                        digest.update(buf, off, n - off)
                        out.write(buf, off, n - off)
                    }
                }
            }
            val hdr = header ?: badRequest("attachment_truncated")
            if (cipherBytes <= Attachments.STREAM_ABYTES) badRequest("attachment_truncated")
            val sha = Bytes.toHexLower(digest.digest())
            if (inFlightAdded > 0) { counter.addAndGet(-inFlightAdded); inFlightAdded = 0 }
            val meta = s.db.tx { c ->
                val role = Quotas.role(c, userId, vaultId)
                if (role == null || role == "reader") forbidden(WireErrors.NO_WRITE_GRANT)
                val existing = rowById(c, attachmentId)
                if (existing != null) {
                    if (existing.vaultId != vaultId) {
                        s.audit.on(c, "attachment_cross_vault", userId, null, null, "$attachmentId:$vaultId")
                        return@tx null
                    }
                    if (existing.sha256 != sha || existing.itemId != itemId) badRequest(WireErrors.ATTACHMENT_ID_TAKEN)
                    return@tx AttachmentMeta(existing.attachmentId, existing.itemId, existing.vaultId, existing.size, existing.sha256, existing.createdAt)
                }
                val owner = Quotas.ownerOf(c, vaultId)
                if (owner != null && Quotas.ownedBytes(c, owner) + cipherBytes > s.policy.quotaOf(c, owner).accountBytes) quotaExceeded(QuotaName.ACCOUNT_BYTES)
                val t = s.clock.now()
                c.exec(
                    "INSERT INTO attachments(attachmentId,itemId,vaultId,size,sha256,header,createdAt) VALUES(?,?,?,?,?,?,?)",
                    attachmentId, itemId, vaultId, cipherBytes, sha, Bytes.toB64(hdr), t,
                )
                if (!part.renameTo(file(attachmentId))) {
                    part.copyTo(file(attachmentId), overwrite = true)
                    part.delete()
                }
                s.audit.on(c, "attachment_upload", userId, null, null, "$attachmentId:$cipherBytes")
                AttachmentMeta(attachmentId, itemId, vaultId, cipherBytes, sha, t)
            }
            return meta ?: forbidden(WireErrors.NO_GRANT)
        } finally {
            if (inFlightAdded > 0) bytes?.addAndGet(-inFlightAdded)
            fl.sem.release()
            tmp?.delete()
        }
    }

    fun deleteRowsForItem(c: Connection, itemId: String): List<String> {
        val ids = c.queryAll("SELECT attachmentId FROM attachments WHERE itemId=?", itemId) { it.getString(1) }
        if (ids.isNotEmpty()) c.exec("DELETE FROM attachments WHERE itemId=?", itemId)
        return ids
    }

    /** Unlink the files of [ids] that no row names any more (after the deleting transaction committed). */
    fun unlinkOrphaned(ids: Collection<String>) {
        if (ids.isEmpty()) return
        val alive = s.db.read { c -> ids.filterTo(HashSet()) { rowById(c, it) != null } }
        ids.filter { it !in alive }.forEach { file(it).delete() }
    }

    /** Uploads never referenced by a live item are removed after 24 hours (spec 02 §6). */
    fun sweepOrphans(): Int {
        val cutoff = s.clock.now() - orphanTtlMs
        val dirFiles = dir.listFiles()?.toList() ?: emptyList()
        val toUnlink = mutableListOf<String>()
        var removed = 0
        val known = s.db.tx { c ->
            val candidates = c.queryAll("SELECT attachmentId, itemId FROM attachments WHERE createdAt < ?", cutoff) { it.getString(1) to it.getString(2) }
            for ((aid, itemId) in candidates) {
                val referenced = c.queryOne("SELECT attachmentIds FROM items WHERE itemId=? AND deleted=0", itemId) { decodeIds(it.getString(1)) }?.contains(aid) ?: false
                if (!referenced) {
                    c.exec("DELETE FROM attachments WHERE attachmentId=?", aid)
                    toUnlink += aid
                    removed++
                }
            }
            c.queryAll("SELECT attachmentId FROM attachments") { it.getString(1) }.toSet()
        }
        unlinkOrphaned(toUnlink)
        dirFiles.forEach { f ->
            val name = f.name.substringBefore('.')
            if (name !in known && f.lastModified() < cutoff && f.delete()) removed++
        }
        return removed
    }

    fun stats(c: Connection): Pair<Long, Long> =
        c.queryOne("SELECT COUNT(*), COALESCE(SUM(size),0) FROM attachments") { it.getLong(1) to it.getLong(2) } ?: (0L to 0L)
}

/** Per-account quotas (spec 03 §14.4): counted over the vaults the account OWNS; writers use the owner's. */
object Quotas {
    fun role(c: Connection, userId: String, vaultId: String): String? =
        c.queryOne("SELECT role FROM grants WHERE userId=? AND vaultId=? AND revokedAt IS NULL", userId, vaultId) { it.getString(1) }

    /** The owner of [vaultId]: its active owner grant, or (while deleted) the owner grant revoked by the delete. */
    fun ownerOf(c: Connection, vaultId: String): String? =
        c.queryOne(
            "SELECT userId FROM grants WHERE vaultId=? AND role='owner' AND (revokedAt IS NULL OR revokedReason='vault_delete') ORDER BY revokedAt IS NOT NULL LIMIT 1",
            vaultId,
        ) { it.getString(1) }

    /** Item ciphertext plus attachment bytes in the vaults [ownerId] owns. */
    fun ownedBytes(c: Connection, ownerId: String): Long =
        (c.queryOne(
            """SELECT COALESCE(SUM(i.blobSize),0) FROM items i JOIN grants g ON g.vaultId=i.vaultId
               WHERE g.userId=? AND g.role='owner' AND (g.revokedAt IS NULL OR g.revokedReason='vault_delete') AND i.deleted=0""",
            ownerId,
        ) { it.getLong(1) } ?: 0L) + (c.queryOne(
            """SELECT COALESCE(SUM(a.size),0) FROM attachments a JOIN grants g ON g.vaultId=a.vaultId
               WHERE g.userId=? AND g.role='owner' AND (g.revokedAt IS NULL OR g.revokedReason='vault_delete')""",
            ownerId,
        ) { it.getLong(1) } ?: 0L)

    /** Live items across the vaults [ownerId] owns. */
    fun ownedItems(c: Connection, ownerId: String): Long =
        c.count(
            """SELECT COUNT(*) FROM items i JOIN grants g ON g.vaultId=i.vaultId
               WHERE g.userId=? AND g.role='owner' AND (g.revokedAt IS NULL OR g.revokedReason='vault_delete') AND i.deleted=0""",
            ownerId,
        )

    /** Shared vaults [ownerId] owns, live or in grace. */
    fun ownedSharedVaults(c: Connection, ownerId: String): Long =
        c.count(
            """SELECT COUNT(*) FROM grants g JOIN vaults v ON v.vaultId=g.vaultId
               WHERE g.userId=? AND g.role='owner' AND v.type='shared' AND v.purgedAt IS NULL AND (g.revokedAt IS NULL OR g.revokedReason='vault_delete')""",
            ownerId,
        )

    /** Links [creatorId] created that are still open and not yet expired at [nowMs]: what `POST /links` counts. */
    fun openLinks(c: Connection, creatorId: String, nowMs: Long): Long =
        c.count("SELECT COUNT(*) FROM links WHERE creatorUserId=? AND state='open' AND expiresAt>?", creatorId, nowMs)

    /** Bytes stored in one vault (items and attachments), for an ownership transfer's quota check. */
    fun vaultBytes(c: Connection, vaultId: String): Long =
        (c.queryOne("SELECT COALESCE(SUM(blobSize),0) FROM items WHERE vaultId=? AND deleted=0", vaultId) { it.getLong(1) } ?: 0L) +
            (c.queryOne("SELECT COALESCE(SUM(size),0) FROM attachments WHERE vaultId=?", vaultId) { it.getLong(1) } ?: 0L)

    fun vaultItems(c: Connection, vaultId: String): Long = c.count("SELECT COUNT(*) FROM items WHERE vaultId=? AND deleted=0", vaultId)
}
