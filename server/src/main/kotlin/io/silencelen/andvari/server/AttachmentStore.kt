package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.AttachmentMeta
import io.silencelen.andvari.core.model.ClientPolicy
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import java.io.File
import java.security.MessageDigest
import java.sql.Connection

class PayloadTooLarge(val reason: String) : Exception()

/**
 * Encrypted attachment blobs (spec 02 §6). The DB row holds the server-visible
 * plaintext contract (ids, ciphertext size, sha256, secretstream header); the
 * ciphertext chunk stream lives on disk at blobDir/{attachmentId}. Upload is
 * blob-first: rows/files that no live item references are GC'd after 24 h.
 */
class AttachmentStore(private val repo: Repo, blobDirPath: String) {
    private val dir = File(blobDirPath).apply { mkdirs() }

    var orphanTtlMs = 24L * 3600 * 1000 // mutable so tests can force an immediate sweep

    fun file(attachmentId: String): File = File(dir, attachmentId)

    /** Ciphertext budget for a plaintext quota: per-chunk secretstream overhead, header excluded (stored in the row). */
    fun maxCipherBytes(plainMax: Long): Long =
        plainMax + ((plainMax + Attachments.CHUNK - 1) / Attachments.CHUNK) * Attachments.STREAM_ABYTES

    class AttachmentRow(val attachmentId: String, val itemId: String, val vaultId: String, val size: Long, val sha256: String, val header: String, val createdAt: Long)

    fun rowById(c: Connection, id: String): AttachmentRow? =
        c.queryOne("SELECT * FROM attachments WHERE attachmentId=?", id) { rs ->
            AttachmentRow(
                rs.getString("attachmentId"), rs.getString("itemId"), rs.getString("vaultId"),
                rs.getLong("size"), rs.getString("sha256"), rs.getString("header"), rs.getLong("createdAt"),
            )
        }

    fun userBytes(c: Connection, userId: String): Long =
        c.queryOne(
            """SELECT COALESCE(SUM(a.size),0) FROM attachments a
               JOIN grants g ON g.vaultId=a.vaultId WHERE g.userId=? AND g.revokedAt IS NULL""",
            userId,
        ) { it.getLong(1) } ?: 0

    /**
     * Persist an uploaded body (header || ciphertext chunks), enforcing the size cap
     * while streaming. Idempotent: re-uploading the same id with the same bytes
     * returns the stored meta; a different payload under a taken id is rejected.
     */
    suspend fun store(
        userId: String,
        attachmentId: String,
        itemId: String,
        vaultId: String,
        body: ByteReadChannel,
        policy: ClientPolicy,
    ): AttachmentMeta {
        val maxCipher = maxCipherBytes(policy.attachmentMaxBytes)
        val tmp = File(dir, "$attachmentId.part")
        val digest = MessageDigest.getInstance("SHA-256")
        var header: ByteArray? = null
        var cipherBytes = 0L
        try {
            tmp.outputStream().use { out ->
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
                        cipherBytes += n - off
                        if (cipherBytes > maxCipher) throw PayloadTooLarge("attachment_too_large")
                        digest.update(buf, off, n - off)
                        out.write(buf, off, n - off)
                    }
                }
            }
            val hdr = header ?: throw BadRequest("attachment_truncated")
            if (cipherBytes <= Attachments.STREAM_ABYTES) throw BadRequest("attachment_truncated")
            val sha = Bytes.toHexLower(digest.digest())

            return repo.db.tx { c ->
                val existing = rowById(c, attachmentId)
                if (existing != null) {
                    tmp.delete()
                    if (existing.sha256 != sha || existing.itemId != itemId || existing.vaultId != vaultId) throw BadRequest("attachment_id_taken")
                    return@tx AttachmentMeta(existing.attachmentId, existing.itemId, existing.vaultId, existing.size, existing.sha256, existing.createdAt)
                }
                if (userBytes(c, userId) + cipherBytes > maxCipherBytes(policy.userAttachmentsMaxBytes)) {
                    tmp.delete()
                    throw PayloadTooLarge("user_attachment_quota")
                }
                val t = now()
                c.exec(
                    "INSERT INTO attachments(attachmentId,itemId,vaultId,size,sha256,header,createdAt) VALUES(?,?,?,?,?,?,?)",
                    attachmentId, itemId, vaultId, cipherBytes, sha, Bytes.toB64(hdr), t,
                )
                if (!tmp.renameTo(file(attachmentId))) {
                    tmp.copyTo(file(attachmentId), overwrite = true)
                    tmp.delete()
                }
                repo.auditOn(c, "attachment_upload", userId, null, null, "$attachmentId:$cipherBytes")
                AttachmentMeta(attachmentId, itemId, vaultId, cipherBytes, sha, t)
            }
        } finally {
            tmp.delete()
        }
    }

    /**
     * Delete the attachment ROWS for a tombstoned item inside the item's tx and return
     * their ids. The blob FILES are deliberately NOT unlinked here — the caller unlinks
     * them only after the batch tx commits, so a later mutation that rolls the tx back
     * (restoring the item) does not leave the item referencing a vanished blob.
     */
    fun deleteRowsForItem(c: Connection, itemId: String): List<String> {
        val ids = c.queryAll("SELECT attachmentId FROM attachments WHERE itemId=?", itemId) { it.getString(1) }
        if (ids.isNotEmpty()) c.exec("DELETE FROM attachments WHERE itemId=?", itemId)
        return ids
    }

    /**
     * GC (spec 02 §6): drop rows older than the TTL that their item does not
     * reference (or whose item is gone/tombstoned), plus stray files with no row.
     */
    fun sweepOrphans(): Int {
        val cutoff = now() - orphanTtlMs
        var removed = 0
        repo.db.tx { c ->
            val candidates = c.queryAll(
                "SELECT attachmentId, itemId FROM attachments WHERE createdAt < ?", cutoff,
            ) { rs -> rs.getString(1) to rs.getString(2) }
            for ((aid, itemId) in candidates) {
                val referenced = c.queryOne("SELECT attachmentIds FROM items WHERE itemId=? AND deleted=0", itemId) { rs ->
                    decodeIds(rs.getString(1))
                }?.contains(aid) ?: false
                if (!referenced) {
                    c.exec("DELETE FROM attachments WHERE attachmentId=?", aid)
                    file(aid).delete()
                    removed++
                }
            }
            // Stray files (crash between file write and row insert, or failed rename).
            val known = c.queryAll("SELECT attachmentId FROM attachments") { it.getString(1) }.toSet()
            dir.listFiles()?.forEach { f ->
                val name = f.name.removeSuffix(".part")
                if ((f.name.endsWith(".part") || name !in known) && f.lastModified() < cutoff && name !in known) {
                    if (f.delete()) removed++
                }
            }
        }
        return removed
    }

    fun stats(c: Connection): Pair<Int, Long> =
        c.queryOne("SELECT COUNT(*), COALESCE(SUM(size),0) FROM attachments") { rs -> rs.getInt(1) to rs.getLong(2) } ?: (0 to 0L)
}
