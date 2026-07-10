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
import java.util.concurrent.ConcurrentHashMap

class PayloadTooLarge(val reason: String) : Exception()

/**
 * Encrypted attachment blobs (spec 02 §6). The DB row holds the server-visible
 * plaintext contract (ids, ciphertext size, sha256, secretstream header); the
 * ciphertext chunk stream lives on disk at blobDir/{attachmentId}. Upload is
 * blob-first: rows/files that no live item references are GC'd after 24 h.
 */
class AttachmentStore(
    private val repo: Repo,
    blobDirPath: String,
    private val maxConcurrentUploadsPerUser: Int = 4,
) {
    private val dir = File(blobDirPath).apply { mkdirs() }

    /**
     * Per-user in-flight upload accounting (LOW-6): a concurrency cap plus streamed-but-
     * uncommitted bytes counted toward the user quota mid-stream. One entry per userId
     * for the process lifetime — bounded by the user table; deliberately never evicted
     * (removing an entry another upload still holds would fork the semaphore and double
     * the effective cap).
     */
    private class InFlight(max: Int) {
        val sem = java.util.concurrent.Semaphore(max)
        val bytes = java.util.concurrent.atomic.AtomicLong()
    }

    private val inFlight = ConcurrentHashMap<String, InFlight>()

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
        val userMaxCipher = maxCipherBytes(policy.userAttachmentsMaxBytes)
        val fl = inFlight.computeIfAbsent(userId) { InFlight(maxConcurrentUploadsPerUser) }
        // Acquire BEFORE the try — a failed acquire must never reach the release in finally.
        if (!fl.sem.tryAcquire()) throw RateLimited()
        val digest = MessageDigest.getInstance("SHA-256")
        var header: ByteArray? = null
        var cipherBytes = 0L
        var inFlightAdded = 0L
        var tmp: File? = null
        try {
            // The quota read and the temp-file creation live INSIDE the try so any throw (a DB
            // error, or an IOException from createTempFile doing disk I/O) still reaches the
            // finally that releases the semaphore permit — a leaked permit would permanently
            // shrink this user's concurrent-upload cap for the process lifetime.
            //
            // An idempotent re-upload of an already-committed id is EXEMPT from the user quota
            // (the authoritative commit path returns the stored meta before its quota check),
            // so the mid-stream bound must exempt it too — else a retry near quota double-counts
            // the existing bytes against itself and false-413s a request the commit path allows.
            val (preexisting, committedBytes) = repo.db.read { c ->
                (rowById(c, attachmentId) != null) to userBytes(c, userId)
            }
            // ATT-1: a UNIQUE temp file per in-flight upload. A deterministic "$attachmentId.part"
            // let two concurrent PUTs for the SAME attachmentId (a client retry / double-tap Save /
            // refresh that re-encrypts while the first body is still draining) interleave their bytes
            // into one inode; the winner's committed row.sha256 then matched NEITHER the winner's nor
            // the loser's on-disk bytes → permanent, silent, undecryptable ciphertext loss. Each
            // upload now streams to its own inode; the commit-time row guard below still serializes
            // the single winner's rename, and the finally-block deletes whichever temp did not commit.
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
                        if (cipherBytes > maxCipher) throw PayloadTooLarge("attachment_too_large")
                        if (!preexisting) {
                            inFlightAdded += delta
                            // Mid-stream bound over committed + ALL of this user's in-flight
                            // bytes. The commit-time check stays authoritative (serialized in
                            // the tx); this only caps .part growth while bodies stream.
                            if (committedBytes + fl.bytes.addAndGet(delta) > userMaxCipher) {
                                throw PayloadTooLarge("user_attachment_quota")
                            }
                        }
                        digest.update(buf, off, n - off)
                        out.write(buf, off, n - off)
                    }
                }
            }
            val hdr = header ?: throw BadRequest("attachment_truncated")
            if (cipherBytes <= Attachments.STREAM_ABYTES) throw BadRequest("attachment_truncated")
            val sha = Bytes.toHexLower(digest.digest())
            // Streaming done: hand this upload's bytes off to the commit's own userBytes
            // read. Keeping them in fl.bytes THROUGH the commit tx would double-count them
            // (committed row + fl.bytes) for a concurrent same-user upload → spurious 413.
            if (inFlightAdded > 0) { fl.bytes.addAndGet(-inFlightAdded); inFlightAdded = 0 }

            return repo.db.tx { c ->
                // Post-revocation blob-commit race (spec 03 §11 / design §4 matrix,
                // attachment-upload-vs-delete): the route-level grant check ran before the
                // body streamed; a vault delete or member removal can land in between.
                // Re-check the grant inside the commit tx so a revoked writer can never
                // land ciphertext into a vault they just lost.
                val txRole = repo.grantRole(c, userId, vaultId)
                if (txRole == null || txRole == "reader") {
                    part.delete()
                    throw Forbidden("no_grant")
                }
                val existing = rowById(c, attachmentId)
                if (existing != null) {
                    part.delete()
                    if (existing.sha256 != sha || existing.itemId != itemId || existing.vaultId != vaultId) throw BadRequest("attachment_id_taken")
                    return@tx AttachmentMeta(existing.attachmentId, existing.itemId, existing.vaultId, existing.size, existing.sha256, existing.createdAt)
                }
                if (userBytes(c, userId) + cipherBytes > maxCipherBytes(policy.userAttachmentsMaxBytes)) {
                    part.delete()
                    throw PayloadTooLarge("user_attachment_quota")
                }
                val t = now()
                c.exec(
                    "INSERT INTO attachments(attachmentId,itemId,vaultId,size,sha256,header,createdAt) VALUES(?,?,?,?,?,?,?)",
                    attachmentId, itemId, vaultId, cipherBytes, sha, Bytes.toB64(hdr), t,
                )
                if (!part.renameTo(file(attachmentId))) {
                    part.copyTo(file(attachmentId), overwrite = true)
                    part.delete()
                }
                repo.auditOn(c, "attachment_upload", userId, null, null, "$attachmentId:$cipherBytes")
                AttachmentMeta(attachmentId, itemId, vaultId, cipherBytes, sha, t)
            }
        } finally {
            if (inFlightAdded > 0) fl.bytes.addAndGet(-inFlightAdded)
            fl.sem.release()
            tmp?.delete()
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
     *
     * F56: all filesystem work (the directory listing and every unlink) happens OUTSIDE the
     * single-connection DB lock — the previous shape did both inside the tx, so a populated
     * blob dir stalled EVERY route for the whole sweep (measured 591 ms max request stall at
     * 10k files; ~0.1 ms after — perf addendum §3). Same post-commit-unlink pattern as
     * Service.push: rows are the source of truth, files deleted only after the tx commits.
     * A crash between commit and unlink leaves stray files the NEXT sweep removes (rows are
     * already gone, so they fail the `known` check once past the TTL).
     *
     * TOCTOU guards (2026-07-09 review): moving the unlinks outside the lock opened a race
     * the in-tx shape could not have — an idempotent re-upload of a swept id (a documented
     * store() contract) whose commit tx was WAITING on the sweep's lock can INSERT a fresh
     * row and rename its blob into place before the sweep thread reaches the unlink loop;
     * the old code then deleted the just-committed ciphertext behind that upload's 200, and
     * the idempotent branch never rewrites the file, so the loss was permanent. So each pass
     * carries its own guard: the SWEPT-ROW pass re-checks row absence under a short db.read
     * and additionally skips fresh-mtime files (renameTo/copyTo give a re-committed blob a
     * fresh mtime; every legitimately swept file is > TTL old, so this skips nothing in the
     * normal path); the STRAY pass re-stats lazily and is protected by the same mtime
     * cutoff, which also protects in-flight .part files. A file skipped by a guard becomes
     * a stray a FUTURE sweep removes once it is past the TTL and still rowless.
     */
    fun sweepOrphans(): Int {
        val cutoff = now() - orphanTtlMs
        // Snapshot the directory before touching the DB (a big listing is pure fs work).
        val dirFiles = dir.listFiles()?.toList() ?: emptyList()
        val toUnlink = mutableListOf<String>()
        var removed = 0
        val known = repo.db.tx { c ->
            val candidates = c.queryAll(
                "SELECT attachmentId, itemId FROM attachments WHERE createdAt < ?", cutoff,
            ) { rs -> rs.getString(1) to rs.getString(2) }
            for ((aid, itemId) in candidates) {
                val referenced = c.queryOne("SELECT attachmentIds FROM items WHERE itemId=? AND deleted=0", itemId) { rs ->
                    decodeIds(rs.getString(1))
                }?.contains(aid) ?: false
                if (!referenced) {
                    c.exec("DELETE FROM attachments WHERE attachmentId=?", aid)
                    toUnlink += aid
                    removed++
                }
            }
            // Read AFTER the deletes so the just-orphaned ids are not "known" to the stray pass.
            c.queryAll("SELECT attachmentId FROM attachments") { it.getString(1) }.toSet()
        }
        // Post-commit: drop ids whose row was re-committed (idempotent re-upload) while we
        // held or released the lock — one short indexed-PK read, then unlink outside it.
        val resurrected = repo.db.read { c -> toUnlink.filterTo(HashSet()) { rowById(c, it) != null } }
        toUnlink.forEach { aid ->
            if (aid in resurrected) return@forEach
            val f = file(aid)
            // Belt to the row re-check: a commit landing between the read above and this
            // delete gave the file a fresh mtime — leave it; if it somehow ends up rowless
            // again, a future sweep's stray pass takes it once past the TTL.
            if (f.lastModified() < cutoff) f.delete()
        }
        // …then stray files (crash between file write and row insert, or failed rename).
        // Files already unlinked above fail delete() and are not double-counted.
        dirFiles.forEach { f ->
            val name = f.name.removeSuffix(".part")
            if ((f.name.endsWith(".part") || name !in known) && f.lastModified() < cutoff && name !in known) {
                if (f.delete()) removed++
            }
        }
        return removed
    }

    fun stats(c: Connection): Pair<Int, Long> =
        c.queryOne("SELECT COUNT(*), COALESCE(SUM(size),0) FROM attachments") { rs -> rs.getInt(1) to rs.getLong(2) } ?: (0 to 0L)
}
