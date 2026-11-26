package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.CsvImportView
import io.silencelen.andvari.core.app.CsvSession
import io.silencelen.andvari.core.app.ExportCopy
import io.silencelen.andvari.core.app.ExportFile
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.app.ExportMade
import io.silencelen.andvari.core.app.ExportSession
import io.silencelen.andvari.core.app.ExportView
import io.silencelen.andvari.core.app.ImportCopy
import io.silencelen.andvari.core.app.ScanProgressView
import io.silencelen.andvari.core.app.VaultChoiceView
import io.silencelen.andvari.core.app.csvImportView
import io.silencelen.andvari.core.app.exportView
import io.silencelen.andvari.core.client.AttachmentPlan
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupSkipped
import io.silencelen.andvari.core.client.BackupSkippedItem
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.ExportCsv
import io.silencelen.andvari.core.client.ExportPlanner
import io.silencelen.andvari.core.client.ExportVault
import io.silencelen.andvari.core.client.PlannedAttachment
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.QuotaCheck
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

/**
 * Import (spec 06) and export (spec 07) for [ContentController]: the old controller's flows, over a [ContentSource].
 * The parsed file and the plan are held only while the import screen is open; the export screen holds no plaintext,
 * and a file is made in memory only when the person has chosen a folder for it.
 */
internal class ContentPorts(
    private val source: ContentSource,
    private val crypto: CryptoProvider,
    private val host: ContentHost,
    /** Where an item may be put now (empty under a stopped server). */
    private val writableChoices: () -> List<VaultChoiceView>,
    private val vaultName: (String) -> String?,
    /** An import a lock stopped: [kept] of its items were kept here, [lost] were not ([UnsavedAtLock.import]). */
    private val unkeptImport: (kept: Int, lost: Int) -> Unit = { _, _ -> },
    /** The account owns this vault: an import into it counts against its own space (spec 03 §14.4). */
    private val owned: (vaultId: String) -> Boolean = { false },
    /** What the check before the import found, for [ContentState.space]; null: nothing to say. */
    private val checked: (SpaceCheck?) -> Unit = {},
) {
    var csv: CsvSession? = null
    var exporting: ExportSession? = null

    /** When the last sync finished (unix ms), for the export's offline line; 0 before the first. */
    var lastSyncedAt = 0L

    fun close() {
        csv = null
        exporting = null
    }

    // ---- import ----

    fun importView(): CsvImportView? = csv?.let { s -> csvImportView(s, { id -> vaultName(id) ?: "this vault" }, writableChoices()) }

    suspend fun importCsv(bytes: ByteArray): ActionResult {
        if (bytes.size > CsvImport.MAX_BYTES) return ActionResult.Failed(ImportCopy.TOO_LARGE)
        if (source.halted) return ActionResult.Failed(ContentCopy.SERVER_STOPPED)
        // Planned only against a vault this device holds: an empty projection would quietly switch the dedupe off.
        val personal = source.personalVaultId
        if (personal == null || writableChoices().none { it.vaultId == personal }) return ActionResult.Failed(ImportCopy.NO_VAULT)
        val read = try {
            withContext(Dispatchers.Default) { CsvImport.parse(bytes) to CsvImport.rowOrdinalsByLine(bytes) }
        } catch (e: CsvImport.ImportException) {
            return ActionResult.Failed(ImportCopy.forCode(e.code))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return ActionResult.Failed(ContentCopy.FILE_READ_FAILED)
        }
        val s = CsvSession(read.first, read.second, looksMangled(read.first))
        s.vaultId = personal
        s.plan = planFor(s, personal) ?: return ActionResult.Failed(ImportCopy.NO_VAULT)
        csv = s
        planned(s)
        return ActionResult.Ok
    }

    /**
     * The plan's own line about space, from the use and limits this device last read (no call): which limit it would pass
     * and by how much. [confirmImport] checks again on a fresh sync before anything is sent.
     */
    private fun planned(s: CsvSession) {
        val plan = s.plan ?: return
        checked(if (owned(s.vaultId) && plan.items.isNotEmpty()) SpaceCheck.of(QuotaCheck.room(source.quota(), source.importSize(plan.items)), SpaceFor.CSV_IMPORT, s.vaultId) else null)
    }

    private suspend fun planFor(s: CsvSession, vaultId: String): CsvImport.ImportPlan? {
        val existing = (source.importProjections(vaultId) as? ItemResult.Ok)?.value ?: return null
        return withContext(Dispatchers.Default) { CsvImport.plan(s.parsed, existing) { ContentController.freshId(crypto) } }
    }

    suspend fun setImportVault(vaultId: String, published: () -> Unit): ActionResult {
        val s = csv ?: return ActionResult.NotDone(null)
        if (s.busy || s.error != null || s.done || vaultId == s.vaultId) return ActionResult.NotDone(null)
        if (writableChoices().none { it.vaultId == vaultId }) return ActionResult.Failed(ImportCopy.VAULT_GONE)
        s.busy = true
        published()
        val plan = try {
            planFor(s, vaultId)
        } finally {
            s.busy = false
        }
        if (csv !== s) return ActionResult.NotDone(null)
        // The plan and its vault change together: a plan is never sent into another vault than the one it was made for.
        s.plan = plan ?: return ActionResult.Failed(ImportCopy.NO_VAULT)
        s.vaultId = vaultId
        planned(s)
        return ActionResult.Ok
    }

    suspend fun confirmImport(published: () -> Unit): ActionResult {
        val s = csv ?: return ActionResult.NotDone(null)
        val plan = s.plan ?: return ActionResult.NotDone(null)
        if (s.busy || s.done || plan.items.isEmpty()) return ActionResult.NotDone(null)
        val vaultId = s.vaultId
        s.busy = true
        s.error = null
        s.retryable = true
        s.kept = false
        s.listedLater = false
        s.progress = ScanProgressView(0, plan.items.size)
        published()
        // Into a vault the account owns, the import does not start when the account is short (spec 03 §14.4): the check
        // is made on a fresh sync, and the plan then says which limit and by how much. Unknown starts it; the server decides.
        if (owned(vaultId)) {
            val room = try {
                source.roomFor(source.importSize(plan.items))
            } finally {
                s.busy = false
            }
            if (csv !== s) return ActionResult.NotDone(null)
            when (room) {
                is ItemResult.Failed -> {
                    s.progress = null
                    s.retryable = retryable(room.why)
                    s.error = if (s.retryable) ImportCopy.INTERRUPTED else ContentCopy.forFailure(room.why, ContentCopy.During.OTHER)
                    return ActionResult.Ok
                }
                is ItemResult.Ok -> {
                    val check = SpaceCheck.of(room.value, SpaceFor.CSV_IMPORT, vaultId)
                    checked(check)
                    if (check.verdict == SpaceVerdict.NOT_ENOUGH) {
                        // Nothing was sent. Retry checks again: the operator may have raised the limit meanwhile.
                        s.progress = null
                        s.retryable = true
                        s.error = ContentCopy.outOfSpace(check)
                        return ActionResult.Ok
                    }
                }
            }
            s.busy = true
            published()
        }
        var stopped: io.silencelen.andvari.core.client.items.ImportStopped? = null
        val r = try {
            source.importAll(plan.items, { done, total ->
                if (csv === s) {
                    s.progress = ScanProgressView(done, total)
                    published()
                }
            }, vaultId) { stopped = it }
        } catch (e: io.silencelen.andvari.core.client.items.LockedBeforeKept) {
            // The screen has gone with the lock: the next unlock says how many were saved and how many were not.
            unkeptImport(e.kept, plan.items.size - e.kept)
            throw e
        } finally {
            s.busy = false
        }
        val st = stopped
        when {
            // Kept on this device (a copy kept at rest): all of it goes at a later sync, so it is said as kept, never as
            // failed, and Retry is not offered: there is nothing left for it to do.
            r is ItemResult.Failed && st != null && st.kept != null && st.notSaved == 0 -> {
                s.retryable = false
                s.kept = true
                s.progress = null
                s.error = ContentCopy.importKept(st.keptToSend, st.kept)
            }
            r is ItemResult.Failed -> {
                s.retryable = retryable(r.why)
                val why = if (s.retryable) null else ContentCopy.forFailure(r.why, ContentCopy.During.OTHER)
                // Part of it saved and the rest not kept: how many of each (the rest is never sent later behind the
                // person's back). A row still kept for a refusal that is not one for now is said as before.
                val counted = if (st == null || st.keptToSend > 0) null else ContentCopy.importStopped(st.saved, st.notSaved, why)
                s.error = counted ?: why ?: ImportCopy.INTERRUPTED
            }
            // A vault that left while importing holds the items rather than refusing them: that is not a success.
            source.vaults().none { it.vaultId == vaultId } -> {
                s.retryable = false
                s.error = ImportCopy.PARKED
            }
            else -> {
                s.done = true
                s.progress = null
                // Every batch landed but the last pull got no answer: the list holds the items only after the next
                // sync, and an import of the same file before then cannot see them and would add them again.
                s.listedLater = plan.items.any { source.item(it.itemId) == null }
            }
        }
        return ActionResult.Ok
    }

    /** A failed import push worth a Retry: no answer, a rate limit or a server error converge on the same items. */
    private fun retryable(why: ItemFailure): Boolean = when (why) {
        is ItemFailure.Unreachable -> true
        is ItemFailure.Refused -> why.code == "rate_limited" || why.status == 429 || why.status >= 500
        else -> false
    }

    /** A file copied out of a web page arrives HTML-escaped: said when more than one value carries an entity. */
    private fun looksMangled(parsed: CsvImport.Parsed): Boolean {
        val entity = Regex("&(amp|lt|gt|quot|#\\d+);")
        var hits = 0
        for (r in parsed.rows) for (v in listOf(r.name, r.url, r.username, r.password, r.notes, r.totp ?: "")) {
            if (entity.containsMatchIn(v) && ++hits >= 2) return true
        }
        return false
    }

    // ---- export ----

    /** The vaults an export can include, in the pinned order (spec 07 §1): personal first, then by name, then id. */
    private fun vaultLines(): List<ExportVault> {
        val counts = source.items().groupingBy { it.vaultId }.eachCount()
        return source.vaults().map { v -> ExportVault(v.vaultId, v.type, v.name, v.role, counts[v.vaultId] ?: 0) }
            .sortedWith(compareBy({ it.type != "personal" }, { it.name.lowercase() }, { it.vaultId }))
    }

    /** Items in export order (spec 07 §1): vault position, then updatedAt, then itemId. */
    private fun orderedItems(order: List<String>): List<VaultItem> {
        val pos = order.withIndex().associate { (i, id) -> id to i }
        return source.items().filter { it.vaultId in pos }.sortedWith(compareBy({ pos[it.vaultId] }, { it.updatedAt }, { it.itemId }))
    }

    fun openExport(kind: ExportKind, offline: Boolean) {
        val s = ExportSession(kind, vaultLines(), source.personalVaultId ?: "")
        if (offline) s.offlineNote = ExportCopy.offline(lastSyncedAt.takeIf { it > 0 }?.let(ContentCopy::day))
        exporting = s
    }

    fun exportView(): ExportView? {
        val s = exporting ?: return null
        val items = orderedItems(s.order())
        return if (s.kind == ExportKind.CSV) {
            val docs = items.map { it.doc }
            val warnings = ExportCsv.warnings(docs)
            // What a tick acknowledges: the cells shown now (re-checked against what is written, [csvFile]).
            s.shownCells = warnings.formulaCells
            exportView(s, warnings, docs.count { it.type == "login" }, items.size, null)
        } else {
            exportView(s, null, 0, items.size, ExportPlanner.planAttachments(items))
        }
    }

    fun setExportVault(vaultId: String, included: Boolean) {
        val s = exporting ?: return
        if (s.busy || vaultId == s.personalId || s.lines.none { it.vaultId == vaultId }) return
        s.included = if (included) s.included + vaultId else s.included - vaultId
        s.error = null
        s.done = null
    }

    fun setExportAttachments(include: Boolean) {
        val s = exporting?.takeIf { it.kind == ExportKind.BACKUP && !it.busy } ?: return
        s.includeAttachments = include
        s.done = null
    }

    fun csvFile(acknowledged: Boolean): ExportFile? {
        val s = exporting?.takeIf { it.kind == ExportKind.CSV && !it.busy } ?: return null
        s.done = null
        val docs = orderedItems(s.order()).map { it.doc }
        val refusal = when {
            docs.none { it.type == "login" } -> ExportCopy.NOTHING_TO_EXPORT
            s.shownCells.isNotEmpty() && !acknowledged -> ExportCopy.FORMULA_ACK_NEEDED
            else -> null
        }
        if (refusal != null) {
            s.error = refusal
            return null
        }
        return when (val gated = ExportCsv.gatedWrite(docs, if (acknowledged) s.shownCells else null)) {
            is ExportCsv.GatedWrite.NeedsAcknowledgement -> {
                s.error = ExportCopy.VAULT_CHANGED
                null
            }
            is ExportCsv.GatedWrite.Ready -> {
                s.error = null
                s.made = ExportMade(gated.loginCount, 0, 0, 0, emptyList())
                ExportFile("andvari-export-${exportDate()}.csv", gated.csv.encodeToByteArray())
            }
        }
    }

    suspend fun backupFile(passphrase: String, confirm: String, published: () -> Unit, stillOpen: () -> Boolean): ExportFile? {
        val s = exporting?.takeIf { it.kind == ExportKind.BACKUP && !it.busy } ?: return null
        s.done = null
        val refusal = when {
            passphrase.isEmpty() -> ExportCopy.PASSPHRASE_REQUIRED
            passphrase != confirm -> ExportCopy.PASSPHRASES_DIFFER
            Strength.estimateStrength(passphrase) < Strength.BACKUP_FLOOR -> ExportCopy.PASSPHRASE_WEAK
            s.order().isEmpty() -> ExportCopy.NOTHING_TO_EXPORT
            else -> null
        }
        if (refusal != null) {
            s.error = refusal
            return null
        }
        s.busy = true
        s.error = null
        published()
        try {
            val made = makeBackup(s, passphrase)
            if (!stillOpen() || exporting !== s) {
                made.second.fill(0)
                return null
            }
            s.made = made.first
            return ExportFile("andvari-backup-${exportDate()}.andvari", made.second)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (exporting === s) s.error = if (e is BackupVerifyException) ExportCopy.VERIFY_FAILED else ContentCopy.SOMETHING_WENT_WRONG
            return null
        } finally {
            s.busy = false
        }
    }

    fun exportSaved(fileName: String, folder: String) {
        val s = exporting ?: return
        val made = s.made ?: return
        s.made = null
        s.error = null
        s.done = when (s.kind) {
            ExportKind.CSV -> ContentCopy.csvSaved(fileName, folder, made.logins)
            ExportKind.BACKUP -> ContentCopy.backupSaved(fileName, folder, made.items, made.vaults, made.files) +
                (if (made.skipped.isEmpty()) "" else " " + ExportCopy.filesSkipped(made.skipped))
        }
    }

    fun exportNotSaved(written: Boolean) {
        val s = exporting ?: return
        s.made = null
        s.error = if (written) ExportCopy.READ_BACK_FAILED else ExportCopy.WRITE_FAILED
    }

    /** spec 07 §2: build in memory, then open again and read every file back; the made file and what it holds. */
    private suspend fun makeBackup(s: ExportSession, passphrase: String): Pair<ExportMade, ByteArray> {
        val order = s.order()
        val lines = s.lines.filter { it.vaultId in order }
        val items = orderedItems(order)
        // §2.4: envelopes with no decrypted twin (a newer formatVersion, a vault not open here) are named, not dropped.
        val undecryptable = source.envelopes().filter { !it.deleted && it.vaultId in order && source.item(it.itemId) == null }
            .map { BackupSkippedItem(it.itemId, it.vaultId, it.formatVersion) }
        val formatVersions = source.envelopes().associate { it.itemId to it.formatVersion }
        val plan = if (s.includeAttachments) ExportPlanner.planAttachments(items) else AttachmentPlan(emptyList(), 0L, emptyList())
        val fetched = ArrayList<Pair<PlannedAttachment, ByteArray>>()
        val fetchFailed = ArrayList<String>()
        try {
            for (p in plan.included) {
                var bytes: ByteArray? = null
                for (attempt in 0 until 2) {
                    bytes = (source.downloadAttachment(p.ref) as? ItemResult.Ok)?.value
                    if (bytes != null) break
                }
                if (bytes == null) fetchFailed.add(AttachmentRules.safeFileName(p.ref.name)) else fetched.add(p to bytes)
            }
            return withContext(Dispatchers.Default) {
                // Each file goes in under a fresh key of its own (spec 07 §2.4); the items keep theirs.
                val freshKeys = fetched.map { crypto.randomBytes(32) }
                val manifest = fetched.mapIndexed { i, (p, bytes) ->
                    BackupAttachmentEntry(section = i + 1, attachmentId = p.ref.id, itemId = p.item.itemId, name = p.ref.name, size = bytes.size.toLong(), fileKey = Bytes.toB64(freshKeys[i]))
                }
                val payload = BackupPayload(
                    exportedAt = host.wallMs(),
                    origin = host.origin(),
                    userId = host.userId(),
                    identityFingerprint = host.accountId(),
                    vaults = lines.map { BackupVault(it.vaultId, it.type, it.name, it.role) },
                    items = items.map { BackupItem(it.itemId, it.vaultId, formatVersions[it.itemId] ?: 1, it.updatedAt, it.doc) },
                    attachments = manifest,
                    skipped = BackupSkipped(undecryptable, plan.overCap, fetchFailed),
                )
                // The policy's KDF cost, within what a backup may ask of the device that opens it (spec 07 §2.2).
                val policy = host.backupKdfParams() ?: KdfParams.DEFAULT
                val kdfParams = if (policy.ops <= Backup.MAX_KDF_OPS && policy.memBytes <= Backup.MAX_KDF_MEM_BYTES) policy else KdfParams.DEFAULT
                val chunks = ArrayList<ByteArray>()
                val sections = fetched.mapIndexed { i, (_, bytes) -> Backup.AttachmentSection(freshKeys[i]) { bytes } }
                Backup.build(
                    crypto = crypto, passphrase = passphrase, fileId = ContentController.freshId(crypto),
                    kdfSalt = crypto.randomBytes(KdfParams.SALT_BYTES), kdfParams = kdfParams, payload = payload, attachments = sections,
                ) { chunks.add(it.copyOf()) }
                val file = ByteArray(chunks.sumOf { it.size })
                var at = 0
                for (c in chunks) {
                    c.copyInto(file, at)
                    at += c.size
                }
                // Opened again under the same passphrase, every file read back (spec 07 §2.6): only a backup that opens leaves.
                val opened = try {
                    Backup.open(crypto, passphrase, file)
                } catch (e: Exception) {
                    file.fill(0)
                    throw BackupVerifyException()
                }
                if (opened.payload != payload) {
                    file.fill(0)
                    throw BackupVerifyException()
                }
                for (entry in opened.payload.attachments) {
                    val plain = opened.readAttachment(entry)
                    val ok = plain.size.toLong() == entry.size
                    plain.fill(0)
                    if (!ok) {
                        file.fill(0)
                        throw BackupVerifyException()
                    }
                }
                ExportMade(0, items.size, lines.size, manifest.size, plan.overCap + fetchFailed) to file
            }
        } finally {
            fetched.forEach { it.second.fill(0) }
        }
    }

    /** Today's date for the file's name, as the other apps name it (yyyy-MM-dd, this device's time zone). */
    private fun exportDate(): String = Instant.fromEpochMilliseconds(host.wallMs()).toLocalDateTime(TimeZone.currentSystemDefault()).date.toString()

    /** A made backup did not open again as made (spec 07 §2.6): nothing is handed over. */
    private class BackupVerifyException : Exception("the backup did not open again as made")
}
