package io.silencelen.andvari.cli

import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.restore.BackupRestore
import io.silencelen.andvari.core.client.restore.RestoreEvent
import io.silencelen.andvari.core.client.restore.RefusedItem
import io.silencelen.andvari.core.client.restore.RestoreHost
import io.silencelen.andvari.core.client.restore.RestoreLeftOut
import io.silencelen.andvari.core.client.restore.RestoreOpening
import io.silencelen.andvari.core.client.restore.RestoreRecords
import io.silencelen.andvari.core.client.restore.RestoreResult
import io.silencelen.andvari.core.client.restore.RestoreStop
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.io.File

/**
 * `andvari-cli restore --backup FILE [--vaults personal|all|<id>,…] [--dry-run]` (spec 07 §3, design §14.1).
 *
 * The restore itself is the shared code's ([BackupRestore]), as every app runs it; this command reads the file and the
 * passphrase, says the preview and what happens, and keeps the restore's record as a file of this device's home
 * (`restore-<file id>-<account>-<digest of the file>.json`, owner-only).
 */
class Restore(private val c: Ctx, private val s: AccountSession) {
    /** `--json`: the preview and progress lines go to standard error, and standard output carries the one document. */
    private val asJson = c.a.has("json")

    /** A preview or progress line: standard output, or standard error under `--json`. */
    private fun line(text: String) = if (asJson) Term.note(text) else c.term.say(text)

    /** The account on this device as the shared restore asks for it; its record as a file of the tool's home. */
    private val host = object : RestoreHost {
        override val crypto get() = s.host.crypto
        override val origin get() = s.origin
        override val userId get() = s.userId
        override val account get() = s.held.session.account
        override val items get() = s.items
        override val logs get() = s.logs
        override val records = RecordFiles(c.home.dir)

        override suspend fun sync() {
            s.sync()
        }

        override fun now(): Long = c.clock()
    }

    /**
     * The restore; its status for the caller: 0 when it ended with nothing the server refused, 1 when it ended with
     * items the server refused (kept, and tried again by the next run). A stop, a file that does not open and a wrong
     * argument are thrown, each with its own status.
     */
    suspend fun run(): Int {
        val path = c.a.opt("backup") ?: throw CliError("--backup FILE is required", 2)
        val source = File(path).takeIf { it.isFile } ?: throw CliError("$path is not a readable file")
        // Asked of the file system before a byte is read: a file over the cap is refused unread.
        if (source.length() > Backup.MAX_FILE_BYTES) throw CliError("the backup does not open: ${Backup.ERR_TOO_LARGE}")
        val bytes = source.readBytes()
        val pass = c.secrets.read("backup-passphrase", "ANDVARI_BACKUP_PASSPHRASE", "Backup passphrase: ")
        val file = try {
            when (val o = BackupRestore.open(s.host.crypto, String(pass), bytes)) {
                is RestoreOpening.Opened -> o.file
                is RestoreOpening.NotOpened -> throw CliError("the backup does not open: ${o.code}")
                RestoreOpening.IdRefused -> throw CliError(FILE_ID_REFUSED)
            }
        } finally {
            pass.fill('\u0000')
        }
        val opened = file.opened
        // A `--vaults` id the file does not hold is a wrong argument: said before the preview, which syncs and may write
        // the record, so that nothing of the restore is sent, written or printed.
        val asked = (c.a.opt("vaults") ?: "personal").split(',').map { it.trim() }.toSet()
        val ids = opened.payload.vaults.mapTo(HashSet()) { it.vaultId }
        val unknown = asked.filter { it != "personal" && it != "all" && it !in ids }
        if (unknown.isNotEmpty()) throw CliError(vaultsNotInFile(unknown), 2)
        val restore = BackupRestore(host)
        val preview = restore.preview(file)
        line("Backup made ${java.time.Instant.ofEpochMilli(preview.exportedAt)} (authenticated) from ${preview.origin.ifEmpty { "an unnamed server" }}")
        // Every line below is read off the shared restore's one description: what is left of each vault, whether it can be
        // chosen, what is known of an earlier restore of it, and the counts.
        for (v in preview.vaults) {
            val earlier = v.restoredAt?.let { "; restored into this account on ${java.time.Instant.ofEpochMilli(it)}" } ?: ""
            line(
                "  ${v.type} vault “${v.name}”: ${count(v.items, "item", "items")}" + (if (v.personal) "" else if (v.owned) "; you owned it" else "; you were a member") +
                    when {
                        v.items == 0 -> "; it holds no item, so nothing is made for it"
                        !v.choosable -> "$earlier; every item of it is in this account already"
                        v.left < v.items || v.restoredAt != null || v.started -> "$earlier; ${v.left} of them are not in this account yet, and only those are restored"
                        else -> ""
                    },
            )
        }
        line("  attachments in the file: ${preview.attachments} (re-encrypted under fresh keys and uploaded before their items)")
        if (preview.attachmentsOverCap.isNotEmpty()) line("  over the 64 MiB total, to re-attach by hand: ${preview.attachmentsOverCap.size}")
        if (preview.undecryptable > 0) line("  items the exporting device could not open: ${preview.undecryptable}")
        line("  not in any backup: server two-step sign-in, item version history and trash")
        // Only the items that did not come from this file's restore on this device: those a restore puts beside.
        if (preview.accountItemsBeside == 1) {
            line("  this account already holds 1 item that no restore of this file on this device stored; a restore adds the backup's items beside it and replaces nothing, so an item in both will be there twice")
        } else if (preview.accountItemsBeside > 0) {
            line("  this account already holds ${preview.accountItemsBeside} items that no restore of this file on this device stored; a restore adds the backup's items beside them and replaces nothing, so an item in both will be there twice")
        }
        // In the desktop's words (decided on 25 November 2026), with "chosen" where the desktop says "ticked".
        if (preview.refused.isNotEmpty()) line("  Refused by the server in an earlier restore: ${names(preview.refused)}. Where their vault can be chosen, the restore tries them again.")
        leftOutLines(preview.leftOut).forEach(::line)

        val p = opened.payload
        val choice = preview.choose(
            preview.vaults.filter { v -> v.personal && ("personal" in asked || "all" in asked) || !v.personal && ("all" in asked || v.vaultId in asked) }.mapTo(HashSet()) { it.vaultId },
        )
        if (preview.vaults.any { !it.personal } && "all" !in asked) line("  shared vaults are skipped unless chosen (--vaults all); restoring one someone else owns would duplicate it")
        if (choice.filesNotInFile > 0) line("  attached files the items to restore name that are not in the file: ${choice.filesNotInFile} (those items are restored without them)")
        line(if (choice.items == 0) "  nothing of the chosen vaults is left to restore into this account" else "  to restore: ${count(choice.items, "item", "items")}")
        // `--json`: the preview, and what was restored (null on a dry run), as one document.
        fun document(restored: JsonObject?) = buildJsonObject {
            put("exportedAt", JsonPrimitive(p.exportedAt))
            put("origin", JsonPrimitive(p.origin))
            put("vaults", JsonArray(preview.vaults.map { v ->
                buildJsonObject {
                    put("vaultId", JsonPrimitive(v.vaultId)); put("name", JsonPrimitive(v.name)); put("type", JsonPrimitive(v.type))
                    put("items", JsonPrimitive(v.items)); put("chosen", JsonPrimitive(v.vaultId in choice.vaults)); put("left", JsonPrimitive(v.left))
                    put("role", JsonPrimitive(v.role)); put("owned", JsonPrimitive(v.owned))
                    put("restoredAt", JsonPrimitive(v.restoredAt)); put("offered", JsonPrimitive(v.offered))
                }
            }))
            put("leftOut", leftOutDocument(preview.leftOut))
            put("attachments", JsonPrimitive(preview.attachments))
            put("attachmentsOverCap", JsonPrimitive(p.skipped.attachmentsOverCap.size))
            put("undecryptable", JsonPrimitive(p.skipped.undecryptable.size))
            put("accountItems", JsonPrimitive(preview.accountItems)); put("accountItemsBeside", JsonPrimitive(preview.accountItemsBeside))
            put("refusedBefore", refusedDocument(preview.refused))
            put("restored", restored ?: JsonNull)
        }
        if (c.a.has("dry-run")) {
            if (asJson) c.term.json(document(null).toString())
            return 0
        }

        val result = restore.restore(file, choice) { e ->
            when (e) {
                RestoreEvent.RoomUnknown -> Term.note("The server gave no usage figures for this account, so the restore starts and the server decides what fits.")
                is RestoreEvent.Waiting -> line(if (e.vaultCreation) "  shared-vault creation is paced: waiting ${e.seconds} s" else "  rate limited: waiting ${e.seconds} s")
                is RestoreEvent.Refused -> line("  not stored: ${count(e.count, "item", "items")} the server refused")
                is RestoreEvent.Progress -> {}
            }
        }
        val done = when (result) {
            is RestoreResult.Done -> result
            is RestoreResult.NoRoom -> {
                // Spec 03 §14.4: nothing was written; which limit and by how much (with `--json`, as a document).
                if (asJson) c.term.json(Quotas.shortDocument(result.limits).toString())
                throw Quotas.shortError(result.limits, "the restore")
            }
            is RestoreResult.Stopped -> throw stopped(result.stop)
            is RestoreResult.Changed -> throw CliError(CHANGED)
        }
        if (done.refused.isNotEmpty()) line("  not stored, kept to try again (run the same command again): ${names(done.refused)}")
        leftOutLines(done.leftOut).forEach(::line)
        // Items the server refused: the run did not do all it was asked, and a script can tell (decided on 23 November 2026).
        val status = if (done.refused.isEmpty()) 0 else 1
        if (asJson) {
            c.term.json(document(buildJsonObject {
                put("items", JsonPrimitive(done.stored)); put("vaults", JsonPrimitive(done.vaults)); put("refused", JsonPrimitive(done.refused.size))
                put("leftOut", leftOutDocument(done.leftOut))
                put("refusedItems", refusedDocument(done.refused))
                put("attachmentsCarried", JsonPrimitive(done.carried)); put("attachmentsStripped", JsonPrimitive(done.stripped))
            }).toString())
            return status
        }
        line(
            if (done.vaults == 0) "nothing of the chosen vaults was left to restore: nothing was sent"
            else "restored ${count(done.stored, "item", "items")} into ${count(done.vaults, "vault", "vaults")}" +
                (if (done.carried > 0) "; ${count(done.carried, "attachment", "attachments")} carried" else "") +
                (if (done.stripped > 0) "; ${count(done.stripped, "attachment", "attachments")} not in the file, stripped (re-attach by hand)" else ""),
        )
        return status
    }

    private fun code(why: ItemFailure) = AccountSession.code(why)

    /** [n] and its noun: [one] for a count of one (decided on 23 November 2026), [more] for none and for more. */
    private fun count(n: Int, one: String, more: String) = "$n ${if (n == 1) one else more}"

    /** Refused items by name, with the server's reason. */
    private fun names(items: List<RefusedItem>) = items.joinToString(", ") { "“${it.name}”" + (it.reason?.let { r -> " ($r)" } ?: "") }

    /** What of the file is left out, one line per kind with its count (drafts awaiting the owner's words). */
    private fun leftOutLines(l: RestoreLeftOut): List<String> = listOfNotNull(
        l.vaultsTwice.takeIf { it > 0 }?.let { "  ⟦Left out, as the file names their id twice: $it vaults⟧" },
        l.itemsTwice.takeIf { it > 0 }?.let { "  ⟦Left out, as the file names their id twice: $it items⟧" },
        l.itemsUnderNoVault.takeIf { it > 0 }?.let { "  ⟦Left out, in no vault the file lists: $it items⟧" },
        l.filesUnderNoItem.takeIf { it > 0 }?.let { "  ⟦Left out, of no item the file lists: $it attached files⟧" },
        l.sectionsUnnamed.takeIf { it > 0 }?.let { "  ⟦Not read, as nothing in the file names them: $it parts of the file⟧" },
    )

    private fun leftOutDocument(l: RestoreLeftOut) = buildJsonObject {
        put("vaultsTwice", JsonPrimitive(l.vaultsTwice)); put("itemsTwice", JsonPrimitive(l.itemsTwice)); put("itemsUnderNoVault", JsonPrimitive(l.itemsUnderNoVault))
        put("filesUnderNoItem", JsonPrimitive(l.filesUnderNoItem)); put("sectionsUnnamed", JsonPrimitive(l.sectionsUnnamed))
    }

    private fun refusedDocument(items: List<RefusedItem>) = JsonArray(items.map {
        buildJsonObject { put("itemId", JsonPrimitive(it.itemId)); put("name", JsonPrimitive(it.name)); put("vaultId", JsonPrimitive(it.vaultId)); put("reason", JsonPrimitive(it.reason)) }
    })

    /** Why the restore stopped, as the tool says it. */
    private fun stopped(stop: RestoreStop): CliError = when (stop) {
        RestoreStop.ItemUnreadable -> CliError("an item in the backup does not read as an item: nothing was written")
        is RestoreStop.RoomCheckFailed -> CliError(
            "the account's space is checked on a fresh sync, which did not complete (${code(stop.why)}): nothing was written. Run the command again",
        )
        RestoreStop.NoPersonalVault -> CliError("this account has no personal vault in force")
        // These two say what is true whether or not anything reached the server (decided on 25 November 2026).
        is RestoreStop.BatchRefused -> CliError("batch ${stop.batch} of “${stop.vaultName}” is not confirmed as stored in the account: ${stop.why?.let(::code) ?: "bad_item"} (run the same command again to resume)")
        is RestoreStop.AttachmentKeyUnopenable -> CliError("the restore plan's key for attachment “${stop.name}” does not open as this account's: nothing uploaded")
        is RestoreStop.AttachmentUnreadable -> CliError("attachment “${stop.name}” in the file does not open: ${stop.code}")
        is RestoreStop.AttachmentWrongSize -> CliError("attachment “${stop.name}” is not the size the file names: nothing uploaded")
        is RestoreStop.AttachmentRefused -> CliError("attachment “${stop.name}” is not confirmed as stored in the account: ${code(stop.why)} (run the same command again to resume)")
        is RestoreStop.OtherVaultAnswered -> CliError("the vault log answered another vault (${stop.answered}) for “${stop.name}”: nothing restored into it")
        is RestoreStop.VaultNotCreated -> CliError("could not recreate “${stop.name}”: ${stop.code}")
        is RestoreStop.VaultNotConfirmed -> CliError("the server did not confirm “${stop.name}” yet: run the same command again to resume (it keeps vault id ${stop.vaultId}, so no second vault is made)")
        is RestoreStop.KeyNotAdopted ->
            if (stop.refusal != null) CliError("the key of “${stop.name}” was not adopted (${stop.refusal}): nothing restored into it; run the same command again to resume")
            else CliError("the key of “${stop.name}” was not adopted (${stop.other}): nothing restored into it")
    }

    private companion object {
        /** What the account holds changed between the preview and the run: nothing was sent. */
        const val CHANGED = "what this account holds changed after the preview was made: nothing was sent; run the command again for what is left now"

        /** A draft awaiting the owner's words: ids given with `--vaults` that are no vault of the file, each as it was given. */
        fun vaultsNotInFile(ids: List<String>) =
            "⟦--vaults names ${ids.joinToString(", ") { "“$it”" }}, which is no vault of this backup: nothing was sent or written⟧"

        /** A draft awaiting the owner's words: the file's id is not the form an andvari app writes. */
        const val FILE_ID_REFUSED = "⟦Restore: this file is refused, as its file id is not the form every andvari app writes; nothing was read or written⟧"
    }
}

/**
 * A restore's records as files of the tool's home, owner-only (`<name>.json`). A name that is not made of lower-case
 * letters, digits and hyphens is refused here, before any path is made of it, whatever the caller checked before.
 */
class RecordFiles(private val dir: File) : RestoreRecords {
    private fun file(name: String): File {
        if (!BackupRestore.safeRecordName(name)) throw CliError("not a restore record's name: nothing was read or written")
        return File(dir, "$name.json")
    }

    override fun read(name: String): String? = file(name).takeIf { it.isFile }?.readText()

    override fun replace(name: String, text: String) = OwnerOnlyFile(file(name)).replace(text)

    override fun remove(name: String) {
        file(name).delete()
    }
}
