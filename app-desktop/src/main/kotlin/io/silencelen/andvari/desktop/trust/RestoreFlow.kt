package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.BackupRestoreApi
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.ExportCopy
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.Shortfall
import io.silencelen.andvari.core.client.restore.RefusedItem
import io.silencelen.andvari.core.client.restore.RestoreEvent
import io.silencelen.andvari.core.client.restore.RestoreFile
import io.silencelen.andvari.core.client.restore.RestoreLeftOut
import io.silencelen.andvari.core.client.restore.RestoreOpening
import io.silencelen.andvari.core.client.restore.RestorePreview
import io.silencelen.andvari.core.client.restore.RestoreResult
import io.silencelen.andvari.core.client.restore.RestoreStop
import io.silencelen.andvari.core.client.restore.RestoreVaultLine
import io.silencelen.andvari.core.model.wire.QuotaName
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * "Restore a backup" (the design approved on 22 November 2026), one picked file at a time, over the vault open as
 * [content]: the passphrase, then what the file holds before anything is written, then the run, then its end. The file
 * is opened on this computer; nothing is sent before [confirm]. The passphrase is typed each time and kept nowhere: the
 * characters handed to [open] are zeroed.
 */
internal class RestoreFlow(private val api: BackupRestoreApi, val content: VaultContent, val fileName: String, private val bytes: ByteArray) {
    enum class Stage { PASSPHRASE, PREVIEW, RUNNING, STOPPED, ENDED }

    /** What the page shows. */
    class View internal constructor(
        val stage: Stage,
        val busy: Boolean = false,
        /** The passphrase step: what opening the file came to. */
        val said: UiText? = null,
        val preview: RestorePreview? = null,
        /** The vaults ticked, by their ids in the file. */
        val chosen: Set<String> = emptySet(),
        /** The last confirm found no room: each limit it would pass. Nothing was written. */
        val noRoom: List<Shortfall>? = null,
        val progress: RestoreEvent.Progress? = null,
        val waiting: RestoreEvent.Waiting? = null,
        val stop: RestoreStop? = null,
        val done: RestoreResult.Done? = null,
        /** The app gave the restore no vault to write to (none open, a locked one, or one that cannot be written here). */
        val noVault: Boolean = false,
        /**
         * The restore's record lives in this process's memory only ([BackupRestoreApi.recordInMemoryOnly]), as last asked:
         * after the preview, at each line of a run, at its end, and whenever the app's state or the switch changed.
         */
        val memoryOnly: Boolean = false,
        /** The run started without the room check: the server gave no figures for the account's room. */
        val roomUnknown: Boolean = false,
        /** The last run ended by a cancellation (its page left the window) or by something thrown out of the restore. */
        val interrupted: Boolean = false,
        /**
         * The last press sent nothing: what the account holds changed after the page was drawn, so the page was made again
         * from what is left now ([RestoreResult.Changed]).
         */
        val changed: Boolean = false,
    ) {
        fun copy(
            stage: Stage = this.stage, busy: Boolean = this.busy, said: UiText? = this.said, preview: RestorePreview? = this.preview,
            chosen: Set<String> = this.chosen, noRoom: List<Shortfall>? = this.noRoom, progress: RestoreEvent.Progress? = this.progress,
            waiting: RestoreEvent.Waiting? = this.waiting, stop: RestoreStop? = this.stop, done: RestoreResult.Done? = this.done,
            noVault: Boolean = this.noVault, memoryOnly: Boolean = this.memoryOnly, roomUnknown: Boolean = this.roomUnknown,
            interrupted: Boolean = this.interrupted, changed: Boolean = this.changed,
        ) = View(stage, busy, said, preview, chosen, noRoom, progress, waiting, stop, done, noVault, memoryOnly, roomUnknown, interrupted, changed)
    }

    private val state = MutableStateFlow(View(Stage.PASSPHRASE))
    val views: StateFlow<View> get() = state

    private var file: RestoreFile? = null

    /** The vaults the last run was asked for: Try again asks for the same. */
    private var lastRun: Set<String> = emptySet()

    /** Open the file under [passphrase] (zeroed), and on success show what it holds; nothing is written. */
    suspend fun open(passphrase: CharArray) {
        if (state.value.busy || state.value.stage != Stage.PASSPHRASE) {
            passphrase.fill(0.toChar())
            return
        }
        state.value = state.value.copy(busy = true, said = null)
        try {
            when (val o = api.open(passphrase, bytes)) {
                is RestoreOpening.Opened -> {
                    val p = api.preview(o.file)
                    if (p == null) {
                        state.value = state.value.copy(noVault = true)
                    } else {
                        file = o.file
                        state.value = View(
                            Stage.PREVIEW, preview = p, chosen = p.vaults.filter { it.personal && it.choosable }.mapTo(HashSet()) { it.vaultId },
                            memoryOnly = api.recordInMemoryOnly() == true,
                        )
                    }
                }
                is RestoreOpening.NotOpened -> state.value = state.value.copy(said = notOpenedLine(o.code))
                RestoreOpening.IdRefused -> state.value = state.value.copy(said = UiText.ph(Placeholder.RESTORE_ID_REFUSED))
            }
        } finally {
            passphrase.fill(0.toChar())
            state.value = state.value.copy(busy = false)
        }
    }

    /** Tick or untick the vault [vaultId]; only a vault the description says can be chosen has a box. */
    fun choose(vaultId: String, on: Boolean) {
        val v = state.value
        if (v.stage != Stage.PREVIEW || v.busy) return
        if (v.preview?.vaults?.any { it.vaultId == vaultId && it.choosable } != true) return
        state.value = v.copy(chosen = if (on) v.chosen + vaultId else v.chosen - vaultId, noRoom = null)
    }

    /**
     * "Restore N items": what the page showed of the vaults ticked ([RestorePreview.choose]), and nothing else; or nothing at
     * all when what is left changed since the page was drawn.
     */
    suspend fun confirm() {
        val v = state.value
        val p = v.preview ?: return
        val choice = p.choose(v.chosen)
        if (v.stage != Stage.PREVIEW || v.busy || choice.items == 0) return
        run(choice.vaults) { f, events -> api.restore(f, choice, events) }
    }

    /** After a stop, or an end with items the server refused: the same restore again, which continues where it was. */
    suspend fun tryAgain() {
        val v = state.value
        if (v.busy || !(v.stage == Stage.STOPPED && !stuck(v.stop) || v.stage == Stage.ENDED && v.done?.refused?.isNotEmpty() == true)) return
        val vaults = lastRun
        run(vaults) { f, events -> api.restoreAgain(f, vaults, events) }
    }

    private suspend fun run(vaults: Set<String>, go: suspend (RestoreFile, (RestoreEvent) -> Unit) -> RestoreResult?) {
        val f = file ?: return
        lastRun = vaults
        val before = state.value
        state.value = before.copy(stage = Stage.RUNNING, busy = true, noRoom = null, progress = null, waiting = null, stop = null, roomUnknown = false, interrupted = false, changed = false)
        var r: RestoreResult? = null
        var returned = false
        try {
            r = go(f) { e ->
                // Each line of the run asks again where the record is: the switch may be turned, or a policy arrive, while
                // it runs.
                state.value = when (e) {
                    is RestoreEvent.Progress -> state.value.copy(progress = e, waiting = null, memoryOnly = memoryOnlyNow())
                    is RestoreEvent.Waiting -> state.value.copy(waiting = e, memoryOnly = memoryOnlyNow())
                    // The refused items are listed by name at the end.
                    is RestoreEvent.Refused -> state.value
                    RestoreEvent.RoomUnknown -> state.value.copy(roomUnknown = true, memoryOnly = memoryOnlyNow())
                }
            }
            returned = true
        } finally {
            // The one place that sets the stage for every way out of a run, so that the page never says it is running
            // when nothing runs: its own result; or a cancellation (its page left the window) or anything thrown out of the
            // restore (a lock or a sign-out closing the vault's store under it), which leave it stopped with Try again
            // and are thrown on after this.
            val now = state.value.copy(busy = false, waiting = null)
            val res = r
            state.value = when {
                !returned -> now.copy(stage = Stage.STOPPED, interrupted = true, memoryOnly = runCatching { memoryOnlyNow() }.getOrDefault(now.memoryOnly))
                res == null -> now.copy(stage = Stage.STOPPED, noVault = true)
                res is RestoreResult.Done -> now.copy(stage = Stage.ENDED, done = res)
                res is RestoreResult.NoRoom -> before.copy(stage = Stage.PREVIEW, busy = false, noRoom = res.limits, memoryOnly = memoryOnlyNow())
                // Asked again: the switch may have been turned, or a policy arrived, while it ran.
                res is RestoreResult.Stopped -> now.copy(stage = Stage.STOPPED, stop = res.stop, memoryOnly = memoryOnlyNow())
                // Nothing was sent: the page is made again from the description now, the ticks kept where their vault can
                // still be chosen, with the line that says so.
                res is RestoreResult.Changed -> View(
                    Stage.PREVIEW, preview = res.preview, chosen = before.chosen.filterTo(HashSet()) { id -> res.preview.vaults.any { it.vaultId == id && it.choosable } },
                    memoryOnly = memoryOnlyNow(), changed = true,
                )
                else -> now.copy(stage = Stage.STOPPED, interrupted = true)
            }
        }
    }

    /** Where the record is now ([BackupRestoreApi.recordInMemoryOnly]); as last asked while no vault is open. */
    private fun memoryOnlyNow(): Boolean = api.recordInMemoryOnly() ?: state.value.memoryOnly

    /**
     * Asked again while the restore's screens are shown, whenever the app's state or the switch changed: the line is
     * drawn while it is true and goes once it is not, on the preview and at a stop as well as in the run.
     */
    fun recheck() {
        if (state.value.stage == Stage.PASSPHRASE || state.value.stage == Stage.ENDED) return
        val now = memoryOnlyNow()
        state.update { if (it.memoryOnly == now) it else it.copy(memoryOnly = now) }
    }

    /**
     * The page as drawn now, made from [v] (the description the shared restore gave, and what the person did): every
     * string finished, each vault's box and the button with whether they can be pressed, and the calls for a press.
     * The screen draws it and decides nothing.
     */
    fun page(v: View = state.value): RestorePageView = RestorePageView(UiText.ph(Placeholder.RESTORE_ENTRY), !v.busy, buildList {
        add(RestoreRow.Line(UiText.Plain(safe(fileName)), RestoreRow.Tone.SMALL))
        if (v.noVault) {
            add(RestoreRow.Line(UiText.ph(Placeholder.RESTORE_NO_VAULT), RestoreRow.Tone.ERROR))
            return@buildList
        }
        fun memory() = memoryOnlyLine(v)?.let { add(RestoreRow.Line(it)) }
        fun againButton() = add(RestoreRow.Button(UiText.ph(Placeholder.TRY_AGAIN), !v.busy, v.busy) { this@RestoreFlow.tryAgain() })
        when (v.stage) {
            Stage.PASSPHRASE -> {
                add(RestoreRow.Line(UiText.ph(Placeholder.RESTORE_PASSPHRASE_NOT_MASTER)))
                add(RestoreRow.Passphrase(UiText.ph(Placeholder.EXPORT_PASSPHRASE), v.said, if (v.busy) UiText.ph(Placeholder.WORKING) else null, UiText.ph(Placeholder.RESTORE_OPEN), v.busy) { open(it) })
            }
            Stage.PREVIEW -> {
                val p = v.preview ?: return@buildList
                add(RestoreRow.Line(madeLine(p)))
                if (v.changed) add(RestoreRow.Line(UiText.ph(Placeholder.RESTORE_CHANGED), RestoreRow.Tone.ERROR))
                for (vault in p.vaults) {
                    val line = vaultLine(vault)
                    val id = vault.vaultId
                    add(if (vault.choosable) RestoreRow.Box(line, id in v.chosen, !v.busy) { on -> choose(id, on) } else RestoreRow.Line(line))
                }
                previewLines(p, v.chosen).forEach { add(RestoreRow.Line(it)) }
                v.noRoom?.let { limits -> noRoomLines(limits).forEach { add(RestoreRow.Line(it, RestoreRow.Tone.ERROR)) } }
                memory()
                val n = p.choose(v.chosen).items
                if (p.nothingLeft) add(RestoreRow.Line(UiText.ph(Placeholder.RESTORE_NOTHING_LEFT)))
                else add(RestoreRow.Button(confirmLine(n), n > 0 && !v.busy, v.busy) { confirm() })
            }
            Stage.RUNNING -> {
                val lines = runLines(v)
                if (lines.isEmpty()) add(RestoreRow.Line(UiText.ph(Placeholder.WORKING)))
                lines.forEach { add(RestoreRow.Line(it)) }
                memory()
            }
            Stage.STOPPED -> {
                runLines(v).forEach { add(RestoreRow.Line(it)) }
                val stop = v.stop
                // A part of the file that cannot be read: its own line, and no Try again, which would stop at the same place.
                if (stop is RestoreStop.AttachmentUnreadable) add(RestoreRow.Line(UiText.ph(Placeholder.RESTORE_PART_UNREADABLE, safe(stop.name)), RestoreRow.Tone.ERROR))
                // A stop the same file reaches every time: said so, and no Try again, which would stop at the same place.
                else if (stop != null && samePlace(stop)) add(RestoreRow.Line(UiText.ph(Placeholder.RESTORE_STOPPED_SAME_PLACE, stopReason(stop)), RestoreRow.Tone.ERROR))
                else if (stop != null) add(RestoreRow.Line(UiText.ph(Placeholder.RESTORE_STOPPED, stopReason(stop)), RestoreRow.Tone.ERROR))
                if (v.interrupted) add(RestoreRow.Line(UiText.ph(Placeholder.RESTORE_INTERRUPTED), RestoreRow.Tone.ERROR))
                memory()
                if (!stuck(stop)) againButton()
            }
            Stage.ENDED -> {
                val d = v.done ?: return@buildList
                endLines(d).forEach { add(RestoreRow.Line(it)) }
                if (d.refused.isNotEmpty()) againButton()
            }
        }
    })

    internal companion object {
        /** A stop no Try again can get past: a part of the file that cannot be read, or any other stop [samePlace]. */
        fun stuck(s: RestoreStop?): Boolean = s is RestoreStop.AttachmentUnreadable || s != null && samePlace(s)

        /**
         * A stop that every later run with the same file into the same account reaches, whatever the server answers: it
         * rests on the file alone. An item that does not read as an item (the room check reads every item still to store
         * before anything is sent; an item of a batch is read again before the batch goes), and an attached file whose part
         * is not the size its entry names (its bytes are the file's). Not a key kept in this computer's record that does
         * not open: a sign-out or "Forget this server" removes the record, and a run after that mints a new key.
         */
        fun samePlace(s: RestoreStop): Boolean = s == RestoreStop.ItemUnreadable || s is RestoreStop.AttachmentWrongSize ||
            s is RestoreStop.BatchRefused && s.why == null

        /** The restore button for [n] items: the design's sentence, and its singular for a single item. */
        fun confirmLine(n: Int): UiText = if (n == 1) UiText.ph(Placeholder.RESTORE_CONFIRM_ONE, "1") else UiText.ph(Placeholder.RESTORE_CONFIRM, n.toString())

        /** What a file that did not open says: a file over the size limit and a file cut short each have a line of their own. */
        fun notOpenedLine(code: String): UiText = when (code) {
            Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT -> UiText.ph(Placeholder.RESTORE_WRONG_PASSPHRASE)
            Backup.ERR_UNKNOWN_FORMAT -> UiText.ph(Placeholder.RESTORE_NOT_A_BACKUP)
            Backup.ERR_TOO_LARGE -> UiText.ph(Placeholder.RESTORE_TOO_LARGE)
            Backup.ERR_TRUNCATED -> UiText.ph(Placeholder.RESTORE_CUT_SHORT)
            else -> UiText.ph(Placeholder.RESTORE_NOT_OPENED, safe(code))
        }

        /** A name the file brings, made safe to show (control characters, direction marks and escapes made visible). */
        private fun safe(name: String) = ExportCopy.safeName(name)

        /** "12 November 2026", as the design writes a day. */
        fun dayText(ms: Long, zone: ZoneId = ZoneId.systemDefault()): String =
            DateTimeFormatter.ofPattern("d MMMM yyyy", Locale.ENGLISH).format(Instant.ofEpochMilli(ms).atZone(zone))

        /** The server the file names, as a host ("vault.example.org"); its whole text when it is no address. */
        private fun serverText(origin: String): String = safe(runCatching { java.net.URI(origin).host }.getOrNull()?.takeIf { it.isNotEmpty() } ?: origin)

        /** The first line of a preview: when and where the file says it was made. */
        fun madeLine(p: RestorePreview, zone: ZoneId = ZoneId.systemDefault()): UiText =
            if (p.origin.isBlank()) UiText.ph(Placeholder.RESTORE_MADE_UNNAMED, dayText(p.exportedAt, zone))
            else UiText.ph(Placeholder.RESTORE_MADE, dayText(p.exportedAt, zone), serverText(p.origin))

        /**
         * A vault's line: offered with a tick, with how many of its items are left where that is less than the whole
         * vault (or where it was restored before and items the server refused are left), or said as restored into this
         * account already, with the day this computer saw it finished; a shared vault whose restore started here and
         * stored nothing says so (decided on 23 November 2026). Each of those longer lines begins with the vault's whole
         * line as the preview reads it.
         */
        fun vaultLine(v: RestoreVaultLine, zone: ZoneId = ZoneId.systemDefault()): UiText {
            val at = v.restoredAt
            val one = v.items == 1
            val whole = when {
                v.personal -> UiText.ph(if (one) Placeholder.RESTORE_PERSONAL_ONE else Placeholder.RESTORE_PERSONAL, v.items.toString())
                v.owned -> UiText.ph(if (one) Placeholder.RESTORE_SHARED_OWNED_ONE else Placeholder.RESTORE_SHARED_OWNED, safe(v.name), v.items.toString())
                else -> UiText.ph(if (one) Placeholder.RESTORE_SHARED_MEMBER_ONE else Placeholder.RESTORE_SHARED_MEMBER, safe(v.name), v.items.toString())
            }
            val joined = sentence(whole)
            return when {
                at != null && v.left == 0 -> UiText.ph(Placeholder.RESTORE_RESTORED_AT, joined, dayText(at, zone))
                // Every item is in the account and nothing ended the vault: a record that cannot be ended by a look (its
                // older shape keeps no started vaults) stopped between the vault's last acknowledged batch and its end, or
                // an item the server refused is in the account all the same (a batch sent again whose answer was lost).
                v.left == 0 && v.items > 0 -> UiText.ph(Placeholder.RESTORE_VAULT_IN_ACCOUNT, joined)
                v.left > 0 && (v.left < v.items || at != null) -> UiText.ph(Placeholder.RESTORE_VAULT_LEFT, joined, v.left.toString())
                // Not ticked: the person chose it once, and chooses it again.
                !v.personal && v.started && v.left == v.items -> UiText.ph(Placeholder.RESTORE_VAULT_STARTED, joined)
                else -> whole
            }
        }

        /**
         * A vault's whole line where a longer line goes on after it with a sentence of its own: with a full stop at its end
         * where it has none (the personal vault's line has none; a shared vault's has one).
         */
        private fun sentence(line: UiText): String = line.shown().let { if (it.endsWith(".")) it else "$it." }

        /** The preview's lines under the vaults, in the design's order, then the restore's own; [chosen] the vaults ticked. */
        fun previewLines(p: RestorePreview, chosen: Set<String>): List<UiText> = buildList {
            if (p.attachments > 0) add(UiText.ph(Placeholder.RESTORE_FILES, p.attachments.toString(), sizeText(p.attachmentBytes)))
            // Before anything is sent: items of the ticked vaults that will come back without files they name.
            val notInFile = p.choose(chosen).filesNotInFile
            if (notInFile > 0) add(UiText.ph(Placeholder.RESTORE_FILES_NOT_IN_BACKUP, notInFile.toString()))
            if (p.attachmentsOverCap.isNotEmpty()) add(counted(p.attachmentsOverCap.size, Placeholder.RESTORE_OVER_CAP_ONE, Placeholder.RESTORE_OVER_CAP))
            if (p.attachmentFetchFailed.isNotEmpty()) add(UiText.ph(Placeholder.RESTORE_FETCH_FAILED, p.attachmentFetchFailed.size.toString()))
            if (p.undecryptable > 0) add(counted(p.undecryptable, Placeholder.RESTORE_UNREADABLE_ONE, Placeholder.RESTORE_UNREADABLE))
            add(UiText.ph(Placeholder.RESTORE_NOT_IN_BACKUP))
            // Only the items that did not come from this file's restore on this computer: those the restore puts beside.
            // Not said when nothing can be restored (decided on 23 November 2026): nothing is put beside them.
            if (p.accountItemsBeside > 0 && !p.nothingLeft) add(counted(p.accountItemsBeside, Placeholder.RESTORE_ACCOUNT_HOLDS_ONE, Placeholder.RESTORE_ACCOUNT_HOLDS))
            if (p.refused.isNotEmpty()) add(UiText.ph(Placeholder.RESTORE_REFUSED_BEFORE, names(p.refused)))
            addAll(leftOutLines(p.leftOut))
            add(UiText.ph(Placeholder.RESTORE_ONE_COMPUTER))
        }

        /** A line with one count [n]: its words for one where [n] is 1 (decided on 23 November 2026), [many] otherwise. */
        private fun counted(n: Int, one: Placeholder, many: Placeholder): UiText = UiText.ph(if (n == 1) one else many, n.toString())

        /** What of the file a restore leaves out, one line per kind with its count (the tool's drafts). */
        fun leftOutLines(l: RestoreLeftOut): List<UiText> = listOfNotNull(
            l.vaultsTwice.takeIf { it > 0 }?.let { UiText.ph(Placeholder.RESTORE_LEFT_OUT_VAULTS_TWICE, it.toString()) },
            l.itemsTwice.takeIf { it > 0 }?.let { UiText.ph(Placeholder.RESTORE_LEFT_OUT_ITEMS_TWICE, it.toString()) },
            l.itemsUnderNoVault.takeIf { it > 0 }?.let { UiText.ph(Placeholder.RESTORE_LEFT_OUT_ITEMS_NO_VAULT, it.toString()) },
            l.filesUnderNoItem.takeIf { it > 0 }?.let { UiText.ph(Placeholder.RESTORE_LEFT_OUT_FILES_NO_ITEM, it.toString()) },
            l.sectionsUnnamed.takeIf { it > 0 }?.let { UiText.ph(Placeholder.RESTORE_LEFT_OUT_SECTIONS, it.toString()) },
        )

        /** Items by name, as the file gives them, made safe to show. */
        fun names(items: List<RefusedItem>): String = items.joinToString(", ") { "“${safe(it.name)}”" }

        /** No room: the design's line, then each limit with by how much, in core's own words for it. */
        fun noRoomLines(limits: List<Shortfall>): List<UiText> = listOf(UiText.ph(Placeholder.RESTORE_NO_ROOM)) + limits.map { s ->
            val size = io.silencelen.andvari.core.app.AttachmentRules::size
            when (s.quota) {
                QuotaName.ITEMS -> if (s.by == 1L) UiText.filled(CopyKey.SPACE_SHORT_ITEMS_ONE_OVER, s.limit.toString()) else UiText.filled(CopyKey.SPACE_SHORT_ITEMS, s.limit.toString(), s.by.toString())
                QuotaName.OWNED_SHARED_VAULTS -> if (s.limit == 1L) UiText.of(CopyKey.SPACE_SHORT_VAULTS_ONE) else UiText.filled(CopyKey.SPACE_SHORT_VAULTS, s.limit.toString())
                else -> UiText.filled(CopyKey.SPACE_SHORT_BYTES, size(s.limit), size(s.by))
            }
        }

        /**
         * Above the button of the preview, under the run's lines while it runs, and again at a stop, while the record lives
         * in memory only: closing the app loses what makes a stopped restore continue.
         */
        fun memoryOnlyLine(v: View): UiText? = if (v.memoryOnly) UiText.ph(Placeholder.RESTORE_MEMORY_ONLY) else null

        /** The run: that it started without the room check, how far, and a wait the server asked for. */
        fun runLines(v: View): List<UiText> = listOfNotNull(
            if (v.roomUnknown) UiText.ph(Placeholder.RESTORE_ROOM_UNKNOWN) else null,
            // Of one item, in the singular, however many are done; of more, the design's line.
            v.progress?.let { UiText.ph(if (it.total == 1) Placeholder.RESTORE_PROGRESS_ONE else Placeholder.RESTORE_PROGRESS, it.done.toString(), it.total.toString()) },
            v.waiting?.let { w -> UiText.ph(if (w.vaultCreation) Placeholder.RESTORE_WAITING_VAULTS else Placeholder.RESTORE_WAITING, waitText(w.seconds.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()).shown()) },
        )

        /** The end: what was stored, what the server refused by name, what was left out. */
        fun endLines(d: RestoreResult.Done): List<UiText> = buildList {
            add(doneLine(d.stored, d.vaults))
            if (d.carried > 0) add(counted(d.carried, Placeholder.RESTORE_DONE_FILES_ONE, Placeholder.RESTORE_DONE_FILES))
            if (d.stripped > 0) add(UiText.ph(Placeholder.RESTORE_DONE_STRIPPED, d.stripped.toString()))
            if (d.refused.isNotEmpty()) add(UiText.ph(Placeholder.RESTORE_REFUSED, names(d.refused)))
            addAll(leftOutLines(d.leftOut))
        }

        /**
         * The end's first line: the design's sentence for the numbers the design shows, a line of its own for a run that
         * found nothing of the chosen vaults left (no vault, nothing sent), the singular for a single item in one vault,
         * and a line of its own for more than one vault.
         */
        fun doneLine(stored: Int, vaults: Int): UiText = when {
            vaults == 0 -> UiText.ph(Placeholder.RESTORE_DONE_NOTHING_LEFT)
            vaults != 1 -> UiText.ph(Placeholder.RESTORE_DONE_VAULTS, stored.toString(), vaults.toString())
            stored == 1 -> UiText.ph(Placeholder.RESTORE_DONE_ONE, stored.toString(), vaults.toString())
            else -> UiText.ph(Placeholder.RESTORE_DONE, stored.toString(), vaults.toString())
        }

        /**
         * Why the restore stopped, as the line of a stop says it: a phrase for each kind of stop, with the name it carries
         * made safe; then, where the stop carries a failure or a code, a colon and what was seen, so that a server that did
         * not answer is told from one that refused, and a refusal can be named to whoever runs the server: the server's
         * code, made safe; that no answer came; or the kind of failure. A code the server or the file chose goes through
         * the cleaner, as every name does.
         */
        fun stopReason(s: RestoreStop): String {
            fun seen(f: ItemFailure): String = when (f) {
                is ItemFailure.Refused -> safe(f.code)
                is ItemFailure.Unreachable -> UiText.ph(Placeholder.RESTORE_SEEN_NO_ANSWER).shown()
                else -> f::class.simpleName ?: "refused"
            }
            fun phrase(p: Placeholder, vararg name: String, seen: String? = null): String =
                UiText.ph(p, *name).shown() + (seen?.let { ": $it" } ?: "")
            return when (s) {
                RestoreStop.ItemUnreadable -> phrase(Placeholder.RESTORE_STOP_ITEM_UNREADABLE)
                is RestoreStop.RoomCheckFailed -> phrase(Placeholder.RESTORE_STOP_ROOM_CHECK, seen = seen(s.why))
                RestoreStop.NoPersonalVault -> phrase(Placeholder.RESTORE_STOP_NO_PERSONAL_VAULT)
                // With no failure, an item of the batch does not read as an item.
                is RestoreStop.BatchRefused -> s.why?.let { phrase(Placeholder.RESTORE_STOP_BATCH, seen = seen(it)) } ?: phrase(Placeholder.RESTORE_STOP_ITEM_UNREADABLE)
                is RestoreStop.AttachmentKeyUnopenable -> phrase(Placeholder.RESTORE_STOP_FILE_KEY, safe(s.name))
                // Drawn by its own line (RESTORE_PART_UNREADABLE); said here only for completeness.
                is RestoreStop.AttachmentUnreadable -> safe(s.code) + ": " + safe(s.name)
                is RestoreStop.AttachmentWrongSize -> phrase(Placeholder.RESTORE_STOP_FILE_SIZE, safe(s.name))
                is RestoreStop.AttachmentRefused -> phrase(Placeholder.RESTORE_STOP_FILE_REFUSED, safe(s.name), seen = seen(s.why))
                is RestoreStop.OtherVaultAnswered -> phrase(Placeholder.RESTORE_STOP_OTHER_VAULT, safe(s.name))
                is RestoreStop.VaultNotCreated -> phrase(Placeholder.RESTORE_STOP_VAULT_NOT_MADE, safe(s.name), seen = safe(s.code))
                is RestoreStop.VaultNotConfirmed -> phrase(Placeholder.RESTORE_STOP_VAULT_NOT_CONFIRMED, safe(s.name))
                is RestoreStop.KeyNotAdopted -> phrase(Placeholder.RESTORE_STOP_KEY_NOT_ADOPTED, safe(s.name), seen = s.refusal?.let(::safe))
            }
        }
    }
}

/** The restore's page as [RestoreFlow.page] made it: its title, whether its way back can be taken, and its rows. */
internal class RestorePageView(val title: UiText, val backEnabled: Boolean, val rows: List<RestoreRow>) {
    /** Every string of the page, in its order (a box's and a button's included). */
    val texts: List<String>
        get() = listOf(title.shown()) + rows.flatMap { r ->
            when (r) {
                is RestoreRow.Line -> listOf(r.text.shown())
                is RestoreRow.Box -> listOf(r.text.shown())
                is RestoreRow.Button -> listOf(r.text.shown())
                is RestoreRow.Passphrase -> listOfNotNull(r.label.shown(), r.said?.shown(), r.working?.shown(), r.button.shown())
            }
        }
}

/** One row of the restore's page: finished strings, and the calls for a press. Nothing in it is decided by the screen. */
internal sealed class RestoreRow {
    enum class Tone { PLAIN, SMALL, ERROR }

    class Line(val text: UiText, val tone: Tone = Tone.PLAIN) : RestoreRow()

    /** A vault that can be chosen: its line in a tick box, ticked or not, and what a tick does. */
    class Box(val text: UiText, val ticked: Boolean, val enabled: Boolean, val onTick: (Boolean) -> Unit) : RestoreRow()

    class Button(val text: UiText, val enabled: Boolean, val busy: Boolean, val onPress: suspend () -> Unit) : RestoreRow()

    /**
     * The passphrase's field, what opening the file came to ([said]), [working] while it opens, and the button that opens
     * it with the characters typed (which [onOpen] zeroes); the button can be pressed once something is typed.
     */
    class Passphrase(val label: UiText, val said: UiText?, val working: UiText?, val button: UiText, val busy: Boolean, val onOpen: suspend (CharArray) -> Unit) : RestoreRow()
}
