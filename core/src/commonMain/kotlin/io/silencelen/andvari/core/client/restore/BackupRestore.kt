package io.silencelen.andvari.core.client.restore

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupException
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.ItemDocShape
import io.silencelen.andvari.core.client.items.CopySize
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.QuotaRoom
import io.silencelen.andvari.core.client.items.Shortfall
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogEngine
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.model.wire.QuotaName
import kotlinx.coroutines.delay
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

/**
 * Where a restore keeps its record on this device: one text per name, replaced whole so that a crash leaves the old
 * copy or the new one. The host decides where (the tool: a file of its own home, owner-only).
 */
interface RestoreRecords {
    /** The record [name], or null when there is none. */
    fun read(name: String): String?

    fun replace(name: String, text: String)

    fun remove(name: String)
}

/**
 * What a restore needs of the signed-in account on this device. Every item is sealed by [items] ([ItemEngine.importAll]),
 * every vault is made by [logs] ([VaultLogEngine.append]), and nothing speaks to the server but those two.
 */
interface RestoreHost {
    val crypto: CryptoProvider
    val origin: String
    val userId: String
    /** The account: its personal vault, and the seal of its local records. */
    val account: OpenedAccount
    val items: ItemEngine
    val logs: VaultLogEngine
    val records: RestoreRecords

    /** One sync as the host runs it (the tool reads the account state first); its outcome is the engines' to keep. */
    suspend fun sync()

    /** The time now, unix ms: when a vault of the file was restored. */
    fun now(): Long
}

/**
 * A backup file opened for a restore ([BackupRestore.open]): its id is a lower-case UUID, and [digest] is the first 32
 * hex digits of the SHA-256 of the whole file as read, which its record's name carries.
 */
class RestoreFile internal constructor(val opened: Backup.OpenedBackup, val digest: String)

/** What opening a file for a restore came to. */
sealed class RestoreOpening {
    class Opened(val file: RestoreFile) : RestoreOpening()

    /**
     * The container did not open: [code] is the [BackupException]'s. Or it opened and its attached files are arranged
     * as no andvari writer arranges them, so the whole file is refused before anything is shown or written:
     * `truncated` when an entry names a part the file does not hold (a file cut short at the edge of a part),
     * `bad_payload` for the other arrangements ([BackupRestore.open]).
     */
    class NotOpened(val code: String) : RestoreOpening()

    /**
     * The file's id is not a UUID in lower case, the only form an andvari app writes (`Bytes.uuidV4FromBytes`, the
     * browser's `crypto.randomUUID`): refused before any record is read or written.
     */
    data object IdRefused : RestoreOpening()
}

/** One vault of the file in a preview. */
class RestoreVaultLine(
    /** The vault's id in the file (never sent: a restore makes new ids). */
    val vaultId: String,
    val name: String,
    /** The vault's type as the file writes it (`personal` or `shared`). */
    val type: String,
    val personal: Boolean,
    /** The person's role in that vault as the file writes it; [owned] when it says `owner`, a member otherwise. */
    val role: String,
    val owned: Boolean,
    /** The items the file holds for this vault. */
    val items: Int,
    /**
     * When the restore of this vault into this account ended (unix ms), from this device's record; null when it did not.
     * A run that ends with items of the vault refused writes its end too; a later run that stores the vault's last refused
     * item moves the end to the time it stored it.
     */
    val restoredAt: Long?,
    /**
     * The items of this vault a restore of it would still store: none restored yet, every item; after an earlier restore
     * of the file into this account, those it did not store (a batch not acknowledged, an item the server refused) and
     * that the account does not hold after the preview's sync. What a run of this vault stores, less what the server
     * refuses in that run.
     */
    val left: Int = items,
    /**
     * The attached files that the [left] items name and the file does not carry (a backup made without its attached
     * files, or one too large for it or not fetched): those items are restored without them.
     */
    val leftFilesNotInFile: Int = 0,
    /**
     * A run of this restore was asked for this vault on this device and its restore has not ended ([restoredAt] null):
     * what this device's record shows of an earlier restore of it besides its end.
     */
    val started: Boolean = false,
) {
    /**
     * Whether the vault can be chosen for a run: exactly when something of it is left to store ([left] above 0). A vault
     * whose items are all in the account cannot, whatever its record says; one with items the server refused can, as
     * those are left; a vault of the file that holds no item never can, and no run makes anything for it.
     */
    val choosable: Boolean get() = left > 0

    /** As [choosable] (decided on 23 November 2026; before, a vault not restored into this account yet). */
    val offered: Boolean get() = choosable
}

/**
 * What a person chose on a preview ([RestorePreview.choose]): the vaults ticked that can be chosen, each with what is
 * left of it as that preview said. A run of it ([BackupRestore.restore]) stores those items, or nothing when what is left
 * of one of them is no longer what the preview said ([RestoreResult.Changed]).
 */
class RestoreChoice internal constructor(
    /** Each vault chosen (its id in the file) and what is left of it, in the file's order. */
    val left: Map<String, Int>,
    /** The attached files that those items name and the file does not carry: they are restored without them. */
    val filesNotInFile: Int,
) {
    val vaults: Set<String> get() = left.keys

    /** The items a run of this choice stores, less what the server refuses in it: what a restore button names. */
    val items: Int get() = left.values.sum()
}

/**
 * What of a file the restore leaves out, by kind, each a count: said before the person confirms and at the end, never
 * counted as stored. No honest andvari writer makes any of these; a file that holds them was made otherwise.
 */
data class RestoreLeftOut(
    /** A vault under an id the file already used (the first is restored). */
    val vaultsTwice: Int = 0,
    /** An item under an id the file already used (the first is restored). */
    val itemsTwice: Int = 0,
    /** An item under a vault the file does not list. */
    val itemsUnderNoVault: Int = 0,
    /** An attached file's entry under an item the file does not list. */
    val filesUnderNoItem: Int = 0,
    /** A section of the file no entry names: never read. */
    val sectionsUnnamed: Int = 0,
) {
    val none: Boolean get() = this == RestoreLeftOut()
}

/** An item of the file the server refused: its id in the file, its name as the file gives it, its vault, the reason. */
data class RefusedItem(val itemId: String, val name: String, val vaultId: String, val reason: String?)

/** What a file holds and what of it this account already has, before anything is written. */
class RestorePreview(
    /** The file's own time of making (authenticated by the passphrase only: whoever made the file chose it). */
    val exportedAt: Long,
    /** The server the file says it was made from (advisory). */
    val origin: String,
    val vaults: List<RestoreVaultLine>,
    /**
     * The attached files the file carries, and their sizes as it states them: one per item and attached file, as each
     * item gets an upload of its own (the room check counts them so too).
     */
    val attachments: Int,
    val attachmentBytes: Long,
    val attachmentsOverCap: List<String>,
    val attachmentFetchFailed: List<String>,
    val undecryptable: Int,
    /** The items this account already holds (every item this device can open, after a fresh sync). */
    val accountItems: Int,
    /** The items of this file the server refused in an earlier restore into this account: tried again by the next one. */
    val refused: List<RefusedItem>,
    /** What of the file a restore leaves out. */
    val leftOut: RestoreLeftOut,
    /**
     * Of [accountItems], those that did not come from a restore of this file into this account on this device (by this
     * device's record): the items a restore puts beside.
     */
    val accountItemsBeside: Int = accountItems,
) {
    /** The vaults of [ticked] that can be chosen ([RestoreVaultLine.choosable]), with what is left of each: no other. */
    fun choose(ticked: Set<String>): RestoreChoice {
        val chosen = vaults.filter { it.vaultId in ticked && it.choosable }
        return RestoreChoice(chosen.associateTo(LinkedHashMap()) { it.vaultId to it.left }, chosen.sumOf { it.leftFilesNotInFile })
    }

    /** True when no vault of the file can be chosen: everything of it is in this account, or nothing of it is left. */
    val nothingLeft: Boolean get() = vaults.none { it.choosable }
}

/** What happens while a restore runs. */
sealed class RestoreEvent {
    /** The server gave no usage figures: the restore starts and the server decides what fits. */
    data object RoomUnknown : RestoreEvent()

    /** A wait of [seconds] the server asked for; [vaultCreation] when it paces the making of shared vaults. */
    data class Waiting(val seconds: Long, val vaultCreation: Boolean) : RestoreEvent()

    /** The server refused [count] items of the batch just sent; they are kept by name and tried again. */
    data class Refused(val count: Int) : RestoreEvent()

    /**
     * [done] of the [total] items this run is to store were answered: the items of the chosen vaults the account did not
     * hold when the run began (a batch sent again only so that the record holds it counts for nothing).
     */
    data class Progress(val done: Int, val total: Int) : RestoreEvent()
}

/** Why a restore stopped. Nothing it wrote is undone; the same restore chosen again continues. */
sealed class RestoreStop {
    /** An item of the file does not read as an item: nothing was written. */
    data object ItemUnreadable : RestoreStop()

    /** The fresh sync the room check needs did not complete: nothing was written. */
    data class RoomCheckFailed(val why: ItemFailure) : RestoreStop()

    data object NoPersonalVault : RestoreStop()

    /** Batch [batch] (from 1) of [vaultName] was refused as a whole; [why] null when one of its items does not read. */
    data class BatchRefused(val batch: Int, val vaultName: String, val why: ItemFailure?) : RestoreStop()

    data class AttachmentKeyUnopenable(val name: String) : RestoreStop()

    data class AttachmentUnreadable(val name: String, val code: String) : RestoreStop()

    data class AttachmentWrongSize(val name: String) : RestoreStop()

    data class AttachmentRefused(val name: String, val why: ItemFailure) : RestoreStop()

    data class OtherVaultAnswered(val name: String, val answered: String) : RestoreStop()

    /** [code] the server's refusal, or the outcome as text. */
    data class VaultNotCreated(val name: String, val code: String) : RestoreStop()

    data class VaultNotConfirmed(val name: String, val vaultId: String) : RestoreStop()

    /** [refusal] the adoption's refusal code; [other] the adoption's answer as text when it was not a refusal. */
    data class KeyNotAdopted(val name: String, val refusal: String?, val other: String?) : RestoreStop()
}

/** What a restore came to. */
sealed class RestoreResult {
    class Done(
        /** The items this run stored that the account did not hold when it began. */
        val stored: Int,
        /** The vaults the run was for: those chosen that could be chosen when it began. */
        val vaults: Int,
        /** The items the server refused in this run, by name, kept for the next. */
        val refused: List<RefusedItem>,
        /**
         * The attached files restored: those of exactly the items this run stored ([stored]), each file of such an item
         * once however often the item's document names it. Made from what the server answered, where [stored] is: the file
         * of an item the server refused is not in it, nor that of an item sent again only so that the record holds it.
         */
        val carried: Int,
        /**
         * References that the file carries no attached file for, taken off the items this file's restore stored into this
         * account in any run on this device (from its record; an item the server refused is not counted, and no
         * reference twice: decided on 23 November 2026), of the vaults this run stored an item into or brought to their
         * end only: 0 for a run that stored nothing and ended no vault. In a file an
         * andvari app made: the files too large for the backup and those not fetched (the preview counts both), and every
         * reference of a backup made without its attached files (which the file says nowhere); in a file made otherwise,
         * any reference it chose not to carry.
         */
        val stripped: Int,
        /** What of the file was left out (as the preview said). */
        val leftOut: RestoreLeftOut,
    ) : RestoreResult()

    /** The account has no room: [limits] each limit it would pass. Nothing was written. */
    class NoRoom(val limits: List<Shortfall>) : RestoreResult()

    class Stopped(val stop: RestoreStop) : RestoreResult()

    /**
     * What is left of a chosen vault is no longer what the preview the choice was made on said: what the account holds
     * changed since (a sync sent what a stopped run left queued). Nothing was sent, and nothing written but the end of a
     * vault whose every item is in the account now. [preview] is the description now, from which a page is made again.
     */
    class Changed(val preview: RestorePreview) : RestoreResult()
}

/**
 * Putting a backup file (spec 07 §3) back into the signed-in account, for every app and the tool alike.
 *
 * The preview opens nothing on the server and writes nothing. The personal vault's items go into this account's
 * personal vault; a shared vault is recreated as a new vault this account owns, only when chosen, pacing itself on `429`
 * with `Retry-After`. Fresh item ids are minted once, at plan time, and kept in a record on this device together with
 * each acknowledged batch, so a rerun resumes from the first unacknowledged batch and never replays the whole plan.
 * `logHead` is dropped. Each attachment the file carries is re-encrypted under a fresh key and uploaded before its item,
 * under an id and key minted once per item and attachment and kept in the record (the key sealed to this account), so
 * two items naming one attached file get an upload each; a reference the file does
 * not carry is stripped and counted. An item the server refuses is kept in the record by its id in the file and tried
 * again by the next restore of the file. When every batch of a vault is acknowledged the record says when, also after
 * the restore has ended, and the next preview of the file offers only the vaults with something left to store.
 *
 * The record holds ids, the sealed keys and times: no item, no name and no key that opens anything without the
 * account's own key.
 */
class BackupRestore(private val host: RestoreHost) {
    companion object {
        /** The local-record purpose that seals a restore's fresh attachment keys in its record. */
        const val KEY_PURPOSE = "andvari-cli restore attachment key"

        /** Items per batch (spec 07 §3; the server's batch cap). */
        const val BATCH = 200

        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }

        /** As the item documents are read before they are sealed. */
        private val docJson = Json { ignoreUnknownKeys = true }

        /** An attachment's stored size from its plain length: 17 bytes more per 64 KiB chunk (as the web's twin counts it). */
        private fun storedSize(plain: Long): Long = plain + 17 * ((plain + 65_535) / 65_536)

        private val FILE_ID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

        /** A record's name: lower-case letters, digits and hyphens only, so that a host may make a path of it. */
        private val RECORD_NAME = Regex("^[a-z0-9-]+$")

        /**
         * Whether the restore record [text] says a restore that has not finished on this device: a vault a run was asked
         * for whose every batch was not acknowledged, or items the server refused that are left. A vault never ticked is
         * not unfinished. A record that cannot be read counts as unfinished (unknown is never "finished").
         */
        fun unfinished(text: String): Boolean {
            val plan = runCatching { json.decodeFromString(Plan.serializer(), text) }.getOrNull() ?: return true
            return (plan.started - plan.restored.keys).isNotEmpty() || plan.refused.isNotEmpty()
        }

        /** True when a host may make a path of [name]: what every record name of a restore is. */
        fun safeRecordName(name: String): Boolean = name.length <= 128 && RECORD_NAME.matches(name)

        /**
         * Open [bytes] for a restore under [passphrase]; a file whose id is not a lower-case UUID is refused, and so is a
         * file whose attached files no andvari writer arranges so ([arrangementRefusal]).
         */
        fun open(crypto: CryptoProvider, passphrase: String, bytes: ByteArray): RestoreOpening {
            val opened = try {
                Backup.open(crypto, passphrase, bytes)
            } catch (e: BackupException) {
                return RestoreOpening.NotOpened(e.code)
            }
            if (!FILE_ID.matches(opened.header.fileId)) return RestoreOpening.IdRefused
            arrangementRefusal(opened)?.let { return RestoreOpening.NotOpened(it) }
            return RestoreOpening.Opened(RestoreFile(opened, Bytes.toHexLower(crypto.sha256(bytes)).take(32)))
        }

        /**
         * The code a whole file is refused with when its attached files are arranged as no andvari writer arranges
         * them; null when none is. The shared and the web writer, at 0.30.0 and since, make one entry and one part per
         * attached file of each item, only after the file was fetched, only for a reference of that item's own
         * document, each of an item's references once; one file named by two items (an item and its conflict copy) lies
         * in one vault. So:
         *
         * - an entry whose part the file does not hold is a file cut short at the edge of a part: `truncated`, as a cut
         *   inside a part is (otherwise the cut file would restore its items without their files, and the whole file,
         *   whose bytes and so whose record differ, would afterwards store every item a second time);
         * - an entry naming no part (a number below 1), the same entry twice under one item, an entry under an item the
         *   restore takes whose document does not name that file, and one file id carried under items of two vaults:
         *   `bad_payload`.
         *
         * An entry under an item the restore does not take stays one it leaves out and says ([RestoreLeftOut]).
         */
        private fun arrangementRefusal(file: Backup.OpenedBackup): String? {
            val entries = file.payload.attachments
            if (entries.any { it.section > file.attachmentSectionCount }) return Backup.ERR_TRUNCATED
            if (entries.any { it.section < 1 }) return Backup.ERR_BAD_PAYLOAD
            val pairs = HashSet<Pair<String, String>>()
            if (!entries.all { pairs.add(it.itemId to it.attachmentId) }) return Backup.ERR_BAD_PAYLOAD
            val taken = Content(file).items.associateBy { it.itemId }
            val vaultOfFile = HashMap<String, String>()
            for (e in entries) {
                val item = taken[e.itemId] ?: continue
                if (item.doc.attachments.none { it.id == e.attachmentId }) return Backup.ERR_BAD_PAYLOAD
                if (vaultOfFile.getOrPut(e.attachmentId) { item.vaultId } != item.vaultId) return Backup.ERR_BAD_PAYLOAD
            }
            return null
        }

        private fun reasonOf(f: ItemFailure): String = when (f) {
            is ItemFailure.Refused -> f.code
            is ItemFailure.Denied -> "denied"
            else -> "refused"
        }
    }

    @Serializable
    private data class Plan(
        val fileId: String,
        /**
         * The account this record restores into ([origin], [userId]): what its acknowledged batches were stored in. A
         * record of another account is never resumed here, or its batches would be skipped as stored while this account
         * got none. Null only in a record written before the record named its account.
         */
        val origin: String? = null,
        val userId: String? = null,
        /**
         * Backup vault id -> the id this restore chose for the vault it recreates, minted once and saved BEFORE the first
         * create, then passed on every retry (spec 07 §3): a create whose answer was lost is re-posted, never made twice.
         */
        val chosenIds: Map<String, String> = emptyMap(),
        /** Backup vault id -> the vault created under its chosen id, once the server confirmed it. */
        val vaults: Map<String, String?> = emptyMap(),
        val items: Map<String, String> = emptyMap(),
        val acked: Set<String> = emptySet(),
        /**
         * Backup item id -> backup attachment id -> the fresh upload id and fresh file key of that pair, minted once (the
         * key sealed to this account). One per pair, never per attachment id alone: an item and its conflict copy name
         * one attached file, and the server binds each upload to one item, so each item gets an upload of its own.
         *
         * A record of the older shape (one upload per attachment id, under `attachments`) is not read for this: its
         * acknowledged batches stay acknowledged, and a pair of a batch not yet acknowledged gets a fresh upload id, so
         * its file is uploaded once more and the earlier upload, which no item names, is left to the server.
         */
        val files: Map<String, Map<String, Carried>> = emptyMap(),
        /** Backup item id -> the reason the server refused it: tried again by the next restore of this file. */
        val refused: Map<String, String> = emptyMap(),
        /**
         * Backup vault id -> when every batch of it was acknowledged (unix ms). Where items of it were refused then, the
         * time moves to when a later run stores its last refused item.
         */
        val restored: Map<String, Long> = emptyMap(),
        /** The backup vault ids a run of this restore was asked for (ticked): one not in [restored] is unfinished. */
        val started: Set<String> = emptySet(),
    )

    /** An attachment re-encrypted for the restore: [newId] and the new file key, sealed as a local record of the account. */
    @Serializable
    private data class Carried(val newId: String, val sealedKey: String)

    private class Stop(val stop: RestoreStop) : Exception(stop.toString())

    /**
     * What of a file a restore acts on: each vault and item id once (the first), items under a listed vault, attached
     * files' entries under a listed item. The rest is [leftOut]. Only the sections those entries name are ever read
     * (every one of them is in the file: [open] refuses a file that names a section it does not hold).
     */
    private class Content(file: Backup.OpenedBackup) {
        val vaults: List<BackupVault>
        val items: List<BackupItem>
        val entries: List<BackupAttachmentEntry>
        val leftOut: RestoreLeftOut

        init {
            val p = file.payload
            val vaultIds = HashSet<String>()
            vaults = p.vaults.filter { vaultIds.add(it.vaultId) }
            val itemIds = HashSet<String>()
            val once = p.items.filter { itemIds.add(it.itemId) }
            items = once.filter { it.vaultId in vaultIds }
            val listed = items.mapTo(HashSet()) { it.itemId }
            val sections = 1..file.attachmentSectionCount
            entries = p.attachments.filter { it.itemId in listed }
            val named = p.attachments.mapTo(HashSet()) { it.section }.count { it in sections }
            leftOut = RestoreLeftOut(
                vaultsTwice = p.vaults.size - vaults.size,
                itemsTwice = p.items.size - once.size,
                itemsUnderNoVault = once.size - items.size,
                filesUnderNoItem = p.attachments.size - entries.size,
                sectionsUnnamed = file.attachmentSectionCount - named,
            )
        }
    }

    private val crypto get() = host.crypto

    /**
     * One record per backup file AND account: the file's id, the account, and the digest of the file's bytes. Another
     * file under the same id (other content, or the same content sealed again) has a record of its own: a record is
     * never read, resumed or removed as another file's.
     */
    private fun recordName(file: RestoreFile): String {
        val owner = Bytes.toHexLower(crypto.sha256("${host.origin}|${host.userId}".encodeToByteArray())).take(16)
        return "restore-${file.opened.header.fileId}-$owner-${file.digest}"
    }

    private fun read(name: String): Plan? = host.records.read(checked(name))?.let { runCatching { json.decodeFromString(Plan.serializer(), it) }.getOrNull() }

    /** Every record name this restore hands its host is one a path can be made of; [open] makes sure of the file's id. */
    private fun checked(name: String): String = name.also { require(safeRecordName(it)) { "not a record name" } }

    private fun ours(q: Plan) = q.origin == host.origin && q.userId == host.userId

    /** This account's record of [file]. */
    private fun existing(file: RestoreFile): Plan? = read(recordName(file))?.takeIf(::ours)

    /**
     * What [file] holds and what of it this account already has: a sync for the account's own count, then the record of
     * an earlier restore of the same file into this account (what was restored and when, what was refused). Sends
     * nothing of the restore. It writes only the end of a vault an earlier run started whose every item is in the
     * account now, with nothing refused: that restore is finished, and the record says so.
     */
    suspend fun preview(restoreFile: RestoreFile): RestorePreview {
        val content = Content(restoreFile.opened)
        host.sync()
        return look(restoreFile, content, host.items.liveItemIds()).second
    }

    /**
     * This account's record of [restoreFile] (null when there is none), with every vault an earlier run started whose
     * items are all in the account ([held]: the ids it holds) and none refused brought to its end (its batches
     * acknowledged, its end's time set, the record written), and the description of the file for this account now made
     * from it: the one place that says, per vault, what is left and whether it can be chosen.
     */
    private fun look(restoreFile: RestoreFile, content: Content, held: Set<String>): Pair<Plan?, RestorePreview> {
        val plan = existing(restoreFile)?.let { finished(content, it, held, recordName(restoreFile)) }
        return plan to describe(restoreFile.opened, content, plan, held)
    }

    /**
     * [plan] with each vault a run of it started and has not ended whose items are all in the account ([held]) and none
     * of whose items the server refused, ended now: nothing is left to send for it. Written when anything ended.
     */
    private fun finished(content: Content, plan: Plan, held: Set<String>, name: String): Plan {
        val leftIn = left(content, plan, held).mapTo(HashSet()) { it.vaultId }
        val refusedIn = content.items.filter { it.itemId in plan.refused }.mapTo(HashSet()) { it.vaultId }
        val ended = content.vaults.filter { v -> v.vaultId in plan.started && v.vaultId !in plan.restored && v.vaultId !in leftIn && v.vaultId !in refusedIn }
        if (ended.isEmpty()) return plan
        val batches = ended.flatMap { v -> content.items.filter { it.vaultId == v.vaultId }.chunked(BATCH).indices.map { "${v.vaultId}#$it" } }
        val now = host.now()
        val next = plan.copy(acked = plan.acked + batches, restored = plan.restored + ended.associate { it.vaultId to now })
        host.records.replace(checked(name), json.encodeToString(Plan.serializer(), next))
        return next
    }

    /**
     * [after] with the end of each vault that had ended moved to now where an item of it left the refused items between
     * [before] and [after] (a run stored it) and no item of it is refused any more: the end of such a vault moves to the
     * time a run stores its last refused item. A vault that has not ended is not ended here.
     */
    private fun lastInAccount(content: Content, before: Plan, after: Plan): Plan {
        val gone = before.refused.keys - after.refused.keys
        if (gone.isEmpty()) return after
        val stillRefused = content.items.filter { it.itemId in after.refused }.mapTo(HashSet()) { it.vaultId }
        val finishedNow = content.items.filter { it.itemId in gone }.mapTo(LinkedHashSet()) { it.vaultId }
            .filter { it in after.restored && it !in stillRefused }
        if (finishedNow.isEmpty()) return after
        val now = host.now()
        return after.copy(restored = after.restored + finishedNow.associateWith { now })
    }

    private fun describe(file: Backup.OpenedBackup, content: Content, plan: Plan?, held: Set<String>): RestorePreview {
        val p = file.payload
        val byId = content.items.associateBy { it.itemId }
        val leftItems = left(content, plan, held)
        val left = leftItems.groupingBy { it.vaultId }.eachCount()
        val leftFiles = leftItems.groupBy { it.vaultId }.mapValues { (_, items) -> items.sumOf { notCarried(content, it) } }
        val mine = host.items.items()
        val fromFile = plan?.items?.values?.toHashSet().orEmpty()
        return RestorePreview(
            exportedAt = p.exportedAt,
            origin = p.origin,
            vaults = content.vaults.map { v ->
                val restoredAt = plan?.restored?.get(v.vaultId)
                RestoreVaultLine(
                    v.vaultId, v.name, v.type, v.type == "personal", v.role, v.role == "owner", content.items.count { it.vaultId == v.vaultId }, restoredAt,
                    left[v.vaultId] ?: 0, leftFiles[v.vaultId] ?: 0, started = restoredAt == null && plan?.started?.contains(v.vaultId) == true,
                )
            },
            attachments = content.entries.size,
            attachmentBytes = content.entries.fold(0L) { s, e -> s + e.size.coerceAtLeast(0) },
            attachmentsOverCap = p.skipped.attachmentsOverCap,
            attachmentFetchFailed = p.skipped.attachmentFetchFailed,
            undecryptable = p.skipped.undecryptable.size,
            accountItems = mine.size,
            refused = plan?.refused.orEmpty().mapNotNull { (id, why) -> byId[id]?.let { RefusedItem(id, it.doc.name, it.vaultId, why) } },
            leftOut = content.leftOut,
            accountItemsBeside = mine.count { it.itemId !in fromFile },
        )
    }

    /** The attached files [item] names that the file does not carry for it, each once. */
    private fun notCarried(content: Content, item: BackupItem): Int =
        item.doc.attachments.map { it.id }.distinct().count { id -> content.entries.none { it.attachmentId == id && it.itemId == item.itemId } }

    /** The attached files [item] names that the file carries for it, each once: those a run that stores it restores. */
    private fun carriedOf(content: Content, item: BackupItem): Int =
        item.doc.attachments.map { it.id }.distinct().count { id -> content.entries.any { it.attachmentId == id && it.itemId == item.itemId } }

    /**
     * The attached files that items this file's restore stored into this account name and the file does not carry, over
     * every run of it on this device, from the record and the file: each item of an acknowledged batch the server did not
     * refuse, each such file once, in the vaults [of] only. What the end of a restore says was taken off.
     */
    private fun notCarriedOverRecord(content: Content, plan: Plan, of: Set<String>): Int = content.vaults.filter { it.vaultId in of }.sumOf { v ->
        content.items.filter { it.vaultId == v.vaultId }.chunked(BATCH).withIndex().filter { (i, _) -> "${v.vaultId}#$i" in plan.acked }
            .sumOf { (_, batch) -> batch.filter { it.itemId !in plan.refused }.sumOf { notCarried(content, it) } }
    }

    /**
     * The items of [content] a restore still has to store into this account, in the file's order: with no record
     * ([plan] null), every item; otherwise each item of a batch the record does not hold as acknowledged and each item
     * the server refused, less those the account holds ([held]: the item ids it holds after a sync), such as the items of
     * a batch a stopped run left queued that a sync sent since. The preview's counts and the run's (what it stores, its
     * progress, its end) are sizes of this one set.
     */
    private fun left(content: Content, plan: Plan?, held: Set<String>): List<BackupItem> {
        if (plan == null) return content.items
        return content.vaults.flatMap { v ->
            content.items.filter { it.vaultId == v.vaultId }.chunked(BATCH).withIndex().flatMap { (i, batch) ->
                batch.filter { "${v.vaultId}#$i" !in plan.acked || it.itemId in plan.refused }
            }
        }.filter { item -> plan.items[item.itemId]?.let { it !in held } ?: true }
    }

    /**
     * Restore what [choice] names, made on a preview of [file] ([RestorePreview.choose]): the run stores what that preview
     * said is left of each vault chosen, or, when what is left of one of them is no longer that, sends nothing and answers
     * [RestoreResult.Changed] with the description now. Items the server refused before are tried again.
     */
    suspend fun restore(file: RestoreFile, choice: RestoreChoice, events: (RestoreEvent) -> Unit = {}): RestoreResult =
        guarded { held -> run(file, null, choice, events, held) }

    /**
     * Restore the vaults of [file] whose ids are in [chosen] (the personal vault and any shared vault, each by its id in
     * the file), as the description at the run's start chooses them: those of them with something left to store
     * ([RestoreVaultLine.choosable]), and no other. For a caller that shows no preview first.
     */
    suspend fun restore(file: RestoreFile, chosen: Set<String>, events: (RestoreEvent) -> Unit = {}): RestoreResult =
        guarded { held -> run(file, chosen, null, events, held) }

    private suspend fun guarded(block: suspend (MutableSet<String>) -> RestoreResult): RestoreResult {
        val held = HashSet<String>()
        return try {
            block(held)
        } catch (s: Stop) {
            RestoreResult.Stopped(s.stop)
        } finally {
            host.items.releaseRefusals(held)
        }
    }

    /**
     * One run, for [shown] (a choice made on a preview, checked against the description now) or [chosenIds] (chosen by
     * the description now). [held]: the item ids whose refusals this run holds ([ItemEngine.holdRefusals]); the caller
     * releases them.
     */
    private suspend fun run(file: RestoreFile, chosenIds: Set<String>?, shown: RestoreChoice?, events: (RestoreEvent) -> Unit, held: MutableSet<String>): RestoreResult {
        val opened = file.opened
        val content = Content(opened)
        val fileId = opened.header.fileId
        val planName = recordName(file)
        val live = host.items.liveItemIds()
        val (existing, now) = look(file, content, live)
        val choice = if (shown == null) now.choose(chosenIds.orEmpty()) else {
            // The press runs what the page showed, or nothing.
            val leftNow = now.vaults.associate { it.vaultId to it.left }
            if (shown.left.any { (id, n) -> leftNow[id] != n }) return RestoreResult.Changed(now)
            shown
        }
        val chosen = content.vaults.filter { it.vaultId in choice.vaults }
        // Nothing of the chosen vaults is left: nothing is sent, written or started.
        if (chosen.isEmpty()) return RestoreResult.Done(0, 0, emptyList(), 0, 0, content.leftOut)
        var plan = existing
            ?: Plan(fileId, host.origin, host.userId, items = content.items.associate { it.itemId to Bytes.uuidV4FromBytes(crypto.randomBytes(16)) })
        // The refusals of this file's items are this restore's while it runs: a sync of the vault's content meanwhile (the
        // bell, "Sync now", this run's own sync sending what a stopped run left queued) leaves them for the batch that
        // takes them, which keeps them by name.
        held += plan.items.values
        host.items.holdRefusals(held)
        // What this run stores: the items of the chosen vaults the account does not hold when it begins ([left], as the
        // preview counted them after its sync). A batch not yet acknowledged whose items the account holds all the same
        // (the preview's sync sent what a stopped run left queued) is sent again so that the record holds it, and its
        // items are counted by none of the run's numbers; what this run's own sync sends of such a batch is this run's.
        val pending = left(content, plan, live).filter { item -> chosen.any { it.vaultId == item.vaultId } }
        val counted = pending.mapTo(HashSet()) { it.itemId }
        fun save() = host.records.replace(checked(planName), json.encodeToString(Plan.serializer(), plan))
        host.sync()
        // The items refused by an earlier run: tried again in this one.
        val again = plan.refused.keys.toSet()
        // Spec 03 §14.4: the room for what this run still writes (those items, the attachments the file carries for
        // them, the vaults not yet created), on a fresh sync, before anything is written.
        val room = room(
            pending.map { item -> plan.items.getValue(item.itemId) to JsonObject(json.encodeToJsonElement(ItemDoc.serializer(), item.doc).jsonObject - "logHead") },
            pending.sumOf { item ->
                item.doc.attachments.sumOf { ref -> content.entries.firstOrNull { it.attachmentId == ref.id && it.itemId == item.itemId }?.let { storedSize(it.size) } ?: 0L }
            },
            chosen.count { it.type != "personal" && plan.vaults[it.vaultId] == null },
            events,
        )
        if (room != null) return room
        // Past the room check, the run starts: its vaults are recorded as started, and the record is written. A run that
        // the room check ended (or whose check could not be made) wrote nothing and started nothing.
        plan = plan.copy(started = plan.started + chosen.map { v -> v.vaultId })
        save()
        var carried = 0
        var stored = 0
        var done = 0
        val refused = ArrayList<RefusedItem>()
        // The vaults this run stored an item into or brought to their end: those whose files taken off its end says.
        val touched = HashSet<String>()

        /** One batch of [batch] into [target]: attachments first, then the items. How many the server kept. */
        suspend fun send(v: BackupVault, target: String, batch: List<BackupItem>, number: Int): Int {
            val docs = batch.map { item ->
                val newItemId = plan.items.getValue(item.itemId)
                // Spec 07 §3: each attachment the file carries is re-encrypted under a fresh key and uploaded first,
                // bound to the item's new id; one the file does not carry (over the cap, or not fetched) is counted.
                val refs = ArrayList<AttachmentRef>()
                for (ref in item.doc.attachments) {
                    val entry = content.entries.firstOrNull { it.attachmentId == ref.id && it.itemId == item.itemId }
                    // Not carried: the item is stored without it, and the end counts it over the record.
                    if (entry == null) continue
                    val minted = plan.files[item.itemId]?.get(ref.id) ?: run {
                        val fresh = crypto.randomBytes(32)
                        try {
                            Carried(Bytes.uuidV4FromBytes(crypto.randomBytes(16)), Bytes.toB64(host.account.sealLocalRecord(crypto, KEY_PURPOSE, fresh)))
                        } finally {
                            fresh.fill(0)
                        }
                    }.also {
                        plan = plan.copy(files = plan.files + (item.itemId to (plan.files[item.itemId].orEmpty() + (ref.id to it))))
                        save()
                    }
                    refs += carry(opened, entry, minted, newItemId, target, events)
                }
                var doc = json.encodeToJsonElement(ItemDoc.serializer(), item.doc.copy(attachments = refs)).jsonObject
                doc = JsonObject(doc - "logHead")
                if (refs.isEmpty()) doc = JsonObject(doc - "attachments")
                newItemId to doc
            }
            // The item engine seals each document at the lowest formatVersion that holds it (cards at 2), which is the
            // one the backup recorded.
            val ids = docs.mapTo(HashSet()) { it.first }
            host.items.takeRefusedForGoodAmong(ids)
            var tries = 0
            while (true) {
                val failure = importNew(target, docs) ?: break
                val why = failure.why
                val retry = (why as? ItemFailure.Refused)?.retryAfterSeconds
                if (why is ItemFailure.Refused && why.code == "rate_limited" && retry != null && tries++ < 5) {
                    events(RestoreEvent.Waiting(retry, vaultCreation = false))
                    delay(retry * 1000)
                    continue
                }
                throw Stop(RestoreStop.BatchRefused(number, v.name, why))
            }
            val byNewId = batch.associateBy { plan.items.getValue(it.itemId) }
            val gone = host.items.takeRefusedForGoodAmong(ids).mapNotNull { (newId, f) -> byNewId[newId]?.let { it to reasonOf(f) } }
            val ours = batch.filter { it.itemId in counted }
            done += ours.size
            events(RestoreEvent.Progress(done, pending.size))
            if (gone.isNotEmpty()) events(RestoreEvent.Refused(gone.size))
            val sent = batch.mapTo(HashSet()) { it.itemId }
            val prior = plan
            plan = plan.copy(refused = plan.refused.filterKeys { it !in sent } + gone.associate { (item, why) -> item.itemId to why })
            // A vault that ended with an item refused, whose last refused item this batch stored: finished now.
            plan = lastInAccount(content, prior, plan)
            for ((item, why) in gone) refused += RefusedItem(item.itemId, item.doc.name, item.vaultId, why)
            val refusedNow = gone.mapTo(HashSet()) { it.first.itemId }
            // What this batch stored: its items the account did not hold before the run, less those refused now; and the
            // attached files restored are those of exactly these items, each once, made here from the server's answer.
            val kept = ours.filter { it.itemId !in refusedNow }
            carried += kept.sumOf { carriedOf(content, it) }
            if (kept.isNotEmpty()) touched += v.vaultId
            return kept.size
        }

        for (v in chosen) {
            val target = if (v.type == "personal") host.account.personalVaultId ?: throw Stop(RestoreStop.NoPersonalVault)
            else (plan.vaults[v.vaultId] ?: run {
                val id = plan.chosenIds[v.vaultId] ?: Bytes.uuidV4FromBytes(crypto.randomBytes(16)).also {
                    plan = plan.copy(chosenIds = plan.chosenIds + (v.vaultId to it)); save()
                }
                createVault(v.name, id, events)
                plan = plan.copy(vaults = plan.vaults + (v.vaultId to id)); save()
                id
            }).also { adoptKey(it, v.name) }
            val items = content.items.filter { it.vaultId == v.vaultId }
            val batches = items.chunked(BATCH)
            batches.forEachIndexed { i, batch ->
                val key = "${v.vaultId}#$i"
                if (key in plan.acked) return@forEachIndexed
                stored += send(v, target, batch, i + 1)
                plan = plan.copy(acked = plan.acked + key)
                save()
            }
            // Refused by an earlier run and not sent again above: tried again now, under the same ids.
            items.filter { it.itemId in again && it.itemId in plan.refused }.chunked(BATCH).forEachIndexed { j, batch ->
                stored += send(v, target, batch, batches.size + j + 1)
                save()
            }
            if (v.vaultId !in plan.restored) {
                plan = plan.copy(restored = plan.restored + (v.vaultId to host.now()))
                save()
                touched += v.vaultId
            }
        }
        return RestoreResult.Done(stored, chosen.size, refused, carried, notCarriedOverRecord(content, plan, touched), content.leftOut)
    }

    private class Failure(val why: ItemFailure?)

    /**
     * New items into [vaultId] (spec 07 §3) with `mutationId = itemId`, so a retried batch is the same mutations. Null
     * when the server answered the batch; the failure of the whole call otherwise (why null: an item does not read).
     */
    private suspend fun importNew(vaultId: String, docs: List<Pair<String, JsonObject>>): Failure? {
        val planned = docs.map { (id, doc) -> CsvImport.PlannedItem(id, parse(doc) ?: return Failure(null)) }
        return when (val r = host.items.importAll(planned, vaultId = vaultId)) {
            is ItemResult.Ok -> null
            is ItemResult.Failed -> Failure(r.why)
        }
    }

    /**
     * The check before a large copy (spec 03 §14.4): a fresh sync, then the shared check on the `quota` that pull served,
     * for [items] (sealed as [importNew] seals them), [attachmentBytes] of stored attachment sizes, and [newSharedVaults]
     * vaults the restore creates. More than one new vault is checked against `ownedSharedVaults` here too, as the shared
     * check counts at most one. Null to go on; [RestoreEvent.RoomUnknown] when the server gave no figures.
     */
    private suspend fun room(items: List<Pair<String, JsonObject>>, attachmentBytes: Long, newSharedVaults: Int, events: (RestoreEvent) -> Unit): RestoreResult? {
        val planned = items.map { (id, doc) -> CsvImport.PlannedItem(id, parse(doc) ?: return RestoreResult.Stopped(RestoreStop.ItemUnreadable)) }
        val size = host.items.importSize(planned)
        val room = when (val r = host.items.roomFor(CopySize(size.bytes + attachmentBytes, size.items, newSharedVaults > 0))) {
            is ItemResult.Failed -> return RestoreResult.Stopped(RestoreStop.RoomCheckFailed(r.why))
            is ItemResult.Ok -> r.value
        }
        val many = host.items.quota()?.takeIf { newSharedVaults > 1 && it.isWhole() }?.ownedSharedVaults
            ?.takeIf { it.limit - it.used < newSharedVaults }
            ?.let { Shortfall(QuotaName.OWNED_SHARED_VAULTS, it.used, it.limit, newSharedVaults.toLong()) }
        return when (room) {
            is QuotaRoom.Short -> RestoreResult.NoRoom(room.limits.map { if (many != null && it.quota == many.quota) many else it })
            QuotaRoom.Room -> if (many != null) RestoreResult.NoRoom(listOf(many)) else null
            else -> {
                events(RestoreEvent.RoomUnknown)
                null
            }
        }
    }

    private fun parse(doc: JsonObject): ItemDoc? {
        if (ItemDocShape.problem(doc) != null) return null
        return runCatching { docJson.decodeFromJsonElement(ItemDoc.serializer(), doc) }.getOrNull()
    }

    /**
     * Re-encrypt the file's [entry] under the [minted] key and upload it bound to [itemId] in [vaultId], through the item
     * engine's attachment channel. A retry uploads the same id under the same key, and the engine takes
     * `attachment_id_taken` as the earlier attempt having landed. Answers the item's new reference.
     */
    private suspend fun carry(file: Backup.OpenedBackup, entry: BackupAttachmentEntry, minted: Carried, itemId: String, vaultId: String, events: (RestoreEvent) -> Unit): AttachmentRef {
        val key = Bytes.fromB64Canonical(minted.sealedKey)?.let { host.account.openLocalRecord(crypto, KEY_PURPOSE, it) }
            ?: throw Stop(RestoreStop.AttachmentKeyUnopenable(entry.name))
        try {
            val plain = try {
                file.readAttachment(entry)
            } catch (e: BackupException) {
                throw Stop(RestoreStop.AttachmentUnreadable(entry.name, e.code))
            }
            val sealed = try {
                if (plain.size.toLong() != entry.size) throw Stop(RestoreStop.AttachmentWrongSize(entry.name))
                Attachments.encrypt(crypto, key, plain).let { it.header + it.ciphertext }
            } finally {
                plain.fill(0)
            }
            var tries = 0
            while (true) {
                when (val r = host.items.uploadEncryptedAttachment(minted.newId, itemId, vaultId, sealed)) {
                    is ItemResult.Ok -> return AttachmentRef(minted.newId, entry.name, entry.size, Bytes.toB64(key))
                    is ItemResult.Failed -> {
                        val why = r.why
                        val retry = (why as? ItemFailure.Refused)?.retryAfterSeconds
                        if (why is ItemFailure.Refused && why.code == "rate_limited" && retry != null && tries++ < 5) {
                            events(RestoreEvent.Waiting(retry, vaultCreation = false))
                            delay(retry * 1000)
                            continue
                        }
                        throw Stop(RestoreStop.AttachmentRefused(entry.name, why))
                    }
                }
            }
        } finally {
            key.fill(0)
        }
    }

    /**
     * A new shared vault this account owns under the [id] the record chose, pacing on `vault_create`'s `429` (design
     * §3.7: 10 an hour). Asked again for the same id, the engine re-posts a genesis it still holds pending byte for byte,
     * or answers `Appended` for one it already verified, so a rerun after a lost answer or a crash makes no second vault.
     */
    private suspend fun createVault(name: String, id: String, events: (RestoreEvent) -> Unit) {
        var tries = 0
        while (true) {
            when (val r = host.logs.append(null, LogAction.Create(name, id))) {
                is AppendOutcome.Appended ->
                    if (r.state.vaultId == id) return else throw Stop(RestoreStop.OtherVaultAnswered(name, r.state.vaultId))
                is AppendOutcome.Refused -> {
                    val wait = r.retryAfterSeconds
                    if (r.code == "rate_limited" && wait != null && tries++ < 10) {
                        events(RestoreEvent.Waiting(wait, vaultCreation = true))
                        delay(wait * 1000)
                    } else throw Stop(RestoreStop.VaultNotCreated(name, r.code))
                }
                AppendOutcome.Pending -> throw Stop(RestoreStop.VaultNotConfirmed(name, id))
                else -> throw Stop(RestoreStop.VaultNotCreated(name, r.toString()))
            }
        }
    }

    /**
     * The key of the recreated vault [id], from the log engine's adoption through the owner wrap the create posted
     * (design §3.6), after a sync has brought its grant row: also after a restart, when nothing of the create is in
     * memory. Items go in only under an adopted key.
     */
    private suspend fun adoptKey(id: String, name: String) {
        host.sync()
        when (val a = host.logs.adoption(id)) {
            is Adoption.Adopted -> {}
            is Adoption.Refused -> throw Stop(RestoreStop.KeyNotAdopted(name, a.reason.code, null))
            else -> throw Stop(RestoreStop.KeyNotAdopted(name, null, a.toString()))
        }
    }
}
