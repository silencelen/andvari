package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.MutationResult
import io.silencelen.andvari.core.model.WireItem
import kotlinx.serialization.Serializable

/** A device's journal keeps its newest rows only: the dedup window a re-sent push needs, and a bound on the table. */
internal const val JOURNAL_PER_DEVICE = 1000

/**
 * The stored item a journaled conflict carried, by id and rev, without its blob or attachment list. The
 * replay reads the blob back at answer time; a replayed item carries no attachment ids (no client reads
 * them from a displaced version: the conflict copy is made from its blob alone).
 */
@Serializable
internal data class JournalItem(
    val itemId: String,
    val vaultId: String,
    val rev: Long,
    val createdAt: Long,
    val updatedAt: Long,
    val deleted: Boolean,
    val conflict: Boolean,
    val formatVersion: Int,
) {
    fun toWire(blob: String?) = WireItem(itemId, vaultId, rev, createdAt, updatedAt, deleted, conflict, formatVersion, emptyList(), blob)

    companion object {
        fun of(w: WireItem) = JournalItem(w.itemId, w.vaultId, w.rev, w.createdAt, w.updatedAt, w.deleted, w.conflict, w.formatVersion)
    }
}

/**
 * One row of the push journal (`mutations.resultJson`, spec 02 §5): the outcome's status, rev and reason,
 * and for a conflict the stored item by reference ([item]). It decodes the rows written before 0.30.0 too,
 * whose [serverItem] is the whole stored item; those are replayed verbatim and age out with the journal.
 * A server older than this one reads a new row as a `MutationResult` without an item.
 */
@Serializable
internal data class JournalRow(
    val mutationId: String,
    val status: String,
    val newItemRev: Long? = null,
    val serverItem: WireItem? = null,
    val reason: String? = null,
    val item: JournalItem? = null,
) {
    companion object {
        fun of(r: MutationResult) = JournalRow(r.mutationId, r.status, r.newItemRev, null, r.reason, r.serverItem?.let { JournalItem.of(it) })
    }
}

/**
 * The stored items one push answer carries: each stored item (an itemId at one rev) at most once per kind
 * of result, and no more than [capBytes] of them in all, the push request's own body cap. A result past
 * either limit carries none. Before this, every rejected put and every stale delete echoed the whole stored
 * item, so a 48 KB request of 200 mutations on one 2 MiB item built a 400 MiB answer in memory. Every
 * client reads an echoed item only from a conflicting put (to make the conflict copy) and pulls in any
 * case, so a missing one costs at most that copy; the displaced version stays in the item's history. The
 * kind ([op] and status) is part of the key so that an informational echo earlier in the batch never
 * takes the place of a conflicting put's.
 */
internal class PushEcho(private val capBytes: Long) {
    private val seen = HashSet<String>()
    private var used = 0L

    fun attach(r: MutationResult, op: String): MutationResult {
        val item = r.serverItem ?: return r
        val cost = (item.blob?.length ?: 0).toLong() + 40L * item.attachmentIds.size + 256
        if (!seen.add("$op:${r.status}:${item.itemId}:${item.rev}") || used + cost > capBytes) return r.copy(serverItem = null)
        used += cost
        return r
    }
}
