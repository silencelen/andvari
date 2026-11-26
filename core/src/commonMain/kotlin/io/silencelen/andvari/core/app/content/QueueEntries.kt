package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.app.SaveQueueStore
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.crypto.CryptoProvider
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * One entry of the extensions' save queue as the content reads it: the outside of [io.silencelen.andvari.core.app.QueuedSave]
 * (who it is for, and the login sealed to that account's key), plus [carriedFrom] on an entry a followed move carried.
 *
 * An extension seals a capture at the origin the app published, and the inside names that origin too. After a followed
 * move (design §4.4) the content reads the queue at the new origin, so [QueueEntries.carry] re-files each entry of the
 * account under the new [origin] with its seal untouched (no key is needed) and records in [carriedFrom] the origin its
 * inside names: the address the namespace moved from, as the move's own records give it to the carry. A second move
 * keeps the first [carriedFrom], since the inside never changes.
 */
@Serializable
internal class QueueEntry(
    val v: Int = SaveQueue.VERSION,
    val origin: String,
    val userId: String,
    val sealed: String,
    val carriedFrom: String? = null,
)

internal object QueueEntries {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /** The entry in [bytes], or null for anything that is not one (oversized, malformed, another version). */
    fun decode(bytes: ByteArray): QueueEntry? {
        if (bytes.size > SaveQueue.MAX_ENTRY_BYTES) return null
        return runCatching { json.decodeFromString(QueueEntry.serializer(), bytes.decodeToString()) }.getOrNull()?.takeIf { it.v == SaveQueue.VERSION }
    }

    fun encode(entry: QueueEntry): ByteArray = json.encodeToString(QueueEntry.serializer(), entry).encodeToByteArray()

    /** How the queue's entries went across a move. */
    enum class Carried {
        /** Every entry of the account at the old origin is now filed at the new one (or there were none). */
        DONE,

        /** The queue could not be read, or an entry could not be written again: what was not carried stays where it was. */
        NOT_ALL,
    }

    /**
     * A followed move from [from] to [to]: each entry [userId] has at [from] is written again as a new entry at [to]
     * (a new id: an entry is never replaced), and the old one is removed only once its copy is written. A queue that
     * cannot be read stops the carry with every entry kept. An entry that is not a save, or another account's or
     * another origin's, is left as it is; the next read judges it.
     */
    fun carry(queue: SaveQueueStore, crypto: CryptoProvider, from: String, to: String, userId: String): Carried {
        val old = OriginCanon.canonicalOrigin(from)
        val new = OriginCanon.canonicalOrigin(to)
        if (old == new) return Carried.DONE
        val entries = try {
            queue.entriesStrict()
        } catch (e: Exception) {
            return Carried.NOT_ALL
        }
        var all = true
        for ((id, bytes) in entries) {
            val e = decode(bytes) ?: continue
            if (e.userId != userId || e.origin != old) continue
            val copy = encode(QueueEntry(origin = new, userId = userId, sealed = e.sealed, carriedFrom = e.carriedFrom ?: old))
            if (copy.size > SaveQueue.MAX_ENTRY_BYTES || !addNew(queue, crypto, copy)) {
                all = false
                continue
            }
            runCatching { queue.remove(id) }
        }
        return if (all) Carried.DONE else Carried.NOT_ALL
    }

    private fun addNew(queue: SaveQueueStore, crypto: CryptoProvider, bytes: ByteArray): Boolean {
        repeat(SaveQueue.ID_ATTEMPTS) {
            if (runCatching { queue.add(SaveQueue.newId(crypto), bytes) }.getOrDefault(false)) return true
        }
        return false
    }
}
