package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.SaveQueueStore

/*
 * Strict readers beside the "never throws" ones. A host's store that keeps records in files (the iPhone's App Group and
 * app container) answers its old readers with null or empty for a record that is not there and also for one it could
 * not read; the extensions rely on that and keep doing so. The vault's content needs to tell the two apart (a record
 * that cannot be read is unknown, never empty), so a store offers these as well, and the
 * content's kept-record reads, sweeps, queue sync and carry use them whenever a store does. Each answers "not there"
 * only when the file or directory does not exist, and throws otherwise.
 */

/** A [FillSnapshotStore] that tells a missing record from one it could not read. */
interface StrictRecordStore {
    /** The record, or null only when it is not there; throws when it is there (or may be) and could not be read. */
    @Throws(Exception::class)
    fun readOrThrow(): ByteArray?
}

/** A [BlobStore] that tells a missing file from one it could not read. */
interface StrictBlobStore {
    /** The file [id], or null only when it is not there; throws when it is there and could not be read. */
    @Throws(Exception::class)
    fun getOrThrow(id: String): ByteArray?

    /** The ids of every file set aside: empty only when there is no directory; throws when it could not be listed. */
    @Throws(Exception::class)
    fun idsOrThrow(): List<String>
}

/** A [SaveQueueStore] that tells an empty queue from one it could not read. */
interface StrictSaveQueueStore {
    /**
     * The entries, by id, under the same bounds as [SaveQueueStore.entries]: empty only when there is no directory or no
     * entry; throws when the directory could not be listed or an entry that is there could not be sized or read.
     */
    @Throws(Exception::class)
    fun entriesOrThrow(): Map<String, ByteArray>
}

/** Thrown by a strict reader: the record is there, or may be, and could not be read. */
class StoreUnreadableException(message: String) : Exception(message)

/** The rule each strict reader follows, written once so it is tested here and the iPhone's stores only call it. */
internal object StrictReads {
    /**
     * What [read] gave; when it gave nothing, null only if [exists] then says the record is not there (asked after
     * the read, so a record removed between the two is "not there"), and [StoreUnreadableException] otherwise. A
     * [read] that throws is a failure too.
     */
    fun <T : Any> value(what: String, read: () -> T?, exists: () -> Boolean): T? {
        val got = read()
        if (got != null) return got
        if (!exists()) return null
        throw StoreUnreadableException("$what is there and could not be read")
    }

    /** A listing: empty only when the directory is not there. */
    fun names(what: String, list: () -> List<String>?, exists: () -> Boolean): List<String> = value(what, list, exists).orEmpty()
}

/** [FillSnapshotStore.read] through the strict reader when the store offers one. */
internal fun FillSnapshotStore.readStrict(): ByteArray? = if (this is StrictRecordStore) readOrThrow() else read()

/** [BlobStore.get] through the strict reader when the store offers one. */
internal fun BlobStore.getStrict(id: String): ByteArray? = if (this is StrictBlobStore) getOrThrow(id) else get(id)

/** [BlobStore.ids] through the strict reader when the store offers one. */
internal fun BlobStore.idsStrict(): List<String> = if (this is StrictBlobStore) idsOrThrow() else ids()

/** [SaveQueueStore.entries] through the strict reader when the store offers one. */
internal fun SaveQueueStore.entriesStrict(): Map<String, ByteArray> = if (this is StrictSaveQueueStore) entriesOrThrow() else entries()
