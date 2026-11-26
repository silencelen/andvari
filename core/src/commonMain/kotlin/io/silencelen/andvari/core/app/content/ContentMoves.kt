package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.client.items.MovePlan
import io.silencelen.andvari.core.client.items.MovedAttachment
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

/**
 * Moves and copies that did not finish, by item, target and kind, kept until the move is done or the person cancels
 * it, across a lock when the host gave a [FillSnapshotStore] for them (the old `VaultMoves`, over [MovePlan]):
 *  - Try again replays the same plan, so the server's mutation dedup converges instead of making a second copy.
 *  - A kept plan is replayed only while its copy is in the target as a sync just before shows it (round-7 review M3):
 *    the server answers a replayed copy leg from its journal without making the copy again, so a copy deleted since
 *    would let the delete leg remove the only original. A plan whose copy is not there goes, and a new one is planned.
 *  - Where the item changed since a try that copied it, nothing new is planned while that copy is there: the person is
 *    told it is there ([Prepared.AlreadyCopied]).
 *
 * The record keeps the old one's shape (purpose "move-memos", the old gesture's field names). Only a record with this
 * account's MAC is ever used; anything else is removed and said. A record this version cannot read is never dropped unsaid; a LOCKED account is not an
 * unreadable record: nothing is read, rewritten or removed then, and the record waits for the next unlock.
 *
 * A record that cannot be read (the host's storage failed) is unknown, never empty: nothing
 * is replaced, no plan is made or replayed, the move answers [Prepared.Unreadable], and the next read tries again.
 */
internal class ContentMoves(private val store: Store) {
    /** Where the kept plans live. */
    interface Store {
        /**
         * What was kept: [KeptRead.Read] (empty when nothing was), [KeptRead.Locked] while the account is locked, and
         * [KeptRead.Unreadable] when the record is there but could not be read. Neither of the last two is "nothing".
         */
        fun load(): KeptRead<Map<String, KeptMove>>

        /**
         * Keep [memos], all of them; empty removes what was kept. Nothing is written while the account is locked. (The
         * record is deleted with the account's copy by `ContentStores.drop`, for the person's own acts only.)
         */
        fun save(memos: Map<String, KeptMove>)
    }

    /** Kept only in this object's memory (no host storage, the fake). */
    class MemoryStore : Store {
        private var kept: Map<String, KeptMove> = emptyMap()
        override fun load(): KeptRead<Map<String, KeptMove>> = KeptRead.Read(kept)
        override fun save(memos: Map<String, KeptMove>) {
            kept = memos
        }
    }

    /**
     * Sealed to the account in [file] ([LocalRecords.MOVES]). [dropped] counts records this version could not read and
     * removed (round-10 review 3), for the notice that says so.
     */
    class SealedStore(private val file: FillSnapshotStore, private val records: LocalRecords, private val dropped: (Int) -> Unit) : Store {
        override fun load(): KeptRead<Map<String, KeptMove>> {
            val sealed = when (val r = file.readKept()) {
                is KeptRead.Read -> r.value ?: return KeptRead.Read(emptyMap())
                KeptRead.Locked -> return KeptRead.Locked
                KeptRead.Unreadable -> return KeptRead.Unreadable
            }
            return when (val opened = records.open(LocalRecords.MOVES, sealed)) {
                Unsealed.Locked -> KeptRead.Locked
                Unsealed.Failed -> KeptRead.Unreadable
                is Unsealed.Plain -> try {
                    decode(opened.bytes)?.let { KeptRead.Read(it) } ?: removed()
                } finally {
                    opened.bytes.fill(0)
                }
                // A memo that is not this account's own (its MAC does not hold, round-9 review 2) is never used, not
                // even as an "earlier version" record: a sealed box to the identity key alone is one any contact can
                // make, and under the clean break no genuine one exists. Removed and said.
                Unsealed.NotOurs -> removed()
            }
        }

        /** A record this version cannot read (it opens, but is not a list of plans): it is removed, and said. */
        private fun removed(): KeptRead<Map<String, KeptMove>> {
            runCatching { file.delete() }
            dropped(1)
            return KeptRead.Read(emptyMap())
        }


        private fun decode(plain: ByteArray): Map<String, KeptMove>? = runCatching { json.decodeFromString(serializer, plain.decodeToString()) }.getOrNull()

        override fun save(memos: Map<String, KeptMove>) {
            if (memos.isEmpty()) {
                runCatching { file.delete() }
                return
            }
            val plain = json.encodeToString(serializer, memos).encodeToByteArray()
            try {
                val sealed = records.seal(LocalRecords.MOVES, plain) ?: return // locked: the record stays as it was
                if (!file.write(sealed)) runCatching { file.delete() }
            } finally {
                plain.fill(0)
            }
        }


        private companion object {
            val json = Json { ignoreUnknownKeys = true }
            val serializer = MapSerializer(String.serializer(), KeptMove.serializer())
        }
    }

    /** What to do for a move or copy the person asked for. */
    sealed interface Prepared {
        /** Run this plan: the one an earlier try kept while the item is unchanged, or a new one. */
        class Run(val plan: MovePlan) : Prepared

        /** An earlier try's copy is in the target and the item changed since: nothing is planned. */
        class AlreadyCopied(val changedSince: Boolean) : Prepared

        /** [mint] made no plan (the caller has its reason): nothing is run. */
        object NotPlanned : Prepared

        /** The account is locked: nothing was read, nothing is run. */
        object Locked : Prepared

        /** What was kept could not be read: nothing is run, nothing kept is changed ([ContentCopy.MOVES_UNREADABLE]). */
        object Unreadable : Prepared
    }

    private val memos = LinkedHashMap<String, KeptMove>()
    private var loaded = false

    /** Why the last read gave nothing: [Prepared.Locked] or [Prepared.Unreadable]; null once a read succeeded. */
    private var notRead: Prepared? = null

    private fun key(itemId: String, targetVaultId: String, move: Boolean) = "$itemId|$targetVaultId|$move"

    /** The kept plans; null while they cannot be read (locked, or the record unreadable), and then nothing here changes them. */
    private fun memos(): MutableMap<String, KeptMove>? {
        if (!loaded) {
            val read = try {
                store.load()
            } catch (c: CancellationException) {
                throw c
            } catch (e: Exception) {
                KeptRead.Unreadable
            }
            when (read) {
                KeptRead.Locked -> {
                    notRead = Prepared.Locked
                    return null
                }
                KeptRead.Unreadable -> {
                    notRead = Prepared.Unreadable
                    return null
                }
                is KeptRead.Read -> {
                    memos.clear()
                    memos.putAll(read.value)
                    loaded = true
                    notRead = null
                }
            }
        }
        return memos
    }

    private fun persist() {
        runCatching { store.save(memos.toMap()) }
    }

    /** How many plans are kept to be finished; null while they cannot be read. */
    fun waiting(): Int? = memos()?.size

    /** Read what was kept now (at an unlock): a record this version cannot read is said at once, not at the next move. */
    fun check() {
        memos()
    }

    /**
     * Whether what was kept can be read now: null when it can, else [Prepared.Locked] or [Prepared.Unreadable], and then
     * a move must not run (a plan kept but not read would be planned afresh, and its copy made twice).
     */
    fun unreadable(): Prepared? = if (memos() == null) notRead ?: Prepared.Unreadable else null

    /** The plan kept for this move, if any; null when none was kept or nothing can be read now ([unreadable] tells). */
    fun kept(itemId: String, targetVaultId: String, move: Boolean): KeptMove? = memos()?.get(key(itemId, targetVaultId, move))

    /**
     * The plan for moving ([move]) or copying [itemId] at [itemRev] into [targetVaultId]. A kept plan was checked by
     * the caller after a sync ([copyInTarget]: whether its copy is in the target now); [mint] makes a new plan.
     * [Prepared.Locked] or [Prepared.Unreadable]: what was kept cannot be read now, and nothing is run or changed.
     */
    fun prepare(itemId: String, itemRev: Long, targetVaultId: String, move: Boolean, copyInTarget: Boolean, mint: () -> MovePlan?): Prepared {
        val all = memos() ?: return notRead ?: Prepared.Unreadable
        val k = key(itemId, targetVaultId, move)
        var kept = all[k]
        if (kept != null && !copyInTarget) {
            all.remove(k)
            persist()
            kept = null
        }
        // Here a kept plan's copy is in the target.
        if (kept != null && kept.gesture.sourceRev == itemRev) return Prepared.Run(kept.gesture.plan())
        if (kept != null) {
            if (!kept.copySeen) {
                all[k] = kept.seen()
                persist()
            }
            return Prepared.AlreadyCopied(changedSince = true)
        }
        val fresh = mint() ?: return Prepared.NotPlanned
        all[k] = KeptMove(KeptGesture.of(fresh))
        persist()
        return Prepared.Run(fresh)
    }

    /** The move or copy is done, or refused for good: its plan goes. */
    fun finished(itemId: String, targetVaultId: String, move: Boolean) {
        val all = memos() ?: return
        if (all.remove(key(itemId, targetVaultId, move)) != null) persist()
    }

    /** The copy was made and the original stayed (it changed, or could not be deleted): a later try must find the copy there. */
    fun copyMade(itemId: String, targetVaultId: String, move: Boolean) {
        val all = memos() ?: return
        val k = key(itemId, targetVaultId, move)
        all[k]?.let {
            all[k] = it.seen()
            persist()
        }
    }

    /** The person cancelled moving or copying [itemId]: every plan kept for it goes. A lock is not a cancel. */
    fun cancelled(itemId: String) {
        val all = memos() ?: return
        val mine = all.keys.filter { it.startsWith("$itemId|") }
        if (mine.isEmpty()) return
        mine.forEach(all::remove)
        persist()
    }

    /** The content closed (a lock): the plans leave memory; the store keeps them for the next unlock. */
    fun forget() {
        memos.clear()
        loaded = false
    }
}

/**
 * A kept plan, and whether its copy was seen in the target. The old `VaultMoves.Kept` without its `unverified` flag:
 * that marked plans carried over from a record without this account's MAC, and under the clean break (design §12.4)
 * no such record exists, so only a forger could make one. A stored `unverified` is ignored.
 */
@Serializable
internal class KeptMove(val gesture: KeptGesture, val copySeen: Boolean = false) {
    fun seen() = KeptMove(gesture, copySeen = true)
}

/**
 * A [MovePlan] under the old gesture's field names, so records written by either stack open in the other. The
 * mutation ids both derive (`sha256("gesture|<id>|copy")`, `…|delete`) are the same, so a replay converges either way.
 */
@Serializable
internal class KeptGesture(
    val gestureId: String,
    val sourceItemId: String,
    val sourceVaultId: String,
    val sourceRev: Long,
    val targetVaultId: String,
    val newItemId: String,
    val del: Boolean,
    val attachments: List<KeptGestureFile>,
) {
    fun plan() = MovePlan(gestureId, sourceItemId, sourceVaultId, sourceRev, targetVaultId, newItemId, del, attachments.map { MovedAttachment(it.oldId, it.newId, it.newFileKey, it.name, it.size) })

    companion object {
        fun of(p: MovePlan) = KeptGesture(
            p.planId, p.sourceItemId, p.sourceVaultId, p.sourceRev, p.targetVaultId, p.targetItemId, p.deleteSource,
            p.attachments.map { KeptGestureFile(it.oldId, it.newId, it.newFileKey, it.name, it.size) },
        )
    }
}

@Serializable
internal class KeptGestureFile(val oldId: String, val newId: String, val newFileKey: String, val name: String, val size: Long)
