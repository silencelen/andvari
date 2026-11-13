package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.CopyDeniedException
import io.silencelen.andvari.core.client.ItemChangedException
import io.silencelen.andvari.core.client.MoveGesture
import io.silencelen.andvari.core.client.SourceDeleteDeniedException
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.VaultInfo
import io.silencelen.andvari.core.client.VaultItem
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

/**
 * Which vaults an item may go to, and moving or copying it there (design §8, F18/F19). One implementation for
 * Android's view model and the iOS controller (round-6 review L6):
 *  - A new item, a move or a copy goes only to a vault this account can write and seal for: its personal vault, or a
 *    shared vault it owns or writes, whose key it holds ([writableVaults]).
 *  - A move deletes the original, so it also needs the item's own vault writable ([canTakeOut]); a copy only reads
 *    the item, so an item in a vault this account only reads can still be copied out.
 *  - A try that did not finish keeps its gesture (the ids it minted) until the move is done or the person cancels it:
 *    another try replays the same ids, and the server's dedup converges instead of making a second copy. Where the
 *    item changed since a try that already copied it, no new gesture is minted while that copy is in the target
 *    (round-6 review L5): the person is told it is there.
 *  - A kept gesture is replayed only while its copy is in the target, as a sync just before shows it (round-7 review
 *    M3, round-8 review M): the server answers a replayed copy leg from its journal without making the copy again, so
 *    a copy deleted since would let the delete leg remove the only original. That holds whatever ended the earlier try
 *    (a timeout of the delete leg, or the app being stopped after the copy leg, is TRANSIENT and says nothing of the
 *    copy). A copy that is not there drops the gesture, and a new one (a new copy) is minted. The cost: a copy leg
 *    still in flight when the next try starts lands as a second copy, never as a lost original.
 *
 * Not thread-safe: each platform calls it from one place (Android's main dispatcher, iOS's actions).
 */
class VaultMoves(private val store: Store = Store.Memory()) {
    /** Where the kept gestures live: this object's memory, or sealed in app-private storage across a lock (iOS). */
    interface Store {
        /** What was kept; empty when nothing was, or when it cannot be read now. */
        fun load(): Map<String, Kept>

        /** Keep [memos], all of them; empty removes what was kept. */
        fun save(memos: Map<String, Kept>)

        /**
         * Kept in [file] (app-private storage), sealed to the signed-in account ([account], null while locked): a lock
         * leaves nothing of it in memory, and only that account opens it. Nothing is read or written while locked; an
         * empty save removes the file whatever the state.
         */
        class Sealed(private val file: FillSnapshotStore, private val account: () -> Account?) : Store {
            override fun load(): Map<String, Kept> {
                val owner = account() ?: return emptyMap()
                val sealed = file.read() ?: return emptyMap()
                val plain = runCatching { owner.openQueuedSave(sealed) }.getOrNull() ?: return emptyMap()
                return try {
                    runCatching { json.decodeFromString(serializer, plain.decodeToString()) }.getOrDefault(emptyMap())
                } finally {
                    plain.fill(0)
                }
            }

            override fun save(memos: Map<String, Kept>) {
                if (memos.isEmpty()) {
                    file.delete()
                    return
                }
                val owner = account() ?: return
                val plain = json.encodeToString(serializer, memos).encodeToByteArray()
                try {
                    if (!file.write(owner.cryptoProvider().sealTo(owner.identityPub, plain))) file.delete()
                } finally {
                    plain.fill(0)
                }
            }

            private companion object {
                val json = Json { ignoreUnknownKeys = true }
                val serializer = MapSerializer(String.serializer(), Kept.serializer())
            }
        }

        /** Kept only here, in memory (tests). */
        class Memory : Store {
            private var kept: Map<String, Kept> = emptyMap()

            override fun load(): Map<String, Kept> = kept

            override fun save(memos: Map<String, Kept>) {
                kept = memos
            }
        }
    }

    /** A kept gesture, and whether its copy was seen in the target (a try that failed after the copy was made). */
    @Serializable
    data class Kept(val gesture: MoveGesture, val copySeen: Boolean = false)

    /** What to do for a move or copy the person asked for. */
    sealed class Prepared {
        /** Run this gesture: the one an earlier try kept while the item is unchanged, or a new one. */
        class Run(val gesture: MoveGesture) : Prepared()

        /** An earlier try already copied the item into the target, and the item changed since: nothing new is minted. */
        class AlreadyCopied(val copyItemId: String) : Prepared()
    }

    /** How a gesture that threw ended, and what became of its memo. */
    enum class Failure {
        /** The target refused the copy: nothing was made, and the gesture goes. */
        COPY_DENIED,

        /** The copy was made, but the item changed in its own vault meanwhile, so the original was kept: it is in both. */
        CHANGED_AFTER_COPY,

        /** The copy was made, but the original could not be removed (access to its vault changed): it is in both. */
        ORIGINAL_KEPT,

        /** The server refused this account (its access changed): the gesture goes. */
        FORBIDDEN,

        /** Anything else: the gesture is kept, and another try replays the same ids. */
        TRANSIENT,
    }

    private val memos = LinkedHashMap<String, Kept>()
    private var loaded = false

    private fun key(itemId: String, targetVaultId: String, move: Boolean) = "$itemId|$targetVaultId|$move"

    private fun memos(): MutableMap<String, Kept> {
        if (!loaded) {
            memos.putAll(runCatching { store.load() }.getOrDefault(emptyMap()))
            loaded = true
        }
        return memos
    }

    private fun persist() {
        runCatching { store.save(memos.toMap()) }
    }

    /**
     * The gesture for moving ([move]) or copying [item] into [targetVaultId], or that an earlier try's copy is there.
     * Any kept gesture is checked against the target after [sync] first (round-8 review M); a sync that fails throws,
     * and nothing is replayed unchecked.
     */
    suspend fun prepare(engine: SyncEngine, item: VaultItem, targetVaultId: String, move: Boolean, sync: suspend () -> Unit): Prepared {
        val k = key(item.itemId, targetVaultId, move)
        var kept = memos()[k]
        if (kept != null) {
            sync()
            if (engine.item(kept.gesture.newItemId)?.vaultId != targetVaultId) {
                memos.remove(k)
                persist()
                kept = null
            }
        }
        // Here a kept gesture's copy is in the target.
        if (kept != null && kept.gesture.sourceRev == item.rev) return Prepared.Run(kept.gesture)
        if (kept != null) {
            if (!kept.copySeen) {
                memos[k] = kept.copy(copySeen = true)
                persist()
            }
            return Prepared.AlreadyCopied(kept.gesture.newItemId)
        }
        val fresh = engine.newMoveGesture(item.itemId, targetVaultId, move)
        memos[k] = Kept(fresh)
        persist()
        return Prepared.Run(fresh)
    }

    /** The move or copy is done: its gesture goes. */
    fun finished(itemId: String, targetVaultId: String, move: Boolean) {
        if (memos().remove(key(itemId, targetVaultId, move)) != null) persist()
    }

    /** The gesture threw [t]: what that means, with the memo kept or dropped as [Failure] says. */
    fun failed(itemId: String, targetVaultId: String, move: Boolean, t: Throwable): Failure {
        val failure = when {
            t is CopyDeniedException -> Failure.COPY_DENIED
            t is ItemChangedException -> Failure.CHANGED_AFTER_COPY
            t is SourceDeleteDeniedException -> Failure.ORIGINAL_KEPT
            t is ApiException && t.status == 403 -> Failure.FORBIDDEN
            else -> Failure.TRANSIENT
        }
        val k = key(itemId, targetVaultId, move)
        if (failure == Failure.COPY_DENIED || failure == Failure.FORBIDDEN) {
            if (memos().remove(k) != null) persist()
        } else if (failure == Failure.CHANGED_AFTER_COPY || failure == Failure.ORIGINAL_KEPT) {
            // The copy was made and seen: a later replay must find it still there (M3).
            memos()[k]?.let {
                memos[k] = it.copy(copySeen = true)
                persist()
            }
        }
        return failure
    }

    /** The person cancelled moving or copying [itemId]: every gesture kept for it goes. */
    fun cancelled(itemId: String) {
        val mine = memos().keys.filter { it.startsWith("$itemId|") }
        if (mine.isEmpty()) return
        mine.forEach(memos::remove)
        persist()
    }

    /** A lock: the gestures leave memory; the store keeps them for the next unlock. */
    fun forget() {
        memos.clear()
        loaded = false
    }

    /** The account is going (sign-out, a server switch, an ended session): every gesture goes, stored ones too. */
    fun drop() {
        memos.clear()
        loaded = true
        persist()
    }

    companion object {
        /**
         * The vaults an item can be written into: the personal vault, then the shared vaults this account owns or writes,
         * each one whose key it holds ([canSealUnder]). The order of [vaults] is kept.
         */
        fun writableVaults(vaults: List<VaultInfo>, canSealUnder: (String) -> Boolean): List<VaultInfo> =
            vaults.filter { (it.type == "personal" || it.role == "owner" || it.role == "writer") && canSealUnder(it.vaultId) }

        /** Where an item in [itemVaultId] can be moved or copied: the writable vaults but its own. */
        fun targets(itemVaultId: String, vaults: List<VaultInfo>, canSealUnder: (String) -> Boolean): List<VaultInfo> =
            writableVaults(vaults, canSealUnder).filter { it.vaultId != itemVaultId }

        /** Whether this account may take an item out of [itemVaultId] (a move deletes it there): not a reader of it. */
        fun canTakeOut(itemVaultId: String, vaults: List<VaultInfo>): Boolean =
            vaults.any { it.vaultId == itemVaultId && (it.type == "personal" || it.role == "owner" || it.role == "writer") }

        /** What a failed move says when the item is now in both vaults, naming the copy and where it went. */
        fun bothVaultsLine(failure: Failure, item: String, target: String, source: String): String? = when (failure) {
            Failure.CHANGED_AFTER_COPY ->
                "Copied “$item” to “$target”, but it changed in “$source” meanwhile, so the original was kept there. It is in both vaults now: review them and delete the one you don't need."
            Failure.ORIGINAL_KEPT ->
                "Copied “$item” to “$target”, but the original couldn't be removed from “$source” (your access there may have changed). It is in both vaults now."
            else -> null
        }

        /** What a try says when an earlier try's copy is already in the target and the item changed since. */
        fun alreadyCopiedLine(item: String, target: String): String =
            "An earlier try already copied “$item” to “$target”, and it has changed since, so nothing more was done. Cancel to start over, or delete the copy you don't need."
    }
}
