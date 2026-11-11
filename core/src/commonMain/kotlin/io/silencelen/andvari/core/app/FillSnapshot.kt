package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * What the iOS AutoFill extension reads instead of the vault cache (design 2026-11-09, "AutoFill"): the rows the
 * app's last sync left, exactly as the server sent them. Nothing here is plaintext: the items are sealed under their
 * vault keys, the grants and the account keys are wrapped blobs, and the UVK that opens them is only in the Secure
 * Enclave-wrapped quick-unlock blob. No token is in it.
 */
@Serializable
data class FillSnapshot(
    val v: Int = VERSION,
    /** The canonical origin this account lives at; a reader that dials another origin ignores the snapshot. */
    val origin: String,
    val userId: String,
    val email: String,
    val keys: AccountKeys,
    val vaults: List<WireVault>,
    val grants: List<WireGrant>,
    val items: List<WireItem>,
    val writtenAtMs: Long,
) {
    fun encode(): ByteArray = json.encodeToString(serializer(), this).encodeToByteArray()

    companion object {
        const val VERSION = 1
        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

        /** Null for anything that is not a snapshot of this version: a torn or foreign file is "no snapshot". */
        fun decode(bytes: ByteArray): FillSnapshot? =
            runCatching { json.decodeFromString(serializer(), bytes.decodeToString()) }.getOrNull()?.takeIf { it.v == VERSION }
    }
}

/** Where the snapshot is kept: one file, replaced atomically (iOS: the App Group container). Never throws. */
interface FillSnapshotStore {
    /** Replace the snapshot. Returns whether it was written. */
    fun write(bytes: ByteArray): Boolean

    fun read(): ByteArray?

    fun delete()

    /** A host with no extension to feed. */
    object None : FillSnapshotStore {
        override fun write(bytes: ByteArray) = false
        override fun read(): ByteArray? = null
        override fun delete() {}
    }
}

/** [FillSnapshotStore] in memory (tests). */
class InMemoryFillSnapshots : FillSnapshotStore {
    var bytes: ByteArray? = null
    var writes = 0

    /** When set, a write fails and changes nothing (a full disk). */
    var refuse = false

    override fun write(bytes: ByteArray): Boolean {
        if (refuse) return false
        this.bytes = bytes
        writes++
        return true
    }

    override fun read(): ByteArray? = bytes

    override fun delete() {
        bytes = null
    }
}
