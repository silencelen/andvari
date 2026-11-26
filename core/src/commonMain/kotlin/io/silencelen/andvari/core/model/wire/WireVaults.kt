package io.silencelen.andvari.core.model.wire

import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.nullable
import kotlinx.serialization.json.JsonObject

// =====================================================================================================
// The vault log (spec 03 §10)
// =====================================================================================================

/**
 * `POST /vaults/{vaultId}/log` (spec 03 §10.2, §10.3). [entry] is the signed 0x03 `frame` (≤ 1,500
 * chars). The side fields by kind:
 *
 * | kind | required side fields |
 * |---|---|
 * | `genesis` | [metaBlob] (`envelope` ≤ 4 KiB), [wrappedVk] (`envelope` ≤ 1 KiB, genesis-bound AD) |
 * | `add` | [grant] (`sealed` 0x01, ≤ 2,100 chars) |
 * | `accept` | [wrappedVk] (the new owner's genesis-bound wrap, round-trip-checked by the client first) |
 * | every other kind | none |
 *
 * A side field the kind does not take is `400 bad_request`; a required one missing or malformed is
 * `400 bad_<field>` ([sideFieldsFor]).
 */
@Serializable
data class LogAppendRequest(
    val entry: String,
    val grant: String? = null,
    val wrappedVk: String? = null,
    val metaBlob: String? = null,
    /**
     * `delete` only, unsigned, beside the entry: the sync `rev` up to which the caller read the vault's items. Any item of
     * the vault with a newer revision refuses the deletion with `409 vault_items_moved` and nothing is stored; null (sent as
     * no key) is no point, taken as before. Any other kind with it is `400 bad_request`.
     */
    val itemsAtMost: Long? = null,
) {
    companion object {
        /** The side fields each log kind takes (spec 03 §10.2); every other side field is refused. */
        fun sideFieldsFor(kind: String): Set<String> = when (kind) {
            LogKind.GENESIS -> setOf("metaBlob", "wrappedVk")
            LogKind.ADD -> setOf("grant")
            LogKind.ACCEPT -> setOf("wrappedVk")
            else -> emptySet()
        }
    }

    /** The side fields this body carries, by JSON name. */
    fun presentSideFields(): Set<String> = buildSet {
        if (grant != null) add("grant")
        if (wrappedVk != null) add("wrappedVk")
        if (metaBlob != null) add("metaBlob")
    }
}

/** The log entry kinds (spec 03 §10.1, design §3.1). */
object LogKind {
    const val GENESIS = "genesis"
    const val ADD = "add"
    const val ROLE = "role"
    const val REMOVE = "remove"
    const val LEAVE = "leave"
    const val OFFER = "offer"
    const val CANCEL = "cancel"
    const val ACCEPT = "accept"
    const val DELETE = "delete"
    const val RESTORE = "restore"
    val ALL: Set<String> = setOf(GENESIS, ADD, ROLE, REMOVE, LEAVE, OFFER, CANCEL, ACCEPT, DELETE, RESTORE)
}

/**
 * `200 {rev, head, deleted?}`: the global rev after the append, the log head as the caller may see it, and
 * [deleted] while the vault is in its grace (spec 03 §10.3; absent on an older server). [deleted] is the
 * server's word only, read leniently ([LogDeletedLenient]); see [LogDeleted].
 */
@Serializable
data class LogAppendResponse(
    val rev: Long,
    val head: LogHead,
    @Serializable(with = LogDeletedLenient::class) val deleted: LogDeleted? = null,
)

/**
 * `deleted: {deletedAt, purgeAt}` (`ms` both, spec 03 §10.3, §10.6, §11.1): when the server stored the vault's
 * `delete` and when it will purge the vault. The server sends it while the vault is in its grace and the head it
 * gives is the vault's current head; an older server never sends it.
 *
 * THIS IS THE SERVER'S WORD AND NOTHING MORE. A client keeps it beside the `delete` it verified in the log and shows
 * "restorable until [purgeAt]" from it; nothing else may depend on it. No device deletes, closes, purges, hides or
 * refuses anything because of [purgeAt] or [deletedAt]: whether a vault is deleted is the verified log's `delete`,
 * and whether it is gone is the verified tombstone ([LogPage.purged] after a verified `delete`), never this value.
 * A server can put any date here; the worst it does is show a wrong date.
 *
 * Decoded through [LogDeletedLenient]: a `deleted` that is not an object of two whole numbers, a negative value, or a
 * [purgeAt] before [deletedAt] reads as absent, so a malformed advisory field never fails the log fetch it rides on.
 */
@Serializable
data class LogDeleted(val deletedAt: Long, val purgeAt: Long)

/**
 * The lenient reading of `deleted` ([LogDeleted]): anything but `{deletedAt: <whole number ≥ 0>, purgeAt: <whole
 * number ≥ deletedAt>}` (strings, fractions, exponents, missing keys, `null`, another JSON type) is null, never an
 * exception. Encodes as [LogDeleted] does.
 */
@OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
object LogDeletedLenient : kotlinx.serialization.KSerializer<LogDeleted?> {
    override val descriptor: kotlinx.serialization.descriptors.SerialDescriptor = LogDeleted.serializer().descriptor.nullable

    override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: LogDeleted?) {
        if (value == null) encoder.encodeNull() else encoder.encodeSerializableValue(LogDeleted.serializer(), value)
    }

    override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): LogDeleted? {
        val json = decoder as? kotlinx.serialization.json.JsonDecoder
            ?: return runCatching { decoder.decodeSerializableValue(LogDeleted.serializer()) }.getOrNull()
        return read(json.decodeJsonElement())
    }

    /** [LogDeleted] from a decoded `deleted` value, or null when it is not one ([LogDeletedLenient]'s rule). */
    fun read(element: kotlinx.serialization.json.JsonElement): LogDeleted? {
        val o = element as? JsonObject ?: return null
        fun whole(name: String): Long? {
            val p = o[name] as? kotlinx.serialization.json.JsonPrimitive ?: return null
            if (p.isString || p is kotlinx.serialization.json.JsonNull) return null
            // Only plain digits: `1.0`, `1e3` and `+1` are not whole numbers on this wire.
            if (p.content.isEmpty() || !p.content.all { it in '0'..'9' }) return null
            return p.content.toLongOrNull()
        }
        val deletedAt = whole("deletedAt") ?: return null
        val purgeAt = whole("purgeAt") ?: return null
        return if (purgeAt < deletedAt) null else LogDeleted(deletedAt, purgeAt)
    }
}

/**
 * `GET /vaults/{vaultId}/log?after=<seq>` (spec 03 §10.6): at most 500 [entries] (0x03 `frame`s) in
 * ascending `seq`, each `> after`; [head] the last entry the caller may see; [purged] once purged; [deleted]
 * while the vault is in its grace (absent on an older server; the server's word only, see [LogDeleted]).
 * A client verifies every page and acts only on what it verified, never on [head], [purged] or [deleted] alone.
 */
@Serializable
data class LogPage(
    val entries: List<String>,
    val head: LogHead,
    val purged: LogPurged? = null,
    @Serializable(with = LogDeletedLenient::class) val deleted: LogDeleted? = null,
)

/** `purged: {purgedAt}` (`ms`) of a purged vault's log (spec 03 §11.1). */
@Serializable
data class LogPurged(val purgedAt: Long)

/**
 * `GET /vaults/{vaultId}/members` (spec 03 §10.7): the server's view of the active grants. A client
 * shows a member's label only where the verified log's member key equals that person's pinned key;
 * otherwise "unverified member (as the server names them)".
 */
@Serializable
data class VaultMemberSummary(
    val userId: String,
    val email: String,
    val displayName: String,
    val role: String,
    /** `b64_32`. Never pinned from here (design §3.9). */
    val identityPub: String,
    val addedAt: Long,
    /** account status, present for a disabled account */
    val status: String? = null,
)

/** `GET /vaults/deleted` (spec 03 §11.2): the in-grace vaults the caller owned when deleted. */
@Serializable
data class DeletedVaultSummary(
    val vaultId: String,
    /** `envelope` */
    val metaBlob: String,
    /** `envelope` (owner wrap) */
    val wrappedVk: String,
    val deletedAt: Long,
    val purgeAt: Long,
    /** `b64_16`, the `delete` entry's id */
    val deleteId: String,
)

/** `PUT /vaults/{vaultId}/meta` (spec 03 §11.3). → [RevResponse]. */
@Serializable
data class VaultMetaPut(val metaBlob: String, val baseVaultRev: Long? = null)

/** `PUT /vaults/{vaultId}/grant/self-wrap` (spec 03 §11.4): the member's genesis-bound UVK wrap. → [RevResponse]. */
@Serializable
data class SelfWrapPut(val wrappedVk: String)
