package io.silencelen.andvari.core.model.wire

import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.builtins.serializer

// =====================================================================================================
// Sync pull (spec 03 §4)
// =====================================================================================================

/**
 * `GET /sync?since=<rev>` (spec 03 §4). A client MUST NOT apply a non-full response whose [rev] is below
 * its cursor, nor an unsolicited [full] snapshot when it pulled with `since>0` (spec 05 T1).
 *
 * [linkAnswers] and [recoveryRequests] are counts that only tell a device to call
 * `GET /links/answers` / `GET /account/recovery-requests`; they decide nothing.
 */
@Serializable
data class SyncResponse(
    val rev: Long,
    val full: Boolean,
    val vaults: List<SyncVault>,
    val grants: List<SyncGrant>,
    val items: List<SyncItem>,
    /** `uuid`s of vaults the caller lost access to (spec 02 §10.6). */
    val removedGrants: List<String>,
    val removedGrantsInfo: List<RemovedGrantInfo>,
    val linkAnswers: Int,
    val recoveryRequests: Int,
    /**
     * The caller's own use and limits (spec 03 §4, §14.4 "What an account is told"; added 2026-11-16, additive). Null
     * when an older server sent none, and when the object it sent cannot be one ([QuotaUseOrUnknown]): unknown.
     */
    @Serializable(with = QuotaUseOrUnknown::class)
    val quota: QuotaUse? = null,
    /**
     * The account state's counter in the same snapshot (spec 03 §4, added 2026-11-16, additive): the `seq` of
     * `GET /account/state`, 0 before the first write; each write advances it and nothing lowers it. A device whose own
     * copy was read or written at this counter knows that no other device of the account has written since. Null when
     * an older server sent none, and when what it sent is not a whole number at least 0 ([CounterOrUnknown]): "not
     * served", and the device reads the state as it did before the counter existed. It is a hint to read, never a
     * verdict: a counter that stands still while another device wrote withholds that write until the counter moves,
     * which the server could do anyway by serving an older state.
     */
    @Serializable(with = CounterOrUnknown::class)
    val accountStateSeq: Long? = null,
)

/**
 * A counter's decoder: a JSON number that is a whole number from 0 to `Long.MAX_VALUE` is the counter; anything else (a
 * string, a fraction, a negative or too large number, `null`, an object) is null, "not served", and never fails the
 * answer that carries it.
 */
object CounterOrUnknown : kotlinx.serialization.KSerializer<Long?> {
    private val plain = Long.serializer().nullable

    override val descriptor: kotlinx.serialization.descriptors.SerialDescriptor = plain.descriptor

    override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): Long? {
        if (decoder !is kotlinx.serialization.json.JsonDecoder) return decoder.decodeSerializableValue(plain)?.takeIf { it >= 0 }
        val p = decoder.decodeJsonElement() as? kotlinx.serialization.json.JsonPrimitive ?: return null
        if (p.isString || p is kotlinx.serialization.json.JsonNull) return null
        return p.content.toLongOrNull()?.takeIf { it >= 0 }
    }

    override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: Long?) {
        encoder.encodeSerializableValue(plain, value)
    }
}

// =====================================================================================================
// An account's own use and limits (spec 03 §14.4, "What an account is told")
// =====================================================================================================

/**
 * One per-account limit (spec 03 §14.4): [used], counted exactly as the server's quota check counts it, and [limit],
 * the limit in force (the account's own override, else the instance default). Both whole numbers, at least 0.
 */
@Serializable
data class QuotaMeter(val used: Long, val limit: Long)

/**
 * `quota` on `GET /sync` (index row 36) and on each `GET /admin/accounts` row (row 73): one [QuotaMeter] per
 * [QuotaName], so the `quota` of a `413 quota_exceeded {quota}` names the meter that refused. It is the account's own
 * and says nothing of the room in a shared vault someone else owns. A client checks it before a large copy through
 * `io.silencelen.andvari.core.client.items.QuotaCheck`; the server's refusal stays authoritative.
 */
@Serializable
data class QuotaUse(
    val accountBytes: QuotaMeter,
    val items: QuotaMeter,
    val ownedSharedVaults: QuotaMeter,
    val openLinks: QuotaMeter,
) {
    /** Every number is at least 0, as spec 03 §14.4 says each is. */
    fun isWhole(): Boolean = listOf(accountBytes, items, ownedSharedVaults, openLinks).all { it.used >= 0 && it.limit >= 0 }
}

/**
 * The `quota` field's decoder: an object that is not a [QuotaUse] of whole numbers (a key missing, a number negative,
 * fractional, quoted or past a `Long`, not an object at all) is read as null, "unknown", and never fails the answer
 * that carries it. The meters only ever let a client refuse early (spec 03 §14.4), so a server that lies in them must
 * not be able to break the sync or the operator's account list with them either. Encoding is the plain [QuotaUse].
 */
object QuotaUseOrUnknown : kotlinx.serialization.KSerializer<QuotaUse?> {
    private val plain = QuotaUse.serializer().nullable

    override val descriptor: kotlinx.serialization.descriptors.SerialDescriptor = plain.descriptor

    override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): QuotaUse? {
        if (decoder !is kotlinx.serialization.json.JsonDecoder) return decoder.decodeSerializableValue(plain)?.takeIf { it.isWhole() }
        val element = decoder.decodeJsonElement()
        if (element !is kotlinx.serialization.json.JsonObject) return null
        val q = try {
            WireJson.json.decodeFromJsonElement(QuotaUse.serializer(), element)
        } catch (e: kotlinx.serialization.SerializationException) {
            return null
        } catch (e: IllegalArgumentException) {
            return null
        }
        return q.takeIf { it.isWhole() }
    }

    override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: QuotaUse?) {
        encoder.encodeSerializableValue(plain, value)
    }
}

/**
 * A changed vault row (spec 03 §4): `{vaultId, type, rev, metaBlob, createdAt, logHead?}`.
 * [type] is [VaultType]. [logHead] rides every shared vault row and is a hint to fetch the log, never
 * a verdict (design §3.9); personal vaults carry none.
 */
@Serializable
data class SyncVault(
    val vaultId: String,
    val type: String,
    val rev: Long,
    /** `envelope` */
    val metaBlob: String,
    val createdAt: Long,
    val logHead: SyncLogHead? = null,
)

/** `SyncVault.type` values. */
object VaultType {
    const val PERSONAL = "personal"
    const val SHARED = "shared"
}

/**
 * The caller's own grant row (spec 03 §4): `{vaultId, userId, role, wrappedVk, rev, signedGrant?}`.
 *
 * - An owner grant carries [wrappedVk] (under the UVK, genesis-bound AD for a shared vault).
 * - A member grant carries [signedGrant] (the sealed 0x01 grant of the `add` that admitted it) and an
 *   EMPTY [wrappedVk] until the member posts a self-wrap (§11.4); then both.
 *
 * [role] is the server's view. A device acts on the role in the vault's verified log (design §3.3), and
 * adopts a key only under design §3.6; nothing on this row is trusted as served.
 */
@Serializable
data class SyncGrant(
    val vaultId: String,
    val userId: String,
    val role: String,
    val wrappedVk: String,
    val rev: Long,
    /** `sealed` 0x01 grant */
    val signedGrant: String? = null,
)

/**
 * A changed item, tombstones included. Spec 03 §4 does not restate the item row's fields; this is the
 * existing item shape (spec 02 §3 / today's server), unchanged by the overhaul.
 */
@Serializable
data class SyncItem(
    val itemId: String,
    val vaultId: String,
    val rev: Long,
    val createdAt: Long,
    val updatedAt: Long,
    val deleted: Boolean,
    val conflict: Boolean,
    val formatVersion: Int,
    val attachmentIds: List<String>,
    /** `envelope`, null on a tombstone. */
    val blob: String?,
)

/**
 * The companion detail of `removedGrants` (spec 03 §4): `{vaultId, reason, deletedAt?, purgeAt?}`.
 * A hint only: what a device believes about a removal comes from the vault's verified log.
 */
@Serializable
data class RemovedGrantInfo(
    val vaultId: String,
    /** [RemovedReason] value. */
    val reason: String,
    val deletedAt: Long? = null,
    val purgeAt: Long? = null,
)

/** `RemovedGrantInfo.reason` values. */
object RemovedReason {
    const val REMOVED = "removed"
    const val LEFT = "left"
    const val DELETED = "deleted"
}

// =====================================================================================================
// Sync push (spec 03 §5)
// =====================================================================================================

/** `POST /sync/push` (spec 03 §5): at most 200 mutations. */
@Serializable
data class PushRequest(val mutations: List<Mutation>)

/** One mutation. [op] is `put` or `delete`; [item] only on `put`. [baseItemRev] 0 = creating. */
@Serializable
data class Mutation(
    val mutationId: String,
    val op: String,
    val itemId: String,
    val vaultId: String,
    val baseItemRev: Long,
    val item: ItemUpload? = null,
)

/** `Mutation.op` values. */
object MutationOp {
    const val PUT = "put"
    const val DELETE = "delete"
}

/** An item body: of a push `put` (§5) and of `POST /items/{id}/restore` (§5.1). */
@Serializable
data class ItemUpload(
    val formatVersion: Int,
    val attachmentIds: List<String>,
    /** `envelope` */
    val blob: String,
)

/** `200 {rev, results}` (spec 03 §5). */
@Serializable
data class PushResponse(val rev: Long, val results: List<MutationResult>)

/** One per-mutation result. [status] is a [MutationStatus] value; [reason] rides `rejected` only. */
@Serializable
data class MutationResult(
    val mutationId: String,
    val status: String,
    val newItemRev: Long? = null,
    val serverItem: SyncItem? = null,
    val reason: String? = null,
    /**
     * Spec 03 §5: the server had a stored item for this result and left it out (an answer carries each stored item at
     * most once and at most 8 MiB of items in all). It is NOT "nothing stored": the client pulls to get it. An optional
     * field: absent (null) unless true.
     */
    val serverItemOmitted: Boolean? = null,
)

/** `MutationResult.status` values. An unknown status is "definitive — dequeue" (spec 03 §5). */
object MutationStatus {
    const val APPLIED = "applied"
    const val CONFLICT = "conflict"
    const val DENIED = "denied"
    const val REJECTED = "rejected"
}

// =====================================================================================================
// Items (spec 03 §4, §5.1)
// =====================================================================================================

/** `GET /items/{itemId}/versions`: newest first. */
@Serializable
data class ItemVersionsResponse(val itemId: String, val versions: List<ItemVersion>)

/** One archived version: `{rev, blob, formatVersion, archivedAt}`. */
@Serializable
data class ItemVersion(val rev: Long, val blob: String, val formatVersion: Int, val archivedAt: Long)

/** `GET /items/deleted`: `{items: [{itemId, vaultId, deletedAt}]}`. */
@Serializable
data class DeletedItemsResponse(val items: List<DeletedItem>)

@Serializable
data class DeletedItem(val itemId: String, val vaultId: String, val deletedAt: Long)

/** `{rev}`: the answer of item restore and purge (§5.1), vault rename and self-wrap (§11.3, §11.4). */
@Serializable
data class RevResponse(val rev: Long)

// =====================================================================================================
// Attachments and events (spec 03 §9, §6)
// =====================================================================================================

/**
 * `POST /attachments/{attachmentId}?vaultId=&itemId=` → `200 AttachmentMeta` (spec 03 §9). Spec 03
 * names what the server records (`size`, `sha256(ciphertext)`, header) but not the answer's fields;
 * this is today's shape.
 */
@Serializable
data class AttachmentMeta(
    val attachmentId: String,
    val itemId: String,
    val vaultId: String,
    val size: Long,
    /** lowercase hex SHA-256 of the stored bytes */
    val sha256: String,
    val createdAt: Long,
)

/** `POST /events/ticket` (spec 03 §6): a single-use 30 s WebSocket ticket. */
@Serializable
data class EventsTicketResponse(val ticket: String, val expiresInSeconds: Long)

/**
 * A server → client WebSocket JSON frame (spec 03 §6), exhaustively `{"type":"rev","rev":N}` or
 * `{"type":"revoked"}`. The text frame `pong` is not JSON and never decoded here.
 */
@Serializable
data class EventFrame(val type: String, val rev: Long? = null) {
    companion object {
        const val REV = "rev"
        const val REVOKED = "revoked"
        const val PING = "ping"
        const val PONG = "pong"
    }
}
