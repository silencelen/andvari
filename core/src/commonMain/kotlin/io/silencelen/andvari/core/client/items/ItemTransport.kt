package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.net.BODY_OVER_LIMIT
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.AttachmentMeta
import io.silencelen.andvari.core.model.wire.DeletedItem
import io.silencelen.andvari.core.model.wire.DeletedVaultSummary
import kotlinx.serialization.builtins.ListSerializer
import io.silencelen.andvari.core.model.wire.DeletedItemsResponse
import io.silencelen.andvari.core.model.wire.ItemUpload
import io.silencelen.andvari.core.model.wire.ItemVersion
import io.silencelen.andvari.core.model.wire.ItemVersionsResponse
import io.silencelen.andvari.core.model.wire.Mutation
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.RevResponse
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.VaultMetaPut
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.CancellationException

/**
 * The item plane's wire (spec 03 §4, §5, §5.1, §9): everything [ItemEngine] ever sends or receives. One instance
 * talks to ONE origin as ONE signed-in account; the session's bearer is the implementation's business
 * ([WireItemTransport] takes the session's own [WireClient]), never the engine's.
 *
 * **Contract.**
 * - Every call answers a [WireResult]: [WireResult.Ok], a refusal in the server's envelope ([WireResult.Refused], keyed
 *   on its `code`, spec 03 §0.1), or [WireResult.NoAnswer] (transport, timeout, a proxy's page). Nothing throws except
 *   cancellation. After [WireResult.NoAnswer] the outcome of a write is UNKNOWN: the engine keeps the row queued and
 *   re-sends it under the same `mutationId`.
 * - The transport moves ciphertext and server-visible metadata only (spec 02 §5). It never sees a key or a plaintext
 *   document, and it decides nothing: no retry policy beyond the session's one refresh, no caching, no id minting.
 * - It does not check served ids. The engine does, at its one pull boundary (spec 03 §5 `bad_item_id`, spec 05 R18).
 * - [pull] with a cursor the server no longer retains answers `410 resync_required`
 *   ([WireErrors.RESYNC_REQUIRED]); the engine then pulls from 0 (spec 03 §4).
 * - [push] carries at most 200 mutations and is one transaction on the server (spec 03 §5). A refusal with status
 *   400 or 413 is a definitive refusal of that batch as sent; any other refusal or no answer leaves the rows queued.
 * - [downloadAttachment] answers EXACTLY [expectedBytes] bytes (the header and the ciphertext, spec 02 §6) or a
 *   refusal with [ATTACHMENT_SIZE_MISMATCH]; it never buffers past the claim.
 * - The event bell (spec 03 §6) is not part of this interface: it carries no data, and the host that owns the socket
 *   (or the poll timer) calls [ItemEngine.sync] when it rings.
 */
interface ItemTransport {
    /** `GET /sync?since=` (spec 03 §4). */
    suspend fun pull(since: Long): WireResult<SyncResponse>

    /** `POST /sync/push` (spec 03 §5). */
    suspend fun push(mutations: List<Mutation>): WireResult<PushResponse>

    /** `GET /items/{itemId}/versions`, newest first (spec 03 §4). */
    suspend fun versions(itemId: String): WireResult<List<ItemVersion>>

    /**
     * One page of `GET /items/deleted[?after=<deletedAt>:<itemId>]` (spec 03 §5.1): at most [TRASH_PAGE_ROWS] rows, newest
     * first in `(deletedAt, itemId)` descending order, starting after the row [after] names (null: the first page).
     */
    suspend fun deletedItems(after: String? = null): WireResult<List<DeletedItem>>

    /** `POST /items/{itemId}/restore` (spec 03 §5.1): the new global rev. */
    suspend fun restore(itemId: String, item: ItemUpload): WireResult<Long>

    /** `POST /items/{itemId}/purge` (spec 03 §5.1): the new global rev. */
    suspend fun purge(itemId: String): WireResult<Long>

    /** `POST /attachments/{attachmentId}?vaultId=&itemId=` (spec 03 §9); [body] is the header and the ciphertext. */
    suspend fun uploadAttachment(attachmentId: String, itemId: String, vaultId: String, body: ByteArray): WireResult<AttachmentMeta>

    /** `GET /attachments/{attachmentId}` (spec 03 §9), exactly [expectedBytes] long. */
    suspend fun downloadAttachment(attachmentId: String, expectedBytes: Long): WireResult<ByteArray>

    /**
     * `PUT /vaults/{vaultId}/meta` (spec 03 §11.3): a rename. The name is ciphertext under the vault key and changes
     * nobody's access, so it is not a log entry; it travels with the item plane. The new global rev.
     */
    suspend fun putVaultMeta(vaultId: String, metaBlob: String, baseVaultRev: Long?): WireResult<Long>

    /**
     * `GET /hibp/range/{prefix}` (spec 03 §8): the k-anonymity breach range relay, for Vault Health. [prefix] is the
     * first 5 hex characters of an ITEM password's SHA-1 and nothing else (never the master password's or a backup
     * passphrase's); the answer is the upstream's "SUFFIX:COUNT" lines, matched on this device.
     */
    suspend fun hibpRange(prefix: String): WireResult<String>

    /**
     * `GET /vaults/deleted` (spec 03 §11.2): the in-grace vaults this account owned when they were deleted, for the
     * owner's "Recently deleted" list. Served rows, checked by the engine; the wraps in them are never opened.
     */
    suspend fun deletedVaults(): WireResult<List<DeletedVaultSummary>>

    companion object {
        /** A body that is not exactly as long as its ref claims (spec 02 §6): refused, never truncated or padded. */
        const val ATTACHMENT_SIZE_MISMATCH = "attachment_size_mismatch"

        /** The host gave this session no raw-body channel ([AttachmentWire]). */
        const val ATTACHMENTS_UNAVAILABLE = "attachments_unavailable"

        /** An id that is not a canonical UUID was about to become a path or query segment: nothing was sent. */
        const val BAD_PATH_SEGMENT = "bad_path_segment"

        /**
         * [ItemFailure.Corrupt]'s `what` when the deleted-items list could not be read to its end (a page of more than
         * [TRASH_PAGE_ROWS] rows, rows out of order or not after the cursor, a full page that names no next row, or one
         * page more than [ItemEngine.TRASH_MAX_PAGES]): the list is unknown, never shown shorter.
         */
        const val TRASH_INCOMPLETE = "trash_incomplete"

        /** The rows of one full page of `GET /items/deleted` (spec 03 §5.1; the server's `DELETED_PAGE_ROWS`). */
        const val TRASH_PAGE_ROWS = 65_536
    }
}

/**
 * The two raw-body routes of spec 03 §9: [WireAttachments] over the session's own [WireClient], or a test's channel.
 */
interface AttachmentWire {
    suspend fun upload(attachmentId: String, itemId: String, vaultId: String, body: ByteArray): WireResult<AttachmentMeta>
    suspend fun download(attachmentId: String, expectedBytes: Long): WireResult<ByteArray>
}

/**
 * [AttachmentWire] over the session's own [WireClient] (spec 03 §9): its raw-body calls ([WireClient.callBytes],
 * [WireClient.fetchBytes]) carry the same origin guard, bearer and single refresh as every other request, so a
 * forked pin stops attachments too. Every id is checked against the UUID grammar before it becomes a path or query
 * segment (spec 02 §3.2), and a download that is not the size its item says is refused.
 */
class WireAttachments(private val client: WireClient) : AttachmentWire {
    override suspend fun upload(attachmentId: String, itemId: String, vaultId: String, body: ByteArray): WireResult<AttachmentMeta> {
        if (!TrustGrammar.isUuid(attachmentId) || !TrustGrammar.isUuid(itemId) || !TrustGrammar.isUuid(vaultId)) return badSegment()
        return client.callBytes(
            WireRoute.ATTACHMENT_UPLOAD, mapOf("attachmentId" to attachmentId), query = "vaultId=$vaultId&itemId=$itemId", body = body,
            decode = { WireJson.json.decodeFromString(AttachmentMeta.serializer(), it) },
        )
    }

    /**
     * [expectedBytes] is the item's claim plus the cipher's overhead ([io.silencelen.andvari.core.crypto.Attachments.wireLength]).
     *
     * **Memory.** The read is capped at [expectedBytes] ([WireClient.fetchBytes] with `maxBytes`): a server that
     * announces more is refused before a body byte is read, and one that sends more is cut off one byte past the claim,
     * so a lie never costs its size. Its [BODY_OVER_LIMIT] refusal is the item's size mismatch; a shorter answer is one
     * too.
     */
    override suspend fun download(attachmentId: String, expectedBytes: Long): WireResult<ByteArray> {
        if (!TrustGrammar.isUuid(attachmentId)) return badSegment()
        if (expectedBytes <= 0 || expectedBytes > MAX_DOWNLOAD_BYTES) return sizeMismatch(expectedBytes)
        return when (val r = client.fetchBytes(WireRoute.ATTACHMENT_GET, mapOf("attachmentId" to attachmentId), null, true, expectedBytes)) {
            is WireResult.Ok -> if (r.value.size.toLong() == expectedBytes) r else {
                r.value.fill(0)
                sizeMismatch(expectedBytes)
            }
            is WireResult.Refused -> if (r.code == BODY_OVER_LIMIT) sizeMismatch(expectedBytes) else r
            else -> r
        }
    }

    private fun sizeMismatch(expected: Long) =
        WireResult.Refused(0, WireError(ItemTransport.ATTACHMENT_SIZE_MISMATCH, "the attachment is not the $expected bytes its item says"))
    private fun badSegment() = WireResult.Refused(0, WireError(ItemTransport.BAD_PATH_SEGMENT, "not an id path segment"))

    companion object {
        /** The largest download one array holds; an item claiming more is refused unread. */
        const val MAX_DOWNLOAD_BYTES: Long = Int.MAX_VALUE - 8L
    }
}

/**
 * [ItemTransport] over the session's [WireClient] and the `core/model/wire` DTOs. Attachments go over the same client
 * ([WireAttachments]) unless a test hands another channel in [attachments].
 */
class WireItemTransport(private val client: WireClient, attachments: AttachmentWire? = null) : ItemTransport {
    private val attachments: AttachmentWire = attachments ?: WireAttachments(client)
    override suspend fun pull(since: Long): WireResult<SyncResponse> =
        client.call(WireRoute.SYNC, query = "since=$since", decode = { WireJson.json.decodeFromString(SyncResponse.serializer(), it) })

    override suspend fun push(mutations: List<Mutation>): WireResult<PushResponse> = client.call(
        WireRoute.PUSH, bodyJson = WireJson.json.encodeToString(PushRequest.serializer(), PushRequest(mutations)),
        decode = { WireJson.json.decodeFromString(PushResponse.serializer(), it) },
    )

    override suspend fun versions(itemId: String): WireResult<List<ItemVersion>> = client.call(
        WireRoute.ITEM_VERSIONS, mapOf("itemId" to itemId),
        decode = { WireJson.json.decodeFromString(ItemVersionsResponse.serializer(), it).versions },
    )

    override suspend fun deletedItems(after: String?): WireResult<List<DeletedItem>> =
        client.call(WireRoute.ITEMS_DELETED, query = after?.let { "after=$it" }, decode = { WireJson.json.decodeFromString(DeletedItemsResponse.serializer(), it).items })

    override suspend fun restore(itemId: String, item: ItemUpload): WireResult<Long> = client.call(
        WireRoute.ITEM_RESTORE, mapOf("itemId" to itemId), bodyJson = WireJson.json.encodeToString(ItemUpload.serializer(), item),
        decode = { WireJson.json.decodeFromString(RevResponse.serializer(), it).rev },
    )

    override suspend fun purge(itemId: String): WireResult<Long> = client.call(
        WireRoute.ITEM_PURGE, mapOf("itemId" to itemId), decode = { WireJson.json.decodeFromString(RevResponse.serializer(), it).rev },
    )

    override suspend fun uploadAttachment(attachmentId: String, itemId: String, vaultId: String, body: ByteArray): WireResult<AttachmentMeta> =
        attachments.upload(attachmentId, itemId, vaultId, body)

    override suspend fun downloadAttachment(attachmentId: String, expectedBytes: Long): WireResult<ByteArray> =
        attachments.download(attachmentId, expectedBytes)

    override suspend fun putVaultMeta(vaultId: String, metaBlob: String, baseVaultRev: Long?): WireResult<Long> = client.call(
        WireRoute.VAULT_META, mapOf("vaultId" to vaultId),
        bodyJson = WireJson.json.encodeToString(VaultMetaPut.serializer(), VaultMetaPut(metaBlob, baseVaultRev)),
        decode = { WireJson.json.decodeFromString(RevResponse.serializer(), it).rev },
    )

    override suspend fun hibpRange(prefix: String): WireResult<String> = client.call(WireRoute.HIBP_RANGE, mapOf("prefix" to prefix), decode = { it })

    override suspend fun deletedVaults(): WireResult<List<DeletedVaultSummary>> = client.call(
        WireRoute.VAULTS_DELETED, decode = { WireJson.json.decodeFromString(ListSerializer(DeletedVaultSummary.serializer()), it) },
    )
}

/** True for the refusal that tells a device its cursor predates retained history (spec 03 §4). */
internal fun WireResult.Refused.isResync(): Boolean = code == WireErrors.RESYNC_REQUIRED
