package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.ItemDocShape
import io.silencelen.andvari.core.client.MalformedItemException
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KeyFloor
import io.silencelen.andvari.core.model.wire.ItemUpload
import io.silencelen.andvari.core.model.wire.ItemVersion
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/**
 * The item plane's one decrypt and one seal (spec 02 §2, §3, §3.2, §4), cut from the old `Account`: an item envelope
 * under a vault key with the AD `andvari/v1|item|{vaultId}|{itemId}|{formatVersion}`, the shape check on every
 * decrypted document, the monotonic formatVersion, and a vault's metadata. It holds no key: every call is handed one,
 * which its caller got from [VaultKeySource] and wipes.
 */
class ItemCodec(private val crypto: CryptoProvider) {
    private val lock = SynchronizedObject()

    /**
     * itemId → the highest formatVersion this session decrypted or sealed it at. A re-seal takes the larger of this
     * and the document's floor: the server enforces a per-item monotonic formatVersion (spec 03 §5 `denied`).
     */
    private val itemFv = HashMap<String, Int>()

    /**
     * Open [row] under [vk]. Refuses a tombstone, a formatVersion newer than this client's (unknown-field
     * preservation is scoped WITHIN a formatVersion, spec 02 §3) and a document that fails the shape rule (spec 02
     * §3.2). A refusal is a [CryptoException] or a [MalformedItemException]; the caller keeps the envelope.
     */
    fun open(vk: ByteArray, row: SyncItem): ItemDoc {
        val blob = row.blob ?: throw CryptoException("item has no blob (tombstone?)")
        if (row.formatVersion > ITEM_FORMAT_VERSION) throw CryptoException("item formatVersion ${row.formatVersion} is newer than this client supports")
        val plain = Envelope.openB64(crypto, vk, blob, Ad.item(row.vaultId, row.itemId, row.formatVersion))
        val tree = try {
            json.parseToJsonElement(plain.decodeToString())
        } catch (e: Exception) {
            throw MalformedItemException("item document is not JSON")
        } finally {
            plain.fill(0)
        }
        ItemDocShape.problem(tree)?.let { throw MalformedItemException("item document is malformed: $it") }
        val doc = json.decodeFromJsonElement(ItemDoc.serializer(), tree)
        synchronized(lock) { itemFv[row.itemId] = maxOf(itemFv[row.itemId] ?: 1, row.formatVersion) }
        return doc
    }

    /** One archived version (spec 03 §4): the AD binds the item and its formatVersion, not the rev. */
    fun openVersion(vk: ByteArray, vaultId: String, itemId: String, version: ItemVersion): ItemDoc =
        open(vk, SyncItem(itemId, vaultId, version.rev, 0, version.archivedAt, false, false, version.formatVersion, emptyList(), version.blob))

    /** Seal [doc] as [itemId] in [vaultId] under [vk]. The caller has already decided this vault may be written. */
    fun seal(vk: ByteArray, vaultId: String, itemId: String, doc: ItemDoc): ItemUpload {
        val fv = synchronized(lock) {
            val v = maxOf(docFloor(doc), itemFv[itemId] ?: 1)
            itemFv[itemId] = v
            v
        }
        val plain = json.encodeToString(ItemDoc.serializer(), doc).encodeToByteArray()
        try {
            return ItemUpload(fv, doc.attachments.map { it.id }, Envelope.sealB64(crypto, vk, plain, Ad.item(vaultId, itemId, fv)))
        } finally {
            plain.fill(0)
        }
    }

    /** A vault's decrypted metadata object (spec 02 §4), or null when it does not open or is not a JSON object. */
    fun vaultMeta(vk: ByteArray, vaultId: String, metaBlob: String): JsonObject? = try {
        json.parseToJsonElement(Envelope.openB64(crypto, vk, metaBlob, Ad.vaultMeta(vaultId)).decodeToString()) as? JsonObject
    } catch (e: Exception) {
        null
    }

    /** The vault's display name: only a JSON string counts (spec 02 §3.2). */
    fun vaultName(vk: ByteArray, vaultId: String, metaBlob: String): String? = vaultMeta(vk, vaultId, metaBlob)?.let { ItemDocShape.vaultName(it) }

    /** The metadata of a new vault named [name]. */
    fun sealVaultMeta(vk: ByteArray, vaultId: String, name: String): String =
        Envelope.sealB64(crypto, vk, newMetaPlain(name), Ad.vaultMeta(vaultId))

    private fun newMetaPlain(name: String): ByteArray = buildJsonObject { put("name", name) }.toString().encodeToByteArray()

    /**
     * The length of the blob [seal] makes of [doc], in characters, with no key: what the server counts for it (spec 03
     * §14.4). A sealed envelope is its plaintext plus a fixed overhead, sent as unpadded base64url.
     */
    fun sealedLength(doc: ItemDoc): Long {
        val plain = json.encodeToString(ItemDoc.serializer(), doc).encodeToByteArray()
        try {
            return b64Length(plain.size.toLong() + Envelope.MIN_BYTES)
        } finally {
            plain.fill(0)
        }
    }

    /** The length of the `metaBlob` [sealVaultMeta] makes for a vault named [name]. */
    fun metaLength(name: String): Long = b64Length(newMetaPlain(name).size.toLong() + Envelope.MIN_BYTES)

    private fun b64Length(bytes: Long): Long = (bytes * 4 + 2) / 3

    /**
     * A rename (spec 03 §11.3): read-modify-write [metaBlob] under the same key and AD, changing only `name`, keeping
     * every unknown field, and incrementing `metaV`. Metadata that is not a JSON object is replaced by a clean one.
     */
    fun renamedMeta(vk: ByteArray, vaultId: String, metaBlob: String, newName: String): String {
        val meta = vaultMeta(vk, vaultId, metaBlob) ?: JsonObject(emptyMap())
        val next = buildJsonObject {
            for ((k, v) in meta) if (k != "name" && k != "metaV") put(k, v)
            put("name", newName)
            put("metaV", metaVOf(meta) + 1)
        }
        return Envelope.sealB64(crypto, vk, next.toString().encodeToByteArray(), Ad.vaultMeta(vaultId))
    }

    fun freshId(): String = Bytes.uuidV4FromBytes(crypto.randomBytes(16))

    /** A random per-file key (spec 02 §6); it lives only inside item ciphertext. */
    fun freshFileKey(): ByteArray = crypto.randomBytes(FILE_KEY_BYTES)

    /** A UUIDv4-shaped id from `sha256(text)`: stable ids for a retried gesture or a conflict copy. */
    fun derivedId(text: String): String = Bytes.uuidV4FromBytes(crypto.sha256(text.encodeToByteArray()))

    companion object {
        /** The newest item formatVersion this client reads and writes (spec 02 §3). */
        const val ITEM_FORMAT_VERSION = 2

        /** The key the vault log's head rides in an item document (spec 02 §3). */
        const val LOG_HEAD = "logHead"

        /** A file key's length (spec 02 §6): the secretstream key. */
        const val FILE_KEY_BYTES = 32

        /**
         * The file key [ref] carries (spec 02 §6), or null when it is no key: not base64url, not [FILE_KEY_BYTES] long,
         * or all zeros (spec 01 §8 rule 4: no legitimate key is all zeros). The ref sits in the item's document, which
         * any writer of a shared vault authors, so its key is data: null is damaged content, refused before anything is
         * fetched or decrypted. The caller wipes the key after its one use.
         */
        internal fun fileKeyOf(ref: AttachmentRef): ByteArray? {
            val key = runCatching { Bytes.fromB64(ref.fileKey) }.getOrNull() ?: return null
            if (key.size != FILE_KEY_BYTES || KeyFloor.allZero(key)) {
                key.fill(0)
                return null
            }
            return key
        }

        private const val METAV_MAX: Long = 9007199254740991L

        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

        /** The lowest formatVersion [doc] may be sealed at: cards need 2. */
        fun docFloor(doc: ItemDoc): Int = if (doc.card != null || doc.type == "card") 2 else 1

        fun parseMetaV(content: String): Long {
            val d = content.toDoubleOrNull() ?: return 0L
            if (!d.isFinite() || d < 0.0 || d > METAV_MAX.toDouble() || d != kotlin.math.floor(d)) return 0L
            return d.toLong()
        }

        /**
         * The metadata's monotonic `metaV` (spec 02 §4): a JSON number that is a non-negative integer up to 2^53−1,
         * anything else 0. One rule for the rename that writes it and the pull that compares it.
         */
        fun metaVOf(meta: JsonObject): Long {
            val p = meta["metaV"] as? JsonPrimitive ?: return 0L
            return if (p.isString) 0L else parseMetaV(p.content)
        }

        /** The log head [doc] carries, when it is well-formed: a hint to fetch, never a verdict (design §3.9). */
        fun logHeadOf(doc: ItemDoc): LogHeadStamp? {
            val o = doc.extras[LOG_HEAD] as? JsonObject ?: return null
            val seq = (o["seq"] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull ?: return null
            val hash = (o["hash"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
            return if (seq >= 0 && TrustGrammar.isHex64(hash)) LogHeadStamp(seq, hash) else null
        }

        /**
         * [doc] as a writer sends it (spec 02 §3): carrying [head], the verified head of the vault it is written to,
         * or no head at all (the personal vault, and a copy that came from another vault: its old head names a
         * different log).
         */
        fun stamped(doc: ItemDoc, head: LogHeadStamp?): ItemDoc {
            val rest = doc.extras - LOG_HEAD
            return doc.copy(extras = if (head == null) rest else rest + (LOG_HEAD to buildJsonObject { put("seq", head.seq); put("hash", head.hash) }))
        }
    }
}
