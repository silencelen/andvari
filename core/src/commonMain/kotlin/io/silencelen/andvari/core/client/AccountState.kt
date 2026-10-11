package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.listSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/**
 * A household member this account has VERIFIED (security review 2026-10, root cause A §4.2, §7.2).
 *
 * A contact exists only because a human compared a fingerprint: a full-hash identity QR scan
 * ([METHOD_QR]), a typed 32-hex match against SHA-256 of the served key ([METHOD_TYPED]), or the
 * in-person enrolment link's `ifp` under the in-person code ([METHOD_ENROL]). [ContactPin] is the only
 * constructor callers should use; nothing pins a key just because the server served it. Pairwise only
 * (owner decision Q4): there are no admin-signed introductions.
 */
@Serializable
data class Contact(
    val userId: String,
    /** base64url of the pinned X25519 identity public key (32 bytes). */
    val identityPub: String,
    /** Display label. Cosmetic: the key, not the label, is what was verified. */
    val label: String,
    val verifiedAt: Long,
    val method: String,
) {
    companion object {
        const val METHOD_QR = "qr"
        const val METHOD_TYPED = "typed"
        const val METHOD_ENROL = "enrol"
        val METHODS = setOf(METHOD_QR, METHOD_TYPED, METHOD_ENROL)
    }
}

/** One consumed lifecycle nonce (root cause A §6), wire form `["<nonce>", <issuedAt>]`. */
@Serializable(with = ConsumedNonceSerializer::class)
data class ConsumedNonce(val nonce: String, val issuedAt: Long)

internal object ConsumedNonceSerializer : KSerializer<ConsumedNonce> {
    override val descriptor: SerialDescriptor = listSerialDescriptor<String>()

    override fun serialize(encoder: Encoder, value: ConsumedNonce) {
        val je = encoder as? JsonEncoder ?: throw SerializationException("account state is JSON-only")
        je.encodeJsonElement(JsonArray(listOf(JsonPrimitive(value.nonce), JsonPrimitive(value.issuedAt))))
    }

    override fun deserialize(decoder: Decoder): ConsumedNonce {
        val jd = decoder as? JsonDecoder ?: throw SerializationException("account state is JSON-only")
        val arr = jd.decodeJsonElement() as? JsonArray ?: throw SerializationException("nonce entry is not an array")
        if (arr.size != 2) throw SerializationException("nonce entry must be [nonce, issuedAt]")
        val n = arr[0].jsonPrimitive
        val t = arr[1].jsonPrimitive
        if (!n.isString || t.isString) throw SerializationException("nonce entry has the wrong types")
        return ConsumedNonce(n.content, t.long)
    }
}

/**
 * The account-state plaintext (root cause A §4.2): `Envelope(UVK, JSON, Ad.accountState(userId))`.
 * Only this user's UVK can seal or open it, so the server can withhold or roll it back but never add
 * to it. [seq] is the authenticated high-water counter; the server's own `seq` is only a CAS token.
 */
@Serializable
data class AccountStateDoc(
    val v: Int = 1,
    val userId: String,
    val seq: Long,
    val contacts: List<Contact> = emptyList(),
    val contactTombstones: Map<String, Long> = emptyMap(),
    val orgRecoveryFp: String? = null,
    val consumedNonces: Map<String, List<ConsumedNonce>> = emptyMap(),
) {
    fun contact(userId: String): Contact? = contacts.firstOrNull { it.userId == userId }
}

class AccountStateException(message: String) : Exception(message)

/**
 * Codec + merge for [AccountStateDoc] (root cause A §4.2). Pure, so the merge table in
 * `spec/test-vectors/accountstate.json` pins it byte-for-byte; the web twin is `web/src/vault/accountstate.ts`.
 */
object AccountState {
    const val VERSION = 1

    /** Newest consumed nonces kept per vault. */
    const val NONCE_CAP = 256

    /** Server-side size cap for the sealed blob (base64url chars), mirrored by the client before a PUT. */
    const val SEALED_MAX = 65536

    private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    private val HEX64_RE = Regex("^[0-9a-f]{64}$")

    private val json = Json { encodeDefaults = true; explicitNulls = true }

    fun empty(userId: String): AccountStateDoc = AccountStateDoc(VERSION, userId, 0)

    fun encode(doc: AccountStateDoc): String = json.encodeToString(AccountStateDoc.serializer(), doc)

    /**
     * Strict decode of an OPENED blob. Throws [AccountStateException] on anything that is not a v1
     * document for [userId] with well-formed contacts: an AEAD-authentic blob from this user's own
     * client is never malformed, so a failure here is a bug or a newer format, and either way it is
     * not adopted.
     */
    fun decode(userId: String, plaintext: String): AccountStateDoc {
        val doc = try {
            Json { ignoreUnknownKeys = false }.decodeFromString(AccountStateDoc.serializer(), plaintext)
        } catch (e: Exception) {
            throw AccountStateException("account state is not a v$VERSION document: ${e.message}")
        }
        if (doc.v != VERSION) throw AccountStateException("account state version ${doc.v} is not supported")
        if (doc.userId != userId) throw AccountStateException("account state belongs to another user")
        if (doc.seq < 0) throw AccountStateException("account state seq is negative")
        for (c in doc.contacts) {
            if (!UUID_RE.matches(c.userId)) throw AccountStateException("contact userId is not a uuid")
            val key = runCatching { Bytes.fromB64(c.identityPub) }.getOrNull()
            if (key == null || key.size != 32) throw AccountStateException("contact key is not 32 bytes")
            if (c.method !in Contact.METHODS) throw AccountStateException("contact method is unknown")
            if (c.verifiedAt < 0) throw AccountStateException("contact verifiedAt is negative")
        }
        if (doc.contacts.map { it.userId }.toSet().size != doc.contacts.size) throw AccountStateException("duplicate contact")
        doc.orgRecoveryFp?.let { if (!HEX64_RE.matches(it)) throw AccountStateException("orgRecoveryFp is not 64 hex") }
        return doc
    }

    /** The outcome of [merge]: the merged document (seq = the high-water, not yet bumped) and whether
     *  the served copy was a rollback (withheld, or below this device's high-water mark). */
    class Merged(val doc: AccountStateDoc, val rollback: Boolean)

    /**
     * Root cause A §4.2 merge, run on every read and on a 409:
     *  - contacts union by userId, newest `verifiedAt` wins (tie: the smaller identityPub string, so
     *    the merge is order-independent);
     *  - tombstones union (max), and a tombstone not older than a pin removes it (a same-millisecond
     *    tie removes: the fail-safe direction is "unpinned");
     *  - `orgRecoveryFp` from the document with the higher seq (the local copy on a tie or rollback);
     *  - nonces union per vault, newest [NONCE_CAP] kept;
     *  - seq = max(local, served, highWater).
     * Rollback: a served seq below this device's [highWater], or a withheld blob once one was seen,
     * raises [Merged.rollback]. The flag changes ONE field: `orgRecoveryFp` is then taken from the local
     * copy. Contacts, tombstones and nonces are still the union of BOTH copies (a served copy is
     * UVK-authenticated, so it can only carry entries this account itself wrote; a pin the local copy
     * holds survives, and an older served tombstone cannot outrank a newer local pin). seq stays at the
     * high-water mark. Rolling back can only REMOVE pins, never add one, because only the UVK can
     * produce a document at all.
     */
    fun merge(userId: String, local: AccountStateDoc?, served: AccountStateDoc?, highWater: Long): Merged {
        val rollback = (served == null && highWater > 0) || (served != null && served.seq < highWater)
        val docs = listOfNotNull(local, served)
        val byUser = HashMap<String, Contact>()
        for (c in docs.flatMap { it.contacts }) {
            val cur = byUser[c.userId]
            byUser[c.userId] = when {
                cur == null -> c
                c.verifiedAt > cur.verifiedAt -> c
                c.verifiedAt < cur.verifiedAt -> cur
                else -> if (c.identityPub < cur.identityPub) c else cur
            }
        }
        val tombstones = HashMap<String, Long>()
        for ((u, t) in docs.flatMap { it.contactTombstones.entries }) tombstones[u] = maxOf(tombstones[u] ?: t, t)
        val contacts = byUser.values
            .filter { c -> (tombstones[c.userId] ?: Long.MIN_VALUE) < c.verifiedAt }
            .sortedBy { it.userId }

        val nonces = HashMap<String, HashMap<String, Long>>()
        for ((vaultId, list) in docs.flatMap { it.consumedNonces.entries }) {
            val m = nonces.getOrPut(vaultId) { HashMap() }
            for (n in list) m[n.nonce] = maxOf(m[n.nonce] ?: n.issuedAt, n.issuedAt)
        }
        val cappedNonces = nonces.mapValues { (_, m) ->
            m.entries.map { ConsumedNonce(it.key, it.value) }
                .sortedWith(compareByDescending<ConsumedNonce> { it.issuedAt }.thenBy { it.nonce })
                .take(NONCE_CAP)
        }.toSortedMap()

        val localSeq = local?.seq ?: -1
        val servedSeq = served?.seq ?: -1
        val preferServed = served != null && !rollback && servedSeq > localSeq
        val fp = if (preferServed) served!!.orgRecoveryFp ?: local?.orgRecoveryFp else local?.orgRecoveryFp ?: served?.orgRecoveryFp

        val seq = maxOf(localSeq, servedSeq, highWater, 0)
        return Merged(
            AccountStateDoc(VERSION, userId, seq, contacts, tombstones.toSortedMap(), fp, cappedNonces),
            rollback,
        )
    }

    /** True when [a] and [b] carry the same content, ignoring seq (no write is needed). */
    fun sameContent(a: AccountStateDoc?, b: AccountStateDoc?): Boolean =
        a != null && b != null && a.copy(seq = 0) == b.copy(seq = 0)

    /** A new pin, replacing any older one for the same user and clearing an older tombstone. */
    fun withContact(doc: AccountStateDoc, c: Contact): AccountStateDoc = doc.copy(
        contacts = (doc.contacts.filter { it.userId != c.userId } + c).sortedBy { it.userId },
        contactTombstones = doc.contactTombstones.filterKeys { it != c.userId }.toSortedMap(),
    )

    /** Remove a pin by tombstone, so the removal survives a merge with an older copy that still has it. */
    fun withoutContact(doc: AccountStateDoc, userId: String, at: Long): AccountStateDoc = doc.copy(
        contacts = doc.contacts.filter { it.userId != userId },
        contactTombstones = (doc.contactTombstones + (userId to maxOf(at, doc.contactTombstones[userId] ?: at))).toSortedMap(),
    )
}
