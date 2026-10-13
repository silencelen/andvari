package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
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
 * One vault grant THIS account signed (security review 2026-10, root cause A, branch A6b): the (vault, member) pair
 * and SHA-256 (hex) of the identity key it was sealed to. A re-issue to a pair recorded here, for the SAME key, needs
 * no prompt; anything else needs a human on the device to confirm the pair. Pre-A6b grants are never recorded.
 */
@Serializable
data class IssuedGrant(val vaultId: String, val userId: String, val keyHash: String, val at: Long)

/**
 * The account's own PERSONAL-VAULT DESIGNATION (security review 2026-10, branch A9, M-2): which vault this account last
 * made personal, and when. Written on register, on the migration choice, on a re-designation and on an accepted change,
 * never by anything the server served. Tombstone-free: the newest `at` wins on merge, so a re-designation simply writes
 * a newer entry, and a rolled-back or withheld blob can never revive an older one on a device that merged the newer.
 * A served `personalWrap` that names this vault is confirmed on any device; one naming another vault, or served to a
 * device with no cached wrap and no designation, is a proposal the human confirms ([SyncEngine.decidePersonalLocally]).
 */
@Serializable
data class PersonalDesignation(val vaultId: String, val at: Long)

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
    /** A6b: every grant this account signed from A6b on (see [IssuedGrant]). */
    val issuedGrants: List<IssuedGrant> = emptyList(),
    /** A6b: `"<vaultId>|<userId>"` → ms; written when the owner removes the member. */
    val issuedTombstones: Map<String, Long> = emptyMap(),
    /** A6b: vaults this account OWNS by its own evidence (created, accepted by transfer, or confirmed with a password
     *  reauth), vaultId → ms. The server's `role=owner` label is never an input. */
    val ownedVaults: Map<String, Long> = emptyMap(),
    /** A6b: vaultId → ms; written when the account transfers the vault away or leaves it. */
    val ownedTombstones: Map<String, Long> = emptyMap(),
    /** A1b (A6b review LOW-R): vaults some device of this account first adopted the key of AS A MEMBER, vaultId → ms.
     *  Add-only (no tombstones), union-merged keeping the larger `at`, like [ownedVaults]. */
    val memberReceived: Map<String, Long> = emptyMap(),
    /** A9 (M-2): the account's own personal-vault designation (see [PersonalDesignation]); absent in older documents and
     *  omitted from the encoding while absent, so a document that never designated stays readable by older clients. */
    @OptIn(ExperimentalSerializationApi::class)
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val personal: PersonalDesignation? = null,
) {
    fun contact(userId: String): Contact? = contacts.firstOrNull { it.userId == userId }

    /** The issued-grant record for ([vaultId], [userId]), when one is in force. */
    fun issued(vaultId: String, userId: String): IssuedGrant? =
        issuedGrants.firstOrNull { it.vaultId == vaultId && it.userId == userId }
            ?.takeIf { it.at > (issuedTombstones[AccountState.pairKey(vaultId, userId)] ?: -1L) }

    /** True when this account's own evidence says it owns [vaultId]. */
    fun owns(vaultId: String): Boolean = ownedVaults[vaultId]?.let { it > (ownedTombstones[vaultId] ?: -1L) } == true

    /** True when some device of this account recorded that it received [vaultId]'s key as a member (A1b, LOW-R). */
    fun receivedAsMember(vaultId: String): Boolean = memberReceived.containsKey(vaultId)

    /** True when there is nothing in the document worth writing. */
    fun isBlank(): Boolean = contacts.isEmpty() && consumedNonces.isEmpty() && orgRecoveryFp == null &&
        issuedGrants.isEmpty() && issuedTombstones.isEmpty() && ownedVaults.isEmpty() && ownedTombstones.isEmpty() &&
        memberReceived.isEmpty() && personal == null
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
        for (g in doc.issuedGrants) {
            if (!UUID_RE.matches(g.vaultId) || !UUID_RE.matches(g.userId)) throw AccountStateException("issued grant id is not a uuid")
            if (!HEX64_RE.matches(g.keyHash)) throw AccountStateException("issued grant keyHash is not 64 hex")
            if (g.at < 0) throw AccountStateException("issued grant at is negative")
        }
        if (doc.issuedGrants.map { pairKey(it.vaultId, it.userId) }.toSet().size != doc.issuedGrants.size) throw AccountStateException("duplicate issued grant")
        for ((k, at) in doc.ownedVaults) {
            if (!UUID_RE.matches(k)) throw AccountStateException("owned vault id is not a uuid")
            if (at < 0) throw AccountStateException("owned vault at is negative")
        }
        for ((k, at) in doc.memberReceived) {
            if (!UUID_RE.matches(k)) throw AccountStateException("member-received vault id is not a uuid")
            if (at < 0) throw AccountStateException("member-received at is negative")
        }
        doc.personal?.let { p ->
            if (!UUID_RE.matches(p.vaultId)) throw AccountStateException("personal designation vault id is not a uuid")
            if (p.at < 0) throw AccountStateException("personal designation at is negative")
        }
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
     *  - `personal` (A9): the designation with the newest `at` (tie: the smaller vaultId);
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

        // A6b: issued grants union by (vaultId, userId), the newest `at` wins (tie: the smaller keyHash); a tombstone
        // not older than the entry removes it. Owned vaults union (max `at`), a tombstone not older removes it. Like
        // contacts, a rollback cannot shrink either: both copies are UVK-authenticated and the local one is kept.
        val issuedTomb = HashMap<String, Long>()
        for ((k, t) in docs.flatMap { it.issuedTombstones.entries }) issuedTomb[k] = maxOf(issuedTomb[k] ?: t, t)
        val byPair = HashMap<String, IssuedGrant>()
        for (g in docs.flatMap { it.issuedGrants }) {
            val k = pairKey(g.vaultId, g.userId)
            val cur = byPair[k]
            byPair[k] = when {
                cur == null -> g
                g.at > cur.at -> g
                g.at < cur.at -> cur
                else -> if (g.keyHash < cur.keyHash) g else cur
            }
        }
        val issued = byPair.entries.filter { (k, g) -> (issuedTomb[k] ?: Long.MIN_VALUE) < g.at }.map { it.value }
            .sortedWith(compareBy<IssuedGrant> { it.vaultId }.thenBy { it.userId })
        val ownedTomb = HashMap<String, Long>()
        for ((k, t) in docs.flatMap { it.ownedTombstones.entries }) ownedTomb[k] = maxOf(ownedTomb[k] ?: t, t)
        val owned = HashMap<String, Long>()
        for ((k, t) in docs.flatMap { it.ownedVaults.entries }) owned[k] = maxOf(owned[k] ?: t, t)
        val ownedLive = owned.filter { (k, t) -> (ownedTomb[k] ?: Long.MIN_VALUE) < t }
        // A1b (LOW-R): add-only union, the larger `at` per vault.
        val memberReceived = HashMap<String, Long>()
        for ((k, t) in docs.flatMap { it.memberReceived.entries }) memberReceived[k] = maxOf(memberReceived[k] ?: t, t)
        // A9 (M-2): the personal designation with the newest `at` wins (tie: the smaller vaultId, so the merge is
        // order-independent). Tombstone-free: a rollback or a withheld blob is simply the older copy, and loses.
        val personal = docs.mapNotNull { it.personal }
            .sortedWith(compareByDescending<PersonalDesignation> { it.at }.thenBy { it.vaultId })
            .firstOrNull()

        val seq = maxOf(localSeq, servedSeq, highWater, 0)
        return Merged(
            AccountStateDoc(
                VERSION, userId, seq, contacts, tombstones.toSortedMap(), fp, cappedNonces,
                issued, issuedTomb.toSortedMap(), ownedLive.toSortedMap(), ownedTomb.toSortedMap(), memberReceived.toSortedMap(),
                personal,
            ),
            rollback,
        )
    }

    /** The tombstone key for an issued grant. */
    fun pairKey(vaultId: String, userId: String): String = "$vaultId|$userId"

    /**
     * Record the account's personal-vault designation (A9, M-2): register, the migration choice, a re-designation, an
     * accepted change. The new entry is pushed past the one it replaces whatever this device's clock says, so the newest
     * human act always wins the merge.
     */
    fun withPersonal(doc: AccountStateDoc, vaultId: String, at: Long): AccountStateDoc {
        val prev = doc.personal
        val t = if (prev == null || prev.vaultId == vaultId) maxOf(at, prev?.at ?: -1L) else maxOf(at, prev.at + 1)
        return doc.copy(personal = PersonalDesignation(vaultId, t))
    }

    /**
     * Record a grant this account just signed (A6b). The entry replaces any earlier one for the pair, and its `at`
     * is pushed past an older tombstone so a re-add after a removal survives the merge.
     */
    fun withIssued(doc: AccountStateDoc, vaultId: String, userId: String, keyHash: String, at: Long): AccountStateDoc {
        val k = pairKey(vaultId, userId)
        val t = maxOf(at, (doc.issuedTombstones[k] ?: -1L) + 1, (doc.issuedGrants.firstOrNull { it.vaultId == vaultId && it.userId == userId }?.at ?: -1L))
        return doc.copy(
            issuedGrants = (doc.issuedGrants.filterNot { it.vaultId == vaultId && it.userId == userId } + IssuedGrant(vaultId, userId, keyHash, t))
                .sortedWith(compareBy<IssuedGrant> { it.vaultId }.thenBy { it.userId }),
        )
    }

    /** Tombstone the issued grant for ([vaultId], [userId]): the owner removed the member (A6b). */
    fun withoutIssued(doc: AccountStateDoc, vaultId: String, userId: String, at: Long): AccountStateDoc {
        val k = pairKey(vaultId, userId)
        val existing = doc.issuedGrants.firstOrNull { it.vaultId == vaultId && it.userId == userId }?.at ?: -1L
        val t = maxOf(at, existing, doc.issuedTombstones[k] ?: -1L)
        return doc.copy(
            issuedGrants = doc.issuedGrants.filterNot { it.vaultId == vaultId && it.userId == userId },
            issuedTombstones = (doc.issuedTombstones + (k to t)).toSortedMap(),
        )
    }

    /** Record that this account owns [vaultId] (created it, accepted it, or confirmed it with a reauth; A6b). */
    fun withOwned(doc: AccountStateDoc, vaultId: String, at: Long): AccountStateDoc {
        val t = maxOf(at, (doc.ownedTombstones[vaultId] ?: -1L) + 1, doc.ownedVaults[vaultId] ?: -1L)
        return doc.copy(ownedVaults = (doc.ownedVaults + (vaultId to t)).toSortedMap())
    }

    /** Record that some device of this account received [vaultIds] as a member (A1b, LOW-R). Add-only. */
    fun withMemberReceived(doc: AccountStateDoc, vaultIds: Collection<String>, at: Long): AccountStateDoc {
        val m = doc.memberReceived.toMutableMap()
        for (id in vaultIds) m[id] = maxOf(m[id] ?: at, at)
        return doc.copy(memberReceived = m.toSortedMap())
    }

    /** Tombstone ownership of [vaultId]: the account transferred it away or left it (A6b). */
    fun withoutOwned(doc: AccountStateDoc, vaultId: String, at: Long): AccountStateDoc {
        val t = maxOf(at, doc.ownedVaults[vaultId] ?: -1L, doc.ownedTombstones[vaultId] ?: -1L)
        return doc.copy(
            ownedVaults = (doc.ownedVaults - vaultId).toSortedMap(),
            ownedTombstones = (doc.ownedTombstones + (vaultId to t)).toSortedMap(),
        )
    }

    /**
     * Fold this device's consumed removal nonces (root cause A §6.2, branch A7) into [doc]: the same rule as [merge]
     * (union per vault, the larger issuedAt for a repeated nonce, newest [NONCE_CAP] kept). Nothing else changes.
     */
    fun withConsumed(doc: AccountStateDoc, extra: Map<String, List<ConsumedNonce>>): AccountStateDoc {
        if (extra.isEmpty()) return doc
        val nonces = HashMap<String, HashMap<String, Long>>()
        for ((vaultId, list) in doc.consumedNonces.entries + extra.entries) {
            val m = nonces.getOrPut(vaultId) { HashMap() }
            for (n in list) m[n.nonce] = maxOf(m[n.nonce] ?: n.issuedAt, n.issuedAt)
        }
        val capped = nonces.mapValues { (_, m) ->
            m.entries.map { ConsumedNonce(it.key, it.value) }
                .sortedWith(compareByDescending<ConsumedNonce> { it.issuedAt }.thenBy { it.nonce })
                .take(NONCE_CAP)
        }.toSortedMap()
        return doc.copy(consumedNonces = capped)
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
