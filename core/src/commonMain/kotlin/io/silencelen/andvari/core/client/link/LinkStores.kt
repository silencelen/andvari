package io.silencelen.andvari.core.client.link

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.GuardedKey
import io.silencelen.andvari.core.client.onboard.GuardedKeyPair
import io.silencelen.andvari.core.client.state.AccountStateStore
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LinkSide
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer

/**
 * The signed-in account a link engine acts for: what it signs and seals with, and its account state. Borrowed from
 * the session (the caller wipes the keys at lock). [deviceId] is `madeOn` for the contacts this device pins;
 * [displayName] the account's chosen name, sent in offers and answers.
 */
class LinkAccount internal constructor(
    val origin: String,
    val emailNorm: String,
    val userId: String,
    val deviceId: String,
    val displayName: String,
    internal val uvk: GuardedKey,
    internal val identity: GuardedKeyPair,
    internal val signing: GuardedKeyPair,
    internal val store: AccountStateStore,
    /** The genesis's `personalVaultId` (design §5.2), for the device-link bundle; null where the engine needs none. */
    internal val personalVaultId: String? = null,
) {
    internal val identityPubB64: String get() = Bytes.toB64(identity.publicKey)

    companion object {
        /** The account of [session], with its account state [store] and the person's [displayName]. */
        fun of(session: EstablishedSession, displayName: String, store: AccountStateStore): LinkAccount = LinkAccount(
            session.origin, session.emailNorm, session.userId, session.deviceId, displayName, session.account.uvk,
            session.account.identity, session.account.signing, store, session.account.genesis.fields.personalVaultId,
        )
    }
}

/** A share attached to a link, as stored. */
@Serializable
internal data class StoredShare(val vaultId: String, val role: String) {
    fun view() = LinkShare(vaultId, role)
}

/**
 * The creating device's record of one link (design §6.7 step 2, spec 03 §15.2): written durably BEFORE `POST /links`,
 * deleted at its expiry, at revocation, or once the answer is processed. [secret] is the link's whole capability and
 * never leaves this device (T-B6). [ttlMs] is the server's answer, null until it is known; [createdAt] this device's
 * clock when it made the link, for the countdown base only.
 */
@Serializable
internal data class LinkRecord(
    val linkId: String,
    val secret: String,
    val nonceA: String,
    val kind: String,
    val offerHash: String,
    val expiresAt: Long,
    val shares: List<StoredShare>,
    val url: String,
    val createdAt: Long,
    val ttlMs: Long? = null,
)

/**
 * The creator's link records of one account on this device, sealed under the account's UVK in device state (the
 * device state holds only public ids or UVK-sealed blobs). A record that does not open is read as none: the link
 * cannot be finished, and an answer to it is ignored (`unknown_link`), which is the fail-closed reading.
 */
internal class LinkRecordStore(private val state: DeviceState, private val crypto: CryptoProvider, private val origin: String, private val userId: String) {
    private val key = "ovh.links|$origin|$userId"

    /**
     * The seal's associated data: the account and the purpose, NOT the origin, so a followed
     * move, which carries the record to the new origin's key without any secret, leaves it readable there. The UVK is
     * the account's own, so another account's record cannot open under it either way.
     */
    private val ad = "andvari/v2|link-records|$userId".encodeToByteArray()

    /** The associated data of a record sealed before the origin left it: still read at the origin it was sealed for. */
    private val adBefore = "andvari/v2|link-records|$origin|$userId".encodeToByteArray()

    private fun open(uvk: ByteArray, sealed: String, ad: ByteArray): ByteArray? = try {
        Envelope.openB64(crypto, uvk, sealed, ad)
    } catch (e: CryptoException) {
        null
    } catch (e: IllegalArgumentException) {
        null
    }

    fun all(uvk: GuardedKey): List<LinkRecord> {
        val sealed = state.get(key) ?: return emptyList()
        // The next write seals the list again under [ad]. The UVK under the account's guard: a wiped account throws (a
        // lock), never reads as "no records", which a write would then make true.
        val plain = uvk.use { k -> open(k, sealed, ad) ?: open(k, sealed, adBefore) } ?: return emptyList()
        return try {
            WireJson.strict.decodeFromString(ListSerializer(LinkRecord.serializer()), plain.decodeToString())
        } catch (e: Exception) {
            emptyList()
        } finally {
            plain.fill(0)
        }
    }

    fun get(uvk: GuardedKey, linkId: String): LinkRecord? = all(uvk).firstOrNull { it.linkId == linkId }

    fun put(uvk: GuardedKey, record: LinkRecord) = write(uvk, all(uvk).filterNot { it.linkId == record.linkId } + record)

    fun remove(uvk: GuardedKey, linkId: String) = write(uvk, all(uvk).filterNot { it.linkId == linkId })

    /**
     * Writes [records]; every link of the previous list that is not among them is remembered as DROPPED by this device
     * (expired, revoked, ignored or processed) until its expiry plus [DROPPED_MARGIN_MS], so a later answer to it is
     * still this device's to acknowledge. Only public link ids and times are kept, in the clear.
     */
    fun write(uvk: GuardedKey, records: List<LinkRecord>) {
        val gone = all(uvk).filter { old -> records.none { it.linkId == old.linkId } }
        if (gone.isNotEmpty()) {
            val ids = gone.map { it.linkId }.toSet()
            writeDropped(dropped().filterNot { it.linkId in ids } + gone.map { DroppedLink(it.linkId, it.expiresAt + DROPPED_MARGIN_MS) })
        }
        if (records.isEmpty()) {
            state.set(key, null)
            return
        }
        val plain = WireJson.json.encodeToString(ListSerializer(LinkRecord.serializer()), records).encodeToByteArray()
        try {
            state.set(key, uvk.use { Envelope.sealB64(crypto, it, plain, ad) })
        } finally {
            plain.fill(0)
        }
    }

    private val droppedKey = "ovh.links.dropped|$origin|$userId"

    private fun dropped(): List<DroppedLink> {
        val text = state.get(droppedKey) ?: return emptyList()
        return try {
            WireJson.strict.decodeFromString(ListSerializer(DroppedLink.serializer()), text)
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun writeDropped(list: List<DroppedLink>) {
        // Bounded: the newest `until` first (link_create allows 30 a day, each kept at most about 38 days).
        val kept = list.sortedByDescending { it.until }.take(MAX_DROPPED)
        state.set(droppedKey, if (kept.isEmpty()) null else WireJson.json.encodeToString(ListSerializer(DroppedLink.serializer()), kept))
    }

    /** True when this device created [linkId] and dropped its record, and the tombstone has not run out at [nowMs]. */
    fun wasDropped(linkId: String, nowMs: Long): Boolean = dropped().any { it.linkId == linkId && nowMs < it.until }

    /** Forget the tombstones that ran out by [nowMs]. */
    fun pruneDropped(nowMs: Long) {
        val all = dropped()
        val kept = all.filter { nowMs < it.until }
        if (kept.size != all.size) writeDropped(kept)
    }

    companion object {
        /**
         * How long after a dropped link's expiry its id is still this device's: the server lists an answered link until
         * it is acknowledged or the janitor deletes it 30 days after it left `open` (spec 03 §15), plus a day.
         */
        const val DROPPED_MARGIN_MS: Long = 31L * 24 * 60 * 60 * 1000
        const val MAX_DROPPED = 2000
    }
}

/** A link this device created and then dropped, remembered until [until] (public id and time only). */
@Serializable
internal data class DroppedLink(val linkId: String, val until: Long)

/**
 * One side's comparison of one link (design §6.11), kept in device state for the account. Neither nonce here is secret
 * (the reveal is public and the answer carries `nonceB`); the code is fixed ONCE from the first accepted value of the
 * other side's nonce (T2-R-b) and never recomputed. [contactKey] and [label] are the key and `name` the other side's
 * signed statement carried. [replacesKey]: a contact for that userId exists under another key, and only this device's
 * own matched entry replaces it. [contactSaved]: the uncompared contact was written to account state.
 * [code] is THIS side's own code ([role]'s [LinkSide], §2.3), the one its screen shows; the other side's code, the only
 * one [WireLinkFlows.typeCode] accepts, is derived from the fixed inputs here when the person types and is never stored.
 */
@Serializable
internal data class CodeRecord(
    val linkId: String,
    val role: String,
    val contactUserId: String,
    val contactKey: String,
    val label: String,
    val offerHash: String,
    val answerHash: String,
    val nonceB: String,
    val commit: String? = null,
    val nonceA: String? = null,
    val code: String? = null,
    val failed: Boolean = false,
    val compared: Boolean = false,
    val replacesKey: Boolean = false,
    val contactSaved: Boolean = false,
    val shares: List<StoredShare> = emptyList(),
    val at: Long,
) {
    /** The side of the link this record is, from [role]; null for a role this build does not know (read as failed). */
    fun side(): LinkSide? = LinkSide.fromCode(role)

    companion object {
        const val CREATOR = "creator"
        const val ANSWERER = "answerer"
    }
}

internal class CodeRecordStore(private val state: DeviceState, private val origin: String, private val userId: String) {
    private val key = "ovh.codes|$origin|$userId"

    fun all(): List<CodeRecord> {
        val text = state.get(key) ?: return emptyList()
        return try {
            WireJson.strict.decodeFromString(ListSerializer(CodeRecord.serializer()), text)
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun byLink(linkId: String): CodeRecord? = all().firstOrNull { it.linkId == linkId }

    /** The latest record with [contactUserId] (the most recent link wins). */
    fun latestFor(contactUserId: String): CodeRecord? = all().filter { it.contactUserId == contactUserId }.maxByOrNull { it.at }

    fun put(record: CodeRecord) = write(all().filterNot { it.linkId == record.linkId } + record)

    fun write(records: List<CodeRecord>) =
        state.set(key, if (records.isEmpty()) null else WireJson.json.encodeToString(ListSerializer(CodeRecord.serializer()), records))
}

/**
 * This device's `pins.confirmed = {userId, keyHash}` records (design §6.9): which contacts are CURRENT here and how.
 * Keyed by the hex SHA-256 of the contact's raw key, so a record for one key never makes another key current.
 * A record list that does not decode is read as empty: nothing is current until re-confirmed (fail closed).
 */
class ContactCurrency(private val state: DeviceState, private val crypto: CryptoProvider, origin: String, userId: String) {
    @Serializable
    private data class Stored(val userId: String, val keyHash: String, val how: String)

    private val key = "ovh.current|$origin|$userId"
    private val oneTapKey = "ovh.onetap|$origin|$userId"

    private fun all(): List<Stored> {
        val text = state.get(key) ?: return emptyList()
        return try {
            WireJson.strict.decodeFromString(ListSerializer(Stored.serializer()), text)
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun write(list: List<Stored>) =
        state.set(key, if (list.isEmpty()) null else WireJson.json.encodeToString(ListSerializer(Stored.serializer()), list))

    /** The lowercase hex SHA-256 of a `b64_32` key; null when it is not one. */
    fun keyHash(identityPubB64: String): String? = Bytes.fromB64Exact(identityPubB64, 32)?.let { Bytes.toHexLower(crypto.sha256(it)) }

    /** How [userId] under [identityPubB64] is current here, or null when it is not. */
    fun currency(userId: String, identityPubB64: String): Currency? {
        val h = keyHash(identityPubB64) ?: return null
        val s = all().firstOrNull { it.userId == userId && it.keyHash == h } ?: return null
        return Currency.entries.firstOrNull { it.code == s.how }
    }

    /** Make [userId] under the key hashing to [keyHash] current here, replacing any record for another key. */
    internal fun markHash(userId: String, keyHash: String, how: Currency) =
        write(all().filterNot { it.userId == userId } + Stored(userId, keyHash, how.code))

    internal fun mark(userId: String, identityPubB64: String, how: Currency): Boolean {
        val h = keyHash(identityPubB64) ?: return false
        markHash(userId, h, how)
        return true
    }

    internal fun drop(userId: String) = write(all().filterNot { it.userId == userId })

    internal fun oneTapShown(): Boolean = state.get(oneTapKey) == "1"

    internal fun setOneTapShown() = state.set(oneTapKey, "1")
}
