package io.silencelen.andvari.core.client.state

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.GuardedKey
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.model.wire.AccountStatePut
import io.silencelen.andvari.core.model.wire.AccountStateResponse
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute

/**
 * [AccountStateStore] over `GET/PUT /account/state` (spec 03 §3, spec 02 §9).
 *
 * Trust: a served blob is used only if it opens under the UVK with AD `andvari/v1|account-state|{userId}`
 * and decodes as this account's v2 document; it is then MERGED, never adopted, so the server alone can
 * only withhold or roll back (both reported) and nothing the local copy holds is lost. The local copy is
 * kept sealed under the UVK in device state, with the high-water mark of the in-blob `seq` and the
 * server's CAS token. [uvk] is borrowed; the caller wipes it at lock.
 */
class StoredAccountState(
    private val userId: String,
    private val uvk: GuardedKey,
    private val client: WireClient,
    private val crypto: CryptoProvider,
    private val state: DeviceState,
    private val maxAttempts: Int = 4,
    private val limits: AccountLimits = AccountLimits.DEFAULT,
) : AccountStateStore {
    private val kSealed = "ovh.acct|$userId|sealed"
    private val kHigh = "ovh.acct|$userId|hw"
    private val kCas = "ovh.acct|$userId|cas"
    private val kSeen = "ovh.acct|$userId|seen"
    private val kCheckpoint = "ovh.acct|$userId|checkpoint"

    /** Remember the served (or written) [sealed] string of the document whose in-blob seq is [seq] (design §8.3). */
    private fun noteServed(seq: Long, sealed: String) =
        state.set(kCheckpoint, seq.toString() + ":" + Bytes.toHexLower(crypto.sha256(sealed.encodeToByteArray())))

    override fun checkpoint(): Pair<Long, String>? {
        val text = state.get(kCheckpoint) ?: return null
        val seq = text.substringBefore(':').toLongOrNull() ?: return null
        val hash = text.substringAfter(':').takeIf { io.silencelen.andvari.core.trust.TrustGrammar.isHex64(it) } ?: return null
        return seq to hash
    }

    override fun raiseHighWater(seq: Long) {
        // An unreadable mark is unknown: it is never replaced (read and update stop on it until it reads again).
        if (stored() == null) return
        val hw = highWaterOrNull() ?: return
        if (seq > hw) state.set(kHigh, seq.toString())
    }

    /**
     * The document [sealed] holds, or null when it does not open or decode. The UVK is used under the account's guard,
     * outside the catch: a wiped account throws (a lock), never reads as an unreadable copy that the server's would then
     * replace.
     */
    private fun open(sealed: String): AccountDocument? {
        val plain = uvk.use { k -> runCatching { Envelope.openB64(crypto, k, sealed, Ad.accountState(userId)) }.getOrNull() } ?: return null
        val text = runCatching { plain.decodeToString(throwOnInvalidSequence = true) }.getOrNull() ?: return null
        return AccountDocumentCodec.decode(userId, text)?.document
    }

    /** [doc] sealed under the UVK, under the account's guard: after a wait (a read, a refusal) a wiped account throws. */
    private fun seal(doc: AccountDocument): String =
        uvk.use { Envelope.sealB64(crypto, it, AccountDocumentCodec.encode(userId, doc).encodeToByteArray(), Ad.accountState(userId)) }

    /**
     * The local copy as this device holds it. A stored copy that cannot be read (a storage error, or a blob that no
     * longer opens) reads as [AccountDocument.EMPTY] HERE ONLY, for display; [read] and [update] check [readable] first
     * and stop, so such a copy is never merged with, or overwritten by, what the server serves.
     */
    override fun local(): AccountDocument = stored() ?: AccountDocument.EMPTY

    override fun localReadable(): Boolean = stored() != null && highWaterOrNull() != null

    override fun heldCounter(): Long? = try { state.get(kCas)?.toLongOrNull() } catch (e: Exception) { null }

    /** The stored copy: EMPTY when none is stored, null when one is stored and cannot be read. */
    private fun stored(): AccountDocument? {
        val text = try { state.get(kSealed) } catch (e: Exception) { return null } ?: return AccountDocument.EMPTY
        return open(text)
    }

    /** The high-water mark: 0 when none is stored, null when one is stored and cannot be read. */
    private fun highWaterOrNull(): Long? {
        val text = try { state.get(kHigh) } catch (e: Exception) { return null } ?: return 0L
        return text.toLongOrNull()
    }

    private fun highWater(): Long = highWaterOrNull() ?: error("unreadable high-water mark")

    /** The code to stop on, or null when every record this store keeps can be read and the origin may be dialed. */
    private fun stop(): String? = when {
        client.stopped -> io.silencelen.andvari.core.client.net.ORIGIN_STOPPED
        stored() == null || highWaterOrNull() == null -> RECORD_UNREADABLE
        else -> null
    }

    private fun keep(doc: AccountDocument, cas: Long?) {
        state.set(kSealed, seal(doc))
        state.set(kHigh, maxOf(highWater(), doc.seq).toString())
        if (cas != null) state.set(kCas, cas.toString())
    }

    override suspend fun read(): AccountStateRead {
        stop()?.let { return AccountStateRead.Stopped(it) }
        val r = client.call(WireRoute.ACCOUNT_STATE_GET, decode = { WireJson.json.decodeFromString(AccountStateResponse.serializer(), it) })
        val resp = when (r) {
            is WireResult.Ok -> r.value
            else -> return AccountStateRead.Unreachable
        }
        val local = local()
        val sealed = resp.sealedState
        if (sealed == null) {
            val anomalies = if (state.get(kSeen) == "1") listOf(MergeAnomaly.Withheld) else emptyList()
            state.set(kCas, resp.seq.toString())
            return AccountStateRead.Ok(local, anomalies)
        }
        val served = open(sealed) ?: return AccountStateRead.Unopenable
        state.set(kSeen, "1")
        noteServed(served.seq, sealed)
        val anomalies = ArrayList<MergeAnomaly>()
        val hw = highWater()
        if (served.seq < hw) anomalies += MergeAnomaly.Rollback(served.seq, hw)
        val merged = AccountMerge.merge(local, served, limits)
        anomalies += merged.anomalies
        keep(merged.document, resp.seq)
        return AccountStateRead.Ok(merged.document, anomalies)
    }

    override suspend fun update(change: (AccountDocument) -> AccountDocument): AccountStateWrite =
        updateVia(change) { put ->
            client.call(WireRoute.ACCOUNT_STATE_PUT, bodyJson = WireJson.json.encodeToString(AccountStatePut.serializer(), put),
                decode = { WireJson.json.decodeFromString(AccountStateResponse.serializer(), it) })
        }

    /**
     * [update], with the sealed document handed to [send] instead of `PUT /account/state`: a route that carries
     * `accountState: {sealedState, baseSeq}` beside its own fields (`PUT /account/recovery`, spec 03 §3, FI-R5) and answers
     * the new compare-and-set token. A `409 stale_state` merges and retries, as on the plain route; any other refusal is
     * returned as is ([AccountStateWrite.Refused] with its code).
     */
    suspend fun updateVia(change: (AccountDocument) -> AccountDocument, send: suspend (AccountStatePut) -> WireResult<AccountStateResponse>): AccountStateWrite {
        repeat(maxAttempts) {
            when (val read = read()) {
                is AccountStateRead.Ok -> {}
                AccountStateRead.Unopenable -> return AccountStateWrite.Refused("unopenable")
                AccountStateRead.Unreachable -> return AccountStateWrite.Unknown
                is AccountStateRead.Stopped -> return AccountStateWrite.Refused(read.code)
            }
            val base = local()
            val next = change(base)
            if (next == base) return AccountStateWrite.Unchanged(base)
            // A document whose in-blob seq cannot be advanced is damaged: nothing is written, no loop.
            if (base.seq >= MAX_SEQ) return AccountStateWrite.Refused(DAMAGED)
            // The caps and the size rule hold on write as on merge (§5.4): unknown keys go first, then the
            // records of vaults the account has left. A document that still does not fit is not written; the
            // merged document this read kept is still the one read.
            val bounded = AccountMerge.bound(next.copy(seq = base.seq + 1), limits)
            if (!bounded.fits) return AccountStateWrite.Refused(FULL)
            val doc = bounded.document
            val sealed = seal(doc)
            if (sealed.length > limits.sealedChars) return AccountStateWrite.Refused(FULL)
            val cas = state.get(kCas)?.toLongOrNull() ?: 0L
            when (val w = send(AccountStatePut(sealed, cas))) {
                is WireResult.Ok -> {
                    keep(doc, w.value.seq)
                    noteServed(doc.seq, sealed)
                    state.set(kSeen, "1")
                    return AccountStateWrite.Written(doc)
                }
                is WireResult.Refused -> if (w.code != WireErrors.STALE_STATE) return AccountStateWrite.Refused(w.code)
                is WireResult.NoAnswer -> return AccountStateWrite.Unknown
            }
        }
        return AccountStateWrite.Contended
    }

    companion object {
        /**
         * The account-state store of [account]'s session, its UVK taken from the opened account itself, so a host never
         * holds the key as a value ([account]'s wipe wipes it here too).
         */
        fun forAccount(
            account: io.silencelen.andvari.core.client.onboard.OpenedAccount,
            client: WireClient,
            crypto: CryptoProvider,
            state: DeviceState,
        ): StoredAccountState = StoredAccountState(account.userId, account.uvk, client, crypto, state)

        /** `ACCOUNT_STATE_SEALED_MAX` (spec 02 §9): 1 MiB of base64. */
        const val SEALED_MAX = AccountLimits.SEALED_MAX

        /** The largest in-blob seq (`2^53 - 1`); a document at it cannot be advanced. */
        const val MAX_SEQ = io.silencelen.andvari.core.trust.TrustGrammar.INT_CEILING - 1

        /** The refusal code of a document whose seq cannot be advanced. */
        const val DAMAGED = "account_state_damaged"

        /** The refusal code of a document that does not fit its size even after every drop (design §5.4). */
        const val FULL = "account_state_full"

        /** A record this device keeps is stored but cannot be read: unknown, so nothing is sent or written (design §4.4). */
        const val RECORD_UNREADABLE = "record_unreadable"
    }
}
