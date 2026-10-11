package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.model.AccountStatePut

/**
 * Client half of `/account/state` (security review 2026-10, root cause A §4.2): read, merge, write back.
 *
 * The blob is `Envelope(UVK, JSON, Ad.accountState(userId))`, so the server cannot add anything to it: an
 * injected or substituted blob does not open ([anomaly] = UNREADABLE, the local copy wins and is written
 * back). What the server CAN do is withhold it or serve an older one; this device keeps a high-water seq
 * and its own sealed copy (in [VaultCache.clientState], which survives a resync), so a served seq below the
 * high-water mark, or a withheld blob after one was seen, is a ROLLBACK ([anomaly]): the local copy wins
 * the merge and is written back. Rollback and withholding can only remove pins, never add one.
 *
 * Pins are added ONLY through [pin] with a [Contact] that [ContactPin] built from a human comparison.
 * Nothing in this class, or in [SyncEngine], pins a key the server served.
 */
class AccountStateSync(
    private val api: AndvariApi,
    private val account: Account,
    private val local: VaultCache,
    private val clock: () -> Long = { kotlinx.datetime.Clock.System.now().toEpochMilliseconds() },
) {
    enum class Anomaly { ROLLBACK, UNREADABLE }

    private val hwKey = "acctstate.hw"
    private val copyKey = "acctstate.copy"

    /** The current merged document (empty until the first [refresh] or a local copy exists). */
    var doc: AccountStateDoc = loadLocal() ?: AccountState.empty(account.userId)
        private set

    /** Set when the last [refresh] saw a rollback or an unreadable blob. Display once; never fatal. */
    var anomaly: Anomaly? = null
        private set

    /** True when the served blob is a newer FORMAT this client cannot read: never overwrite it. */
    var readOnly: Boolean = false
        private set

    private var serverSeq: Long = 0

    private fun highWater(): Long = local.clientState(hwKey)?.toLongOrNull() ?: 0L

    private fun loadLocal(): AccountStateDoc? = local.clientState(copyKey)?.let { sealed ->
        runCatching { account.openAccountState(sealed) }.getOrNull()
    }

    fun contacts(): List<Contact> = doc.contacts

    /** GET → open → merge with the local copy and high-water → write back when anything differs. */
    suspend fun refresh(): AccountStateDoc {
        repeat(3) {
            val resp = api.accountState()
            serverSeq = resp.seq
            var served: AccountStateDoc? = null
            var unreadable = false
            if (resp.sealedState != null) {
                try {
                    served = account.openAccountState(resp.sealedState)
                } catch (e: AccountStateException) {
                    // Opens under our UVK but is not a v1 document: a newer client wrote it. Read-only.
                    readOnly = true
                    anomaly = null
                    return doc
                } catch (e: CryptoException) {
                    unreadable = true
                } catch (e: IllegalArgumentException) {
                    unreadable = true
                }
            }
            val localDoc = loadLocal() ?: doc.takeIf { it.seq > 0 || it.contacts.isNotEmpty() }
            val hw = highWater()
            val merged = AccountState.merge(account.userId, localDoc, served, hw)
            anomaly = when {
                unreadable -> Anomaly.UNREADABLE
                merged.rollback -> Anomaly.ROLLBACK
                else -> null
            }
            val needsWrite = unreadable || merged.rollback || served == null && localDoc != null ||
                !AccountState.sameContent(merged.doc, served)
            if (!needsWrite || readOnly) {
                adopt(merged.doc, resp.sealedState)
                return doc
            }
            if (served == null && localDoc == null && merged.doc.contacts.isEmpty() && merged.doc.consumedNonces.isEmpty() &&
                merged.doc.orgRecoveryFp == null
            ) {
                // Nothing to say yet: do not create an empty blob just to have one (§8.2 step 1 creates
                // it lazily, on the first pin).
                doc = merged.doc
                return doc
            }
            if (write(merged.doc)) return doc
        }
        return doc
    }

    /** Write [next] with seq bumped past every value seen. False on a 409 (caller re-reads). */
    private suspend fun write(next: AccountStateDoc): Boolean {
        val bumped = next.copy(seq = maxOf(next.seq, highWater(), doc.seq) + 1)
        val sealed = account.sealAccountState(bumped)
        if (sealed.length > AccountState.SEALED_MAX) throw IllegalStateException("account state is too large")
        return try {
            val r = api.putAccountState(AccountStatePut(sealed, serverSeq))
            serverSeq = r.seq
            adopt(bumped, sealed)
            true
        } catch (e: ApiException) {
            if (e.status == 409) false else throw e
        }
    }

    private fun adopt(next: AccountStateDoc, sealed: String?) {
        doc = next
        if (next.seq > highWater()) local.setClientState(hwKey, next.seq.toString())
        val copy = sealed ?: runCatching { account.sealAccountState(next) }.getOrNull()
        if (copy != null) local.setClientState(copyKey, copy)
    }

    /**
     * Pin a contact that [ContactPin] built from a HUMAN comparison. Refuses a pin for this account
     * itself. Re-reads first so a pin made on another device is merged, then writes.
     */
    suspend fun pin(contact: Contact) {
        require(contact.userId != account.userId) { "cannot pin yourself" }
        if (readOnly) throw IllegalStateException("account state was written by a newer client")
        runCatching { refresh() }
        repeat(3) {
            if (write(AccountState.withContact(doc, contact))) return
            refresh()
        }
        throw IllegalStateException("account state kept changing; try again")
    }

    /** Remove a pin (tombstoned, so the removal survives merges with older copies). */
    suspend fun unpin(userId: String) {
        if (readOnly) throw IllegalStateException("account state was written by a newer client")
        runCatching { refresh() }
        repeat(3) {
            if (write(AccountState.withoutContact(doc, userId, clock()))) return
            refresh()
        }
        throw IllegalStateException("account state kept changing; try again")
    }
}
