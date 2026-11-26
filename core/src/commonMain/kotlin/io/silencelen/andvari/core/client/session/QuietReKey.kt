package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.KdfUpgrade
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.account.WireAccountSettings
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.model.wire.PasswordChangeRequest
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CancellationException

/**
 * What the quiet re-key after a full-password opening came to (spec 01 §7, "KDF upgrade"). The person is never shown
 * it: the opening had already succeeded, whatever this answers, and every answer leaves the account openable with the
 * same password.
 */
enum class ReKeyOutcome {
    /** The policy asks for no more than the account has, or for a lower, mixed, ragged or absurd cost: nothing sent. */
    NOT_DUE,

    /** No policy came back (offline, or nothing may be dialed there): nothing sent; the next full-password opening looks again. */
    NO_POLICY,

    /** The opening asked for "not now" (one that must be fast, such as the Android autofill overlay): nothing done. */
    PUT_OFF,

    /** The open session was not opened with the full password in this opening (a quick unlock), or none is open: nothing done. */
    NOT_FULL_PASSWORD,

    /** A password change sent earlier could not be settled against the server's keys: nothing sent. */
    UNSETTLED,

    /** The password gate or the device's own proof refused: nothing sent. */
    NOT_PROVEN,

    /** A lock, an end or another session came first: nothing sent and no pending record kept. */
    STALE,

    /** The server took it: this device keeps exactly the wrap it sent, at the policy's cost. */
    DONE,

    /** The server answered that it was not made: that request's wrap is dropped, and only that one. */
    REFUSED,

    /** No answer, or a server error: the wrap stays pending, and the next opening settles it. */
    UNKNOWN,

    /** This device could not derive or seal (its crypto provider failed): nothing sent. */
    FAILED,

    /**
     * This opening already ran the step (spec 01 §7: once per opening): this call read nothing, derived nothing and
     * sent nothing. What the first call came to is [SessionKeeper.lastReKey].
     */
    ALREADY_RAN,
}

/**
 * What a full-password opening found when it read the account's keys as the server holds them and compared the wrap
 * there with this device's own (spec 01 §7, the pending-record rule). Never shown as it stands: [NOT_THIS_DEVICES] is
 * kept on the session ([KeptSession.serverKeysNotKnownHere]) for the app interface to word.
 */
enum class ServedWrap {
    /** The server serves this device's own wrap or its pending one; the pending-record rule settled the latter. */
    KNOWN,

    /**
     * Neither, and the password this opening verified opened it, under the served salt and cost (inside the fence), to
     * exactly the account key this device holds: it is this device's own wrap from now on.
     */
    ADOPTED,

    /**
     * Neither, and its cost failed the fence, or it did not open with that password, or it opened to another key: nothing
     * changed ("leaves both"). The account's keys on the server are not the ones this device knows: never a wrong password.
     */
    NOT_THIS_DEVICES,

    /** Nothing came back from the server, nothing may be dialed, or the opening was not one with the full password. */
    NOT_READ,

    /** A lock, an end or another session came while it was looked at: nothing changed. */
    STALE,
}

/**
 * The one open-and-compare of a served wrap (spec 01 §7, the pending-record rule), used by the engine's keeper at an
 * opening and by a held session's [io.silencelen.andvari.core.client.onboard.EstablishedSession.settleServed]: [password]
 * (borrowed: only a copy is derived from, and that copy is wiped) opens [served]'s wrap, under its own salt and cost, to
 * exactly the key [account] holds, compared in constant time. The whole fence runs first, so a cost outside it is never
 * derived at; a salt that does not decode, a wrap that does not open and another key all answer false. Nothing derived
 * is kept: the derived keys and the opened key are wiped before this returns. Throws
 * [io.silencelen.andvari.core.crypto.KeysGoneException] when a lock erased the account's key meanwhile.
 */
internal fun servedWrapOpensToKey(crypto: CryptoProvider, userId: String, served: io.silencelen.andvari.core.model.wire.AccountKeys, account: OpenedAccount, password: CharArray): Boolean {
    if (!KdfUpgrade.withinFence(served.kdfParams)) return false
    val salt = runCatching { Bytes.fromB64(served.kdfSalt) }.getOrNull() ?: return false
    val keys = try {
        PasswordKeys.derive(crypto, password.copyOf(), salt, served.kdfParams, served = true)
    } catch (e: CryptoException) {
        null
    } catch (e: IllegalArgumentException) {
        null
    } ?: return false
    val uvk = try {
        Envelope.openB64(crypto, keys.wrapKey, served.wrappedUvk, Ad.uvk(userId))
    } catch (e: CryptoException) {
        null
    } catch (e: IllegalArgumentException) {
        null
    } finally {
        keys.wipe()
    }
    if (uvk == null) return false
    return try {
        account.uvk.use { Bytes.ctEquals(uvk, it) }
    } finally {
        uvk.fill(0)
    }
}

/**
 * The device's own record of the account's wrap, as the re-key reads and settles it: the engine's [SessionKeeper] for
 * the apps, a held [io.silencelen.andvari.core.client.onboard.EstablishedSession] for a host that keeps its session
 * itself (the command-line tool). Public values only cross it: salts, costs, wrapped keys.
 */
internal interface WrapRecord {
    /** The account whose key is re-wrapped: the envelope's associated data names it. */
    val userId: String

    /** The KDF cost of this device's own wrap of the account's key; null when there is none. */
    fun ownParams(): KdfParams?

    fun hasPending(): Boolean

    /**
     * Settle the pending record against the account's keys as the server holds them (`GET /account/keys`, read now or
     * already read by this opening); true when none is left.
     */
    suspend fun settle(): Boolean

    /** The in-session proof of spec 01 §7: the password gate, then [password] (wiped) against this device's own wrap. */
    suspend fun prove(password: CharArray): ReauthKey

    /** True while the opening this re-key belongs to is still the open one (no lock, no end, no other session). */
    fun current(): Boolean

    /** Keep [wrap] as pending before the request goes; false, with nothing kept, when another one is pending. */
    fun keepPending(wrap: WireAccountSettings.NewWrap): Boolean

    /** The request carrying [wrap] is on its way ([wrap]) or answered (null): a settle meanwhile must not drop it. */
    fun inFlight(wrap: WireAccountSettings.NewWrap?)

    fun taken(wrap: WireAccountSettings.NewWrap)

    fun notTaken(wrap: WireAccountSettings.NewWrap)
}

/**
 * Spec 01 §7, "KDF upgrade (F61, normative)", on the new engine: inside the opening that verified the master password,
 * with the server reachable, when [KdfUpgrade.belowServed] says the account is below the policy's cost on any figure (the
 * policy inside this client's fence), the account's key is wrapped again under the same password at
 * [KdfUpgrade.wrapCost] (figure by figure the higher of the policy's and the account's; a fresh 16-byte salt)
 * and sent as the same atomic `PUT /account/password` a password change makes. The password is the one it just
 * verified; the person is not asked anything.
 *
 * The order, each step for its own reason:
 * 1. The policy, read now ([policy]); none (offline) is [ReKeyOutcome.NO_POLICY] with nothing sent.
 * 2. A password change whose answer never came is settled first, against the server's keys (the pending-record rule
 *    of spec 01 §7); while it settles neither way, nothing is sent ([ReKeyOutcome.UNSETTLED]). Due is decided again
 *    on the cost the settled wrap has.
 * 3. The new keys at the policy's cost (the fence again: the policy came from the server), and the account's key sealed
 *    under them inside the guard: a lock that came refuses the seal, and nothing is sent.
 * 4. The proof of the current password, the in-session proof of spec 01 §7 ([WrapRecord.prove]): the password gate,
 *    then the device's own wrap under its own salt and cost; nothing a server names now goes into it.
 * 5. That proof was a wait: the keys and the session are checked again before anything is kept or sent.
 * 6. The wrap is kept as pending, then the request goes, so a lost answer leaves this device able to open whichever
 *    wrap the server holds (both open with the same password).
 * 7. The answer, read without a key: taken, this device keeps exactly the wrap it sent; refused, only that wrap goes;
 *    no answer or a server error, it stays pending for the next opening to settle.
 *
 * [password] and every key derived here are wiped before this returns, whatever happens: nothing of them outlives the
 * opening, and nothing is kept for later. A failure of any kind is an answer, never a throw (a cancel excepted).
 */
internal object QuietReKey {
    suspend fun run(
        crypto: CryptoProvider,
        client: WireClient,
        account: OpenedAccount,
        record: WrapRecord,
        password: CharArray,
        policy: suspend () -> KdfParams?,
    ): ReKeyOutcome {
        try {
            if (!record.current()) return ReKeyOutcome.STALE
            val target = policy() ?: return ReKeyOutcome.NO_POLICY
            if (!record.current()) return ReKeyOutcome.STALE
            if (!due(record, target)) return ReKeyOutcome.NOT_DUE
            if (record.hasPending()) {
                val settled = record.settle()
                if (!record.current()) return ReKeyOutcome.STALE
                if (!settled) return ReKeyOutcome.UNSETTLED
                if (!due(record, target)) return ReKeyOutcome.NOT_DUE
            }
            // The wrap's cost by the one rule for every new wrap ([KdfUpgrade.wrapCost]): figure by figure the higher of the
            // served cost and the account's, so a figure the account lacks is raised and none is lowered.
            return send(crypto, client, account, record, password, KdfUpgrade.wrapCost(target, record.ownParams()))
        } catch (e: CancellationException) {
            throw e
        } catch (e: KeysGoneException) {
            return ReKeyOutcome.STALE
        } catch (e: CryptoException) {
            return ReKeyOutcome.FAILED
        } finally {
            password.fill('\u0000')
        }
    }

    private fun due(record: WrapRecord, target: KdfParams): Boolean {
        val own = record.ownParams() ?: return false
        // Due when the account is below the served cost on ANY figure (decided on 2026-11-17); before, only where the served
        // cost dominated on both, so an account above it on one figure and below on the other was never raised.
        return KdfUpgrade.belowServed(own, target)
    }

    private suspend fun send(
        crypto: CryptoProvider,
        client: WireClient,
        account: OpenedAccount,
        record: WrapRecord,
        password: CharArray,
        target: KdfParams,
    ): ReKeyOutcome {
        val forNew = password.copyOf()
        val keys = PasswordKeys.derive(crypto, forNew, crypto.randomBytes(KdfParams.SALT_BYTES), target, served = true) ?: return ReKeyOutcome.NOT_DUE
        try {
            // The derivation was a wait: a lock that came during it refuses the seal (rule 3), and nothing is sent.
            val wrapped = account.uvk.use { Envelope.sealB64(crypto, keys.wrapKey, it, Ad.uvk(record.userId)) }
            val wrap = WireAccountSettings.NewWrap(Bytes.toB64(keys.salt), keys.params, wrapped)
            val current = when (val proof = record.prove(password)) {
                is ReauthKey.Key -> proof.currentAuthKey
                else -> return ReKeyOutcome.NOT_PROVEN
            }
            // The proof was a wait too: nothing built from the keys is kept or sent once they are wiped.
            account.guard.check()
            if (!record.current()) return ReKeyOutcome.STALE
            if (!record.keepPending(wrap)) return ReKeyOutcome.UNSETTLED
            val body = PasswordChangeRequest(current, keys.authKeyB64, wrap.kdfSalt, wrap.kdfParams, wrap.wrappedUvk)
            record.inFlight(wrap)
            val r = try {
                client.call(WireRoute.PASSWORD_CHANGE, bodyJson = WireJson.json.encodeToString(PasswordChangeRequest.serializer(), body), decode = { })
            } finally {
                record.inFlight(null)
            }
            // The answer is taken without a key (rule 6): a lock that came while it was on its way changes none of this.
            return when {
                r is WireResult.Ok -> ReKeyOutcome.DONE.also { record.taken(wrap) }
                r is WireResult.Refused && r.status in 1..499 -> ReKeyOutcome.REFUSED.also { record.notTaken(wrap) }
                // Status 0 is this device's own refusal before sending (a stopped origin): nothing reached the server.
                r is WireResult.Refused && r.status <= 0 -> ReKeyOutcome.REFUSED.also { record.notTaken(wrap) }
                else -> ReKeyOutcome.UNKNOWN
            }
        } finally {
            keys.wipe()
        }
    }
}
