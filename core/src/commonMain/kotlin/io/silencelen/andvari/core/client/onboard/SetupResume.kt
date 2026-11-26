package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.account.Reauth
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.model.wire.InstanceCardPut
import io.silencelen.andvari.core.model.wire.InstanceCardPutResponse
import io.silencelen.andvari.core.model.wire.InstanceResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.SignedFrame
import io.silencelen.andvari.core.trust.TrustGrammar

/** Whether "Finish setting up this server" is due for the signed-in operator (design §6.7 Resume, §9.5). */
sealed class SetupDue {
    /** The instance serves a card (or this session is not the operator's): nothing to finish. */
    data object No : SetupDue()

    /**
     * No card is served and this is the operator's session: offer "Finish setting up this server", naming [name] and
     * [origin]. [fromKeptOffer] is true when the values come from the setup offer this device opened; false when they
     * come from `GET /instance`'s `setup` block on a device that never saw the offer.
     */
    data class Due(val name: String, val origin: String, val kind: String, val fromKeptOffer: Boolean) : SetupDue()

    data object Unreachable : SetupDue()
}

/**
 * "Finish setting up this server" (design §6.7 Resume, R10; spec 03 §17.1, §17.2): when the app stopped between the
 * setup registration and card 0, the operator account's next unlock on ANY device signs card 0 with its own key from
 * the kept setup offer, or, on a device that never saw it, from `GET /instance`'s `setup` block, uploads it with a fresh
 * `currentAuthKey` (the one [Reauth] path) and pins it through the setup root.
 *
 * Trust: a served `setup` block is never a pin; it only supplies the fields this account signs, and it is refused when
 * it names another origin than the session's, or operator recovery on a `public` instance. The server's card 0 checks
 * bind the card to the operator account and to what `andvari setup` wrote either way, and the pin is made only from the
 * card 0 this device signed ([InstanceTrust.pinFromOwnCard0]). [session] is borrowed.
 */
class SetupResume(
    private val session: EstablishedSession,
    private val client: WireClient,
    private val crypto: CryptoProvider,
    private val state: DeviceState,
    private val trust: InstanceTrust,
    private val reauth: Reauth,
    private val clock: () -> Long,
) {
    private val origin get() = session.origin

    private class Values(val instanceId: String, val name: String, val kind: InstanceKind, val recoveryFp: String, val kept: Boolean)

    /** What the served instance and this device's kept offer say; a [SetupDue] when there is nothing to sign from. */
    private suspend fun values(): Any {
        if (session.role != "operator") return SetupDue.No
        val served = (client.call(WireRoute.INSTANCE, decode = { WireJson.json.decodeFromString(InstanceResponse.serializer(), it) }) as? WireResult.Ok)?.value
            ?: return SetupDue.Unreachable
        if (served.cards.isNotEmpty()) return StoredCard0(served.cards.first())
        SetupOffers(state).get(origin)?.let { k ->
            return Values(k.instanceId, k.name, InstanceKind.fromLiteral(k.kind)!!, k.recoveryFp, kept = true)
        }
        val s = served.setup ?: return SetupDue.No
        val name = TrustGrammar.decodeName(s.name)
        val kind = InstanceKind.fromLiteral(s.kind)
        val fpOk = s.recoveryFp == TrustGrammar.NONE || TrustGrammar.isHex64(s.recoveryFp)
        // Never another origin than the one this session talks to; never operator recovery on a public instance (variant R).
        if (s.origin != origin || name == null || kind == null || !fpOk || !TrustGrammar.isUuid(s.instanceId)) return SetupDue.No
        if (kind == InstanceKind.PUBLIC && s.recoveryFp != TrustGrammar.NONE) return SetupDue.No
        return Values(s.instanceId, name, kind, s.recoveryFp, kept = false)
    }

    /** The instance serves a card already: card 0 as served (a stored upload whose answer this device never got, or another's). */
    private class StoredCard0(val frameB64: String)

    suspend fun due(): SetupDue = when (val v = values()) {
        is SetupDue -> v
        is StoredCard0 -> SetupDue.No
        else -> (v as Values).let { SetupDue.Due(it.name, origin, it.kind.literal, it.kept) }
    }

    /**
     * Sign card 0 and upload it† with [password] (wiped), then pin it. Answers card 0's hash; `setup_done` when a card is
     * served by now, `card_mismatch` when the server stored another card 0, `pin_failed` when the pin was refused.
     */
    suspend fun finish(password: CharArray): Reauthed<String> {
        // Only the operator's session has a setup to finish; known here, with nothing sent.
        if (session.role != "operator") {
            password.fill('\u0000')
            return Reauthed.Refused(SETUP_DONE)
        }
        // The password first, proven on this device: the act sends its first request, the read of the served instance
        // included, only once the proof has held, so a wrong password sends nothing at all (spec 01 §7).
        val key = try {
            reauth.currentAuthKey(password)
        } finally {
            password.fill('\u0000')
        }
        val current = when (key) {
            is ReauthKey.Key -> key.currentAuthKey
            ReauthKey.Refused -> return Reauthed.NoSession
            ReauthKey.Unreachable -> return Reauthed.Unknown
            ReauthKey.WrongPassword -> return Reauthed.WrongPassword
        }
        val v = when (val x = values()) {
            is SetupDue -> return if (x is SetupDue.Unreachable) Reauthed.Unknown else Reauthed.Refused(SETUP_DONE)
            // A card is served: when it is the card 0 this account signed with its own key (an upload that was stored
            // and whose answer was lost), it is pinned now, behind the same password proof and with nothing
            // more sent; any other card is a finished setup.
            is StoredCard0 -> {
                // Already pinned here: nothing is left to finish.
                if (trust.pinState(origin) != io.silencelen.andvari.core.client.pin.PinState.None) return Reauthed.Refused(SETUP_DONE)
                val account = session.account
                if (trust.pinFromOwnCard0(origin, x.frameB64, session.userId, session.emailNorm, account.signing.publicKey) !is FirstPin.Pinned) {
                    return Reauthed.Refused(SETUP_DONE)
                }
                SetupOffers(state).remove(origin)
                val hash = runCatching { SignedFrame.hash(crypto, Bytes.fromB64(x.frameB64)) }.getOrNull() ?: return Reauthed.Refused(PIN_FAILED)
                return Reauthed.Done(hash)
            }
            else -> x as Values
        }
        val account = session.account
        val card = CardFields(
            v.instanceId, 0, TrustGrammar.ZERO_HASH, origin, v.name, v.kind, session.userId, Bytes.toB64(account.signing.publicKey),
            v.recoveryFp.takeIf { it != TrustGrammar.NONE }, clock(),
        )
        // Under the account's guard, after the re-authentication's wait; sent at once.
        val frame = account.signing.use { InstanceCard.sign(crypto, it, card) }
        val hash = SignedFrame.hash(crypto, frame)
        val frameB64 = Bytes.toB64(frame)
        val body = WireJson.json.encodeToString(InstanceCardPut.serializer(), InstanceCardPut(frameB64, current))
        when (val r = client.call(WireRoute.INSTANCE_CARD_PUT, bodyJson = body, decode = { WireJson.json.decodeFromString(InstanceCardPutResponse.serializer(), it) })) {
            is WireResult.Ok -> if (r.value.seq != 0L || r.value.hash != hash) return Reauthed.Refused(CARD_MISMATCH)
            is WireResult.Refused -> return when {
                r.code == Reauthed.PROOF_REFUSED -> Reauthed.Refused(Reauthed.PROOF_REFUSED, r.retryAfterSeconds)
                r.status >= 500 -> Reauthed.Unknown
                else -> Reauthed.Refused(r.code, r.retryAfterSeconds)
            }
            is WireResult.NoAnswer -> return Reauthed.Unknown
        }
        if (trust.pinFromOwnCard0(origin, frameB64, session.userId, session.emailNorm, account.signing.publicKey) !is FirstPin.Pinned) {
            return Reauthed.Refused(PIN_FAILED)
        }
        SetupOffers(state).remove(origin)
        return Reauthed.Done(hash)
    }

    companion object {
        const val SETUP_DONE = "setup_done"
        const val CARD_MISMATCH = "card_mismatch"
        const val PIN_FAILED = "pin_failed"
    }
}
