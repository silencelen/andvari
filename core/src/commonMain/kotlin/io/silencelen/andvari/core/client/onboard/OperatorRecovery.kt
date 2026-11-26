package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.client.recovery.EscrowRules
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.model.wire.InstanceResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.TrustGrammar

/**
 * The checks every operator-recovery choice runs (design §4.5, §7.7), shared by registration and Settings: the pinned
 * card offers it (kind `private`, a `recoveryFp`; variant R compiled in for `public`), the served recovery key hashes to
 * that `recoveryFp` at full length, and the first-consent walk over the WHOLE verified chain from card 0 (FS-R2, FC-2).
 */
internal object OperatorRecovery {
    /** What the served chain and rotations came to, for a pin that is the newest card served. */
    class Served(
        val pin: CardPin,
        val rotations: List<ByteArray>,
        val clean: Boolean,
        /** The verified chain's cards, card 0 first, ending at the pinned card. */
        val cards: List<io.silencelen.andvari.core.trust.CardFields> = emptyList(),
    )

    /** True when [pin] offers operator recovery at all (variant R: never for a `public` card). */
    fun offered(pin: CardPin): Boolean = pin.kind == InstanceKind.PRIVATE.literal && pin.recoveryFp != TrustGrammar.NONE

    /**
     * The pinned card of [origin], refreshed so it is the newest card served; the served rotations; and whether every
     * `recoveryFp` change from card 0 to it is covered by rotations (the shared verifiers' linear walk; not clean shows the warning,
     * "Only me" preselected). Null when the chain does not extend the pin.
     */
    suspend fun served(client: WireClient, trust: InstanceTrust, crypto: CryptoProvider, origin: String): Served? {
        val pin = when (val s = trust.refresh(origin)) {
            is CardStatus.Ok -> s.pin
            else -> return null
        }
        val resp = (client.call(WireRoute.INSTANCE, decode = { WireJson.json.decodeFromString(InstanceResponse.serializer(), it) }) as? WireResult.Ok)?.value ?: return null
        val frames = resp.cards.map { Bytes.fromB64Canonical(it) ?: return null }
        val rotations = resp.rotations.orEmpty().map { Bytes.fromB64Canonical(it) ?: return null }
        val chain = InstanceCard.verifyChain(crypto, frames)
        if (chain.verdict != null) return null
        val cards = chain.chain.cards
        // The walk is over the whole verified chain from card 0, which must be the pin's chain and end at the pinned card.
        if (cards.isEmpty() || cards[0].hash != pin.card0Hash || cards.last().hash != pin.hash) return null
        val clean = EscrowRules.firstConsentClean(crypto, cards.map { it.fields }, rotations)
        return Served(pin, rotations, clean, cards.map { it.fields })
    }

    /** The served recovery public key when it hashes to [fp] at full length; null otherwise. */
    suspend fun recoveryKey(client: WireClient, crypto: CryptoProvider, fp: String): ByteArray? {
        val text = (client.call(WireRoute.RECOVERY_PUBKEY, decode = { it }) as? WireResult.Ok)?.value ?: return null
        val key = Bytes.fromB64Exact(text.trim(), 32) ?: return null
        return key.takeIf { Escrow.fingerprint(crypto, it) == fp }
    }

    /** The offer of operator recovery on [origin]'s pinned card, or null when it is not offered. */
    suspend fun offer(client: WireClient, trust: InstanceTrust, crypto: CryptoProvider, origin: String): OperatorRecoveryOffer? {
        val start = trust.pinFor(origin) ?: return null
        if (!offered(start)) return null
        val served = served(client, trust, crypto, origin) ?: return null
        val pin = served.pin
        if (!offered(pin)) return null
        val key = recoveryKey(client, crypto, pin.recoveryFp) ?: return null
        return OperatorRecoveryOffer(pin.name, pin.origin, !served.clean, pin.hash, pin.recoveryFp, key)
    }
}
