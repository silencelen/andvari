package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.serialization.Serializable

/**
 * A setup offer this device opened, kept until card 0 is accepted (design §6.7 setup step 2, "Resume (R10)"): the
 * values card 0 is signed from. [name] is the decoded plain text; [recoveryFp] a `hex64` or `none`. The values came
 * from a host-minted offer that opened under the link's key (§6.4), never from a served JSON field.
 */
@Serializable
internal data class KeptSetup(val origin: String, val instanceId: String, val name: String, val kind: String, val recoveryFp: String) {
    fun valid(): Boolean = TrustGrammar.isOrigin(origin) && TrustGrammar.isUuid(instanceId) && TrustGrammar.encodeName(name) != null &&
        InstanceKind.fromLiteral(kind) != null && (recoveryFp == TrustGrammar.NONE || TrustGrammar.isHex64(recoveryFp))
}

/**
 * The kept setup offers, one per origin, in device state. A record that does not decode is read as none.
 *
 * A record is read only under the origin it names. That protects card 0: its [KeptSetup] values (instance id, name,
 * kind, recovery key) were minted for the offer of one address, and card 0 is signed for the address the session talks
 * to, so a record found under another origin's key never becomes another server's card 0. It is deliberately NOT
 * carried across a followed move: a move needs a pinned card chain, and a kept offer is needed only while no card 0 is
 * pinned (it is removed once card 0 is), so one carried by a move is stale by definition and reads as none.
 */
internal class SetupOffers(private val state: DeviceState) {
    private fun key(origin: String) = "ovh.setup|$origin"

    fun get(origin: String): KeptSetup? {
        val text = state.get(key(origin)) ?: return null
        val k = runCatching { WireJson.strict.decodeFromString(KeptSetup.serializer(), text) }.getOrNull() ?: return null
        return k.takeIf { it.origin == origin && it.valid() }
    }

    fun put(setup: KeptSetup) {
        if (setup.valid()) state.set(key(setup.origin), WireJson.json.encodeToString(KeptSetup.serializer(), setup))
    }

    fun remove(origin: String) = state.set(key(origin), null)
}
