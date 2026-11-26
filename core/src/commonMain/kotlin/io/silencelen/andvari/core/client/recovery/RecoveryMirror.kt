package io.silencelen.andvari.core.client.recovery

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.state.RecoveryRecord
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.Serializable

/**
 * This device's own mirror of the account's `recovery` record (design §4.5, T2-R-e): what this device itself
 * recorded or confirmed, so that an account-state record written by any other holder of the UVK cannot alone
 * make this device seal an escrow ([EscrowRules]). Written only by this device's own consent steps
 * (registration, a posture change, the "Keep that?" answer).
 */
class RecoveryMirror(private val state: DeviceState) {
    @Serializable
    private data class Stored(val posture: String, val fp: String, val at: Long)

    private fun key(userId: String) = "ovh.rmirror|$userId"

    fun get(userId: String): RecoveryRecord? {
        val text = state.get(key(userId)) ?: return null
        val s = runCatching { WireJson.strict.decodeFromString(Stored.serializer(), text) }.getOrNull() ?: return null
        if (s.posture != "private" && s.posture != "operator") return null
        return RecoveryRecord(s.posture, s.fp, s.at)
    }

    fun put(userId: String, record: RecoveryRecord) =
        state.set(key(userId), WireJson.json.encodeToString(Stored.serializer(), Stored(record.posture, record.fp, record.at)))

    fun forget(userId: String) = state.set(key(userId), null)
}

/**
 * The fingerprint the account's escrow is sealed to, as THIS device last sealed or re-sealed it (design §4.5): the
 * `escrowFp` of [EscrowRules]. Null when this device sealed none (or the posture was turned private here); a device
 * that does not know asks rather than re-sealing silently.
 */
class EscrowSeen(private val state: DeviceState) {
    private fun key(userId: String) = "ovh.escrowfp|$userId"

    fun get(userId: String): String? = state.get(key(userId))?.takeIf { io.silencelen.andvari.core.trust.TrustGrammar.isHex64(it) }

    fun put(userId: String, fp: String?) = state.set(key(userId), fp)
}
