package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.model.wire.LoginDevice
import io.silencelen.andvari.core.model.wire.NewDevice
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.serialization.Serializable

/**
 * This device's `deviceSecret` and `deviceId` per (origin, account) (design §8.7, FI-R10; spec 03 §0.3).
 *
 * The secret is 32 CSPRNG bytes made the first time this device creates a device row for the account
 * (registration, password sign-in, device-link pickup, a recovery commit), written to device state BEFORE it
 * is sent, and kept for good: only a revoke on the server forgets it there. It never leaves the core except
 * inside the device object of those four requests. The `deviceId` is stored when the server answers with a
 * session; a login sends it with the secret, which is what makes this a known device.
 *
 * One secret per account and origin, so two accounts or two servers cannot correlate this device by it.
 */
class KnownDevices(private val state: DeviceState, private val crypto: CryptoProvider) {
    @Serializable
    private data class Stored(val deviceSecret: String, val deviceId: String? = null)

    private fun key(origin: String, emailNorm: String) = "ovh.dev|$origin|$emailNorm"

    private fun read(origin: String, emailNorm: String): Stored? {
        val text = state.get(key(origin, emailNorm)) ?: return null
        val s = runCatching { WireJson.strict.decodeFromString(Stored.serializer(), text) }.getOrNull() ?: return null
        if (!TrustGrammar.isB64_32(s.deviceSecret)) return null
        if (s.deviceId != null && !TrustGrammar.isUuid(s.deviceId)) return s.copy(deviceId = null)
        return s
    }

    /** The account's secret, made and stored durably now when there is none (a damaged record is replaced). */
    internal fun secret(origin: String, emailNorm: String): String {
        read(origin, emailNorm)?.let { return it.deviceSecret }
        val made = Bytes.toB64(crypto.randomBytes(32))
        state.set(key(origin, emailNorm), WireJson.json.encodeToString(Stored.serializer(), Stored(made)))
        return made
    }

    /** The device row the server gave this device for the account, if any. */
    fun deviceId(origin: String, emailNorm: String): String? = read(origin, emailNorm)?.deviceId

    /** Record the device row of a session the server opened with [deviceSecret]; a secret that changed meanwhile is left alone. */
    internal fun remember(origin: String, emailNorm: String, deviceSecret: String, deviceId: String) {
        val s = read(origin, emailNorm) ?: return
        if (s.deviceSecret != deviceSecret || !TrustGrammar.isUuid(deviceId)) return
        state.set(key(origin, emailNorm), WireJson.json.encodeToString(Stored.serializer(), s.copy(deviceId = deviceId)))
    }

    /** The login device object (spec 03 §2): always the secret, and the device id once known. */
    internal fun loginDevice(origin: String, emailNorm: String, platform: String, name: String): LoginDevice {
        val secret = secret(origin, emailNorm)
        return LoginDevice(platform, name, secret, deviceId(origin, emailNorm))
    }

    /** The device object of a request that creates a device row (register, pickup, recovery commits). */
    internal fun newDevice(origin: String, emailNorm: String, platform: String, name: String): NewDevice =
        NewDevice(platform, name, secret(origin, emailNorm))

    /** Forget the account on this device (account deleted): the next device row starts from a new secret. */
    fun forget(origin: String, emailNorm: String) = state.set(key(origin, emailNorm), null)

    internal companion object {
        /** The key prefix of a device's record (`ovh.dev|<origin>|<emailNorm>`). */
        const val PREFIX = "ovh.dev|"

        /**
         * Whether a device's record ([text], as stored) holds a device id, which it does only once a server opened a session
         * for it: true; false for a record that holds a secret and no device id (only an attempt was made); null for text
         * that cannot be read as a device's record (not one, a secret that is not one, or a device id that is not an id).
         */
        fun holdsDeviceId(text: String): Boolean? {
            val s = runCatching { WireJson.strict.decodeFromString(Stored.serializer(), text) }.getOrNull() ?: return null
            if (!TrustGrammar.isB64_32(s.deviceSecret)) return null
            return when {
                s.deviceId == null -> false
                TrustGrammar.isUuid(s.deviceId) -> true
                else -> null
            }
        }
    }
}
