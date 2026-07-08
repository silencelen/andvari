package io.silencelen.andvari.core.crypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** spec 04 §3 — sealed escrow payload (canonical JSON: exact key order, no whitespace). */
@Serializable
data class EscrowPayload(
    @SerialName("v") val v: Int,
    @SerialName("userId") val userId: String,
    @SerialName("keyType") val keyType: String,
    @SerialName("key") val key: String,
    @SerialName("sha256") val sha256: String,
)

object Escrow {
    const val KEY_TYPE_UVK = "uvk"
    const val KEY_TYPE_CANARY = "canary"
    const val CANARY_USER_ID = "00000000-0000-0000-0000-000000000000"

    /** spec 04 §4 — the fixed canary key: 32 bytes of 0x5A. */
    val CANARY_KEY: ByteArray get() = ByteArray(32) { 0x5A }

    private val json = Json { ignoreUnknownKeys = true }

    /** Canonical bytes — built by string template to guarantee key order and no whitespace. */
    fun canonicalPayload(userId: String, keyType: String, keyBytes: ByteArray, crypto: CryptoProvider): ByteArray {
        val keyB64 = Bytes.toB64(keyBytes)
        val shaB64 = Bytes.toB64(crypto.sha256(keyBytes))
        return """{"v":1,"userId":"$userId","keyType":"$keyType","key":"$keyB64","sha256":"$shaB64"}"""
            .encodeToByteArray()
    }

    fun sealUvk(crypto: CryptoProvider, recoveryPub: ByteArray, userId: String, uvk: ByteArray): ByteArray =
        crypto.sealTo(recoveryPub, canonicalPayload(userId, KEY_TYPE_UVK, uvk, crypto))

    fun sealCanary(crypto: CryptoProvider, recoveryPub: ByteArray): ByteArray =
        crypto.sealTo(recoveryPub, canonicalPayload(CANARY_USER_ID, KEY_TYPE_CANARY, CANARY_KEY, crypto))

    /** Open + self-validate (sha256 of key must match; spec 04 §3). */
    fun open(crypto: CryptoProvider, recoveryPub: ByteArray, recoveryPriv: ByteArray, sealed: ByteArray): EscrowPayload {
        val payload = json.decodeFromString<EscrowPayload>(
            crypto.sealOpen(recoveryPub, recoveryPriv, sealed).decodeToString(),
        )
        if (payload.v != 1) throw CryptoException("unsupported escrow payload version ${payload.v}")
        val keyBytes = Bytes.fromB64(payload.key)
        val expected = Bytes.toB64(crypto.sha256(keyBytes))
        if (!Bytes.ctEquals(expected.encodeToByteArray(), payload.sha256.encodeToByteArray())) {
            throw CryptoException("escrow payload self-check failed (sha256 mismatch)")
        }
        return payload
    }

    /** spec 04 §1 — full fingerprint: lowercase hex SHA-256 of the 32-byte public key. */
    fun fingerprint(crypto: CryptoProvider, publicKey: ByteArray): String =
        Bytes.toHexLower(crypto.sha256(publicKey))

    fun shortFingerprint(crypto: CryptoProvider, publicKey: ByteArray): String =
        fingerprint(crypto, publicKey).take(16)

    /**
     * spec 04 §2(3): the user TYPES the first 16 hex chars of the org recovery fingerprint from
     * the PRINTED sheet (the UI must NOT display them first, so a compromised server can't get a
     * lazy eyeball-match). Separators / whitespace are tolerated; exactly 16 hex chars required.
     * Mirrors the web `shortFormMatches` for cross-client parity (enrollment + F57 re-seal).
     */
    fun shortFormMatches(entry: String, fullFingerprintHex: String): Boolean {
        val norm = entry.lowercase().filter { it in "0123456789abcdef" }
        return norm.length == 16 && fullFingerprintHex.lowercase().take(16) == norm
    }
}
