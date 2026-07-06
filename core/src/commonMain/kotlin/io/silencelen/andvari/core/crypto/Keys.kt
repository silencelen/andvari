package io.silencelen.andvari.core.crypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** spec 01 §1 — per-user KDF parameters, server-stored and cached beside wrappedUvk. */
@Serializable
data class KdfParams(
    @SerialName("v") val v: Int = 1,
    @SerialName("alg") val alg: String = "argon2id13",
    @SerialName("ops") val ops: Long = 3,
    @SerialName("memBytes") val memBytes: Long = 67_108_864,
) {
    init {
        require(v == 1 && alg == "argon2id13") { "unsupported kdfParams" }
    }

    companion object {
        val DEFAULT = KdfParams()
        const val SALT_BYTES = 16
    }
}

/** spec 01 §§1–2: master key derivation and the auth/wrap purpose split. */
object Keys {
    const val KEY_BYTES = 32
    private val INFO_AUTH = "andvari/v1/auth".encodeToByteArray()
    private val INFO_WRAP = "andvari/v1/wrap".encodeToByteArray()

    fun masterKey(crypto: CryptoProvider, password: String, kdfSalt: ByteArray, params: KdfParams): ByteArray {
        require(kdfSalt.size == KdfParams.SALT_BYTES) { "kdfSalt must be ${KdfParams.SALT_BYTES} bytes" }
        return crypto.argon2id(password.encodeToByteArray(), kdfSalt, KEY_BYTES, params.ops, params.memBytes)
    }

    fun authKey(crypto: CryptoProvider, masterKey: ByteArray): ByteArray =
        Hkdf.sha256(crypto, masterKey, ByteArray(0), INFO_AUTH, KEY_BYTES)

    fun wrapKey(crypto: CryptoProvider, masterKey: ByteArray): ByteArray =
        Hkdf.sha256(crypto, masterKey, ByteArray(0), INFO_WRAP, KEY_BYTES)
}
