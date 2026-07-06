package io.silencelen.andvari.server

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.goterl.lazysodium.interfaces.PwHash
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider

/**
 * Server-only crypto. The vault crypto is all client-side; the server just needs:
 *  - a slow hash over the received authKey (so a DB leak ≠ login replay, spec 01 §3)
 *  - opaque token generation + hashing
 *  - deterministic fake prelogin salts (anti-enumeration, spec 01 §3)
 */
object ServerCrypto {
    private val ls = LazySodiumJava(SodiumJava())
    private val crypto = createCryptoProvider()

    /** Store side of the login verifier: argon2id string over the (already KDF-derived) authKey. */
    fun hashVerifier(authKeyB64: String): String {
        val out = ls.cryptoPwHashStr(authKeyB64, PwHash.OPSLIMIT_INTERACTIVE, PwHash.MEMLIMIT_INTERACTIVE)
            ?: error("cryptoPwHashStr failed")
        return out
    }

    fun verify(storedVerifier: String, authKeyB64: String): Boolean =
        ls.cryptoPwHashStrVerify(storedVerifier, authKeyB64)

    fun newToken(): String = Bytes.toB64(crypto.randomBytes(32))

    fun hashToken(token: String): String = Bytes.toB64(crypto.sha256(token.encodeToByteArray()))

    /** Deterministic 16-byte fake salt for unknown emails (looks real, leaks nothing). */
    fun fakeSalt(enumSecret: ByteArray, email: String): ByteArray =
        crypto.hmacSha256(enumSecret, email.lowercase().encodeToByteArray()).copyOf(16)

    fun randomB64(n: Int): String = Bytes.toB64(crypto.randomBytes(n))
}
