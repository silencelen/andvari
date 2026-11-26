package io.silencelen.andvari.cli

import io.silencelen.andvari.core.crypto.CryptoProvider
import java.util.Collections

/**
 * A run's crypto provider seen by a test: every password derivation (Argon2id) the tool asks for is recorded with its cost
 * (passes, memory in bytes), in order, and then made by the real provider. Nothing else is changed.
 */
class CountingCrypto {
    val derivations: MutableList<Pair<Long, Long>> = Collections.synchronizedList(ArrayList())

    fun over(inner: CryptoProvider): CryptoProvider = object : CryptoProvider by inner {
        override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray {
            derivations += opsLimit to memLimitBytes
            return inner.argon2id(password, salt, outLen, opsLimit, memLimitBytes)
        }
    }
}
