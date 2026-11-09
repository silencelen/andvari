@file:OptIn(ExperimentalForeignApi::class)

package io.silencelen.andvari.core.crypto

import io.silencelen.andvari.core.crypto.sodium.sodium_init
import kotlinx.cinterop.ExperimentalForeignApi

/**
 * The one process-wide provider. libsodium is linked statically, so the only way to fail here is
 * sodium_init itself. Memoized either way and re-thrown as [CryptoUnavailableException], the same
 * seam the JVM and Android actuals provide.
 */
private val loaded: Result<CryptoProvider> by lazy {
    if (sodium_init() < 0) Result.failure(IllegalStateException("sodium_init failed")) else Result.success(SodiumCryptoProvider())
}

actual fun createCryptoProvider(): CryptoProvider = loaded.getOrElse { throw CryptoUnavailableException(it) }
