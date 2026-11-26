package io.silencelen.andvari.core.crypto

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid

/**
 * The one process-wide provider. `SodiumAndroid()` runs `System.loadLibrary("sodium")` against
 * the .aar-bundled natives; a load failure (an ABI the APK does not carry, a corrupt install) is
 * an `UnsatisfiedLinkError` — permanent for the life of the process. Memoized either way and
 * re-thrown as the ONE common [CryptoUnavailableException] so the household canon can say
 * "not a password problem" instead of "Sign-in failed. Please try again." (audit H15) — the
 * same seam the JVM actual (CryptoProvider.jvm.kt) provides, so both natives behave alike.
 */
private val loaded: Result<CryptoProvider> by lazy {
    try {
        // A test run's tripwire, when one is on the class path (the app's JVM unit tests), decorates it ([watched]).
        Result.success(watched(LazySodiumCryptoProvider(LazySodiumAndroid(SodiumAndroid()))))
    } catch (t: Throwable) {
        // A VM-level failure is not a loader verdict — let it out un-memoized (the lazy retries).
        if (t is VirtualMachineError) throw t
        Result.failure(t)
    }
}

actual fun createCryptoProvider(): CryptoProvider =
    loaded.getOrElse { throw CryptoUnavailableException(it) }
