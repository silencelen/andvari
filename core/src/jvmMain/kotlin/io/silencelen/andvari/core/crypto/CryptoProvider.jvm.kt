package io.silencelen.andvari.core.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava

/**
 * A host (the desktop app) may pre-extract the bundled libsodium and hand core its ABSOLUTE
 * path via this system property, to sidestep lazysodium's resource-loader: on a jpackage
 * runtime whose install path contains a space (Windows "Program Files") that loader mis-detects
 * the app jar and calls Paths.get on an unopened jar filesystem — FileSystemNotFoundException at
 * the first crypto call, before login, which read as a generic "Sign-in failed" (0.26.3).
 * `SodiumJava(path)` instead does a plain JNA load-by-path and never touches that code.
 *
 * Honoured wherever this jvm target runs — the server and the CLI tools included — because the
 * property is read by core, not by the desktop. That is deliberate (one loader, one seam) and
 * harmless: nothing but the desktop launcher sets it, and an operator who sets it by hand gets
 * exactly the desktop's behaviour, fallback included.
 */
const val NATIVE_SODIUM_PATH_PROPERTY = "andvari.native.sodium.path"

/**
 * Why the property-path load FALLS BACK to the bundled loader (audit H89): the desktop's
 * `NativeSodium.prepare()` sets the property BEFORE any load is attempted — its "best-effort,
 * falls back on any failure" contract covered only the extraction (resource lookup, temp file,
 * copy). A path that was written but does not LOAD (a `noexec` or AV-quarantined temp dir, a
 * runtime missing VCRUNTIME/UCRT, a hand-set property pointing nowhere) used to throw an
 * `UnsatisfiedLinkError` out of the lazy initializer on every crypto call, with no second
 * attempt — the exact symptom 0.26.3 fixed, one layer down. Now the failed path is recorded
 * ([nativeSodiumFallbackCause]) and lazysodium's own loader gets its turn, so the property can
 * only ever ADD a way to load, never remove one.
 *
 * [onFallback] receives the load failure when — and only when — a non-null [path] failed and
 * the bundled loader is about to run; the test pins that a bogus path reaches it and a good
 * one does not. A failure of the bundled loader itself propagates: there is nothing left to
 * try, and [createCryptoProvider] turns it into a [CryptoUnavailableException].
 */
internal fun loadSodium(path: String?, onFallback: (Throwable) -> Unit = {}): SodiumJava {
    if (path == null) return SodiumJava()
    return try {
        SodiumJava(path)
    } catch (t: Throwable) {
        // A VM-level failure (OOM, stack overflow) is not a loader verdict — never swallow it.
        if (t is VirtualMachineError) throw t
        onFallback(t)
        SodiumJava()
    }
}

@Volatile
private var fallbackCause: Throwable? = null

/**
 * The failure that made [loadSodium] abandon the property path and fall back to the bundled
 * loader — null when the property was unset or loaded fine. Read by the desktop's startup
 * self-check so `diagnostic.log` records WHICH loader actually served the process (the
 * property being set is no longer proof that its path was used).
 */
fun nativeSodiumFallbackCause(): Throwable? = fallbackCause

/**
 * The one process-wide provider. The load result — success OR failure — is memoized: a native
 * library that did not load is a permanent, local condition for the life of the process, and
 * re-running the loader on every crypto touch would only make the failing path slow. Every
 * later [createCryptoProvider] call re-throws the SAME [CryptoUnavailableException], which the
 * household canon ([io.silencelen.andvari.core.client.HouseholdCopy.CRYPTO_UNAVAILABLE]) renders
 * as the honest "not a password problem" sentence instead of "Sign-in failed. Please try again."
 * (audit H15).
 */
private val loaded: Result<CryptoProvider> by lazy {
    try {
        val path = System.getProperty(NATIVE_SODIUM_PATH_PROPERTY)?.takeIf { it.isNotBlank() }
        val sodium = loadSodium(path) { t ->
            fallbackCause = t
            // stderr, not a logger: core owns no sink (CoreLog is per-component and this runs
            // before any component exists). The desktop mirrors its diagnostics to stderr too.
            System.err.println(
                "[andvari-core] $NATIVE_SODIUM_PATH_PROPERTY=$path did not load " +
                    "(${t::class.qualifiedName}: ${t.message}); falling back to the bundled loader",
            )
        }
        Result.success(LazySodiumCryptoProvider(LazySodiumJava(sodium)))
    } catch (t: Throwable) {
        // A VM-level failure is not a loader verdict: let it out of the initializer un-memoized
        // (the lazy stays uninitialized and the next touch tries again). Everything else — the
        // LinkageErrors a loader throws — is the permanent condition the KDoc describes.
        if (t is VirtualMachineError) throw t
        Result.failure(t)
    }
}

actual fun createCryptoProvider(): CryptoProvider =
    loaded.getOrElse { throw CryptoUnavailableException(it) }
