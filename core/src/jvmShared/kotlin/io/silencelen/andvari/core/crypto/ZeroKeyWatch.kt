package io.silencelen.andvari.core.crypto

import java.util.ServiceLoader

/**
 * The seam for a test run's watch over zero-key work: the test suites'
 * tripwire (`core/src/jvmTripwire`, compiled into each watched module's TEST source set only) implements it and is
 * found through `META-INF/services`. Nothing that ships provides one, so in a release [watched] finds none and hands
 * out the provider unchanged; the tripwire itself is not in the release.
 */
interface ZeroKeyWatch {
    /** The provider to hand out in place of [provider]: the watch's recording decorator, or [provider] itself. */
    fun watch(provider: CryptoProvider): CryptoProvider

    /** The floor ([KeyFloor]) refused [what]; called before it throws, so a refusal a handler swallows still shows. */
    fun refused(what: String)

    /**
     * Whether a guarded lend's answer is inspected now (spec 01 §8 rule 1: a development check, never a rule of the
     * running product), asked at every lend. Only the test suites' tripwire implements this interface, so a shipped
     * build, which has none, never inspects one.
     */
    fun checksLends(): Boolean
}

/** The test seam's word on lend checks: the [ZeroKeyWatch] on the class path, or null (a shipped build: never checked). */
internal actual fun lendCheckSwitch(): (() -> Boolean)? =
    ServiceLoader.load(ZeroKeyWatch::class.java, ZeroKeyWatch::class.java.classLoader).firstOrNull()?.let { w -> { w.checksLends() } }

/** [provider], or the decorator of the one [ZeroKeyWatch] on the class path, which also hears every refusal of the floor. */
internal fun watched(provider: CryptoProvider): CryptoProvider {
    val watch = ServiceLoader.load(ZeroKeyWatch::class.java, ZeroKeyWatch::class.java.classLoader).firstOrNull() ?: return provider
    KeyFloor.onRefusal = watch::refused
    return watch.watch(provider)
}
