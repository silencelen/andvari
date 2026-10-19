package io.silencelen.andvari.core.client

import java.util.concurrent.atomic.AtomicLong

/**
 * Security review 2026-10, branch A12 (desktop row 80, and the same shape on Android): the fence
 * that keeps a policy reply from an ABANDONED origin out of the current origin's state.
 *
 * A policy probe is an unauthenticated GET that can take as long as its server likes. Pinning the
 * probed origin's KEY (§4.2) already kept a late verdict out of another origin's persisted
 * fallbacks, but the reply still landed in the client's single in-memory policy, which the next
 * bind reads. A hostile origin the user connected to and then cancelled could answer late with
 * `offlineCacheAllowed=false` and have the home origin's vault cache deleted on the next unlock.
 *
 * Every probe is tagged, when it STARTS, with the origin it dials and the current generation.
 * Every origin change ([advance]) bumps the generation. A reply applies only when [isCurrent]
 * says both still match, so a reply from an abandoned origin, or from an earlier visit to the
 * same origin, is dropped. Thread-safe: probes resume on IO threads.
 */
class OriginProbeFence {
    private val generation = AtomicLong(0)

    /** The origin and generation a probe was started for. */
    data class Tag(val originKey: String, val generation: Long)

    /** Tag a probe of [originKey] at the current generation. Call BEFORE any await. */
    fun tag(originKey: String): Tag = Tag(originKey, generation.get())

    /** The app moved (or abandoned) its origin: every outstanding tag goes stale. */
    fun advance(): Long = generation.incrementAndGet()

    /** True only for a reply from the origin the app dials now, started in this generation. */
    fun isCurrent(tag: Tag, currentOriginKey: String): Boolean =
        tag.generation == generation.get() && tag.originKey == currentOriginKey
}
