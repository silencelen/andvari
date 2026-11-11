package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.OriginCanon

/**
 * The quick-unlock gates (spec 01 §8.1), in one place for every process that unwraps the UVK: the app's unlock
 * ladder, and on iOS the AutoFill extension, which reads the same shared state. The policy permits a durable unlock
 * secret and was seen within 7 days (A4), a strong biometric is usable, a key is wrapped, and the last full-password
 * unlock is recent enough (A1/A2). Reading it advances the high-water clock, as every freshness check does.
 */
class QuickGates(
    private val store: SessionPersistence,
    private val quickKeys: QuickUnlockKeys,
    private val clocks: Clocks,
) {
    /** The gates for [userId] at the origin the client dials. */
    fun status(userId: String?): QuickStatus {
        val originKey = store.baseUrl?.let(OriginCanon::originKey)
        val origin = originKey?.let(store::origin)
        val permits = origin != null && QuickUnlockRules.policyPermits(origin.cacheAllowed, origin.policyFetchedAt, clocks.wallMs())
        val eligible = permits && quickKeys.hasStrongBiometric()
        val enrolled = originKey != null && userId != null && quickKeys.isEnrolled(originKey, userId)
        val fresh = enrolled && isFresh(originKey, userId)
        val refusal = when {
            !permits -> QuickGate.POLICY
            !eligible -> QuickGate.NO_BIOMETRIC
            !enrolled -> QuickGate.NOT_ENROLLED
            !fresh -> QuickGate.EXPIRED
            else -> null
        }
        return QuickStatus(eligible, enrolled, fresh, refusal)
    }

    /** A1/A2 freshness of [userId]'s last full-password unlock at [originKey], against the monotonic high-water clock. */
    private fun isFresh(originKey: String, userId: String): Boolean {
        val now = clocks.wallMs()
        val elapsedNow = clocks.monotonicMs()
        val highWater = store.bumpHighWater(now) // monotonically non-decreasing
        val origin = store.origin(originKey)
        val stamp = origin.passwordStamp(userId)
        return QuickUnlockRules.isFreshPure(
            QuickUnlockRules.FreshnessInputs(
                nowMs = now,
                elapsedNowMs = elapsedNow,
                stampWallMs = stamp?.wallMs ?: 0L,
                stampElapsedMs = stamp?.monotonicMs ?: 0L,
                stampBootRefMs = stamp?.bootRefMs ?: 0L,
                highWaterWallMs = highWater,
                serverFloorMs = origin.serverTimeFloorMs,
                bootIdNow = clocks.bootId(),
                stampBootId = stamp?.bootId,
            ),
        )
    }
}
