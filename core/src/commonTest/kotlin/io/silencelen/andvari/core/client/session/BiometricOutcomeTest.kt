package io.silencelen.andvari.core.client.session

import kotlin.test.Test
import kotlin.test.assertEquals

/** The quick-unlock failure table (spec 01 §8.1), as iOS's LocalAuthentication codes map onto it. */
class BiometricOutcomeTest {
    private fun recover(code: Long) = QuickUnlockCopy.recoverFailure(LocalAuthenticationCodes.outcome(code))
    private fun enroll(code: Long) = QuickUnlockCopy.enrollFailure(LocalAuthenticationCodes.outcome(code))

    @Test
    fun aCancelOrTheFallbackButtonKeepsTheEnrollmentSilently() {
        for (code in listOf(-2L, -3L, -4L, -9L)) assertEquals(QuickRecover.Fallback(null), recover(code), "code $code")
    }

    @Test
    fun aLockoutKeepsTheEnrollmentAndSaysSo() {
        // A8: a lockout must never be a way to destroy a valid enrollment.
        assertEquals(QuickRecover.Fallback(QuickUnlockCopy.LOCKOUT_FALLBACK), recover(-8L))
    }

    @Test
    fun aKeyThatCanNeverWorkAgainIsWiped() {
        assertEquals(QuickRecover.Wiped(QuickUnlockCopy.BIOMETRICS_CHANGED), recover(-7L), "no biometric enrolled any more")
        assertEquals(QuickRecover.Wiped(QuickUnlockCopy.BIOMETRICS_CHANGED), recover(-5L), "the passcode was removed")
    }

    @Test
    fun anythingElsePointsAtThePassword() {
        for (code in listOf(-1L, -6L, -10L, -1004L, 42L)) assertEquals(QuickRecover.Fallback(QuickUnlockCopy.DEVICE_FALLBACK), recover(code), "code $code")
    }

    @Test
    fun anEnrollmentPromptThatDidNotConsentWrapsNothing() {
        assertEquals(QuickEnroll.Cancelled, enroll(-2L))
        assertEquals(QuickEnroll.Failed(QuickUnlockCopy.ENROLL_LOCKED_OUT), enroll(-8L))
        assertEquals(QuickEnroll.Failed(null), enroll(-1L))
    }
}
