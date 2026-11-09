package io.silencelen.andvari.core.client.session

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Spot checks that the shared rules behave the same on every platform. Android's unit tests pin them in depth. */
class SessionRulesTest {
    private val exempt = setOf("127.0.0.1")
    private val day = 24L * 60 * 60 * 1000
    private val stamp = 100 * day

    private fun inputs(now: Long, elapsedNow: Long, bootNow: String?, bootThen: String?, floor: Long = 0L) = QuickUnlockRules.FreshnessInputs(
        nowMs = now, elapsedNowMs = elapsedNow, stampWallMs = stamp, stampElapsedMs = day, stampBootRefMs = stamp - day,
        highWaterWallMs = now, serverFloorMs = floor, bootIdNow = bootNow, stampBootId = bootThen,
    )

    @Test fun trustGateShowsTheRealHost() {
        val plain = trustGateRender("https://vault.example:8443", exempt)
        assertEquals("https://vault.example:8443", plain.displayOrigin)
        assertFalse(plain.punycodeCaution)
        assertFalse(plain.httpCaution)
        assertTrue(trustGateRender("https://xn--bcher-kva.example", exempt).punycodeCaution)
        val idn = trustGateRender("https://bücher.example", exempt)
        assertEquals("https://xn--bcher-kva.example", idn.displayOrigin)
        assertTrue(idn.punycodeCaution)
        assertEquals("https://[::1]:8443", trustGateRender("https://[::1]:8443", exempt).displayOrigin)
    }

    @Test fun cleartextIsJudgedOnTheResolvedHost() {
        assertFalse(trustGateRender("http://127.0.0.1:8080", exempt).cleartextBlocked)
        assertTrue(trustGateRender("http://192.168.1.9:8080", exempt).cleartextBlocked)
        assertTrue(trustGateRender("http://127.0.0.1@evil.example", exempt).cleartextBlocked)
    }

    @Test fun aServerCannotDisableAutoLock() {
        assertEquals(clampAutoLockSeconds(Int.MAX_VALUE), clampAutoLockSeconds(0))
        assertEquals(clampAutoLockSeconds(Int.MAX_VALUE), clampAutoLockSeconds(-1))
        assertEquals(60, clampAutoLockSeconds(60))
    }

    @Test fun aRealSwitchInheritsNoTokens() {
        assertTrue(switchDropsSession("https://a.example", "https://b.example"))
        assertFalse(switchDropsSession("https://A.example/", "https://a.example:443"))
        assertNull(inheritedTokensAcrossSwitch("https://a.example", "https://b.example", io.silencelen.andvari.core.client.Tokens("a", "r")))
    }

    @Test fun anInviteFieldThatIsNotALinkIsAToken() {
        assertIs<InviteFieldParse.Token>(parseInviteField(" abc123 ", "https://a.example"))
    }

    @Test fun onlyATransportFailureMeansUnreachable() {
        assertFalse(switchProbeReachable(kotlinx.io.IOException("timed out")))
        assertTrue(switchProbeReachable(IllegalStateException("answered oddly")))
        assertTrue(switchProbeReachable(null))
    }

    @Test fun freshnessSameBootUsesTheMonotonicClock() {
        assertTrue(QuickUnlockRules.isFreshPure(inputs(stamp + day, 2 * day, "b1", "b1")))
        assertFalse(QuickUnlockRules.isFreshPure(inputs(stamp + day, 40 * day, "b1", "b1")), "a monotonic delta past the window is stale")
    }

    @Test fun freshnessAcrossABootNeedsAServerAnchor() {
        assertFalse(QuickUnlockRules.isFreshPure(inputs(stamp + day, 2 * day, "b2", "b1")))
        assertTrue(QuickUnlockRules.isFreshPure(inputs(stamp + day, 2 * day, "b2", "b1", floor = stamp + 1000)))
        assertFalse(QuickUnlockRules.isFreshPure(inputs(stamp + 31 * day, 2 * day, "b2", "b1", floor = stamp + 1000)), "the window still applies")
    }

    @Test fun aClockBeforeTheStampFailsClosed() {
        assertFalse(QuickUnlockRules.isFreshPure(inputs(stamp - 1, 2 * day, "b1", "b1")))
    }
}
