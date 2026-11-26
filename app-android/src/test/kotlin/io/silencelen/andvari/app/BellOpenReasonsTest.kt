package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.net.BellMessageTooLarge
import io.silencelen.andvari.core.client.net.BellOpenFailed
import io.silencelen.andvari.core.client.net.BellOpenFailed.Reason
import java.io.EOFException
import java.io.File
import java.net.ConnectException
import java.net.SocketException
import java.net.SocketTimeoutException
import javax.net.ssl.SSLHandshakeException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Why a live-update socket failed, as the shared code's closed reasons: every throw site of the Android socket names
 * one, and the platform's own failures are turned into one with a fixed message and no cause, so the library's text
 * (which can quote the address, and the ticket is in it) never travels up.
 */
class BellOpenReasonsTest {
    private val src = File("src/main/kotlin/io/silencelen/andvari/app/AndroidBellSocket.kt").readText()

    @Test
    fun everyThrowSiteNamesItsReason() {
        assertFalse(Regex("""BellOpenFailed\("""").containsMatchIn(src), "no failure with a message only (reason OTHER) is left")
        assertFalse(src.contains("internal class BellOpenFailed"), "the shared code's class, not the app's own")
        assertTrue(src.contains("BellOpenFailed(Reason.PROXY_FAILED, \"the proxy asks for a sign-in, which this socket does not give\", status = 407)"))
        assertTrue(src.contains("BellOpenFailed(Reason.UPGRADE_REFUSED, \"the server answered \$status, not 101: no socket (no redirect is followed)\", status = status.toIntOrNull())"))
        assertTrue(src.contains("throw openFailure(e)"))
        assertTrue(src.contains("private fun failure(e: Throwable): Throwable = openLinkFailure(e)"))
    }

    @Test
    fun thePlatformsOwnFailuresWhileOpeningAreReasonsWithoutTheirMessage() {
        val secret = "wss://host/x?ticket=SECRET"
        val cases = listOf(
            SSLHandshakeException(secret) to Reason.TLS_FAILED,
            SocketTimeoutException(secret) to Reason.TIMED_OUT_OPENING,
            ConnectException(secret) to Reason.UNREACHABLE,
            EOFException(secret) to Reason.CONNECTION_LOST,
            SocketException(secret) to Reason.CONNECTION_LOST,
            IllegalStateException(secret) to Reason.OTHER,
        )
        for ((e, reason) in cases) {
            val f = assertIs<BellOpenFailed>(openFailure(e), e.javaClass.simpleName)
            assertEquals(reason, f.reason, e.javaClass.simpleName)
            assertFalse(f.message.orEmpty().contains("SECRET"))
            assertNull(f.cause)
        }
        val own = BellOpenFailed(Reason.NAME_LOOKUP_FAILED, "the server's name could not be found")
        assertSame(own, openFailure(own))
    }

    @Test
    fun thePlatformsOwnFailuresWhileOpenAreReasonsAndATooLargeMessageStaysItself() {
        val secret = "ticket=SECRET"
        assertEquals(Reason.PROTOCOL_ERROR, assertIs<BellOpenFailed>(openLinkFailure(BellProtocolError("a masked frame from the server"))).reason)
        assertEquals(Reason.PAST_DEADLINE, assertIs<BellOpenFailed>(openLinkFailure(BellMessageTimedOut())).reason)
        assertEquals(Reason.PAST_DEADLINE, assertIs<BellOpenFailed>(openLinkFailure(SocketTimeoutException(secret))).reason)
        assertEquals(Reason.CONNECTION_LOST, assertIs<BellOpenFailed>(openLinkFailure(EOFException(secret))).reason)
        assertEquals(Reason.CONNECTION_LOST, assertIs<BellOpenFailed>(openLinkFailure(SocketException(secret))).reason)
        assertFalse(openLinkFailure(SocketException(secret)).message.orEmpty().contains("SECRET"))
        val big = BellMessageTooLarge()
        assertSame(big, openLinkFailure(big))
    }
}
