package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.core.client.pin.PinRoot
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Journey 1: `andvari setup --test`, the setup link, the operator's registration, card 0, an everyday enrol link. */
class J1SetupTest {
    @Test fun setupLinkEnrolsTheOperatorSignsAndPinsCardZeroAndThenEnrolLinksExist() {
        TestServer().use { it.journey { val s = this
            assertTrue(s.admin("status").contains("none (setup not finished)"))
            val op = s.device("operator")
            val reg = Steps.registerThrough(op, s.origin, s.setupLink, "op@example.org")
            assertFalse(reg.cardPending, "card 0 was uploaded and pinned")
            val pin = assertNotNull(op.trust.pinFor(s.origin))
            assertEquals(PinRoot.SETUP, pin.root)
            assertEquals(0L, pin.seq)
            assertEquals(s.setup["instanceId"]!!.toString().trim('"'), pin.instanceId)
            val status = s.admin("status")
            assertTrue(status.contains("card: seq 0, ${pin.hash}"), status)
            assertTrue(s.admin("operator").contains("op@example.org"))
            // Only now may the host mint the everyday enrol link (FI-B9).
            val enrol = Steps.enrolLink(s, "me@example.org")
            assertTrue(enrol.contains("/l#v2."), enrol)
        } }
    }

    /**
     * The proxy seam: a device can send every request to another address than the origin (here the server's own listener,
     * behind the origin's relay) and still checks everything against the origin.
     */
    @Test fun theOriginAndTheAddressADeviceDialsAreSeparable() {
        TestServer().use { it.journey { val s = this
            assertTrue(s.serverAddress != s.origin)
            val op = s.device("operator", dial = s.serverAddress)
            val reg = Steps.registerThrough(op, s.origin, s.setupLink, "op@example.org")
            assertFalse(reg.cardPending)
            assertEquals(s.origin, op.trust.pinFor(s.origin)!!.origin, "card 0 names the origin, not the listening address")
        } }
    }
}
