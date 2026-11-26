package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Journey 2: a member registers through an enrol link, signs out, signs in again on the same device; a second account registers. */
class J2MembersTest {
    @Test fun membersEnrolSignOutAndSignInAgainFromAKnownDevice() {
        TestServer().use { it.journey { val s = this
            val op = s.device("operator")
            Steps.registerThrough(op, s.origin, s.setupLink, "op@example.org")
            val card0 = op.trust.pinFor(s.origin)!!.card0Hash

            val alice = s.device("alice laptop")
            val a = Steps.registerThrough(alice, s.origin, Steps.enrolLink(s, "alice@example.org"), "alice@example.org", trustGate = true)
            val pin = assertNotNull(alice.trust.pinFor(s.origin))
            assertEquals(PinRoot.ENROL, pin.root)
            assertEquals(card0, pin.card0Hash, "the enrol pin is the operator's card 0")
            val deviceId = assertNotNull(alice.devices.deviceId(s.origin, "alice@example.org"))
            assertEquals(deviceId, alice.session(s.origin)!!.session.deviceId)

            // Sign out: the server ends the session, the device keeps its pin and its known-device record.
            val out = alice.client(s.origin).call(WireRoute.LOGOUT, decode = { })
            assertIs<WireResult.Ok<Unit>>(out, "logout: $out")
            alice.dropSession(s.origin)
            val after = alice.client(s.origin).call(WireRoute.ACCOUNT_KEYS, decode = { it })
            assertIs<WireResult.Refused>(after, "no session after logout: $after")

            // An enrol pin is not a password pin (design §4.4, FI-B8): signing in shows the Trust Gate first, and then
            // the pin is one.
            assertEquals(SignIn.TrustGateFirst, alice.onboarding(s.origin).signIn("alice@example.org", Steps.PASSWORD.toCharArray()))
            val gate = assertIs<FirstPin.NeedsTrustGate>(alice.trust.beginTrustGate(s.origin, TrustGateWording.TYPED_ADDRESS))
            assertEquals(pin.hash, assertIs<FirstPin.Pinned>(alice.trust.confirmTrustGate(gate.confirm)).pin.hash)
            assertEquals(PinRoot.TRUST_GATE, alice.trust.pinFor(s.origin)!!.root)
            // Sign in again from the same device: the device id is sent and reused (design §8.7).
            val signed = alice.onboarding(s.origin).signIn("alice@example.org", Steps.PASSWORD.toCharArray())
            assertIs<SignIn.SignedIn>(signed, "sign-in from the known device: $signed")
            assertEquals(a.userId, signed.userId)
            assertEquals(deviceId, alice.session(s.origin)!!.session.deviceId, "the known device is the same device row")
            assertEquals(SignIn.InvalidCredentials, alice.onboarding(s.origin).signIn("alice@example.org", "wrong password entirely 7".toCharArray()))

            // A second account, through an unbound enrol link.
            val bob = s.device("bob phone")
            val b = Steps.registerThrough(bob, s.origin, Steps.enrolLink(s), "bob@example.org", trustGate = true)
            assertNotEquals(a.userId, b.userId)
            assertTrue(s.admin("accounts").contains("bob@example.org"))
            // A device with no pin is sent to the Trust Gate before any password-derived value (design §4.4).
            assertEquals(SignIn.TrustGateFirst, s.device("stranger").onboarding(s.origin).signIn("bob@example.org", Steps.PASSWORD.toCharArray()))
            assertNull(s.device("stranger").session(s.origin))
        } }
    }
}
