package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupStart
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.TrustGateWording
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Journey 3: public sign-up: the emailed code from the mail sink, proof of work, ticket, register, kit reveal and confirmation. */
class J3PublicSignupTest {
    @Test fun aPublicInstanceSignsUpThroughTheEmailedCodeWithProofOfWork() {
        TestServer(kind = "public", mode = "open", extraEnv = mapOf("ANDVARI_SIGNUP_POW_BITS" to "10")).use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val d = s.device("new person")
            // A device with no pin types the address and passes the Trust Gate (design §4.4).
            val gate = assertIs<FirstPin.NeedsTrustGate>(d.trust.beginTrustGate(s.origin, TrustGateWording.TYPED_ADDRESS))
            assertIs<FirstPin.Pinned>(d.trust.confirmTrustGate(gate.confirm))
            val o = d.onboarding(s.origin)
            val offer = assertIs<Fetched.Ok<io.silencelen.andvari.core.client.onboard.SignupOffer>>(o.signupOffer()).value
            assertEquals("open", offer.mode)
            assertEquals(10, offer.powBits)
            assertTrue(offer.ageConfirmRequired, "a public instance asks for the age confirmation")

            assertEquals(SignupStart.Sent, o.signupStart("carol@example.org", ageConfirmed = true))
            val code = Steps.awaitCode(s, "carol@example.org")
            assertEquals(SignupVerify.BadCode, o.signupVerify("carol@example.org", if (code == "000000") "111111" else "000000"))
            val ticket = assertIs<SignupVerify.Ticket>(o.signupVerify("carol@example.org", code))
            val reg = assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(ticket), Steps.form("carol@example.org")))
            assertEquals(11, reg.kit.groups.size)
            assertTrue(reg.kit.qr.startsWith("andvari-kit:2:"), reg.kit.qr)
            Steps.confirmKit(o, reg.kit)
            val keys = d.client(s.origin).call(io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_KEYS,
                decode = { io.silencelen.andvari.core.model.wire.WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.AccountKeys.serializer(), it) })
            assertTrue(assertIs<io.silencelen.andvari.core.client.net.WireResult.Ok<io.silencelen.andvari.core.model.wire.AccountKeys>>(keys).value.recoveryConfirmed)
            assertIs<SignIn.SignedIn>(o.signIn("carol@example.org", Steps.PASSWORD.toCharArray()))
            // The same address again is the uniform answer, and the mail says an account exists.
            assertEquals(SignupStart.Sent, o.signupStart("carol@example.org", ageConfirmed = true))
            Steps.awaitMail(s, "carol@example.org", "signup_existing")
            // Every mail sent so far, none still on its way: none carries the password.
            assertTrue(s.settledMail().none { it["text"]!!.jsonPrimitive.content.contains(Steps.PASSWORD) })
        } }
    }
}
