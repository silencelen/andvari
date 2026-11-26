package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.SignupStart
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.answer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * **A** lies on sign-up that need a second instance ([World.another]): another public instance's real answer to its own
 * sign-up, served for this instance's. The verify step's answer is a registration ticket, an opaque value that names
 * neither the instance nor the address, so a device cannot tell it from this server's own (the stated limit); the device
 * holds it only for the address and the server the person typed. What matters is what follows: the registration with it
 * is refused by this server, no account is made here or there, the password's proof went to this server alone, and
 * nothing reached the other instance. The honest code still signs the person up afterwards.
 */
class OtherInstanceSignupLiesTest {
    private val open = mapOf("ANDVARI_SIGNUP_POW_BITS" to "10")

    private suspend fun World.emails(op: io.silencelen.andvari.cli.Host): List<String> =
        assertIs<Fetched.Ok<List<AccountSummary>>>(op.operator(op.session(origin)!!).accounts()).value.map { it.email }

    @Test fun anotherInstancesSignupTicketIsTakenAsServedAndMakesNoAccountAnywhere() = world("public", "open", extraEnv = open) {
        val op = operator()
        val d = pinnedDevice("carol")
        val o = d.onboarding(origin)

        // The other instance signs bob up as far as its ticket, which the server here then serves as its own.
        val other = another("public", mode = "open", extraEnv = open)
        val otherOp = other.operator()
        val bd = other.pinnedDevice("bob")
        val bo = bd.onboarding(other.origin)
        assertEquals(SignupStart.Sent, bo.signupStart("bob@example.org", ageConfirmed = true))
        val bobTicket = assertIs<SignupVerify.Ticket>(bo.signupVerify("bob@example.org", Steps.awaitCode(other.server, "bob@example.org")))
        val theirs = other.realAnswer(WireRoute.SIGNUP_VERIFY, "bob")
        assertTrue(theirs.ok, "the other instance verified its own sign-up: $theirs")
        val otherMark = other.proxy.mark()

        assertEquals(SignupStart.Sent, o.signupStart("carol@example.org", ageConfirmed = true))
        val code = Steps.awaitCode(server, "carol@example.org")
        val mark = proxy.mark()
        val lie = proxy.on(WireRoute.SIGNUP_VERIFY, "carol", handler = answer { theirs })
        val served = assertIs<SignupVerify.Ticket>(o.signupVerify("carol@example.org", code), "taken as served: the ticket names nothing")
        lie.remove()
        val refused = o.register(RegistrationAuth.Ticket(served), Steps.form("carol@example.org"))
        assertIs<Registration.Refused>(refused, "this server knows no such ticket: $refused")
        assertEquals(1, sent(d, WireRoute.REGISTER, mark).size, "one registration, sent here")
        assertTrue(secretSends("carol", mark).all { it.route == WireRoute.REGISTER }, "the proof went with the registration, to this server: ${secretSends("carol", mark).map { it.route }}")
        assertFalse("carol@example.org" in emails(op), "no account was made here")
        nothingReached(other, otherMark)
        // Asked by the other instance's own operator, after the check above.
        assertFalse("carol@example.org" in other.emails(otherOp), "nor at the other instance")

        // The honest answer: the same code is still unused here, and it signs carol up.
        val ticket = assertIs<SignupVerify.Ticket>(o.signupVerify("carol@example.org", code))
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(ticket), Steps.form("carol@example.org")))
        assertTrue("carol@example.org" in emails(op))
        // bob's own ticket still signs him up at his own instance.
        assertIs<Registration.Registered>(bo.register(RegistrationAuth.Ticket(bobTicket), Steps.form("bob@example.org")))
    }

    private fun nothingReached(other: World, mark: Int) {
        assertEquals(emptyList(), other.proxy.requests(since = mark).map { "${it.tag} ${it.route}" }, "nothing reached the other instance")
    }
}
