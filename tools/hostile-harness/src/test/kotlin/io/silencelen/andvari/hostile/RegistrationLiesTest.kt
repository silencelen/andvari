package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.set
import kotlinx.serialization.json.JsonObject
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `POST /auth/register` (index row 8) lied to after the server created the account: the answer of another account,
 * the right answer with one field taken from another account's, and answers the route never gives. The device that
 * registers derived the account's keys itself and knows what it sent; it never takes a session it did not make, keeps
 * nothing, and is never told "wrong password". The account the server did create then signs in with the password.
 */
class RegistrationLiesTest {
    @Test fun aRegisterAnswerOfAnotherAccountOrWithOneFieldSwappedOrNotARegisterAnswerIsNeverTaken() = world {
        operator()
        member("bob")
        val bobs = proxy.last(WireRoute.REGISTER, "bob")!!.upstream!!.json!!
        val bobKeys = bobs.obj("accountKeys")!!
        val lies: List<Pair<String, (Resp) -> Resp>> = listOf(
            "Bob's whole answer (A)" to { _ -> Resp.json(200, bobs) },
            "the right answer with Bob's user id (W)" to { r -> r.withJson { it.set("userId", bobs["userId"]!!) } },
            "the right answer with Bob's salt (W)" to { r -> r.withJson { it.set("accountKeys", it.obj("accountKeys")!!.set("kdfSalt", bobKeys["kdfSalt"]!!)) } },
            "the right answer with Bob's wrapped key (W)" to { r -> r.withJson { it.set("accountKeys", it.obj("accountKeys")!!.set("wrappedUvk", bobKeys["wrappedUvk"]!!)) } },
            "the right answer with Bob's identity key (W)" to { r -> r.withJson { it.set("accountKeys", it.obj("accountKeys")!!.set("identityPub", bobKeys["identityPub"]!!)) } },
            "a plain ok (X)" to { _ -> Resp.ok() },
            "an empty object (X)" to { _ -> Resp.json(200, JsonObject(emptyMap())) },
        )
        for ((i, lie) in lies.withIndex()) {
            val tag = "c$i"
            val email = "carol$i@example.org"
            val d = device(tag)
            val tg = assertIs<RecipientStep.TrustGate>(d.links.open(Steps.enrolLink(server), GateEntry.PASTE_INVITE))
            val confirm = assertIs<RecipientStep.Confirm>(d.links.proceed(tg))
            proxy.on(WireRoute.REGISTER, tag) { x -> lie.second(x.forward()) }
            val reg = d.onboarding(origin).register(RegistrationAuth.EnrolLink(confirm), Steps.form(email))
            assertTrue(reg !is Registration.Registered, "${lie.first}: never registered on this device: $reg")
            assertTrue(reg !is Registration.PasswordTooWeak, "${lie.first}: never a password verdict")
            assertNull(d.session(origin), "${lie.first}: no session is kept")
            assertTrue(proxy.last(WireRoute.REGISTER, tag)!!.upstream!!.ok, "${lie.first}: the server did create the account")
            // The link's pin went with the refused registration (the flow drops the pin it made). The account the server
            // created is the person's: the typed address, the Trust Gate and the password sign in (passwordDevice asserts it).
            proxy.honest()
            passwordDevice("s$i", email)
        }
    }
}
