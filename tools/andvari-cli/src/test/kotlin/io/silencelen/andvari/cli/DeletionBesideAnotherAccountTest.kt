package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The tool's own deletion of an account the server confirmed (decided on 2026-11-19): the server is forgotten with the
 * account only where the home keeps nothing of another account there; otherwise only the deleted account's records go,
 * the pin and the other account's records stay, and the tool says so. Over the real server.
 */
class DeletionBesideAnotherAccountTest {
    private fun records(home: File): Map<String, String?> {
        val h = CliHome(home)
        return listOf("state" to h.deviceState(), "secure" to h.secureState()).flatMap { (n, st) -> st.keys()!!.map { "$n:$it" to st.get(it) } }.toMap()
    }

    /** Nothing of another account is kept at the server: the account and the server go, pin and all. */
    @Test fun aDeletionWithNothingOfAnotherAccountKeptForgetsTheServerToo() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = "alone@example.org"
            val a = w.account(me)
            val done = w.run(a, "account", "delete", "--confirm-email", me)
            assertEquals(0, done.code, done.out + done.err)
            println("records after the deletion: ${records(a).keys}")
            assertTrue(records(a).keys.none { it.contains(s.origin) }, "nothing of the server is kept: ${records(a).keys}")
            assertTrue(w.run(a, "whoami").ok().contains("not pinned on this device"))
            assertTrue(done.out.contains(fill(DELETED_SERVER_FORGOTTEN, s.origin)), done.out)
        }
    }

    /**
     * The check's sequence: the earlier account U under an address is forgotten (its identity key stays on record), the
     * account V is then taken on this home, and V is deleted with the tool's own command. U's key record is something of
     * another account kept at the server: the pin and that record stay, and the tool says the server was kept. U served
     * afterwards under another key (here: the home's record of U's key is another key than the server gives) is refused
     * at the sign-in with the key's sentence and no offer. V is another address here: the real server cannot serve U
     * again under V's address once V holds it.
     */
    @Test fun aDeletionBesideAForgottenAccountsKeyKeepsTheServerAndThatKey() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val u = "earlier@example.org"
            val v = "taken@example.org"
            val a = w.account(u)
            val uId = w.userId(u)
            s.advance(2 * 3_600_000L)
            val refused = w.run(a, "enrol", Steps.enrolLink(s, u), "--email", u, "--kit-out", File(w.tmp, "kit-2").path)
            assertEquals(1, refused.code, refused.out + refused.err)
            w.run(a, "forget-earlier-account", "--email", u, "--yes").ok()
            val keyRecord = "${Host.CLI_IDENTITY}${s.origin}|$uId"
            val uKey = assertNotNull(CliHome(a).deviceState().get(keyRecord), "the forgetting keeps U's key")

            w.account(v)
            val vId = w.userId(v)
            w.run(a, "sign-in", "--email", v, "--trust-card", w.card0).ok()
            val done = w.run(a, "account", "delete", "--confirm-email", v)
            assertEquals(0, done.code, done.out + done.err)
            val after = records(a)
            println("records after the deletion: ${after.keys}")
            assertTrue(after.keys.none { it.contains(vId) || it.contains(v) }, "nothing of the deleted account: ${after.keys}")
            assertEquals(uKey, CliHome(a).deviceState().get(keyRecord), "U's key stays on record")
            assertTrue(w.run(a, "whoami").ok().contains("server:  andvari"), "the pin stays")

            // U served under another key than the one on record: refused at the sign-in, nothing kept, nothing offered.
            CliHome(a).deviceState().set(keyRecord, Bytes.toB64(createCryptoProvider().randomBytes(32)))
            val r = w.run(a, "sign-in", "--email", u)
            assertEquals(1, r.code, r.out + r.err)
            assertNull(CliHome(a).secureState().get("cli.session|${s.origin}|$u"), "no session kept")
            assertFalse(r.err.contains("forget-earlier-account"), r.err)
            val f = w.run(a, "forget-earlier-account", "--email", u)
            assertEquals(1, f.code, f.out + f.err)
            assertTrue(f.err.contains("[$KEY_EARLIER_NOT_OFFERED]: " + fill(EARLIER_KEY_NOT_OFFERED, s.origin, u)), f.err)
            // What is said: the server was kept, and why; the key's own sentence at the sign-in.
            assertTrue(done.out.contains(fill(DELETED_SERVER_KEPT, s.origin, fill(KEPT_OTHER_KEY, uId))), done.out)
            assertTrue(r.err.contains("[$IDENTITY_KEY_NOT_KNOWN]: " + fill(IDENTITY_KEY_REFUSED_OPEN, s.origin, ACT_SIGN_IN)), r.err)
        }
    }
}
