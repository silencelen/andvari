package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * One home keeps the same address at two servers. The tool's confirmed deletion of the account at the first removes only
 * records of the first: every record of the second stays byte for byte (its saved session, its device record, the
 * address's record and the key's record), the person stays signed in there, and the second server serving another
 * account under the address later is refused with both possibilities and the offer. Before, the deletion matched the
 * address and the device id in the records of every server, and the second server's next account was taken without a
 * word. Over two real servers.
 */
class DeletionAtOneOfTwoServersTest {
    /** Both stores of [home], as `store:key` → value. */
    private fun records(home: File): Map<String, String?> {
        val h = CliHome(home)
        return listOf("state" to h.deviceState(), "secure" to h.secureState()).flatMap { (n, st) -> st.keys()!!.map { "$n:$it" to st.get(it) } }.toMap()
    }

    /** The two test clocks set to the same time (the later one), so that one home can run against both. */
    private fun align(a: TestServer, b: TestServer) {
        if (a.now() < b.now()) a.advance(b.now() - a.now()) else if (b.now() < a.now()) b.advance(a.now() - b.now())
    }

    /** [email] made and signed in on [home] at [w]'s server; answers its user id. */
    private fun made(w: CliWorld, home: File, email: String, kit: File): String {
        w.s.advance(2 * 3_600_000L)
        w.run(home, "enrol", Steps.enrolLink(w.s, email), "--email", email, "--kit-out", kit.path, "--trust-card", w.card0).ok()
        w.run(home, "sign-in", "--trust-card", w.card0).ok()
        return w.userId(email)
    }

    /** The records of [origin] in [home]: every key that names it, and every key of its account [userId]. */
    private fun ofServer(home: File, origin: String, userId: String) =
        records(home).filterKeys { k -> names(k, origin) || names(k, userId) }

    /** True where the record `store:key` [k] has [part] as one of its key's components. */
    private fun names(k: String, part: String) = k.substringAfter(':').split('|').contains(part)

    /**
     * The other removals that take an address or an account's id, at the first server, beside the same address at the
     * second: a sign-out, the forgetting of the earlier account and "Forget this server" leave every record of the second
     * as it was, a record that names the second server under the first one's account id included.
     */
    @Test fun aSignOutAForgettingAndForgetServerAtOneServerLeaveTheOther() {
        TestServer().use { s1 ->
            TestServer().use { s2 ->
                val w1 = CliWorld(s1)
                val w2 = CliWorld(s2)
                align(s1, s2)
                val me = "twice@example.org"
                val a = File(w1.tmp, "a")
                val u1 = made(w1, a, me, File(w1.tmp, "kit-1"))
                align(s1, s2)
                val u2 = made(w2, a, me, File(w2.tmp, "kit-2"))
                align(s1, s2)
                CliHome(a).deviceState().set("${Host.CLI_NAME}${s2.origin}|$u1", "a name the second server's account had")
                val before = ofServer(a, s2.origin, u2)

                w1.run(a, "sign-out", "--email", me).ok()
                assertEquals(before, ofServer(a, s2.origin, u2), "a sign-out at the first server")

                val b = File(w1.tmp, "elsewhere")
                w1.run(b, "sign-in", "--email", me, "--trust-card", w1.card0).ok()
                w1.run(b, "account", "delete", "--confirm-email", me).ok()
                made(w1, File(w1.tmp, "remade"), me, File(w1.tmp, "kit-remade"))
                val r = w1.run(a, "sign-in", "--email", me, "--trust-card", w1.card0)
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$EARLIER_ACCOUNT_KNOWN]: "), r.err)
                val plan = w1.run(a, "forget-earlier-account", "--email", me)
                assertEquals(2, plan.code, plan.out + plan.err)
                assertTrue(plan.err.lines().none { it.contains(s2.origin) }, "the plan names nothing of the second server: ${plan.err}")
                w1.run(a, "forget-earlier-account", "--email", me, "--yes").ok()
                assertEquals(before, ofServer(a, s2.origin, u2), "the forgetting of the earlier account at the first server")
                assertTrue(records(a).keys.none { names(it, s1.origin) && names(it, u1) && !it.startsWith("state:${Host.CLI_IDENTITY}") }, "${records(a).keys}")

                w1.run(a, "forget-server", "--yes").ok()
                assertEquals(before, ofServer(a, s2.origin, u2), "forget-server at the first server")
                assertTrue(records(a).keys.none { names(it, s1.origin) }, "nothing of the first server: ${records(a).keys}")

                align(s1, s2)
                w2.run(a, "sync").ok()
            }
        }
    }

    @Test fun aDeletionAtOneServerLeavesEveryRecordOfTheSameAddressAtAnother() {
        TestServer().use { s1 ->
            TestServer().use { s2 ->
                val w1 = CliWorld(s1)
                val w2 = CliWorld(s2)
                align(s1, s2)
                val me = "both@example.org"
                val a = File(w1.tmp, "a")
                val u1 = made(w1, a, me, File(w1.tmp, "kit-1"))
                align(s1, s2)
                val u2 = made(w2, a, me, File(w2.tmp, "kit-2"))
                align(s1, s2)

                // As if the second server had handed out the first one's account id too: its record names the second server.
                CliHome(a).deviceState().set("${Host.CLI_IDENTITY}${s2.origin}|$u1", "a key the second server gave")
                fun ofTheSecond() = ofServer(a, s2.origin, u2)
                val before = ofTheSecond()
                println("records of the second server before: ${before.keys.sorted()}")
                for (k in listOf("secure:cli.session|${s2.origin}|$me", "state:ovh.dev|${s2.origin}|$me",
                    "state:${Host.CLI_ADDRESS}${s2.origin}|$me", "state:${Host.CLI_IDENTITY}${s2.origin}|$u2")) {
                    assertNotNull(before[k], "$k is kept before the deletion: ${before.keys}")
                }

                val done = w1.run(a, "account", "delete", "--confirm-email", me)
                assertEquals(0, done.code, done.out + done.err)
                val after = records(a)
                println("records after the deletion at the first server: ${after.keys.sorted()}")
                assertEquals(before, ofTheSecond(), "every record of the second server is as it was")
                assertTrue(after.keys.none { names(it, s1.origin) || (names(it, u1) && !names(it, s2.origin)) }, "nothing of the first server is kept: ${after.keys}")
                assertTrue(done.out.contains(fill(DELETED_SERVER_FORGOTTEN, s1.origin)), done.out)

                // Still signed in at the second server.
                align(s1, s2)
                w2.run(a, "sync").ok()

                // The second server now serves another account under the address: refused, with the offer.
                val b = File(w2.tmp, "elsewhere")
                w2.run(b, "sign-in", "--email", me, "--trust-card", w2.card0).ok()
                w2.run(b, "account", "delete", "--confirm-email", me).ok()
                val v2 = made(w2, File(w2.tmp, "remade"), me, File(w2.tmp, "kit-remade"))
                assertTrue(v2 != u2)
                val ended = w2.run(a, "sync")
                assertEquals(1, ended.code, ended.out + ended.err)
                val r = w2.run(a, "sign-in", "--email", me, "--trust-card", w2.card0)
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$EARLIER_ACCOUNT_KNOWN]: " + fill(EARLIER_ACCOUNT_REFUSED_OPENED, s2.origin, me, ACT_SIGN_IN)), r.err)
                assertTrue(r.err.contains("forget-earlier-account"), r.err)
                assertEquals(u2, CliHome(a).deviceState().get("${Host.CLI_ADDRESS}${s2.origin}|$me"), "the address is still the first account there")
            }
        }
    }
}
