package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The mailbox value of a request for the operator's help (spec 03 §18.1, decided on 2026-11-17), with the tool against the
 * real server and its mail sink. Someone else uses up an address's five requests of the day; the person's own request then
 * goes nowhere, and the same request with the value from one of those mails (`--mailbox-value-file`, or
 * `$ANDVARI_MAILBOX_VALUE`) is taken: its mail arrives. A wrong value gets the same output and no mail. The tool never
 * says whether a value was right; one that cannot be a value stops before anything is dialed.
 */
class MailboxValueTest {
    private val crypto = createCryptoProvider()
    private val pub = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
    private val email = "alice@example.org"
    private val code = "recovery_request_code"

    /** The value line under the code mail's paragraph: four groups of four, on a line of its own. */
    private val valueLine = Regex("""(?m)^ {4}([A-Z2-9]{4} [A-Z2-9]{4} [A-Z2-9]{4} [A-Z2-9]{4})$""")

    private class World(val s: TestServer, val tmp: File, val card0: String)

    private fun world(s: TestServer): World {
        val tmp = Files.createTempDirectory("andvari-cli").toFile()
        val op = File(tmp, "operator")
        CliRun.run(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
        val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, op, "card", "show").ok())!!.groupValues[1]
        val alice = File(tmp, "alice")
        CliRun.run(s, alice, "enrol", Steps.enrolLink(s, email), "--email", email, "--kit-out", File(tmp, "alice-kit.txt").path, "--trust-card", card0).ok()
        CliRun.run(s, alice, "recovery", "operator", "--i-understand").ok()
        return World(s, tmp, card0)
    }

    /** `recover assist --email` on a new device [name]; [stdin] answers the code prompt, [env] may carry a value. */
    private fun World.ask(name: String, env: (String) -> String? = { null }, stdin: () -> String?, vararg extra: String): CliRun =
        CliRun.run(s, File(tmp, name), "recover", "assist", "--email", email, "--trust-card", card0, *extra, env = env, stdin = stdin)

    /**
     * Five requests from elsewhere, each verified with its mailed code: the values their mails carry, in order. Then an
     * hour and a minute pass on the server's clock, so that the route's own limit per caller address (five an hour; every
     * run here comes from the loopback address) is not what answers the person's own: the address's five of the day stay spent.
     */
    private fun World.fiveFromElsewhere(): List<String> = (1..5).map { i ->
        val seen = Steps.mailCount(s, email, code)
        val r = ask("stranger $i", stdin = { Steps.awaitCode(s, email, code, seen) })
        assertEquals(0, r.code, r.out + r.err)
        val text = (Steps.awaitMail(s, email, code, seen)["text"] as kotlinx.serialization.json.JsonPrimitive).content
        valueLine.find(text)?.groupValues?.get(1) ?: throw AssertionError("no mailbox value in mail ${i}: $text")
    }.also { s.advance(61 * 60_000L) }

    /** What a run printed up to and including its request code, with the code itself masked. */
    private fun upToTheCode(r: CliRun): String {
        val lines = r.out.lines()
        val at = lines.indexOfFirst { it.startsWith("request code: ") }
        assertTrue(at >= 0, "a request code: ${r.out}")
        return (lines.take(at) + ("request code: X   " + lines[at].substringAfter("   "))).joinToString("\n")
    }

    @Test fun theGap_fiveRequestsFromElsewhere_thenThePersonsOwnWithAValueFromOneOfThoseMails_isTakenAndItsMailArrives() {
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub))).use { s ->
            val w = world(s)
            val values = w.fiveFromElsewhere()
            assertEquals(5, values.toSet().size, "each mail its own value")

            // The person's own request with no value goes nowhere: no sixth mail.
            var seen = Steps.mailCount(s, email, code)
            val none = w.ask("alice own", stdin = { "000000" })
            assertEquals(1, none.code, none.out + none.err)
            assertTrue(none.out.contains("request code: "), none.out)
            assertFalse(none.err.contains(MailboxValue.SENT), "no value, no line about one: ${none.err}")
            assertEquals(seen, Steps.mailCount(s, email, code), "the address's five are used up: no mail")

            // The same with the value from mail 3, typed as a person might (lower case, dashes): its mail arrives.
            val file = File(w.tmp, "value.txt").apply { writeText(values[2].lowercase().replace(' ', '-') + "\n") }
            seen = Steps.mailCount(s, email, code)
            val taken = w.ask("alice own 2", stdin = { Steps.awaitCode(s, email, code, seen) }, extra = arrayOf("--mailbox-value-file", file.path))
            assertEquals(0, taken.code, taken.out + taken.err)
            assertTrue(taken.out.contains("holding"), "verified with the code its mail carried: ${taken.out}")
            assertTrue(taken.err.contains(MailboxValue.SENT), taken.err)
            assertEquals(seen + 1, Steps.mailCount(s, email, code), "one mail, the request's own")
        }
    }

    @Test fun aWrongValue_getsTheSameOutputAsARightOne_andNoMail() {
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub))).use { s ->
            val w = world(s)
            val values = w.fiveFromElsewhere()
            // Well formed, of the alphabet, and none of the five.
            val wrong = generateSequence { (1..16).map { MailboxValue.ALPHABET[crypto.randomBytes(1)[0].toInt().and(31)] }.joinToString("") }
                .first { v -> values.none { it.replace(" ", "") == v } }

            var seen = Steps.mailCount(s, email, code)
            val refused = w.ask("alice wrong", env = { if (it == MailboxValue.ENV) wrong else null }, stdin = { "000000" })
            assertEquals(seen, Steps.mailCount(s, email, code), "a wrong value: no mail")
            seen = Steps.mailCount(s, email, code)
            val right = w.ask("alice right", env = { if (it == MailboxValue.ENV) values[0] else null }, stdin = { Steps.awaitCode(s, email, code, seen) })
            assertEquals(0, right.code, right.out + right.err)
            assertEquals(seen + 1, Steps.mailCount(s, email, code), "a right value: its mail")

            // Up to the code, which only the mail holds, the two runs print the same: the tool cannot tell the two apart.
            assertEquals(upToTheCode(right), upToTheCode(refused))
            val before = { r: CliRun -> r.err.substringBefore(MailboxValue.SENT) + MailboxValue.SENT }
            assertTrue(refused.err.contains(MailboxValue.SENT), refused.err)
            assertEquals(before(right), before(refused))
            assertFalse(refused.err.contains("wrong value") || refused.err.contains("not taken"), refused.err)
        }
    }

    @Test fun oneThatCannotBeAValue_stopsBeforeAnythingIsDialed() {
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub))).use { s ->
            val home = Files.createTempDirectory("andvari-cli").toFile()
            for (bad in listOf("hello", "ABCD EFGH JKLM NPQ1", "ABCD EFGH JKLM NPQR S")) {
                ConnectionCounter().use { counter ->
                    val r = CliRun.run(s, home, "recover", "assist", "--email", email, "--trust-card", "0".repeat(64),
                        env = { if (it == MailboxValue.ENV) bad else null }, dial = counter.address)
                    assertEquals(2, r.code, r.out + r.err)
                    assertTrue(r.err.contains(MailboxValue.NOT_A_VALUE), r.err)
                    assertEquals(0, counter.settled(), "nothing dialed for $bad")
                }
            }
            // Never on the command line.
            assertEquals(2, CliRun.run(s, home, "recover", "assist", "--email", email, "--mailbox-value", "ABCD").code)
        }
    }

    /**
     * The value goes in the shared step's own field, as the step writes it: without the spaces, tabs and dashes between its
     * groups, in capitals, once. A value whose groups stand apart by no-break spaces is not one by the step's own rule
     * (a value is ASCII only on the device): it is refused before anything is dialed, as the tool says for any value that
     * cannot be one.
     */
    @Test fun aValueGoesInTheRequestsOwnFieldOnce_andOneWithNoBreakSpacesIsRefusedBeforeAnythingIsDialed() {
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub))).use { s ->
            ConnectionCounter().use { counter ->
                val w = world(s)
                val r = CliRun.run(s, File(w.tmp, "alice nbsp"), "recover", "assist", "--email", email, "--trust-card", w.card0,
                    env = { if (it == MailboxValue.ENV) "abcd\u00A0efgh\u00A0jkmn\u00A0pqrs" else null }, stdin = { "000000" }, dial = counter.address)
                assertEquals(2, r.code, r.out + r.err)
                assertTrue(r.err.contains(MailboxValue.NOT_A_VALUE), r.err)
                assertEquals(0, counter.settled(), "nothing dialed")
            }
        }
    }

    @Test fun aValueWithItsGroupsApartBySpacesTabsAndDashes_goesInTheRequestsOwnFieldOnce() {
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub))).use { s ->
            LyingProxy(s).use { p ->
                val w = world(s)
                val bodies = java.util.Collections.synchronizedList(ArrayList<String>())
                p.answer = mapOf(io.silencelen.andvari.core.model.wire.WireRoute.RECOVERY_REQUEST_CREATE to { body, forward ->
                    bodies += String(body)
                    forward().let { (status, text) -> status to String(text) }
                })
                val typed = "abcd-efgh\tjkmn pqrs"
                val r = CliRun.run(s, File(w.tmp, "alice nbsp"), "recover", "assist", "--email", email, "--trust-card", w.card0,
                    env = { if (it == MailboxValue.ENV) typed else null }, stdin = { "000000" }, dial = p.address)
                assertTrue(r.out.contains("request code: ") && r.err.contains(MailboxValue.SENT), r.out + r.err)
                assertEquals(1, bodies.size, "one request: $bodies")
                val sent = kotlinx.serialization.json.Json.parseToJsonElement(bodies[0]) as kotlinx.serialization.json.JsonObject
                assertEquals("ABCDEFGHJKMNPQRS", (sent["mailboxValue"] as kotlinx.serialization.json.JsonPrimitive).content)
                assertEquals(1, Regex("\"mailboxValue\"").findAll(bodies[0]).count(), bodies[0])
            }
        }
    }

    /** At a terminal the value is asked for only after a yes; without one nothing is asked at all. */
    @Test fun theValueIsAskedForOnlyWhenThePersonSaysTheyHaveOne() {
        val asked = ArrayList<String>()
        val secret = { p: String -> asked += p; "abcd-efgh-jkmn-pqrs".toCharArray() }
        val q = { answer: String? -> { s: String -> asked += s; answer } }
        assertNull(MailboxValue.read(null, null, null), "no terminal: none, nothing asked")
        assertEquals(emptyList(), asked)
        for (no in listOf("", "n", "no", null)) assertNull(MailboxValue.read(null, q(no), secret))
        assertEquals(List(4) { MailboxValue.QUESTION }, asked, "the question only, never the value's prompt")
        asked.clear()
        assertEquals("ABCDEFGHJKMNPQRS", MailboxValue.normal(MailboxValue.read(null, q("y"), secret)!!))
        assertEquals(listOf(MailboxValue.QUESTION, MailboxValue.PROMPT), asked)
        asked.clear()
        assertEquals("given", String(MailboxValue.read("given".toCharArray(), q("y"), secret)!!), "a value given in a file or the environment")
        assertEquals(emptyList(), asked)
    }
}
