package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Spec 01 §7 at the device link's pickup, against the real server through a lying proxy: a first exchange (the pickup's
 * prelogin) that gets no usable answer ends the pickup at once, as what is so. A cost outside the fence is the server's
 * fault (exit 3); an answer that cannot be used is said as that, and only no answer at all is a server that cannot be
 * reached (the same at the pickup itself, and a two-step code refused there is never a wrong master password). Either way the exchange is made once, nothing is
 * derived from the password, the pickup itself is never sent, and the password is asked for once only.
 */
class DeviceLinkFirstExchangeTest {
    private val prelogin = "POST /api/v1/auth/prelogin"
    private val pickup = "/pickup"

    private fun await(buf: ByteArrayOutputStream, re: Regex): String =
        io.silencelen.andvari.cli.e2e.Await.until("a line matching ${re.pattern} from the other process", 120_000, { "its output so far: $buf" }) {
            re.find(buf.toString())?.groupValues?.get(1)
        }

    private class Picked(val run: CliRun, val derivations: List<Pair<Long, Long>>, val passwordReads: Int)

    /**
     * `link-device show` on [me], and `link-device` on a new device whose requests go through [p]; answers the new device's
     * run (within five minutes: a pickup that asks again without end fails here), what it derived and how often it read the
     * password. The limit is long on purpose: both sides wait between their steps, and when the machine is busy a link that
     * takes ten seconds by itself has taken two minutes (seen on 2026-11-17); what proves that the pickup did not ask
     * again is the count of first exchanges, not the clock.
     */
    private fun link(w: CliWorld, p: LyingProxy, me: File, name: String, totp: String? = null): Picked = link(w, p, me, name, listOfNotNull(totp))

    /** [link], with the two-step code read as [totps] in turn (the last one again after the list). */
    private fun link(w: CliWorld, p: LyingProxy, me: File, name: String, totps: List<String>): Picked {
        val codes = AtomicInteger()
        val shown = ByteArrayOutputStream()
        val joined = ByteArrayOutputStream()
        val shownEnv: (String) -> String? = { n ->
            when (n) {
                "ANDVARI_PASSWORD" -> Steps.PASSWORD
                "ANDVARI_DEVICE_CODE" -> await(joined, Regex("Type this code on your other device: ([0-9 ]+)"))
                else -> null
            }
        }
        val reads = AtomicInteger()
        val newEnv: (String) -> String? = { n ->
            when (n) {
                "ANDVARI_PASSWORD" -> Steps.PASSWORD.also { reads.incrementAndGet() }
                "ANDVARI_TOTP" -> totps.getOrNull(codes.getAndIncrement().coerceAtMost(totps.size - 1))
                else -> null
            }
        }
        val counted = CountingCrypto()
        val pool = Executors.newFixedThreadPool(2)
        val slow = SlowRunReport("link ($name)", {
            "-- the showing device's output:\n$shown\n-- the new device's output:\n$joined\n-- what the proxy passed:\n" + synchronized(p.timed) { p.timed.joinToString("\n") }
        })
        try {
            val show = pool.submit<CliRun> { CliRun.run(w.s, me, "link-device", "show", env = shownEnv, out = shown, captureErr = false) }
            val url = await(shown, Regex("(?m)^(\\S+://\\S+)$"))
            val linkFile = File(w.tmp, "device-link-$name.txt").also { it.writeText(url) }
            val newDevice = File(w.tmp, name)
            val joining = pool.submit<CliRun> {
                CliRun.run(w.s, newDevice, "link-device", "--link-file", linkFile.path, "--trust-card", w.card0, origin = null, env = newEnv,
                    out = joined, dial = p.address, crypto = counted)
            }
            val r = joining.get(2, TimeUnit.MINUTES)
            assertTrue(show.get(2, TimeUnit.MINUTES).out.contains("approved"), "the other device approved the link")
            return Picked(r, counted.derivations.toList(), reads.get())
        } finally {
            slow.close()
            pool.shutdownNow()
        }
    }

    private fun once(p: LyingProxy, mark: Int, picked: Picked) {
        val sent = p.seen.drop(mark)
        assertEquals(1, sent.count { it.startsWith(prelogin) }, "one first exchange: $sent")
        assertTrue(sent.none { it.contains(pickup) }, "the pickup was never sent: $sent")
        assertEquals(emptyList(), picked.derivations, "nothing derived from the password")
        assertEquals(1, picked.passwordReads, "the password was asked for once")
        assertFalse(picked.run.err.contains("wrong master password") || picked.run.err.contains("is wrong"), picked.run.err)
    }

    /**
     * The pickup is refused by the address's sign-in back-off (spec 03 §16.6, §8: a fixed `Retry-After: 60` whatever the
     * lock): the tool says so as at a sign-in, "at least a minute", decided on 2026-11-17; never "cannot be reached".
     */
    @Test fun aPickupRefusedByTheSignInBackOffSaysAtLeastAMinute() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val stranger = w.home("stranger@example.org")
                val wrong: (String) -> String? = { if (it == "ANDVARI_PASSWORD") "not the password at all 42" else null }
                repeat(5) { w.run(stranger, "sign-in", "--email", "me@example.org", "--trust-card", w.card0, env = wrong) }
                val picked = link(w, p, me, "new")
                assertEquals(listOf("60"), p.retryAfters.filter { it.first.contains(pickup) }.map { it.second.trim() }, "one pickup, refused for a minute")
                assertEquals(EXIT_TOO_MANY_PASSWORDS, picked.run.code, picked.run.out + picked.run.err)
                assertTrue(picked.run.err.contains("[$KEY_TOO_MANY_PASSWORDS]: $SIGN_IN_TOO_MANY_TRIES"), picked.run.err)
                assertFalse(picked.run.err.contains("be reached") || picked.run.err.contains("wrong master password"), picked.run.err)
            }
        }
    }

    @Test fun aFirstExchangeAtACostOutsideTheFenceEndsThePickupWithExitThree() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val ragged = 64L * 1024 * 1024 + 1
                p.lie = mapOf(WireRoute.PRELOGIN to { e: JsonElement ->
                    val o = e.jsonObject
                    JsonObject(o + ("kdfParams" to JsonObject(o.getValue("kdfParams").jsonObject + ("memBytes" to JsonPrimitive(ragged)))))
                })
                val mark = p.seen.size
                val picked = link(w, p, me, "new")
                assertEquals(EXIT_SERVER_ANSWER, picked.run.code, picked.run.out + picked.run.err)
                assertTrue(picked.run.err.contains("[$KEY_SERVED_COST_REFUSED]") && picked.run.err.contains("$ragged bytes") &&
                    picked.run.err.contains(SERVED_COST_REFUSED.substringAfterLast("}")), picked.run.err)
                once(p, mark, picked)
            }
        }
    }

    /** A first exchange answered with a body that is not its answer: the server was reached, so it is said as that. */
    @Test fun aFirstExchangeAnsweredWithNothingUsableEndsThePickupAsAnAnswerThatCouldNotBeUsed() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                p.answer = mapOf(WireRoute.PRELOGIN to { _, _ -> 200 to """{"not":"a prelogin"}""" })
                val mark = p.seen.size
                val picked = link(w, p, me, "new")
                assertEquals(1, picked.run.code, picked.run.out + picked.run.err)
                assertTrue(picked.run.err.contains(fill(FIRST_STEP_UNUSABLE, s.origin)), picked.run.err)
                assertFalse(picked.run.err.contains("reached"), "it was reached: ${picked.run.err}")
                once(p, mark, picked)
            }
        }
    }

    /** A first exchange that gets no answer at all: the server was not reached, and only then is it said so. */
    @Test fun aFirstExchangeWithNoAnswerEndsThePickupAsAServerThatCannotBeReached() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                p.cut = setOf(WireRoute.PRELOGIN)
                val mark = p.seen.size
                val picked = link(w, p, me, "new")
                assertEquals(1, picked.run.code, picked.run.out + picked.run.err)
                assertTrue(picked.run.err.contains(fill(FIRST_STEP_NOT_REACHED, s.origin)), picked.run.err)
                once(p, mark, picked)
            }
        }
    }

    /** The pickup itself answered with nothing usable (a server error with a proxy's page): said as that, not as unreachable. */
    @Test fun aPickupAnsweredWithNothingUsableIsSaidAsAnAnswerThatCouldNotBeUsed() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                p.answer = mapOf(WireRoute.DEVICE_LINK_PICKUP to { _, _ -> 500 to "<html>a proxy's page</html>" })
                val mark = p.seen.size
                val unusable = link(w, p, me, "new").run
                assertEquals(1, unusable.code, unusable.out + unusable.err)
                assertTrue(unusable.err.contains(fill(LATER_STEP_UNUSABLE, s.origin)), unusable.err)
                assertFalse(unusable.err.contains("reached") || unusable.err.contains(": wrong master password"), unusable.err)
                assertEquals(1, p.seen.drop(mark).count { it.contains(pickup) }, "one pickup")
            }
        }
    }

    /** The pickup itself not answered at all: only then is the server said not to be reached. */
    @Test fun aPickupNotAnsweredIsSaidAsAServerThatCannotBeReached() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                p.cut = setOf(WireRoute.DEVICE_LINK_PICKUP)
                val mark = p.seen.size
                val gone = link(w, p, me, "new").run
                assertEquals(1, gone.code, gone.out + gone.err)
                assertTrue(gone.err.contains(fill(LATER_STEP_NOT_REACHED, s.origin)), gone.err)
                assertEquals(1, p.seen.drop(mark).count { it.contains(pickup) }, "one pickup")
            }
        }
    }

    /**
     * A two-step code refused at the pickup (the server's `invalid_credentials` after its `totp_required`, made here by the
     * proxy): said as a code most likely wrong, never as a wrong master password.
     */
    @Test fun aTwoStepCodeRefusedAtThePickupIsNeverSaidAsAWrongMasterPassword() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val calls = AtomicInteger()
                p.answer = mapOf(WireRoute.DEVICE_LINK_PICKUP to { _, _ ->
                    if (calls.getAndIncrement() == 0) 401 to """{"error":"totp_required","message":"a code is needed"}"""
                    else 401 to """{"error":"invalid_credentials","message":"refused"}"""
                })
                val r = link(w, p, me, "new", totp = "123456").run
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains(fill(WRONG_CODE_AT_LINK, s.origin)), r.err)
                assertFalse(r.err.contains(": wrong master password"), r.err)
                assertEquals(2, calls.get(), "the pickup, then the pickup with the code")
            }
        }
    }

    /**
     * A two-step code refused at the pickup keeps the link (the server keeps it approved within its time): the tool says
     * the refusal after the code with its line that the link is still open, asks for the password and the code again, and
     * the link finishes with the right ones at the real server. The code step and the refusal are made here by the proxy
     * (the account has no two-step code); the third pickup goes to the real server. Before, the first refused code ended
     * the link.
     */
    @Test fun aTwoStepCodeRefusedAtThePickupKeepsTheLinkAndAsksForThePasswordAndTheCodeAgain() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val calls = AtomicInteger()
                p.answer = mapOf(WireRoute.DEVICE_LINK_PICKUP to { _, forward ->
                    when (calls.getAndIncrement()) {
                        0 -> 401 to """{"error":"totp_required","message":"a code is needed"}"""
                        1 -> 401 to """{"error":"invalid_credentials","message":"refused"}"""
                        else -> forward().let { (status, text) -> status to String(text) }
                    }
                })
                val picked = link(w, p, me, "new", listOf("111111", "222222"))
                val r = picked.run
                assertEquals(0, r.code, r.out + r.err)
                assertTrue(r.out.contains("linked: this device is"), r.out)
                assertTrue(r.err.contains(fill(WRONG_CODE_LINK_STAYS, s.origin)), r.err)
                assertFalse(r.err.contains(": wrong master password") || r.err.contains(fill(WRONG_CODE_AT_LINK, s.origin)), r.err)
                assertEquals(3, calls.get(), "the pickup, the pickup with the code, and again with the password and a new code")
                assertEquals(2, picked.passwordReads, "the password was asked for again")
            }
        }
    }

    /**
     * The same code refused again is not sent again: given in a file or the environment, it would only be refused once
     * more, and the server counts codes on its own back-off. The link's refusal is said as before, and nothing is linked.
     */
    @Test fun theSameCodeIsNotSentAgainAfterTheServerRefusedIt() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val calls = AtomicInteger()
                p.answer = mapOf(WireRoute.DEVICE_LINK_PICKUP to { _, _ ->
                    if (calls.getAndIncrement() == 0) 401 to """{"error":"totp_required","message":"a code is needed"}"""
                    else 401 to """{"error":"invalid_credentials","message":"refused"}"""
                })
                val r = link(w, p, me, "new", listOf("123456")).run
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains(fill(WRONG_CODE_LINK_STAYS, s.origin)) && r.err.contains(fill(WRONG_CODE_AT_LINK, s.origin)), r.err)
                assertEquals(2, calls.get(), "the pickup, then the pickup with the code; the same code never again")
            }
        }
    }
}
