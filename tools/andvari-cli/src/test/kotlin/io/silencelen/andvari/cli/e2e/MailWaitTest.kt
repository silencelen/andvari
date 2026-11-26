package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.core.client.onboard.SignupStart
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.server.MailTransport
import io.silencelen.andvari.server.OutgoingMail
import io.silencelen.andvari.server.SendResult
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The fixtures' own wait for mail ([Steps.awaitMail], [Steps.mailCount]), against a sink slowed down on purpose: it holds
 * each mail until the test lets it go, then writes its file in pieces, as the server's sink writes in place. A look at
 * once finds nothing; the wait finds the mail only once it is whole; and a wait that runs out says what it waited for
 * and what the sink and the outbox held instead.
 */
class MailWaitTest {
    /**
     * A sink in the server's own format (one JSON file per message, `{template, to, subject, text}`) that holds each mail
     * until [release], then writes the empty file, half the message and all of it, [pieceMs] apart.
     */
    private class SlowSink(private val dir: () -> File, private val pieceMs: Long) : MailTransport {
        val release = CountDownLatch(1)
        @Volatile var sent = 0

        /** Per recipient: when the last write of its newest mail's file began, and that mail. */
        val wholeAt = java.util.concurrent.ConcurrentHashMap<String, Long>()
        val body = java.util.concurrent.ConcurrentHashMap<String, String>()

        override fun send(m: OutgoingMail): SendResult {
            check(release.await(Await.DEFAULT_MS, TimeUnit.MILLISECONDS)) { "the test never let the slowed sink write" }
            val text = buildJsonObject { put("template", m.template); put("to", m.to); put("subject", m.subject); put("text", m.text) }.toString()
            val f = File(dir().apply { mkdirs() }, "%d-%06d-%s.json".format(System.currentTimeMillis(), ++sent, m.template))
            f.writeText("")
            Thread.sleep(pieceMs)
            f.writeText(text.substring(0, text.length / 2))
            Thread.sleep(pieceMs)
            // Noted before the last write: no read of the file can parse as a message before it began.
            body[m.to] = text
            wholeAt[m.to] = System.nanoTime()
            f.writeText(text)
            return SendResult.Ok
        }
    }

    private fun publicServer(sink: SlowSink?): TestServer =
        TestServer(kind = "public", mode = "open", extraEnv = mapOf("ANDVARI_SIGNUP_POW_BITS" to "10"), mailTransport = { inner -> sink ?: inner })

    /** A device past the Trust Gate asks for a sign-up code for [email]: the server queues the mail. */
    private suspend fun askForCode(s: TestServer, email: String) {
        val d = s.device("new person")
        val gate = assertIs<FirstPin.NeedsTrustGate>(d.trust.beginTrustGate(s.origin, TrustGateWording.TYPED_ADDRESS))
        assertIs<FirstPin.Pinned>(d.trust.confirmTrustGate(gate.confirm))
        assertEquals(SignupStart.Sent, d.onboarding(s.origin).signupStart(email, ageConfirmed = true))
    }

    private fun codesTo(s: TestServer, email: String) = s.mail().count { it.toString().contains(email) && it.toString().contains("signup_code") }

    @Test fun aMailTheSinkWritesLateAndInPiecesIsAwaitedUntilItIsWhole() {
        var server: TestServer? = null
        val sink = SlowSink({ server!!.mailSinkDir }, pieceMs = 500)
        publicServer(sink).use { s -> server = s; s.journey {
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            askForCode(s, "carol@example.org")
            // A look at once: the request has returned, the mail is queued, and the sink holds nothing of it.
            assertEquals(0, codesTo(s, "carol@example.org"), "a look at once finds no mail")
            assertEquals(1L, s.queuedMail("carol@example.org", "signup_code"), "the mail is queued, on its way")

            sink.release.countDown()
            val code = Steps.awaitCode(s, "carol@example.org")
            val foundAt = System.nanoTime()
            val whole = sink.wholeAt["carol@example.org"]
            assertTrue(whole != null && foundAt >= whole, "the wait returned only once the file was whole")
            assertTrue(sink.body["carol@example.org"]!!.contains(code), "the code is the one the sink wrote: $code in ${sink.body}")
            assertEquals(1, Steps.mailCount(s, "carol@example.org", "signup_code"), "one mail, read once it was whole")
        } }
    }

    @Test fun aWaitThatRunsOutSaysWhatItAwaitedAndWhatWasThereInstead() {
        publicServer(null).use { s -> s.journey {
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            askForCode(s, "carol@example.org")
            Steps.awaitMail(s, "carol@example.org", "signup_code")
            // A file the sink is still writing sits beside it.
            File(s.mailSinkDir, "${System.currentTimeMillis()}-999999-signup_code.json").writeText("{\"template\":\"sig")

            val e = assertFailsWith<AssertionError> { Steps.awaitCode(s, "dave@example.org", timeoutMs = 400) }
            val said = e.message!!
            for (words in listOf(
                "waited", "the bound is 400 ms", "signup_code mail number 1 to dave@example.org",
                "signup_code to carol@example.org", "1 file(s) not yet whole", "message(s) still queued in the server's outbox",
            )) assertTrue(said.contains(words), "\"$words\" in: $said")
        } }
    }
}
