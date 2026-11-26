package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * A sign-up's first step refused before anything is sent costs its caller nothing (decided on 2026-11-17). Before, the
 * step drew the caller's allowances (3 an hour, 10 a day) and the typed address's (5 a day) and only then found that no
 * mail could be sent, so a stalled outbox sent a person into an hour's wait for starts that sent nothing; and the draw
 * for an existing account's one notice a day, made inside the transaction, stayed spent when the transaction failed.
 */
class SignupStartGiveBackTest {
    private val post = HttpMethod.Post

    /**
     * A give-back never removes every limit (decided on 2026-11-17): while no mail can be sent, the caller's own sign-up
     * allowance comes back, but the ceiling per address in front of it does not. Before, three hundred starts from one
     * address while mail was down were all answered.
     */
    @Test
    fun whileMailIsDown_theCeilingPerAddressStillStands() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(TestKit.config(mode = "open"), clock)
        s.mailTransport = MailTransport { SendResult.Transient("down") }
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        c.login(Flow.member(c, s, "me@example.com")) // a new_device notice: the outbox is not empty
        s.mail.drain()
        clock.advance(Mail.STALL_MS)
        val ip = "10.9.9.8"
        val codes = (1..300).map { i ->
            c.call(post, "/api/v1/signup/start", """{"email":"n$i@example.com","ageConfirmed":true}""", ip = ip).let { r ->
                "${r.status.value} ${r.errorCode()}"
            }
        }
        val ceiling = SIGNUP_START_CEILING.limit
        assertEquals(List(ceiling) { "503 mail_unavailable" }, codes.take(ceiling), "the first starts: no mail can be sent")
        assertEquals(List(300 - ceiling) { "429 rate_limited" }, codes.drop(ceiling), "past the ceiling: too many")
        // The sign-up's own allowance was given back each time.
        assertEquals(0, s.limiter.count("${SIGNUP_START_HOUR.name}:${rateKeyOf(ip)}"))
    }

    @Test
    fun startsRefusedForAStalledOutbox_spendNothing_andTheNextStartIsTaken() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(TestKit.config(mode = "open"), clock)
        var down = true
        s.mailTransport = MailTransport { if (down) SendResult.Transient("down") else SendResult.Ok }
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        c.login(me) // a new_device notice: the outbox is not empty
        s.mail.drain()
        clock.advance(Mail.STALL_MS)
        val ip = "10.9.9.9"
        val email = "new@example.com"
        suspend fun start() = c.call(post, "/api/v1/signup/start", """{"email":"$email","ageConfirmed":true}""", ip = ip)
        // Five starts from one address for one typed address, more than either limit allows: every one is 503, none 429.
        repeat(5) { i ->
            val r = start()
            assertEquals(503, r.status.value, "try ${i + 1}: ${r.bodyAsText()}")
            assertEquals("mail_unavailable", r.errorCode())
        }
        assertEquals(0, s.limiter.count("${SIGNUP_START_HOUR.name}:${rateKeyOf(ip)}"))
        assertEquals(0, s.limiter.count("${SIGNUP_START_DAY.name}:${rateKeyOf(ip)}"))
        assertEquals(0, s.limiter.count("signup_start_address:${Grammar.emailHash(email)}"))
        // The outbox works again: the start is taken at once, on the caller's whole allowance.
        down = false
        s.mail.drain()
        assertEquals(202, start().status.value)
        assertEquals(1, s.limiter.count("${SIGNUP_START_HOUR.name}:${rateKeyOf(ip)}"))
    }

    @Test
    fun aFailedTransaction_givesTheExistingAccountsNoticeBack() = testApplication {
        val s = TestKit.services(TestKit.config(mode = "open"))
        s.mailTransport = MailTransport { SendResult.Ok }
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val key = "$SIGNUP_EXISTING_KEY${Grammar.emailHash(me.email)}"
        // The start's transaction fails at its last write (the audit row).
        s.db.tx { it.exec("CREATE TRIGGER fail_start BEFORE INSERT ON audit WHEN NEW.type='signup_start' BEGIN SELECT RAISE(ABORT, 'test'); END") }
        val failed = c.call(post, "/api/v1/signup/start", """{"email":"${me.email}","ageConfirmed":true}""")
        assertEquals(500, failed.status.value, failed.bodyAsText())
        assertEquals(0, s.limiter.count(key), "the notice was not sent, so the day's one is not spent")
        s.db.tx { it.exec("DROP TRIGGER fail_start") }
        val before = s.db.read { it.count("SELECT COUNT(*) FROM mail_outbox") }
        assertEquals(202, c.call(post, "/api/v1/signup/start", """{"email":"${me.email}","ageConfirmed":true}""").status.value)
        assertEquals(1, s.limiter.count(key))
        assertEquals(before + 1, s.db.read { it.count("SELECT COUNT(*) FROM mail_outbox") }, "the notice is queued")
    }
}
