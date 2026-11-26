package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * What a recovery request draws, and what it gives back (decided on 2026-11-17).
 */
class RecoveryRequestGiveBackTest {
    private val post = HttpMethod.Post

    /**
     * A request whose transaction fails gives its address's draw back, and its code mail's place under the cap: it stored
     * nothing and mailed nothing. Before, the address bucket and the mail cap were drawn inside the transaction and kept
     * when it rolled back, so one failed request left the person four of the day's five.
     */
    @Test
    fun aRequestWhoseTransactionFails_spendsNoneOfTheAddresssFive() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        Flow.sink(s)
        suspend fun open() = c.call(
            post, "/api/v1/recovery/requests",
            """{"email":"${me.email}","rPub":"${b32()}","pollHash":"${sha256Hex(TestKit.crypto.randomBytes(32))}","platform":"android"}""",
        )
        // The transaction fails at the code mail's insert, after both draws were made.
        s.db.tx { it.exec("CREATE TRIGGER probe_fail BEFORE INSERT ON mail_outbox BEGIN SELECT RAISE(ABORT, 'probe'); END") }
        val failed = open()
        assertEquals(500, failed.status.value, failed.bodyAsText())
        s.db.tx { it.exec("DROP TRIGGER probe_fail") }
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM recovery_requests") })

        // The day's five are all still the person's: five real requests, five code mails, nothing dropped.
        repeat(5) { assertEquals(202, open().status.value) }
        assertEquals(5L, s.db.read { it.count("SELECT COUNT(*) FROM recovery_requests WHERE userId=?", me.userId) })
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='email_dropped'") })
        assertEquals(5, Flow.sink(s).count { it.first == "recovery_request_code" })
        // The sixth is over the address's five, as before.
        assertEquals(202, open().status.value)
        assertEquals(5L, s.db.read { it.count("SELECT COUNT(*) FROM recovery_requests WHERE userId=?", me.userId) })
    }

    /**
     * The ceiling for requests taken by a mailbox value and the cap for their code mails cannot drift apart: the cap is
     * derived from the ceiling, and both count in windows of the same length. A request taken by a value uses the value up
     * before its mail is queued, so a cap below the ceiling would spend values with no mail sent.
     */
    @Test
    fun theMailboxCeiling_andItsMailCap_areOneFigure() {
        assertEquals(Assisted.MAILBOX_BUCKET.limit, Mail.CapClass.MAILBOX_CODE.perWindow)
        assertEquals(Assisted.MAILBOX_BUCKET.windowMs, Mail.CapClass.MAILBOX_CODE.windowMs)
        assertEquals(Assisted.ADDRESS_BUCKET.windowMs, Mail.CapClass.CODE.windowMs)
    }
}
