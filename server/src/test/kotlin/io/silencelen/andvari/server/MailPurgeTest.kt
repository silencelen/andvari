package io.silencelen.andvari.server

import kotlin.test.Test
import kotlin.test.assertEquals

/** Spec 03 §14.5: the outbox is purged past its discard time even with no mail transport. */
class MailPurgeTest {
    @Test
    fun withoutATransport_expiredRowsStillGo() {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        s.mailTransport = null
        s.db.tx { c -> s.mail.enqueue(c, "account_deleted", "gone@example.com", Mail.Ctx(null, clock.now())) }
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM mail_outbox") })
        clock.advance(40 * Clock.DAY_MS)
        assertEquals(0, s.mail.drain())
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM mail_outbox") }, "the address is gone after its discard time")
    }
}
