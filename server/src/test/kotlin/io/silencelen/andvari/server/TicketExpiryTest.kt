package io.silencelen.andvari.server

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** Every ticket's expiry is exclusive (spec 03 §0.1): valid while `now < expiresAt`, dead at `now = expiresAt`. */
class TicketExpiryTest {
    @Test
    fun recoveryTicket_isDeadAtItsExpiry() {
        val clock = MutableClock()
        val t = RecoveryTickets(clock, ttlMs = 1_000)
        val a = t.mint("u", "v")
        clock.advance(999)
        assertEquals("u" to "v", t.redeem(a))
        val b = t.mint("u", "v")
        clock.advance(1_000)
        assertNull(t.redeem(b))
    }

    @Test
    fun eventsTicket_isDeadAtItsExpiry() {
        val clock = MutableClock()
        val t = EventsTicketStore(1_000) { clock.now() }
        val a = t.mint("u", "d", "s")
        clock.advance(999)
        kotlin.test.assertEquals(EventsTicketStore.Redeemed("u", "d", "s"), t.redeem(a))
        val b = t.mint("u", "d", "s")
        clock.advance(1_000)
        assertNull(t.redeem(b))
        // Single use.
        val c = t.mint("u", "d", "s")
        assertNotNull(t.redeem(c)); assertNull(t.redeem(c))
    }

    @Test
    fun wsTicket_isDeadAtItsExpiry() {
        val clock = MutableClock()
        val t = WsTicketStore(1_000) { clock.now() }
        val a = t.mint("u")
        clock.advance(1_000)
        assertNull(t.redeem(a))
    }
}
