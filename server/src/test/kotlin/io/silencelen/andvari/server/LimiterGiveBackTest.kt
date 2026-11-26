package io.silencelen.andvari.server

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * A draw on a device's budget that the account's ceiling refuses is given back to the window it was counted in
 * ([drawDevice], [RateLimiter.refund]). The case: the call is counted in the last moment of the device's window, and
 * another request of the same device, at the window's edge, starts the device's next window before the give-back. Given
 * back to whichever window was current, the next window lost a call it had counted and admitted one more than its limit.
 */
class LimiterGiveBackTest {
    private val b = Bucket.devicePerMinute("give_back", 3)
    private val w = b.windowMs

    @Test
    fun aGiveBackAtTheWindowsEdge_leavesTheNextWindowAtItsLimit() {
        var t = 0L
        var reads = 0
        var between: (() -> Unit)? = null
        // The driven clock. Armed, its second reading (the ceiling's draw of the call under test) first runs the other
        // request, at the next instant, and is then answered with the time it was read at.
        val limiter = RateLimiter {
            val v = t
            if (between != null && ++reads == 2) between!!.also { between = null }.invoke()
            v
        }
        val user = "u"
        // The device spends two of its three at t = 0, and the account's other devices fill its ceiling in that window.
        repeat(2) { assertNull(limiter.drawDevice(b, user, "d")) }
        repeat(b.accountCeiling!! - 2) { i -> assertNull(limiter.drawDevice(b, user, "e${i / b.limit}")) }

        // The last instant of the device's window: its third call is counted there, and the full ceiling refuses it.
        t = w - 1
        var other: Long? = -1L
        between = {
            // Another request of the same device at the window's edge draws its device budget (its ceiling's draw comes
            // after): the device's next window starts with it.
            t = w
            other = limiter.retryAfterMs(Bucket.deviceKey(b, "d"), b.limit, w)
        }
        assertNotNull(limiter.drawDevice(b, user, "d"), "the ceiling refuses the call at the window's last instant")
        between?.invoke()
        assertNull(other, "the other request opens the device's next window")

        // The next window holds the other request's call and admits exactly its limit in all.
        t = w
        var admitted = 1
        while (limiter.drawDevice(b, user, "d") == null) admitted++
        assertEquals(b.limit, admitted, "the device's window that started at its edge admits exactly its limit")
        assertEquals(b.limit, limiter.count(Bucket.deviceKey(b, "d")))
    }

    @Test
    fun aGiveBackInTheSameWindow_spendsNothing() {
        val clock = MutableClock(0)
        val limiter = RateLimiter(clock::now)
        // The ceiling is full from other devices; a call of a fresh device is refused by it and costs that device nothing.
        repeat(b.accountCeiling!!) { i -> assertNull(limiter.drawDevice(b, "u", "e${i / b.limit}")) }
        repeat(5) { assertNotNull(limiter.drawDevice(b, "u", "d")) }
        assertEquals(0, limiter.count(Bucket.deviceKey(b, "d")))
        // Once the ceiling's window lapses, the device has its whole budget.
        clock.advance(w)
        repeat(b.limit) { assertNull(limiter.drawDevice(b, "u", "d")) }
        assertNotNull(limiter.drawDevice(b, "u", "d"))
    }

    /**
     * A give-back is good for one use (decided on 2026-11-17): a second give-back of the same draw does nothing. Before, two
     * give-backs of one draw took two calls off the window, so with two counted against a limit of two, two more got in:
     * four against a limit of two.
     */
    @Test
    fun aSecondGiveBackOfTheSameDraw_doesNothing() {
        val limiter = RateLimiter(MutableClock(0)::now)
        val first = limiter.draw("k", 2, w).admitted!!
        assertNotNull(limiter.draw("k", 2, w).admitted)
        limiter.refund(first)
        limiter.refund(first)
        assertEquals(1, limiter.count("k"))
        assertNotNull(limiter.draw("k", 2, w).admitted)
        assertNull(limiter.draw("k", 2, w).admitted)
        // The same for a held device draw given back twice: the device's window loses one call, once; the account's
        // ceiling keeps both (a give-back never reaches it).
        val held = limiter.drawDeviceHeld(b, "u", "d")
        assertNull(held.waitMs)
        assertNull(limiter.drawDeviceHeld(b, "u", "d").waitMs)
        held.giveBack(); held.giveBack()
        assertEquals(1, limiter.count(Bucket.deviceKey(b, "d")))
        assertEquals(2, limiter.count(Bucket.accountKey(b, "u")))
    }

    /**
     * The account's ceiling is never given back (decided on 2026-11-17): a device whose every call is given back is still
     * refused once the ceiling is spent, so a refusal the caller can produce at will does not open unlimited calls. Before,
     * the give-back reached the ceiling too, and every such call was free.
     */
    @Test
    fun callsGivenBackEveryTime_areRefusedOnceTheCeilingIsSpent() {
        val limiter = RateLimiter(MutableClock(0)::now)
        val ceiling = b.accountCeiling!!
        repeat(ceiling) { i ->
            val d = limiter.drawDeviceHeld(b, "u", "d")
            assertNull(d.waitMs, "call ${i + 1} is within the ceiling")
            d.giveBack()
        }
        assertEquals(0, limiter.count(Bucket.deviceKey(b, "d")))
        assertEquals(ceiling, limiter.count(Bucket.accountKey(b, "u")))
        val refused = limiter.drawDeviceHeld(b, "u", "d")
        assertNotNull(refused.waitMs, "the call past the ceiling is refused although the device's own budget is empty")
        assertEquals(0, limiter.count(Bucket.deviceKey(b, "d")), "and it costs the device nothing")
    }
}
