package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The event bell (spec 03 §6): behind the origin guard, a fresh ticket per attempt, a ladder that resets only on a registered socket. */
class EventBellTest {
    private val goodTicket = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    private class Client : WireClient {
        override val origin = "https://vault.example.com"
        var stop = false
        override val stopped: Boolean get() = stop
        val tickets = ArrayDeque<WireResult<String>>()
        var mints = 0
        var onMint: () -> Unit = {}

        @Suppress("UNCHECKED_CAST")
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            check(route == WireRoute.EVENTS_TICKET)
            mints++
            onMint()
            return when (val t = tickets.removeFirstOrNull() ?: WireResult.NoAnswer(NoAnswerKind.TRANSPORT)) {
                is WireResult.Ok -> WireResult.Ok(decode("""{"ticket":"${t.value}","expiresInSeconds":30}"""), 200)
                else -> t as WireResult<T>
            }
        }
    }

    /** Each open plays one script: the frames the server sends after the client's `ping`, then the socket closes. */
    private class Socket(val onReceive: () -> Unit = {}) : BellSocket {
        val scripts = ArrayDeque<List<String>>()
        val opened = ArrayList<String>()
        val sent = ArrayList<String>()

        override suspend fun <T> open(origin: String, ticket: String, block: suspend (BellLink) -> T): T? {
            opened += "$origin $ticket"
            val frames = ArrayDeque(scripts.removeFirstOrNull() ?: emptyList())
            return block(object : BellLink {
                override suspend fun send(text: String): Boolean {
                    sent += text
                    return true
                }

                override suspend fun receive(): String? {
                    onReceive()
                    return frames.removeFirstOrNull()
                }
            })
        }
    }

    /** [msPerFrame]: how far the monotonic clock moves at each frame the socket reads (how long a socket stays open). */
    private class Rig(pauses: Int, msPerFrame: Long = 0) {
        val client = Client()
        var clock = 0L
        val socket = Socket { clock += msPerFrame }
        val rings = ArrayList<Long?>()
        var revoked = 0
        val waits = ArrayList<Long>()
        val bell = EventBell(client, socket, { rings += it }, { revoked++ }, jitter = { it }, pause = { ms ->
            waits += ms
            if (waits.size >= pauses) client.stop = true
        }, now = { clock })

        fun run() = runBlocking { withTimeout(10_000) { coroutineScope { bell.start(this) } } }
    }

    @Test
    fun aStoppedOrigin_getsNoTicketAndNoSocket() {
        val r = Rig(pauses = 1)
        r.client.stop = true
        r.run()
        assertEquals(0, r.client.mints)
        assertTrue(r.socket.opened.isEmpty())
        assertEquals(BellState.ORIGIN_STOPPED, r.bell.state)
    }

    @Test
    fun anOriginThatStopsBetweenTheTicketAndTheDial_getsNoSocket() {
        val r = Rig(pauses = 5)
        r.client.tickets += WireResult.Ok(goodTicket, 200)
        r.client.onMint = { r.client.stop = true }
        r.run()
        assertEquals(1, r.client.mints)
        assertTrue(r.socket.opened.isEmpty())
        assertEquals(BellState.ORIGIN_STOPPED, r.bell.state)
    }

    @Test
    fun failedAttempts_climbTheLadderFromOneSecondToTheCap() {
        val r = Rig(pauses = 8)
        r.run()
        assertEquals(listOf(1_000L, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000), r.waits)
        assertEquals(8, r.client.mints, "one ticket per attempt")
    }

    @Test
    fun aSocketThatDiesBeforeItsPong_isAFailedAttempt_andEachAttemptMintsAFreshTicket() {
        val r = Rig(pauses = 3)
        repeat(3) { r.client.tickets += WireResult.Ok(goodTicket, 200) }
        r.run()
        assertEquals(listOf(1_000L, 2_000, 4_000), r.waits)
        assertEquals(3, r.socket.opened.size)
        assertEquals(3, r.client.mints)
        assertTrue(r.socket.opened.all { it.startsWith("https://vault.example.com ") }, "only the client's own origin is dialed")
        assertTrue(r.rings.isEmpty(), "nothing rings before registration")
    }

    @Test
    fun aRegisteredSocket_ringsOnOpenAndOnRev_andResetsTheLadder() {
        // Six reads of 10 s each: registered at the first, ended at the last, 50 s later.
        val r = Rig(pauses = 4, msPerFrame = 10_000)
        repeat(4) { r.client.tickets += WireResult.Ok(goodTicket, 200) }
        r.socket.scripts += listOf<String>()
        r.socket.scripts += listOf<String>()
        r.socket.scripts += listOf("pong", """{"type":"rev","rev":7}""", "pong", "not json", """{"type":"policy"}""")
        r.run()
        assertEquals(listOf(1_000L, 2_000, 1_000, 2_000), r.waits, "the ladder starts over after a registered socket")
        assertEquals(listOf(null, 7L), r.rings, "a pull on the (re)open, then the rev; a second pong rings nothing")
        assertTrue(r.socket.sent.all { it == "ping" })
    }

    /**
     * A server (or a front) that kills each socket right after its `pong` would reset the ladder every time
     * and get a ticket, a handshake and a pull about once a second without end. A registered socket that did not stay
     * [EventBell.STABLE_MS] is a failed attempt: the ladder climbs, while each (re)open still rings once.
     */
    @Test
    fun registeredSocketsThatDoNotStay_climbTheLadderAsFailures() {
        val r = Rig(pauses = 7, msPerFrame = 1_000)
        repeat(7) {
            r.client.tickets += WireResult.Ok(goodTicket, 200)
            r.socket.scripts += listOf("pong")
        }
        r.run()
        assertEquals(listOf(1_000L, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000), r.waits)
        assertEquals(List<Long?>(7) { null }, r.rings, "each registered open still asks for a pull")
    }

    /** The edge of [EventBell.STABLE_MS]: one millisecond short climbs, exactly the interval starts the ladder over. */
    @Test
    fun aRegisteredSocketResetsTheLadderOnlyOnceItStayedTheInterval() {
        for ((stayed, waits) in listOf(EventBell.STABLE_MS - 1 to listOf(1_000L, 2_000, 4_000), EventBell.STABLE_MS to listOf(1_000L, 2_000, 1_000))) {
            // Two failed attempts, then a socket registered at its first read and ended at its second, [stayed] later.
            val r = Rig(pauses = 3, msPerFrame = stayed)
            repeat(3) { r.client.tickets += WireResult.Ok(goodTicket, 200) }
            r.socket.scripts += listOf<String>()
            r.socket.scripts += listOf<String>()
            r.socket.scripts += listOf("pong")
            r.run()
            assertEquals(waits, r.waits, "stayed $stayed ms")
        }
    }

    @Test
    fun aDeadSessionAtMint_orARevokedFrame_stopsTheBellForGood() {
        val r = Rig(pauses = 5)
        r.client.tickets += WireResult.Refused(401, WireError("unauthorized", "no"))
        r.run()
        assertEquals(listOf(1, 0), listOf(r.revoked, r.socket.opened.size))
        assertEquals(BellState.REVOKED, r.bell.state)
        assertTrue(r.waits.isEmpty())

        val f = Rig(pauses = 5)
        f.client.tickets += WireResult.Ok(goodTicket, 200)
        f.socket.scripts += listOf("pong", """{"type":"revoked"}""", """{"type":"rev","rev":9}""")
        f.run()
        assertEquals(1, f.revoked)
        assertEquals(listOf<Long?>(null), f.rings, "nothing after the revoked frame")
        assertEquals(BellState.REVOKED, f.bell.state)
        assertTrue(f.waits.isEmpty())
    }

    @Test
    fun aTicketThatIsNotAToken_neverBecomesAUrl() {
        val r = Rig(pauses = 2)
        r.client.tickets += WireResult.Ok("abc&x=1/../../evil-ticket-value", 200)
        r.client.tickets += WireResult.Ok("short", 200)
        r.run()
        assertTrue(r.socket.opened.isEmpty())
        assertEquals(listOf(1_000L, 2_000), r.waits)
    }

    @Test
    fun aRefusedMint_otherThanADeadSession_isRetried() {
        val r = Rig(pauses = 2)
        r.client.tickets += WireResult.Refused(429, WireError("rate_limited", "slow"), 5)
        r.client.tickets += WireResult.Ok(goodTicket, 200)
        r.run()
        assertEquals(0, r.revoked)
        assertEquals(1, r.socket.opened.size)
    }
}
