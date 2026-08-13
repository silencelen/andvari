package io.silencelen.andvari.server

import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketExtension
import io.ktor.websocket.WebSocketSession
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.CoroutineContext
import kotlin.system.measureTimeMillis
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * F21: the dirty-bell fan-out must never be awaited on a request. `send` parks on the session's
 * bounded outgoing channel, so a member who opens /events and stops reading it (a suspended tab on a
 * stalled TCP connection) used to hold a CO-MEMBER's `POST /sync/push` until the 60 s pong reaper
 * fired — one client's state degrading another tenant's write latency, which no per-user bucket can
 * mitigate. These pin the two properties the fix rests on: the call returns immediately, and one
 * wedged peer does not starve the healthy ones sharing the fan-out.
 */
class NotifierFanoutTest {

    /** A socket that accepts frames into [taken]; capacity 0 + nobody receiving = a wedged peer. */
    private class FakeSession(capacity: Int) : WebSocketSession {
        val taken = Channel<Frame>(capacity)
        override val coroutineContext: CoroutineContext = Job() + Dispatchers.IO
        override val incoming = Channel<Frame>(Channel.UNLIMITED)
        override val outgoing = taken
        override val extensions: List<WebSocketExtension<*>> get() = emptyList()
        override var maxFrameSize: Long = Long.MAX_VALUE
        override var masking: Boolean = false
        override suspend fun send(frame: Frame) = outgoing.send(frame)
        override suspend fun flush() {}
        @Deprecated("Use cancel() instead.", replaceWith = ReplaceWith("cancel()", "kotlinx.coroutines.cancel"))
        override fun terminate() = Unit
    }

    @Test
    fun notifyRev_returnsImmediately_evenWithAWedgedPeer() {
        val notifier = Notifier()
        notifier.register("wedged-user", "d1", FakeSession(capacity = 0))

        // The fan-out is a launch, not an await: the caller is back before the 2 s send timeout, let
        // alone the 60 s pong reaper that used to be the only bound.
        val elapsed = measureTimeMillis { notifier.notifyRev(listOf("wedged-user"), 7) }
        assertTrue(elapsed < 500, "the push path must not wait on a socket (took ${elapsed}ms)")
    }

    @Test
    fun notifyRev_aWedgedPeerDoesNotStarveAHealthyOne() {
        val notifier = Notifier()
        val wedged = FakeSession(capacity = 0)
        val healthy = FakeSession(capacity = Channel.UNLIMITED)
        // Registered in this order under ONE user so the wedged conn is reached first: with a
        // sequential fan-out the healthy peer would wait behind it.
        notifier.register("u", "wedged", wedged)
        notifier.register("u", "healthy", healthy)

        notifier.notifyRev(listOf("u"), 42)

        val frame = runBlocking { withTimeout(2_000) { healthy.taken.receive() } }
        assertTrue(String((frame as Frame.Text).data).contains("\"rev\":42"), "the healthy peer still gets the bell")
    }
}
