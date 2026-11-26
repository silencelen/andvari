package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.BellState
import io.silencelen.andvari.core.client.items.EventBell
import io.silencelen.andvari.core.client.net.BellFailure
import io.silencelen.andvari.core.client.net.DialedBellSocket
import io.silencelen.andvari.core.client.net.Dialer
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Live updates come back within seconds after the network does, instead of after up to two
 * minutes. The platform's network notice is replaced by a test double: the test calls [BellNetworkWatch.available] and
 * [BellNetworkWatch.lost] itself, with plain strings as networks.
 */
class LiveUpdatesNetworkTest {
    // ---- the rule and its bound, on a test clock ----

    private class Clock {
        var now = 0L
        val queued = mutableListOf<Pair<Long, () -> Unit>>()

        /** Run every deferred redial that is due by [t], in order, moving the clock there. */
        fun advanceTo(t: Long) {
            while (true) {
                val next = queued.filter { it.first <= t }.minByOrNull { it.first } ?: break
                queued.remove(next)
                now = next.first
                next.second()
            }
            now = t
        }
    }

    private class Watched(initial: Any?) {
        val clock = Clock()
        var ended = 0
        val watch = BellNetworkWatch(
            initial = initial,
            endSockets = { ended++ },
            redial = {},
            nowMs = { clock.now },
            later = { ms, run -> clock.queued += (clock.now + ms) to run },
        )
    }

    @Test
    fun aLostNetworkEndsTheSocketsAndOneThatIsThereAgainDialsAtOnce() {
        val w = Watched("wifi")
        w.watch.available("wifi")
        assertEquals(0, w.ended, "the platform's first notice for the network in place is no change")
        assertEquals(0, w.watch.redials)
        w.watch.lost("cell")
        assertEquals(0, w.ended, "a network that is not the default is not ours")
        w.watch.lost("wifi")
        assertEquals(1, w.ended, "the default network is gone: the sockets on it end now")
        assertEquals(0, w.watch.redials, "nothing is dialled while there is no network")
        w.watch.lost("wifi")
        assertEquals(1, w.ended)
        w.clock.advanceTo(5_000)
        w.watch.available("wifi")
        assertEquals(1, w.ended, "after a loss nothing is left to end")
        assertEquals(1, w.watch.redials, "a network is there again: the bell dials at once")
        w.watch.available("wifi")
        assertEquals(1, w.watch.redials, "the same network again is no change")
    }

    @Test
    fun anotherNetworkTakingOverEndsTheSocketsOnTheOldOneAndDials() {
        val w = Watched("wifi")
        w.watch.available("cell")
        assertEquals(1, w.ended, "a socket opened on wifi sits on a network that may be gone")
        assertEquals(1, w.watch.redials)
    }

    @Test
    fun aFlappingNetworkCausesAtMostOneRedialEvery30Seconds() {
        val w = Watched(null)
        // A network that comes and goes every half second for ten minutes.
        var t = 0L
        var up = false
        while (t <= 600_000) {
            w.clock.advanceTo(t)
            if (up) w.watch.lost("wifi") else w.watch.available("wifi")
            up = !up
            t += 500
        }
        w.clock.advanceTo(t + 60_000)
        // 600 s / 30 s = 20 windows, plus the first, plus one folded at the end: never more.
        assertTrue(w.watch.redials <= 22, "redials: ${w.watch.redials}")
        assertTrue(w.watch.redials >= 15, "but it does keep coming back: ${w.watch.redials}")
        assertTrue(w.clock.queued.isEmpty())
    }

    @Test
    fun noticesInsideTheWindowFoldIntoOneRedialAtItsEndWhichIsSkippedIfTheNetworkIsGoneAgain() {
        val w = Watched(null)
        w.watch.available("wifi")
        assertEquals(1, w.watch.redials)
        w.clock.advanceTo(1_000)
        w.watch.available("cell")
        w.clock.advanceTo(2_000)
        w.watch.available("wifi")
        assertEquals(1, w.watch.redials, "inside the window: folded")
        assertEquals(1, w.clock.queued.size, "one redial waits, at the window's end")
        assertEquals(30_000L, w.clock.queued.single().first)
        w.clock.advanceTo(30_000)
        assertEquals(2, w.watch.redials)

        w.clock.advanceTo(40_000)
        w.watch.lost("wifi")
        w.watch.available("wifi")
        assertEquals(2, w.watch.redials)
        w.watch.lost("wifi")
        w.clock.advanceTo(60_000)
        assertEquals(2, w.watch.redials, "no network at the window's end: nothing is dialled")
        w.watch.available("wifi")
        assertEquals(3, w.watch.redials, "the next return dials at once (the window has passed)")
    }

    // ---- the app's socket ended by the notice ----

    private val ticket = "TiCkEtSeCrEt0123456789abcdef"

    private fun pinned(origin: String) = MemoryDeviceState().also {
        PinStore(it).put(
            CardPin("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", 1, "a".repeat(64), origin, "Home", "private",
                "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f", "A".repeat(43), "none", PinRoot.TRUST_GATE, null, "b".repeat(64)),
        )
    }

    /** The app's socket with a 60 s read timeout (so only the notice can end a silent socket quickly), and the dialer's. */
    private fun sockets(origin: String): Pair<AndroidBellSocket, DialedBellSocket> {
        val bell = AndroidBellSocket(
            tls = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory,
            hostNames = okhttp3.OkHttpClient().hostnameVerifier,
            cleartextPermitted = { true },
            timeouts = AndroidBellSocket.Timeouts(readMs = 60_000, openMs = 60_000, connectMs = 60_000),
        )
        return bell to Dialer(PinStore(pinned(origin)), androidHttpClient(), "android", bell).bellSocket(origin)
    }

    private suspend fun until(ms: Long, cond: () -> Boolean): Boolean {
        val end = System.nanoTime() + ms * 1_000_000
        while (System.nanoTime() < end) {
            if (cond()) return true
            delay(10)
        }
        return cond()
    }

    @Test
    fun aSocketOnANetworkThatWentAwayEndsAtOnceNotAfterItsReadTimeout() {
        // The server goes silent after the pong, as a socket on a vanished network does: no close, no reset.
        WsTestServer { p ->
            p.upgrade()
            p.clientFrame()
            p.text("pong")
            p.endsWithin(60_000)
        }.use { s ->
            val origin = "http://127.0.0.1:${s.port}"
            val (app, dialed) = sockets(origin)
            val watch = BellNetworkWatch("wifi", { app.endAll() }, {}, { 0L }, { _, _ -> })
            runBlocking {
                val read = async {
                    dialed.open(origin, ticket) { link ->
                        link.send("""{"type":"ping"}""")
                        val first = link.receive()
                        val t0 = System.nanoTime()
                        val after = link.receive()
                        Triple(first, after, (System.nanoTime() - t0) / 1_000_000)
                    }
                }
                assertTrue(until(10_000) { dialed.connected.value })
                assertTrue(until(10_000) { s.accepted.get() == 1 })
                delay(200)
                watch.lost("wifi")
                val (first, after, ms) = read.await()!!
                assertEquals("pong", first)
                assertNull(after, "the read ended")
                assertTrue(ms < 5_000, "ended in $ms ms, not after the 60 s read timeout")
            }
            assertEquals(BellFailure.Kind.BROKEN, dialed.failure.value?.kind, "recorded as any broken socket")
            assertFalse(dialed.connected.value)
            assertFalse(dialed.failure.value!!.detail.contains(ticket))
        }
    }

    @Test
    fun aSocketBeingOpenedWhenTheNetworkGoesIsAFailureToOpenThatSaysSo() {
        val asked = CompletableFuture<Unit>()
        WsTestServer { p ->
            p.head()
            asked.complete(Unit)
            p.endsWithin(60_000) // never answers the upgrade
        }.use { s ->
            val origin = "http://127.0.0.1:${s.port}"
            val (app, dialed) = sockets(origin)
            val t0 = System.nanoTime()
            val got = runBlocking {
                val opening = async { dialed.open(origin, ticket) { "opened" } }
                assertTrue(until(10_000) { asked.isDone }, "the upgrade was asked")
                assertEquals(1, app.endAll())
                opening.await()
            }
            assertNull(got)
            assertTrue((System.nanoTime() - t0) / 1_000_000 < 10_000)
            val failure = dialed.failure.value!!
            assertEquals(BellFailure.Kind.NOT_OPENED, failure.kind)
            // The dialer keeps the shared code's closed reason, never the message: a message can quote the address, and
            // the single-use ticket travels in the address.
            assertEquals(io.silencelen.andvari.core.client.net.BellOpenFailed.Reason.NETWORK_GONE, failure.reason)
            assertEquals("BellOpenFailed(NETWORK_GONE)", failure.detail)
            assertEquals(0, app.endAll(), "nothing is left to end")
        }
    }

    /** A session client that mints a fresh ticket for every attempt and dials [origin]. */
    private class Minting(override val origin: String) : WireClient {
        val mints = AtomicInteger()

        override suspend fun <T> call(
            route: WireRoute,
            pathParams: Map<String, String>,
            query: String?,
            bodyJson: String?,
            authenticated: Boolean,
            decode: (String) -> T,
        ): WireResult<T> {
            check(route == WireRoute.EVENTS_TICKET)
            val n = mints.incrementAndGet()
            return WireResult.Ok(decode("""{"ticket":"TiCkEt${n}abcdefghijklmnopqrstuv","expiresInSeconds":30}"""), 200)
        }
    }

    @Test
    fun theBellIsBackWithinSecondsOfTheNetworkWhereItsLadderWouldWaitMinutes() {
        val pongs = AtomicInteger()
        WsTestServer { p ->
            p.upgrade()
            p.clientFrame()
            p.text("pong")
            pongs.incrementAndGet()
            p.endsWithin(60_000)
        }.use { s ->
            val origin = "http://127.0.0.1:${s.port}"
            val (app, dialed) = sockets(origin)
            val client = Minting(origin)
            val waits = mutableListOf<Long>()
            runBlocking {
                // The bell's own ladder is made to wait ten minutes, so only the network notice can bring it back soon.
                val bell = EventBell(client, dialed, onRing = {}, onRevoked = {}, jitter = { it }, pause = { ms -> waits += ms; delay(600_000) })
                val watch = BellNetworkWatch("wifi", { app.endAll() }, { bell.reset() }, { System.nanoTime() / 1_000_000 }, { _, _ -> })
                bell.start(this)
                assertTrue(until(10_000) { bell.state == BellState.OPEN }, "registered: ${bell.state}")
                assertEquals(1, s.accepted.get())

                watch.lost("wifi")
                assertTrue(until(5_000) { bell.state == BellState.WAITING }, "the dead socket was noticed at once: ${bell.state}")
                assertEquals(BellFailure.Kind.BROKEN, dialed.failure.value?.kind)

                val t0 = System.nanoTime()
                watch.available("cell")
                assertTrue(until(5_000) { bell.state == BellState.OPEN && s.accepted.get() == 2 }, "back: ${bell.state}")
                val ms = (System.nanoTime() - t0) / 1_000_000
                assertTrue(ms < 5_000, "back in $ms ms")
                assertEquals(2, pongs.get())
                assertEquals(2, client.mints.get(), "a fresh ticket for the new socket, minted by the bell as always")
                assertEquals(1, watch.redials)
                bell.stop()
            }
            assertTrue(waits.isNotEmpty(), "the bell had gone to its ladder")
        }
    }

    @Test
    fun theAppRegistersThePlatformsNoticeForItsOwnSocketAndTellsLiveUpdatesAlone() {
        val seam = File("src/main/kotlin/io/silencelen/andvari/app/trust/TrustSeam.kt").readText()
        assertTrue(seam.contains("val bellSocket = AndroidBellSocket.forApp()"))
        assertTrue(seam.contains("Dialer(PinStore(state), http, AppPlatform.ANDROID.wireName, bellSocket = bellSocket)"))
        // The shared code's own call for a network's return (live updates alone, the background
        // too), through the model, which contains a fault of the shared code there (item 1); never the foreground call.
        assertTrue(seam.contains("BellNetworkWatch.register(app, bellSocket) {\n            model.networkReturned()\n        }"))
        assertFalse(seam.contains("inForeground()"))
        val watch = File("src/main/kotlin/io/silencelen/andvari/app/BellNetworkWatch.kt").readText()
        assertTrue(watch.contains("cm.registerDefaultNetworkCallback("))
        assertTrue(watch.contains("initial = cm.activeNetwork"))
        assertEquals(30_000L, BellNetworkWatch.MIN_REDIAL_SPACING_MS)
        val manifest = File("src/main/AndroidManifest.xml").readText()
        assertTrue(manifest.contains("android.permission.ACCESS_NETWORK_STATE"))
    }
}
