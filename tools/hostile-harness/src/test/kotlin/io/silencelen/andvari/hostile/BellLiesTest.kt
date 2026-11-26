package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.items.BellState
import io.silencelen.andvari.core.client.items.EventBell
import io.silencelen.andvari.hostile.proxy.BellConn
import io.silencelen.andvari.hostile.proxy.HostileBell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The event bell told lies it understands (spec 03 §6): honest-looking frames, sent too often, or with an absurd number.
 * The bell is a dirty-bell: a ring means "something changed, pull when you can", so a flood of rings must cost the
 * device at most a few pulls, never one pull per ring, and no number a ring names may silence the rings after it.
 *
 * The headless host has no bell glue of its own, so the ring handler here is the app's (`EngineVault.startBell` since
 * the fix of H12 in the app interface), on one thread as the app's main thread is: it never waits for the pull,
 * a ring that arrives while a pull runs costs one more pull after it, and a ring is measured only against the rev a pull
 * was ANSWERED at, never against another ring's number. What these scenarios test of the device is the bell itself
 * ([EventBell]): it hands every ring up at once, in order, without waiting for a pull, and keeps the socket open.
 */
class BellLiesTest {
    /** The app's ring handler; [serverRev] is the rev the stand-in pull is answered at. */
    private class AppRings(private val scope: CoroutineScope) {
        val pulls = AtomicInteger()
        val rings = CopyOnWriteArrayList<Long?>()
        @Volatile var newest = 0L
        @Volatile var serverRev = 0L
        @Volatile var answered = 0L
        private val pending = AtomicBoolean(false)
        private val pulling = AtomicBoolean(false)
        val idle: Boolean get() = !pulling.get() && !pending.get()

        val onRing: suspend (Long?) -> Unit = { rev ->
            rings += rev
            if (rev != null && rev > newest) newest = rev
            if (rev == null || rev > answered) {
                pending.set(true)
                if (pulling.compareAndSet(false, true)) scope.launch {
                    try {
                        while (pending.getAndSet(false)) {
                            pulls.incrementAndGet()
                            delay(25)
                            answered = serverRev
                        }
                    } finally {
                        pulling.set(false)
                    }
                }
            }
        }

        /** Wait until [n] pulls ran and none is running or pending, then a little longer, so a stray one would show. */
        suspend fun settlesAt(n: Int, what: String) {
            val end = System.currentTimeMillis() + 30_000
            while (!(pulls.get() >= n && idle) && System.currentTimeMillis() < end) delay(20)
            delay(300)
            assertEquals(n, pulls.get(), "$what (rings handed up: $rings)")
        }
    }

    /**
     * H12, fixed (`EngineVault.startBell` coalesces): a flood of 400 honest-looking rings, each with a
     * higher `rev`, sent at once. The bell hands up every one of them, in order, and the socket stays open; the app's
     * handler answers the flood with a few pulls. On the old handler (one awaited sync per ring) this was 401 pulls. It
     * fails again if the bell waits for a pull before it reads the next frame (the pulls would be one per ring), drops a
     * ring (the newest would not be 400) or drops the socket.
     */
    @Test fun aFloodOfHonestLookingRingsCostsTheDeviceAFewPullsNotOnePerRing() = HostileBell().use { hb ->
        world {
            operator()
            val ah = member("alice", bell = hb)
            account(ah).synced()
            val flood = 400
            hb.script = { c ->
                assertEquals("ping", c.readText(), "the bell registers with ping")
                c.sendText("pong")
                for (rev in 1..flood) c.sendText("""{"type":"rev","rev":$rev}""")
                while (c.readText() != null) Unit
            }
            Executors.newSingleThreadExecutor().asCoroutineDispatcher().use { main ->
                val scope = CoroutineScope(main + SupervisorJob())
                val app = AppRings(scope)
                val bell = EventBell(ah.client(origin), ah.dialer.bellSocket(origin), onRing = app.onRing, onRevoked = {}, pause = { awaitCancellation() })
                bell.start(scope)
                val conn = withContext(Dispatchers.IO) { hb.nextConn() }
                val end = System.currentTimeMillis() + 30_000
                while (!(app.newest >= flood && app.idle) && System.currentTimeMillis() < end) delay(50)
                delay(500)
                val state = bell.state
                bell.stop()
                scope.cancel()
                conn.close()
                assertEquals(BellState.OPEN, state, "an honest-looking flood does not drop the socket")
                assertEquals(flood.toLong(), app.newest, "the newest ring is seen")
                assertEquals(listOf<Long?>(null) + (1..flood).map { it.toLong() }, app.rings.toList(), "the registration, then every ring in order, each handed up once")
                assertTrue(app.pulls.get() <= 10, "a flood of $flood rings cost ${app.pulls.get()} pulls")
            }
        }
    }

    /**
     * A ring with an absurdly high number (`Long.MAX_VALUE / 2`, far above anything this account's server could be at),
     * then an honest, lower one: the absurd ring costs one pull, and the honest ring after it still pulls. The bell
     * hands both up and keeps the socket open; the number never becomes a bar (it would, on a handler that measured
     * rings against the highest ring, as B1 found). It fails again if the bell refuses or drops an out-of-range number
     * as a broken frame, closes the socket on it, or stops handing up rings below the highest one it saw.
     */
    @Test fun anAbsurdlyHighRingCostsOnePullAndAnHonestLowerRingAfterItStillPulls() = HostileBell().use { hb ->
        world {
            operator()
            val ah = member("alice", bell = hb)
            account(ah).synced()
            val frames = LinkedBlockingQueue<String>()
            hb.script = { c: BellConn ->
                assertEquals("ping", c.readText(), "the bell registers with ping")
                c.sendText("pong")
                while (true) {
                    val f = frames.poll(60, TimeUnit.SECONDS) ?: break
                    if (f.isEmpty()) break
                    c.sendText(f)
                }
                while (c.readText() != null) Unit
            }
            Executors.newSingleThreadExecutor().asCoroutineDispatcher().use { main ->
                val scope = CoroutineScope(main + SupervisorJob())
                val app = AppRings(scope).apply { serverRev = 7 }
                val bell = EventBell(ah.client(origin), ah.dialer.bellSocket(origin), onRing = app.onRing, onRevoked = {}, pause = { awaitCancellation() })
                bell.start(scope)
                val conn = withContext(Dispatchers.IO) { hb.nextConn() }
                try {
                    app.settlesAt(1, "the registered socket pulls once, answered at rev 7")
                    val absurd = Long.MAX_VALUE / 2
                    frames.put("""{"type":"rev","rev":$absurd}""")
                    app.settlesAt(2, "the absurd ring costs one pull")
                    assertEquals(7L, app.answered, "the pull was answered at the server's own rev; the ring's number is no bar")
                    app.serverRev = 8
                    frames.put("""{"type":"rev","rev":8}""")
                    app.settlesAt(3, "the honest ring after the absurd one pulls")
                    assertEquals(listOf(null, absurd, 8L), app.rings.toList(), "the bell handed up each ring once, in order")
                    assertEquals(BellState.OPEN, bell.state, "an absurd number does not drop the socket")
                } finally {
                    frames.put("")
                    bell.stop()
                    scope.cancel()
                    conn.close()
                }
            }
        }
    }
}
