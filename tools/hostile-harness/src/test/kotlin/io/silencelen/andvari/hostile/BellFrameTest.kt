package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.items.BellState
import io.silencelen.andvari.core.client.items.EventBell
import io.silencelen.andvari.core.client.net.ResponseCaps
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.BellConn
import io.silencelen.andvari.hostile.proxy.HostileBell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The event bell's frames are capped (spec 03 §6; [ResponseCaps.of]`(EVENTS)`). The bell is a dirty-bell, never a data
 * plane: its frames are a few dozen bytes. A hostile server registers the socket honestly (`pong`), then sends a frame
 * that never ends, by a length far above the cap or by fragments that never finish. The device takes at most the cap
 * plus what sockets buffer, drops the socket, rings nothing, and keeps nothing of the frame: the session, the pin, the
 * device state and the copy are what they were, and the next sync works.
 *
 * The socket is a real one: the proxy cannot upgrade, so the device's socket goes to [HostileBell] on its own loopback
 * port, while its ticket is minted through the proxy by the real server.
 */
class BellFrameTest {
    /** What may reach the device beyond the cap before it hangs up or stops reading: what the sockets and the engine buffer. */
    private val buffered = 16L shl 20
    private val cap = ResponseCaps.of(WireRoute.EVENTS)

    private class Run(val bell: EventBell, val rings: MutableList<Long?>, val revoked: AtomicBoolean, val scope: CoroutineScope)

    /** An event bell over [h]'s own session client and its dialer's socket, parked (not redialing) after its first drop. */
    private fun bellOf(h: Host, origin: String): Run {
        val rings = CopyOnWriteArrayList<Long?>()
        val revoked = AtomicBoolean()
        val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        val bell = EventBell(h.client(origin), h.dialer.bellSocket(origin), onRing = { rings += it }, onRevoked = { revoked.set(true) }, pause = { awaitCancellation() })
        bell.start(scope)
        return Run(bell, rings, revoked, scope)
    }

    private suspend fun until(what: () -> String, ms: Long = 30_000, cond: () -> Boolean) {
        val end = System.currentTimeMillis() + ms
        while (!cond()) {
            if (System.currentTimeMillis() > end) throw AssertionError(what())
            delay(25)
        }
    }

    private fun snapshot(h: Host): Map<String, String?> =
        h.state.keys()!!.associateWith { h.state.get(it) } + h.secure.keys()!!.associate { "secure:$it" to h.secure.get(it) }

    /** Registers honestly, then [lie]. */
    private fun registerThen(lie: (BellConn) -> Unit): (BellConn) -> Unit = { c ->
        assertEquals("ping", c.readText(), "the bell registers with ping")
        c.sendText("pong")
        lie(c)
    }

    @Test fun anOversizedOrEndlesslyFragmentedBellFrameDropsTheSocketAndKeepsNothing() = HostileBell().use { hb ->
        world {
            operator()
            val ah = member("alice", bell = hb)
            val a = account(ah)
            a.synced()
            val items = a.items(a.personalVaultId!!)
            val lies = listOf<Pair<String, (BellConn) -> Unit>>(
                "a whole frame of 1 MiB" to { c -> c.endlessFrame(declaredLength = 1L shl 20, upTo = 1L shl 20) },
                "a frame declaring 1 TiB" to { c -> c.endlessFrame(declaredLength = 1L shl 40, upTo = cap + (64L shl 20)) },
                "a frame whose fragments never end" to { c -> c.endlessFragments(piece = 4096, upTo = cap + (64L shl 20)) },
            )
            for ((what, lie) in lies) {
                hb.script = registerThen(lie)
                val before = snapshot(ah)
                val session = ah.session(origin)!!.let { it.accessToken to it.refreshToken }
                val pin = ah.trust.pinFor(origin)
                val run = bellOf(ah, origin)
                val conn = withContext(Dispatchers.IO) { hb.nextConn() }
                assertNull(conn.upgrade.header("Authorization"), "$what: the socket carries no bearer")
                assertTrue(conn.upgrade.queryParam("ticket") != null, "$what: the socket carries its ticket")
                val taken = withContext(Dispatchers.IO) { conn.awaitQuiet({ hb.scriptDone }) }
                until({ "$what: the bell drops the socket (state ${run.bell.state}, took $taken bytes)" }) { run.bell.state == BellState.WAITING }
                conn.close()
                run.bell.stop()
                run.scope.cancel()
                assertTrue(taken <= cap + buffered, "$what: the device took $taken bytes of the frame, cap $cap")
                assertEquals(listOf<Long?>(null), run.rings, "$what: the bell rang only its registration, never the frame")
                assertFalse(run.revoked.get(), "$what: an oversized frame does not end the session")
                assertEquals(1, run.bell.failures, "$what: one failed attempt on the ladder")
                assertEquals(session, ah.session(origin)!!.let { it.accessToken to it.refreshToken }, "$what: the session is unchanged")
                assertEquals(pin, ah.trust.pinFor(origin), "$what: the pin is unchanged")
                assertEquals(before, snapshot(ah), "$what: nothing of the frame is kept")
                assertEquals(items, a.items(a.personalVaultId!!), "$what: the copy is unchanged")
            }
            assertTrue(hb.failures.isEmpty(), "the bell's scripts: ${hb.failures}")
            a.synced()
        }
    }

    @Test fun aBellFrameAtTheCapKeepsTheSocketAndOneByteOverDropsIt() = HostileBell().use { hb ->
        world {
            operator()
            val ah = member("alice", bell = hb)
            account(ah).synced()
            val pad = { n: Int, json: String -> (json + " ".repeat(n - json.length)) }

            // At the cap: the socket takes it (the bell skips a frame this long, as any it cannot use), and an honest
            // ring after it still arrives. This is the honest control for the scenario above.
            hb.script = registerThen { c ->
                c.sendText(pad(cap.toInt(), """{"type":"revoked"}"""))
                c.sendText("""{"type":"rev","rev":7}""")
                while (c.readText() != null) Unit
            }
            val ok = bellOf(ah, origin)
            withContext(Dispatchers.IO) { hb.nextConn() }
            until({ "an honest ring after a frame at the cap arrives: ${ok.rings}, state ${ok.bell.state}" }) { 7L in ok.rings }
            assertEquals(BellState.OPEN, ok.bell.state, "the socket stays open")
            assertFalse(ok.revoked.get(), "a padded frame the bell cannot use is not a revocation")
            ok.bell.stop()
            ok.scope.cancel()

            // One byte over: the socket is dropped before the ring that follows it.
            hb.script = registerThen { c ->
                c.sendText(pad(cap.toInt() + 1, """{"type":"rev","rev":8}"""))
                c.sendText("""{"type":"rev","rev":9}""")
                while (c.readText() != null) Unit
            }
            val over = bellOf(ah, origin)
            val conn = withContext(Dispatchers.IO) { hb.nextConn() }
            until({ "one byte over the cap drops the socket (state ${over.bell.state}, rings ${over.rings})" }) { over.bell.state == BellState.WAITING }
            conn.close()
            over.bell.stop()
            over.scope.cancel()
            assertEquals(listOf<Long?>(null), over.rings, "nothing after the oversized frame rang")
            assertFalse(over.revoked.get())
            assertTrue(hb.failures.isEmpty(), "the bell's scripts: ${hb.failures}")
        }
    }
}
