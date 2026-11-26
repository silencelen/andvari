package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Resp
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A server that answers with a redirect (spec 03 §0: no route of the protocol ever does). Whether the request carried
 * a credential (a sync with its bearer) or not (the card chain before the Trust Gate, the client policy), and wherever
 * `Location` points (another path on the origin, another host, a host over plain http, an address the origin grammar
 * refuses and the device must never dial): no credential and no request at all reaches anything but the pinned
 * origin's own route, the address is never dialled, nothing fetched through the redirect is taken (the device holds
 * what it held, a sync is not a sync, no Trust Gate is shown), and the honest answer then works.
 */
class RedirectTest {
    private fun kept(h: Host): Map<String, String?> =
        h.state.keys()!!.associateWith { h.state.get(it) } + h.secure.keys()!!.associate { "secure:$it" to h.secure.get(it) }

    /** A listener on 127.0.0.2, an address no origin may name: it counts every connection made to it and closes it. */
    private class NeverDial : AutoCloseable {
        val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.2"))
        val dials = AtomicInteger()
        private val acceptor = thread(isDaemon = true, name = "never-dial") {
            while (!socket.isClosed) runCatching { socket.accept().use { dials.incrementAndGet() } }
        }
        val url: String get() = "http://127.0.0.2:${socket.localPort}"
        override fun close() = socket.close()
    }

    @Test fun aRedirectIsNeverFollowed_withACredentialOrWithout() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        assertEquals(null, a.putItem(a.personalVaultId!!, doc("kept")).second)
        a.synced()
        val elsewhere = proxy.dial("elsewhere")
        NeverDial().use { never ->
            val locations = listOf(
                "another path on the origin" to "/api/v1/redirected-here",
                "another host" to "$elsewhere/api/v1/sync",
                "another host name over plain http" to elsewhere.replace("127.0.0.1", "localhost") + "/api/v1/sync",
                "an address the device must never dial" to "${never.url}/api/v1/sync",
            )
            // Every way a redirect was followed, collected so that one run says what each kind did.
            val followed = ArrayList<String>()
            fun observe(what: String, tag: String, mark: Int, elsewhereBefore: Int, dialsBefore: Int) {
                proxy.requests(tag = tag, since = mark).filter { it.path == "/api/v1/redirected-here" }
                    .forEach { followed += "$what: followed on the origin, bearer=${it.bearer != null}" }
                proxy.requests(tag = "elsewhere").drop(elsewhereBefore)
                    .forEach { followed += "$what: reached another host (${it.header("Host")}), bearer=${it.bearer != null}" }
                if (never.dials.get() > dialsBefore) followed += "$what: dialled the never-dial address"
            }
            for ((where, location) in locations) {
                // With a credential: the sync and its bearer.
                run {
                    val what = "a sync redirected to $where"
                    val before = kept(ah)
                    val mark = proxy.mark()
                    val e0 = proxy.requests(tag = "elsewhere").size
                    val n0 = never.dials.get()
                    val rule = proxy.on(WireRoute.SYNC, "alice") { _ -> Resp(302, mapOf("Location" to location), ByteArray(0)) }
                    val outcome = a.sync()
                    rule.remove()
                    observe(what, "alice", mark, e0, n0)
                    assertTrue(outcome !is SyncOutcome.Synced, "$what: a redirect is not a sync: $outcome")
                    assertEquals(before, kept(ah), "$what: the device holds what it held")
                }
                // Without one: the card chain before the Trust Gate, and the client policy.
                run {
                    val tag = "d-" + where.replace(' ', '-')
                    val d = device(tag)
                    var mark = proxy.mark()
                    var e0 = proxy.requests(tag = "elsewhere").size
                    var n0 = never.dials.get()
                    val cards = proxy.on(WireRoute.INSTANCE, tag) { _ -> Resp(302, mapOf("Location" to location), ByteArray(0)) }
                    val gate = d.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS)
                    cards.remove()
                    observe("the card chain redirected to $where", tag, mark, e0, n0)
                    assertTrue(gate !is FirstPin.NeedsTrustGate && gate !is FirstPin.Pinned, "the card chain redirected to $where: no Trust Gate: $gate")
                    assertEquals(PinState.None, d.trust.pinState(origin), "the card chain redirected to $where: nothing is pinned")
                    mark = proxy.mark()
                    e0 = proxy.requests(tag = "elsewhere").size
                    n0 = never.dials.get()
                    val policy = proxy.on(WireRoute.CLIENT_POLICY, tag) { _ -> Resp(302, mapOf("Location" to location), ByteArray(0)) }
                    val r = d.client(origin).call(WireRoute.CLIENT_POLICY, decode = { it })
                    policy.remove()
                    observe("the policy redirected to $where", tag, mark, e0, n0)
                    assertTrue(r !is WireResult.Ok, "the policy redirected to $where is not an answer: $r")
                    assertTrue(d.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS) is FirstPin.NeedsTrustGate, "$where: the honest chain then shows the Trust Gate")
                }
            }
            assertEquals(emptyList<String>(), followed, "no redirect is followed")
        }
        a.synced()
    }
}
