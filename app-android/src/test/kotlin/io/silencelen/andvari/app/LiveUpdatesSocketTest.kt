package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.BellFailure
import io.silencelen.andvari.core.client.net.DialedBellSocket
import io.silencelen.andvari.core.client.net.Dialer
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinStore
import kotlinx.coroutines.runBlocking
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Live updates as the app now opens them. This replaces the earlier `BellOnOkHttpTest`, which
 * pinned that the bell never opened on OkHttp (and that OkHttp would have held a message of any size): the bell no
 * longer goes through OkHttp at all. The shared code's dialer, with the app's [AndroidBellSocket] as its platform socket
 * (as `TrustSeam` builds it), opens the socket to a pinned origin: an honest message arrives, and a message over the
 * limit ends the socket and is recorded as TOO_LARGE.
 */
class LiveUpdatesSocketTest {
    private val cap = 64 * 1024
    private val ticket = "TiCkEtSeCrEt0123456789abcdef"

    /** The dialer as TrustSeam builds it, its pin store holding a pin in force for [origin]. */
    private fun socketFor(origin: String): DialedBellSocket {
        val state = MemoryDeviceState().also {
            PinStore(it).put(
                CardPin("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", 1, "a".repeat(64), origin, "Home", "private",
                    "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f", "A".repeat(43), "none", PinRoot.TRUST_GATE, null, "b".repeat(64)),
            )
        }
        val bell = AndroidBellSocket(
            tls = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory,
            hostNames = okhttp3.OkHttpClient().hostnameVerifier,
            cleartextPermitted = { true },
        )
        return Dialer(PinStore(state), androidHttpClient(), "android", bell).bellSocket(origin)
    }

    @Test
    fun anHonestMessageArrives() {
        val head = CompletableFuture<String>()
        val ping = CompletableFuture<String>()
        WsTestServer { p ->
            head.complete(p.upgrade())
            ping.complete(p.clientFrame().payload.decodeToString())
            p.text("pong")
            p.text("""{"type":"rev","rev":7}""")
            p.endsWithin(5_000)
        }.use { s ->
            val origin = "http://127.0.0.1:${s.port}"
            val socket = socketFor(origin)
            val got = runBlocking {
                socket.open(origin, ticket) { link ->
                    assertTrue(socket.connected.value)
                    listOf(link.send("""{"type":"ping"}""").toString(), link.receive(), link.receive())
                }
            }
            assertEquals(listOf("true", "pong", """{"type":"rev","rev":7}"""), got)
            assertEquals("""{"type":"ping"}""", ping.get(10, TimeUnit.SECONDS))
            val h = head.get(10, TimeUnit.SECONDS)
            assertTrue(h.startsWith("GET /api/v1/events?ticket=$ticket HTTP/1.1\r\n"), h)
            assertTrue(Regex("(?m)^X-Andvari-Client: android/").containsMatchIn(h), h)
            assertNull(socket.failure.value)
            assertFalse(socket.connected.value)
        }
    }

    @Test
    fun aMessageOverTheLimitEndsTheSocket() {
        val ended = CompletableFuture<Boolean>()
        WsTestServer { p ->
            p.upgrade()
            p.text("pong")
            p.header(true, 1, cap + 1L)
            ended.complete(p.endsWithin(5_000))
        }.use { s ->
            val origin = "http://127.0.0.1:${s.port}"
            val socket = socketFor(origin)
            val got = runBlocking { socket.open(origin, ticket) { link -> listOf(link.receive(), link.receive(), link.send("x").toString()) } }
            assertEquals(listOf("pong", null, "false"), got)
            assertEquals(BellFailure.Kind.TOO_LARGE, socket.failure.value?.kind)
            assertTrue(ended.get(10, TimeUnit.SECONDS), "the socket was ended")
        }
    }

    @Test
    fun aRefusedUpgradeIsAVisibleFailureThatNamesNoTicket() {
        WsTestServer { p ->
            p.head()
            p.write("HTTP/1.1 301 Moved Permanently\r\nLocation: ws://127.0.0.1:1/\r\n\r\n")
            p.endsWithin(5_000)
        }.use { s ->
            val origin = "http://127.0.0.1:${s.port}"
            val socket = socketFor(origin)
            assertNull(runBlocking { socket.open(origin, ticket) { "opened" } })
            val failure = socket.failure.value!!
            assertEquals(BellFailure.Kind.NOT_OPENED, failure.kind)
            assertFalse(failure.detail.contains(ticket), failure.detail)
        }
    }

    @Test
    fun theAppGivesTheDialerItsOwnSocket() {
        val seam = File("src/main/kotlin/io/silencelen/andvari/app/trust/TrustSeam.kt").readText()
        assertTrue(seam.contains("val bellSocket = AndroidBellSocket.forApp()"))
        assertTrue(seam.contains("Dialer(PinStore(state), http, AppPlatform.ANDROID.wireName, bellSocket = bellSocket)"))
        assertEquals(1, Regex("""\bDialer\(""").findAll(seam).count(), "the one dialer the app builds")
    }
}
