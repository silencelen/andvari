package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.Dialer
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The word a write's request gets over the network library this app ships (OkHttp, through the shared code's dialer as
 * the app opens it): "may have arrived" for a request that left, never "not sent". OkHttp sends a written request again
 * on a new connection when a kept connection drops, and where that second connection cannot be made it reports the
 * second failure with the first, sent attempt attached; the shared code then reads "may have left". The library's second
 * try stays on (it keeps a request alive over a connection the server closed). Over a server on this machine that
 * answers as told.
 */
class SentRequestWordOverOkHttpTest {
    private val body = """{"mutations":[]}"""

    private fun pinned(origin: String) = MemoryDeviceState().also {
        PinStore(it).put(
            CardPin("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", 1, "a".repeat(64), origin, "Home", "private",
                "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f", "A".repeat(43), "none", PinRoot.TRUST_GATE, null, "b".repeat(64)),
        )
    }

    /** One request read whole from [input]: its head and its body, by its Content-Length; null at the end of the stream. */
    private fun readRequest(input: InputStream): String? {
        val head = ByteArrayOutputStream()
        var tail = 0
        while (tail != 0x0d0a0d0a) {
            val b = input.read()
            if (b < 0) return null
            head.write(b)
            tail = (tail shl 8) or b
        }
        val text = head.toString(Charsets.ISO_8859_1.name())
        val length = Regex("(?im)^content-length:\\s*(\\d+)").find(text)?.groupValues?.get(1)?.toInt() ?: 0
        val got = ByteArray(length)
        var n = 0
        while (n < length) {
            val r = input.read(got, n, length - n)
            if (r < 0) return null
            n += r
        }
        return text + String(got, Charsets.UTF_8)
    }

    /**
     * The check's sequence: the first request is answered on a connection kept open; the second is read whole on that same
     * connection (the server took it), then the server goes (nothing listens any more) and the connection drops without an
     * answer. The library's second try finds no server.
     */
    @Test
    fun aRequestTheServerTookWholeOnAKeptConnectionThatDropsIsMayHaveArrivedWhenTheSecondTryFindsNoServer() {
        val listener = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val origin = "http://127.0.0.1:${listener.localPort}"
        // Which connection each request came on, and whether it was read whole (the server took it).
        val taken = CopyOnWriteArrayList<Pair<Int, String>>()
        val connections = CopyOnWriteArrayList<Socket>()
        val server = thread(isDaemon = true) {
            runCatching {
                while (true) {
                    val conn = listener.accept()
                    conn.soTimeout = 10_000
                    connections += conn
                    val index = connections.size
                    thread(isDaemon = true) {
                        runCatching {
                            val input = conn.getInputStream()
                            val out = conn.getOutputStream()
                            while (true) {
                                val request = readRequest(input) ?: break
                                taken += index to request
                                if (taken.size == 1) {
                                    out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".toByteArray())
                                    out.flush()
                                } else {
                                    // Taken whole; the server goes before the connection drops, so a second try finds nothing.
                                    listener.close()
                                    conn.close()
                                    break
                                }
                            }
                        }
                    }
                }
            }
        }
        val client = Dialer(PinStore(pinned(origin)), androidHttpClient(), "android").open(origin, null)
        try {
            val first = runBlocking { client.call(WireRoute.PUSH, emptyMap(), null, body, false) { it } }
            assertIs<WireResult.Ok<String>>(first, "the first request is answered, and its connection is kept")
            val second = runBlocking { client.call(WireRoute.PUSH, emptyMap(), null, body, false) { it } }

            assertEquals(2, taken.size, "the server read both requests")
            assertEquals(listOf(1, 1), taken.map { it.first }, "both on the one kept connection")
            assertTrue(taken[1].second.endsWith(body), "the second was taken whole, its body included")
            val none = assertIs<WireResult.NoAnswer>(second, "no answer came")
            assertEquals(NoAnswerKind.TRANSPORT, none.kind)
            assertEquals(false, none.neverLeft, "a request the server took is \"may have arrived\", never \"not sent\"")
        } finally {
            runCatching { listener.close() }
            connections.forEach { runCatching { it.close() } }
            server.join(5_000)
        }
    }

    /**
     * The other side of the same word, so that the test above tells the two apart: where no connection is ever made (nothing
     * listens at the address), the request never left and is "not sent". This guards the direction only: it passed before
     * the fix too.
     */
    @Test
    fun aRequestWhoseConnectionIsNeverMadeIsNotSent() {
        val listener = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val origin = "http://127.0.0.1:${listener.localPort}"
        listener.close()
        val client = Dialer(PinStore(pinned(origin)), androidHttpClient(), "android").open(origin, null)
        val r = runBlocking { client.call(WireRoute.PUSH, emptyMap(), null, body, false) { it } }
        val none = assertIs<WireResult.NoAnswer>(r)
        assertEquals(true, none.neverLeft, "nothing left this device")
    }
}
