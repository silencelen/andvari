package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.net.BellMessageTooLarge
import io.silencelen.andvari.core.client.net.BellOpenFailed
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLSocketFactory
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Six points about [AndroidBellSocket], in the style of
 * [AndroidBellSocketTest] (raw servers on loopback sockets), and the reviewer's hostile frames still behaving as before.
 */
class BellSocketNotesTest {
    private val cap = 64 * 1024
    private val ticket = "TiCkEtSeCrEt0123456789abcdef"
    private val headers = mapOf("X-Andvari-Client" to "android/0.29.1")

    private fun url(port: Int, host: String = "127.0.0.1", scheme: String = "ws") = "$scheme://$host:$port/api/v1/events?ticket=$ticket"

    private val normal = AndroidBellSocket.Timeouts(connectMs = 5_000, openMs = 5_000, readMs = 60_000, writeMs = 5_000)

    private fun bell(
        timeouts: AndroidBellSocket.Timeouts = normal,
        tls: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
        resolve: (String) -> List<InetAddress> = { InetAddress.getAllByName(it).toList() },
        proxies: (URI) -> List<Proxy> = { emptyList() },
    ) = AndroidBellSocket(tls, OkHttpClient().hostnameVerifier, { true }, timeouts, resolve = resolve, proxies = proxies)

    private fun <T> CompletableFuture<T>.within(s: Long = 10): T = get(s, TimeUnit.SECONDS)

    private fun elapsed(block: () -> Unit): Long {
        val t0 = System.nanoTime()
        block()
        return (System.nanoTime() - t0) / 1_000_000
    }

    private fun raw(p: WsTestServer.Peer, vararg b: Int) {
        p.out.write(ByteArray(b.size) { b[it].toByte() })
        p.out.flush()
    }

    // ---- 1. a message has a deadline of its own ----

    @Test
    fun aMessageHasADeadlineOfItsOwnSoATrickleCannotHoldTheReader() {
        val short = AndroidBellSocket.Timeouts(connectMs = 2_000, openMs = 3_000, readMs = 1_000, writeMs = 1_000, messageMs = 1_500)
        val trickles = listOf<(WsTestServer.Peer) -> Unit>(
            // One byte of a text frame inside every read timeout.
            { p -> p.header(true, 1, 200); repeat(40) { raw(p, 'x'.code); Thread.sleep(300) } },
            // Empty fragments, each inside the read timeout.
            { p -> p.frame(false, 1, ByteArray(0)); repeat(40) { p.frame(false, 0, ByteArray(0)); Thread.sleep(300) } },
            // A ping between a message's fragments, each inside the read timeout.
            { p -> p.frame(false, 1, "a".toByteArray()); repeat(40) { p.frame(true, 9, "k".toByteArray()); Thread.sleep(300) } },
            // A ping frame, one byte at a time.
            { p -> raw(p, 0x89, 50); repeat(40) { raw(p, 1); Thread.sleep(300) } },
        )
        for ((i, trickle) in trickles.withIndex()) {
            WsTestServer { p -> p.upgrade(); runCatching { trickle(p) } }.use { s ->
                var e: Throwable? = null
                val ms = elapsed { e = runCatching { runBlocking { bell(short).connect(url(s.port), headers, cap) { it.receive() } } }.exceptionOrNull() }
                assertEquals(BellOpenFailed.Reason.PAST_DEADLINE, assertIs<BellOpenFailed>(e, "case $i").reason, "case $i")
                assertTrue(ms in 1_300..4_500, "case $i ended by the message's deadline in $ms ms (it would have run 12 s)")
            }
        }
    }

    @Test
    fun pingsWithNoMessageUnderWayAreTheServersKeepAliveAndAMessageAfterThemArrives() {
        val short = AndroidBellSocket.Timeouts(connectMs = 2_000, openMs = 3_000, readMs = 1_000, writeMs = 1_000, messageMs = 1_500)
        WsTestServer { p ->
            p.upgrade()
            repeat(8) { p.frame(true, 9, "k".toByteArray()); Thread.sleep(300) }
            p.text("after the pings")
            p.endsWithin(5_000)
        }.use { s ->
            assertEquals("after the pings", runBlocking { bell(short).connect(url(s.port), headers, cap) { it.receive() } })
        }
    }

    // ---- 2. the name lookup is inside the opening's deadline and ends with a cancel ----

    @Test
    fun theNameLookupIsInsideTheOpeningsDeadlineAndACancelEndsIt() {
        val asked = CopyOnWriteArrayList<String>()
        val never: (String) -> List<InetAddress> = { h -> asked += h; Thread.sleep(60_000); emptyList() }
        val short = AndroidBellSocket.Timeouts(connectMs = 500, openMs = 1_000, readMs = 1_000, writeMs = 1_000)
        var e: IOException? = null
        val ms = elapsed { e = assertFailsWith<IOException> { runBlocking { bell(short, resolve = never).connect(url(1, "andvari.example", "wss"), headers, cap) { it.receive() } } } }
        assertTrue(ms < 2_500, "the opening's deadline ended the lookup in $ms ms")
        assertEquals("the server's name was not found in time", e?.message)
        assertEquals(listOf("andvari.example"), asked.toList())
        // A cancel ends the wait at once.
        runBlocking {
            val job = launch { runCatching { bell(resolve = never).connect(url(1, "andvari.example", "wss"), headers, cap) { it.receive() } } }
            delay(200)
            val t0 = System.nanoTime()
            job.cancelAndJoin()
            assertTrue((System.nanoTime() - t0) / 1_000_000 < 1_000, "the cancel ended the lookup")
        }
        // The address the lookup answers is the one dialled.
        WsTestServer { p -> p.upgrade(); p.text("looked up"); p.endsWithin(5_000) }.use { s ->
            val seen = CopyOnWriteArrayList<String>()
            val got = runBlocking { bell(resolve = { h -> seen += h; listOf(InetAddress.getLoopbackAddress()) }).connect(url(s.port, "localhost"), headers, cap) { it.receive() } }
            assertEquals("looked up", got)
            assertEquals(listOf("localhost"), seen.toList())
        }
        // A name not found fails as an IOException that names nothing.
        val notFound = assertFailsWith<IOException> {
            runBlocking { bell(resolve = { throw java.net.UnknownHostException(it) }).connect(url(1, "andvari.example", "wss"), headers, cap) { it.receive() } }
        }
        assertFalse(notFound.message.orEmpty().contains("andvari.example"))
    }

    // ---- 3. a length in a longer form than it needs is refused ----

    @Test
    fun aLengthWrittenInALongerFormThanItNeedsIsRefused() {
        val hello = "hello".map { it.code }.toIntArray()
        val longer = listOf<(WsTestServer.Peer) -> Unit>(
            { p -> raw(p, 0x81, 126, 0, 5, *hello) },
            { p -> raw(p, 0x81, 127, 0, 0, 0, 0, 0, 0, 0, 5, *hello) },
            { p -> raw(p, 0x81, 127, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF) },
            { p -> raw(p, 0x82, 126, 0, 125) },
            { p -> raw(p, 0x89, 126, 0, 4, 1, 2, 3, 4) },
        )
        for ((i, bad) in longer.withIndex()) {
            WsTestServer { p -> p.upgrade(); bad(p); p.endsWithin(5_000) }.use { s ->
                val e = assertFailsWith<IOException>("case $i") { runBlocking { bell().connect(url(s.port), headers, cap) { it.receive() } } }
                assertEquals(BellOpenFailed.Reason.PROTOCOL_ERROR, assertIs<BellOpenFailed>(e, "case $i").reason, "case $i")
            }
        }
        // The shortest forms still pass: 126 bytes in the two-byte form, a whole capped message in the eight-byte one.
        WsTestServer { p -> p.upgrade(); p.frame(true, 1, ByteArray(126) { 'a'.code.toByte() }); p.frame(true, 1, ByteArray(cap) { 'b'.code.toByte() }); p.endsWithin(5_000) }.use { s ->
            val got = runBlocking { bell().connect(url(s.port), headers, cap) { l -> listOf(l.receive()?.length, l.receive()?.length) } }
            assertEquals(listOf(126, cap), got)
        }
    }

    // ---- 4. every buffer that held a message's bytes is zeroed ----

    @Test
    fun theSkipBufferAControlPayloadTheRequestAndTheReadBufferAreZeroed() {
        val held = CopyOnWriteArrayList<ByteArray>()
        val streams = CopyOnWriteArrayList<ByteArray>()
        WsTestServer { p ->
            p.upgrade()
            p.frame(true, 2, ByteArray(5_000) { 7 })
            p.frame(true, 9, "ping-bytes".toByteArray())
            p.text("the message")
            p.clientFrame()
            p.endsWithin(5_000)
        }.use { s ->
            val b = bell().also {
                it.heldProbe = { buf -> held += buf }
                it.streamProbe = { buf -> streams += buf }
            }
            assertEquals("the message", runBlocking { b.connect(url(s.port), headers, cap) { it.receive() } })
        }
        assertTrue(held.any { it.size == 4096 }, "the skip buffer was made")
        assertTrue(held.any { it.size == "ping-bytes".length }, "the ping's payload")
        assertTrue(held.any { it.size > ticket.length + 100 }, "the request")
        assertTrue(held.all { buf -> buf.all { it == 0.toByte() } }, "every buffer of a message's bytes is zeroed")
        assertEquals(1, streams.size)
        assertTrue(streams.single().all { it == 0.toByte() }, "the read buffer is zeroed whole at the end")
        // The request is built as bytes, never in a string builder.
        val source = java.io.File("src/main/kotlin/io/silencelen/andvari/app/AndroidBellSocket.kt").readText()
        val open = source.substringAfter("private fun open(conn: Conn").substringBefore("private fun connectFirst(")
        assertFalse(open.contains("StringBuilder"))
    }

    // ---- 5. a system proxy: the HTTP client's path ----

    /** An HTTP proxy on loopback that opens a tunnel for CONNECT (or answers [status]) and records what it saw. */
    private class TestProxy(val status: Int = 200) : AutoCloseable {
        private val ss = ServerSocket(0, 8, InetAddress.getLoopbackAddress())
        val port: Int get() = ss.localPort
        val heads = CopyOnWriteArrayList<String>()
        val relayed = ByteArrayOutputStream()

        init {
            thread(isDaemon = true) {
                while (true) {
                    val c = try { ss.accept() } catch (_: IOException) { break }
                    thread(isDaemon = true) { serve(c) }
                }
            }
        }

        private fun serve(c: Socket) = runCatching {
            val input = c.getInputStream()
            val head = StringBuilder()
            while (!head.endsWith("\r\n\r\n")) head.append(input.read().takeIf { it >= 0 }?.toChar() ?: throw EOFException())
            heads += head.toString()
            if (status != 200) {
                c.getOutputStream().write("HTTP/1.1 $status No\r\nContent-Length: 0\r\n\r\n".toByteArray())
                c.close()
                return@runCatching
            }
            val port = Regex("CONNECT [^ ]+:(\\d+) ").find(head)!!.groupValues[1].toInt()
            val up = Socket(InetAddress.getLoopbackAddress(), port)
            c.getOutputStream().write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray())
            thread(isDaemon = true) { pipe(input, up.getOutputStream(), relayed) }
            pipe(up.getInputStream(), c.getOutputStream(), relayed)
        }

        private fun pipe(from: InputStream, to: OutputStream, seen: ByteArrayOutputStream) = runCatching {
            val b = ByteArray(4096)
            while (true) {
                val n = from.read(b)
                if (n < 0) break
                synchronized(seen) { seen.write(b, 0, n) }
                to.write(b, 0, n)
                to.flush()
            }
        }

        override fun close() = ss.close()
    }

    @Test
    fun aSystemHttpProxyIsAskedForATunnelAndTlsRunsEndToEndThroughIt() {
        WsTestServer(TestCerts.server(TestCerts.localhost)) { p -> p.upgrade(); p.text("through the tunnel"); p.endsWithin(5_000) }.use { s ->
            TestProxy().use { proxy ->
                val asked = CopyOnWriteArrayList<URI>()
                val via = bell(tls = TestCerts.trustBoth.socketFactory, proxies = { u -> asked += u; listOf(Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved("127.0.0.1", proxy.port))) })
                assertEquals("through the tunnel", runBlocking { via.connect(url(s.port, "localhost", "wss"), headers, cap) { it.receive() } })
                assertEquals(listOf(URI("https://localhost:${s.port}")), asked.toList(), "asked as the HTTP client asks")
                val head = proxy.heads.single()
                assertEquals("CONNECT localhost:${s.port} HTTP/1.1\r\nHost: localhost:${s.port}\r\n\r\n", head)
                assertFalse(synchronized(proxy.relayed) { proxy.relayed.toString(Charsets.ISO_8859_1) }.contains(ticket), "the ticket travels inside TLS only")
                assertEquals(1, s.handshakes.get(), "TLS with the server itself")
            }
        }
        // The host-name checks run through the tunnel exactly as without it.
        WsTestServer(TestCerts.server(TestCerts.other)) { p -> p.upgrade(); p.text("must not arrive") }.use { s ->
            TestProxy().use { proxy ->
                val via = bell(tls = TestCerts.trustBoth.socketFactory, proxies = { listOf(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxy.port))) })
                val e = assertFailsWith<BellOpenFailed> { runBlocking { via.connect(url(s.port, "localhost", "wss"), headers, cap) { it.receive() } } }
                assertEquals(BellOpenFailed.Reason.TLS_FAILED, e.reason)
            }
        }
    }

    @Test
    fun aProxyThatAsksForASignInOrASocksProxyOpensNothing() {
        WsTestServer(TestCerts.server(TestCerts.localhost)) { p -> p.upgrade(); p.text("must not arrive") }.use { s ->
            for (status in listOf(407, 403, 302)) {
                TestProxy(status).use { proxy ->
                    val via = bell(tls = TestCerts.trustBoth.socketFactory, proxies = { listOf(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxy.port))) })
                    assertFailsWith<IOException> { runBlocking { via.connect(url(s.port, "localhost", "wss"), headers, cap) { it.receive() } } }
                    assertEquals(1, proxy.heads.size)
                }
            }
            val socks = bell(tls = TestCerts.trustBoth.socketFactory, proxies = { listOf(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", s.port))) })
            assertFailsWith<IOException> { runBlocking { socks.connect(url(s.port, "localhost", "wss"), headers, cap) { it.receive() } } }
            assertEquals(0, s.accepted.get(), "nothing reached the server")
        }
    }

    @Test
    fun aDirectRouteAndAPlainLoopbackSocketConnectToTheServerItself() {
        WsTestServer(TestCerts.server(TestCerts.localhost)) { p -> p.upgrade(); p.text("direct"); p.endsWithin(5_000) }.use { s ->
            val direct = bell(tls = TestCerts.trustBoth.socketFactory, proxies = { listOf(Proxy.NO_PROXY) })
            assertEquals("direct", runBlocking { direct.connect(url(s.port, "localhost", "wss"), headers, cap) { it.receive() } })
        }
        // A plain socket (loopback only) never asks the proxy setting.
        WsTestServer { p -> p.upgrade(); p.text("plain"); p.endsWithin(5_000) }.use { s ->
            assertEquals("plain", runBlocking { bell(proxies = { error("a plain socket asked for a proxy") }).connect(url(s.port), headers, cap) { it.receive() } })
        }
        // The app's own socket asks the system's selector, as OkHttp does.
        val source = java.io.File("src/main/kotlin/io/silencelen/andvari/app/AndroidBellSocket.kt").readText()
        assertTrue(source.contains("internal fun systemProxies(uri: URI): List<Proxy> = ProxySelector.getDefault()?.select(uri).orEmpty()"))
        assertTrue(source.contains("private val proxies: (URI) -> List<Proxy> = ::systemProxies,"))
    }

    // ---- 6. every failure is the one exception type the contract names ----

    @Test
    fun everyFailureIsAnIOException() {
        val failures = listOf<() -> Unit>(
            { runBlocking { bell().connect("ws://127.0.0.1:70000/api/v1/events?ticket=$ticket", headers, cap) { it.receive() } } },
            { runBlocking { bell().connect("ws://127.0.0.1:0/api/v1/events?ticket=$ticket", headers, cap) { it.receive() } } },
            { runBlocking { bell(resolve = { throw IllegalStateException("$ticket") }).connect(url(1, "andvari.example", "wss"), headers, cap) { it.receive() } } },
            { runBlocking { bell(proxies = { throw IllegalArgumentException("$ticket") }).connect(url(1, "localhost", "wss"), headers, cap) { it.receive() } } },
            { runBlocking { bell(proxies = { listOf(Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved("proxy.invalid", 1))) }, resolve = { emptyList() }).connect(url(1, "localhost", "wss"), headers, cap) { it.receive() } } },
            {
                val refusing = object : SSLSocketFactory() {
                    val d = SSLSocketFactory.getDefault() as SSLSocketFactory
                    override fun getDefaultCipherSuites(): Array<String> = d.defaultCipherSuites
                    override fun getSupportedCipherSuites(): Array<String> = d.supportedCipherSuites
                    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket = throw IllegalArgumentException("$ticket")
                    override fun createSocket(host: String?, port: Int): Socket = throw UnsupportedOperationException()
                    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket = throw UnsupportedOperationException()
                    override fun createSocket(host: InetAddress?, port: Int): Socket = throw UnsupportedOperationException()
                    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket = throw UnsupportedOperationException()
                }
                WsTestServer { p -> p.head() }.use { s -> runBlocking { bell(tls = refusing).connect(url(s.port, "localhost", "wss"), headers, cap) { it.receive() } } }
            },
        )
        for ((i, f) in failures.withIndex()) {
            val e = runCatching { f() }.exceptionOrNull()
            assertIs<IOException>(e, "case $i: ${e?.javaClass}")
            var c: Throwable? = e
            while (c != null) {
                assertFalse(c.message.orEmpty().contains(ticket), "case $i quotes the ticket")
                c = c.cause
            }
        }
    }

    // ---- what must not change: the reviewer's hostile frames ----

    @Test
    fun theReviewersHostileFramesBehaveAsBefore() {
        fun len8(v: Long) = IntArray(8) { ((v ushr (8 * (7 - it))) and 0xFF).toInt() }
        val tooLarge = listOf<(WsTestServer.Peer) -> Unit>(
            { p -> raw(p, 0x81, 127, *len8(1L shl 31)) },
            { p -> raw(p, 0x81, 127, *len8((1L shl 32) + 2)) },
            { p -> raw(p, 0x81, 127, *len8(Long.MAX_VALUE)) },
            { p -> raw(p, 0x82, 127, *len8(1L shl 31)) },
            { p -> raw(p, 0x81, 127, *len8(cap + 1L)) },
            { p -> p.frame(false, 1, ByteArray(cap - 1)); p.header(true, 0, 2) },
            { p -> p.frame(false, 2, ByteArray(cap)); p.header(true, 0, 1) },
        )
        for ((i, bad) in tooLarge.withIndex()) {
            WsTestServer { p -> p.upgrade(); bad(p); p.endsWithin(5_000) }.use { s ->
                val ms = elapsed { assertFailsWith<BellMessageTooLarge>("too large $i") { runBlocking { bell().connect(url(s.port), headers, cap) { it.receive() } } } }
                assertTrue(ms < 3_000)
            }
        }
        val broken = listOf<(WsTestServer.Peer) -> Unit>(
            { p -> raw(p, 0x81, 127, 0x80, 0, 0, 0, 0, 0, 0, 0) }, // the top bit
            { p -> raw(p, 0x81, 127, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) },
            { p -> raw(p, 0xC1, 1, 'x'.code) }, // RSV1
            { p -> raw(p, 0xA1, 1, 'x'.code) }, // RSV2
            { p -> raw(p, 0x91, 1, 'x'.code) }, // RSV3
            { p -> raw(p, 0x81, 0x81, 1, 2, 3, 4, 5) }, // masked
        )
        for ((i, bad) in broken.withIndex()) {
            WsTestServer { p -> p.upgrade(); bad(p); p.endsWithin(5_000) }.use { s ->
                val e = assertFailsWith<IOException>("broken $i") { runBlocking { bell().connect(url(s.port), headers, cap) { it.receive() } } }
                assertEquals(BellOpenFailed.Reason.PROTOCOL_ERROR, assertIs<BellOpenFailed>(e).reason, "broken $i")
            }
        }
        // A close in the middle of a message: the server's close, answered null as before.
        WsTestServer { p -> p.upgrade(); p.frame(false, 1, "half".toByteArray()); p.frame(true, 8, byteArrayOf(0x03, 0xE8.toByte())); p.endsWithin(5_000) }.use { s ->
            assertNull(runBlocking { bell().connect(url(s.port), headers, cap) { it.receive() } })
        }
        assertEquals(14, tooLarge.size + broken.size + 1)
    }

    @Test
    fun aRefusedConnectionIsAPlainIOExceptionAfterOneLookup() {
        // The dialer's view: a refused connection is still a plain IOException from the opening, never a hang.
        val counted = AtomicInteger()
        val e = runCatching { runBlocking { bell(resolve = { counted.incrementAndGet(); listOf(InetAddress.getLoopbackAddress()) }).connect(url(1), headers, cap) { it.receive() } } }.exceptionOrNull()
        assertIs<IOException>(e)
        assertEquals(1, counted.get())
    }
}
