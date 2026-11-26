package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.net.BellMessageTooLarge
import io.silencelen.andvari.core.client.net.BellOpenFailed
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import java.io.File
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocketFactory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [AndroidBellSocket] against raw servers on loopback sockets, one test per point of the
 * `PlatformBellSocket` contract. Everything here runs on the JVM over the JDK's sockets and TLS; what
 * only a phone confirms is the handshake and host-name check of Android's own TLS stack (Conscrypt) and its network
 * security config.
 */
class AndroidBellSocketTest {
    private val cap = 64 * 1024
    private val ticket = "TiCkEtSeCrEt0123456789abcdef"
    private val headers = mapOf("X-Andvari-Client" to "android/0.29.1")

    private fun url(port: Int, host: String = "127.0.0.1", scheme: String = "ws") = "$scheme://$host:$port/api/v1/events?ticket=$ticket"

    private fun bell(
        timeouts: AndroidBellSocket.Timeouts = AndroidBellSocket.Timeouts(connectMs = 5_000, openMs = 5_000, readMs = 60_000, writeMs = 5_000),
        tls: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
        hostNames: HostnameVerifier = OkHttpClient().hostnameVerifier,
        cleartext: (String) -> Boolean = { true },
    ) = AndroidBellSocket(tls, hostNames, cleartext, timeouts)

    private fun <T> CompletableFuture<T>.within(s: Long = 10): T = get(s, TimeUnit.SECONDS)

    private fun elapsed(block: () -> Unit): Long {
        val t0 = System.nanoTime()
        block()
        return (System.nanoTime() - t0) / 1_000_000
    }

    // 1. Exactly the address and every header; an honest message arrives (whole, fragmented, with a ping between its
    //    fragments, at exactly the cap), and a binary message is skipped.
    @Test
    fun anHonestMessageArrivesAndTheUpgradeIsExactlyTheAddressWithEveryHeader() {
        val head = CompletableFuture<String>()
        val pong = CompletableFuture<WsTestServer.ClientFrame>()
        WsTestServer { p ->
            head.complete(p.upgrade())
            p.text("""{"type":"rev","rev":1}""")
            p.frame(false, 1, "frag-".toByteArray())
            p.frame(true, 9, "hi".toByteArray())
            p.frame(false, 0, "ment".toByteArray())
            p.frame(true, 0, "ed".toByteArray())
            p.frame(true, 2, ByteArray(1000) { 7 })
            p.frame(true, 1, ByteArray(cap) { 'x'.code.toByte() })
            pong.complete(p.clientFrame())
            p.endsWithin(10_000)
        }.use { s ->
            val got = runBlocking { bell().connect(url(s.port), headers, cap) { l -> listOf(l.receive(), l.receive(), l.receive()?.length) } }
            assertEquals(listOf("""{"type":"rev","rev":1}""", "frag-mented", cap), got)
            val h = head.within()
            assertTrue(h.startsWith("GET /api/v1/events?ticket=$ticket HTTP/1.1\r\n"), h)
            for (line in listOf("Host: 127.0.0.1:${s.port}", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Version: 13", "X-Andvari-Client: android/0.29.1")) {
                assertTrue(h.contains("\r\n$line\r\n"), "$line in $h")
            }
            val f = pong.within()
            assertEquals(0xA, f.op, "a ping is answered with a pong")
            assertTrue(f.masked)
            assertContentEquals("hi".toByteArray(), f.payload)
        }
    }

    // 2. A fresh random key every time, and the answer must prove it.
    @Test
    fun everyUpgradeSendsAFreshRandomKey() {
        val keys = CopyOnWriteArrayList<String>()
        WsTestServer { p ->
            keys += WsTestServer.key(p.upgrade())
            p.text("ok")
            p.endsWithin(10_000)
        }.use { s ->
            repeat(3) { assertEquals("ok", runBlocking { bell().connect(url(s.port), headers, cap) { it.receive() } }) }
        }
        assertEquals(3, keys.toSet().size, keys.toString())
        keys.forEach { assertEquals(16, Base64.getDecoder().decode(it).size) }
    }

    @Test
    fun anUpgradeIsRefusedUnless101WithTheRightAccept() {
        val wrong = listOf<(String) -> String>(
            { k -> "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${WsTestServer.accept(k + "x")}\r\n\r\n" },
            { _ -> "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" },
            { k -> "HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${WsTestServer.accept(k)}\r\n\r\n" },
            { k -> "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${WsTestServer.accept(k)}\r\n\r\n" },
            { k -> "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ${WsTestServer.accept(k)}\r\n\r\n" },
            { k -> "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${WsTestServer.accept(k)}\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n" },
            { k -> "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${WsTestServer.accept(k)}\r\nSec-WebSocket-Accept: ${WsTestServer.accept(k)}\r\n\r\n" },
        )
        for ((i, answer) in wrong.withIndex()) {
            WsTestServer { p ->
                p.write(answer(WsTestServer.key(p.head())))
                p.text("should never be read")
                p.endsWithin(10_000)
            }.use { s ->
                val ran = AtomicBoolean(false)
                val e = assertFailsWith<IOException>("answer $i") { runBlocking { bell().connect(url(s.port), headers, cap) { ran.set(true) } } }
                assertFalse(ran.get(), "answer $i: no block runs over a refused upgrade")
                assertFalse(e.message.orEmpty().contains(ticket))
            }
        }
    }

    @Test
    fun noRedirectIsFollowed() {
        WsTestServer { p -> p.upgrade(); p.text("elsewhere") }.use { elsewhere ->
            for (status in listOf("301 Moved Permanently", "302 Found", "303 See Other", "307 Temporary Redirect", "308 Permanent Redirect")) {
                WsTestServer { p ->
                    p.head()
                    p.write("HTTP/1.1 $status\r\nLocation: ${url(elsewhere.port)}\r\nContent-Length: 0\r\n\r\n")
                    p.endsWithin(10_000)
                }.use { s ->
                    val e = assertFailsWith<IOException>(status) { runBlocking { bell().connect(url(s.port), headers, cap) { it.receive() } } }
                    assertTrue(e.message!!.contains(status.take(3)), e.message)
                }
            }
            assertEquals(0, elsewhere.accepted.get(), "nothing was dialled where a redirect pointed")
        }
    }

    // 5. The bound, from the frame header alone.
    @Test
    fun aFrameHeaderThatDeclaresMoreThanTheCapEndsTheSocketWithoutReadingTheBody() {
        for ((op, declared) in listOf(1 to cap + 1L, 1 to (1L shl 40), 2 to cap + 1L)) {
            val ended = CompletableFuture<Boolean>()
            WsTestServer { p ->
                p.upgrade()
                // The header only: the body never comes, so a reader that waited for it would hang until the read timeout.
                p.header(true, op, declared)
                ended.complete(p.endsWithin(5_000))
            }.use { s ->
                val ms = elapsed {
                    assertFailsWith<BellMessageTooLarge>("op $op, $declared") { runBlocking { bell().connect(url(s.port), headers, cap) { it.receive() } } }
                }
                assertTrue(ms < 3_000, "ended from the header in $ms ms (read timeout 60 s)")
                assertTrue(ended.within(), "the socket was ended")
            }
        }
    }

    @Test
    fun fragmentsAreCountedTogetherAndEveryByteHeldIsZeroed() {
        val held = CopyOnWriteArrayList<ByteArray>()
        WsTestServer { p ->
            p.upgrade()
            // An honest fragmented message first: its buffers are zeroed once it is handed up.
            p.frame(false, 1, ByteArray(3000) { 'a'.code.toByte() })
            p.frame(true, 0, ByteArray(3000) { 'b'.code.toByte() })
            // Then fragments that add up to one byte more than the cap: the last header ends it, its body never read.
            p.frame(false, 1, ByteArray(cap - 10) { 'c'.code.toByte() })
            p.frame(false, 0, ByteArray(5) { 'd'.code.toByte() })
            p.header(true, 0, 6)
            p.endsWithin(5_000)
        }.use { s ->
            val b = bell().also { it.heldProbe = { buf -> held += buf } }
            runBlocking {
                b.connect(url(s.port), headers, cap) { l ->
                    assertEquals("a".repeat(3000) + "b".repeat(3000), l.receive())
                    assertTrue(held.isNotEmpty() && held.all { buf -> buf.all { it == 0.toByte() } }, "zeroed after an honest message")
                    held.clear()
                    assertFailsWith<BellMessageTooLarge> { l.receive() }
                    assertNull(l.receive(), "the socket is ended")
                    assertFalse(l.send("x"))
                }
            }
            assertTrue(held.isNotEmpty())
            assertTrue(held.all { buf -> buf.all { it == 0.toByte() } }, "every buffer that held the refused message is zeroed")
            assertTrue(held.all { it.size <= cap }, "nothing larger than the cap was ever made")
        }
    }

    // 6. Control frames.
    @Test
    fun controlFramesAreAtMost125BytesAndUnfragmented() {
        for (bad in listOf<(WsTestServer.Peer) -> Unit>(
            { p -> p.frame(true, 9, ByteArray(126)) },
            { p -> p.frame(true, 10, ByteArray(126)) },
            { p -> p.frame(false, 9, ByteArray(4)) },
        )) {
            WsTestServer { p ->
                p.upgrade()
                bad(p)
                p.text("after")
                p.endsWithin(5_000)
            }.use { s ->
                // A protocol failure (an IOException), not the cap's BellMessageTooLarge.
                assertFailsWith<IOException> { runBlocking { bell().connect(url(s.port), headers, cap) { it.receive() } } }
            }
        }
        // 125 is allowed, and the pong carries the ping's bytes.
        val pong = CompletableFuture<WsTestServer.ClientFrame>()
        WsTestServer { p ->
            p.upgrade()
            p.frame(true, 9, ByteArray(125) { it.toByte() })
            p.text("after")
            pong.complete(p.clientFrame())
            p.endsWithin(5_000)
        }.use { s ->
            assertEquals("after", runBlocking { bell().connect(url(s.port), headers, cap) { it.receive() } })
            assertContentEquals(ByteArray(125) { it.toByte() }, pong.within().payload)
        }
    }

    @Test
    fun aServerFrameThatBreaksTheFramingEndsTheSocket() {
        for (bad in listOf<(WsTestServer.Peer) -> Unit>(
            { p -> p.out.write(byteArrayOf(0x81.toByte(), (0x80 or 2).toByte(), 1, 2, 3, 4, 5, 6)); p.out.flush() }, // masked
            { p -> p.out.write(byteArrayOf(0xC1.toByte(), 2, 'h'.code.toByte(), 'i'.code.toByte())); p.out.flush() }, // RSV1
            { p -> p.frame(true, 0, "x".toByteArray()) }, // continuation with no message
            { p -> p.frame(false, 1, "x".toByteArray()); p.frame(true, 1, "y".toByteArray()) }, // new message inside one
            { p -> p.frame(true, 3, "x".toByteArray()) }, // unknown opcode
            { p -> p.frame(true, 1, byteArrayOf(0xC3.toByte(), 0x28)) }, // not UTF-8
        )) {
            WsTestServer { p ->
                p.upgrade()
                bad(p)
                p.endsWithin(5_000)
            }.use { s ->
                assertFailsWith<IOException> { runBlocking { bell().connect(url(s.port), headers, cap) { it.receive() } } }
            }
        }
    }

    // 8. Client frames are masked, each with a fresh random mask, at every length encoding.
    @Test
    fun clientFramesAreMaskedWithFreshRandomMasks() {
        val texts = listOf("""{"type":"ping"}""", "y".repeat(200), "z".repeat(70_000), """{"type":"ping"}""")
        val frames = CompletableFuture<List<WsTestServer.ClientFrame>>()
        WsTestServer { p ->
            p.upgrade()
            frames.complete(texts.map { p.clientFrame() })
            p.endsWithin(5_000)
        }.use { s ->
            val sent = runBlocking { bell().connect(url(s.port), headers, cap) { l -> texts.map { l.send(it) } } }
            assertEquals(List(texts.size) { true }, sent)
            val got = frames.within()
            assertEquals(texts, got.map { it.payload.decodeToString() })
            assertTrue(got.all { it.masked && it.fin && it.op == 1 })
            assertEquals(texts.size, got.map { it.mask.toList() }.toSet().size, "a fresh mask for every frame")
        }
    }

    // 4 and 7. Closed at once when the block returns; the server's close answers null; send answers false once gone.
    @Test
    fun theBlocksEndClosesAtOnceWithACloseFrameAndWaitsForNoReply() {
        val close = CompletableFuture<WsTestServer.ClientFrame>()
        val ended = CompletableFuture<Boolean>()
        WsTestServer { p ->
            p.upgrade()
            close.complete(p.clientFrame())
            ended.complete(p.endsWithin(5_000))
            Thread.sleep(10_000) // never answers the close
        }.use { s ->
            val ms = elapsed { assertEquals("done", runBlocking { bell().connect(url(s.port), headers, cap) { "done" } }) }
            assertTrue(ms < 3_000, "no wait for the server's close: $ms ms")
            val f = close.within()
            assertEquals(8, f.op)
            assertTrue(f.masked)
            assertTrue(ended.within())
        }
        // A block that throws: the socket is closed the same way and the exception comes through.
        WsTestServer { p -> p.upgrade(); p.endsWithin(5_000) }.use { s ->
            assertFailsWith<IllegalStateException> { runBlocking { bell().connect(url(s.port), headers, cap) { error("the bell's own failure") } } }
        }
    }

    @Test
    fun theServersCloseAnswersNullAndSendThenAnswersFalse() {
        val reply = CompletableFuture<WsTestServer.ClientFrame>()
        WsTestServer { p ->
            p.upgrade()
            p.frame(true, 8, byteArrayOf(0x03, 0xE8.toByte()))
            reply.complete(p.clientFrame())
            p.endsWithin(5_000)
        }.use { s ->
            val got = runBlocking { bell().connect(url(s.port), headers, cap) { l -> listOf(l.receive(), l.send("x").toString(), l.receive()) } }
            assertEquals(listOf(null, "false", null), got)
            assertEquals(8, reply.within().op, "the close is answered with a close")
        }
        // A connection dropped between frames reads as closed, too.
        WsTestServer { p -> p.upgrade(); p.text("one") }.use { s ->
            val got = runBlocking { bell().connect(url(s.port), headers, cap) { l -> listOf(l.receive(), l.receive(), l.send("x").toString()) } }
            assertEquals(listOf("one", null, "false"), got)
        }
    }

    // Timeouts: a server that accepts and then says nothing cannot hold a thread for ever.
    @Test
    fun aServerThatSaysNothingCannotHoldTheThread() {
        val short = AndroidBellSocket.Timeouts(connectMs = 500, openMs = 1_500, readMs = 700, writeMs = 1_000)
        // Accepts the connection and never answers the upgrade.
        WsTestServer { p -> p.head(); Thread.sleep(10_000) }.use { s ->
            val ms = elapsed { assertFailsWith<IOException> { runBlocking { bell(short).connect(url(s.port), headers, cap) { it.receive() } } } }
            assertTrue(ms < 3_000, "silent upgrade: $ms ms")
        }
        // Dribbles a correct answer one byte at a time, each inside the read timeout: the opening deadline ends it.
        WsTestServer { p ->
            val answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${WsTestServer.accept(WsTestServer.key(p.head()))}\r\n\r\n"
            for (c in answer) {
                p.write(c.toString())
                Thread.sleep(300)
            }
        }.use { s ->
            var e: IOException? = null
            val ms = elapsed { e = assertFailsWith<IOException> { runBlocking { bell(short).connect(url(s.port), headers, cap) { it.receive() } } } }
            assertTrue(ms in 1_200..4_000, "dribbled upgrade: $ms ms")
            assertEquals("the server did not open the socket in time", e?.message)
        }
        // Opens, then says nothing: the read timeout ends the socket.
        val ended = CompletableFuture<Boolean>()
        WsTestServer { p -> p.upgrade(); ended.complete(p.endsWithin(5_000)) }.use { s ->
            val ms = elapsed {
                val e = assertFailsWith<BellOpenFailed> { runBlocking { bell(short).connect(url(s.port), headers, cap) { it.receive() } } }
                assertEquals(BellOpenFailed.Reason.PAST_DEADLINE, e.reason)
            }
            assertTrue(ms < 3_000, "silent socket: $ms ms")
            assertTrue(ended.within())
        }
        // TLS: accepts the TCP connection and never says a word of the handshake.
        WsTestServer { p -> p.socket.soTimeout = 10_000; runCatching { p.input.read() }; Thread.sleep(10_000) }.use { s ->
            val tls = TestCerts.trustBoth.socketFactory
            val ms = elapsed { assertFailsWith<IOException> { runBlocking { bell(short, tls = tls).connect(url(s.port, "localhost", "wss"), headers, cap) { it.receive() } } } }
            assertTrue(ms < 3_000, "silent handshake: $ms ms")
        }
    }

    @Test
    fun aCancelledWaitClosesTheSocketAtOnce() {
        val ended = CompletableFuture<Boolean>()
        WsTestServer { p -> p.upgrade(); ended.complete(p.endsWithin(5_000)) }.use { s ->
            runBlocking {
                val opened = CompletableFuture<Unit>()
                val job = launch { bell().connect(url(s.port), headers, cap) { l -> opened.complete(Unit); l.receive() } }
                while (!opened.isDone) delay(20)
                delay(200)
                val t0 = System.nanoTime()
                job.cancelAndJoin()
                val ms = (System.nanoTime() - t0) / 1_000_000
                assertTrue(ms < 1_000, "the cancelled wait ended in $ms ms (read timeout 60 s)")
            }
            assertTrue(ended.within(), "the server saw the socket end")
        }
    }

    // TLS: the host name is verified.
    @Test
    fun aCertificateForTheHostOpensOverTls() {
        WsTestServer(TestCerts.server(TestCerts.localhost)) { p -> p.upgrade(); p.text("over tls"); p.endsWithin(5_000) }.use { s ->
            val got = runBlocking { bell(tls = TestCerts.trustBoth.socketFactory).connect(url(s.port, "localhost", "wss"), headers, cap) { it.receive() } }
            assertEquals("over tls", got)
        }
    }

    @Test
    fun theHostNameIsCheckedByThePlatformInTheHandshakeEvenWhenNothingElseChecksIt() {
        // A certificate the trust accepts, for another name; the host-name check after the handshake waved through.
        WsTestServer(TestCerts.server(TestCerts.other)) { p -> p.upgrade(); p.text("must not arrive") }.use { s ->
            val ran = AtomicBoolean(false)
            val e = assertFailsWith<BellOpenFailed> {
                runBlocking { bell(tls = TestCerts.trustBoth.socketFactory, hostNames = { _, _ -> true }).connect(url(s.port, "localhost", "wss"), headers, cap) { ran.set(true) } }
            }
            assertEquals(BellOpenFailed.Reason.TLS_FAILED, e.reason)
            assertFalse(ran.get())
            assertEquals(0, s.handshakes.get())
        }
    }

    @Test
    fun theHostNameIsCheckedAgainAfterTheHandshakeWhenThePlatformOnlySaysItChecked() {
        WsTestServer(TestCerts.server(TestCerts.other)) { p -> p.upgrade(); p.text("must not arrive") }.use { s ->
            val ran = AtomicBoolean(false)
            val lying = ShamSslFactory(TestCerts.trustBoth.socketFactory, ShamSslFactory.Mode.LIES)
            assertEquals(BellOpenFailed.Reason.TLS_FAILED, assertFailsWith<BellOpenFailed> { runBlocking { bell(tls = lying).connect(url(s.port, "localhost", "wss"), headers, cap) { ran.set(true) } } }.reason)
            assertFalse(ran.get())
            val until = System.currentTimeMillis() + 5_000
            while (s.handshakes.get() == 0 && System.currentTimeMillis() < until) Thread.sleep(20)
            assertEquals(1, s.handshakes.get(), "the platform's handshake let it through; OkHttp's check after it did not")
        }
    }

    @Test
    fun theOpenFailsClosedWhenThePlatformWillNotCheckTheHostName() {
        WsTestServer(TestCerts.server(TestCerts.localhost)) { p -> p.upgrade(); p.text("must not arrive") }.use { s ->
            val dropping = ShamSslFactory(TestCerts.trustBoth.socketFactory, ShamSslFactory.Mode.DROPS)
            val e = assertFailsWith<IOException> { runBlocking { bell(tls = dropping).connect(url(s.port, "localhost", "wss"), headers, cap) { "opened" } } }
            assertEquals("the platform would not check the server's host name", e.message)
            assertEquals(0, s.handshakes.get(), "no handshake was even started")
        }
    }

    @Test
    fun theAppsTrustIsThePlatformsNoMore() {
        // The app's own socket (OkHttp's trust, as the HTTP client's): a self-signed certificate, for the right name, is refused.
        WsTestServer(TestCerts.server(TestCerts.localhost)) { p -> p.upgrade(); p.text("must not arrive") }.use { s ->
            assertEquals(BellOpenFailed.Reason.TLS_FAILED, assertFailsWith<BellOpenFailed> { runBlocking { AndroidBellSocket.forApp().connect(url(s.port, "localhost", "wss"), headers, cap) { it.receive() } } }.reason)
            assertEquals(0, s.handshakes.get())
        }
    }

    @Test
    fun aPlainSocketOpensOnlyToLoopbackTheNetworkConfigPermits() {
        WsTestServer { p -> p.upgrade(); p.text("x") }.use { s ->
            assertFailsWith<IOException> { runBlocking { bell(cleartext = { false }).connect(url(s.port), headers, cap) { it.receive() } } }
            assertFailsWith<IOException> { runBlocking { bell().connect("ws://example.com:${s.port}/api/v1/events?ticket=$ticket", headers, cap) { it.receive() } } }
            assertFailsWith<IOException> { runBlocking { bell().connect("http://127.0.0.1:${s.port}/api/v1/events?ticket=$ticket", headers, cap) { it.receive() } } }
            assertEquals(0, s.accepted.get())
        }
    }

    @Test
    fun aHeaderThatCouldSplitTheRequestIsRefusedBeforeAnythingIsSent() {
        WsTestServer { p -> p.upgrade(); p.text("x") }.use { s ->
            for (bad in listOf(mapOf("X-A" to "v\r\nEvil: 1"), mapOf("X-A\r\nEvil" to "1"), mapOf("Host" to "elsewhere"), mapOf("Sec-WebSocket-Key" to "x"))) {
                val e = assertFailsWith<IOException> { runBlocking { bell().connect(url(s.port), bad, cap) { it.receive() } } }
                assertFalse(e.message.orEmpty().contains("Evil"))
            }
            assertEquals(0, s.accepted.get())
        }
    }

    // Nothing of the ticket or of a message is ever logged, or carried in a failure's message.
    @Test
    fun nothingOfTheTicketOrAMessageIsLoggedOrCarriedInAFailure() {
        val source = File("src/main/kotlin/io/silencelen/andvari/app/AndroidBellSocket.kt").readText()
        for (logging in listOf("Log.", "println", "printStackTrace", "System.out", "System.err", "Timber")) {
            assertFalse(source.contains(logging), "no $logging in AndroidBellSocket")
        }
        val messages = ArrayList<String?>()
        val short = AndroidBellSocket.Timeouts(connectMs = 500, openMs = 1_000, readMs = 500, writeMs = 500)
        val scripts = listOf<(WsTestServer.Peer) -> Unit>(
            { p -> p.head(); p.write("HTTP/1.1 301 Moved\r\nLocation: ws://127.0.0.1:1/$ticket\r\n\r\n$ticket") },
            { p -> p.head(); p.write("HTTP/1.1 101 OK\r\nSec-WebSocket-Accept: $ticket\r\n\r\n") },
            { p -> p.upgrade(); p.frame(false, 1, ticket.toByteArray()); p.header(true, 0, cap.toLong()) },
            { p -> p.upgrade(); p.frame(true, 1, ticket.toByteArray() + byteArrayOf(0xC3.toByte())) },
            { p -> p.upgrade(); Thread.sleep(2_000) },
        )
        for (script in scripts) {
            WsTestServer { p -> script(p); p.endsWithin(3_000) }.use { s ->
                val e = runCatching { runBlocking { bell(short).connect(url(s.port), headers, cap) { it.receive() } } }.exceptionOrNull()
                assertNotNull(e)
                var c: Throwable? = e
                while (c != null) {
                    messages += c.message
                    c = c.cause
                }
            }
        }
        messages += runCatching { runBlocking { bell().connect("ws://example.com/x?ticket=$ticket", headers, cap) { it.receive() } } }.exceptionOrNull()?.message
        messages += runCatching { runBlocking { bell().connect("ws://127.0.0.1:1/x?ticket=$ticket bad", headers, cap) { it.receive() } } }.exceptionOrNull()?.message
        assertTrue(messages.none { it.orEmpty().contains(ticket) || it.orEmpty().contains("TiCkEt") }, messages.toString())
    }
}
