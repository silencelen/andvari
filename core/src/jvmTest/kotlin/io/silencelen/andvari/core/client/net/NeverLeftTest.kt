package io.silencelen.andvari.core.client.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * A request that never left the device is told apart from one that left and got no answer (the policy's one try counts
 * the first as not sent and the second as "may or may not have arrived"). Over the desktop's real engine and real sockets.
 */
class NeverLeftTest {
    private val loopback = InetAddress.getLoopbackAddress()

    @Test fun aConnectionThatIsRefusedNeverLeft() = runBlocking<Unit> {
        // A port nobody listens on: taken, then let go, so the connection is refused.
        val port = ServerSocket(0, 1, loopback).use { it.localPort }
        val c = KtorWireClient("http://127.0.0.1:$port", HttpClient(Java), "linux")
        val r = assertIs<WireResult.NoAnswer>(c.call(WireRoute.PUSH, bodyJson = "{}", decode = { it }))
        assertEquals(NoAnswerKind.TRANSPORT, r.kind)
        assertTrue(r.neverLeft, "no connection was made: nothing of the request left")
    }

    @Test fun aRequestThatLeftAndGotNoAnswerMayHaveArrived() = runBlocking<Unit> {
        val server = ServerSocket(0, 4, loopback)
        // The server takes each request whole, then closes the connection without answering (until it is closed).
        val t = thread {
            runCatching {
                while (true) {
                    server.accept().use { s ->
                        val input = s.getInputStream()
                        val seen = StringBuilder()
                        while (!seen.endsWith("\r\n\r\n")) {
                            val b = input.read()
                            if (b < 0) break
                            seen.append(b.toChar())
                        }
                        input.readNBytes(2)
                    }
                }
            }
        }
        try {
            val c = KtorWireClient("http://127.0.0.1:${server.localPort}", HttpClient(Java), "linux")
            val r = assertIs<WireResult.NoAnswer>(c.call(WireRoute.PUSH, bodyJson = "{}", decode = { it }))
            assertFalse(r.neverLeft, "the request left: its outcome is unknown")
        } finally {
            server.close()
            t.join()
        }
    }

    /**
     * Android's engine (OkHttp) quietly sends a written request again on a new connection when the kept one drops without
     * an answer; when that second connection is refused it throws the second failure and attaches the first, sent attempt
     * to it as suppressed, not as its cause (`RetryAndFollowUpInterceptor`: `throw e.withSuppressed(recoveredFailures)`).
     * OkHttp is not on this test's classpath, so the failure is built here in that shape: a request the server took whole
     * may have arrived.
     */
    @Test fun aRefusedSecondTryOfARequestThatLeftMayHaveArrived() {
        val sent = java.io.IOException("unexpected end of stream on http://127.0.0.1:41000/...", java.io.EOFException("\\n not found: limit=0 content=…"))
        val retry = java.net.ConnectException("Failed to connect to /127.0.0.1:41000").apply {
            initCause(java.net.ConnectException("Connection refused"))
            addSuppressed(sent)
        }
        assertFalse(KtorWireClient.neverLeft(retry), "the first attempt was sent: its outcome is unknown")
        // The same failure wrapped once more by a caller along the way.
        assertFalse(KtorWireClient.neverLeft(IllegalStateException("wrapped", retry)))
        // The same refusal with nothing attached never left.
        assertTrue(KtorWireClient.neverLeft(java.net.ConnectException("Failed to connect to /127.0.0.1:41000").apply { initCause(java.net.ConnectException("Connection refused")) }))
    }

    /**
     * The check's sequence over the desktop's engine: one request answered on a kept connection (the policy's read just
     * before the run's push), a second one the server takes whole, then the server stops listening and drops the
     * connection without an answer. The second may have arrived.
     */
    @Test fun aRequestTakenWholeOnAKeptConnectionThatThenDropsMayHaveArrived() = runBlocking<Unit> {
        val server = ServerSocket(0, 4, loopback)
        var taken = 0
        val t = thread {
            runCatching {
                server.accept().use { s ->
                    val input = s.getInputStream()
                    val out = s.getOutputStream()
                    repeat(2) { n ->
                        val seen = StringBuilder()
                        while (!seen.endsWith("\r\n\r\n")) {
                            val b = input.read()
                            if (b < 0) return@runCatching
                            seen.append(b.toChar())
                        }
                        val length = Regex("(?i)content-length: *(\\d+)").find(seen)?.groupValues?.get(1)?.toInt() ?: 0
                        input.readNBytes(length)
                        taken++
                        if (n == 0) {
                            out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".toByteArray())
                            out.flush()
                        } else {
                            server.close() // stops listening first, so a second try finds no one
                        }
                    }
                }
            }
        }
        try {
            val c = KtorWireClient("http://127.0.0.1:${server.localPort}", HttpClient(Java), "linux")
            assertIs<WireResult.Ok<String>>(c.call(WireRoute.CLIENT_POLICY, authenticated = false, decode = { it }))
            val r = assertIs<WireResult.NoAnswer>(c.call(WireRoute.PUSH, bodyJson = "{}", decode = { it }))
            assertEquals(NoAnswerKind.TRANSPORT, r.kind)
            assertFalse(r.neverLeft, "the server took the request whole: its outcome is unknown")
        } finally {
            server.close()
            t.join()
        }
        assertEquals(2, taken)
    }

    @Test fun theCauseChainIsRead() {
        assertTrue(KtorWireClient.neverLeft(IllegalStateException("wrapped", java.net.ConnectException("refused"))))
        assertTrue(KtorWireClient.neverLeft(java.net.UnknownHostException("h.example")))
        assertFalse(KtorWireClient.neverLeft(java.net.SocketException("Connection reset")))
        assertFalse(KtorWireClient.neverLeft(java.io.IOException("closed")))
    }
}
