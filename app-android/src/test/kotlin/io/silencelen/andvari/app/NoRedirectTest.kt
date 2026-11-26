package io.silencelen.andvari.app

import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * No client the app builds follows a redirect. The shared code's dialer stopped following them;
 * the app's own client ([androidHttpClient], behind every Android API and the new path's transport) refuses them at
 * both layers, ktor's and OkHttp's. Run against a raw HTTP server on a loopback socket that answers every path but
 * `/landed` with a redirect to `/landed`, and records each request line it reads.
 */
class NoRedirectTest {
    private fun server(status: String): Pair<Int, List<String>> {
        val ss = ServerSocket(0, 8, InetAddress.getLoopbackAddress())
        ss.soTimeout = 15_000
        val seen = CopyOnWriteArrayList<String>()
        thread(isDaemon = true) {
            ss.use {
                while (true) {
                    val s = try { ss.accept() } catch (e: SocketTimeoutException) { break }
                    s.use {
                        val head = readHead(s.getInputStream())
                        val line = head.lineSequence().first()
                        seen += line
                        val length = Regex("(?i)Content-Length: *(\\d+)").find(head)?.groupValues?.get(1)?.toInt() ?: 0
                        repeat(length) { s.getInputStream().read() }
                        val reply = if (line.contains(" /landed ")) {
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                        } else {
                            "HTTP/1.1 $status\r\nLocation: http://127.0.0.1:${ss.localPort}/landed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        }
                        s.getOutputStream().write(reply.toByteArray())
                        s.getOutputStream().flush()
                    }
                }
            }
        }
        return ss.localPort to seen
    }

    private fun readHead(input: InputStream): String {
        val b = ByteArrayOutputStream()
        while (!b.toString().endsWith("\r\n\r\n")) {
            val c = input.read()
            if (c < 0) break
            b.write(c)
        }
        return b.toString()
    }

    @Test
    fun theAppsClientAnswersARedirectAsItIsAndNeverGoesWhereItPoints() {
        for (status in listOf("301 Moved Permanently", "302 Found", "303 See Other", "307 Temporary Redirect", "308 Permanent Redirect")) {
            val (port, seen) = server(status)
            val client = androidHttpClient()
            try {
                val got: HttpResponse = runBlocking { client.get("http://127.0.0.1:$port/api/v1/sync") }
                assertEquals(status.substringBefore(' ').toInt(), got.status.value, "$status reaches the caller as the answer")
                val posted: HttpResponse = runBlocking { client.post("http://127.0.0.1:$port/api/v1/items") { setBody("x") } }
                assertEquals(status.substringBefore(' ').toInt(), posted.status.value)
            } finally {
                client.close()
            }
            assertTrue(seen.none { it.contains("/landed") }, "$status: nothing went where the redirect pointed: $seen")
            assertEquals(2, seen.size, "$status: one request each, none repeated: $seen")
        }
    }
}
