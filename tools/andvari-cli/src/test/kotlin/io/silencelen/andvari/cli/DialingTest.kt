package io.silencelen.andvari.cli

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.silencelen.andvari.cli.e2e.Redirect
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.file.Files
import java.util.Collections
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * `--origin O --connect C` (design §9.5 R11). The library that let the tool name O on a connection to C (ktor's CIO
 * engine) was declined by the owner on 2026-11-15, and the tool's HTTP client cannot do it alone. So:
 * - a `--connect` to any address but the origin's own is refused before anything is sent, in words that say why and
 *   what to do instead;
 * - a `--connect` that IS the origin's own address is kept, and its requests name the origin;
 * - the tests' own redirect ([Redirect]) states the limit: its requests name the dialed address.
 */
class DialingTest {
    /** A loopback listener that records every request's head (lowercase header names) and answers each `503`. */
    private class Listener : AutoCloseable {
        val socket = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val seen: MutableList<Map<String, String>> = Collections.synchronizedList(ArrayList())
        val address = "http://127.0.0.1:${socket.localPort}"

        init {
            Thread {
                while (true) {
                    val sock = runCatching { socket.accept() }.getOrNull() ?: break
                    runCatching {
                        sock.use {
                            val reader = it.getInputStream().bufferedReader(Charsets.ISO_8859_1)
                            val lines = generateSequence { reader.readLine() }.takeWhile { l -> l.isNotEmpty() }.toList()
                            if (lines.isNotEmpty()) {
                                seen += mapOf("request-line" to lines.first()) +
                                    lines.drop(1).associate { l -> l.substringBefore(':').trim().lowercase() to l.substringAfter(':').trim() }
                            }
                            val body = """{"error":"unavailable"}"""
                            it.getOutputStream().apply {
                                write("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body".toByteArray())
                                flush()
                            }
                        }
                    }
                }
            }.apply { isDaemon = true }.start()
        }

        /**
         * [seen] once every connection made before this call has been read: the listener reads one connection at a time
         * in arrival order, and answers a probe of its own only after reading it, so when the probe's answer is in, every
         * earlier request is in [seen]. The probe itself is left out.
         */
        fun settled(): List<Map<String, String>> {
            val probe = "GET /settled-${System.nanoTime()} HTTP/1.1"
            java.net.Socket(InetAddress.getLoopbackAddress(), socket.localPort).use { s ->
                s.soTimeout = io.silencelen.andvari.cli.e2e.Await.DEFAULT_MS.toInt()
                s.getOutputStream().apply { write("$probe\r\nHost: probe\r\n\r\n".toByteArray()); flush() }
                s.getInputStream().readBytes()
            }
            val all = seen.toList()
            val at = all.indexOfFirst { it["request-line"] == probe }
            check(at >= 0) { "the listener answered its probe without reading it: $all" }
            return all.take(at)
        }

        override fun close() = socket.close()
    }

    private class Run(val code: Int, val out: String, val err: String)

    private fun cli(vararg args: String): Run {
        val home = Files.createTempDirectory("andvari-cli-dial").toFile()
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val old = System.err
        System.setErr(PrintStream(err, true))
        val code = try {
            Cli.run(listOf("--home", home.path) + args, PrintStream(out, true), { if (it == "ANDVARI_PASSWORD") "a password nobody types" else null }, { null })
        } finally {
            System.setErr(old)
            home.deleteRecursively()
        }
        return Run(code, out.toString(), err.toString())
    }

    @Test fun aConnectToAnotherAddressIsRefusedBeforeAnythingIsSentAndSaysWhatToDoInstead() {
        Listener().use { l ->
            val trust = "0".repeat(64)
            // The design's own case: a public origin, dialed on the instance host's loopback port.
            val public = cli("--origin", "https://vault.example.org", "--connect", l.address, "sign-in", "--email", "a@example.org", "--trust-card", trust)
            assertEquals(2, public.code, public.out + public.err)
            for (words in listOf("refused", "cannot name vault.example.org", "the wrong name", "Nothing was sent", "Leave out --connect", "hosts entry")) {
                assertTrue(public.err.contains(words), "\"$words\" in: ${public.err}")
            }
            // A loopback origin on another port: no hosts entry can help, so none is suggested.
            val loopback = cli("--origin", "http://127.0.0.1:5555", "--connect", l.address, "sign-in", "--email", "a@example.org", "--trust-card", trust)
            assertEquals(2, loopback.code, loopback.out + loopback.err)
            assertTrue(loopback.err.contains("cannot name 127.0.0.1") && loopback.err.contains("Nothing was sent"), loopback.err)
            assertFalse(loopback.err.contains("hosts entry"), loopback.err)
            // The address check still comes first.
            val far = cli("--origin", "https://vault.example.org", "--connect", "http://192.0.2.1:8080", "sign-in", "--email", "a@example.org")
            assertEquals(2, far.code)
            assertTrue(far.err.contains("only for a loopback address"), far.err)
            assertEquals(emptyList(), l.settled(), "nothing reached the address")
        }
        assertTrue(Cli.HELP.contains("--connect URL is accepted only when it is the origin's own address") && Cli.HELP.contains("hosts entry"), Cli.HELP)
    }

    @Test fun aConnectThatIsTheOriginsOwnAddressIsKeptAndItsRequestsNameTheOrigin() {
        Listener().use { l ->
            val r = cli("--origin", l.address, "--connect", l.address, "sign-in", "--email", "a@example.org", "--trust-card", "0".repeat(64))
            assertEquals(1, r.code, "the listener is not a server, so the sign-in stops: ${r.out}${r.err}")
            val seen = l.seen.toList()
            assertTrue(seen.isNotEmpty(), "the request was sent: ${r.err}")
            seen.forEach { assertEquals(l.address.substringAfter("://"), it["host"], "$it") }
        }
    }

    /** The limit the tests live with (H7, declined): a redirected request names the address it was sent to. */
    @Test fun theTestsRedirectNamesTheDialedAddressAndNeverDialsAnotherHost() {
        Listener().use { l ->
            Redirect.client("https://vault.example.org", l.address).use { http ->
                runBlocking { assertEquals("""{"error":"unavailable"}""", http.get("https://vault.example.org/api/v1/client-policy").bodyAsText()) }
                val e = assertFails { runBlocking { http.get("https://elsewhere.example.org/api/v1/client-policy") } }
                assertTrue(e.message.orEmpty().contains("refusing to dial elsewhere.example.org"), "$e")
            }
            val h = l.seen.single()
            assertEquals("GET /api/v1/client-policy HTTP/1.1", h["request-line"])
            assertEquals(l.address.substringAfter("://"), h["host"], "the dialed address, not vault.example.org: $h")
        }
    }
}
