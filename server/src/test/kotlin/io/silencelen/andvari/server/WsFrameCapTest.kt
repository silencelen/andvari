package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.encodeURLParameter
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.testing.testApplication
import io.ktor.websocket.CloseReason
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.WsTicketResponse
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Security review 2026-10 (server F1): the /api/v1/events WebSocket was exempt from both body-cap
 * layers on the theory that the WebSocket layer bounds its own input — but `install(WebSockets)`
 * left `maxFrameSize` at Ktor's default of Long.MAX_VALUE, and Ktor's frame reader allocates a
 * buffer of the DECLARED frame length as soon as it has parsed the header, before any payload
 * arrives. A handful of sockets each declaring a few hundred MiB and then going quiet pinned that
 * much heap per socket and could take the single-process server down for every member.
 *
 * Deliberately a REAL Netty listener and a raw socket: the test engine and every WS client library
 * only send frames they actually have the bytes for, so neither can declare a length it never
 * delivers — which is the whole attack.
 */
class WsFrameCapTest : P4TestSupport() {

    @Test
    fun oversizedDeclaredFrame_isRefusedFromTheHeaderAlone_beforeAnyPayload() {
        val services = buildServices(config(), Notifier())
        val server = embeddedServer(Netty, port = 0, host = "127.0.0.1") { andvariModule(services) }
        server.start(wait = false)
        try {
            val port = runBlocking { server.engine.resolvedConnectors().first().port }
            val ticket = runBlocking { mintTicket(port) }
            Socket("127.0.0.1", port).use { sock ->
                sock.soTimeout = 10_000
                val out = sock.getOutputStream()
                val input = sock.getInputStream()
                val key = Base64.getEncoder().encodeToString(ByteArray(16) { it.toByte() })
                out.write(
                    ("GET /api/v1/events?ticket=${ticket.encodeURLParameter()} HTTP/1.1\r\n" +
                        "Host: 127.0.0.1:$port\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                        "Sec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13\r\n\r\n").toByteArray(),
                )
                out.flush()
                val head = readHttpHead(input)
                assertTrue(head.startsWith("HTTP/1.1 101"), "upgrade must succeed: $head")

                // A masked text frame header declaring 64 MiB — and then nothing. No payload byte is
                // ever sent, so the only way the server can answer is from the header itself.
                val declared = 64L * 1024 * 1024
                val header = ByteArrayOutputStream().apply {
                    write(0x81) // FIN + text
                    write(0x80 or 127) // MASK + 64-bit extended length
                    for (shift in 56 downTo 0 step 8) write(((declared shr shift) and 0xff).toInt())
                    write(byteArrayOf(1, 2, 3, 4)) // masking key
                }.toByteArray()
                out.write(header)
                out.flush()

                val code: Int = try {
                    readCloseCode(input)
                } catch (e: SocketTimeoutException) {
                    fail("server sat waiting for 64 MiB of payload instead of refusing the frame header (no maxFrameSize)")
                }
                assertEquals(CloseReason.Codes.TOO_BIG.code.toInt(), code, "an over-cap frame is closed 1009 TOO_BIG")
            }
        } finally {
            server.stop(500, 2_000)
        }
    }

    @Test
    fun theLegitimatePingStillFitsUnderTheCap() {
        // The cap must leave the ONE frame the handler accepts — "ping" — comfortably inside it.
        assertTrue(WS_MAX_FRAME_BYTES >= 1024, "cap $WS_MAX_FRAME_BYTES is too tight for ping + headroom")
        assertTrue(WS_MAX_FRAME_BYTES <= 64 * 1024, "cap $WS_MAX_FRAME_BYTES is too generous for a 4-byte ping")
    }

    @Test
    fun eventsUpgrade_declaredBodyOverTheTightCap_isRefused() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        // The upgrade is a GET with no body; a declared Content-Length over the TIGHT cap is junk
        // and is refused by layer 1 like on every other route — /events is no longer exempt from it.
        val resp = client.get("/api/v1/events") {
            header("Content-Length", (BODY_CAP_TIGHT_BYTES + 1).toString())
            setBody(ByteArray((BODY_CAP_TIGHT_BYTES + 1).toInt()))
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, resp.status, resp.bodyAsText())
    }

    private suspend fun mintTicket(port: Int): String {
        val client = HttpClient(Java) { install(ContentNegotiation) { json(json) } }
        try {
            val vc = VirtualClient("wscap@x.com", "ws frame cap password", fast = true)
            val reg = client.post("http://127.0.0.1:$port/api/v1/auth/register") {
                contentType(ContentType.Application.Json)
                header("X-Andvari-Client", "test/1.0.0")
                setBody(vc.buildRegister(bootstrapToken, recovery.publicKey, fingerprint))
            }
            assertEquals(HttpStatusCode.OK, reg.status, reg.bodyAsText())
            val session = json.decodeFromString(SessionResponse.serializer(), reg.bodyAsText())
            val t = client.post("http://127.0.0.1:$port/api/v1/events/ticket") { authed(session.accessToken) }
            assertEquals(HttpStatusCode.OK, t.status, t.bodyAsText())
            return json.decodeFromString(WsTicketResponse.serializer(), t.bodyAsText()).ticket
        } finally {
            client.close()
        }
    }

    private fun readHttpHead(input: InputStream): String {
        val buf = ByteArrayOutputStream()
        while (!buf.toString(Charsets.ISO_8859_1).endsWith("\r\n\r\n")) {
            val b = input.read()
            if (b < 0) break
            buf.write(b)
        }
        return buf.toString(Charsets.ISO_8859_1)
    }

    /** Skip any non-close frames the server sends first, then return the close frame's status code. */
    private fun readCloseCode(input: InputStream): Int {
        while (true) {
            val b0 = input.read().also { if (it < 0) fail("connection dropped without a close frame") }
            var len = (input.read() and 0x7f).toLong()
            if (len == 126L) len = ((input.read() shl 8) or input.read()).toLong()
            else if (len == 127L) { len = 0; repeat(8) { len = (len shl 8) or input.read().toLong() } }
            val payload = input.readNBytes(len.toInt())
            if ((b0 and 0x0f) == 0x8) {
                return if (payload.size >= 2) ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff) else -1
            }
        }
    }
}
