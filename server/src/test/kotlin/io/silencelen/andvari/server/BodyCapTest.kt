package io.silencelen.andvari.server

import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PushResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * spec 03 request-body caps (pentest M4 [S4-01]: an 8 MiB body to the unauthenticated
 * /auth/prelogin was fully heap-buffered). Per route class: TIGHT everywhere — notably
 * every unauthenticated route — a GENEROUS ceiling on /sync/push (a CSV import arrives
 * as one JSON body), and the streamed attachment upload exempt (its own quotas). Both
 * enforcement layers are exercised: declared Content-Length and chunked/undeclared.
 */
class BodyCapTest : P4TestSupport() {

    @Test
    fun unauthTightCap_declaredOversizeRejected_underCapServed() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)

        // Over the 256 KiB tight cap → 413 in the house error shape (layer 1: Content-Length).
        val rejected = client.post("/api/v1/auth/prelogin") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody("""{"email":"cap@x.com","pad":"${"x".repeat(300 * 1024)}"}""")
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, rejected.status)
        assertEquals("body_too_large", errorOf(rejected))

        // The same request under the cap still serves (json ignores the unknown pad key).
        val ok = client.post("/api/v1/auth/prelogin") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody("""{"email":"cap@x.com","pad":"${"x".repeat(64 * 1024)}"}""")
        }
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
    }

    @Test
    fun unauthTightCap_chunkedBodyWithoutContentLengthRejected() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val resp = client.post("/api/v1/auth/prelogin") {
            header("X-Andvari-Client", "test/1.0.0")
            setBody(object : OutgoingContent.WriteChannelContent() {
                override val contentType: ContentType = ContentType.Application.Json
                // contentLength stays null → layer 1 can't see it; the receive-time
                // bounded read (layer 2) must cut the stream off at the cap.
                override suspend fun writeTo(channel: ByteWriteChannel) {
                    val chunk = ByteArray(64 * 1024) { 'x'.code.toByte() }
                    repeat(5) { channel.writeFully(chunk) } // 320 KiB total
                }
            })
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, resp.status)
        assertEquals("body_too_large", errorOf(resp))
    }

    @Test
    fun tightCap_firesBeforeTheHandlerOnAuthedRoutes() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        // No Authorization header at all: 413 (not 401) proves the cap fires BEFORE the
        // handler — an oversize body costs header parsing only, never auth or buffering.
        val resp = client.put("/api/v1/escrow/self") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody("""{"sealed":"${"A".repeat(300 * 1024)}","fingerprint":"f"}""")
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, resp.status)
        assertEquals("body_too_large", errorOf(resp))
    }

    @Test
    fun attachmentUpload_isExemptFromTheTightCap() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("cap-att@x.com", "body cap attachment pw")
        client.register(vc, bootstrapToken)

        // 400 KiB of ciphertext — over the tight cap; the streamed upload must still land
        // (its own quotas govern it: default attachmentMaxBytes is 25 MiB).
        val fileKey = crypto.randomBytes(32)
        val enc = Attachments.encrypt(crypto, fileKey, crypto.randomBytes(400 * 1024))
        val up = client.uploadAttachment(vc, uuid(), vc.newItemId(), enc.header + enc.ciphertext)
        assertEquals(HttpStatusCode.OK, up.status, up.bodyAsText())
    }

    @Test
    fun bodyCapBytes_exemptsStreamsAndWebSocket_capsTheRest() {
        // Fast pin (the WS + attachment integration tests are the slow guard): the /events
        // WebSocket upgrade and the streamed attachment upload are EXEMPT — draining a live WS
        // channel in the layer-2 receive interceptor hangs the handshake (regressed 4 WS tests).
        assertNull(bodyCapBytes("/api/v1/events"))
        assertNull(bodyCapBytes("/api/v1/attachments/abc"))
        assertEquals(BODY_CAP_PUSH_BYTES, bodyCapBytes("/api/v1/sync/push"))
        // a single-item restore re-uploads that item's uncapped blob — generous, not tight, else a
        // big item accepted at creation would be un-restorable from Trash.
        assertEquals(BODY_CAP_PUSH_BYTES, bodyCapBytes("/api/v1/items/abc-123/restore"))
        assertEquals(BODY_CAP_TIGHT_BYTES, bodyCapBytes("/api/v1/auth/prelogin"))
        assertEquals(BODY_CAP_TIGHT_BYTES, bodyCapBytes("/api/v1/items/abc-123/purge"))
    }

    @Test
    fun pushCeiling_allowsAMultiMiBImportBatch() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("cap-push@x.com", "body cap push password")
        client.register(vc, bootstrapToken)

        // A 200-item CSV import lands as ONE push body (spec 06); fat-ish notes make the
        // serialized batch decisively bigger than spec 03's old 1 MiB wording allowed.
        val note = "n".repeat(7 * 1024)
        val mutations = (1..200).map {
            putMutation(vc, vc.newItemId(), """{"type":"note","name":"import $it","notes":"$note"}""", 0)
        }
        val body = json.encodeToString(PushRequest.serializer(), PushRequest(mutations))
        assertTrue(body.length > 1_500_000, "batch must exceed the old 1 MiB claim (was ${body.length})")

        val resp = client.post("/api/v1/sync/push") {
            contentType(ContentType.Application.Json)
            authed(vc)
            setBody(body)
        }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        val push = json.decodeFromString(PushResponse.serializer(), resp.bodyAsText())
        assertEquals(200, push.results.size)
        assertTrue(push.results.all { it.status == "applied" }, "every import mutation must apply")
    }

    @Test
    fun pushCeiling_rejectsPastTheCeiling() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("cap-push2@x.com", "body cap push password 2")
        client.register(vc, bootstrapToken)

        // Declared 9 MiB: refused on Content-Length alone (even authenticated) — the body
        // writer never has to produce a byte, and the server never reads one.
        val resp = client.post("/api/v1/sync/push") {
            authed(vc)
            setBody(object : OutgoingContent.WriteChannelContent() {
                override val contentType: ContentType = ContentType.Application.Json
                override val contentLength: Long = 9L * 1024 * 1024
                override suspend fun writeTo(channel: ByteWriteChannel) {} // nothing sent
            })
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, resp.status)
        assertEquals("body_too_large", errorOf(resp))
    }
}
