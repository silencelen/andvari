package io.silencelen.andvari.core.client.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Every answer is read up to a cap that fits its route ([ResponseCaps]), before a Trust Gate as
 * after it, by length and without one; over it the call is `body_over_limit` and nothing of the answer is decoded.
 */
class ResponseCapsTest {
    private val o = "https://h.example"

    @Test fun everyRouteHasACapAndTheLargerOnesAreTheStatedOnes() {
        assertEquals(WireRoute.entries.toSet(), ResponseCaps.table.keys, "one cap per route")
        for ((route, cap) in ResponseCaps.table) {
            assertTrue(cap > 0, "$route has a cap")
            assertTrue(ResponseCaps.ofRefusal(route) in 1..ResponseCaps.ERROR_BODY, "$route: a refusal is read to the envelope's cap")
        }
        assertEquals(64L * 1024, ResponseCaps.of(WireRoute.CLIENT_POLICY))
        assertEquals(1L shl 20, ResponseCaps.of(WireRoute.INSTANCE))
        assertEquals(2L shl 20, ResponseCaps.of(WireRoute.LOG_FETCH))
        assertEquals(256L shl 20, ResponseCaps.of(WireRoute.SYNC))
        // Every JSON route whose answer is one short object has the small default.
        val small = WireRoute.entries.filter { ResponseCaps.of(it) == ResponseCaps.SMALL }
        assertTrue(WireRoute.LOGIN in small && WireRoute.REFRESH in small && WireRoute.LINK_FETCH in small)
        assertEquals(8L * 1024 * 1024 + 256 * 1024, ResponseCaps.of(WireRoute.PUSH), "a push answer may echo 8 MiB of stored items")
    }

    /**
     * Spec 03 §5 lets an honest push answer carry stored items totalling the request's own body cap (8 MiB): the
     * server's echo counts each as its blob plus 256 bytes. The largest such answer, 200 results of which as many echo
     * an item as the 8 MiB allows, arrives whole and decodes; the 64 KiB a push answer was read to before refused it.
     */
    @Test fun aPushAnswerEchoingTheEightMiBOfStoredItemsTheSpecAllowsArrives() = runBlocking<Unit> {
        val budget = 8L * 1024 * 1024
        val perItem = 2 * 1024 * 1024 - 256 // four items of the default 2 MiB maximum fill the echo
        var used = 0L
        val results = (0 until 200).map { i ->
            val echo = used + perItem + 256 <= budget
            if (echo) used += perItem + 256
            MutationResult(
                mutationId = "m".repeat(60) + i.toString().padStart(4, '0'), status = "conflict", newItemRev = 1_000_000_000L + i,
                serverItem = if (!echo) null else SyncItem(
                    "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f", "2d8e5f4a-6f7c-4d9e-8f1a-2b3c4d5e6f70", 1_000_000_000L + i,
                    1_700_000_000_000, 1_700_000_000_000, false, true, 1, emptyList(), "A".repeat(perItem),
                ),
                serverItemOmitted = if (echo) null else true,
            )
        }
        val body = WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(1_000_000_500L, results))
        assertTrue(body.length > 8L * 1024 * 1024, "the answer is past 8 MiB: ${body.length}")
        val c = KtorWireClient(o, HttpClient(MockEngine { respond(ByteReadChannel(body.encodeToByteArray()), HttpStatusCode.OK) }), "linux")
        val r = c.call(WireRoute.PUSH, bodyJson = "{}", decode = { WireJson.json.decodeFromString(PushResponse.serializer(), it) })
        assertEquals(200, assertIs<WireResult.Ok<PushResponse>>(r, "$r").value.results.size)
        assertEquals(4, r.value.results.count { it.serverItem != null })
        over(Server(ResponseCaps.PUSH_ANSWER + 1, null).client().call(WireRoute.PUSH, bodyJson = "{}", decode = { it }))
    }

    /**
     * An answer of [size] bytes of a valid JSON string (so the old whole read decodes it), with a `Content-Length` of
     * [length] when given. The byte counts on a real socket, an endless body included, are the hostile harness's
     * (`AnswerCapsTest`); this mock only shows where the client refuses.
     */
    private class Server(val size: Long, val length: Long?, val status: HttpStatusCode = HttpStatusCode.OK) {
        fun client(): KtorWireClient = KtorWireClient("https://h.example", HttpClient(MockEngine { _ ->
            val body = ByteArray(size.toInt()) { 0x41 }.also { if (it.size >= 2) { it[0] = 0x22; it[it.size - 1] = 0x22 } }
            respond(ByteReadChannel(body), status, if (length != null) headersOf(HttpHeaders.ContentLength, length.toString()) else headersOf())
        }), "linux")
    }

    private fun over(r: WireResult<*>) = assertEquals(BODY_OVER_LIMIT, assertIs<WireResult.Refused>(r, "$r").code)

    @Test fun anAnswerPastItsRouteCapIsRefusedWithoutALength() = runBlocking<Unit> {
        for (route in listOf(WireRoute.CLIENT_POLICY, WireRoute.INSTANCE, WireRoute.LOG_FETCH)) {
            val cap = ResponseCaps.of(route)
            val params = if (route == WireRoute.LOG_FETCH) mapOf("vaultId" to "v1") else emptyMap()
            over(Server(cap + 1, null).client().call(route, params, decode = { it }))
            assertIs<WireResult.Ok<String>>(Server(cap, null).client().call(route, params, decode = { it }), "$route at its cap")
        }
    }

    @Test fun aLengthOverTheCapIsRefusedBeforeTheBodyIsRead() = runBlocking<Unit> {
        // The length lies far past the cap over a short body: the refusal comes from the length alone (a whole read would
        // have decoded the short body).
        over(Server(16, 1L shl 30).client().call(WireRoute.CLIENT_POLICY, decode = { it }))
        // The same through fetchBytes without the caller's cap: the route's own.
        over(Server(ResponseCaps.SMALL + 1, null).client().fetchBytes(WireRoute.DOWNLOADS_MANIFEST_SIG, emptyMap(), null, false))
    }

    @Test fun anAnswerAtItsCapArrivesAndOneByteMoreDoesNot() = runBlocking<Unit> {
        val cap = ResponseCaps.of(WireRoute.HEALTHZ)
        for (length in listOf<Long?>(cap, null)) {
            val ok = assertIs<WireResult.Ok<String>>(Server(cap, length).client().call(WireRoute.HEALTHZ, decode = { it }), "$length")
            assertEquals(cap.toInt(), ok.value.length)
        }
        for (length in listOf<Long?>(cap + 1, null)) over(Server(cap + 1, length).client().call(WireRoute.HEALTHZ, decode = { it }))
    }

    @Test fun aRefusalEnvelopeIsReadToItsOwnCapOnARouteWithALargeOne() = runBlocking<Unit> {
        over(Server(ResponseCaps.ERROR_BODY + 1, null, HttpStatusCode.Forbidden).client().call(WireRoute.SYNC, decode = { it }))
        // A genuine envelope still reads as the refusal it is.
        val c = KtorWireClient(o, HttpClient(MockEngine { respond("""{"error":"no_grant","message":"m"}""", HttpStatusCode.Forbidden) }), "linux")
        assertEquals("no_grant", assertIs<WireResult.Refused>(c.call(WireRoute.SYNC, decode = { it })).code)
    }

    @Test fun aLargeAnswerWithinItsRouteCapArrivesWhole() = runBlocking<Unit> {
        val body = "\"" + "x".repeat(1_500_000) + "\""
        val c = KtorWireClient(o, HttpClient(MockEngine { respond(ByteReadChannel(body.encodeToByteArray()), HttpStatusCode.OK) }), "linux")
        assertEquals(body, assertIs<WireResult.Ok<String>>(c.call(WireRoute.LOG_FETCH, mapOf("vaultId" to "v1"), decode = { it })).value)
        over(c.call(WireRoute.CLIENT_POLICY, decode = { it }))
    }
}
