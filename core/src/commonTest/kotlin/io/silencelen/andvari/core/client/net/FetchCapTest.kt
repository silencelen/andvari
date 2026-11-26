package io.silencelen.andvari.core.client.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * [WireClient.fetchBytes] with a cap (for the vault content's attachments): an attachment download never buffers more
 * than the size its item's record claims. A `Content-Length` over the cap is refused before the body is read; without
 * one, the body is read to the cap plus one byte and refused there.
 */
class FetchCapTest {
    private val o = "https://h.example"
    private val id = mapOf("attachmentId" to "a1")

    private fun client(body: ByteArray, length: Long?, status: HttpStatusCode = HttpStatusCode.OK, tokens: TokenSource? = null): KtorWireClient {
        val engine = MockEngine { req ->
            when {
                req.headers[HttpHeaders.Authorization] == "Bearer old" -> respond("""{"error":"invalid_credentials","message":"m"}""", HttpStatusCode.Unauthorized)
                length != null -> respond(ByteReadChannel(body), status, headersOf(HttpHeaders.ContentLength, length.toString()))
                else -> respond(ByteReadChannel(body), status)
            }
        }
        return KtorWireClient(o, HttpClient(engine), "linux", tokens)
    }

    private fun over(r: WireResult<ByteArray>) = assertEquals(BODY_OVER_LIMIT, assertIs<WireResult.Refused>(r).code)

    @Test fun aBodyOverTheCapIsRefusedWithOrWithoutALength() = runBlocking<Unit> {
        val ten = ByteArray(10) { (it + 1).toByte() }
        for (length in listOf<Long?>(10, null)) {
            val ok = assertIs<WireResult.Ok<ByteArray>>(client(ten, length).fetchBytes(WireRoute.ATTACHMENT_GET, id, null, true, 10L), "$length")
            assertTrue(ok.value.contentEquals(ten))
            over(client(ten, length).fetchBytes(WireRoute.ATTACHMENT_GET, id, null, true, 9L))
        }
        // A length that claims far more than the cap is refused before anything is read.
        over(client(ten, 1_000_000).fetchBytes(WireRoute.ATTACHMENT_GET, id, null, true, 100L))
        // No cap: as before.
        assertTrue(assertIs<WireResult.Ok<ByteArray>>(client(ten, null).fetchBytes(WireRoute.ATTACHMENT_GET, id, null, true, null)).value.contentEquals(ten))
    }

    @Test fun aLargeBodyWithinItsCapArrivesWhole() = runBlocking<Unit> {
        val big = ByteArray(300_000) { (it % 251).toByte() }
        val ok = assertIs<WireResult.Ok<ByteArray>>(client(big, null).fetchBytes(WireRoute.ATTACHMENT_GET, id, null, true, big.size.toLong()))
        assertTrue(ok.value.contentEquals(big))
        over(client(big, null).fetchBytes(WireRoute.ATTACHMENT_GET, id, null, true, big.size - 1L))
    }

    @Test fun theCappedFetchKeepsTheRefreshTheRefusalsAndTheGuard() = runBlocking<Unit> {
        var token = "old"
        val tokens = object : TokenSource {
            override fun accessToken() = token
            override suspend fun refresh(staleAccessToken: String): Boolean { token = "new"; return true }
        }
        val three = byteArrayOf(1, 2, 3)
        assertTrue(assertIs<WireResult.Ok<ByteArray>>(client(three, 3, tokens = tokens).fetchBytes(WireRoute.ATTACHMENT_GET, id, null, true, 3L)).value.contentEquals(three))
        assertEquals("new", token)
        val notFound = client("""{"error":"not_found","message":"m"}""".encodeToByteArray(), null, HttpStatusCode.NotFound)
        assertEquals("not_found", assertIs<WireResult.Refused>(notFound.fetchBytes(WireRoute.ATTACHMENT_GET, id, null, true, 3L)).code)
        assertEquals(KtorWireClient.BAD_PATH_SEGMENT, assertIs<WireResult.Refused>(notFound.fetchBytes(WireRoute.ATTACHMENT_GET, mapOf("attachmentId" to "../x"), null, true, 3L)).code)
        // Behind the guard, with no pin in force, nothing is fetched.
        val guarded = OriginGuard(io.silencelen.andvari.core.client.pin.PinStore(io.silencelen.andvari.core.client.MemoryDeviceState())).guard(client(three, 3))
        assertTrue(guarded.fetchBytes(WireRoute.ATTACHMENT_GET, id, null, true, 3L).originStopped)
    }

    @Test fun aClientThatCannotStreamRefusesAnOversizedAnswerAfterItAndZeroesIt() = runBlocking<Unit> {
        val served = ByteArray(8) { 7 }
        val c = object : WireClient {
            override val origin = o
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean): WireResult<ByteArray> =
                WireResult.Ok(served, 200)
        }
        over(c.fetchBytes(WireRoute.ATTACHMENT_GET, id, null, true, 7L))
        assertTrue(served.all { it == 0.toByte() }, "the oversized answer is zeroed")
    }
}
