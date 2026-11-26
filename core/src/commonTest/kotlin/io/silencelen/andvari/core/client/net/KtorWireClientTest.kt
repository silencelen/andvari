package io.silencelen.andvari.core.client.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class KtorWireClientTest {
    private val o = "https://h.example"
    private val h = "a".repeat(64)

    private class Tokens(var token: String?, val next: String?) : TokenSource {
        var refreshes = 0
        override fun accessToken() = token
        override suspend fun refresh(staleAccessToken: String): Boolean { refreshes++; token = next; return next != null }
    }

    @Test fun okRefusedRetryAfterRefreshAndSegments() = runBlocking<Unit> {
        val seen = ArrayList<String>()
        val engine = MockEngine { req ->
            seen += "${req.method.value} ${req.url.encodedPath}?${req.url.encodedQuery} auth=${req.headers[HttpHeaders.Authorization]} client=${req.headers["X-Andvari-Client"]}"
            when {
                req.url.encodedPath.endsWith("/log") && req.headers[HttpHeaders.Authorization] == "Bearer old" ->
                    respond("""{"error":"invalid_credentials","message":"m"}""", HttpStatusCode.Unauthorized)
                req.url.encodedPath.endsWith("/log") ->
                    respond("""{"entries":["f"],"head":{"seq":0,"hash":"$h","at":1},"x":1}""", HttpStatusCode.OK)
                req.url.encodedPath == "/api/v1/auth/refresh" ->
                    respond("""{"error":"rate_limited","message":"m"}""", HttpStatusCode.TooManyRequests, headersOf("Retry-After", "17"))
                req.url.encodedPath == "/api/v1/sync" -> respond("<html>proxy</html>", HttpStatusCode.BadGateway)
                else -> respond("not json", HttpStatusCode.OK)
            }
        }
        val tokens = Tokens("old", "new")
        val c = KtorWireClient(o, HttpClient(engine), "linux", tokens)
        val vault = "0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e"
        val page = assertIs<WireResult.Ok<LogPage>>(c.call(WireRoute.LOG_FETCH, mapOf("vaultId" to vault), "after=3", decode = { WireJson.json.decodeFromString(LogPage.serializer(), it) }))
        assertEquals(listOf("f"), page.value.entries)
        assertEquals(1, tokens.refreshes)
        assertTrue(seen.last().contains("after=3") && seen.last().contains("Bearer new") && seen.last().contains("client=linux/"))
        val r = assertIs<WireResult.Refused>(c.call(WireRoute.REFRESH, bodyJson = "{}", decode = { WireJson.json.decodeFromString(TokenPair.serializer(), it) }))
        assertEquals("rate_limited", r.code)
        assertEquals(17, r.retryAfterSeconds)
        assertNull(seen.last().substringAfter("auth=").substringBefore(" ").takeIf { it != "null" }, "an unauthenticated route sends no bearer")
        assertEquals(NoAnswerKind.SERVER_ERROR, assertIs<WireResult.NoAnswer>(c.call(WireRoute.SYNC, decode = { it })).kind)
        assertEquals(NoAnswerKind.UNDECODABLE, assertIs<WireResult.NoAnswer>(c.call(WireRoute.SIGNUP_START, bodyJson = "{}", decode = { WireJson.json.decodeFromString(LogPage.serializer(), it) })).kind)
        val before = seen.size
        val bad = assertIs<WireResult.Refused>(c.call(WireRoute.LOG_FETCH, mapOf("vaultId" to "../admin"), decode = { it }))
        assertEquals(KtorWireClient.BAD_PATH_SEGMENT, bad.code)
        assertEquals(before, seen.size, "nothing is sent for a bad segment")
    }

    @Test fun transportFailureIsNoAnswer() = runBlocking<Unit> {
        val c = KtorWireClient(o, HttpClient(MockEngine { throw IllegalStateException("down") }), "ios")
        assertEquals(NoAnswerKind.TRANSPORT, assertIs<WireResult.NoAnswer>(c.call(WireRoute.CLIENT_POLICY, decode = { it })).kind)
    }
}
