package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The server spends a refresh token the moment it rotates it, and a second use revokes the whole
 * device. So a refresh the server has answered must be stored even if the caller has gone away.
 */
class AndvariApiRefreshDurabilityTest {
    private fun headers() = headersOf(HttpHeaders.ContentType, "application/json")

    /** Collects onTokens calls; they arrive off the caller's thread. */
    private class Stored {
        private val lock = SynchronizedObject()
        private val list = mutableListOf<Tokens?>()
        fun add(t: Tokens?) = synchronized(lock) { list.add(t) }
        fun all(): List<Tokens?> = synchronized(lock) { list.toList() }
    }

    @Test
    fun aCallerCancelledMidRefreshStillStoresTheRotatedPair() = runBlocking<Unit> {
        val refreshArrived = CompletableDeferred<Unit>()
        val answer = CompletableDeferred<Unit>()
        val engine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/api/v1/auth/refresh" -> {
                    refreshArrived.complete(Unit)
                    answer.await() // the server has the request; the caller is about to give up
                    respond("""{"accessToken":"access-2","refreshToken":"refresh-2"}""", HttpStatusCode.OK, headers())
                }
                else -> respond("""{"error":"unauthorized","message":"bad access token"}""", HttpStatusCode.Unauthorized, headers())
            }
        }
        val stored = Stored()
        val api = AndvariApi("http://fake", HttpClient(engine), Tokens("access-1", "refresh-1"), onTokens = { stored.add(it) })
        val caller = launch { runCatching { api.sync(0) } }
        refreshArrived.await()
        caller.cancel() // an op bound firing, or the screen going away
        answer.complete(Unit)
        caller.join()
        assertEquals(Tokens("access-2", "refresh-2"), api.currentTokens(), "the rotated pair is the one held")
        assertEquals(listOf<Tokens?>(Tokens("access-2", "refresh-2")), stored.all(), "and the one stored: refresh-1 is spent")
        api.close()
    }

    @Test
    fun aStalledRefreshIsBoundedByItsOwnTimeoutAndKeepsThePair() = runBlocking<Unit> {
        val engine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/api/v1/auth/refresh" -> { delay(60_000L); respond("{}", HttpStatusCode.OK, headers()) }
                else -> respond("""{"error":"unauthorized","message":"bad access token"}""", HttpStatusCode.Unauthorized, headers())
            }
        }
        val stored = Stored()
        val api = AndvariApi("http://fake", HttpClient(engine), Tokens("access-1", "refresh-1"), onTokens = { stored.add(it) }, refreshTimeoutMs = 50L)
        // No caller may cancel the refresh, so its own bound is what ends it; a timeout is transient.
        assertFailsWith<IOException> { api.sync(0) }
        assertEquals(Tokens("access-1", "refresh-1"), api.currentTokens(), "an unanswered refresh spends nothing")
        assertEquals(emptyList(), stored.all())
        api.close()
    }
}
