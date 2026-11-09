package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.model.RefreshRequest
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for AndvariApi.tryRefresh against a fake engine (full client↔server behavior
 * is covered by server's ClientEngineTest against a real server):
 *  - two concurrent 401s must never double-spend the same rotating refresh token — the
 *    server treats reuse as theft (refresh_reuse) and revokes the whole device;
 *  - a transient refresh failure (502/503/429) must KEEP the token pair;
 *  - only a definitive 401/403 from the refresh endpoint clears it;
 *  - uploadAttachment, the ONE call that hand-rolls its own 401→refresh→retry outside
 *    [AndvariApi.request], retries exactly like every other call (quality-tests--12).
 */
class AndvariApiRefreshTest {

    private companion object {
        const val ATTACHMENT_ID = "11111111-2222-3333-4444-555555555555"
    }

    private val json = Json { ignoreUnknownKeys = true }

    /** Strict server sim: exactly one valid access/refresh pair at a time; presenting a
     *  stale refresh token trips [reusedRefresh], mirroring the real reuse-revocation. */
    private class FakeAuth {
        private val lock = Any()
        private var counter = 0
        var validAccess = "access-0"
            private set
        var validRefresh = "refresh-0"
            private set
        var refreshCalls = 0
            private set
        var reusedRefresh = false
            private set
        var refreshFailuresToServe = 0
        var refreshFailureStatus: HttpStatusCode = HttpStatusCode.ServiceUnavailable

        /** Completed once TWO sync requests have been rejected 401 — the concurrency gate. */
        val bothSyncs401 = CompletableDeferred<Unit>()
        private var sync401s = 0

        fun recordSync401() = synchronized(lock) {
            sync401s++
            if (sync401s >= 2) bothSyncs401.complete(Unit)
        }

        fun refresh(token: String): Pair<HttpStatusCode, String> = synchronized(lock) {
            refreshCalls++
            if (refreshFailuresToServe > 0) {
                refreshFailuresToServe--
                return refreshFailureStatus to """{"error":"upstream","message":"transient"}"""
            }
            if (token != validRefresh) {
                reusedRefresh = true
                return HttpStatusCode.Unauthorized to """{"error":"refresh_reuse","message":"token reuse - device revoked"}"""
            }
            counter++
            validAccess = "access-$counter"
            validRefresh = "refresh-$counter"
            return HttpStatusCode.OK to """{"accessToken":"$validAccess","refreshToken":"$validRefresh"}"""
        }

        fun accessOk(authorization: String?): Boolean = synchronized(lock) { authorization == "Bearer $validAccess" }

        /** Attachment PUTs seen, and how many of them were rejected 401. */
        var uploadAttempts = 0
            private set
        var upload401s = 0
            private set

        fun recordUpload(ok: Boolean) = synchronized(lock) {
            uploadAttempts++
            if (!ok) upload401s++
        }
    }

    private val emptySync = """{"rev":1,"full":false,"vaults":[],"grants":[],"items":[],"removedGrants":[]}"""
    private fun jsonHeaders() = headersOf(HttpHeaders.ContentType, "application/json")

    /** [gateRefresh] holds every refresh POST until BOTH syncs have 401'd, forcing the
     *  two tryRefresh calls to genuinely overlap (single-shot tests must leave it off). */
    private fun apiAgainst(server: FakeAuth, tokens: Tokens, gateRefresh: Boolean = false): AndvariApi {
        val engine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/api/v1/auth/refresh" -> {
                    if (gateRefresh) server.bothSyncs401.await()
                    val body = json.decodeFromString(RefreshRequest.serializer(), request.body.toByteArray().decodeToString())
                    val (status, payload) = server.refresh(body.refreshToken)
                    respond(payload, status, jsonHeaders())
                }
                "/api/v1/sync" ->
                    if (server.accessOk(request.headers[HttpHeaders.Authorization])) {
                        respond(emptySync, HttpStatusCode.OK, jsonHeaders())
                    } else {
                        server.recordSync401()
                        respond("""{"error":"unauthorized","message":"bad access token"}""", HttpStatusCode.Unauthorized, jsonHeaders())
                    }
                "/api/v1/attachments/$ATTACHMENT_ID" -> {
                    val ok = server.accessOk(request.headers[HttpHeaders.Authorization])
                    server.recordUpload(ok)
                    if (ok) {
                        respond(
                            """{"attachmentId":"$ATTACHMENT_ID","itemId":"item-1","vaultId":"vault-1","size":${request.body.toByteArray().size},"sha256":"deadbeef"}""",
                            HttpStatusCode.OK,
                            jsonHeaders(),
                        )
                    } else {
                        respond("""{"error":"unauthorized","message":"bad access token"}""", HttpStatusCode.Unauthorized, jsonHeaders())
                    }
                }
                else -> respond("""{"error":"not_found","message":"unexpected path"}""", HttpStatusCode.NotFound, jsonHeaders())
            }
        }
        return AndvariApi("http://fake", HttpClient(engine), tokens)
    }

    @Test
    fun concurrent401sNeverDoubleSpendTheRefreshToken() = runBlocking {
        val server = FakeAuth()
        // Stale ACCESS token, valid refresh token: both requests 401 and hit tryRefresh.
        val api = apiAgainst(server, Tokens("stale-access", "refresh-0"), gateRefresh = true)
        withTimeout(30_000) {
            coroutineScope {
                val a = async { api.sync(0) }
                val b = async { api.sync(0) }
                assertEquals(1L, a.await().rev)
                assertEquals(1L, b.await().rev)
            }
        }
        // The invariant that keeps the device alive: a refresh token is never SPENT
        // twice. Without the mutex both 401s POSTed refresh-0 → reuse → revocation.
        // (The loser usually skips its POST entirely — 1 call — but may legally rotate
        // once more with the CURRENT token if it entered after the winner finished, so
        // the call COUNT is 1 or 2; reuse is what must never happen.)
        assertFalse(server.reusedRefresh, "the same refresh token was spent twice")
        assertTrue(server.refreshCalls <= 2, "refresh storm: ${server.refreshCalls} calls")
        assertNotNull(api.currentTokens())
        api.close()
    }

    @Test
    fun transientRefreshFailureKeepsTheTokenPair() = runBlocking {
        val server = FakeAuth().apply { refreshFailuresToServe = 1 }
        val api = apiAgainst(server, Tokens("stale-access", "refresh-0"))
        // Refresh 503s → the original 401 surfaces, but the pair MUST survive (a proxy
        // blip must not sign the device out).
        val failed = assertFailsWith<ApiException> { api.sync(0) }
        assertEquals(401, failed.status)
        assertEquals(Tokens("stale-access", "refresh-0"), api.currentTokens())
        // Proxy recovered: the SAME kept pair refreshes and the call goes through.
        assertEquals(1L, api.sync(0).rev)
        assertFalse(server.reusedRefresh)
        api.close()
    }

    @Test
    fun uploadAttachmentRefreshesOnceAndRetries() = runBlocking {
        // uploadAttachment cannot ride request() — it streams a raw octet-stream body — so it
        // repeats the refresh/retry loop by hand. Nothing pinned that loop, which is exactly how
        // it would rot into "401 → give up" while every request()-based call kept working: a
        // stale access token would then fail the LAST leg of every attachment save.
        val server = FakeAuth()
        val api = apiAgainst(server, Tokens("stale-access", "refresh-0"))
        val meta = api.uploadAttachment(ATTACHMENT_ID, "item-1", "vault-1", ByteArray(11) { 7 })
        assertEquals(ATTACHMENT_ID, meta.attachmentId)
        assertEquals(11L, meta.size, "the retry must resend the SAME body, not an empty one")
        assertEquals(2, server.uploadAttempts, "expected exactly one retry after the 401")
        assertEquals(1, server.upload401s)
        assertEquals(1, server.refreshCalls)
        assertFalse(server.reusedRefresh)
        assertNotNull(api.currentTokens())
        api.close()
    }

    @Test
    fun uploadAttachmentSurfacesTheErrorWhenTheRefreshFails() = runBlocking {
        // The other half of the contract: a refresh that cannot succeed must surface the 401
        // rather than loop, and must not silently swallow it into a "successful" upload.
        val server = FakeAuth().apply {
            refreshFailuresToServe = 1
            refreshFailureStatus = HttpStatusCode.Unauthorized
        }
        val api = apiAgainst(server, Tokens("stale-access", "refresh-0"))
        val failed = assertFailsWith<ApiException> { api.uploadAttachment(ATTACHMENT_ID, "item-1", "vault-1", ByteArray(4)) }
        assertEquals(401, failed.status)
        assertEquals(1, server.uploadAttempts, "a failed refresh must not re-send the body")
        api.close()
    }

    @Test
    fun definitiveRefreshRejectionClearsTheTokenPair() = runBlocking {
        val server = FakeAuth().apply {
            refreshFailuresToServe = 1
            refreshFailureStatus = HttpStatusCode.Unauthorized
        }
        val api = apiAgainst(server, Tokens("stale-access", "refresh-0"))
        assertFailsWith<ApiException> { api.sync(0) }
        assertNull(api.currentTokens(), "a definitive 401 from the refresh endpoint signs the device out")
        api.close()
    }
}
