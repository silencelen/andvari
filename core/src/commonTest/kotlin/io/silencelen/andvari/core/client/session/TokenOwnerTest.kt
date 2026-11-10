package io.silencelen.andvari.core.client.session

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.Tokens
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A client's token callback writes only into the stored session it holds: same origin, user and refresh token. */
class TokenOwnerTest {
    private val home = "https://home.example"
    private val store = FakeSessionPersistence(home)

    private fun stored(user: String, origin: String = home, access: String = "a1", refresh: String = "r1") =
        StoredSession(origin, user, "u@example.com", access, refresh).also { store.save(it) }

    @Test
    fun theHoldingClientsRotationsAreStoredInTurn() {
        stored("u1")
        val owner = TokenOwner(home, "u1", heldRefreshToken = "r1")
        store.updateTokensFor(owner, Tokens("a2", "r2"))
        assertEquals(Tokens("a2", "r2"), store.load()?.tokens())
        store.updateTokensFor(owner, Tokens("a3", "r3"))
        assertEquals(Tokens("a3", "r3"), store.load()?.tokens(), "each rotation starts from the one before")
    }

    @Test
    fun aSupersededClientOfTheSameUserCannotOverwriteTheNewerPair() {
        // The autofill overlay read the session at r1; the main app rotated it to r2 since.
        stored("u1", access = "a2", refresh = "r2")
        val overlay = TokenOwner(home, "u1", heldRefreshToken = "r1")
        store.updateTokensFor(overlay, Tokens("a9", "r9"))
        assertEquals(Tokens("a2", "r2"), store.load()?.tokens())
    }

    @Test
    fun aSupersededClientOfTheSameUserCannotClearTheNewerSession() {
        stored("u1", access = "a2", refresh = "r2")
        val overlay = TokenOwner(home, "u1", heldRefreshToken = "r1")
        store.updateTokensFor(overlay, null) // its refresh was refused, or it logged out
        assertNotNull(store.load())
        assertEquals(0, store.clearCalls)
    }

    @Test
    fun aClientThatLostTheRaceTracksItsOwnPairAndStillCannotClear() {
        stored("u1", access = "a2", refresh = "r2")
        val overlay = TokenOwner(home, "u1", heldRefreshToken = "r1")
        store.updateTokensFor(overlay, Tokens("a9", "r9")) // not stored: the session moved on
        assertEquals("r9", overlay.heldRefreshToken, "it holds what the server gave it")
        store.updateTokensFor(overlay, null)
        assertNotNull(store.load(), "its later drop is about its own pair, not the stored one")
    }

    @Test
    fun aSupersededClientOfAnotherUserWritesNothing() {
        stored("u2", access = "b1", refresh = "s1") // another account signed in since
        store.updateTokensFor(TokenOwner(home, "u1", heldRefreshToken = "s1"), Tokens("a9", "r9"))
        assertEquals(Tokens("b1", "s1"), store.load()?.tokens(), "the user still has to match, whatever the token")
    }

    @Test
    fun aClientOfAnotherOriginWritesNothing() {
        stored("u1")
        store.updateTokensFor(TokenOwner("https://other.example", "u1", heldRefreshToken = "r1"), Tokens("a9", "r9"))
        assertEquals(Tokens("a1", "r1"), store.load()?.tokens())
    }

    @Test
    fun theHoldersDropEndsItsOwnSession() {
        stored("u1")
        store.updateTokensFor(TokenOwner("https://HOME.example:443/", "u1", heldRefreshToken = "r1"), null) // the canonical compare decides
        assertNull(store.load())
    }

    @Test
    fun aSignInWritesNothingUntilItsCallerCommitsTheSession() {
        val owner = TokenOwner(home) // built before its login
        stored("previous")
        store.updateTokensFor(owner, Tokens("login-a", "login-r"))
        assertEquals(Tokens("a1", "r1"), store.load()?.tokens(), "the login's own pair is saved by its caller, with the session")
        assertEquals("login-r", owner.heldRefreshToken)
        store.save(StoredSession(home, "u1", "u@example.com", "login-a", "login-r"))
        owner.userId = "u1"
        store.updateTokensFor(owner, Tokens("a2", "r2"))
        assertEquals(Tokens("a2", "r2"), store.load()?.tokens(), "from the commit on, its rotations are the session's")
    }

    @Test
    fun theStoreComparesAndWritesInOneStep() {
        stored("u1")
        assertFalse(store.replaceTokensIf(home, "u1", "r0", Tokens("x", "y")), "a stale expectation writes nothing")
        assertEquals(Tokens("a1", "r1"), store.load()?.tokens())
        assertTrue(store.replaceTokensIf(home, "u1", "r1", Tokens("a2", "r2")))
        assertEquals(Tokens("a2", "r2"), store.load()?.tokens())
    }

    @Test
    fun aSupersededClientsRefreshThroughTheApiLeavesTheNewSessionAlone() = runBlocking<Unit> {
        val headers = headersOf(HttpHeaders.ContentType, "application/json")
        val engine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/api/v1/auth/refresh" -> respond("""{"accessToken":"late-a","refreshToken":"late-r"}""", HttpStatusCode.OK, headers)
                "/api/v1/sync" ->
                    if (request.headers[HttpHeaders.Authorization] == "Bearer late-a") {
                        respond("""{"rev":1,"full":false,"vaults":[],"grants":[],"items":[],"removedGrants":[]}""", HttpStatusCode.OK, headers)
                    } else {
                        respond("""{"error":"unauthorized","message":"expired"}""", HttpStatusCode.Unauthorized, headers)
                    }
                else -> respond("""{"error":"not_found","message":"?"}""", HttpStatusCode.NotFound, headers)
            }
        }
        stored("u1")
        val owner = TokenOwner(home, "u1", heldRefreshToken = "r1")
        val superseded = AndvariApi(home, HttpClient(engine), Tokens("a1", "r1"), onTokens = { store.updateTokensFor(owner, it) })
        stored("u1", access = "b1", refresh = "s1") // the same account, rotated by another client since
        superseded.sync(0) // rotates late
        assertEquals(Tokens("b1", "s1"), store.load()?.tokens(), "the newer pair stays")
        superseded.close()
    }
}
