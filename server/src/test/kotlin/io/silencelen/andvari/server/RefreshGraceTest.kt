package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.TokenPair
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame

/**
 * The 60-second refresh grace (spec 03 §2). A client whose refresh reply was lost holds only the spent token; before
 * the grace its next try was taken for theft and revoked the device, and the released Android app then wiped its local
 * copy, unsynced offline edits included (release 0.30.0 checklist, "Decisions that are yours", item 2). A repeat of the
 * same refresh within the window is now answered with the identical reply, while the pair it minted is untouched;
 * everything else is still reuse.
 */
class RefreshGraceTest : P4TestSupport() {

    private suspend fun HttpClient.refresh(token: String): HttpResponse = post("/api/v1/auth/refresh") {
        contentType(ContentType.Application.Json); setBody(RefreshRequest(token))
    }

    private suspend fun HttpResponse.pair(): TokenPair {
        assertEquals(HttpStatusCode.OK, status, bodyAsText())
        return json.decodeFromString(TokenPair.serializer(), bodyAsText())
    }

    @Test
    fun aRepeatOfALostReplyGetsTheIdenticalPairAndTheDeviceStaysSignedIn() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val session = client.register(VirtualClient("lost@x.com", "lost reply password", fast = true), bootstrapToken)

        val first = client.refresh(session.refreshToken).pair() // the reply the client never received
        val repeat = client.refresh(session.refreshToken).pair()
        assertEquals(first, repeat, "the identical reply")
        val again = client.refresh(session.refreshToken).pair()
        assertEquals(first, again, "every repeat inside the window, while the pair is untouched")

        // The pair works, and rotates on as usual: nothing was revoked.
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/sync?since=0") { authed(repeat.accessToken) }.status)
        val next = client.refresh(repeat.refreshToken).pair()
        assertNotEquals(repeat.refreshToken, next.refreshToken)
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/sync?since=0") { authed(next.accessToken) }.status)
        val types = services.repo.auditQuery(0, null, null, 100).map { it.type }
        assertEquals(2, types.count { it == "refresh_grace" }, "each repeat is audited")
        assertEquals(0, types.count { it == "refresh_reuse" })
    }

    @Test
    fun refreshesOfOneTokenAtTheSameMomentAllGetTheWinnersPair() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val session = client.register(VirtualClient("race@x.com", "race reply password", fast = true), bootstrapToken)

        val n = 8
        val pool = Executors.newFixedThreadPool(n)
        val barrier = CyclicBarrier(n)
        val outcomes = try {
            val futures = (1..n).map {
                pool.submit<Any> {
                    barrier.await()
                    try {
                        services.service.refresh(session.refreshToken, "198.51.100.7")
                    } catch (e: Unauthorized) {
                        "401"
                    }
                }
            }
            futures.map { it.get(60, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }
        assertEquals(1, outcomes.toSet().size, "one pair for all of them, no refusal: $outcomes")
        val pair = outcomes.first() as TokenPair
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/sync?since=0") { authed(pair.accessToken) }.status, "the device was not revoked")
    }

    @Test
    fun aRepeatAfterThePairWasUsedIsStillReuseAndRevokesTheDevice() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val session = client.register(VirtualClient("used@x.com", "used pair password", fast = true), bootstrapToken)

        val pair = client.refresh(session.refreshToken).pair()
        // The client received the reply and used it, so a later repeat of the old token is not a lost reply.
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/sync?since=0") { authed(pair.accessToken) }.status)
        val reuse = client.refresh(session.refreshToken)
        assertEquals(HttpStatusCode.Unauthorized, reuse.status)
        assertEquals("refresh_reuse", errorOf(reuse))
        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/v1/sync?since=0") { authed(pair.accessToken) }.status, "device revoked")
    }

    @Test
    fun aRepeatAfterTheNewPairWasRefreshedIsStillReuse() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val session = client.register(VirtualClient("rotated@x.com", "rotated pair password", fast = true), bootstrapToken)

        val pair = client.refresh(session.refreshToken).pair()
        val next = client.refresh(pair.refreshToken).pair()
        val reuse = client.refresh(session.refreshToken)
        assertEquals(HttpStatusCode.Unauthorized, reuse.status)
        assertEquals("refresh_reuse", errorOf(reuse))
        assertEquals(HttpStatusCode.Unauthorized, client.refresh(next.refreshToken).status, "the whole device is revoked")
    }

    @Test
    fun aRepeatAfterTheDeviceWasRevokedGetsNothing() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val session = client.register(VirtualClient("revoked@x.com", "revoked pair password", fast = true), bootstrapToken)

        client.refresh(session.refreshToken).pair()
        services.repo.db.tx { c -> c.exec("UPDATE sessions SET revokedAt=?", now()) } // an admin revoke, a password change elsewhere
        val repeat = client.refresh(session.refreshToken)
        assertEquals(HttpStatusCode.Unauthorized, repeat.status)
        assertEquals("session_revoked", errorOf(repeat))
    }

    @Test
    fun theWindowIsSixtySecondsAndAnEntryGoesAtFirstUseOrBeyondTheCap() {
        var t = 1_000_000L
        val grace = RefreshGrace(cap = 3, clock = { t })
        assertEquals(60_000L, RefreshGrace.WINDOW_MS)
        val pair = TokenPair("access-1", "refresh-1")
        grace.record("spent-1", pair, "s1", "d1")
        t += 60_000
        assertSame(pair, grace.lookup("spent-1")?.pair, "still inside at 60 s")
        t += 1
        assertNull(grace.lookup("spent-1"), "gone after 60 s")
        assertEquals(0, grace.size)

        grace.record("spent-2", TokenPair("access-2", "refresh-2"), "s2", "d1")
        grace.accessUsed(ServerCrypto.hashToken("access-other"))
        assertEquals(1, grace.size, "another token's use drops nothing")
        grace.accessUsed(ServerCrypto.hashToken("access-2"))
        assertNull(grace.lookup("spent-2"), "the pair was used: no grace")

        for (i in 3..7) { t += 1; grace.record("spent-$i", TokenPair("access-$i", "refresh-$i"), "s$i", "d1") }
        assertEquals(3, grace.size, "bounded")
        assertNull(grace.lookup("spent-3"), "the oldest go first")
        assertEquals("refresh-7", grace.lookup("spent-7")?.pair?.refreshToken)
        assertNull(RefreshGrace().lookup("spent-7"), "in memory only: a new server instance knows nothing")
    }
}
