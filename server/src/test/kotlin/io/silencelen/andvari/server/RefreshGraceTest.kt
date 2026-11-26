package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The sixty-second grace for a refresh that is repeated (spec 03 §2, decided for 0.30.0 on 2026-11-15 and for this line
 * on 2026-11-17), on a driven clock. A refresh whose answer was lost leaves the client holding only the token the server
 * has replaced; before, presenting it again was taken for a reuse at once, every session of the device ended, and the
 * person was signed out with a reuse on record that was no theft. Now, within sixty seconds of the replacement (inclusive),
 * on its own device row, while the pair that replaced it is untouched, the repeat is answered with that same pair. After
 * the window, once the pair was used or refreshed, or for an entry of another row, the reuse rule stands as it is.
 */
class RefreshGraceTest {
    private val post = HttpMethod.Post

    private suspend fun HttpClient.refresh(token: String): HttpResponse = call(post, "/api/v1/auth/refresh", """{"refreshToken":"$token"}""")

    private suspend fun HttpResponse.pair(): TokenPair {
        assertEquals(200, status.value, bodyAsText())
        return WireJson.json.decodeFromString(TokenPair.serializer(), bodyAsText())
    }

    private fun reuses(s: Services) = s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='refresh_reuse'") }
    /** The device's sessions that can still be used: not ended, not replaced by a refresh. */
    private fun live(s: Services, deviceId: String) =
        s.db.read { it.count("SELECT COUNT(*) FROM sessions WHERE deviceId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL", deviceId) }

    private class World(val s: Services, val clock: MutableClock, val me: Me, val replaced: String, val lost: TokenPair)

    /** A member refreshes once and the answer is "lost": the client still holds [World.replaced]. */
    private suspend fun ApplicationTestBuilder.world(): World {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        Flow.finishSetup(client, s)
        val me = Flow.member(client, s, "me@example.com")
        val replaced = me.session!!.refreshToken
        val lost = client.refresh(replaced).pair()
        return World(s, clock, me, replaced, lost)
    }

    /** The repeat is reuse: every session of the device ends, with one record. */
    private suspend fun assertReuse(w: World, r: HttpResponse, what: String) {
        assertEquals(401, r.status.value, "$what: ${r.bodyAsText()}")
        assertEquals("refresh_reuse", r.errorCode(), what)
        assertEquals(1L, reuses(w.s), what)
        assertEquals(0L, live(w.s, w.me.deviceId), what)
        assertEquals(0L, w.s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='refresh_grace'") }, "$what: no grace answer recorded")
    }

    @Test
    fun aRepeatInsideTheMinute_getsTheSamePair_isNoReuse_andThePairStillWorks() = testApplication {
        val w = world()
        w.clock.advance(30_000)
        val again = client.refresh(w.replaced).pair()
        assertEquals(w.lost, again, "the same pair, not a fresh one")
        // A second repeat in the minute gets it too: the pair is still untouched.
        w.clock.advance(10_000)
        assertEquals(w.lost, client.refresh(w.replaced).pair())
        assertEquals(0L, reuses(w.s))
        assertEquals(1L, live(w.s, w.me.deviceId))
        // The pair is the person's: it refreshes as any pair does.
        client.refresh(w.lost.refreshToken).pair()
    }

    @Test
    fun aRepeatAtTheMinutesEdge_isAnswered() = testApplication {
        val w = world()
        w.clock.advance(RefreshGrace.WINDOW_MS)
        assertEquals(w.lost, client.refresh(w.replaced).pair())
        assertEquals(0L, reuses(w.s))
    }

    @Test
    fun aRepeatAfterTheMinute_isTheReuse() = testApplication {
        val w = world()
        w.clock.advance(RefreshGrace.WINDOW_MS + 1)
        assertReuse(w, client.refresh(w.replaced), "one millisecond after the minute")
    }

    /**
     * The grace answers only on the token's own device row. The refresh carries nothing but the token, so another row is
     * reached by an entry that names another row than the token's (as a bug that keyed entries wrongly would make): the
     * repeat is then the reuse.
     */
    @Test
    fun anEntryOfAnotherRow_isNotAnswered() = testApplication {
        val w = world()
        val other = Flow.member(client, w.s, "other@example.com")
        val successor = w.s.db.read { c -> c.queryOne("SELECT sessionId FROM sessions WHERE accessHash=?", ServerCrypto.hashToken(w.lost.accessToken)) { it.getString(1) } }!!
        w.s.sessions.refreshGrace.record(ServerCrypto.hashToken(w.replaced), w.lost, successor, other.deviceId)
        w.clock.advance(1_000)
        assertReuse(w, client.refresh(w.replaced), "an entry naming another row")
    }

    @Test
    fun aRepeatAfterThePairWasUsed_isTheReuse() = testApplication {
        val w = world()
        // The client got the answer after all and used it: a later repeat is no lost answer.
        assertEquals(200, client.call(HttpMethod.Get, "/api/v1/account/keys", token = w.lost.accessToken).status.value)
        w.clock.advance(1_000)
        assertReuse(w, client.refresh(w.replaced), "after the pair authenticated a request")
    }

    @Test
    fun aRepeatAfterThePairWasRefreshed_isTheReuse_asBefore() = testApplication {
        val w = world()
        client.refresh(w.lost.refreshToken).pair()
        w.clock.advance(1_000)
        assertReuse(w, client.refresh(w.replaced), "after the pair itself was refreshed")
    }

    /**
     * The pair's session ended (as a sign-in that names the replaced token ends it): the repeat is never answered with a
     * dead pair; it is the reuse, as before.
     */
    @Test
    fun aRepeatAfterThePairsSessionEnded_isTheReuse() = testApplication {
        val w = world()
        w.s.db.tx { c -> c.exec("UPDATE sessions SET revokedAt=? WHERE accessHash=?", w.clock.now(), ServerCrypto.hashToken(w.lost.accessToken)) }
        w.clock.advance(1_000)
        assertReuse(w, client.refresh(w.replaced), "after the pair's session ended")
    }

    /**
     * Each answer inside the grace is recorded as `refresh_grace`, as on the released line (decided on 2026-11-17): the
     * account, the device and the caller's address, and nothing else (no token, no session id). Before, nothing was
     * recorded, so a replaced token presented again and answered left no trace for the operator or the person.
     */
    @Test
    fun eachAnswerInsideTheMinute_isRecorded_asTheReleasedLineRecordsIt() = testApplication {
        val w = world()
        w.clock.advance(5_000)
        client.refresh(w.replaced).pair()
        w.clock.advance(5_000)
        client.refresh(w.replaced).pair()
        val rows = w.s.db.read { c ->
            c.queryAll("SELECT userId,deviceId,ip,meta FROM audit WHERE type='refresh_grace' ORDER BY id") { rs ->
                listOf(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4))
            }
        }
        assertEquals(2, rows.size, "one row per answer: $rows")
        for (row in rows) {
            assertEquals(listOf(w.me.userId, w.me.deviceId), row.take(2), "$row")
            assertTrue(!row[2].isNullOrBlank(), "the caller's address is recorded: $row")
            assertEquals(null, row[3], "nothing else: $row")
        }
        assertTrue("refresh_grace" in AuditKinds.ALL, "the consoles are served the kind")
        assertTrue("refresh_grace" in AccountDeletion.RETAINED_AUDIT_TYPES, "kept with the account's security record, as refresh_reuse is")
    }

    /**
     * The grace draws the caller address's refresh allowance, as on the released line (decided on 2026-11-17). Before,
     * a replaced token inside its window drew nothing: five hundred repeats from one address were all answered, each taking
     * the server's database lock. Now the address's thirty a minute are answered and the rest refused as too many; the
     * pair is still the person's.
     */
    @Test
    fun repeatsInsideTheMinute_drawTheAddressesAllowance() = testApplication {
        val w = world()
        val ip = "10.7.7.7"
        val codes = (1..500).map {
            val r = client.call(post, "/api/v1/auth/refresh", """{"refreshToken":"${w.replaced}"}""", ip = ip)
            if (r.status.value == 200) "200" else "${r.status.value} ${r.errorCode()}"
        }
        val allowance = REFRESH_ADDRESS_BUCKET.limit
        assertEquals(List(allowance) { "200" }, codes.take(allowance))
        assertEquals(List(500 - allowance) { "429 rate_limited" }, codes.drop(allowance))
        assertEquals(allowance.toLong(), w.s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='refresh_grace'") })
        assertEquals(0L, reuses(w.s))
        // Another address is not held up by it, and the pair refreshes as any pair does.
        assertEquals(w.lost, client.call(post, "/api/v1/auth/refresh", """{"refreshToken":"${w.replaced}"}""", ip = "10.7.7.8").pair())
        client.refresh(w.lost.refreshToken).pair()
    }

    /**
     * The pair the grace keeps is dropped when its window ends, not only when a later refresh or a lookup of the same token
     * comes by (decided on 2026-11-17): the server's sweep, every second, drops it. Before, an unused pair was still held
     * in plain text an hour later on a server where nothing else was refreshed.
     */
    @Test
    fun thePairIsDropped_whenItsWindowEnds() = testApplication {
        val w = world()
        val grace = w.s.sessions.refreshGrace
        assertEquals(1, grace.size)
        w.clock.advance(RefreshGrace.WINDOW_MS)
        grace.sweepExpired()
        assertEquals(1, grace.size, "kept for the whole minute")
        w.clock.advance(1)
        grace.sweepExpired()
        assertEquals(0, grace.size, "dropped once the minute has passed, with no other refresh or lookup")
        w.clock.advance(3_600_000)
        grace.sweepExpired()
        assertEquals(0, grace.size)
    }

    /** The window is kept in memory: a server that starts again keeps no entry, and the repeat is the reuse. */
    @Test
    fun aRestartForgetsTheWindow() {
        val grace = RefreshGrace(MutableClock(0))
        grace.record("h", TokenPair("a", "r"), "s", "d")
        assertEquals("s", grace.lookup("h")?.successorSessionId)
        assertEquals(null, RefreshGrace(MutableClock(0)).lookup("h"))
    }
}
