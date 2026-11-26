package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.server.queryOne
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * What is left from the earlier run: a refresh of the session a run HOLDS (reopened at the start of the run, its access
 * token running out during it), whose answer is lost, against the real server with its test clock. [RefreshSecondTryTest]
 * loses the refresh the reopening itself sends; this one loses the held session's own ([Host.tokens]).
 */
class RefreshLostInOneRunTest {
    private fun audits(s: TestServer, type: String): Long = s.services.db.read { c ->
        c.queryOne("SELECT COUNT(*) FROM audit WHERE type=?", type) { it.getLong(1) }
    } ?: 0L

    private fun liveSessions(s: TestServer, userId: String): Long = s.services.db.read { c ->
        c.queryOne("SELECT COUNT(*) FROM sessions WHERE userId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL AND refreshExpiresAt>?",
            userId, s.now()) { it.getLong(1) }
    } ?: 0L

    private fun field(body: ByteArray, name: String): String? =
        runCatching { Json.parseToJsonElement(String(body)).jsonObject[name]?.jsonPrimitive?.content }.getOrNull()

    /**
     * The first refresh's answer is lost; any later one goes through. The run's next request sends the same token once
     * more itself (inside the window) and the run finishes: never a third send, one session at the server, no reuse
     * recorded, and the mark cleared by the answer.
     */
    @Test fun aRefreshOfTheHeldSessionLostInsideTheRunIsSentOnceMoreAndNeverReadAsReuse() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val userId = w.userId("me@example.org")
                val sent = ArrayList<String?>()
                var expired = false
                p.answer = mapOf(
                    // The reopening is answered while the access token is good; from then on it has run out.
                    WireRoute.ACCOUNT_KEYS to { _, forward ->
                        val (status, text) = forward()
                        if (!expired) { expired = true; s.advance(2 * 3_600_000L) }
                        status to String(text)
                    },
                    WireRoute.REFRESH to { body, forward ->
                        sent += field(body, "refreshToken")
                        val (status, text) = forward()
                        if (sent.size == 1) {
                            assertEquals(200, status, "the real server answered the refresh")
                            throw java.io.IOException("the answer is lost")
                        }
                        status to String(text)
                    },
                )
                val reusesBefore = audits(s, "refresh_reuse")
                val first = w.run(me, "item", "list", "personal", dial = p.address)
                assertTrue(expired, "the access token ran out inside the run")
                // The run's next request sends the same token once more, inside the window, and the run finishes.
                assertEquals(0, first.code, first.out + first.err)
                assertFalse(first.err.contains("session_refresh"), first.err)
                assertEquals(2, sent.size, "sent once more inside the run, and no third time")
                assertEquals(sent[0], sent[1], "the same token")
                val saved = CliHome(me).secureState().get("cli.session|${s.origin}|me@example.org")!!
                assertEquals(null, Json.parseToJsonElement(saved).jsonObject["refreshOutAt"]?.jsonPrimitive?.content?.toLongOrNull(), "the answer cleared the mark")
                assertEquals(1, liveSessions(s, userId), "one session at the server")
                assertEquals(reusesBefore, audits(s, "refresh_reuse"), "no reuse is recorded")
                p.answer = emptyMap()
                w.run(me, "item", "list", "personal").ok()
            }
        }
    }
}
