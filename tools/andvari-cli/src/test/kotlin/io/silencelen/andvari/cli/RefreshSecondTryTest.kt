package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.server.queryOne
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A refresh that got no answer is sent once more only within [Host.REFRESH_SECOND_TRY_MS] of its first try, in the same
 * run or a later one, and never after it nor a third time, against the real server with its test clock (the tool's clock
 * too). The mark is written before the refresh goes, so a run that ended while the refresh was out leaves it. Inside the
 * window the real server takes the replaced token again within its grace: one session at the server, no reuse. Past it
 * nothing is sent, and the next sign-in names the token ([SignInNamesReplacedSessionTest]).
 */
class RefreshSecondTryTest {
    private fun audits(s: TestServer, type: String, meta: String? = null): Long = s.services.db.read { c ->
        if (meta == null) c.queryOne("SELECT COUNT(*) FROM audit WHERE type=?", type) { it.getLong(1) }
        else c.queryOne("SELECT COUNT(*) FROM audit WHERE type=? AND meta=?", type, meta) { it.getLong(1) }
    } ?: 0L

    /** The account's sessions the server would still refresh. */
    private fun liveSessions(s: TestServer, userId: String): Long = s.services.db.read { c ->
        c.queryOne("SELECT COUNT(*) FROM sessions WHERE userId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL AND refreshExpiresAt>?",
            userId, s.now()) { it.getLong(1) }
    } ?: 0L

    private fun field(body: ByteArray, name: String): String? =
        runCatching { Json.parseToJsonElement(String(body)).jsonObject[name]?.jsonPrimitive?.content }.getOrNull()

    private fun refreshes(p: LyingProxy, since: Int) = p.seen.drop(since).count { it.contains(WireRoute.REFRESH.path) }

    /** Every file of [home], by its path inside it: the home as it stands. */
    private fun snapshot(home: File): Map<String, ByteArray> =
        home.walkTopDown().filter { it.isFile }.associate { it.relativeTo(home).path to it.readBytes() }

    /** [home] put back as [snap] had it (files written in place, so their owner-only modes stay; later files deleted). */
    private fun restore(home: File, snap: Map<String, ByteArray>) {
        home.walkTopDown().filter { it.isFile && it.relativeTo(home).path !in snap }.toList().forEach { it.delete() }
        for ((path, bytes) in snap) File(home, path).also { it.parentFile.mkdirs() }.writeBytes(bytes)
    }

    @Test fun aLostAnswerIsTriedOnceMoreInsideTheWindowAndTheServerKeepsOneSessionWithNoReuse() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val userId = w.userId("me@example.org")
                s.advance(2 * 3_600_000L)
                val sent = ArrayList<String?>()
                p.answer = mapOf(WireRoute.REFRESH to { body, forward ->
                    sent += field(body, "refreshToken")
                    assertEquals(200, forward().first, "the real server answered the refresh")
                    throw java.io.IOException("the answer is lost")
                })
                val reusesBefore = audits(s, "refresh_reuse")
                val gracesBefore = audits(s, "refresh_grace")
                val lost = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(1, lost.code, lost.out + lost.err)
                assertTrue(lost.err.contains("[$KEY_REFRESH_LOST]: " + fill(REFRESH_LOST, s.origin, "me@example.org", 50)), lost.err)
                assertEquals(1, sent.size, "one refresh was sent")

                // Inside the window (the edge counts as inside), the next run sends the same token once more.
                p.answer = mapOf(WireRoute.REFRESH to { body, forward ->
                    sent += field(body, "refreshToken")
                    forward().let { (status, text) -> status to String(text) }
                })
                s.advance(Host.REFRESH_SECOND_TRY_MS)
                val again = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(0, again.code, again.out + again.err)
                assertFalse(again.err.contains("session_refresh"), again.err)
                assertEquals(2, sent.size, "the second try was sent")
                assertEquals(sent[0], sent[1], "with the same token")
                assertEquals(1, liveSessions(s, userId), "one session at the server")
                assertEquals(reusesBefore, audits(s, "refresh_reuse"), "no reuse is recorded")
                assertEquals(gracesBefore + 1, audits(s, "refresh_grace"), "the server took it within its grace")

                // The mark is cleared by the answer: the next refresh is an ordinary one, with the new token.
                s.advance(2 * 3_600_000L)
                val later = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(0, later.code, later.out + later.err)
                assertEquals(3, sent.size)
                assertTrue(sent[2] != sent[1], "the rotated token")
                assertEquals(reusesBefore, audits(s, "refresh_reuse"), "still no reuse")
            }
        }
    }

    /**
     * A refresh the real server took, answered on the way back with [answer] (a page that is not the server's envelope, or
     * a body that does not read): the mark stays. Inside the window the token is sent once more and the session lives (one
     * session at the server, no reuse); after another such answer and a run past the window, nothing is sent.
     */
    private fun anAnswerNotInTheServersEnvelopeLeavesTheMark(answer: Pair<Int, String>) {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val userId = w.userId("me@example.org")
                val reusesBefore = audits(s, "refresh_reuse")
                val sent = ArrayList<String?>()
                val spoilt = mapOf(WireRoute.REFRESH to { body: ByteArray, forward: () -> Pair<Int, ByteArray> ->
                    sent += field(body, "refreshToken")
                    assertEquals(200, forward().first, "the real server took the refresh")
                    answer
                })
                s.advance(2 * 3_600_000L)
                p.answer = spoilt
                val first = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(1, first.code, first.out + first.err)
                assertTrue(first.err.contains("[$KEY_REFRESH_LOST]: " + fill(REFRESH_LOST, s.origin, "me@example.org", 50)), first.err)

                // Inside the window: the same token once more, and the session lives.
                p.answer = mapOf(WireRoute.REFRESH to { body, forward ->
                    sent += field(body, "refreshToken")
                    forward().let { (status, text) -> status to String(text) }
                })
                s.advance(20_000)
                val inside = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(0, inside.code, inside.out + inside.err)
                assertEquals(2, sent.size)
                assertEquals(sent[0], sent[1], "the same token, once more")
                assertEquals(1, liveSessions(s, userId), "one session at the server")
                assertEquals(reusesBefore, audits(s, "refresh_reuse"), "no reuse is recorded")

                // Past the window: nothing is sent.
                s.advance(2 * 3_600_000L)
                p.answer = spoilt
                assertEquals(1, w.run(me, "item", "list", "personal", dial = p.address).code)
                assertEquals(3, sent.size)
                s.advance(Host.REFRESH_SECOND_TRY_MS + 1)
                val mark = p.seen.size
                val after = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(1, after.code, after.out + after.err)
                assertTrue(after.err.contains("[$KEY_REFRESH_UNANSWERED]: " + fill(REFRESH_UNANSWERED, s.origin, "me@example.org")), after.err)
                assertEquals(emptyList(), p.seen.drop(mark), "nothing was sent")
                assertEquals(reusesBefore, audits(s, "refresh_reuse"), "still no reuse")
            }
        }
    }

    @Test fun aGatewaysPageInsteadOfTheServersAnswerLeavesTheMark() =
        anAnswerNotInTheServersEnvelopeLeavesTheMark(502 to "<html><body>502 Bad Gateway</body></html>")

    @Test fun aTwoHundredWhoseBodyDoesNotReadLeavesTheMark() = anAnswerNotInTheServersEnvelopeLeavesTheMark(200 to "{}")

    @Test fun aSecondTryWhoseAnswerIsLostTooIsNeverSentAThirdTime() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                s.advance(2 * 3_600_000L)
                var sent = 0
                p.answer = mapOf(WireRoute.REFRESH to { _, forward ->
                    sent++
                    forward()
                    throw java.io.IOException("the answer is lost")
                })
                assertEquals(1, w.run(me, "item", "list", "personal", dial = p.address).code)
                s.advance(1_000)
                val second = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(1, second.code, second.out + second.err)
                assertTrue(second.err.contains("[$KEY_REFRESH_UNANSWERED]"), second.err)
                assertEquals(2, sent)
                s.advance(1_000)
                val mark = p.seen.size
                val third = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(1, third.code, third.out + third.err)
                assertTrue(third.err.contains("[$KEY_REFRESH_UNANSWERED]: " + fill(REFRESH_UNANSWERED, s.origin, "me@example.org")), third.err)
                assertEquals(2, sent, "no third try")
                assertEquals(emptyList(), p.seen.drop(mark), "nothing was sent")
            }
        }
    }

    /**
     * The run ends while its refresh is out: the home is put back as it stood while the refresh was at the server (the
     * mark is on disk before the refresh goes). A new run inside the window sends it once more and works; after a second
     * such end and a run past the window, nothing is sent, and the sign-in names the token, which the server ends as replaced.
     */
    @Test fun aRunThatEndedWhileItsRefreshWasOutLeavesTheMarkForTheNextRunInsideAndAfterTheWindow() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val userId = w.userId("me@example.org")
                val reusesBefore = audits(s, "refresh_reuse")
                fun endWhileOut(): Pair<String, Map<String, ByteArray>> {
                    s.advance(2 * 3_600_000L)
                    var token: String? = null
                    var atSend: Map<String, ByteArray>? = null
                    p.answer = mapOf(WireRoute.REFRESH to { body, forward ->
                        token = field(body, "refreshToken")
                        atSend = snapshot(me)
                        forward()
                        throw java.io.IOException("the run ended")
                    })
                    w.run(me, "item", "list", "personal", dial = p.address)
                    val snap = assertNotNull(atSend, "a refresh was sent")
                    assertTrue(String(snap.getValue("secure-state.json")).contains("refreshOutAt"), "the mark was written before the refresh went")
                    restore(me, snap)
                    p.answer = emptyMap()
                    return assertNotNull(token) to snap
                }

                // Inside the window.
                val (first, _) = endWhileOut()
                s.advance(30_000)
                var sentAgain: String? = null
                p.answer = mapOf(WireRoute.REFRESH to { body, forward ->
                    sentAgain = field(body, "refreshToken")
                    forward().let { (status, text) -> status to String(text) }
                })
                val inside = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(0, inside.code, inside.out + inside.err)
                assertEquals(first, sentAgain, "the same token, once more")
                assertEquals(1, liveSessions(s, userId), "one session at the server")
                assertEquals(reusesBefore, audits(s, "refresh_reuse"), "no reuse")

                // After the window.
                val (second, _) = endWhileOut()
                s.advance(Host.REFRESH_SECOND_TRY_MS + 1)
                val mark = p.seen.size
                val after = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(1, after.code, after.out + after.err)
                assertTrue(after.err.contains("[$KEY_REFRESH_UNANSWERED]: " + fill(REFRESH_UNANSWERED, s.origin, "me@example.org")), after.err)
                assertEquals(emptyList(), p.seen.drop(mark), "nothing was sent")
                assertEquals(0, refreshes(p, mark))

                val namedBefore = audits(s, "session_end", "sign_in_named_replaced")
                var named: String? = null
                p.answer = mapOf(WireRoute.LOGIN to { body, forward ->
                    named = field(body, "replacesRefreshToken")
                    forward().let { (status, text) -> status to String(text) }
                })
                val signed = w.run(me, "sign-in", "--trust-card", w.card0, dial = p.address)
                assertEquals(0, signed.code, signed.out + signed.err)
                assertEquals(second, named, "the sign-in names the token that was out")
                assertEquals(namedBefore + 1, audits(s, "session_end", "sign_in_named_replaced"), "the server ends it as replaced")
                assertEquals(reusesBefore, audits(s, "refresh_reuse"), "no reuse")
                assertEquals(1, liveSessions(s, userId), "the new session only")
            }
        }
    }
}
