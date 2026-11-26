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
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A sign-in names the session it replaces, and the real server ends that one with the sign-in. Through a proxy that loses
 * the answer to a refresh: the server rotated the saved session's tokens, the home still holds the replaced refresh token.
 * Past the window for one more try the tool never sends that token to the refresh again (the server would read it as a
 * stolen token's reuse and end every session of the device): the command stops, having sent nothing, and says to sign in.
 * The sign-in names the token the home holds; the server ends that session and records it as a named, replaced one; no
 * reuse is recorded, and the new session works. ([RefreshSecondTryTest] has the try inside the window.)
 */
class SignInNamesReplacedSessionTest {
    private fun audits(s: TestServer, type: String, meta: String? = null): Long = s.services.db.read { c ->
        if (meta == null) c.queryOne("SELECT COUNT(*) FROM audit WHERE type=?", type) { it.getLong(1) }
        else c.queryOne("SELECT COUNT(*) FROM audit WHERE type=? AND meta=?", type, meta) { it.getLong(1) }
    } ?: 0L

    private fun field(body: ByteArray, name: String): String? =
        runCatching { Json.parseToJsonElement(String(body)).jsonObject[name]?.jsonPrimitive?.content }.getOrNull()

    @Test fun aSignInAfterALostRefreshAnswerNamesTheTokenTheHomeHoldsAndTheServerEndsThatSessionAsReplaced() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                // The access token has run out, so the next command refreshes; the server answers, the answer is lost.
                s.advance(2 * 3_600_000L)
                var replaced: String? = null
                p.answer = mapOf(WireRoute.REFRESH to { body, forward ->
                    replaced = field(body, "refreshToken")
                    val (status, _) = forward()
                    assertEquals(200, status, "the real server answered the refresh")
                    // The connection closes with nothing answered: the answer is lost on the road.
                    throw java.io.IOException("the answer is lost")
                })
                val reusesBefore = audits(s, "refresh_reuse")
                val namedBefore = audits(s, "session_end", "sign_in_named_replaced")
                val lost = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(1, lost.code, lost.out + lost.err)
                assertTrue(lost.err.contains("[$KEY_REFRESH_LOST]: " + fill(REFRESH_LOST, s.origin, "me@example.org", 50)), lost.err)
                val token = assertNotNull(replaced, "the refresh was sent")

                // Past the window, another command sends nothing with the replaced token.
                p.answer = emptyMap()
                s.advance(Host.REFRESH_SECOND_TRY_MS + 1)
                val mark = p.seen.size
                val again = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(1, again.code, again.out + again.err)
                assertTrue(again.err.contains("[$KEY_REFRESH_UNANSWERED]: " + fill(REFRESH_UNANSWERED, s.origin, "me@example.org")), again.err)
                assertEquals(emptyList(), p.seen.drop(mark), "nothing was sent")

                // The sign-in names the token the home holds.
                var named: String? = null
                p.answer = mapOf(WireRoute.LOGIN to { body, forward ->
                    named = field(body, "replacesRefreshToken")
                    forward().let { (status, text) -> status to String(text) }
                })
                val signed = w.run(me, "sign-in", "--trust-card", w.card0, dial = p.address)
                assertEquals(0, signed.code, signed.out + signed.err)
                assertTrue(signed.err.contains(fill(REFRESH_UNANSWERED_SIGN_IN, s.origin, "me@example.org")), signed.err)
                assertEquals(token, named, "the login names the token the home still holds")
                assertEquals(namedBefore + 1, audits(s, "session_end", "sign_in_named_replaced"), "the end is recorded as a named, replaced token")
                assertEquals(reusesBefore, audits(s, "refresh_reuse"), "no reuse is recorded")
                val ends = listOf(WireRoute.END_SESSION.path, WireRoute.LOGOUT.path)
                assertTrue(p.seen.none { seen -> ends.any { seen.contains(it) } }, "no end-session and no sign-out from this home: ${p.seen}")

                // The new session works, through a refresh of its own.
                p.answer = emptyMap()
                s.advance(2 * 3_600_000L)
                val before = p.seen.size
                val after = w.run(me, "item", "list", "personal", dial = p.address)
                assertEquals(0, after.code, after.out + after.err)
                assertFalse(after.err.contains(KEY_REFRESH_UNANSWERED), after.err)
                assertNotEquals(0, p.seen.drop(before).count { it.contains(WireRoute.REFRESH.path) }, "the new session refreshed")
                assertEquals(reusesBefore, audits(s, "refresh_reuse"), "still no reuse")
            }
        }
    }

    /** A home that keeps no session for the address names none: the login carries no token. */
    @Test fun aSignInOnAHomeThatKeepsNoSessionNamesNone() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                assertEquals(0, w.run(me, "sign-out", "--email", "me@example.org").code)
                var sent: ByteArray? = null
                p.answer = mapOf(WireRoute.LOGIN to { body, forward ->
                    sent = body
                    forward().let { (status, text) -> status to String(text) }
                })
                val signed = w.run(me, "sign-in", "--email", "me@example.org", "--trust-card", w.card0, dial = p.address)
                assertEquals(0, signed.code, signed.out + signed.err)
                assertEquals(null, field(assertNotNull(sent, "a login was sent"), "replacesRefreshToken"))
            }
        }
    }
}
