package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The shared code hands a session's tokens over once ([EstablishedSession.takeTokens]) and rebuilds a kept session only
 * through its public factory ([EstablishedSession.reopened]). The tool takes the tokens at its session sink; a session
 * whose tokens were already handed over is not held and stops in words; a saved session the factory will not rebuild is
 * "unusable: sign in again", in words, and signing in again continues.
 */
class SessionHandoverTest {
    @Test fun aSessionWhoseTokensWereAlreadyHandedOverIsNotHeldAndStopsInWords() {
        TestServer().use { s -> s.journey {
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val me = s.device("me")
            Steps.registerThrough(me, s.origin, Steps.enrolLink(s), "me@example.org", trustGate = true)
            val h = me.session(s.origin)!!
            assertTrue(h.accessToken.isNotEmpty() && h.refreshToken.isNotEmpty(), "the sink took the tokens")
            assertEquals(null, h.session.takeTokens(), "the tokens were handed over once, to the sink")

            // The same session handed in again: refused in words, and the session held is untouched, its keys too.
            val again = assertFailsWith<CliError> { me.sink.established(h.session) }
            assertTrue(again.message!!.contains("already been handed over") && again.message!!.contains("sign in again"), again.message)
            assertSame(h, me.session(s.origin), "the session held is still the first")
            assertIs<ReauthKey.Key>(me.reauth(h).currentAuthKey(Steps.PASSWORD.toCharArray()), "its keys are not wiped")

            // A session rebuilt from kept tokens hands none out: handed to the sink, it is refused the same way.
            val saved = SavedSessions(me.secure)
            saved.save(h)
            val other = Host(me.state, me.secure, s::now, http = s.httpFor(), deviceName = "me")
            assertEquals(SavedSessions.Reopen.Reopened, saved.reopen(other, s.origin, "me@example.org", Steps.PASSWORD.toCharArray()))
            val rebuilt = other.session(s.origin)!!
            assertEquals(null, rebuilt.session.takeTokens(), "a rebuilt session hands out no tokens")
            assertFailsWith<CliError> { other.sink.established(rebuilt.session) }
            assertSame(rebuilt, other.session(s.origin))
            assertIs<ReauthKey.Key>(other.reauth(rebuilt).currentAuthKey(Steps.PASSWORD.toCharArray()), "the rebuilt session proves the password")
        } }
    }

    @Test fun aSavedSessionThatCannotBeRebuiltIsUnusableInWordsAndSigningInAgainContinues() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val secure = CliHome(me).secureState()
            val key = "cli.session|${s.origin}|me@example.org"
            val kept = secure.get(key)!!
            // What the device kept no longer makes a session (here, a way of signing in the tool does not know).
            val broken = Regex("\"how\":\"[A-Z]+\"").replace(kept, "\"how\":\"SOMEHOW\"")
            assertTrue(broken != kept, kept)
            secure.set(key, broken)

            val r = w.run(me, "item", "list", "personal")
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("is unusable") && r.err.contains("andvari-cli sign-in"), r.err)
            assertFalse(r.err.contains("Exception"), r.err)

            val again = w.run(me, "sign-in", "--trust-card", w.card0)
            assertEquals(0, again.code, again.err)
            assertTrue(again.err.contains("unusable; signing in again"), again.err)
            w.run(me, "item", "list", "personal").ok()
            assertTrue(secure.get(key)!!.contains("\"how\":\"PASSWORD\""), "the sign-in replaced the saved session")
            w.tmp.deleteRecursively()
        }
    }
}
