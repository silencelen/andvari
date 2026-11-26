package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A sign-in that gets no usable answer, against the real server through a lying proxy: the shared step has one word for
 * no answer and for an answer it could not use, and the tool tells the two apart. "Did not answer" only when the server
 * was not reached; an answer that could not be used (a server error with a proxy's page) is said as that.
 */
class SignInAnswerWordsTest {
    @Test fun aSignInAnsweredWithNothingUsable_isNotSaidAsAServerThatDidNotAnswer() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            w.account("bob@example.org")
            val home = w.home("bob2@example.org")
            p.answer = mapOf(WireRoute.LOGIN to { _, _ -> 500 to "<html>a proxy's page</html>" })
            val unusable = w.run(home, "sign-in", "--email", "bob@example.org", "--trust-card", w.card0, dial = p.address)
            assertEquals(1, unusable.code, unusable.out + unusable.err)
            assertTrue(unusable.err.contains(fill(SIGN_IN_UNUSABLE, s.origin)), unusable.err)
            assertFalse(unusable.err.contains("did not answer") || unusable.err.contains("wrong"), unusable.err)

            p.answer = emptyMap()
            p.cut = setOf(WireRoute.LOGIN)
            val gone = w.run(home, "sign-in", "--email", "bob@example.org", "--trust-card", w.card0, dial = p.address)
            assertEquals(1, gone.code, gone.out + gone.err)
            assertTrue(gone.err.contains("the server did not answer"), gone.err)
            assertFalse(gone.err.contains(fill(SIGN_IN_UNUSABLE, s.origin)), gone.err)
        } }
    }
}
