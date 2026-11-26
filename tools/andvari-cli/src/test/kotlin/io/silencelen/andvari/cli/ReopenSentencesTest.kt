package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The sentences of the reopening of a saved session, each by its key, over the real server. */
class ReopenSentencesTest {
    /** The server gives no answer to the reopening: nothing changed, the session is kept for the next try, and it works then. */
    @Test fun aReopeningWithNoAnswerKeepsTheSessionForTheNextTry() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("quiet@example.org")
                val before = CliHome(me).secureState().get("cli.session|${s.origin}|quiet@example.org")
                p.cut = setOf(WireRoute.ACCOUNT_KEYS)
                val r = w.run(me, "sync", dial = p.address)
                p.cut = emptySet()
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$KEY_SESSION_KEPT_NO_ANSWER]: " + fill(SESSION_KEPT_NO_ANSWER, s.origin)), r.err)
                assertEquals(before, CliHome(me).secureState().get("cli.session|${s.origin}|quiet@example.org"), "the session is kept as it was")
                w.run(me, "sync", dial = p.address).ok()
            }
        }
    }

    /** The account served under another key than the home's record of it, at the reopening: the key's own sentence. */
    @Test fun aReopeningUnderAnotherKeySaysTheKeysOwnSentence() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("reopen@example.org")
            val record = "${Host.CLI_IDENTITY}${s.origin}|${w.userId("reopen@example.org")}"
            CliHome(me).deviceState().set(record, Bytes.toB64(createCryptoProvider().randomBytes(32)))
            val r = w.run(me, "sync")
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$IDENTITY_KEY_NOT_KNOWN]: " + fill(IDENTITY_KEY_REFUSED_OPEN, s.origin, ACT_REOPEN)), r.err)
        }
    }
}
