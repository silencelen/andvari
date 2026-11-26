package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A vault's deletion that got no answer, over the real server: the tool says what is so (it waits for the person's word
 * and is never sent again by itself, and the vault takes no other change from here meanwhile), and the two commands send
 * it now or keep the vault. Before, the tool said that it was kept and re-sent on the next run, which no run did.
 */
class WaitingDeletionTest {
    private fun appendsSince(p: LyingProxy, mark: Int): Int =
        p.seen.drop(mark).count { it.startsWith("POST ") && LyingProxy.pathOf(WireRoute.LOG_APPEND).matches(it.substringAfter(' ').substringBefore('?')) }

    @Test fun aDeletionWithNoAnswerWaitsForTheWordAndIsSentOrKept() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("deleting@example.org")
                val gone = CliWorld.vaultId(w.run(me, "vault", "create", "Gone").ok())
                val kept = CliWorld.vaultId(w.run(me, "vault", "create", "Kept").ok())

                p.cut = setOf(WireRoute.LOG_APPEND)
                val r = w.run(me, "vault", "delete", gone, dial = p.address)
                p.cut = emptySet()
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$KEY_DELETION_WAITS]: " + fill(DELETION_WAITS, gone)), r.err)

                // Not sent by itself: the next change to the vault stops on it, and nothing is sent.
                val mark = p.seen.size
                val next = w.run(me, "vault", "delete", gone, dial = p.address)
                assertEquals(1, next.code, next.out + next.err)
                assertTrue(next.err.contains("[$KEY_DELETION_WAITS]: " + fill(DELETION_WAITS, gone)), next.err)
                assertEquals(0, appendsSince(p, mark), "nothing was sent")

                // The person's word: sent now, and made.
                val sent = w.run(me, "vault", "send-deletion", gone)
                assertEquals(0, sent.code, sent.out + sent.err)
                assertTrue(sent.out.contains(fill(DELETION_MADE, gone)), sent.out)
                assertTrue(w.run(me, "vault", "list").ok().lines().none { it.startsWith(gone) }, "the vault is gone")

                // Or the vault kept: the deletion is withdrawn and never sent; the vault stays and takes changes again.
                p.cut = setOf(WireRoute.LOG_APPEND)
                assertEquals(1, w.run(me, "vault", "delete", kept, dial = p.address).code)
                p.cut = emptySet()
                val keep = w.run(me, "vault", "keep", kept)
                assertEquals(0, keep.code, keep.out + keep.err)
                assertTrue(keep.out.contains(fill(DELETION_KEPT_MAYBE_MADE, kept)), keep.out)
                assertTrue(w.run(me, "vault", "list").ok().lines().any { it.startsWith(kept) }, "the vault stays")
                val none = w.run(me, "vault", "send-deletion", kept)
                assertEquals(1, none.code, none.out + none.err)
                assertTrue(none.err.contains("[$KEY_DELETION_WAITS]: " + fill(NO_DELETION_WAITS, kept)), none.err)
            }
        }
    }

    /** Any other change that got no answer: said as the engine treats it (sent again only before the next change, within a day). */
    @Test fun anotherChangeWithNoAnswerSaysWhenItIsSentAgain() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("adding@example.org")
                val bo = w.account("added@example.org")
                val (_, boId) = w.connect(me, bo)
                val v = CliWorld.vaultId(w.run(me, "vault", "create", "Shared").ok())
                p.cut = setOf(WireRoute.LOG_APPEND)
                val r = w.run(me, "vault", "add", v, boId, dial = p.address)
                p.cut = emptySet()
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$KEY_CHANGE_WAITS]: $CHANGE_WAITS"), r.err)
            }
        }
    }
}
