package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * What the tool says of a change that waits and of a vault's deletion that waits, read from the change's own state, and
 * what a deletion keeps beside a request for the operator's help. Over the real server, the answers cut or lost by a proxy.
 */
class HeldChangeWordsTest {
    /** The server takes the change, and its answer is lost: the proxy forwards it and then breaks off. */
    private fun answerLost(p: LyingProxy) {
        p.answer = mapOf(WireRoute.LOG_APPEND to { _, forward -> forward(); throw java.io.IOException("the answer is lost") })
    }

    /** The server takes the change and answers; every read of a vault's log after it is cut, so it is not read back. */
    private fun notReadBack(p: LyingProxy) {
        p.answer = mapOf(WireRoute.LOG_APPEND to { _, forward ->
            val (status, body) = forward()
            p.cut = setOf(WireRoute.LOG_FETCH)
            status to String(body)
        })
    }

    private fun clear(p: LyingProxy) {
        p.answer = emptyMap()
        p.cut = emptySet()
    }

    /**
     * A change the server's own answer called stored and that this device has not read back is never "not sent again
     * after a day"; a deletion the server took is said deleted by `vault keep` and `vault send-deletion` once the sync that
     * runs first finds it, and a deletion the server's answer called stored is not "try again" at `vault keep`.
     */
    @Test fun aHeldChangeIsSaidByItsOwnState() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("holding@example.org")
                val bo = w.account("held@example.org")
                val (_, boId) = w.connect(me, bo)
                val shared = CliWorld.vaultId(w.run(me, "vault", "create", "Shared").ok())
                val stored = CliWorld.vaultId(w.run(me, "vault", "create", "Stored").ok())
                val lost = CliWorld.vaultId(w.run(me, "vault", "create", "Lost").ok())

                // (e) An addition the server answered as stored, not read back.
                notReadBack(p)
                val add = w.run(me, "vault", "add", shared, boId, dial = p.address)
                clear(p)
                assertEquals(1, add.code, add.out + add.err)
                assertTrue(add.err.contains("[$KEY_CHANGE_WAITS]: $CHANGE_WAITS_STORED"), add.err)

                // (d) A deletion the server answered as stored, not read back: keeping it cannot undo it, and "try again" is not said.
                notReadBack(p)
                val del = w.run(me, "vault", "delete", stored, dial = p.address)
                assertEquals(1, del.code, del.out + del.err)
                assertTrue(del.err.contains("[$KEY_DELETION_WAITS]: "), del.err)
                p.answer = emptyMap()
                p.cut = setOf(WireRoute.LOG_FETCH)
                val keepStored = w.run(me, "vault", "keep", stored, dial = p.address)
                clear(p)
                assertEquals(1, keepStored.code, keepStored.out + keepStored.err)
                assertTrue(keepStored.err.contains("[$KEY_DELETION_WAITS]: " + fill(DELETION_STORED_NOT_WITHDRAWN, stored)), keepStored.err)

                // (c) The sync that runs first finds the deletion made: send-deletion says the vault is deleted.
                val send = w.run(me, "vault", "send-deletion", stored)
                assertEquals(0, send.code, send.out + send.err)
                assertTrue(send.out.contains(fill(DELETION_MADE, stored)), send.out)

                // (c) A deletion whose answer was lost, taken by the server: keep says it is deleted and was not kept.
                answerLost(p)
                val delLost = w.run(me, "vault", "delete", lost, dial = p.address)
                clear(p)
                assertEquals(1, delLost.code, delLost.out + delLost.err)
                assertTrue(delLost.err.contains("[$KEY_DELETION_WAITS]: " + fill(DELETION_WAITS, lost)), delLost.err)
                val keepLost = w.run(me, "vault", "keep", lost)
                assertEquals(1, keepLost.code, keepLost.out + keepLost.err)
                assertTrue(keepLost.err.contains("[$KEY_DELETION_WAITS]: " + fill(DELETION_MADE_NOT_KEPT, lost)), keepLost.err)
                assertTrue(w.run(me, "vault", "list").ok().lines().none { it.startsWith(lost) || it.startsWith(stored) }, "both vaults are deleted")
            }
        }
    }

    /**
     * A deletion kept (`vault keep`) that the server had taken is in the vault's log after all: the next signed-in run says
     * so once, on a line of its own, and the run after it says nothing more. Before, nothing ever said it.
     */
    @Test fun aKeptDeletionTheServerHadTakenIsSaidMadeAfterAllOnce() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("afterall@example.org")
                val v = CliWorld.vaultId(w.run(me, "vault", "create", "After all").ok())
                answerLost(p)
                val del = w.run(me, "vault", "delete", v, dial = p.address)
                assertEquals(1, del.code, del.out + del.err)
                p.answer = emptyMap()
                p.cut = setOf(WireRoute.LOG_FETCH)
                val keep = w.run(me, "vault", "keep", v, dial = p.address)
                clear(p)
                assertEquals(0, keep.code, keep.out + keep.err)
                assertTrue(keep.out.contains(fill(DELETION_KEPT_MAYBE_MADE, v)), keep.out)

                val next = w.run(me, "vault", "list")
                assertEquals(0, next.code, next.out + next.err)
                assertEquals(1, next.err.split(fill(FOUND_DELETION_MADE_AFTER_ALL, v)).size - 1, next.err)
                val after = w.run(me, "vault", "list")
                assertEquals(0, after.code, after.out + after.err)
                assertTrue(!after.err.contains(fill(FOUND_DELETION_MADE_AFTER_ALL, v)), "said once: ${after.err}")
            }
        }
    }

    /**
     * (a) A request for the operator's help kept for another address at the server is something of another account kept
     * there: the deletion keeps the server and the request, and says so. Before, both went and the tool said that nothing
     * of another account was kept.
     */
    @Test fun aRequestForAnotherAddressKeepsTheServerAtADeletion() {
        val crypto = createCryptoProvider()
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey))).use { s ->
            val w = CliWorld(s)
            val other = "asking@example.org"
            w.run(w.account(other), "recovery", "operator", "--i-understand").ok()
            val a = File(w.tmp, "a")
            val seen = Steps.mailCount(s, other, "recovery_request_code")
            w.run(a, "recover", "assist", "--email", other, "--trust-card", w.card0, stdin = { Steps.awaitCode(s, other, "recovery_request_code", seen) }).ok()
            val request = "${Host.KEPT_ASSIST}${s.origin}"
            val kept = assertNotNull(CliHome(a).secureState().get(request), "the request is kept")

            val me = "deleted@example.org"
            s.advance(2 * 3_600_000L)
            w.run(a, "enrol", Steps.enrolLink(s, me), "--email", me, "--kit-out", File(w.tmp, "kit-me").path, "--trust-card", w.card0).ok()
            w.run(a, "sign-in", "--email", me, "--trust-card", w.card0).ok()
            val done = w.run(a, "account", "delete", "--confirm-email", me)
            assertEquals(0, done.code, done.out + done.err)
            assertTrue(done.out.contains(fill(DELETED_SERVER_KEPT, s.origin, fill(KEPT_OTHER_REQUEST, other))), done.out)
            assertEquals(kept, CliHome(a).secureState().get(request), "the request stays as it was")
            assertTrue(w.run(a, "whoami").ok().contains("server:  andvari"), "the pin stays")
        }
    }
}
