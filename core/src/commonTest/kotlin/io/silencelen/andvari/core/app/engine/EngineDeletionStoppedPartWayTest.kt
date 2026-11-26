package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A deletion the server confirmed and that the device stopped in part-way is finished at the next start: the deletion
 * writes a mark of a deletion begun before its first removal, and a start finishes what a mark names by the deletion's own
 * steps. Before, a stop between its steps left the server pinned and, in the ordinary case, the records kept by the
 * account's id; the next sign-in there met no first sight of the server.
 *
 * A stop is a process that ends at one write: that write and every one after it are not made.
 */
class EngineDeletionStoppedPartWayTest {
    private val k = SweepSteps(createCryptoProvider())
    private val uuid = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

    /** Both stores' whole key lists, every account id in a key written the same way (the ids differ from world to world). */
    private fun keyLists(w: SweepWorld): List<List<String>> =
        listOf(w.state.inner.keys(), w.secure.inner.keys()).map { keys -> keys.map { it.replace(uuid, "<id>") }.sorted() }

    /**
     * A stop at the [n]-th write (0: the first) over both stores of [w], counted from the first write [startsAt] names, or
     * from the write after the one [startsAfter] names.
     */
    private class Stop(
        val w: SweepWorld, val n: Int, val startsAt: (String, String?) -> Boolean, val startsAfter: (String, String?) -> Boolean = { _, _ -> false },
    ) {
        var started = false
        var count = 0
        var at: String? = null

        init {
            val hook: (String, String?) -> Unit = hook@{ key, value ->
                if (at != null) throw IllegalStateException("stopped")
                if (!started) {
                    if (startsAfter(key, value)) {
                        started = true
                        return@hook
                    }
                    if (!startsAt(key, value)) return@hook
                    started = true
                }
                if (count++ == n) {
                    at = key
                    throw IllegalStateException("stopped at $key")
                }
            }
            w.state.beforeSet = hook
            w.secure.beforeSet = hook
        }

        fun end() {
            w.state.beforeSet = null
            w.secure.beforeSet = null
        }
    }

    /** alice at h.example; with [beside], bob registered and signed out there first (the server stays known with him). */
    private suspend fun world(beside: Boolean): SweepWorld {
        val w = k.world()
        if (beside) {
            k.register(w.app, "h.example", k.bob)
            k.signOut(w.app)
        }
        w.u = k.register(w.app, "h.example", k.alice)
        return w
    }

    private suspend fun uncut(beside: Boolean): List<List<String>> {
        val w = world(beside)
        k.deleteAt(w, w.home)
        k.restart(w)
        assertNull(w.state.inner.get(EngineAccountSettings.DELETION_KEY), "the uncut deletion leaves no mark")
        assertEquals(emptyMap(), k.byId(w))
        return keyLists(w)
    }

    /**
     * The deletion stopped at the [n]-th write of its own steps; null where it has fewer writes. Its steps are counted from
     * the write after its mark of a deletion begun (a stop before the mark lands leaves the device as it was, as a stop
     * before the server's answer is read does), or, where no mark is written, from the keeper's note of the person's own
     * end.
     */
    private suspend fun stoppedDeletion(beside: Boolean, n: Int): Pair<SweepWorld, String>? {
        val w = world(beside)
        val stop = Stop(w, n, startsAt = { key, value -> key == SessionKeeper.OWN_ENDS_KEY && value != null },
            startsAfter = { key, value -> key == EngineAccountSettings.DELETION_KEY && value != null })
        val r = runCatching { k.deleteAt(w, w.home) }
        stop.end()
        val at = stop.at ?: run {
            r.getOrThrow()
            return null
        }
        return w to at
    }

    private suspend fun everyStopEndsAsTheUncut(beside: Boolean, label: String) {
        val expected = uncut(beside)
        val cutAt = ArrayList<String>()
        val bad = ArrayList<String>()
        var n = 0
        while (n < 200) {
            val (w, at) = stoppedDeletion(beside, n) ?: break
            cutAt += at.replace(uuid, "<id>")
            k.restart(w)
            if (keyLists(w) != expected || k.byId(w).isNotEmpty()) bad += "#$n $at: ${keyLists(w)}"
            n++
        }
        println("DELETION $label: stopped at $n writes: $cutAt")
        assertTrue(n > 5, "$label: the deletion's writes were cut ($n)")
        assertEquals(emptyList(), bad, "$label: each stop, then a start, ends as the uncut deletion $expected")
    }

    @Test fun aDeletionStoppedAtEachOfItsWritesIsFinishedAtTheNextStart() = runBlocking<Unit> {
        everyStopEndsAsTheUncut(beside = false, label = "one account at its server")
    }

    @Test fun aDeletionBesideAnotherAccountAtTheServerStoppedAtEachOfItsWritesIsFinishedAtTheNextStart() = runBlocking<Unit> {
        everyStopEndsAsTheUncut(beside = true, label = "beside another account there")
    }

    /** After the stop, the server is not trusted again without a first sight: its pin is gone with the deletion. */
    @Test fun afterAStoppedDeletionAndAStartTheServerIsNewToTheDevice() = runBlocking<Unit> {
        val (w, _) = assertNotNull(stoppedDeletion(beside = false, n = 3))
        k.restart(w)
        assertIs<PinState.None>(w.app.trust.pinState(w.home.origin))
    }

    /** A start that finishes a stopped deletion, itself stopped at each of its writes, is finished at the start after it. */
    @Test fun aStartThatFinishesAStoppedDeletionAndIsStoppedItselfIsFinishedAtTheNextStart() = runBlocking<Unit> {
        val expected = uncut(beside = false)
        val bad = ArrayList<String>()
        var n = 0
        while (n < 200) {
            val (w, _) = assertNotNull(stoppedDeletion(beside = false, n = 0))
            w.app.close()
            val stop = Stop(w, n, startsAt = { _, _ -> true })
            val cut = k.device(w, start = false)
            runCatching { cut.start() }
            cut.close()
            stop.end()
            val at = stop.at ?: break
            w.app = k.device(w)
            if (keyLists(w) != expected || k.byId(w).isNotEmpty()) bad += "#$n $at: ${keyLists(w)}"
            n++
        }
        println("DELETION a stopped start: stopped at $n writes")
        assertTrue(n > 3, "the start's writes were cut ($n)")
        assertEquals(emptyList(), bad)
    }

    /**
     * A mark of a deletion begun that does not read, met by a sweep, holds the sweep back, and nothing is removed; the next
     * start writes the record again without it (removing nothing for it), and the sweep goes on.
     */
    @Test fun aMarkThatCannotBeReadHoldsBackAndRemovesNothing() = runBlocking<Unit> {
        for (text in listOf("not a mark", """[["https://h.example","not an id","alice@example.com","tie:no","others:no",""]]""")) {
            val w = k.world()
            w.u = k.register(w.app, "h.example", k.alice)
            k.signOut(w.app)
            w.state.inner.set(SessionKeeper.EMAIL_BINDING_PREFIX + w.home.origin + "|" + k.alice, null)
            w.state.inner.set(EngineAccountSettings.DELETION_KEY, text)
            val before = w.state.snapshot()
            assertEquals(EngineAccountSettings.DELETION_KEY, assertIs<AccountSweep.Outcome.HeldBack>(w.app.sweepAccounts(), text).record, text)
            assertEquals(text, w.state.inner.get(EngineAccountSettings.DELETION_KEY), "$text: the mark stays as it is")
            assertEquals(before.filterKeys { key -> SWEEP_BY_ID.any { key.startsWith(it) } }, w.state.snapshot().filterKeys { key -> SWEEP_BY_ID.any { key.startsWith(it) } }, "$text: nothing kept by an id went")
            k.restart(w)
            assertNull(w.state.inner.get(EngineAccountSettings.DELETION_KEY), "$text: the start wrote the record again")
            assertEquals(emptyMap(), k.byId(w), "$text: the sweep went on: nothing names the account")
        }
    }

    /**
     * A deletion stopped before the keeper's end of the session, then the account signed out and signed in again in the
     * same run (a new take of the same account at the same server): the next start finds the mark and a session that is not
     * the one the deletion began with. Nothing of the new session's account goes; the mark does.
     */
    @Test fun aMarkForAnAccountSignedInToAgainDoesNotDeleteTheNewSessionsRecords() = runBlocking<Unit> {
        val (w, _) = assertNotNull(stoppedDeletion(beside = false, n = 0))
        assertEquals(w.u, assertNotNull(w.app.keeper.session).userId, "stopped before the keeper's end")
        k.signOut(w.app)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.home.origin, k.alice))
        assertEquals(w.u, assertNotNull(w.app.keeper.session).userId)
        val before = k.byId(w).keys
        assertTrue("ovh.identity|${w.u}" in before)
        k.restart(w)
        assertEquals(w.u, assertNotNull(w.app.keeper.session).userId, "the new session is kept")
        assertEquals(before, k.byId(w).keys, "what is kept by its id stays")
        assertEquals(w.u, w.state.inner.get(SessionKeeper.EMAIL_BINDING_PREFIX + w.home.origin + "|" + k.alice)?.substringBefore('|'))
        assertIs<PinState.Pinned>(w.app.trust.pinState(w.home.origin))
        assertNull(w.state.inner.get(EngineAccountSettings.DELETION_KEY), "the mark went")
    }
}
