package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.client.CoreLog
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
 * The sweep of records kept by the id of accounts the device no longer knows ([AccountSweep]): cut at each of its writes and
 * followed by a start, it ends as the uncut one; run again, it changes nothing; where it cannot list or cannot read what it
 * must, it removes nothing and says so in the diagnostic log; a session another process keeps in the secure store counts.
 */
class EngineAccountSweepCutTest {
    private val k = SweepSteps(createCryptoProvider())

    private class Lines : CoreLog {
        val lines = ArrayList<Pair<String, String>>()
        override fun warn(event: String, detail: String) {
            lines += event to detail
        }
    }

    /**
     * Records kept by the id of a deleted account, left because the store could not list its keys at the deletion: the
     * stores as they are then (state, secure), and the deleted account's id.
     */
    private suspend fun leftovers(): Triple<Map<String, String>, Map<String, String>, String> {
        val w = k.world()
        w.u = k.register(w.app, "h.example", k.alice)
        w.state.unlisted = true
        k.deleteAt(w, w.home)
        w.state.unlisted = false
        w.app.close()
        assertTrue(k.byId(w).size >= 4, "${k.byId(w)}")
        return Triple(w.state.snapshot(), w.secure.snapshot(), w.u)
    }

    /** A device over stores holding [state] and [secure], not started. */
    private fun from(state: Map<String, String>, secure: Map<String, String>): SweepWorld {
        val w = k.world()
        w.app.close()
        for (key in w.state.inner.keys()) w.state.inner.set(key, null)
        for (key in w.secure.inner.keys()) w.secure.inner.set(key, null)
        for ((key, v) in state) w.state.inner.set(key, v)
        for ((key, v) in secure) w.secure.inner.set(key, v)
        return w
    }

    @Test fun theSweepCutAtEachOfItsWritesAndFollowedByAStartEndsAsTheUncutSweep() = runBlocking<Unit> {
        val (state, secure, u) = leftovers()
        val ref = from(state, secure)
        ref.u = u
        ref.app = k.device(ref)
        k.restart(ref)
        assertEquals(emptyMap(), k.byId(ref), "the uncut sweep leaves nothing kept by the id")
        val refState = ref.state.snapshot()
        val refSecure = ref.secure.snapshot()
        val wrong = ArrayList<String>()
        var n = 0
        while (true) {
            val w = from(state, secure)
            w.u = u
            val log = Lines()
            w.state.failByIdRemoval = n
            w.app = k.device(w, start = false)
            w.app.diagnostics = log
            w.app.start()
            val failedOn = w.state.failedOn
            w.state.failByIdRemoval = -1
            if (failedOn == null) {
                println("SWEEP cut: write #$n: no failure, the sweep had $n writes")
                break
            }
            assertEquals(listOf(CoreLog.EVENT_ACCOUNT_SWEEP_STOPPED), log.lines.map { it.first }, "one line: the sweep stopped at $failedOn")
            assertTrue(failedOn in log.lines.single().second)
            k.restart(w)
            println("SWEEP cut: write #$n failed on $failedOn; after a start byId=${k.byId(w).keys}")
            if (w.state.snapshot() != refState || w.secure.snapshot() != refSecure) wrong += "#$n $failedOn"
            n++
        }
        assertTrue(n >= 4, "the sweep had several writes: $n")
        assertEquals(emptyList(), wrong, "a sweep cut at a write and followed by a start ends as the uncut sweep")
    }

    @Test fun theSweepRunTwiceChangesNothingTheSecondTime() = runBlocking<Unit> {
        val (state, secure, u) = leftovers()
        val w = from(state, secure)
        w.u = u
        w.app = k.device(w)
        assertEquals(emptyMap(), k.byId(w))
        val after = w.state.snapshot()
        val again = assertIs<AccountSweep.Outcome.Swept>(w.app.sweepAccounts())
        assertEquals(0, again.removed)
        assertEquals(after, w.state.snapshot())
        k.restart(w)
        assertEquals(after, w.state.snapshot(), "nor does the next start")
    }

    @Test fun aStoreThatCannotListItsKeysRemovesNothingAndSaysSoOnce() = runBlocking<Unit> {
        val (state, secure, u) = leftovers()
        val w = from(state, secure)
        w.u = u
        val log = Lines()
        w.state.unlisted = true
        w.app = k.device(w, start = false)
        w.app.diagnostics = log
        w.app.start()
        assertEquals(listOf(CoreLog.EVENT_ACCOUNT_SWEEP_HELD_BACK), log.lines.map { it.first })
        assertEquals(state.filterKeys { key -> SWEEP_BY_ID.any { key.startsWith(it) } }, k.byId(w))
        assertIs<AccountSweep.Outcome.HeldBack>(w.app.sweepAccounts())
    }

    @Test fun anAddressRecordThatCannotBeReadRemovesNothingAndSaysWhich() = runBlocking<Unit> {
        val (state, secure, u) = leftovers()
        val w = from(state, secure)
        w.u = u
        val bobs = SessionKeeper.EMAIL_BINDING_PREFIX + w.other.origin + "|" + k.bob
        w.state.inner.set(bobs, "22222222-2222-4222-8222-222222222222|" + "B".repeat(43) + "=")
        w.state.unreadable += bobs
        val log = Lines()
        w.app = k.device(w, start = false)
        w.app.diagnostics = log
        w.app.start()
        assertEquals(listOf(CoreLog.EVENT_ACCOUNT_SWEEP_HELD_BACK), log.lines.map { it.first })
        assertTrue(bobs in log.lines.single().second)
        assertEquals(state.filterKeys { key -> SWEEP_BY_ID.any { key.startsWith(it) } }, k.byId(w))
        w.state.unreadable.clear()
        k.restart(w)
        assertEquals(emptyMap(), k.byId(w), "read again, the next start sweeps")
    }

    /**
     * Another process over the same stores keeps a session for an account whose records no address record names (the
     * stand-in for a take with no address): this process's sweep reads the secure store and keeps them. A session record
     * it cannot read keeps everything too, and is said.
     */
    @Test fun aSessionAnotherProcessKeepsCountsAndOneThatCannotBeReadHoldsTheSweepBack() = runBlocking<Unit> {
        val w = k.world()
        val here = w.app
        val log = Lines()
        here.diagnostics = log
        val there = k.device(w)
        w.u = k.register(there, "h.example", k.alice)
        w.state.inner.set(SessionKeeper.EMAIL_BINDING_PREFIX + w.home.origin + "|" + k.alice, null)
        // Nor a copy held (the open copy's entry): only the session names the account.
        w.state.inner.set(EngineAppApi.HELD_KEY, null)
        val before = k.byId(w)
        assertNotNull(before["ovh.identity|${w.u}"])
        assertNull(here.keeper.session, "this process's keeper keeps no session")
        assertIs<AccountSweep.Outcome.Swept>(here.sweepAccounts())
        assertEquals(before, k.byId(w), "the session the secure store holds names the account")
        val kept = assertNotNull(w.secure.inner.get(SessionKeeper.KEY))
        w.secure.inner.set(SessionKeeper.KEY, "not a session record")
        assertIs<AccountSweep.Outcome.HeldBack>(here.sweepAccounts())
        assertEquals(before, k.byId(w))
        assertEquals(listOf(CoreLog.EVENT_ACCOUNT_SWEEP_HELD_BACK), log.lines.map { it.first })
        assertTrue(SessionKeeper.KEY in log.lines.single().second)
        w.secure.inner.set(SessionKeeper.KEY, kept)
        there.close()
        here.close()
    }
}
