package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A deletion the server confirmed and a stop cut part-way ends at a later take that uses what it would remove: a take at
 * the deletion's server of the deleted account, or of any account under the address the deleted account was known by
 * there, removes the mark of the deletion begun before it writes anything of its own, and nothing is removed for a mark
 * that ended. Before, only a session still kept at the next start told a later take apart, so a take followed by a
 * sign-out (or a lost session record) before that start had its address record, its identity record, what is kept by its
 * id and the server's pin removed: the next sign-in there was a first sight the server chose.
 *
 * A take at that server of another account under another address does not end the mark (the deletion finishes, and that
 * account and the server's pin are untouched); nor does a take of the same account at another server.
 *
 * A stop is a process that ends at one write: that write and every one after it are not made.
 */
class EngineDeletionEndsAtATakeTest {
    private val k = SweepSteps(createCryptoProvider())
    private val h = "https://h.example"

    private class Stop(val w: SweepWorld, val n: Int, val startsAt: (String, String?) -> Boolean, val startsAfter: (String, String?) -> Boolean = { _, _ -> false }) {
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

    /** alice at h.example (the same instance served at other.example too with [sameInstance]). */
    private suspend fun world(sameInstance: Boolean = false): SweepWorld {
        val w = k.world(sameInstance = sameInstance)
        w.u = k.register(w.app, "h.example", k.alice)
        return w
    }

    /** alice's deletion at h.example, stopped at its first write after the mark (the keeper's note of the own end). */
    private suspend fun stopBeforeTheKeepersEnd(w: SweepWorld) {
        val stop = Stop(w, 0, startsAt = { key, value -> key == SessionKeeper.OWN_ENDS_KEY && value != null },
            startsAfter = { key, value -> key == EngineAccountSettings.DELETION_KEY && value != null })
        runCatching { k.deleteAt(w, w.home) }
        stop.end()
        assertEquals(SessionKeeper.OWN_ENDS_KEY, stop.at, "the deletion stopped after its mark")
        assertNotNull(mark(w), "the mark of the deletion begun stands")
    }

    private fun mark(w: SweepWorld) = w.state.inner.get(EngineAccountSettings.DELETION_KEY)

    /** The readable entries of the mark that name [origin] with [userId] or [email]. */
    private fun marksFor(w: SweepWorld, origin: String, userId: String, email: String) =
        mark(w)?.let { EngineAccountSettings.deletionEntries(it) }.orEmpty().filterNotNull()
            .filter { it.origin == origin && (it.userId == userId || it.emailNorm == email) }

    private fun addr(w: SweepWorld, origin: String = h, email: String = k.alice) =
        w.state.inner.get(SessionKeeper.EMAIL_BINDING_PREFIX + origin + "|" + email)?.substringBefore('|')

    /** The server serves another account under alice's address; the device meets it, forgets the earlier one and signs in. */
    private suspend fun anotherAccountUnderTheAddress(w: SweepWorld): String {
        w.home.accounts.remove(k.alice)
        val v = k.register(k.otherDevice(w.home), "h.example", k.alice)
        assertNotEquals(w.u, v)
        assertEquals(SignInAnswer.IDENTITY_FAULT, k.signInAt(w.app, h, k.alice))
        assertEquals(ForgetEarlierResult.FORGOTTEN, k.forgetEarlier(w))
        assertNotNull(mark(w), "the deletion's mark stands up to the take")
        return v
    }

    /** What protects the account [v] signed out at h.example under alice's address. */
    private fun keepsWhatProtects(w: SweepWorld, v: String, label: String) {
        assertEquals(v, addr(w), "$label: the signed-out account's address record stays")
        assertTrue(k.byId(w, v).containsKey("ovh.identity|$v"), "$label: its identity record stays: ${k.byId(w, v).keys}")
        assertIs<PinState.Pinned>(w.app.trust.pinState(h), "$label: the server stays pinned")
        assertNull(mark(w), "$label: no mark is left")
    }

    @Test fun theSameAccountSignedInAgainAndOutBeforeTheNextStartKeepsItsRecords() = runBlocking<Unit> {
        val w = world()
        stopBeforeTheKeepersEnd(w)
        k.signOut(w.app)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, h, k.alice))
        k.signOut(w.app)
        val before = k.byId(w).keys
        k.restart(w)
        keepsWhatProtects(w, w.u, "signed in again and out")
        assertEquals(before, k.byId(w).keys, "what is kept by its id stays")
    }

    @Test fun aMarkHeldOverAStartThenTheSameAccountSignedInAgainAndOutKeepsItsRecords() = runBlocking<Unit> {
        val w = world()
        stopBeforeTheKeepersEnd(w)
        w.app.close()
        w.secure.handsNothingFor += SessionKeeper.KEY
        w.app = k.device(w)
        assertNotNull(mark(w), "the start waits while the session record cannot be read")
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, h, k.alice))
        k.signOut(w.app)
        val before = k.byId(w).keys
        k.restart(w)
        keepsWhatProtects(w, w.u, "held over a start, signed in again and out")
        assertEquals(before, k.byId(w).keys, "what is kept by its id stays")
    }

    @Test fun anotherAccountUnderTheSameAddressSignedInAndOutBeforeTheNextStartKeepsItsRecords() = runBlocking<Unit> {
        val w = world()
        stopBeforeTheKeepersEnd(w)
        k.signOut(w.app)
        val v = anotherAccountUnderTheAddress(w)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, h, k.alice))
        assertEquals(v, assertNotNull(w.app.keeper.session).userId)
        k.signOut(w.app)
        val row = assertNotNull(w.state.inner.get("ovh.dev|$h|${k.alice}"), "the device's row for the address")
        k.restart(w)
        keepsWhatProtects(w, v, "another account under the address")
        assertEquals(row, w.state.inner.get("ovh.dev|$h|${k.alice}"), "the device's row for the address stays")
        assertEquals(emptyMap(), k.byId(w), "nothing kept by the deleted account's id is left")
    }

    @Test fun aMarkHeldOverAStartThenAnotherAccountUnderTheSameAddressSignedInAndOutKeepsItsRecords() = runBlocking<Unit> {
        val w = world()
        stopBeforeTheKeepersEnd(w)
        w.app.close()
        w.secure.handsNothingFor += SessionKeeper.KEY
        w.app = k.device(w)
        assertNotNull(mark(w), "the start waits while the session record cannot be read")
        // A take elsewhere writes a new session record, which the store reads again (the forgetting waits until then).
        val b = k.register(w.app, "other.example", k.bob)
        k.signOut(w.app)
        assertNotNull(mark(w), "a take at another server under another address does not end the mark")
        val v = anotherAccountUnderTheAddress(w)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, h, k.alice))
        k.signOut(w.app)
        k.restart(w)
        keepsWhatProtects(w, v, "held over a start, then another account under the address")
        assertEquals(emptyMap(), k.byId(w), "nothing kept by the deleted account's id is left")
        assertTrue(k.byId(w, b).containsKey("ovh.identity|$b"), "bob at other.example keeps his records")
        assertIs<PinState.Pinned>(w.app.trust.pinState(w.other.origin))
    }

    @Test fun aTakeUnderAnotherAddressAtTheSameServerLeavesTheMarkAndTheDeletionFinishes() = runBlocking<Unit> {
        for (signedOut in listOf(true, false)) {
            val label = if (signedOut) "bob signed out" else "bob kept"
            val w = world()
            stopBeforeTheKeepersEnd(w)
            k.signOut(w.app)
            val b = k.register(w.app, "h.example", k.bob)
            assertEquals(1, marksFor(w, h, w.u, k.alice).size, "$label: bob's take leaves alice's mark")
            if (signedOut) k.signOut(w.app)
            val bobsBefore = k.byId(w, b)
            k.restart(w)
            assertNull(mark(w), "$label: the deletion finished")
            assertNull(addr(w), "$label: alice's address record went")
            assertEquals(emptyMap(), k.byId(w), "$label: nothing kept by alice's id is left")
            assertEquals(b, addr(w, h, k.bob), "$label: bob's address record stays")
            assertEquals(bobsBefore, k.byId(w, b), "$label: what is kept by bob's id stays")
            assertIs<PinState.Pinned>(w.app.trust.pinState(h), "$label: the server stays pinned")
            if (!signedOut) assertEquals(b, assertNotNull(w.app.keeper.session, label).userId, "$label: bob's session stays")
        }
    }

    @Test fun theSameAccountTakenAtAnotherServerBeforeTheStartDoesNotEndTheMark() = runBlocking<Unit> {
        for (signedOut in listOf(true, false)) {
            val label = if (signedOut) "signed out at other.example" else "kept at other.example"
            val w = world(sameInstance = true)
            w.other.accounts[k.alice] = assertNotNull(w.home.accounts[k.alice])
            stopBeforeTheKeepersEnd(w)
            k.signOut(w.app)
            assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.other.origin, k.alice), label)
            assertEquals(w.u, assertNotNull(w.app.keeper.session).userId)
            assertEquals(1, marksFor(w, h, w.u, k.alice).size, "$label: a take at another server leaves the mark")
            if (signedOut) k.signOut(w.app)
            k.restart(w)
            assertNull(mark(w), "$label: the deletion finished")
            assertNull(addr(w), "$label: h.example's address record went")
            assertIs<PinState.None>(w.app.trust.pinState(h), "$label: h.example is new to the device")
            assertEquals(w.u, addr(w, w.other.origin), "$label: other.example's address record stays")
            assertTrue(k.byId(w).containsKey("ovh.identity|${w.u}"), "$label: the identity record stays")
            assertIs<PinState.Pinned>(w.app.trust.pinState(w.other.origin), "$label: other.example stays pinned")
            if (!signedOut) {
                val kept = assertNotNull(w.app.keeper.session, label)
                assertEquals(w.u to w.other.origin, kept.userId to kept.origin, "$label: the session there stays")
            }
        }
    }

    /**
     * The take stopped at each of its writes, then a start. Where the take's session record landed, no mark of a deletion
     * at its server names its account or its address; where a session is kept after the start, what protects it stays.
     */
    private suspend fun everyStopOfTheTake(label: String, setUp: suspend (SweepWorld) -> String) {
        val cutAt = ArrayList<String>()
        val bad = ArrayList<String>()
        var n = 0
        while (n < 200) {
            val w = world()
            stopBeforeTheKeepersEnd(w)
            k.signOut(w.app)
            val taker = setUp(w)
            val stop = Stop(w, n, startsAt = { _, _ -> true })
            val r = runCatching { k.signInAt(w.app, h, k.alice) }
            runCatching { w.app.close() }
            stop.end()
            val at = stop.at
            if (at == null) {
                assertEquals(SignInAnswer.DONE, r.getOrThrow(), label)
                break
            }
            cutAt += at.replace(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "<id>")
            val record = w.secure.inner.get(SessionKeeper.KEY)
            if (record != null && taker in record && marksFor(w, h, taker, k.alice).isNotEmpty()) bad += "#$n $at: a session record beside a live mark"
            w.app = k.device(w)
            val kept = w.app.keeper.session
            if (kept != null) {
                if (addr(w) != kept.userId) bad += "#$n $at: kept ${kept.userId}, address record ${addr(w)}"
                if (!k.byId(w, kept.userId).containsKey("ovh.identity|${kept.userId}")) bad += "#$n $at: no identity record"
                if (w.app.trust.pinState(h) !is PinState.Pinned) bad += "#$n $at: the server is not pinned"
            }
            n++
        }
        println("TAKE $label: stopped at $n writes: $cutAt")
        assertTrue(n > 5, "$label: the take's writes were cut ($n)")
        assertEquals(emptyList(), bad, label)
    }

    @Test fun theSameAccountsTakeStoppedAtEachOfItsWritesNeverKeepsASessionBesideItsMark() = runBlocking<Unit> {
        everyStopOfTheTake("the same account") { w -> w.u }
    }

    @Test fun anotherAccountsTakeUnderTheAddressStoppedAtEachOfItsWritesNeverKeepsASessionBesideTheMark() = runBlocking<Unit> {
        everyStopOfTheTake("another account under the address") { w -> anotherAccountUnderTheAddress(w) }
    }
}
