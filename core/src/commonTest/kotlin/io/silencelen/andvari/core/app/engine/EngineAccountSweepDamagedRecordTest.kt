package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.client.CoreLog
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * One damaged record among those the sweep reads to decide which accounts the device knows: the sweep then removes
 * nothing, and where the engine's own reader of that record drops exactly the lines the sweep cannot read, the next rewrite
 * of the record (or the start, for the forgettings begun and the marks of a deletion of unknown outcome) clears it and the
 * sweep runs again. An address record or a session record that cannot be read could name an account the device must keep:
 * it still holds the sweep back until a take writes it again. Before, a damaged held list, forgetting record or mark of a
 * deletion of unknown outcome switched the sweep off for good.
 *
 * Each state is an account this device no longer knows (alice: signed out, its address record gone) with its records still
 * here, plus one planted record; then a start; then ordinary use (bob registers at the same server and signs out) and a
 * start.
 */
class EngineAccountSweepDamagedRecordTest {
    private val k = SweepSteps(createCryptoProvider())
    private val h = "https://h.example"
    private val u2 = "22222222-2222-4222-8222-222222222222"

    private suspend fun leftovers(): SweepWorld {
        val w = k.world()
        w.u = k.register(w.app, "h.example", k.alice)
        k.signOut(w.app)
        w.state.inner.set(SessionKeeper.EMAIL_BINDING_PREFIX + w.home.origin + "|" + k.alice, null)
        assertTrue(k.byId(w).isNotEmpty())
        return w
    }

    /** [plant] over [leftovers], then a start. */
    private suspend fun planted(plant: (SweepWorld) -> Unit): SweepWorld {
        val w = leftovers()
        w.app.close()
        plant(w)
        w.app = k.device(w)
        return w
    }

    private suspend fun ordinaryUse(w: SweepWorld) {
        k.register(w.app, "h.example", k.bob)
        k.signOut(w.app)
        k.restart(w)
    }

    private fun heldBack(w: SweepWorld, record: String, label: String) {
        assertTrue(k.byId(w).isNotEmpty(), "$label: nothing of alice went")
        assertEquals(record, assertIs<AccountSweep.Outcome.HeldBack>(w.app.sweepAccounts(), label).record, label)
    }

    private fun sweptAgain(w: SweepWorld, label: String) {
        assertEquals(emptyMap(), k.byId(w), "$label: the sweep ran again and nothing of alice is left")
        assertIs<AccountSweep.Outcome.Swept>(w.app.sweepAccounts(), label)
    }

    @Test fun aHeldLineWithNoServerHoldsTheSweepBackUntilTheHeldListIsWrittenAgain() = runBlocking<Unit> {
        val w = planted { it.state.inner.set(EngineAppApi.HELD_KEY, "|$u2") }
        heldBack(w, EngineAppApi.HELD_KEY, "at the start")
        ordinaryUse(w)
        sweptAgain(w, "after ordinary use")
    }

    @Test fun aHeldLineWhoseIdIsNoAccountIdIsDroppedAtTheNextWriteOfTheHeldList() = runBlocking<Unit> {
        val w = planted { it.state.inner.set(EngineAppApi.HELD_KEY, "$h|ABC") }
        heldBack(w, EngineAppApi.HELD_KEY, "at the start")
        ordinaryUse(w)
        sweptAgain(w, "after ordinary use")
        assertTrue(w.state.inner.get(EngineAppApi.HELD_KEY)?.contains("ABC") != true, "the line went with the rewrite")
    }

    @Test fun anOwnEndOfOneFieldHoldsTheSweepBackUntilTheOwnEndsAreWrittenAgain() = runBlocking<Unit> {
        val w = planted { it.state.inner.set(SessionKeeper.OWN_ENDS_KEY, h) }
        heldBack(w, SessionKeeper.OWN_ENDS_KEY, "at the start")
        ordinaryUse(w)
        sweptAgain(w, "after ordinary use")
    }

    @Test fun anOwnEndAnEarlierBuildWroteIsReadAndSettledAtTheStart() = runBlocking<Unit> {
        val w = planted { it.state.inner.set(SessionKeeper.OWN_ENDS_KEY, "$h|$u2") }
        sweptAgain(w, "at the start")
        assertNull(w.state.inner.get(SessionKeeper.OWN_ENDS_KEY))
    }

    @Test fun aForgettingRecordThatIsNotJsonIsWrittenAgainAtTheStartAndTheSweepRuns() = runBlocking<Unit> {
        val w = planted { it.state.inner.set(EngineAppApi.FORGETTING_KEY, "x") }
        sweptAgain(w, "at the start")
        assertNull(w.state.inner.get(EngineAppApi.FORGETTING_KEY), "the record that named no forgetting went")
        ordinaryUse(w)
        sweptAgain(w, "after ordinary use")
    }

    @Test fun aForgettingEntryTooShortIsDroppedAtTheStartAndTheSweepRuns() = runBlocking<Unit> {
        val w = planted { it.state.inner.set(EngineAppApi.FORGETTING_KEY, """[["$h","bob@example.com"]]""") }
        sweptAgain(w, "at the start")
        assertNull(w.state.inner.get(EngineAppApi.FORGETTING_KEY), "the entry that named no account went")
        ordinaryUse(w)
        sweptAgain(w, "after ordinary use")
    }

    /** An address record that cannot be read could name an account the device must keep: it holds back until a take writes it. */
    @Test fun anAddressRecordNamingNoAccountHoldsTheSweepBackUntilATakeOfThatAddressWritesIt() = runBlocking<Unit> {
        val carols = SessionKeeper.EMAIL_BINDING_PREFIX + "$h|carol@example.com"
        val w = planted { it.state.inner.set(carols, "garbage") }
        heldBack(w, carols, "at the start")
        ordinaryUse(w)
        heldBack(w, carols, "after ordinary use")
        k.register(w.app, "h.example", "carol@example.com")
        k.signOut(w.app)
        k.restart(w)
        sweptAgain(w, "after a take of that address")
    }

    @Test fun anAddressRecordOfABareIdIsReadAsThatAccounts() = runBlocking<Unit> {
        val w = planted { it.state.inner.set(SessionKeeper.EMAIL_BINDING_PREFIX + "$h|carol@example.com", u2) }
        sweptAgain(w, "at the start")
    }

    @Test fun aMarkOfADeletionOfUnknownOutcomeWithNoIdGoesAtTheStartAndTheSweepRuns() = runBlocking<Unit> {
        val mark = EngineAccountSettings.OUTCOME_UNKNOWN_KEY + h
        val w = planted { it.state.inner.set(mark, "1") }
        sweptAgain(w, "at the start")
        assertNull(w.state.inner.get(mark), "the mark that named no account went")
    }

    /** A session record the keeper cannot read could name an account the device must keep: it holds back until a take writes it. */
    @Test fun aSessionRecordWithNoUserIdHoldsTheSweepBackUntilATakeWritesIt() = runBlocking<Unit> {
        val w = planted { it.secure.inner.set(SessionKeeper.KEY, """{"origin":"$h"}""") }
        heldBack(w, SessionKeeper.KEY, "at the start")
        ordinaryUse(w)
        sweptAgain(w, "after a take wrote the session record again")
    }

    /** A sweep held back removes nothing at all, from either store. */
    @Test fun aSweepHeldBackRemovesNothing() = runBlocking<Unit> {
        val carols = SessionKeeper.EMAIL_BINDING_PREFIX + "$h|carol@example.com"
        val w = leftovers()
        w.app.close()
        w.state.inner.set(carols, "garbage")
        val state = w.state.snapshot()
        val secure = w.secure.snapshot()
        assertEquals(carols, assertIs<AccountSweep.Outcome.HeldBack>(AccountSweep.run(w.state, w.secure, null, CoreLog.Silent)).record)
        assertEquals(state, w.state.snapshot(), "the device state as it was")
        assertEquals(secure, w.secure.snapshot(), "the secure store as it was")
        // The same over the start, for what the sweep holds: every record kept by alice's id stays.
        val byId = k.byId(w)
        w.app = k.device(w)
        assertEquals(byId, k.byId(w))
    }
}
