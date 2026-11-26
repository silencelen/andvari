package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The sweep: a record kept by an account's id alone (its identity record, its state copy and marks, its vault logs, the
 * item engine's records, its recovery mirror and escrow mark) goes once the device no longer knows that account anywhere: no
 * session kept for it, no copy held for it, no address record naming it, nothing of it in flight. Each state below left such
 * records on the device for good; each guard is an account the device still knows, which keeps them.
 */
class EngineAccountSweepTest {
    private val k = SweepSteps(createCryptoProvider())

    private fun nothingKeptById(w: SweepWorld, label: String) {
        println("SWEEP $label: byId=${k.byId(w).keys} naming=${k.naming(w)}")
        assertEquals(emptyMap(), k.byId(w), "$label: nothing kept by the account's id")
    }

    // ---- the states that left records kept by the id for good ----

    /** Kept as a guard (closed by the tie's own rule): the same address only tried at an unrelated server. */
    @Test fun theSameAddressOnlyTriedAtAnUnrelatedServerLeavesNothingAfterADeletionAndThatServersForgetting() = runBlocking<Unit> {
        val w = k.world()
        assertEquals(SignInAnswer.WRONG, k.signInAt(w.app, w.other.origin, k.alice, password = "not her password at all 77"))
        k.toFirstScreen(w)
        w.u = k.register(w.app, "h.example", k.alice)
        k.deleteAt(w, w.home)
        w.app.instancePart.forgetOrigin(w.other.origin)
        k.restart(w)
        nothingKeptById(w, "tried elsewhere")
        assertEquals(emptyList(), k.naming(w))
    }

    /**
     * An earlier account forgotten at one server, then ended at its other server: the same account id served at h.example
     * and other.example; h.example serves another account under the address and the person forgets the earlier one there
     * (its key stays as h.example's record); then the account, signed in at other.example, is deleted there. Before, the
     * record h.example keeps of its key tied it, and everything kept by its id stayed for good.
     */
    @Test fun anEarlierAccountForgottenAtOneServerAndThenDeletedAtItsOtherServerLeavesNothingKeptByItsId() = runBlocking<Unit> {
        val w = k.world(sameInstance = true)
        w.u = k.register(w.app, "h.example", k.alice)
        w.other.accounts[k.alice] = assertNotNull(w.home.accounts[k.alice])
        k.loseSession(w)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.other.origin, k.alice))
        k.loseSession(w)
        w.home.accounts.remove(k.alice)
        assertNotEquals(w.u, k.register(k.otherDevice(w.home), "h.example", k.alice))
        assertEquals(SignInAnswer.IDENTITY_FAULT, k.signInAt(w.app, w.home.origin, k.alice))
        assertEquals(ForgetEarlierResult.FORGOTTEN, k.forgetEarlier(w))
        val earlierKey = SessionKeeper.EARLIER_IDENTITY_PREFIX + w.home.origin + "|" + w.u
        assertNotNull(w.state.inner.get(earlierKey), "h.example keeps the key of the account it forgot")
        k.toFirstScreen(w)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.other.origin, k.alice))
        assertEquals(w.u, assertNotNull(w.app.keeper.session).userId)
        k.deleteAt(w, w.other)
        k.restart(w)
        nothingKeptById(w, "forgotten at h.example, deleted at other.example")
        assertNotNull(w.state.inner.get(earlierKey), "h.example's own record of the key stays: it is not kept by the id alone")
    }

    /**
     * A true tie whose tying server is later forgotten while it holds only a device's row: at other.example the person's
     * earlier account was forgotten (the device's row for the address stays there, with its device id, and no address record);
     * then account u is made at h.example under the same address and deleted there, which other.example's row ties; then
     * other.example is forgotten. Before, nothing removed what was kept by u's id.
     */
    @Test fun aTieThroughADevicesRowLeavesNothingKeptByTheIdOnceThatServerIsForgotten() = runBlocking<Unit> {
        val w = k.world()
        k.register(w.app, "other.example", k.alice)
        k.signOut(w.app)
        w.other.accounts.remove(k.alice)
        k.register(k.otherDevice(w.other), "other.example", k.alice)
        assertEquals(SignInAnswer.IDENTITY_FAULT, k.signInAt(w.app, w.other.origin, k.alice))
        assertEquals(ForgetEarlierResult.FORGOTTEN, k.forgetEarlier(w))
        k.toFirstScreen(w)
        assertNull(w.state.inner.get(SessionKeeper.EMAIL_BINDING_PREFIX + w.other.origin + "|" + k.alice))
        assertNotNull(w.state.inner.get("ovh.dev|${w.other.origin}|${k.alice}"))
        w.u = k.register(w.app, "h.example", k.alice)
        assertTrue(PinStore.tiedElsewhere(w.state, w.u, w.home.origin), "other.example's row for the address ties the account")
        k.deleteAt(w, w.home)
        w.app.instancePart.forgetOrigin(w.other.origin)
        k.restart(w)
        nothingKeptById(w, "a row's tie, its server forgotten")
        assertEquals(emptyList(), k.naming(w))
    }

    /**
     * The first check's probe of a deletion stopped after the keeper's forgetting (one account, one server, the store failing
     * at the first write after the address record's removal): what is kept by the id goes at the next start. (That the server
     * is then still trusted with no first sight is the next unit's, not this one's.)
     */
    @Test fun aDeletionStoppedAfterTheKeepersForgettingLeavesNothingKeptByTheIdAfterAStart() = runBlocking<Unit> {
        val w = k.world()
        w.u = k.register(w.app, "h.example", k.alice)
        assertTrue(k.byId(w).keys.any { it.startsWith("ovh.acct|") })
        w.state.armAfterRemovalOf = SessionKeeper.EMAIL_BINDING_PREFIX + w.home.origin + "|" + k.alice
        assertTrue(runCatching { k.deleteAt(w, w.home) }.isFailure, "the deletion stops")
        k.restart(w)
        nothingKeptById(w, "a deletion stopped after the keeper's forgetting, then a start")
    }

    /**
     * An address record at another server that could not be read at the deletion: the tie then names every account, and what
     * is kept by the id stayed for good. Once the record reads again, the next start leaves nothing.
     */
    @Test fun anAddressRecordThatCouldNotBeReadAtTheDeletionLeavesNothingOnceItReadsAgainAndTheAppStarts() = runBlocking<Unit> {
        val w = k.world()
        k.register(w.app, "other.example", k.bob)
        k.signOut(w.app)
        w.u = k.register(w.app, "h.example", k.alice)
        val bobs = SessionKeeper.EMAIL_BINDING_PREFIX + w.other.origin + "|" + k.bob
        assertNotNull(w.state.inner.get(bobs))
        w.state.unreadable += bobs
        k.deleteAt(w, w.home)
        w.state.unreadable.clear()
        k.restart(w)
        nothingKeptById(w, "an address record unreadable at the deletion, read again")
        assertEquals(emptyList(), k.naming(w))
    }

    /** A store that could not list its keys at the deletion: once it lists them again, the next start leaves nothing. */
    @Test fun aStoreThatCouldNotListItsKeysAtTheDeletionLeavesNothingOnceItListsThemAgainAndTheAppStarts() = runBlocking<Unit> {
        val w = k.world()
        w.u = k.register(w.app, "h.example", k.alice)
        w.state.unlisted = true
        k.deleteAt(w, w.home)
        w.state.unlisted = false
        k.restart(w)
        nothingKeptById(w, "a store that could not list, listing again")
        assertEquals(emptyList(), k.naming(w))
    }

    // ---- guards: an account the device still knows keeps everything ----

    /**
     * An account signed out and still known by its address record keeps its marks and its identity record through a start,
     * and through the deletion of another account at the same server (whose own end sweeps).
     */
    @Test fun anAccountSignedOutAndKnownByItsAddressRecordKeepsItsMarksAndItsIdentityRecord() = runBlocking<Unit> {
        val w = k.world()
        w.u = k.register(w.app, "h.example", k.alice)
        k.signOut(w.app)
        val before = k.byId(w)
        assertTrue(before.keys.containsAll(listOf("ovh.identity|${w.u}", "ovh.acct|${w.u}|hw", "ovh.rmirror|${w.u}")), "$before")
        k.restart(w)
        assertEquals(before, k.byId(w), "through a start")
        k.register(w.app, "h.example", k.bob)
        k.deleteAt(w, w.home, k.bob)
        assertEquals(before, k.byId(w), "through another account's deletion at the same server")
        k.restart(w)
        assertEquals(before, k.byId(w), "and the start after it")
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.home.origin, k.alice))
        assertEquals(w.u, assertNotNull(w.app.keeper.session).userId)
    }

    /** One account id held at two servers keeps what is kept by its id when one of them is forgotten, and after a start. */
    @Test fun oneAccountIdHeldAtTwoServersKeepsItsRecordsWhenOneOfThemIsForgotten() = runBlocking<Unit> {
        val w = k.world(sameInstance = true)
        w.u = k.register(w.app, "h.example", k.alice)
        w.other.accounts[k.alice] = assertNotNull(w.home.accounts[k.alice])
        k.loseSession(w)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.other.origin, k.alice))
        k.loseSession(w)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.home.origin, k.alice))
        val before = k.byId(w)
        assertTrue(before.keys.containsAll(listOf("ovh.identity|${w.u}", "ovh.acct|${w.u}|hw")), "$before")
        assertEquals(PlainResult.DONE, w.app.instance.forgetServer(assertNotNull(w.app.snapshot.instance)))
        assertEquals(before, k.byId(w), "at the forgetting")
        k.restart(w)
        assertEquals(before, k.byId(w), "after a start")
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.other.origin, k.alice))
        w.app.lock()
        assertEquals(VaultUnlockResult.DONE, w.app.unlock(assertNotNull(w.app.snapshot.locked), k.strong))
    }

    // ---- an account at a server's new address whose address record lies only under the old one ----

    /**
     * The same account served at h.example (the server's old address) and other.example (its new one), signed in at both; the
     * address record at the new address is then removed by hand, so that the only address record naming the account lies
     * under the old address (the state a server's move can leave). [kept]: the session stays kept at the new address;
     * otherwise it is lost, and with [copy] the copy held at the new address stays held. Answers the world and the records kept
     * by the id at that point.
     */
    private suspend fun parkedAtTheOldAddress(kept: Boolean, copy: Boolean): Pair<SweepWorld, Map<String, String>> {
        val w = k.world(sameInstance = true)
        w.u = k.register(w.app, "h.example", k.alice)
        w.other.accounts[k.alice] = assertNotNull(w.home.accounts[k.alice])
        k.loseSession(w)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.other.origin, k.alice))
        assertEquals(w.u to w.other.origin, assertNotNull(w.app.keeper.session).let { it.userId to it.origin })
        if (!kept) k.loseSession(w)
        if (!copy) w.state.inner.set(EngineAppApi.HELD_KEY, w.state.inner.get(EngineAppApi.HELD_KEY).orEmpty().split('\n')
            .filter { it.isNotEmpty() && it != "${w.other.origin}|${w.u}" }.joinToString("\n").ifEmpty { null })
        w.state.inner.set(SessionKeeper.EMAIL_BINDING_PREFIX + w.other.origin + "|" + k.alice, null)
        val named = w.state.inner.keys().filter { it.startsWith(SessionKeeper.EMAIL_BINDING_PREFIX) }
        assertEquals(listOf(SessionKeeper.EMAIL_BINDING_PREFIX + w.home.origin + "|" + k.alice), named, "the one address record, under the old address")
        val before = k.byId(w)
        assertTrue(before.keys.containsAll(listOf("ovh.identity|${w.u}", "ovh.acct|${w.u}|hw")), "$before")
        return w to before
    }

    /**
     * "Forget this server" at the old address (the engine's step for that origin: the person's screen offers it for the
     * server on show), then a start, whose sweep decides.
     */
    private fun forgetTheOldAddressAndStart(w: SweepWorld) {
        w.app.instancePart.forgetOrigin(w.home.origin)
        k.restart(w)
        assertEquals(io.silencelen.andvari.core.client.pin.PinState.None, w.app.trust.pinState(w.home.origin))
        assertTrue(w.app.trust.pinState(w.other.origin) is io.silencelen.andvari.core.client.pin.PinState.Pinned, "the new address's pin stays")
    }

    @Test fun anAccountKeptAtTheNewAddressWithItsAddressRecordOnlyUnderTheOldKeepsEverythingWhenTheOldIsForgotten() = runBlocking<Unit> {
        val (w, before) = parkedAtTheOldAddress(kept = true, copy = true)
        forgetTheOldAddressAndStart(w)
        assertEquals(w.u, assertNotNull(w.app.keeper.session).userId, "still kept at the new address")
        assertEquals(before, k.byId(w), "the identity record and every record kept by the id, as they were")
        assertEquals(VaultUnlockResult.DONE, w.app.unlock(assertNotNull(w.app.snapshot.locked), k.strong))
    }

    @Test fun anAccountWithACopyHeldAtTheNewAddressAndNoSessionKeepsEverythingWhenTheOldIsForgotten() = runBlocking<Unit> {
        val (w, before) = parkedAtTheOldAddress(kept = false, copy = true)
        assertNull(w.app.keeper.session)
        forgetTheOldAddressAndStart(w)
        assertTrue("${w.other.origin}|${w.u}" in w.state.inner.get(EngineAppApi.HELD_KEY).orEmpty().split('\n'), "the copy stays held")
        assertEquals(before, k.byId(w), "the identity record and every record kept by the id, as they were")
    }

    @Test fun anAccountWithNeitherASessionNorACopyAtTheNewAddressLeavesNothingKeptByItsIdWhenTheOldIsForgotten() = runBlocking<Unit> {
        val (w, _) = parkedAtTheOldAddress(kept = false, copy = false)
        assertNull(w.app.keeper.session)
        forgetTheOldAddressAndStart(w)
        nothingKeptById(w, "parked under the old address, neither a session nor a copy at the new")
    }

    // ---- guards: a start (another process over the same stores) falling in the middle of each flow ----

    private fun lostNothing(s: SweepSteps.SecondStarts, label: String) {
        s.stop()
        println("SWEEP $label: second starts=${s.starts} lost=${s.lost}")
        assertTrue(s.starts > 0, "$label: a second start fell in the flow")
        assertEquals(emptyList(), s.lost, "$label: a start in the middle of the flow takes nothing")
    }

    @Test fun aStartInTheMiddleOfARegistrationTakesNothing() = runBlocking<Unit> {
        val w = k.world()
        val s = k.secondStartAtEachWrite(w)
        w.u = k.register(w.app, "h.example", k.alice)
        lostNothing(s, "registration")
        assertNotNull(w.app.keeper.knownIdentity(w.u))
    }

    @Test fun aStartInTheMiddleOfASignInOnADeviceThatNeverKnewTheAccountTakesNothing() = runBlocking<Unit> {
        val w = k.world()
        val u = k.register(k.otherDevice(w.home), "h.example", k.alice)
        val s = k.secondStartAtEachWrite(w)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.home.origin, k.alice))
        lostNothing(s, "sign-in")
        assertEquals(u, assertNotNull(w.app.keeper.session).userId)
        assertNotNull(w.app.keeper.knownIdentity(u))
    }

    @Test fun aStartInTheMiddleOfARecoveryWithTheKitOnADeviceThatNeverKnewTheAccountTakesNothing() = runBlocking<Unit> {
        val w = k.world()
        val (u, doc) = k.registerKeepingKit(k.otherDevice(w.home), "h.example", k.alice)
        val s = k.secondStartAtEachWrite(w)
        val a = w.app
        a.entry.openSignIn(k.at(a))
        a.entry.openForgot(k.at(a))
        a.entry.openKitEntry(k.at(a))
        assertEquals(KitScanResult.DONE, a.entry.submitKit(k.at(a), doc.qrPayload, PayloadSource.SCANNED))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(KitRecoverResult.DONE, a.entry.confirmKitRecovery(k.at(a)))
        assertEquals(ReplacePasswordResult.DONE, a.entry.chooseReplacementPassword(k.at(a), "a brand new Master password 7"))
        k.confirmKit(a)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        lostNothing(s, "recovery with the kit")
        assertEquals(u, assertNotNull(a.keeper.session).userId)
        assertNotNull(a.keeper.knownIdentity(u))
    }

    @Test fun aStartInTheMiddleOfSavesASyncAndAnUnlockTakesNothing() = runBlocking<Unit> {
        val w = k.world(items = true)
        w.u = k.register(w.app, "h.example", k.alice)
        val s = k.secondStartAtEachWrite(w)
        val c = assertNotNull(w.app.content)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Bank", "me", "pw-Bank", listOf("https://bank.test"), "", "", false), null))
        assertEquals(ActionResult.Ok, c.syncQuietly())
        w.app.lock()
        assertEquals(VaultUnlockResult.DONE, w.app.unlock(assertNotNull(w.app.snapshot.locked), k.strong))
        assertEquals(ActionResult.Ok, assertNotNull(w.app.content).syncQuietly())
        lostNothing(s, "saves, a sync, an unlock")
    }
}
