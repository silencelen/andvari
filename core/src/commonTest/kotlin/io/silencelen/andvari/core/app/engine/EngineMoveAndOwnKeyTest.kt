package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.MoveResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.QuickUnlockResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.MOVE_UNFINISHED
import io.silencelen.andvari.core.client.pin.NamespaceMover
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.TrustCardChainVerifier
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.TestClocks
import io.silencelen.andvari.core.client.session.TestKeyWrap
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.SignedFrame
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Two hooks of the engine the app API wires: the signed-in account's own check of the operator key a card names
 * (design §4.1, VR-11), and a followed move whose platform namespace did not move (§4.4, `OriginAccess.MOVING`).
 */
class EngineMoveAndOwnKeyTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val moved = "https://moved.example"

    /** The platform's namespace move: fails until [works], and records every call. */
    private class Mover : NamespaceMover {
        var works = false
        val calls = ArrayList<Pair<String, String>>()
        override fun onMoved(from: String, to: String): Boolean {
            calls += from to to
            return works
        }
    }

    private class Env(val server: FakeInstance, val transport: BearerTransport, val state: MemoryDeviceState, val secure: MemoryDeviceState)

    private fun env(): Env {
        val server = FakeInstance(crypto)
        return Env(server, BearerTransport(mapOf(server.origin to server, moved to server)), MemoryDeviceState(), MemoryDeviceState())
    }

    /** A phone on [e]'s stores: a new app over the same device, as at a cold start. */
    private fun Env.app(mover: NamespaceMover? = null, desktop: Boolean = false, quick: Boolean = false): EngineAppApi {
        val engine = AppEngine(
            AppPlatform.ANDROID, "Pixel", transport, state, secure, crypto, { server.now }, baked = null, storeBuild = false,
            stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
            keyWrap = if (quick) TestKeyWrap() else null, clocks = if (quick) TestClocks(wall = server.now) else null,
            namespaceMover = mover,
        )
        return (if (desktop) EngineDesktopAppApi(engine) else EngineAppApi(engine)).also { it.start() }
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Typed address, Trust Gate, sign-up, kit: the vault is open. */
    private suspend fun open(a: EngineAppApi) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /** The operator signs the next card of [s]'s chain: at [origin], naming [operator] with [operatorKey] (base64). */
    private fun nextCard(s: FakeInstance, origin: String = s.origin, operator: String = "99999999-9999-4999-8999-999999999999", operatorKey: String = Bytes.toB64(s.operatorSign.publicKey)) {
        s.cards += InstanceCard.sign(
            crypto, s.operatorSign,
            CardFields(s.instanceId, s.cards.size.toLong(), SignedFrame.hash(crypto, s.cards.last()), origin, "Home", s.kind, operator, operatorKey, s.recoveryFp,
                s.now - 10_000 + s.cards.size * 1_000L),
        )
    }

    // ---- §4.1 (VR-11): the operator key a card names is checked on the named account's own device ----

    @Test fun aCardNamingThisAccountAsOperatorUnderAnotherKeyIsRefusedOnItsOwnDevice() = runBlocking<Unit> {
        val e = env()
        val a = e.app(desktop = true)
        open(a)
        val userId = a.keeper.session!!.userId
        // A card the operator key signs, naming this account as the operator under a key that is not this account's.
        nextCard(e.server, operator = userId, operatorKey = Bytes.toB64(crypto.signKeypairFromSeed(ByteArray(32) { 3 }).publicKey))
        val status = assertIs<CardStatus.Refused>((a.instance as EngineInstance).refresh())
        assertEquals("operator_key_mismatch", status.verdict)
        assertEquals(0L, PinStore(e.state).get(e.server.origin)!!.seq, "the pin stays where it was")
        assertIs<InstanceCardState.NotVerified>(a.snapshot.instance!!.card)

        // A cold start reopens the account at its unlock, and the check is back with it.
        a.lock()
        a.close()
        val b = e.app(desktop = true)
        assertEquals(VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        assertEquals("operator_key_mismatch", assertIs<CardStatus.Refused>((b.instance as EngineInstance).refresh()).verdict)

        // Signed out, this device holds no key of the account and checks nothing: the card is followed.
        b.signOut()
        assertEquals(1L, assertIs<CardStatus.Ok>(b.trust.refresh(e.server.origin)).pin.seq)
    }

    @Test fun onAPhoneTheRefusedCardDoesNotSignTheAccountOut() = runBlocking<Unit> {
        val e = env()
        val a = e.app()
        open(a)
        nextCard(e.server, operator = a.keeper.session!!.userId, operatorKey = Bytes.toB64(crypto.signKeypairFromSeed(ByteArray(32) { 3 }).publicKey))
        assertIs<CardStatus.Refused>((a.instance as EngineInstance).refresh())
        // Unchecked, the card would have named this account as the operator, and a phone would have signed it out (rule 7).
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertNotNull(a.keeper.session)
    }

    // ---- §4.4: a followed move whose platform namespace did not move ----

    @Test fun aMoveWhoseNamespaceDidNotMoveKeepsTheNewAddressShutUntilItIsFinished() = runBlocking<Unit> {
        val e = env()
        val mover = Mover()
        val a = e.app(mover)
        open(a)
        val home = e.server.origin
        nextCard(e.server, moved)
        assertIs<CardStatus.Moved>((a.instance as EngineInstance).refresh())
        val card = assertIs<InstanceCardState.Moved>(a.snapshot.instance!!.card)
        assertEquals(MoveResult.NOT_FINISHED, a.instance.followMove(card))
        assertEquals(listOf(home to moved), mover.calls)

        // The session went with the namespace, and the vault is shut: nothing may be read there yet.
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        assertNull(a.keeper.established)
        assertNull(a.content)
        assertEquals(moved, a.keeper.session!!.origin)
        val instance = a.snapshot.instance!!
        assertEquals(moved, instance.label.origin)
        assertIs<InstanceCardState.NotVerified>(instance.card)
        val unfinished = assertNotNull(instance.unfinishedMove)
        assertEquals(home, unfinished.fromOrigin)
        // Nothing is sent to the new address, and the password opens nothing there.
        assertTrue(!a.mayDial(moved))
        assertEquals(VaultUnlockResult.SERVER_BLOCKED, a.unlock(a.snapshot.locked!!, strong))
        assertTrue(e.transport.sent.none { it.origin == moved }, "sent: ${e.transport.sent.map { it.origin to it.route }}")

        // Trying again while the platform still fails changes nothing.
        assertEquals(MoveResult.NOT_FINISHED, a.instance.finishMove(unfinished))
        assertTrue(a.snapshot.instance!!.unfinishedMove === unfinished)
        assertTrue(e.transport.sent.none { it.origin == moved })

        // The platform moved its data: the server opens at the new address as after a followed move.
        mover.works = true
        assertEquals(MoveResult.DONE, a.instance.finishMove(unfinished))
        assertNull(a.snapshot.instance!!.unfinishedMove)
        assertIs<InstanceCardState.Ok>(a.snapshot.instance!!.card)
        assertEquals(MoveResult.STALE, a.instance.finishMove(unfinished))
        assertTrue(a.mayDial(moved))
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertEquals(moved, a.keeper.established!!.origin)
        assertNotNull(a.snapshot.account!!.kitAfterMove, "a kit made before the move names the old address")
    }

    /**
     * A followed move carries the kit's marks: the kept session's mark reads the same at the new address (its value names
     * no server), a kit's mark in memory follows the move, and nothing stays under the old address. Before: the kept mark's
     * value began with the old address, so a new mark was made and a kit's notice no longer named the session kept, and the
     * next write of a kit's mark went under the old address again.
     */
    @Test fun aFollowedMoveCarriesTheKitMarksAndTheKeptMarkStaysTheSame() = runBlocking<Unit> {
        val e = env()
        val a = e.app(Mover().also { it.works = true })
        open(a)
        val home = e.server.origin
        val userId = a.keeper.session!!.userId
        val before = a.keptMark()
        assertTrue(before.isNotEmpty())
        a.markNotKeptKit(EngineAppApi.KitMark(true, "alice@example.com", null, false, origin = home))
        assertTrue(e.state.get(EngineAppApi.KIT_ON_SHOW_PREFIX + home) != null)
        nextCard(e.server, moved)
        assertIs<CardStatus.Moved>((a.instance as EngineInstance).refresh())
        assertEquals(MoveResult.DONE, a.instance.followMove(assertIs(a.snapshot.instance!!.card)))
        assertEquals(moved, a.keeper.session!!.origin)
        assertEquals(before, a.keptMark(), "the same session, the same mark")
        assertEquals("$userId|$before", e.state.get(EngineAppApi.KEPT_MARK_PREFIX + moved), "no server in the value")
        // A later write of the marks (here: another server's forgetting) stands under the new address only.
        a.kitMarksForgotten("https://unrelated.example")
        assertTrue(e.state.get(EngineAppApi.KIT_ON_SHOW_PREFIX + moved) != null, "the kit's mark at the new address")
        assertEquals(emptyList(), e.state.keys().filter { home in it && ("kit" in it || "keptmark" in it) }, "nothing under the old address")
    }

    @Test fun lockedOnAMovingServerTheQuickUnlockReadsAsBlocked() = runBlocking<Unit> {
        // OriginAccess.MOVING reads as BLOCKED on the lock screen, and as stopped wherever the app asks whether the
        // server can be used: the password opens nothing there either.
        val e = env()
        val mover = Mover()
        val a = e.app(mover, quick = true)
        open(a)
        assertEquals(io.silencelen.andvari.core.app.QuickEnrolResult.DONE, a.settings.turnOnQuickUnlock(a.snapshot.account!!.quickUnlock))
        nextCard(e.server, moved)
        (a.instance as EngineInstance).refresh()
        assertEquals(MoveResult.NOT_FINISHED, a.instance.followMove(assertIs(a.snapshot.instance!!.card)))
        assertEquals(QuickUnlockResult.SERVER_BLOCKED, a.quickUnlock(a.snapshot.locked!!))
    }

    @Test fun aMoveLeftUnfinishedByAStopIsCarriedAndTriedAgainAtTheNextStart() = runBlocking<Unit> {
        val e = env()
        val a = e.app()
        open(a)
        val home = e.server.origin
        a.lock()
        a.close()
        // The app stopped between the engine's move and the platform's: the pin and its mark are at the new address,
        // the kept session still names the old one.
        nextCard(e.server, moved)
        val stopped = CardTrust(PinStore(e.state), TrustCardChainVerifier(crypto), { e.server }, crypto, null, false, onMoved = NamespaceMover { _, _ -> false })
        val status = assertIs<CardStatus.Moved>(stopped.refresh(home))
        assertEquals(MOVE_UNFINISHED, assertIs<CardStatus.Refused>(stopped.followMove(status)).verdict)

        // The next start carries the session to the new address and tries the platform's move once by itself.
        val failing = Mover()
        val b = e.app(failing)
        assertEquals(listOf(home to moved), failing.calls)
        assertEquals(AppPhase.LOCKED, b.snapshot.phase)
        assertEquals(moved, b.keeper.session!!.origin)
        assertEquals(home, assertNotNull(b.snapshot.instance!!.unfinishedMove).fromOrigin)
        assertEquals(VaultUnlockResult.SERVER_BLOCKED, b.unlock(b.snapshot.locked!!, strong))
        b.close()

        // A start where the platform's move works opens the server there before anything else.
        val working = Mover().also { it.works = true }
        val c = e.app(working)
        assertEquals(listOf(home to moved), working.calls)
        assertNull(c.snapshot.instance!!.unfinishedMove)
        assertEquals(VaultUnlockResult.DONE, c.unlock(c.snapshot.locked!!, strong))
        assertEquals(moved, c.keeper.established!!.origin)
        assertNotNull(c.snapshot.account!!.kitAfterMove)
    }
}
