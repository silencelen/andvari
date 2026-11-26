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
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.TrustCardChainVerifier
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
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
 * A followed move must never leave the kept session at an address that holds no pin. The
 * session goes where the pin went, whatever the new address then said; a session left behind by a stop is shown as a
 * blocked server that can be forgotten; and no bearer goes to an address with no pin in force.
 */
class EngineMoveStrandTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val moved = "https://moved.example"

    private class Env(val server: FakeInstance, val transport: BearerTransport, val state: MemoryDeviceState, val secure: MemoryDeviceState)

    /** [elsewhere]: the new address serves another instance's chain (a fork once the pin is there). */
    private fun env(elsewhere: Boolean): Env {
        val server = FakeInstance(crypto)
        val other = if (elsewhere) FakeInstance(crypto, moved, "ffffffff-ffff-4fff-8fff-ffffffffffff") else server
        return Env(server, BearerTransport(mapOf(server.origin to server, moved to other)), MemoryDeviceState(), MemoryDeviceState())
    }

    private fun Env.app(): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.LINUX, "Desk", transport, state, secure, crypto, { server.now }, baked = null, storeBuild = false,
            stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

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

    private fun nextCard(s: FakeInstance, origin: String) {
        s.cards += InstanceCard.sign(
            crypto, s.operatorSign,
            CardFields(s.instanceId, s.cards.size.toLong(), SignedFrame.hash(crypto, s.cards.last()), origin, "Home", s.kind,
                "99999999-9999-4999-8999-999999999999", Bytes.toB64(s.operatorSign.publicKey), s.recoveryFp, s.now - 10_000 + s.cards.size * 1_000L),
        )
    }

    private fun Env.logouts() = transport.sent.filter { it.route == WireRoute.LOGOUT }.map { it.origin }

    /** Scenario A: the new address serves another chain. The pin moved there and forked; the session must follow it. */
    @Test fun aMoveWhoseNewAddressDoesNotCheckOutTakesTheSessionWithThePin() = runBlocking<Unit> {
        val e = env(elsewhere = true)
        val a = e.app()
        open(a)
        val home = e.server.origin
        nextCard(e.server, moved)
        assertIs<CardStatus.Moved>((a.instance as EngineInstance).refresh())
        val card = assertIs<InstanceCardState.Moved>(a.snapshot.instance!!.card)
        assertEquals(MoveResult.MOVED_NOT_VERIFIED, a.instance.followMove(card))
        assertEquals(PinState.None, a.trust.pinState(home))
        assertIs<PinState.Forked>(a.trust.pinState(moved))
        assertEquals(moved, a.keeper.session!!.origin, "the session is where the pin is")
        val instance = assertNotNull(a.snapshot.instance, "an instance is on show, with its card")
        assertEquals(moved, instance.label.origin)
        assertIs<InstanceCardState.Stopped>(instance.card)
        // Nothing carrying the session's bearer goes to the address the instance left.
        e.transport.sent.clear()
        assertEquals(PlainResult.DONE, a.signOut())
        assertTrue(e.transport.sent.none { it.origin == home }, "sent: ${e.transport.sent.map { it.origin to it.route }}")
    }

    /** Scenario B: the app stopped between the engine's move and the session's. The next start shows a server to forget. */
    @Test fun aSessionLeftAtAnAddressWithNoPinIsABlockedServerThatCanBeForgotten() = runBlocking<Unit> {
        val e = env(elsewhere = false)
        val a = e.app()
        open(a)
        val home = e.server.origin
        a.lock()
        a.close()
        nextCard(e.server, moved)
        val outside = CardTrust(PinStore(e.state), TrustCardChainVerifier(crypto), { e.server }, crypto, null, false)
        assertIs<CardStatus.Ok>(outside.followMove(assertIs<CardStatus.Moved>(outside.refresh(home))))

        val b = e.app()
        assertEquals(AppPhase.LOCKED, b.snapshot.phase)
        assertEquals(home, b.keeper.session!!.origin)
        val instance = assertNotNull(b.snapshot.instance, "the server is on show, so it can be forgotten")
        assertEquals(home, instance.label.origin)
        assertIs<InstanceCardState.Damaged>(instance.card)
        assertEquals(VaultUnlockResult.SERVER_BLOCKED, b.unlock(b.snapshot.locked!!, strong))
        e.transport.sent.clear()
        // A request with the session's bearer needs a pin in force at the session's address.
        b.keeper.clientFor(home).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertTrue(e.transport.sent.none { it.bearer != null }, "a bearer went out: ${e.transport.sent.map { it.origin to it.route }}")
        assertEquals(PlainResult.DONE, b.instance.forgetServer(instance))
        assertEquals(AppPhase.ENTRY, b.snapshot.phase)
        assertNull(b.keeper.session)
        assertTrue(e.logouts().isEmpty(), "the server was told nothing")
    }

    @Test fun signingOutWithNoPinAtTheSessionsAddressSendsNothing() = runBlocking<Unit> {
        val e = env(elsewhere = false)
        val a = e.app()
        open(a)
        val home = e.server.origin
        a.lock()
        a.close()
        nextCard(e.server, moved)
        val outside = CardTrust(PinStore(e.state), TrustCardChainVerifier(crypto), { e.server }, crypto, null, false)
        assertIs<CardStatus.Ok>(outside.followMove(assertIs<CardStatus.Moved>(outside.refresh(home))))
        val b = e.app()
        e.transport.sent.clear()
        assertEquals(PlainResult.DONE, b.signOutConfirmed(kotlin.test.assertNotNull(b.signOutCheck())))
        assertNull(b.keeper.session)
        assertTrue(e.logouts().isEmpty(), "logout went to ${e.logouts()}")
    }
}
