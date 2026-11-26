package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KeyPairBytes
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

/**
 * Signed in, what a chain check finds reaches the screen. Every sync judges the origin's chain
 * (design §4.4); a move, a kind change, an older version or a refused chain found there is on the card at once, and a
 * card naming the signed-in account as the operator signs a phone out without waiting for the next unlock.
 */
class EngineChainCheckTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Env(val server: FakeInstance, val transport: BearerTransport, val app: EngineAppApi)

    private fun env(): Env {
        val server = FakeInstance(crypto)
        val transport = BearerTransport(mapOf(server.origin to server))
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, { server.now }, baked = null,
                storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also { it.start() }
        return Env(server, transport, app)
    }

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

    /** The next card of [s]'s chain, signed by [signer] (the operator key in force), naming [operator] with [operatorKey]. */
    private fun nextCard(
        s: FakeInstance, origin: String, signer: KeyPairBytes = s.operatorSign,
        operator: String = "99999999-9999-4999-8999-999999999999", operatorKey: ByteArray = s.operatorSign.publicKey,
    ) {
        s.cards += InstanceCard.sign(
            crypto, signer,
            CardFields(s.instanceId, s.cards.size.toLong(), SignedFrame.hash(crypto, s.cards.last()), origin, "Home", s.kind,
                operator, Bytes.toB64(operatorKey), s.recoveryFp, s.now - 10_000 + s.cards.size * 1_000L),
        )
    }

    /** A signed move, then a quiet sync: the card on show is Moved, with no refresh by hand. */
    @Test fun aMoveFoundByASyncIsOnTheCardAtOnce() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        nextCard(e.server, "https://moved.example")
        val before = e.server.calls.count { it == WireRoute.INSTANCE }
        a.content!!.syncQuietly()
        assertEquals(before + 1, e.server.calls.count { it == WireRoute.INSTANCE }, "the sync checked the chain")
        assertIs<InstanceCardState.Moved>(a.snapshot.instance!!.card)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /**
     * A handover names the signed-in account as the operator under its own key; on a phone the next
     * sync's chain check signs it out at once (§12.2 rule 7), not the next unlock.
     */
    @Test fun aCardNamingTheAccountAsOperatorFoundByASyncSignsAPhoneOutAtOnce() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val me = a.keeper.session!!.userId
        val ownKey = a.keeper.established!!.account.signing.publicKey
        nextCard(e.server, e.server.origin, operator = me, operatorKey = ownKey)
        a.content!!.syncQuietly()
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertEquals(FirstRunNotice.OPERATOR_NEEDS_COMPUTER, a.at<EntryScreen.FirstRun>().notice)
        // The owner's decision of 2026-11-16: stopped and kept locked, never deleted.
        assertNotNull(a.at<EntryScreen.FirstRun>().heldAsOperator)
        kotlin.test.assertTrue(assertNotNull(a.keeper.session).heldAsOperator)
        assertNull(a.content)
    }

    /** An unreachable server changes nothing on the card. */
    @Test fun anUnreachableCheckLeavesTheCardAsItWas() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val card = a.snapshot.instance!!.card
        e.server.override[WireRoute.INSTANCE] = io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        a.content!!.syncQuietly()
        assertEquals(card, a.snapshot.instance!!.card)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }
}
