package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.KeptUnlock
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
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The owner's decision of 2026-11-16: "When a handover makes someone's account the server's operator: what happens to that
 * account on their phone? Stop using it at once, keep the copy locked, let the person remove it." On a phone, a verified
 * card naming the account as the operator stops the account (nothing more sent), keeps its copy locked (nothing deleted,
 * nothing opens it) and lets the person remove it; a lying server can neither cause that state nor any deletion.
 */
class EngineOperatorHeldTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Env(val server: FakeInstance, val transport: BearerTransport, val state: MemoryDeviceState, val secure: MemoryDeviceState, var app: EngineAppApi)

    private fun build(server: FakeInstance, transport: BearerTransport, state: MemoryDeviceState, secure: MemoryDeviceState): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", transport, state, secure, crypto, { server.now }, baked = null, storeBuild = false, stores = null,
            main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also {
        it.linkPollMs = Long.MAX_VALUE
        it.start()
    }

    private fun env(): Env {
        val server = FakeInstance(crypto)
        val transport = BearerTransport(mapOf(server.origin to server))
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        return Env(server, transport, state, secure, build(server, transport, state, secure))
    }

    /** The app starts again over the same device stores (a restart, or an update without a reinstall). */
    private fun restart(e: Env) {
        e.app.close()
        e.app = build(e.server, e.transport, e.state, e.secure)
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

    /** The next card of [s]'s chain, signed by [signer], naming [operator] with [operatorKey]. */
    private fun nextCard(s: FakeInstance, signer: KeyPairBytes, operator: String, operatorKey: ByteArray) {
        s.cards += InstanceCard.sign(
            crypto, signer,
            CardFields(s.instanceId, s.cards.size.toLong(), SignedFrame.hash(crypto, s.cards.last()), s.origin, "Home", s.kind,
                operator, Bytes.toB64(operatorKey), s.recoveryFp, s.now - 10_000 + s.cards.size * 1_000L),
        )
    }

    /** A handover to the open account, found by the next sync's chain check; a save waiting to be sent when it comes. */
    private suspend fun handedOver(e: Env): Pair<String, String> {
        val a = e.app
        open(a)
        val me = assertNotNull(a.keeper.session).userId
        val ownKey = assertNotNull(a.keeper.established).account.signing.publicKey
        nextCard(e.server, e.server.operatorSign, me, ownKey)
        a.content!!.syncQuietly()
        return me to e.server.origin
    }

    private fun EngineAppApi.held() = at<EntryScreen.FirstRun>().heldAsOperator

    /**
     * The handover found by a sync: the account stops at once (the vault closes, nothing more is sent: no sync, no queued
     * save, no refresh, no logout), the first screen shows the operator sentence and the account, held; nothing is
     * deleted: the session record with its wrapped key, the cache's account and its account-state copy stay.
     */
    @Test fun aHandoverStopsTheAccountAtOnceSendsNothingAndKeepsTheCopyLocked() = runBlocking<Unit> {
        val e = env()
        val (me, origin) = handedOver(e)
        val a = e.app
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertNull(a.content)
        assertNull(a.keeper.established, "the keys are wiped")
        val kept = assertNotNull(a.keeper.session, "the record and its wrapped key stay")
        assertTrue(kept.heldAsOperator)
        val first = a.at<EntryScreen.FirstRun>()
        assertEquals(FirstRunNotice.OPERATOR_NEEDS_COMPUTER, first.notice)
        val held = assertNotNull(first.heldAsOperator)
        assertEquals("alice@example.com", held.email)
        assertEquals(CopyKey.OPERATOR_HELD_ON_PHONE, held.line.key)
        // Counted while the vault was still open (this server serves no item plane, so nothing waited: 0).
        assertEquals(0, held.unsentChanges)
        assertEquals(CopyKey.OPERATOR_HELD_REMOVE_LOSES, held.removeLine.key)
        assertTrue(e.state.get(EngineAppApi.HELD_KEY).orEmpty().contains("$origin|$me"), "the copy is still listed as on this device")
        assertNotNull(e.state.get("ovh.acct|$me|sealed"), "the account-state copy stays")

        // Nothing at all is sent with the account from here on.
        val sent = e.transport.sent.size
        a.returnedToForeground()
        a.networkReturned()
        assertEquals(sent, e.transport.sent.size, "nothing sent: ${e.transport.sent.drop(sent).map { it.route }}")
        assertEquals(0, e.transport.bearersFor(WireRoute.LOGOUT).size, "not even a logout")
    }

    /**
     * Across a restart the state stands, and nothing opens the account: not the password, not a key from quick unlock,
     * not a new sign-in of the same account (refused before anything is sent). A later card naming someone else as the
     * operator changes nothing (the design is silent; it stays held until removed).
     */
    @Test fun theHeldStateSurvivesARestartAndNothingOpensTheAccount() = runBlocking<Unit> {
        val e = env()
        val (me, _) = handedOver(e)
        restart(e)
        val a = e.app
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertNotNull(a.held(), "shown after a restart")
        assertEquals(KeptUnlock.HeldAsOperator, a.keeper.unlock(strong.toCharArray()))
        assertEquals(KeptUnlock.HeldAsOperator, a.keeper.unlockWithUvk(ByteArray(32) { 1 }))
        assertNull(a.keeper.established)

        val logins = e.server.calls.count { it == WireRoute.LOGIN }
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), e.server.origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        // Said as what it is, with its own way out (remove it from this device), never as "another account is kept".
        assertEquals(SignInAnswer.OPERATOR_ACCOUNT_HELD, a.entry.submitSignIn(a.at(), "alice@example.com", strong))
        assertEquals(logins, e.server.calls.count { it == WireRoute.LOGIN }, "the password went nowhere")
        assertTrue(assertNotNull(a.keeper.session).heldAsOperator)

        // The role moves on to someone else: still held.
        nextCard(e.server, e.server.operatorSign, "99999999-9999-4999-8999-999999999999", e.server.operatorSign.publicKey)
        restart(e)
        assertTrue(assertNotNull(e.app.keeper.session).heldAsOperator)
        assertEquals(me, e.app.keeper.session!!.userId)
    }

    /** The person removes it, after the confirmation: the copy goes, nothing is sent, and the first screen is as for no account. */
    @Test fun thePersonRemovesTheHeldAccountAndOnlyThenItsCopyGoes() = runBlocking<Unit> {
        val e = env()
        val (me, origin) = handedOver(e)
        restart(e)
        val a = e.app
        val held = assertNotNull(a.held())
        val sent = e.transport.sent.size
        assertEquals(PlainResult.DONE, a.entry.removeHeldOperatorAccount(held))
        assertEquals(sent, e.transport.sent.size, "nothing sent")
        assertNull(a.keeper.session)
        assertNull(a.held())
        assertFalse(e.state.get(EngineAppApi.HELD_KEY).orEmpty().contains("$origin|$me"), "the copy is gone")
        assertEquals(PlainResult.STALE, a.entry.removeHeldOperatorAccount(held), "once")
    }

    /** A server that serves a card naming the account, signed by a key that is not the operator's: refused, nothing held. */
    @Test fun aCardTheDeviceCannotVerifyPutsNothingInThisState() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val me = assertNotNull(a.keeper.session).userId
        val stranger = crypto.signKeypairFromSeed(ByteArray(32) { 9 })
        nextCard(e.server, stranger, me, stranger.publicKey)
        a.content!!.syncQuietly()
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertFalse(assertNotNull(a.keeper.session).heldAsOperator)
        assertNotNull(a.content)
    }

    /**
     * The old deletion path is gone: a server that says "operator" in a sign-in's answer (its word, no card) to a phone
     * that holds the account's copy (signed out by the server, signing in again) gets the sign-in refused, and nothing of
     * the copy is deleted, at once or at the next start. Before, that sign-out counted as the person's own and the next
     * start deleted the copy.
     */
    @Test fun aServerThatSaysOperatorAtASignInCanNoLongerMakeThePhoneDeleteItsCopy() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val me = assertNotNull(a.keeper.session).userId
        val origin = e.server.origin
        a.keeper.endedByServer(origin)
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        a.signInAgain(assertNotNull(a.snapshot.locked))
        e.server.operatorUserId = me
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(SignInAnswer.OPERATOR_NEEDS_COMPUTER, a.entry.submitSignIn(a.at(), "alice@example.com", strong))
        assertTrue(e.state.get(EngineAppApi.HELD_KEY).orEmpty().contains("$origin|$me"))
        restart(e)
        assertTrue(e.state.get(EngineAppApi.HELD_KEY).orEmpty().contains("$origin|$me"), "nothing deleted at the next start")
    }
}
