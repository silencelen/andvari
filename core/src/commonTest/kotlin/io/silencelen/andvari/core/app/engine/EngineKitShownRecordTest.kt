package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.MoveResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.UnlockForFilling
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
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
 * The mark that a kit was shown on this device and never confirmed (`ovh.kit.shown|<server>|<address>`) is a record of that
 * server like the others: it goes when the server is forgotten and when the account is deleted on the device, it is carried
 * when a server's move is followed, and the forgetting of an earlier account takes it for that address. And the mark
 * behind "a kit is due at the app's opening" ends with every end of the session, not only at a lock.
 */
class EngineKitShownRecordTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"

    private fun app(server: FakeInstance, state: MemoryDeviceState = MemoryDeviceState(), alsoAt: List<String> = emptyList()): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server) + alsoAt.associateWith { server }), state,
            MemoryDeviceState(), crypto, { server.now }, baked = null, storeBuild = false, stores = null,
            main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** A registration of [email] with its first kit confirmed: the vault is open. */
    private suspend fun register(a: EngineAppApi, email: String = alice) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    private fun marks(state: MemoryDeviceState): List<String> = state.keys().filter { it.startsWith(EngineKit.SHOWN_KEY) }.sorted()

    @Test fun forgettingTheServerTakesTheMarkThatAKitWasShownThere() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val a = app(server, state)
        register(a)
        // A kit made in Settings and never confirmed: the mark is written.
        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        assertEquals(listOf(EngineKit.shownKey(server.origin, alice)), marks(state))
        assertEquals(PlainResult.DONE, a.instance.forgetServer(assertNotNull(a.snapshot.instance)))
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        // Before: the address and the server stayed on a device that was told to forget the server.
        assertEquals(emptyList(), marks(state))
    }

    @Test fun theAccountsDeletionOnThisDeviceTakesTheMark() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val a = app(server, state)
        register(a)
        // As a kit shown here and never confirmed leaves it (a lock took it; the account opened again from a kit since).
        state.set(EngineKit.shownKey(server.origin, alice), "1")
        // Another address's mark at the same server is not this account's.
        state.set(EngineKit.shownKey(server.origin, "carol@example.com"), "1")
        server.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        server.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(PlainResult.DONE, a.settings.openDeletion())
        assertEquals(DeletionResult.DONE, a.settings.deleteAccount(assertNotNull(a.snapshot.account!!.deletion), alice, strong, null))
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        // The server is forgotten with the account (decided on 2026-11-18: nothing of it stays), so every mark there goes.
        assertEquals(emptyList(), marks(state))
    }

    /** The operator signs the next card of [s]'s chain, at [origin]. */
    private fun nextCard(s: FakeInstance, origin: String) {
        s.cards += io.silencelen.andvari.core.trust.InstanceCard.sign(
            crypto, s.operatorSign,
            io.silencelen.andvari.core.trust.CardFields(
                s.instanceId, s.cards.size.toLong(), io.silencelen.andvari.core.trust.SignedFrame.hash(crypto, s.cards.last()), origin, "Home", s.kind,
                "99999999-9999-4999-8999-999999999999", io.silencelen.andvari.core.crypto.Bytes.toB64(s.operatorSign.publicKey), s.recoveryFp,
                s.now - 10_000 + s.cards.size * 1_000L,
            ),
        )
    }

    @Test fun aFollowedMoveCarriesTheMarkToTheNewAddress() = runBlocking<Unit> {
        val moved = "https://moved.example"
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val a = app(server, state, alsoAt = listOf(moved))
        register(a)
        // A kit made in Settings and never confirmed: the mark is written under the server's address.
        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        assertEquals(listOf(EngineKit.shownKey(server.origin, alice)), marks(state))

        nextCard(server, moved)
        (a.instance as EngineInstance).refresh()
        val card = assertIs<InstanceCardState.Moved>(a.snapshot.instance!!.card)
        assertEquals(MoveResult.DONE, a.instance.followMove(card))
        assertEquals(moved, a.keeper.session!!.origin)
        // Before: the mark stayed under the old address, so a kit at the new one could not say the earlier one was void,
        // and the old address stayed on the device.
        assertEquals(listOf(EngineKit.shownKey(moved, alice)), marks(state))
    }

    @Test fun theForgettingOfAnEarlierAccountTakesTheMarkForItsAddress() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val d = app(server, state)
        register(d)
        assertEquals(PlainResult.DONE, d.signOut())
        // A kit of the earlier account shown here and never confirmed (as a lock over a Settings kit leaves it), and
        // another address's at the same server.
        state.set(EngineKit.shownKey(server.origin, alice), "1")
        state.set(EngineKit.shownKey(server.origin, "carol@example.com"), "1")
        // The account is deleted and made again elsewhere.
        server.accounts.remove(alice)
        register(app(server))

        d.entry.openSignIn(d.at())
        d.entry.openPasswordSignIn(d.at())
        assertEquals(ServerResult.DONE, d.entry.chooseOwnServer(d.at(), server.origin))
        (d.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, d.entry.confirmTrustGate(it)) }
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(d.at(), alice, strong))
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        // Before: the earlier account's mark stayed, and the new account's first kit here would have called a kit void
        // that the new account never had.
        assertEquals(listOf(EngineKit.shownKey(server.origin, "carol@example.com")), marks(state))
    }

    @Test fun anOpeningForFillingWithoutItsKitEndsWithEveryEndOfTheSession() = runBlocking<Unit> {
        for (end in listOf("sign-out", "forget the server")) {
            val server = FakeInstance(crypto)
            val a = app(server)
            register(a)
            assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
            a.lock()
            assertEquals(VaultUnlockResult.DONE, (a as UnlockForFilling).unlockForFilling(a.snapshot.locked!!, strong))
            assertTrue(a.snapshot.account!!.kitDueAtOpening, end)
            assertTrue(a.openedWithoutKit, end)
            when (end) {
                "sign-out" -> assertEquals(PlainResult.DONE, a.signOut())
                else -> assertEquals(PlainResult.DONE, a.instance.forgetServer(assertNotNull(a.snapshot.instance)))
            }
            assertEquals(AppPhase.ENTRY, a.snapshot.phase, end)
            assertNull(a.snapshot.account, end)
            // Before: only a lock reset it, so the next session of that account would have been told to lock at its opening.
            assertFalse(a.openedWithoutKit, "$end ends it")
        }
    }
}
