package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The keeper's forgetting, over the real engine and its test server: it forgets the account the person's confirmation
 * named and no other, also where a second process ties the address to another account in between; a forgetting cut at the
 * removal of the earlier account's identity record is finished; and the forgetting after a deletion whose outcome is not
 * known leaves the records of which account the address is and of that account's identity key, as a sign-out does.
 */
class EngineForgetEarlierSettleTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"

    /**
     * A store that fails once at the removal of a key starting with [failAt], and that runs [atMark] once, right after the
     * forgetting's mark that it is begun is written (the last write before the keeper's call).
     */
    private class Store(val inner: MemoryDeviceState) : DeviceState {
        var failAt: String? = null
        var atMark: (() -> Unit)? = null
        override fun get(key: String): String? = inner.get(key)
        override fun keys(): Set<String> = inner.keys()
        override fun set(key: String, value: String?) {
            val f = failAt
            if (f != null && value == null && key.startsWith(f)) {
                failAt = null
                throw IllegalStateException("store failed on $key")
            }
            inner.set(key, value)
            if (key == EngineAppApi.FORGETTING_KEY && value != null) atMark?.let { act ->
                atMark = null
                act()
            }
        }
    }

    /** [inner], except that the next 16 random bytes asked for are [next], once: a registration's new account id. */
    private class FixedId(val inner: CryptoProvider) : CryptoProvider by inner {
        var next: ByteArray? = null
        override fun randomBytes(n: Int): ByteArray {
            val fixed = next
            if (n == 16 && fixed != null) {
                next = null
                return fixed.copyOf()
            }
            return inner.randomBytes(n)
        }
    }

    private fun device(server: FakeInstance, state: DeviceState = MemoryDeviceState(), secure: DeviceState = MemoryDeviceState(), c: CryptoProvider = crypto): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), state, secure, c,
            { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun register(a: EngineAppApi, email: String, before: () -> Unit = {}): String {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        before()
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "P", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        return assertNotNull(a.keeper.session).userId
    }

    private suspend fun signInScreen(a: EngineAppApi, server: FakeInstance): EntryScreen.SignIn {
        (a.snapshot.entry as? EntryScreen.SignIn)?.let { return it }
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), server.origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        return a.at()
    }

    /** [alice]'s account was made on [d] and signed out there, then deleted and made again elsewhere. The earlier user id. */
    private suspend fun remadeAfterSignOut(server: FakeInstance, d: EngineAppApi): String {
        val earlier = register(d, alice)
        assertEquals(PlainResult.DONE, d.signOut())
        server.accounts.remove(alice)
        register(device(server), alice)
        return earlier
    }

    /** Refused at the sign-in with the offer, and the second confirmation on show. */
    private suspend fun toConfirmation(d: EngineAppApi, server: FakeInstance) {
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertTrue(assertNotNull(d.snapshot.earlierAccount).confirming)
    }

    private fun bindingKey(origin: String) = SessionKeeper.EMAIL_BINDING_PREFIX + origin + "|" + alice

    /** Every record of [state] whose key or value names [userId]. */
    private fun naming(state: MemoryDeviceState, userId: String): List<String> =
        state.keys().filter { it.contains(userId) || state.get(it)?.contains(userId) == true }.sorted()

    private fun all(state: MemoryDeviceState): Map<String, String> = state.keys().associateWith { state.get(it)!! }

    private fun kept(origin: String, userId: String) = SessionKeeper.EARLIER_IDENTITY_PREFIX + origin + "|" + userId

    // ---- the keeper forgets the account the confirmation named ----

    /**
     * Between the confirmation and the keeper's call, the address's record comes to name a third account C (as a second
     * process sharing this device's records would write it, taking C under the address): the keeper answers that the
     * confirmation no longer holds, and nothing is forgotten, neither of C nor of the account the confirmation named. Before:
     * C was forgotten (its records deleted, its key moved to the kept record) and the answer was "forgotten".
     */
    @Test fun anAddressTiedToAnotherAccountBeforeTheKeepersCallIsNotForgotten() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val inner = MemoryDeviceState()
        val state = Store(inner)
        val d = device(server, state)
        val a = remadeAfterSignOut(server, d)
        toConfirmation(d, server)
        val confirmation = assertNotNull(d.snapshot.earlierAccount)
        assertEquals(a, confirmation.earlierUserId)
        val c = "00000000-0000-4000-8000-0000000000cc"
        val cKey = Bytes.toB64(crypto.randomBytes(32))
        state.atMark = {
            inner.set(bindingKey(server.origin), "$c|$cKey")
            inner.set("ovh.identity|$c", cKey)
            inner.set("ovh.acct|$c|checkpoint", "7|sealed")
            inner.set("ovh.current|${server.origin}|$c", "{}")
        }
        // What names the confirmation's account, but the address's record, which the second process replaces.
        val before = naming(inner, a) - bindingKey(server.origin)
        assertEquals(ForgetEarlierResult.NOT_CONFIRMED, d.entry.forgetEarlierAccount(confirmation))
        assertNull(state.atMark, "the second process wrote between the confirmation and the keeper's call")
        assertEquals("$c|$cKey", inner.get(bindingKey(server.origin)), "the address's record names C still")
        assertEquals(listOf("ovh.acct|$c|checkpoint", "ovh.current|${server.origin}|$c", "ovh.identity|$c", bindingKey(server.origin)).sorted(),
            naming(inner, c), "nothing of C is forgotten")
        assertNull(inner.get(kept(server.origin, c)))
        assertEquals(before, naming(inner, a), "nothing of the confirmation's account changed either")
        assertNull(inner.get(EngineAppApi.FORGETTING_KEY), "no forgetting stands begun")
        assertNotEquals(a, d.snapshot.earlierAccount?.earlierUserId, "no offer stands for the account the address no longer names")
    }

    // ---- a forgetting cut at the removal of the identity record is finished ----

    /**
     * The keeper's forgetting is cut at its last write, the removal of the earlier account's identity record (the address's
     * record is gone, the kept record written); then the app restarts: the settle at the start removes that identity record,
     * and nothing but the kept record names the account. Before: the identity record stayed for good.
     */
    @Test fun aForgettingCutAtTheIdentityRecordIsFinishedAtTheNextStart() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val inner = MemoryDeviceState()
        val state = Store(inner)
        val secure = MemoryDeviceState()
        val d = device(server, state, secure)
        val a = remadeAfterSignOut(server, d)
        toConfirmation(d, server)
        state.failAt = "ovh.identity|$a"
        assertIs<IllegalStateException>(runCatching { d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)) }.exceptionOrNull())
        assertNull(inner.get(bindingKey(server.origin)), "the address's record went")
        assertNotNull(inner.get("ovh.identity|$a"), "the cut left the identity record")
        d.close()
        val d2 = device(server, inner, secure)
        assertEquals(listOf(kept(server.origin, a)), naming(inner, a))
        assertNull(inner.get(EngineAppApi.FORGETTING_KEY))
        assertNull(d2.snapshot.earlierAccount)
        assertEquals(SignInAnswer.DONE, d2.entry.submitSignIn(signInScreen(d2, server), alice, strong))
        assertEquals(AppPhase.UNLOCKED, d2.snapshot.phase)
    }

    /** The same cut, then the person's next tap: said as forgotten, and the identity record goes with it. */
    @Test fun aForgettingCutAtTheIdentityRecordIsFinishedByTheNextTap() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val inner = MemoryDeviceState()
        val state = Store(inner)
        val d = device(server, state)
        val a = remadeAfterSignOut(server, d)
        toConfirmation(d, server)
        state.failAt = "ovh.identity|$a"
        assertIs<IllegalStateException>(runCatching { d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)) }.exceptionOrNull())
        val again = assertNotNull(d.snapshot.earlierAccount)
        assertTrue(again.confirming)
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(again))
        assertEquals(listOf(kept(server.origin, a)), naming(inner, a))
        assertNull(inner.get(EngineAppApi.FORGETTING_KEY))
    }

    /**
     * A forgetting of A cut at its identity record; the next account B is taken under the address and signed out; the server
     * then serves a third account C there, and the person confirms the forgetting of B. B is forgotten (the address is new
     * again, B's key kept on record), and A's forgetting is finished too. Before: the answer was "forgotten" for B while only
     * A's leftovers went, and B's record stayed.
     */
    @Test fun aCutForgettingFinishedByAConfirmationNamingAnotherAccountForgetsTheConfirmedOne() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val inner = MemoryDeviceState()
        val state = Store(inner)
        val d = device(server, state)
        val a = remadeAfterSignOut(server, d)
        toConfirmation(d, server)
        state.failAt = "ovh.identity|$a"
        assertIs<IllegalStateException>(runCatching { d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)) }.exceptionOrNull())
        assertEquals(SignInAnswer.DONE, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        val b = assertNotNull(d.keeper.session).userId
        assertNotNull(inner.get(EngineAppApi.FORGETTING_KEY), "the cut forgetting of A is still marked")
        assertEquals(PlainResult.DONE, d.signOut())
        server.accounts.remove(alice)
        register(device(server), alice)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        val offer = assertNotNull(d.snapshot.earlierAccount)
        assertEquals(b, offer.earlierUserId)
        assertTrue(d.entry.askToForgetEarlierAccount(offer))
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertNull(inner.get(bindingKey(server.origin)), "B is forgotten: the address is new to this device")
        assertEquals(listOf(kept(server.origin, b)), naming(inner, b))
        assertEquals(listOf(kept(server.origin, a)), naming(inner, a))
        assertNull(inner.get(EngineAppApi.FORGETTING_KEY))
    }

    // ---- a confirmed deletion where a forgetting kept another account's key at the server ----

    /** The account's deletion, confirmed by the server, from its open vault. */
    private suspend fun deletedConfirmed(d: EngineAppApi, server: FakeInstance) {
        server.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        server.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(PlainResult.DONE, d.settings.openDeletion())
        assertEquals(DeletionResult.DONE, d.settings.deleteAccount(assertNotNull(d.snapshot.account!!.deletion), alice, strong, null))
        server.override.remove(WireRoute.ACCOUNT_DELETE)
    }

    /**
     * U is forgotten for V, V is taken, and V is deleted with the server's confirmation. The key a forgetting kept for U is
     * something of another account kept at that server: the server is kept and the notice says so, the pin stands, U's kept
     * record stands, and U served afterwards under another key is refused with no offer. Before: the deletion forgot the
     * server, U's kept key went with it, and U under another key was taken.
     */
    @Test fun aConfirmedDeletionAfterAForgettingKeepsTheServerAndTheEarlierAccountsKey() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val inner = MemoryDeviceState()
        val d = device(server, inner)
        val u = remadeAfterSignOut(server, d)
        toConfirmation(d, server)
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertEquals(SignInAnswer.DONE, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertNotEquals(u, assertNotNull(d.keeper.session).userId, "V is taken")
        deletedConfirmed(d, server)
        val said = assertNotNull(d.at<EntryScreen.FirstRun>().accountDeleted)
        assertEquals(false, said.serverForgotten, "the notice says the server was kept")
        assertIs<io.silencelen.andvari.core.client.pin.PinState.Pinned>(d.trust.pinState(server.origin), "the pin stands")
        assertNotNull(inner.get(kept(server.origin, u)), "U's kept key stands")

        // U served under another key.
        server.accounts.remove(alice)
        val fixed = FixedId(crypto)
        register(device(server, c = fixed), alice) { fixed.next = assertNotNull(Bytes.fromHexLower(u.replace("-", ""))) }
        assertEquals(u, server.accounts.getValue(alice).userId)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertNull(d.snapshot.earlierAccount, "no offer")
        assertNull(d.keeper.session, "U under another key is not taken")
    }

    /** Where nothing of another account is kept at the server (no kept key either), a confirmed deletion still forgets it. */
    @Test fun aConfirmedDeletionWithNothingOfAnotherAccountStillForgetsTheServer() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val inner = MemoryDeviceState()
        val d = device(server, inner)
        register(d, alice)
        deletedConfirmed(d, server)
        assertEquals(true, assertNotNull(d.at<EntryScreen.FirstRun>().accountDeleted).serverForgotten)
        assertTrue(d.trust.pinState(server.origin) !is io.silencelen.andvari.core.client.pin.PinState.Pinned, "the server is forgotten")
        assertTrue(inner.keys().none { it.startsWith(SessionKeeper.EARLIER_IDENTITY_PREFIX) })
    }

    // ---- the forgetting after a deletion of unknown outcome ----

    /**
     * The account's deletion got no answer; the person forgets the account on this device. The device still knows which
     * account the address is, and that account's identity key: the same account served later under another key is refused
     * with no offer, and another account under the address is refused with the offer to forget the earlier one. Before:
     * both records went, and the same account under another key was taken.
     */
    @Test fun aForgettingAfterAnUnknownDeletionKeepsTheAddressAndKeyRecords() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val inner = MemoryDeviceState()
        val d = device(server, inner)
        val u = register(d, alice)
        val binding = assertNotNull(inner.get(bindingKey(server.origin)))
        val identity = assertNotNull(inner.get("ovh.identity|$u"))
        server.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        server.override[WireRoute.ACCOUNT_DELETE] = WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
        assertEquals(PlainResult.DONE, d.settings.openDeletion())
        assertEquals(DeletionResult.OUTCOME_UNKNOWN, d.settings.deleteAccount(assertNotNull(d.snapshot.account!!.deletion), alice, strong, null))
        server.override.remove(WireRoute.ACCOUNT_DELETE)
        assertEquals(PlainResult.DONE, d.forgetAfterUnknownDeletion(assertNotNull(d.forgetAfterUnknownDeletionCheck())))
        assertNull(d.keeper.session)
        assertEquals(binding, inner.get(bindingKey(server.origin)), "the address's record stays")
        assertEquals(identity, inner.get("ovh.identity|$u"), "the account's key record stays")

        // The same account U served under another key: refused, and nothing is offered.
        val pub = server.accounts.getValue(alice).identityPub
        server.accounts.remove(alice)
        val fixed = FixedId(crypto)
        register(device(server, c = fixed), alice) { fixed.next = assertNotNull(Bytes.fromHexLower(u.replace("-", ""))) }
        assertEquals(u, server.accounts.getValue(alice).userId)
        assertNotEquals(pub, server.accounts.getValue(alice).identityPub)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertNull(d.snapshot.earlierAccount, "the same account under another key: no offer")
        assertNull(d.keeper.session)

        // Another account under the address: refused, with the offer to forget U.
        server.accounts.remove(alice)
        val w = register(device(server), alice)
        assertNotEquals(u, w)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertEquals(u, assertNotNull(d.snapshot.earlierAccount, "another account: offered").earlierUserId)
        assertNull(d.keeper.session)
    }
}
