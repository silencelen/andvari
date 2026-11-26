package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
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
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * "Forget the earlier account on this device" is offered only where the server serves ANOTHER account (by its id) than the
 * one this device ties the address to (decided on 2026-11-19), over the real engine and its test server. Where the server
 * serves the SAME account under another identity key, the refusal is the identity fault and nothing is offered: that is the
 * substitution the record exists to stop, and an account deleted and made again never comes back under its old id. After a
 * forgetting the earlier account's key stays on record, so that account is refused under another key there also then.
 *
 * "The same account under another key" is made on the test server as a deleted account made again under the very id it had
 * ([FixedId] gives the registration that id): a consistent account whose identity key is not the one this device knows.
 */
class EngineForgetEarlierCauseTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val replacement = "a brand new Master password 7"
    private val alice = "alice@example.com"
    private val bob = "bob@example.com"

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

    private fun device(server: FakeInstance, c: CryptoProvider = crypto): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), MemoryDeviceState(), MemoryDeviceState(), c,
            { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun toForm(a: EngineAppApi, email: String) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        a.at<EntryScreen.CreateAccount>()
    }

    /** Register [email] through the screens ([before] just before the account is made) and confirm the first kit. */
    private suspend fun register(a: EngineAppApi, email: String, before: () -> Unit = {}): KitDocument {
        toForm(a, email)
        before()
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "P", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        return doc
    }

    private fun idOf(a: EngineAppApi): String = assertNotNull(a.keeper.session).userId

    /** The account under [alice] is deleted at [server] and made again from another device under ANOTHER id. Its kit. */
    private suspend fun remade(server: FakeInstance): KitDocument {
        server.accounts.remove(alice)
        return register(device(server), alice)
    }

    /**
     * The account under [alice] at [server] is replaced by one made under the SAME id [userId] with another identity key: the
     * server serves the account this device knows under another key. Its kit.
     */
    private suspend fun sameIdOtherKey(server: FakeInstance, userId: String): KitDocument {
        val before = server.accounts.getValue(alice).identityPub
        server.accounts.remove(alice)
        val fixed = FixedId(crypto)
        val doc = register(device(server, fixed), alice) { fixed.next = assertNotNull(Bytes.fromHexLower(userId.replace("-", ""))) }
        assertEquals(userId, server.accounts.getValue(alice).userId, "the same account id")
        assertNotEquals(before, server.accounts.getValue(alice).identityPub, "another identity key")
        return doc
    }

    private suspend fun signInScreen(a: EngineAppApi, server: FakeInstance): EntryScreen.SignIn {
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), server.origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        return a.at()
    }

    private fun kitEntry(a: EngineAppApi): EntryScreen.KitEntry {
        a.entry.openSignIn(a.at())
        a.entry.openForgot(a.at())
        a.entry.openKitEntry(a.at())
        return a.at()
    }

    private suspend fun toConfirm(a: EngineAppApi, doc: KitDocument) {
        assertEquals(KitScanResult.DONE, a.entry.submitKit(kitEntry(a), doc.qrPayload, PayloadSource.SCANNED))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        a.at<EntryScreen.KitRecover>()
    }

    private fun bindingKey(origin: String, email: String) = SessionKeeper.EMAIL_BINDING_PREFIX + origin + "|" + email

    private fun bindingOf(d: EngineAppApi, origin: String) = d.engine.state.get(bindingKey(origin, alice))

    /** This device's own record of [userId]'s identity key, as the keeper writes it. */
    private fun identityRecord(userId: String) = "ovh.identity|$userId"

    // ---- item 1: the two causes, at each place that raises the offer ----

    /**
     * The check's sequence at the sign-in: this device knows account U under the address with key P; the server serves U
     * with key Q. The sign-in is refused as the identity fault and nothing is offered, both where this device's record of
     * U's key says so and where the address's record alone does; an offer object made before (for a remade account) and its
     * confirmation forget nothing. Before: the offer was raised, and two taps removed the record that stops the substitution.
     */
    @Test fun aSignInServingTheKnownAccountUnderAnotherKeyIsTheIdentityFaultWithNoOffer() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        register(d, alice)
        val u = idOf(d)
        assertEquals(PlainResult.DONE, d.signOut())
        // First another account under the address (remade): offered as before; the confirmation object is kept.
        remade(server)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        val offer = assertNotNull(d.snapshot.earlierAccount, "another account: offered")
        assertEquals(u, offer.earlierUserId)
        assertTrue(d.entry.askToForgetEarlierAccount(offer))
        val stale = assertNotNull(d.snapshot.earlierAccount)
        assertTrue(stale.confirming)
        // Then the account U itself, under another key.
        sameIdOtherKey(server, u)
        val bound = assertNotNull(bindingOf(d, server.origin))
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(d.at(), alice, strong))
        assertNull(d.snapshot.earlierAccount, "the same account under another key: nothing is offered")
        assertEquals(ForgetEarlierResult.STALE, d.entry.forgetEarlierAccount(stale))
        assertEquals(bound, bindingOf(d, server.origin), "nothing was forgotten")
        assertNotNull(d.engine.state.get(identityRecord(u)))
        // The keeper's own comparison: the address's record alone names U with P (no record of U's key).
        d.engine.state.set(identityRecord(u), null)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(d.at(), alice, strong))
        assertNull(d.snapshot.earlierAccount, "the address's record names this account under another key: nothing is offered")
        assertEquals(bound, bindingOf(d, server.origin))
        assertNull(d.keeper.session, "nothing was taken")
    }

    /**
     * An offer made for a remade account (served V, the address tied to U) whose confirmation stands when the address comes
     * to be tied to V itself: the confirmation is not taken, nothing is forgotten, and the offer goes. Before: the
     * forgetting went ahead and forgot V, the account the server serves.
     */
    @Test fun aConfirmationIsNotTakenOnceTheAddressIsTiedToTheServedAccount() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        register(d, alice)
        assertEquals(PlainResult.DONE, d.signOut())
        remade(server)
        val v = server.accounts.getValue(alice)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        val confirm = assertNotNull(d.snapshot.earlierAccount)
        // The address is tied to V now (as a take of V by another flow writes it).
        val tied = "${v.userId}|${v.identityPub}"
        d.engine.state.set(bindingKey(server.origin, alice), tied)
        val r = d.entry.forgetEarlierAccount(confirm)
        assertEquals(ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT, r, "said as what happened, never \"read it again\"")
        assertEquals(io.silencelen.andvari.core.app.CopyKey.REMADE_ACCOUNT_FORGET_ADDRESS_NOW_SERVED, r.sentence)
        assertEquals(tied, bindingOf(d, server.origin), "nothing was forgotten")
        assertNull(d.snapshot.earlierAccount)
    }

    /** A registration under an address known here as another account: offered as before (a new account never has an old id). */
    @Test fun aRegistrationUnderAnAddressKnownAsAnotherAccountIsOfferedAsBefore() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        register(d, alice)
        val u = idOf(d)
        assertEquals(PlainResult.DONE, d.signOut())
        server.accounts.remove(alice)
        toForm(d, alice)
        assertEquals(CreateAccountResult.IDENTITY_FAULT, d.entry.createAccount(d.at(), NewAccountInput("", "P", strong, true)))
        assertEquals(u, assertNotNull(d.snapshot.earlierAccount).earlierUserId)
    }

    /**
     * The kit's check: the kit of account U under another key, on a device that knows U under the address. Refused as the
     * identity fault with no offer, where this device's record of U's key says so (as before) and where the address's
     * record alone does (before: offered); nothing is committed. A kit of a remade account (another id) is offered as before.
     */
    @Test fun aKitCheckOffersOnlyForAnotherAccount() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        register(d, alice)
        val u = idOf(d)
        assertEquals(PlainResult.DONE, d.signOut())
        val swapped = sameIdOtherKey(server, u)
        for (withRecord in listOf(true, false)) {
            if (!withRecord) d.engine.state.set(identityRecord(u), null)
            toConfirm(d, swapped)
            assertEquals(KitRecoverResult.IDENTITY_FAULT, d.entry.confirmKitRecovery(d.at()), "record of the key: $withRecord")
            assertNull(d.snapshot.earlierAccount, "the same account under another key: nothing is offered (record of the key: $withRecord)")
            d.entry.startOver()
        }
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "nothing was committed")
        val other = remade(server)
        toConfirm(d, other)
        assertEquals(KitRecoverResult.IDENTITY_FAULT, d.entry.confirmKitRecovery(d.at()))
        assertEquals(u, assertNotNull(d.snapshot.earlierAccount, "another account: offered as before").earlierUserId)
    }

    /**
     * The kit's commit, asked again just before it is sent: the address came to be tied here to the kit's own account under
     * another key meanwhile. The identity fault, no offer, nothing committed (before: offered). Tied to another account
     * instead: offered as before.
     */
    @Test fun aKitCommitOffersOnlyForAnotherAccount() = runBlocking<Unit> {
        for (another in listOf(false, true)) {
            val server = FakeInstance(crypto)
            val doc = register(device(server), alice)
            val u = server.accounts.getValue(alice).userId
            register(device(server), bob)
            val b = server.accounts.getValue(bob)
            val d = device(server)
            toConfirm(d, doc)
            assertEquals(KitRecoverResult.DONE, d.entry.confirmKitRecovery(d.at()))
            val choose = d.at<EntryScreen.ReplacePassword>()
            // As a take writes it: the account (U, or another account) with an identity key that is not U's.
            d.engine.state.set(bindingKey(server.origin, alice), "${if (another) b.userId else u}|${b.identityPub}")
            assertEquals(ReplacePasswordResult.IDENTITY_FAULT, d.entry.chooseReplacementPassword(choose, replacement), "another account: $another")
            assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "nothing was committed")
            if (another) {
                assertEquals(b.userId, assertNotNull(d.snapshot.earlierAccount, "another account: offered as before").earlierUserId)
            } else {
                assertNull(d.snapshot.earlierAccount, "the same account under another key: nothing is offered")
            }
        }
    }

    // ---- item 2: the forgetting keeps the record of the earlier account's key ----

    /**
     * After a forgetting of account U (the server served another account V under the address), the server serves U again
     * under another key Q: refused as the identity fault, at the sign-in and at the kit's check, with no offer (before: U
     * was taken under Q). Served again under its own key P: taken as U, with nothing of U's earlier records on the device.
     */
    @Test fun afterAForgettingTheEarlierAccountIsRefusedUnderAnotherKeyAndTakenUnderItsOwn() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        register(d, alice)
        val u = idOf(d)
        val own = server.accounts.getValue(alice)
        assertEquals(PlainResult.DONE, d.signOut())
        d.engine.state.set("ovh.acct|$u|checkpoint", "7|sealed")
        remade(server)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertNull(d.engine.state.get("ovh.acct|$u|checkpoint"))
        // The second step: the server serves the forgotten account U again, under a key of its own.
        val swapped = sameIdOtherKey(server, u)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(d.at(), alice, strong))
        assertNull(d.snapshot.earlierAccount, "nothing is offered")
        assertNull(d.keeper.session, "U under another key is not taken")
        d.entry.startOver()
        toConfirm(d, swapped)
        assertEquals(KitRecoverResult.IDENTITY_FAULT, d.entry.confirmKitRecovery(d.at()))
        assertNull(d.snapshot.earlierAccount)
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "nothing was committed")
        d.entry.startOver()
        // U, never deleted after all, served again under its own key: taken as itself.
        server.accounts[alice] = own
        assertEquals(SignInAnswer.DONE, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
        assertEquals(u, idOf(d))
        assertNotEquals("7|sealed", d.engine.state.get("ovh.acct|$u|checkpoint"), "nothing of U's earlier records")
    }

    /**
     * After a forgetting of U, the next account V under the address is taken and recorded: U under another key is still
     * refused with no offer, and a third account W under the address is refused with the offer, V now the earlier account.
     */
    @Test fun afterAForgettingTheNextAccountIsTheEarlierOneForAThird() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        register(d, alice)
        val u = idOf(d)
        assertEquals(PlainResult.DONE, d.signOut())
        remade(server)
        val v = server.accounts.getValue(alice).userId
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertEquals(SignInAnswer.DONE, d.entry.submitSignIn(d.at(), alice, strong))
        assertEquals(v, idOf(d))
        assertTrue(assertNotNull(bindingOf(d, server.origin)).startsWith("$v|"), "V is recorded under the address")
        assertEquals(PlainResult.DONE, d.signOut())
        // U under another key, the address tied to V now: the identity fault, nothing offered.
        server.accounts.remove(alice)
        val fixed = FixedId(crypto)
        register(device(server, fixed), alice) { fixed.next = assertNotNull(Bytes.fromHexLower(u.replace("-", ""))) }
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertNull(d.snapshot.earlierAccount, "the forgotten account under another key: nothing is offered")
        // A third account W under the address: offered, with V as the earlier account.
        remade(server)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(d.at(), alice, strong))
        assertEquals(v, assertNotNull(d.snapshot.earlierAccount, "another account: offered").earlierUserId)
    }

    /**
     * U forgotten, V taken under the address; the server then serves U again under its own key: the identity fault with the
     * offer to forget V, the account the address names now (someone who forgot by mistake finds the way back), and U is not
     * taken before that. The fake plays the same (`FakeForgetEarlierStaleTest`).
     */
    @Test fun theEarlierAccountBackUnderItsOwnKeyIsOfferedToForgetTheNewOne() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        register(d, alice)
        val u = idOf(d)
        val own = server.accounts.getValue(alice)
        assertEquals(PlainResult.DONE, d.signOut())
        remade(server)
        val v = server.accounts.getValue(alice).userId
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertEquals(SignInAnswer.DONE, d.entry.submitSignIn(d.at(), alice, strong))
        assertEquals(v, idOf(d))
        assertEquals(PlainResult.DONE, d.signOut())
        server.accounts[alice] = own
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        val back = assertNotNull(d.snapshot.earlierAccount, "offered")
        assertEquals(v, back.earlierUserId, "the account offered is the new one")
        assertEquals(u, back.servedUserId, "the account served is the earlier one")
        assertNull(d.keeper.session)
    }
}
