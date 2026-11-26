package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.state.ContactRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What an account's other device decided is known at an opening: the account's state is read
 * once per opening, in the background, and after a read that got no answer at the next completed sync; what the server
 * serves is merged, never adopted. Two devices of one account over one server, the second signed in with the password.
 */
class EngineAccountStateReadTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val carol = "33333333-3333-4333-8333-333333333333"

    /** The server, with the account-state read of the device watched by [fails] refused and held while [holds] says so. */
    private class Front(val inner: FakeInstance) : WireClient by inner {
        var fails: () -> Boolean = { false }
        var holds: () -> Boolean = { false }
        val gate = CompletableDeferred<Unit>()
        var stateReads = 0
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == WireRoute.ACCOUNT_STATE_GET) {
                stateReads++
                if (fails()) return WireResult.Refused(503, WireError("unavailable", "x"))
                if (holds()) gate.await()
            }
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private fun app(server: FakeInstance, front: WireClient = server, state: MemoryDeviceState = MemoryDeviceState()): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to front)), state, MemoryDeviceState(), crypto,
            { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also {
        it.linksFlow.answersPollMs = Long.MAX_VALUE
        it.start()
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** The first device: typed address, Trust Gate, sign-up, kit, and Carol a compared contact of the account. */
    private suspend fun first(s: FakeInstance): EngineAppApi {
        val a = app(s)
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
        return a
    }

    /** Carol, compared on the device [a] (as a link there would have made her). */
    private suspend fun compareCarol(a: EngineAppApi, s: FakeInstance) {
        a.vault!!.store.update { doc ->
            doc.copy(contacts = doc.contacts + (carol to ContactRecord(carol, Bytes.toB64(crypto.randomBytes(32)), TrustGrammar.encodeName("Carol")!!,
                verifiedAt = s.now, compared = true, madeOn = "44444444-4444-4444-8444-444444444444")))
        }
    }

    /** The second device of the account signs in with only the password. */
    private suspend fun signIn(b: EngineAppApi, s: FakeInstance) {
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), s.origin))
        (b.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(it)) }
        assertEquals(SignInAnswer.DONE, b.entry.submitSignIn(b.at(), "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
    }

    private fun EngineAppApi.peopleList(): AccountPrompt.PeopleList? = snapshot.account!!.prompts.filterIsInstance<AccountPrompt.PeopleList>().singleOrNull()

    /**
     * A contact compared on the first device is one tap on the second without opening Contacts; when the opening's read
     * got no answer, the next completed sync reads again and the list comes then, and a read that answered is not made
     * again at every sync.
     */
    @Test fun aContactComparedOnTheFirstIsOneTapOnTheSecondEvenWhenTheOpeningsReadGotNoAnswer() = runBlocking<Unit> { withTimeout(60_000) {
        val s = FakeInstance(crypto)
        val a = first(s)
        compareCarol(a, s)

        val front = Front(s)
        val b = app(s, front)
        var failing = true
        front.fails = { failing && b.phase == AppPhase.UNLOCKED }
        signIn(b, s)
        assertNull(b.peopleList(), "nothing read yet")
        assertNull(b.snapshot.account!!.contacts, "the contacts screen is never opened in this test")

        failing = false
        // This server serves no `/sync` (the sync answers Failed): a completed attempt is enough for the read to be made again.
        b.content!!.refresh()
        val list = assertNotNull(b.peopleList(), "read again after the sync: ${b.snapshot.account!!.prompts}")
        assertEquals(listOf(carol), list.people.map { it.userId })
        assertTrue(list.people.single().compared)

        // One tap: Carol is current here.
        assertEquals(PlainResult.DONE, b.contacts.usePeople(list, listOf(carol)))
        assertNull(b.peopleList())
        assertTrue(assertNotNull(b.contactsFlow.rowFor(carol)).currentHere)

        // Answered: the next sync does not read again.
        val reads = front.stateReads
        b.content!!.refresh()
        assertEquals(reads, front.stateReads, "a read that answered is made once per opening")
    } }

    /** A contact compared on the first device AFTER the second opened is there at the second's next opening (an unlock). */
    @Test fun aContactComparedLaterIsOneTapAtTheNextUnlock() = runBlocking<Unit> {
        val s = FakeInstance(crypto)
        val a = first(s)
        val b = app(s)
        signIn(b, s)
        assertNull(b.peopleList())
        compareCarol(a, s)
        b.lock()
        assertEquals(VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        assertEquals(listOf(carol), assertNotNull(b.peopleList()).people.map { it.userId })
    }

    /**
     * A lying server can only withhold: at the second device's next opening it serves the account's earlier state (a
     * rollback), then none at all (withheld), then a blob that does not open, then a refusal. Each time this device's own
     * copy stays: Carol is still listed, compared, and nothing of hers was lost or changed.
     */
    @Test fun whatTheServerServesIsMergedNeverAdoptedSoALyingServerCanOnlyWithhold() = runBlocking<Unit> {
        val s = FakeInstance(crypto)
        val a = first(s)
        val acct = s.accounts.values.single()
        val earlier = acct.sealedState to acct.stateSeq
        compareCarol(a, s)
        val b = app(s)
        signIn(b, s)
        assertEquals(listOf(carol), assertNotNull(b.peopleList()).people.map { it.userId })
        val honest = acct.sealedState to acct.stateSeq

        val lies = listOf<() -> Unit>(
            { acct.sealedState = earlier.first; acct.stateSeq = earlier.second },
            { acct.sealedState = null; acct.stateSeq = honest.second },
            { acct.sealedState = Bytes.toB64(crypto.randomBytes(120)); acct.stateSeq = honest.second + 1 },
            { s.override[WireRoute.ACCOUNT_STATE_GET] = WireResult.Refused(500, WireError("internal", "x")) },
        )
        for ((n, lie) in lies.withIndex()) {
            b.lock()
            lie()
            assertEquals(VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong), "lie $n")
            val list = assertNotNull(b.peopleList(), "lie $n")
            assertEquals(listOf(carol), list.people.map { it.userId }, "lie $n")
            assertTrue(list.people.single().compared, "lie $n")
            assertEquals(true, b.vault!!.store.local().contacts[carol]?.compared, "lie $n: this device's copy keeps her")
            s.override.remove(WireRoute.ACCOUNT_STATE_GET)
            acct.sealedState = honest.first
            acct.stateSeq = honest.second
        }
    }

    /**
     * A lock while the opening's read waits leaves nothing behind: the answer that arrives after the lock is neither
     * opened nor kept, nothing is listed, and the next unlock reads again.
     */
    @Test fun aLockDuringTheReadLeavesNothingBehindAndTheNextUnlockReadsAgain() = runBlocking<Unit> { withTimeout(60_000) {
        val s = FakeInstance(crypto)
        val a = first(s)
        compareCarol(a, s)
        val front = Front(s)
        val state = MemoryDeviceState()
        val b = app(s, front, state)
        front.holds = { b.phase == AppPhase.UNLOCKED && !front.gate.isCompleted }
        signIn(b, s)
        assertNull(b.peopleList(), "the read waits")
        val userId = assertNotNull(b.keeper.session).userId
        val kept = state.get("ovh.acct|$userId|sealed")

        b.lock()
        front.gate.complete(Unit)
        assertEquals(AppPhase.LOCKED, b.snapshot.phase)
        assertEquals(kept, state.get("ovh.acct|$userId|sealed"), "nothing was kept from the answer that came after the lock")
        assertNull(b.snapshot.account)

        assertEquals(VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        assertEquals(listOf(carol), assertNotNull(b.peopleList()).people.map { it.userId })
    } }
}
