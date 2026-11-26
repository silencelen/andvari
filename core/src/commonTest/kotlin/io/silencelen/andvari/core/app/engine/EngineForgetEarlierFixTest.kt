package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
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
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
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
 * "Forget the earlier account on this device" (decided on 2026-11-17), what a review of it found: every record the device
 * keeps for the server under the earlier account's user id goes with it, and nothing of another account, of the server or of
 * the device's own row; a forgetting begun is finished, by the next tap or at the next start, also after a store that failed
 * part-way or a stop right after the keeper's call; and the confirmation says of a copy held here that it is deleted, also
 * where the keeper cannot read it as its session.
 */
class EngineForgetEarlierFixTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"

    /** A store that fails once: at the removal of a key starting with [failAt], or at the next write after [armAt] is removed. */
    private class Failing(val inner: MemoryDeviceState) : DeviceState {
        var failAt: String? = null
        var armAt: String? = null
        private var armed = false
        override fun get(key: String): String? = inner.get(key)
        override fun keys(): Set<String> = inner.keys()
        override fun set(key: String, value: String?) {
            if (armed) {
                armed = false
                throw IllegalStateException("store failed on $key")
            }
            val f = failAt
            if (f != null && value == null && key.startsWith(f)) {
                failAt = null
                throw IllegalStateException("store failed on $key")
            }
            inner.set(key, value)
            if (value == null && key == armAt) {
                armAt = null
                armed = true
            }
        }
    }

    private fun device(server: FakeInstance, state: DeviceState = MemoryDeviceState(), secure: DeviceState = MemoryDeviceState()): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), state, secure, crypto,
            { server.now }, baked = null, storeBuild = false, stores = null,
            main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun register(a: EngineAppApi, email: String): String {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "P", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        return assertNotNull(a.keeper.session).userId
    }

    private suspend fun signInScreen(a: EngineAppApi, server: FakeInstance): EntryScreen.SignIn {
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

    private fun bindingOf(d: EngineAppApi, origin: String): String? = d.engine.state.get(SessionKeeper.EMAIL_BINDING_PREFIX + origin + "|" + alice)

    /** Every record of [state] whose key or value names [userId]. */
    private fun naming(state: MemoryDeviceState, userId: String): List<String> =
        state.keys().filter { it.contains(userId) || state.get(it)?.contains(userId) == true }.sorted()

    private fun all(state: MemoryDeviceState): Map<String, String> = state.keys().associateWith { state.get(it)!! }

    /** The record a forgetting keeps of [userId]'s identity key at [origin], and nothing else of the account. */
    private fun kept(origin: String, userId: String) = SessionKeeper.EARLIER_IDENTITY_PREFIX + origin + "|" + userId

    // ---- everything kept for the server under the earlier account's user id goes ----

    @Test fun everyRegisteredPerOriginPrefixIsDecidedByTheForgetting() = runBlocking<Unit> {
        // The app's own prefixes are registered at its start.
        device(FakeInstance(crypto))
        // Prefixes the engine's own tests register for themselves are no host's.
        val undecided = PinStore.originKeyed().filter { !it.startsWith("ovhtest.") && it !in EngineAppApi.FORGOTTEN_PER_ORIGIN }
        assertEquals(emptyList(), undecided, "a per-origin prefix the forgetting does not know how to treat")
    }

    @Test fun everyRecordKeptForTheServerUnderTheEarlierAccountGoesAndNothingElse() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val d = device(server, state, secure)
        val a = remadeAfterSignOut(server, d)
        toConfirmation(d, server)
        // Another account at the same server, and the same user id at another server where this device never held it.
        val b = "0b6f0c2e-6c1d-4c8e-9a51-3f1d2c7e8a90"
        val o = server.origin
        val other = "https://other.example"
        for ((p, accounts) in EngineAppApi.FORGOTTEN_PER_ORIGIN) {
            if (accounts) {
                for (u in listOf(a, b)) {
                    state.set("$p$o|$u", "1")
                    state.set("$p$o|$u|part", "1")
                }
                state.set("$p$other|$a", "1")
            } else {
                state.set("$p$o", "1")
                state.set("$p$o|carol@example.com", "1")
            }
        }
        for (u in listOf(a, b)) for (k in listOf("ovh.acct|$u|checkpoint", "ovh.log|$u|v1|3", "ovh.rmirror|$u", "ovh.escrowfp|$u", "ovh.items|$u|lost")) state.set(k, "1")
        val before = all(state)
        val secureBefore = all(secure)
        // What names the earlier account at this server: every record planted for it, the address's record, its identity record.
        val expected = before.keys.filter { (it.contains(a) || before.getValue(it).contains(a)) && !it.contains(other) }.toSet()
        assertTrue(expected.any { it.startsWith("ovh.current|") } && expected.any { it.startsWith(EngineRecovery.MINE_KEY) }, "$expected")

        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        val after = all(state)
        // Before: nine kinds of per-origin record of the earlier account were left (its confirmed contacts among them).
        // Another server has records under the earlier account's id (planted above), so what is kept by that id alone is that
        // server's too and stays, as at a deletion (one tie for every end); everything else of the account here goes.
        // Its identity record stays too, with what is kept by its id: that other server ties the account, and something of
        // it is in flight there (a mark of a deletion of unknown outcome is among the records planted), so the device still
        // knows it, and an end keeps what the device's sweep of accounts it no longer knows would keep.
        assertEquals(expected.filterNot { k -> k == "ovh.identity|$a" || keptByIdAlone.any { p -> k == p + a || k.startsWith("$p$a|") } }.sorted(), (before.keys - after.keys).sorted(), "removed")
        // Added: the mark for the notice at the next take under the address, which names no account; and the one record the
        // forgetting keeps of the earlier account: its id and identity key, as the server's (decided on 2026-11-19).
        assertEquals(listOf(EngineAppApi.REMEMBERED_PREFIX + "$o|$alice", kept(o, a)).sorted(), (after.keys - before.keys).sorted(), "added")
        assertEquals(alice, after[EngineAppApi.REMEMBERED_PREFIX + "$o|$alice"])
        assertEquals(emptyList(), after.keys.filter { it in before && before[it] != after[it] && it != EngineAppApi.HELD_KEY }.sorted(), "changed")
        assertEquals(secureBefore, all(secure), "the secure store is untouched")
        assertTrue(after.keys.any { it.startsWith("ovh.dev|$o|") }, "the device's own row stays")
        assertIs<PinState.Pinned>(d.trust.pinState(o), "what this device knows of the server stays")
    }

    /** The prefixes of the records the forgetting keeps by the account's id alone (the vault logs among them). */
    private val keptByIdAlone = EngineAppApi.FORGOTTEN_KEYED + "ovh.log|"

    /**
     * The twin of the test above, without records at another server under the earlier account's id: nothing ties the
     * account elsewhere, so everything of it goes, what is kept by its id alone among it, and nothing else.
     */
    @Test fun everyRecordKeptUnderTheEarlierAccountGoesAndNothingElseWhereNoOtherServerHasRecordsUnderItsId() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val d = device(server, state, secure)
        val a = remadeAfterSignOut(server, d)
        toConfirmation(d, server)
        // Another account at the same server; no other server has anything under the earlier account's id.
        val b = "0b6f0c2e-6c1d-4c8e-9a51-3f1d2c7e8a90"
        val o = server.origin
        for ((p, accounts) in EngineAppApi.FORGOTTEN_PER_ORIGIN) {
            if (accounts) {
                for (u in listOf(a, b)) {
                    state.set("$p$o|$u", "1")
                    state.set("$p$o|$u|part", "1")
                }
            } else {
                state.set("$p$o", "1")
                state.set("$p$o|carol@example.com", "1")
            }
        }
        for (u in listOf(a, b)) for (k in listOf("ovh.acct|$u|checkpoint", "ovh.log|$u|v1|3", "ovh.rmirror|$u", "ovh.escrowfp|$u", "ovh.items|$u|lost")) state.set(k, "1")
        val before = all(state)
        val secureBefore = all(secure)
        // What names the earlier account: every record planted for it, the address's record, its identity record.
        val expected = before.keys.filter { it.contains(a) || before.getValue(it).contains(a) }.toSet()
        assertTrue(expected.any { it.startsWith("ovh.current|") } && expected.any { it.startsWith(EngineRecovery.MINE_KEY) }, "$expected")
        assertTrue(expected.count { k -> keptByIdAlone.any { p -> k.startsWith("$p$a|") || k == p + a } } >= 5, "$expected")

        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        val after = all(state)
        assertEquals(expected.sorted(), (before.keys - after.keys).sorted(), "removed")
        assertEquals(listOf(EngineAppApi.REMEMBERED_PREFIX + "$o|$alice", kept(o, a)).sorted(), (after.keys - before.keys).sorted(), "added")
        assertEquals(emptyList(), after.keys.filter { it in before && before[it] != after[it] && it != EngineAppApi.HELD_KEY }.sorted(), "changed")
        assertEquals(secureBefore, all(secure), "the secure store is untouched")
        assertTrue(after.keys.any { it.startsWith("ovh.dev|$o|") }, "the device's own row stays")
        assertIs<PinState.Pinned>(d.trust.pinState(o), "what this device knows of the server stays")
    }

    // ---- a forgetting begun is finished ----

    @Test fun aForgettingThatFailedPartWayIsFinishedByTheNextTapAndSaidAsForgotten() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val state = Failing(MemoryDeviceState())
        val d = device(server, state)
        val a = remadeAfterSignOut(server, d)
        state.set("ovh.acct|$a|checkpoint", "7|sealed")
        state.set("ovh.rmirror|$a", "private|fp|1")
        state.set("ovh.current|${server.origin}|$a", "{}")
        toConfirmation(d, server)
        state.failAt = "ovh.rmirror|$a"
        val thrown = runCatching { d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)) }.exceptionOrNull()
        assertIs<IllegalStateException>(thrown)
        assertNull(bindingOf(d, server.origin), "the keeper forgot")
        assertNotNull(state.get(EngineAppApi.FORGETTING_KEY), "the forgetting is marked as begun")
        val again = assertNotNull(d.snapshot.earlierAccount)
        assertTrue(again.confirming)
        // Before: NOTHING_TO_FORGET ("nothing changed"), and the records left stayed for good.
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(again))
        assertEquals(listOf(kept(server.origin, a)), naming(state.inner, a))
        assertNull(state.get(EngineAppApi.FORGETTING_KEY))
        assertNull(d.snapshot.earlierAccount)
    }

    @Test fun aForgettingThatFailedPartWayIsFinishedAtTheNextStart() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val inner = MemoryDeviceState()
        val state = Failing(inner)
        val secure = MemoryDeviceState()
        val d = device(server, state, secure)
        val a = remadeAfterSignOut(server, d)
        state.set("ovh.acct|$a|checkpoint", "7|sealed")
        state.set("ovh.rmirror|$a", "private|fp|1")
        state.set("ovh.codes|${server.origin}|$a", "{}")
        toConfirmation(d, server)
        state.failAt = "ovh.rmirror|$a"
        assertIs<IllegalStateException>(runCatching { d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)) }.exceptionOrNull())
        d.close()
        // Before: the same records were left after the restart; nothing settled them.
        val d2 = device(server, inner, secure)
        assertEquals(listOf(kept(server.origin, a)), naming(inner, a))
        assertNull(inner.get(EngineAppApi.FORGETTING_KEY))
        assertNull(d2.snapshot.earlierAccount)
        assertEquals(SignInAnswer.DONE, d2.entry.submitSignIn(signInScreen(d2, server), alice, strong))
        assertEquals(AppPhase.UNLOCKED, d2.snapshot.phase)
    }

    @Test fun aStopRightAfterTheKeepersCallIsFinishedAtTheNextStart() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val inner = MemoryDeviceState()
        val state = Failing(inner)
        val secure = MemoryDeviceState()
        val d = device(server, state, secure)
        val a = remadeAfterSignOut(server, d)
        state.set("ovh.acct|$a|checkpoint", "7|sealed")
        state.set("ovh.onetap|${server.origin}|$a", "1")
        toConfirmation(d, server)
        // The keeper's last write is the identity record's removal: the app stops at the next one.
        state.armAt = "ovh.identity|$a"
        assertIs<IllegalStateException>(runCatching { d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)) }.exceptionOrNull())
        assertNull(bindingOf(d, server.origin))
        assertTrue(naming(inner, a).any { it.startsWith("ovh.acct|") }, "nothing was deleted yet: ${naming(inner, a)}")
        d.close()
        device(server, inner, secure)
        assertEquals(listOf(kept(server.origin, a)), naming(inner, a))
        assertNull(inner.get(EngineAppApi.FORGETTING_KEY))
    }

    // ---- what the answers say ----

    /** A request for the operator's help kept at [origin] for [email], as the engine keeps one. */
    private fun keepRequest(d: EngineAppApi, origin: String, email: String) {
        io.silencelen.andvari.core.client.recovery.AssistRequests(d.requestStore, d.engine.clock, null).put(
            io.silencelen.andvari.core.client.recovery.KeptAssistRequest(
                origin, email, io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(16) { 1 }),
                io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 2 }), io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 3 }),
                io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 4 }), d.engine.clock(),
            ),
        )
    }

    @Test fun aRequestKeptIsSaidOnlyWhenTheKeptRequestIsForThisAddress() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        remadeAfterSignOut(server, d)
        toConfirmation(d, server)
        // A request kept at that server for another address, while a flow for this address is under way.
        keepRequest(d, server.origin, "bob@example.com")
        assertTrue(server.origin in d.assisted.keptOrigins())
        val done = d.keeper.underWay(server.origin, alice)
        // Before: REQUEST_KEPT, whose way out (leaving that request) would not free this address.
        assertEquals(ForgetEarlierResult.UNDER_WAY, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        done()
        // A request kept for this very address: said as that.
        keepRequest(d, server.origin, alice)
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.REQUEST_KEPT, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertNotNull(bindingOf(d, server.origin), "nothing was forgotten")
    }

    @Test fun afterForgottenATwoStepSignInStandsAtItsPasswordStep() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        remadeAfterSignOut(server, d)
        server.account(alice).totp = "123456"
        assertEquals(SignInAnswer.CODE_NEEDED, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignInCode(d.at(), "123456"))
        // The code step was used: the screen is back at the password at once, and the offer stays on it.
        assertTrue(!d.at<EntryScreen.SignIn>().codeNeeded)
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        // Before: the code screen stayed, and "try again" with the code was STALE.
        val again = d.at<EntryScreen.SignIn>()
        assertTrue(!again.codeNeeded, "back at the password step")
        assertEquals(SignInAnswer.CODE_NEEDED, d.entry.submitSignIn(again, alice, strong))
        assertEquals(SignInAnswer.DONE, d.entry.submitSignInCode(d.at(), "123456"))
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
        assertNotNull(d.snapshot.rememberedNewAccount)
    }

    /**
     * After a forgetting, the notice that this device now remembers the new account is kept at rest until it is dismissed:
     * the app closed after the take says it again at the next opening, a dismissal ends it for good, and the server's
     * forgetting takes its mark. Before: it lived in memory, and a restart lost it unsaid.
     */
    @Test fun theNoticeThatTheNewAccountIsRememberedStaysUntilDismissedAcrossARestart() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val d = device(server, state, secure)
        remadeAfterSignOut(server, d)
        toConfirmation(d, server)
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertEquals(SignInAnswer.DONE, d.entry.submitSignIn(d.at(), alice, strong))
        assertEquals(alice, assertNotNull(d.snapshot.rememberedNewAccount).email)
        d.close()

        val again = device(server, state, secure)
        assertEquals(AppPhase.LOCKED, again.snapshot.phase)
        val notice = assertNotNull(again.snapshot.rememberedNewAccount, "said again after a restart")
        assertEquals(CopyKey.REMADE_ACCOUNT_REMEMBERED, notice.line.key)
        again.dismissNewAccountRemembered(notice)
        assertNull(again.snapshot.rememberedNewAccount)
        again.close()
        assertNull(device(server, state, secure).snapshot.rememberedNewAccount, "dismissed: not said again")

        // A mark not yet dismissed goes with the server's forgetting.
        val marked = device(server, state, secure)
        state.set(EngineAppApi.REMEMBERED_PREFIX + server.origin + "|" + alice, alice)
        marked.instancePart.forgetOrigin(server.origin)
        assertEquals(emptyList(), state.keys().filter { it.startsWith(EngineAppApi.REMEMBERED_PREFIX) }, "gone with the server")
    }

    /**
     * The fake follows the engine where the session keeper refuses a sign-in once its code was taken: the screen is back at
     * the password, with the keeper's answer, on both. Before: the fake left the screen asking for a code.
     */
    @Test fun theFakeGoesBackToThePasswordAfterTheKeeperRefusesASignInsCodeAsTheEngineDoes() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        remadeAfterSignOut(server, d)
        server.account(alice).totp = "123456"
        assertEquals(SignInAnswer.CODE_NEEDED, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        val engine = listOf(d.entry.submitSignInCode(d.at(), "123456"), d.at<EntryScreen.SignIn>().codeNeeded)

        val f = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.SIGN_IN_CODE_NEEDED)
        f.script.identityFault = true
        val fake = listOf(f.entry.submitSignInCode(assertIs(f.snapshot.entry), "654321"), assertIs<EntryScreen.SignIn>(f.snapshot.entry).codeNeeded)
        assertEquals(listOf<Any>(SignInAnswer.IDENTITY_FAULT, false), engine)
        assertEquals(engine, fake)

        // The keeper's reasons of its own, on the fake: back at the password too, and the password and a code then sign in.
        f.script.keeperRefuses = io.silencelen.andvari.core.client.session.Establishing.KEPT_COPY_DAMAGED
        assertEquals(SignInAnswer.CODE_NEEDED, f.entry.submitSignIn(assertIs(f.snapshot.entry), io.silencelen.andvari.core.app.fake.FakeScenes.EMAIL,
            io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD))
        val refused = f.entry.submitSignInCode(assertIs(f.snapshot.entry), "654321")
        assertTrue(refused != SignInAnswer.DONE && refused != SignInAnswer.STALE, "$refused")
        assertTrue(!assertIs<EntryScreen.SignIn>(f.snapshot.entry).codeNeeded, "back at the password")
        f.script.keeperRefuses = null
        assertEquals(SignInAnswer.CODE_NEEDED, f.entry.submitSignIn(assertIs(f.snapshot.entry), io.silencelen.andvari.core.app.fake.FakeScenes.EMAIL,
            io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD))
        assertEquals(SignInAnswer.DONE, f.entry.submitSignInCode(assertIs(f.snapshot.entry), "654321"))
    }

    // ---- the confirmation says of every copy that is deleted that it is ----

    @Test fun aCopyHeldButNotReadAsTheKeptSessionIsSaidInTheConfirmation() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val d = device(server, state, secure)
        val a = register(d, alice)
        d.lock()
        assertTrue(state.get(EngineAppApi.HELD_KEY).orEmpty().contains(a))
        // The kept session record can no longer be read (a way of signing in this build does not know).
        val text = assertNotNull(secure.get(SessionKeeper.KEY))
        val bad = text.replace(Regex("\"how\":\"[A-Z_]+\""), "\"how\":\"NOT_A_WAY\"")
        assertNotEquals(text, bad)
        secure.set(SessionKeeper.KEY, bad)
        d.close()
        server.accounts.remove(alice)
        register(device(server), alice)
        val d2 = device(server, state, secure)
        assertNull(d2.keeper.session)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d2.entry.submitSignIn(signInScreen(d2, server), alice, strong))
        val offer = assertNotNull(d2.snapshot.earlierAccount)
        // Before: keptCopy false and 0, and no copy line, while the forgetting deleted the held copy.
        assertTrue(offer.keptCopy)
        assertNull(offer.unsentChanges, "cannot be told")
        assertTrue(d2.entry.askToForgetEarlierAccount(offer))
        val confirm = assertNotNull(d2.snapshot.earlierAccount)
        assertEquals(
            listOf(CopyKey.REMADE_ACCOUNT_CONFIRM, CopyKey.REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL, CopyKey.REMADE_ACCOUNT_CONFIRM_ALWAYS),
            confirm.confirmLines.map { it.key },
        )
        assertEquals(ForgetEarlierResult.FORGOTTEN, d2.entry.forgetEarlierAccount(confirm))
        assertTrue(!state.get(EngineAppApi.HELD_KEY).orEmpty().contains(a), "the held copy went")
    }

    /** What a screen reads of the offer: the copy, the count, and each confirmation line's key with its values after the address. */
    private fun offerRead(o: io.silencelen.andvari.core.app.EarlierAccountKnown): List<Any?> =
        listOf(o.keptCopy, o.unsentChanges, o.confirming, o.confirmLines.map { it.key to it.values.drop(1) })

    /**
     * An earlier account with one signed change to a shared vault that was never sent (a sign-out keeps it; the forgetting
     * removes it) and no copy held here: the confirmation names that one change; a second one while it is on show makes a
     * new confirmation, so the one shown no longer holds; after the forgetting those records are gone. The stand-in walks
     * the same and reads the same. Before: no copy held read as nothing unsent (0), and no line said that anything is lost.
     */
    @Test fun anEarlierAccountsSharedVaultChangeNeverSentIsCountedInTheConfirmationWithoutACopy() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val d = device(server, state)
        val earlier = remadeAfterSignOut(server, d)
        assertTrue(!state.get(EngineAppApi.HELD_KEY).orEmpty().contains(earlier), "no copy of it is held here")
        fun pending(v: String) = io.silencelen.andvari.core.client.log.StoredVaultLogs.recordKey(earlier, v, "pending")
        state.set(pending("v1"), "signed")
        state.set("ovh.log|$earlier|pending-index", "v1")

        val engine = io.silencelen.andvari.core.app.engine.Readings()
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        engine += offerRead(assertNotNull(d.snapshot.earlierAccount))
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        val confirm = assertNotNull(d.snapshot.earlierAccount)
        engine += offerRead(confirm)
        // A second change of that account waits while the confirmation is on show: the one shown no longer holds.
        state.set(pending("v2"), "signed")
        engine += d.entry.forgetEarlierAccount(confirm)
        val again = assertNotNull(d.snapshot.earlierAccount)
        kotlin.test.assertNotSame(confirm, again)
        engine += offerRead(again)
        engine += d.entry.forgetEarlierAccount(again)
        assertEquals(emptyList(), state.keys().filter { it.startsWith("ovh.log|$earlier|") }, "its signed changes went with it")

        val one = CopyKey.REMADE_ACCOUNT_CONFIRM_SHARED_ONE_UNSENT to emptyList<String>()
        val two = CopyKey.REMADE_ACCOUNT_CONFIRM_SHARED_UNSENT to listOf("2")
        val first = CopyKey.REMADE_ACCOUNT_CONFIRM to emptyList<String>()
        val last = CopyKey.REMADE_ACCOUNT_CONFIRM_ALWAYS to emptyList<String>()
        assertEquals<List<Any?>>(listOf(
            listOf(false, 1, false, emptyList<Any>()),
            listOf(false, 1, true, listOf(first, one, last)),
            ForgetEarlierResult.NOT_CONFIRMED,
            listOf(false, 2, true, listOf(first, two, last)),
            ForgetEarlierResult.FORGOTTEN,
        ), engine)

        val f = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.SIGN_IN)
        val email = io.silencelen.andvari.core.app.fake.FakeScenes.EMAIL
        val pw = io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD
        f.script.publicInstance.addAccount(email, pw)
        f.script.earlierAccountKnown = true
        f.script.earlierSharedChangesUnsent = 1
        f.script.identityFault = true
        val fake = io.silencelen.andvari.core.app.engine.Readings()
        assertEquals(SignInAnswer.IDENTITY_FAULT, f.entry.submitSignIn(assertIs(f.snapshot.entry), email, pw))
        fake += offerRead(assertNotNull(f.snapshot.earlierAccount))
        assertTrue(f.entry.askToForgetEarlierAccount(assertNotNull(f.snapshot.earlierAccount)))
        val fConfirm = assertNotNull(f.snapshot.earlierAccount)
        fake += offerRead(fConfirm)
        f.script.earlierSharedChangesUnsent = 2
        fake += f.entry.forgetEarlierAccount(fConfirm)
        val fAgain = assertNotNull(f.snapshot.earlierAccount)
        kotlin.test.assertNotSame(fConfirm, fAgain)
        fake += offerRead(fAgain)
        fake += f.entry.forgetEarlierAccount(fAgain)
        assertEquals(0, f.script.earlierSharedChangesUnsent, "gone with the forgetting")
        assertEquals<List<Any?>>(engine, fake)
    }
}
