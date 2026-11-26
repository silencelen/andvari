package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The session keeper's stops before anything is committed, and its refusals after a commit, as the screens say them: a
 * recovery with the kit at its start, its check and its commit, and a registration. Another account kept here is said
 * with its way out and never as a general failure or "the server's card was not accepted"; an address known here under
 * another account is the identity fault; a kit the server took while this device refused the session is shown, kept until
 * it is confirmed, and only then wiped.
 */
class EngineKeptStopsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val replacement = "a brand new Master password 7"
    private val alice = "alice@example.com"

    /** Runs [meanwhile] once, the first time [route] is called, before the call goes on to [inner]. */
    private class Racing(val inner: FakeInstance, val route: WireRoute) : WireClient by inner {
        var meanwhile: (suspend () -> Unit)? = null
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == this.route) meanwhile?.let { meanwhile = null; it() }
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private fun device(vararg servers: WireClient): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(servers.associateBy { it.origin }), MemoryDeviceState(), MemoryDeviceState(), crypto,
            { when (val s = servers.first()) { is Racing -> s.inner; is SeedSwap -> s.inner; else -> s as FakeInstance }.now }, baked = null, storeBuild = false, stores = null,
            main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Register [email] at [host] through the screens and confirm the first kit; the account is open and kept. */
    private suspend fun register(a: EngineAppApi, host: String, email: String): KitDocument {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), host))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "P", strong, true)))
        return confirmKit(a)
    }

    private suspend fun confirmKit(a: EngineAppApi): KitDocument {
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        return doc
    }

    private fun kitEntry(a: EngineAppApi): EntryScreen.KitEntry {
        a.entry.openSignIn(a.at())
        a.entry.openForgot(a.at())
        a.entry.openKitEntry(a.at())
        return a.at()
    }

    /** Hand [doc] in on the kit's screen and pass any Trust Gate: the confirmation is on show. */
    private suspend fun toConfirm(a: EngineAppApi, doc: KitDocument) {
        assertEquals(KitScanResult.DONE, a.entry.submitKit(kitEntry(a), doc.qrPayload, PayloadSource.SCANNED))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        a.at<EntryScreen.KitRecover>()
    }

    /** Another account is signed in on [a] behind the screens' back (as a race would have it): the keeper keeps it. */
    private suspend fun anotherAccountTaken(a: EngineAppApi, origin: String, email: String = "carol@example.com") {
        val o = a.onboardingFor(origin)
        o.signupStart(email, true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify(email, "482915"))
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), RegistrationForm(email, "C", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
        assertEquals(email, assertNotNull(a.keeper.session).emailNorm)
    }

    /** The account under [alice] at [server] is deleted and made again (a new account id) on another device: its kit. */
    private suspend fun remadeElsewhere(server: FakeInstance): KitDocument {
        server.accounts.remove(alice)
        return register(device(server), "h.example", alice)
    }

    @Test fun aKitAtAnotherServerWhileAnAccountIsKeptSaysSoAndSendsNothingThere() = runBlocking<Unit> {
        val a = FakeInstance(crypto)
        val b = FakeInstance(crypto, "https://b.example", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        val bobsKit = register(device(b), "b.example", "bob@example.com")
        val d = device(a, b)
        register(d, "h.example", alice)
        d.keeper.endedByServer(a.origin)
        d.signInAgain(assertNotNull(d.snapshot.locked))
        val sent = b.calls.size
        val r = d.entry.submitKit(kitEntry(d), bobsKit.qrPayload, PayloadSource.SCANNED)
        // Before: CARD_NOT_ACCEPTED ("the server's card was not accepted"), although nothing was asked of that server.
        assertEquals(KitScanResult.ANOTHER_ACCOUNT_KEPT, r)
        assertEquals(CopyKey.RECOVERY_ANOTHER_ACCOUNT_KEPT, r.sentence)
        assertEquals(sent, b.calls.size, "nothing was sent to the kit's server")
        d.at<EntryScreen.KitEntry>()
        assertEquals(alice, assertNotNull(d.snapshot.keptSignedOut).email, "the way out: the kept account, to sign out")
    }

    @Test fun aKitOfAnotherAccountUnderTheKeptAddressIsAnotherAccountKeptAtItsCheck() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        register(d, "h.example", alice)
        d.keeper.endedByServer(server.origin)
        d.signInAgain(assertNotNull(d.snapshot.locked))
        val remade = remadeElsewhere(server)
        toConfirm(d, remade)
        // Before: FAILED (a general failure).
        assertEquals(KitRecoverResult.ANOTHER_ACCOUNT_KEPT, d.entry.confirmKitRecovery(d.at()))
        d.at<EntryScreen.KitEntry>()
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "nothing was committed")
    }

    @Test fun aKitOfAnAccountMadeAgainUnderAnAddressThisDeviceKnewIsTheIdentityFaultAtItsCheck() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        register(d, "h.example", alice)
        assertEquals(PlainResult.DONE, d.signOut())
        val remade = remadeElsewhere(server)
        toConfirm(d, remade)
        // Before: FAILED (a general failure). The device remembers the earlier account under the address.
        assertEquals(KitRecoverResult.IDENTITY_FAULT, d.entry.confirmKitRecovery(d.at()))
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "nothing was committed")
    }

    @Test fun anAccountTakenBeforeTheCommitStopsItWithItsOwnResultAndNothingIsCommitted() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        val doc = register(d, "h.example", alice)
        assertEquals(PlainResult.DONE, d.signOut())
        toConfirm(d, doc)
        assertEquals(KitRecoverResult.DONE, d.entry.confirmKitRecovery(d.at()))
        val choose = d.at<EntryScreen.ReplacePassword>()
        anotherAccountTaken(d, server.origin)
        val r = d.entry.chooseReplacementPassword(choose, replacement)
        // Before: FAILED. Not ANOTHER_ACCOUNT_KEPT either, which says the new password is in force.
        assertEquals(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED, r)
        assertEquals(CopyKey.RECOVERY_ANOTHER_ACCOUNT_KEPT, r.sentence)
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "nothing was committed")
        d.at<EntryScreen.KitEntry>()
    }

    @Test fun aKitTheServerTookWhileThisDeviceRefusedTheSessionIsShownKeptUntilConfirmedThenWiped() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val racing = Racing(server, WireRoute.RECOVERY_SELF_COMMIT)
        val d = device(racing)
        val old = register(d, "h.example", alice)
        assertEquals(PlainResult.DONE, d.signOut())
        toConfirm(d, old)
        assertEquals(KitRecoverResult.DONE, d.entry.confirmKitRecovery(d.at()))
        racing.meanwhile = { anotherAccountTaken(d, server.origin) }
        val r = d.entry.chooseReplacementPassword(d.at(), replacement)
        assertEquals(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT, r, "the new password is in force; the other account is kept")
        assertTrue(WireRoute.RECOVERY_SELF_COMMIT in server.calls)
        // Before: the kit was wiped unshown and the journey stayed on the password screen.
        val kit = d.at<EntryScreen.Kit>().kit
        assertEquals(KitReason.AFTER_RECOVERY, kit.reason)
        assertEquals(CopyKey.KIT_RECOVERED_NOT_KEPT, kit.notKeptLine)
        assertEquals(AppPhase.ENTRY, d.snapshot.phase, "nothing of the recovered account opens here")
        val doc = assertNotNull(d.kit.kitDocument(kit))
        assertTrue(doc.qrPayload != old.qrPayload)
        // It is the kit the server holds a piece of: it is accepted on a fresh device, and the old one no longer is.
        val fresh = device(server)
        toConfirm(fresh, doc)
        assertEquals(KitRecoverResult.DONE, fresh.entry.confirmKitRecovery(fresh.at()))
        val stale = device(server)
        toConfirm(stale, old)
        assertEquals(KitRecoverResult.KIT_NOT_ACCEPTED, stale.entry.confirmKitRecovery(stale.at()))
        // A wrong confirm keeps it; after three, the kit is shown again, still readable.
        d.kit.proceedToConfirm(kit)
        repeat(3) {
            val confirm = d.at<EntryScreen.Kit>().kit
            assertEquals(KitConfirmResult.MISMATCH, d.kit.confirmKit(confirm, listOf("xxxx", "xxxx", "xxxx")))
        }
        val again = d.at<EntryScreen.Kit>().kit
        assertNotNull(d.kit.kitDocument(again), "not wiped before the confirmation")
        d.kit.proceedToConfirm(again)
        val confirm = d.at<EntryScreen.Kit>().kit
        assertEquals(CopyKey.KIT_RECOVERED_NOT_KEPT, confirm.notKeptLine)
        assertEquals(KitConfirmResult.DONE, d.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        // Wiped after it, and the journey is back at the first screen, with the kept account to sign out.
        assertNull(d.kitFlow.entryScreen)
        assertNull(d.kit.kitDocument(confirm))
        d.at<EntryScreen.FirstRun>()
        assertEquals("carol@example.com", assertNotNull(d.keeper.session).emailNorm)
    }

    /**
     * The earlier account under [alice] (deleted and made again since) is signed in on [d] behind the screens' back while a
     * recovery's commit of the account made again is on its way; [thenSignedOut]: and signed out again, so that only the
     * device's record of the address remains. The server's current account under the address is left as it was.
     */
    private suspend fun earlierAccountTakenMeanwhile(d: EngineAppApi, server: FakeInstance, earlier: FakeInstance.Account, thenSignedOut: Boolean) {
        val now = server.accounts.getValue(alice)
        server.accounts[alice] = earlier
        try {
            assertIs<io.silencelen.andvari.core.client.onboard.SignIn.SignedIn>(d.onboardingFor(server.origin).signIn(alice, strong.toCharArray(), null))
        } finally {
            server.accounts[alice] = now
        }
        assertEquals(earlier.userId, assertNotNull(d.keeper.session).userId)
        if (thenSignedOut) d.keeper.signOut()
    }

    /**
     * The check's road: a recovery with the kit of an account deleted and made again, on a device that comes to keep the
     * EARLIER account under the same address while the commit is on its way. The keeper refuses the session for its own
     * reason (another account kept; with the earlier account signed out again, the identity fault), and the screen says
     * that the commit happened: the new password is in force, the old kit is dead, and the new kit is on show. Before,
     * the reason was guessed from the addresses and said "the server's keys are not this account's: nothing was
     * committed", although the commit had gone through.
     */
    @Test fun aRecoveryCommittedWhileThisDeviceComesToKeepTheEarlierAccountSaysTheCommitHappened() = runBlocking<Unit> {
        for (thenSignedOut in listOf(false, true)) {
            val server = FakeInstance(crypto)
            val racing = Racing(server, WireRoute.RECOVERY_SELF_COMMIT)
            register(device(server), "h.example", alice)
            val earlier = server.accounts.getValue(alice)
            val remade = remadeElsewhere(server)
            val d = device(racing)
            // This device already holds the server's pin for signing in (another account of its, signed out since).
            register(d, "h.example", "zed@example.com")
            assertEquals(PlainResult.DONE, d.signOut())
            toConfirm(d, remade)
            assertEquals(KitRecoverResult.DONE, d.entry.confirmKitRecovery(d.at()))
            racing.meanwhile = { earlierAccountTakenMeanwhile(d, server, earlier, thenSignedOut) }
            val r = d.entry.chooseReplacementPassword(d.at(), replacement)
            val expected = if (thenSignedOut) ReplacePasswordResult.IDENTITY_FAULT_COMMITTED else ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT
            assertEquals(expected, r, "signed out again: $thenSignedOut")
            assertTrue(r != ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE, "never \"nothing was committed\"")
            assertTrue(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "the commit went through")
            // The new kit is on show with the line for that reason, and it is the account's: a fresh device recovers with it.
            val kit = d.at<EntryScreen.Kit>().kit
            assertEquals(if (thenSignedOut) CopyKey.RECOVERY_COMMITTED_IDENTITY_FAULT else CopyKey.KIT_RECOVERED_NOT_KEPT, kit.notKeptLine)
            if (thenSignedOut) assertEquals(CopyKey.RECOVERY_COMMITTED_IDENTITY_FAULT, r.sentence)
            val doc = assertNotNull(d.kit.kitDocument(kit))
            val fresh = device(server)
            toConfirm(fresh, doc)
            assertEquals(KitRecoverResult.DONE, fresh.entry.confirmKitRecovery(fresh.at()))
            // The old kit no longer works.
            val stale = device(server)
            toConfirm(stale, remade)
            assertEquals(KitRecoverResult.KIT_NOT_ACCEPTED, stale.entry.confirmKitRecovery(stale.at()))
        }
    }

    /**
     * The engine's reason `kept_copy_damaged`: this device keeps alice, signed out by her server, and its copy's sealed
     * identity seed is damaged (as damaged storage leaves it). A recovery with her own kit stops at its check with nothing
     * committed, said as the damaged copy with its way out, never a general failure.
     */
    @Test fun aKitRecoveryOverADamagedCopyIsSaidAsTheDamagedCopyAndCommitsNothing() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        fun on(): EngineAppApi = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), state, secure, crypto, { server.now },
                baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also { it.start() }
        val first = on()
        val kit = register(first, "h.example", alice)
        val userId = assertNotNull(first.keeper.session).userId
        first.keeper.endedByServer(server.origin)
        // The kept record's sealed identity seed is replaced by bytes of the same shape that open under no key of the account.
        val text = assertNotNull(secure.get(io.silencelen.andvari.core.client.session.SessionKeeper.KEY))
        val record = io.silencelen.andvari.core.model.wire.WireJson.json.parseToJsonElement(text).jsonObject
        val keys = assertNotNull(record["accountKeys"]).jsonObject
        val otherKey = crypto.randomBytes(32)
        val otherSeed = crypto.randomBytes(32)
        val damaged = io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, otherKey, otherSeed, io.silencelen.andvari.core.crypto.Ad.idkey(userId))
        otherKey.fill(0)
        otherSeed.fill(0)
        secure.set(io.silencelen.andvari.core.client.session.SessionKeeper.KEY,
            JsonObject(record + ("accountKeys" to JsonObject(keys + ("encryptedIdentitySeed" to JsonPrimitive(damaged))))).toString())
        // The device starts again from its stores.
        val d = on()
        d.signInAgain(assertNotNull(d.snapshot.locked))
        toConfirm(d, kit)
        val r = d.entry.confirmKitRecovery(d.at())
        // Before: FAILED (the reason was not mapped).
        assertEquals(KitRecoverResult.KEPT_COPY_DAMAGED, r)
        assertEquals(CopyKey.KEPT_COPY_DAMAGED, r.sentence)
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "nothing was committed")
        d.at<EntryScreen.KitEntry>()
        assertEquals(alice, assertNotNull(d.snapshot.keptSignedOut).email, "the way out: this device's copy, to remove")
    }

    @Test fun aRegistrationTheServerTookWhileThisDeviceRefusedTheSessionShowsItsKitUntilConfirmed() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val racing = Racing(server, WireRoute.REGISTER)
        val d = device(racing)
        d.entry.openOwnServer(d.at())
        assertEquals(ServerResult.DONE, d.entry.submitServerAddress(d.at(), "h.example"))
        assertEquals(ServerResult.DONE, d.entry.confirmTrustGate(d.at()))
        assertEquals(ServerResult.DONE, d.entry.createAccountHere(d.at()))
        assertEquals(SignUpStartResult.DONE, d.entry.startSignUp(d.at(), alice, true))
        assertEquals(CodeResult.DONE, d.entry.verifySignUpCode(d.at(), "482915"))
        racing.meanwhile = { anotherAccountTaken(d, server.origin) }
        val r = d.entry.createAccount(d.at(), NewAccountInput("", "Alice", strong, true))
        // Before: ANOTHER_ACCOUNT_KEPT ("no account was made"), with the kit dropped unshown.
        assertEquals(CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, r)
        assertTrue(server.accounts.containsKey(alice), "the account was made")
        val kit = d.at<EntryScreen.Kit>().kit
        assertEquals(KitReason.FIRST_KIT, kit.reason)
        assertEquals(CopyKey.KIT_REGISTERED_NOT_KEPT, kit.notKeptLine)
        val doc = assertNotNull(d.kit.kitDocument(kit))
        val fresh = device(server)
        toConfirm(fresh, doc)
        assertEquals(KitRecoverResult.DONE, fresh.entry.confirmKitRecovery(fresh.at()), "the kit shown is the account's")
        d.kit.proceedToConfirm(kit)
        val confirm = d.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, d.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertNull(d.kit.kitDocument(confirm))
        d.at<EntryScreen.FirstRun>()
    }

    /**
     * [inner], whose answer to a recovery's commit (taken by the server as usual) carries, while [swap] is set, an identity
     * seed sealed under another key: the account cannot be opened from it on the device.
     */
    private class SeedSwap(val inner: FakeInstance, val crypto: io.silencelen.andvari.core.crypto.CryptoProvider) : WireClient by inner {
        var swap = false

        /** Runs once, when the commit arrives, before the server takes it (as [Racing.meanwhile]). */
        var meanwhile: (suspend () -> Unit)? = null
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == WireRoute.RECOVERY_SELF_COMMIT) meanwhile?.let { meanwhile = null; it() }
            if (route != WireRoute.RECOVERY_SELF_COMMIT || !swap) return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            return when (val raw = inner.call(route, pathParams, query, bodyJson, authenticated) { it }) {
                is WireResult.Ok -> {
                    val body = io.silencelen.andvari.core.model.wire.WireJson.json.parseToJsonElement(raw.value).jsonObject
                    val userId = (body.getValue("userId") as JsonPrimitive).content
                    val keys = body.getValue("accountKeys").jsonObject
                    val otherKey = crypto.randomBytes(32)
                    val otherSeed = crypto.randomBytes(32)
                    val sealed = io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, otherKey, otherSeed, io.silencelen.andvari.core.crypto.Ad.idkey(userId))
                    otherKey.fill(0)
                    otherSeed.fill(0)
                    val swapped = JsonObject(body + ("accountKeys" to JsonObject(keys + ("encryptedIdentitySeed" to JsonPrimitive(sealed)))))
                    WireResult.Ok(decode(swapped.toString()), raw.status)
                }
                is WireResult.Refused -> raw
                is WireResult.NoAnswer -> raw
            }
        }
    }

    /**
     * AN 6: a recovery's commit the server took, whose answer this device cannot open the account from (a fault while
     * opening, after the commit). The result says that the commit happened (the new password is in force, the old kit no
     * longer works) and the journey is back at the first screen; nothing of the account is kept. Before: a general
     * failure, back at the kit's entry, as if nothing had been committed.
     */
    @Test fun aFaultWhileOpeningAfterARecoverysCommitSaysTheCommitHappened() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val swap = SeedSwap(server, crypto)
        val old = register(device(server), "h.example", alice)
        val d = device(swap)
        toConfirm(d, old)
        assertEquals(KitRecoverResult.DONE, d.entry.confirmKitRecovery(d.at()))
        swap.swap = true
        val r = d.entry.chooseReplacementPassword(d.at(), replacement)
        assertEquals(ReplacePasswordResult.COMMITTED_NOT_OPENED, r)
        assertEquals(CopyKey.RECOVERY_COMMITTED_NOT_OPENED, r.sentence)
        assertTrue(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "the commit went through")
        d.at<EntryScreen.FirstRun>()
        assertNull(d.keeper.session, "nothing of the account is kept here")
        // The old kit no longer works.
        val stale = device(server)
        toConfirm(stale, old)
        assertEquals(KitRecoverResult.KIT_NOT_ACCEPTED, stale.entry.confirmKitRecovery(stale.at()))
    }

    /**
     * The check's probe for AN 6 under N3: the same fault while opening after the commit, while another flow's session is
     * refused on this device during the call (carol is taken, dave is refused, carol is signed out). The answer is still
     * said as a commit that happened and could not be opened, at the first screen. Before: the refusal of dave's session
     * counted against this call, which turned the answer into STALE and left the journey on the password step.
     */
    @Test fun aFaultWhileOpeningAfterARecoverysCommitIsSaidAsThatAlsoWhenAnotherSessionWasRefusedMeanwhile() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val swap = SeedSwap(server, crypto)
        val old = register(device(server), "h.example", alice)
        val d = device(swap)
        register(d, "h.example", "zed@example.com")
        assertEquals(PlainResult.DONE, d.signOut())
        toConfirm(d, old)
        assertEquals(KitRecoverResult.DONE, d.entry.confirmKitRecovery(d.at()))
        swap.swap = true
        swap.meanwhile = { anotherFlowRefusedMeanwhile(d, server) }
        val r = d.entry.chooseReplacementPassword(d.at(), replacement)
        assertEquals(ReplacePasswordResult.COMMITTED_NOT_OPENED, r)
        assertEquals(CopyKey.RECOVERY_COMMITTED_NOT_OPENED, r.sentence)
        assertTrue(WireRoute.RECOVERY_SELF_COMMIT in server.calls, "the commit went through")
        d.at<EntryScreen.FirstRun>()
        assertNull(d.keeper.session, "nothing of the account is kept here")
        val stale = device(server)
        toConfirm(stale, old)
        assertEquals(KitRecoverResult.KIT_NOT_ACCEPTED, stale.entry.confirmKitRecovery(stale.at()), "the old kit no longer works")
    }

    /**
     * A session of a new account [email] at [server], made on [a] by a second flow whose own early check saw nothing in its
     * way (as two flows establishing at once on one device meet the keeper only at its take): the keeper refuses it,
     * because another account is kept here now. Its kit is wiped.
     */
    private suspend fun anotherSessionRefused(a: EngineAppApi, server: FakeInstance, email: String) {
        val blind = object : io.silencelen.andvari.core.client.onboard.SessionSink by a.keeper {
            override fun wouldRefuse(origin: String, emailNorm: String?, userId: String?, identityPub: ByteArray?): String? = null
        }
        val o = io.silencelen.andvari.core.client.onboard.WireOnboarding(
            server.origin, a.clientFor(server.origin), a.trust, a.knownDevices, blind, crypto, a.engine.state, "android", "Pixel", { server.now },
            work = Dispatchers.Unconfined,
        )
        val refusals = a.keeper.refusals
        o.signupStart(email, true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify(email, "482915"))
        val r = assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), RegistrationForm(email, "D", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
        assertNotNull(r.notKept, "the keeper refused that session")
        r.kit.wipe()
        assertEquals(refusals + 1, a.keeper.refusals)
    }

    /** While this call waits at its server: carol is taken, dave's session is refused (carol is kept), and carol is signed out. */
    private suspend fun anotherFlowRefusedMeanwhile(d: EngineAppApi, server: FakeInstance) {
        anotherAccountTaken(d, server.origin)
        anotherSessionRefused(d, server, "dave@example.com")
        d.keeper.signOut()
        assertNull(d.keeper.session)
    }

    /**
     * The check's road (a recovery of the account made again, committed while this device comes to keep the earlier
     * account), up to the kit on show with the keeper's refusal. [open]: the earlier account's session stays OPEN here;
     * otherwise it is signed out again and only the device's record of the address remains.
     */
    private suspend fun committedKitOnShow(open: Boolean, away: Boolean = false): Triple<FakeInstance, EngineAppApi, FakeInstance.Account> {
        val server = FakeInstance(crypto)
        val racing = Racing(server, WireRoute.RECOVERY_SELF_COMMIT)
        register(device(server), "h.example", alice)
        val earlier = server.accounts.getValue(alice)
        val remade = remadeElsewhere(server)
        val d = device(racing)
        register(d, "h.example", "zed@example.com")
        assertEquals(PlainResult.DONE, d.signOut())
        toConfirm(d, remade)
        assertEquals(KitRecoverResult.DONE, d.entry.confirmKitRecovery(d.at()))
        racing.meanwhile = { earlierAccountTakenMeanwhile(d, server, earlier, thenSignedOut = !open) }
        // The person left the app while the commit was out: its kit comes on show while nothing of the app is on show.
        if (away) d.wentAway()
        val r = d.entry.chooseReplacementPassword(d.at(), replacement)
        assertEquals(if (open) ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT else ReplacePasswordResult.IDENTITY_FAULT_COMMITTED, r)
        assertNotNull(d.at<EntryScreen.Kit>().kit.notKeptLine)
        assertEquals(open, d.keeper.established != null)
        return Triple(server, d, earlier)
    }

    /**
     * Section AZ (correcting the check's N1): a lock, by hand or by the kit screen's idle limit, wipes a kit of a committed
     * change shown with the keeper's refusal, with or without another account's session open here: it is gone from the
     * screen and from memory, and the screen the person comes back to says so, once. With the earlier account's session
     * open, that screen is its lock screen; otherwise the first screen.
     */
    @Test fun aLockByHandOrByTheIdleLimitWipesAKitOfACommittedChangeAndSaysSoOnce() = runBlocking<Unit> {
        for (open in listOf(true, false)) for (idle in listOf(false, true)) {
            val (_, d, earlier) = committedKitOnShow(open)
            val kit = d.at<EntryScreen.Kit>().kit
            assertNotNull(d.kit.kitDocument(kit))
            val refusalLine = assertNotNull(kit.notKeptLine)
            if (idle) {
                // The app's own timer, with the kit screen's limit: five minutes without a touch, a warning 30 seconds before.
                assertEquals(5 * 60_000L, kit.idleLockAfterMs)
                assertEquals(30_000L, kit.idleWarnBeforeMs)
                assertEquals(CopyKey.KIT_IDLE_WARNING, kit.idleWarningLine)
            }
            d.lock()
            val road = "open=$open idle=$idle"
            assertNull(d.kitFlow.entryScreen, "gone from the screen: $road")
            assertNull(d.kit.kitDocument(kit), "gone from memory: $road")
            assertTrue(d.snapshot.entry !is EntryScreen.Kit, road)
            if (open) {
                assertEquals(AppPhase.LOCKED, d.snapshot.phase, road)
                assertEquals(earlier.userId, assertNotNull(d.keeper.session).userId)
            } else {
                d.at<EntryScreen.FirstRun>()
            }
            val notice = assertNotNull(d.snapshot.kitWiped, "said: $road")
            // This device cannot take the account now (the earlier account is kept; or, signed out, its identity fault
            // stands): never "on any device", and a line of the refusal's reason says what stands in the way here, never the
            // kit's own line (which tells the person to save a kit that is gone).
            assertEquals(CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE, notice.line, road)
            assertEquals(io.silencelen.andvari.core.app.KeptStops.whyFromKitLine(refusalLine), notice.whyHere, road)
            assertTrue(notice.whyHere != refusalLine && notice.whyHere!!.name.startsWith("KIT_NOT_HERE_WHY_"), road)
            assertEquals(io.silencelen.andvari.core.app.KeptStops.wayOutFromKitLine(refusalLine), notice.wayOut, road)
            assertEquals(alice, notice.email)
            // Said once: dismissed, it is not said again, also after another lock.
            d.dismissKitWiped(notice)
            assertNull(d.snapshot.kitWiped, road)
            d.lock()
            assertNull(d.snapshot.kitWiped, road)
        }
    }

    /**
     * A kit of a committed recovery that came on show while the app was away, and was wiped by a lock before the app came
     * back, was never seen: the notice has a reason of its own (never "the kit that was on the screen"), the refusal's
     * reason line as before. Where the app came back before the lock, the kit was on the screen, and the line is the
     * ordinary one. Before: the ordinary line in both cases.
     */
    @Test fun aKitMadeWhileTheAppWasAwayAndWipedUnseenIsSaidAsNeverShown() = runBlocking<Unit> {
        for (back in listOf(false, true)) {
            val (_, d, _) = committedKitOnShow(open = true, away = true)
            val refusalLine = assertNotNull(d.at<EntryScreen.Kit>().kit.notKeptLine)
            if (back) d.returnedToForeground()
            d.lock()
            val notice = assertNotNull(d.snapshot.kitWiped, "back=$back")
            assertEquals(!back, notice.unseen, "back=$back")
            assertEquals(if (back) CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE else CopyKey.KIT_WIPED_UNSEEN_AFTER_RECOVERY_NOT_HERE, notice.line, "back=$back")
            assertEquals(io.silencelen.andvari.core.app.KeptStops.whyFromKitLine(refusalLine), notice.whyHere, "back=$back")
            assertTrue(notice.whyHere!!.name.startsWith("KIT_NOT_HERE_WHY_"), "never the kit's own line: back=$back")
        }
    }

    /**
     * The notice names the kept session its reason names, by the mark the lock screen's prompt carries for it: the two
     * agree for the same kept copy, across locks, and differ once that copy is replaced (signed out, another account
     * taken). A reason that names no kept session (the identity fault) names none.
     */
    @Test fun theNoticesNamedKeptSessionAgreesWithThePromptOnlyForTheSameKeptCopy() = runBlocking<Unit> {
        val (_, d, _) = committedKitOnShow(open = true)
        d.lock()
        val locked = assertNotNull(d.snapshot.locked)
        val notice = assertNotNull(d.snapshot.kitWiped)
        assertTrue(locked.prompt.keptMark.isNotEmpty())
        assertEquals(locked.prompt.keptMark, notice.namedKept, "the same kept copy")
        d.lock()
        assertEquals(assertNotNull(d.snapshot.locked).prompt.keptMark, notice.namedKept, "a second lock changes nothing")
        // The kept copy is replaced: signed out, and another account taken here.
        assertEquals(PlainResult.DONE, d.signOutConfirmed(assertNotNull(d.signOutCheck())))
        register(d, "h.example", "yan@example.com")
        d.lock()
        val other = assertNotNull(d.snapshot.locked).prompt.keptMark
        assertTrue(other.isNotEmpty())
        assertSame(notice, d.snapshot.kitWiped, "the notice stays until its dismiss")
        assertTrue(other != notice.namedKept, "another copy: the way out under the notice is no longer offered")

        val (_, signedOut, _) = committedKitOnShow(open = false)
        signedOut.lock()
        assertNull(assertNotNull(signedOut.snapshot.kitWiped).namedKept, "the identity fault names no kept session")
    }

    /**
     * The check's D2a: the notice that a kit is gone goes only when the person dismisses it. A kit of a committed recovery
     * on show while the earlier account's session is open here; a lock wipes it and the lock screen says so; then that
     * account is opened with its password. The notice is still there after the opening (and a second lock), and goes only
     * with the dismiss. Before: the opening cleared it, so a quick unlock started by the app could take it away unread.
     */
    @Test fun anOpeningOfTheAccountKeptHereDoesNotTakeTheNoticeThatAKitIsGone() = runBlocking<Unit> {
        val (_, d, earlier) = committedKitOnShow(open = true)
        d.lock()
        assertEquals(AppPhase.LOCKED, d.snapshot.phase)
        val notice = assertNotNull(d.snapshot.kitWiped)
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, d.unlock(assertNotNull(d.snapshot.locked), strong))
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
        assertEquals(earlier.userId, assertNotNull(d.keeper.session).userId)
        assertSame(notice, d.snapshot.kitWiped, "an opening does not take it")
        d.lock()
        assertSame(notice, d.snapshot.kitWiped, "nor a second lock")
        d.dismissKitWiped(notice)
        assertNull(d.snapshot.kitWiped, "the dismiss takes it")
    }

    /**
     * The notice's line is true of this device. Where what stood in the way here is gone before the lock (the other account
     * kept here was signed out while the kit was on show), the next sign-in can show a new kit on any device, this one
     * included: the plain line, with no refusal line. Where it still stands (the earlier test), never "on any device".
     */
    @Test fun theNoticeSaysOnAnyDeviceOnlyWhereNothingStandsInTheWayHere() = runBlocking<Unit> {
        val (_, d, _) = committedKitOnShow(open = true)
        assertEquals(PlainResult.DONE, d.signOut())
        assertNull(d.keeper.session)
        d.at<EntryScreen.Kit>()
        d.lock()
        val notice = assertNotNull(d.snapshot.kitWiped)
        assertEquals(CopyKey.KIT_WIPED_AFTER_RECOVERY, notice.line)
        assertNull(notice.whyHere)
        d.dismissKitWiped(notice)
        assertNull(d.snapshot.kitWiped)
    }

    /**
     * The check's D2b: the mark that makes a later start say the kit is gone stays until the notice was dismissed. The app
     * is closed with a registration's kit on show; the next start says so; the app is closed again without a dismiss; the
     * start after that says so again. Once dismissed, the mark goes and a later start says nothing. Before: the first
     * start used the mark up, so the second said nothing.
     */
    /**
     * The check's P1k: a standing notice that a kit is gone, for an address whose account this device then deletes, goes
     * with the deletion, with its marks at rest, also across a restart; the kept session's mark goes with its server too.
     * Before: the notice and the address stayed at rest and promised a kit at the next sign-in of a deleted account.
     */
    @Test fun aConfirmedDeletionTakesAStandingKitNoticeForItsAddressAndItsMarksAcrossARestart() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val racing = Racing(server, WireRoute.REGISTER)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        fun on(): EngineAppApi = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to racing)), state, secure, crypto, { server.now },
                baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also { it.start() }
        val d = on()
        d.entry.openOwnServer(d.at())
        assertEquals(ServerResult.DONE, d.entry.submitServerAddress(d.at(), "h.example"))
        assertEquals(ServerResult.DONE, d.entry.confirmTrustGate(d.at()))
        assertEquals(ServerResult.DONE, d.entry.createAccountHere(d.at()))
        assertEquals(SignUpStartResult.DONE, d.entry.startSignUp(d.at(), alice, true))
        assertEquals(CodeResult.DONE, d.entry.verifySignUpCode(d.at(), "482915"))
        // Carol is kept here meanwhile: Alice's account is made, and its kit is shown "not kept here".
        racing.meanwhile = { anotherAccountTaken(d, server.origin) }
        assertEquals(CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, d.entry.createAccount(d.at(), NewAccountInput("", "Alice", strong, true)))
        d.at<EntryScreen.Kit>()
        d.lock()
        assertEquals(alice, assertNotNull(d.snapshot.kitWiped).email)
        assertNotNull(state.get(EngineAppApi.KIT_ON_SHOW_PREFIX + server.origin), "the notice's mark, under its server")
        // Carol signs out; Alice signs in and deletes her account.
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, d.signOut())
        server.account(alice).recoveryConfirmed = true
        d.entry.openSignIn(d.at())
        d.entry.openPasswordSignIn(d.at())
        assertEquals(ServerResult.DONE, d.entry.chooseOwnServer(d.at(), server.origin))
        (d.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, d.entry.confirmTrustGate(it)) }
        assertEquals(io.silencelen.andvari.core.app.SignInAnswer.DONE, d.entry.submitSignIn(d.at(), alice, strong))
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
        assertTrue(state.keys().any { it.startsWith(EngineAppApi.KEPT_MARK_PREFIX) }, "the kept session's mark, under its server")
        server.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = io.silencelen.andvari.core.client.net.WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        server.override[WireRoute.ACCOUNT_DELETE] = io.silencelen.andvari.core.client.net.WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, d.settings.openDeletion())
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.DONE,
            d.settings.deleteAccount(assertNotNull(d.snapshot.account!!.deletion), alice, strong, null))

        assertNull(d.snapshot.kitWiped, "the notice goes with the account")
        val marks = listOf(EngineAppApi.KIT_ON_SHOW_PREFIX, EngineAppApi.KIT_NAMED_KEPT_PREFIX, EngineAppApi.KEPT_MARK_PREFIX,
            EngineAppApi.KIT_ON_SHOW_KEY, EngineAppApi.KIT_NAMED_KEPT_KEY, EngineAppApi.KEPT_MARK_KEY)
        assertEquals(emptyList(), state.keys().filter { k -> marks.any { k.startsWith(it) } }, "no mark at rest")
        assertTrue(state.keys().none { alice in it || state.get(it).orEmpty().contains(alice) }, "the address stays nowhere")
        d.close()
        assertNull(on().snapshot.kitWiped, "nor after a restart")
    }

    @Test fun aStartWithoutADismissDoesNotUseUpTheNoticeThatAKitIsGone() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val racing = Racing(server, WireRoute.REGISTER)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        fun on(): EngineAppApi = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to racing)), state, secure, crypto, { server.now },
                baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also { it.start() }
        val d = on()
        d.entry.openOwnServer(d.at())
        assertEquals(ServerResult.DONE, d.entry.submitServerAddress(d.at(), "h.example"))
        assertEquals(ServerResult.DONE, d.entry.confirmTrustGate(d.at()))
        assertEquals(ServerResult.DONE, d.entry.createAccountHere(d.at()))
        assertEquals(SignUpStartResult.DONE, d.entry.startSignUp(d.at(), alice, true))
        assertEquals(CodeResult.DONE, d.entry.verifySignUpCode(d.at(), "482915"))
        racing.meanwhile = { anotherAccountTaken(d, server.origin) }
        assertEquals(CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, d.entry.createAccount(d.at(), NewAccountInput("", "Alice", strong, true)))
        d.at<EntryScreen.Kit>()
        d.close()
        val first = on()
        assertEquals(alice, assertNotNull(first.snapshot.kitWiped, "said at the first start").email)
        first.close()
        val second = on()
        val notice = assertNotNull(second.snapshot.kitWiped, "said again: nobody dismissed it")
        assertEquals(alice, notice.email)
        assertNotNull(state.get(EngineAppApi.KIT_ON_SHOW_PREFIX + server.origin), "the mark stays until the dismiss")
        second.dismissKitWiped(notice)
        assertNull(second.snapshot.kitWiped)
        assertNull(state.get(EngineAppApi.KIT_ON_SHOW_PREFIX + server.origin), "the dismiss takes the mark")
        second.close()
        assertNull(on().snapshot.kitWiped, "dismissed: a later start says nothing")
    }

    /**
     * A registration's first kit that came on show while the app was away, and the app was closed before it came back: the
     * next start says the kit was never shown, with the registration's own unseen line (before: "the kit that was on the
     * screen").
     */
    @Test fun aKitOnShowOnlyWhileTheAppWasAwayIsSaidAsNeverShownAfterARestart() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val racing = Racing(server, WireRoute.REGISTER)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        fun on(): EngineAppApi = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to racing)), state, secure, crypto, { server.now },
                baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also { it.start() }
        val d = on()
        d.entry.openOwnServer(d.at())
        assertEquals(ServerResult.DONE, d.entry.submitServerAddress(d.at(), "h.example"))
        assertEquals(ServerResult.DONE, d.entry.confirmTrustGate(d.at()))
        assertEquals(ServerResult.DONE, d.entry.createAccountHere(d.at()))
        assertEquals(SignUpStartResult.DONE, d.entry.startSignUp(d.at(), alice, true))
        assertEquals(CodeResult.DONE, d.entry.verifySignUpCode(d.at(), "482915"))
        racing.meanwhile = { anotherAccountTaken(d, server.origin) }
        d.wentAway()
        assertEquals(CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, d.entry.createAccount(d.at(), NewAccountInput("", "Alice", strong, true)))
        d.at<EntryScreen.Kit>()
        d.close()
        val next = on()
        val notice = assertNotNull(next.snapshot.kitWiped)
        assertTrue(notice.unseen)
        assertTrue(notice.line.name.startsWith("KIT_WIPED_UNSEEN_AFTER_REGISTRATION"), "${notice.line}")
        assertEquals(alice, notice.email)
    }

    /**
     * A registration's first kit shown with the keeper's refusal, wiped by a lock, is said with the registration's own
     * notice. And when the app is closed with such a kit on show, the next start says it is gone: only a mark that a kit
     * was on show for the address is kept at rest, never anything of the kit.
     */
    @Test fun aRegistrationsKitWipedByALockOrByTheAppsCloseIsSaidAtTheNextScreen() = runBlocking<Unit> {
        for (closed in listOf(false, true)) {
            val server = FakeInstance(crypto)
            val racing = Racing(server, WireRoute.REGISTER)
            val state = MemoryDeviceState()
            val secure = MemoryDeviceState()
            fun on(): EngineAppApi = EngineAppApi(
                AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to racing)), state, secure, crypto, { server.now },
                    baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
            ).also { it.start() }
            val d = on()
            d.entry.openOwnServer(d.at())
            assertEquals(ServerResult.DONE, d.entry.submitServerAddress(d.at(), "h.example"))
            assertEquals(ServerResult.DONE, d.entry.confirmTrustGate(d.at()))
            assertEquals(ServerResult.DONE, d.entry.createAccountHere(d.at()))
            assertEquals(SignUpStartResult.DONE, d.entry.startSignUp(d.at(), alice, true))
            assertEquals(CodeResult.DONE, d.entry.verifySignUpCode(d.at(), "482915"))
            racing.meanwhile = { anotherAccountTaken(d, server.origin) }
            assertEquals(CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, d.entry.createAccount(d.at(), NewAccountInput("", "Alice", strong, true)))
            val kit = d.at<EntryScreen.Kit>().kit
            val doc = assertNotNull(d.kit.kitDocument(kit))
            // At rest: only that a kit was on show, and for which address; none of the kit's groups.
            val mark = assertNotNull(state.get(EngineAppApi.KIT_ON_SHOW_PREFIX + server.origin))
            assertEquals("registration|${CopyKey.KIT_REGISTERED_NOT_KEPT.name}|$alice", mark, "the road, the refusal's line key and the address only")
            assertTrue(doc.groups.none { it in mark })
            assertTrue(doc.qrPayload !in mark)
            val after = if (closed) {
                d.close()
                on()
            } else {
                d.lock()
                d
            }
            val notice = assertNotNull(after.snapshot.kitWiped, "closed: $closed")
            // Carol is still kept here: never "on any device".
            assertEquals(CopyKey.KIT_WIPED_AFTER_REGISTRATION_NOT_HERE, notice.line)
            // The reason without the kit, and its way out: Carol's sign-out, reachable under the notice.
            assertEquals(CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT, notice.whyHere)
            assertEquals(io.silencelen.andvari.core.app.KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, notice.wayOut)
            assertEquals(alice, notice.email)
            assertNotNull(state.get(EngineAppApi.KIT_ON_SHOW_PREFIX + server.origin), "the mark stays until the dismiss")
            after.dismissKitWiped(notice)
            assertNull(after.snapshot.kitWiped)
            assertNull(state.get(EngineAppApi.KIT_ON_SHOW_PREFIX + server.origin), "the dismiss takes the mark")
        }
    }

    /**
     * Section AZ, fourth point (as built for the check's N1): the kit of a recovery the server committed, on show with the
     * keeper's refusal while this device holds the earlier account's OPEN session. That account's end by its server and
     * its sign-out each leave the kit on show, the same kit, with the line that says how long it holds; the open account's
     * keys go. After the kit is confirmed: the first screen offering the account its server signed out (after its end),
     * the first screen (after the sign-out). Before, each dropped the kit and nothing said so.
     */
    @Test fun aKitOfACommittedRecoveryStaysOnShowThroughWhatHappensToTheOpenAccountKeptHere() = runBlocking<Unit> {
        for (event in listOf("ended", "signedOut")) {
            val (server, d, _) = committedKitOnShow(open = true)
            val shown = assertNotNull(d.kit.kitDocument(d.at<EntryScreen.Kit>().kit))
            when (event) {
                "ended" -> d.keeper.endedByServer(server.origin)
                else -> assertEquals(PlainResult.DONE, d.signOut())
            }
            assertEquals(AppPhase.ENTRY, d.snapshot.phase, event)
            val kit = d.at<EntryScreen.Kit>().kit
            assertEquals(CopyKey.KIT_RECOVERED_NOT_KEPT, kit.notKeptLine, event)
            assertEquals(CopyKey.KIT_NOT_KEPT_HOLDS_UNTIL_SIGN_IN, kit.notKeptHoldsLine, event)
            val doc = assertNotNull(d.kit.kitDocument(kit), "still readable after: $event")
            assertEquals(shown.qrPayload, doc.qrPayload, "the same kit")
            assertNull(d.keeper.established, "the open account's keys went: $event")
            d.kit.proceedToConfirm(kit)
            val confirm = d.at<EntryScreen.Kit>().kit
            assertEquals(KitConfirmResult.DONE, d.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
            assertNull(d.kit.kitDocument(confirm), "wiped once confirmed")
            assertNull(d.snapshot.kitWiped, "confirmed, nothing to say")
            when (event) {
                "ended" -> {
                    d.at<EntryScreen.FirstRun>()
                    assertEquals(alice, assertNotNull(d.snapshot.keptSignedOut).email)
                }
                else -> {
                    d.at<EntryScreen.FirstRun>()
                    assertNull(d.keeper.session)
                }
            }
            // The kit shown is the account's: a fresh device recovers with it.
            val fresh = device(server)
            toConfirm(fresh, doc)
            assertEquals(KitRecoverResult.DONE, fresh.entry.confirmKitRecovery(fresh.at()), event)
        }
    }

    /**
     * The check's N3: another flow's session is refused on this device while a recovery's commit waits at its server, and
     * this call's own session is then taken. The call is answered as what it is: the recovery is done, its session kept,
     * and its new kit is on show. Before: STALE, with the new kit wiped unseen while its session stayed kept here.
     */
    @Test fun anotherSessionRefusedWhileARecoverysCommitRunsLeavesThisCallsSessionAndKit() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val racing = Racing(server, WireRoute.RECOVERY_SELF_COMMIT)
        val alicesKit = register(device(server), "h.example", alice)
        val d = device(racing)
        register(d, "h.example", "zed@example.com")
        assertEquals(PlainResult.DONE, d.signOut())
        toConfirm(d, alicesKit)
        assertEquals(KitRecoverResult.DONE, d.entry.confirmKitRecovery(d.at()))
        racing.meanwhile = { anotherFlowRefusedMeanwhile(d, server) }
        val r = d.entry.chooseReplacementPassword(d.at(), replacement)
        assertEquals(ReplacePasswordResult.DONE, r)
        assertEquals(alice, assertNotNull(d.keeper.session).emailNorm, "this call's session is kept")
        val kit = d.at<EntryScreen.Kit>().kit
        assertNull(kit.notKeptLine)
        assertNull(kit.notKeptHoldsLine)
        assertEquals(KitReason.AFTER_RECOVERY, kit.reason)
        val doc = assertNotNull(d.kit.kitDocument(kit))
        d.kit.proceedToConfirm(kit)
        val confirm = d.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, d.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
    }

    /** The check's N3 at a registration: as above, the account made is the one kept and opened here, with its first kit. */
    @Test fun anotherSessionRefusedWhileARegistrationRunsLeavesThisCallsSessionAndKit() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val racing = Racing(server, WireRoute.REGISTER)
        val d = device(racing)
        d.entry.openOwnServer(d.at())
        assertEquals(ServerResult.DONE, d.entry.submitServerAddress(d.at(), "h.example"))
        assertEquals(ServerResult.DONE, d.entry.confirmTrustGate(d.at()))
        assertEquals(ServerResult.DONE, d.entry.createAccountHere(d.at()))
        assertEquals(SignUpStartResult.DONE, d.entry.startSignUp(d.at(), alice, true))
        assertEquals(CodeResult.DONE, d.entry.verifySignUpCode(d.at(), "482915"))
        racing.meanwhile = { anotherFlowRefusedMeanwhile(d, server) }
        val r = d.entry.createAccount(d.at(), NewAccountInput("", "Alice", strong, true))
        // Before: ACCOUNT_MADE_NOT_KEPT ("this device keeps another account"), although this account's session was kept.
        assertEquals(CreateAccountResult.DONE, r)
        assertEquals(alice, assertNotNull(d.keeper.session).emailNorm)
        val kit = d.at<EntryScreen.Kit>().kit
        assertNull(kit.notKeptLine)
        assertEquals(KitReason.FIRST_KIT, kit.reason)
        val doc = assertNotNull(d.kit.kitDocument(kit))
        d.kit.proceedToConfirm(kit)
        val confirm = d.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, d.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
    }

    /**
     * The check's N2: a registration the server took while this device came to hold its server's operator account. The
     * keeper's own reason is said, with its way out (removal, not a sign-out), and the first kit is on show with the line
     * that says how long it holds. Before: ACCOUNT_MADE_NOT_KEPT, "opens once the other account is signed out".
     */
    @Test fun aRegistrationTakenWhileThisDeviceComesToHoldItsServersOperatorAccountSaysThat() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val racing = Racing(server, WireRoute.REGISTER)
        val d = device(racing)
        d.entry.openOwnServer(d.at())
        assertEquals(ServerResult.DONE, d.entry.submitServerAddress(d.at(), "h.example"))
        assertEquals(ServerResult.DONE, d.entry.confirmTrustGate(d.at()))
        assertEquals(ServerResult.DONE, d.entry.createAccountHere(d.at()))
        assertEquals(SignUpStartResult.DONE, d.entry.startSignUp(d.at(), alice, true))
        assertEquals(CodeResult.DONE, d.entry.verifySignUpCode(d.at(), "482915"))
        racing.meanwhile = {
            anotherAccountTaken(d, server.origin)
            d.keeper.holdAsOperator()
        }
        val r = d.entry.createAccount(d.at(), NewAccountInput("", "Alice", strong, true))
        assertEquals(CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD, r)
        assertEquals(CopyKey.KIT_REGISTERED_OPERATOR_ACCOUNT_HELD, r.sentence)
        assertTrue(server.accounts.containsKey(alice), "the account was made")
        val kit = d.at<EntryScreen.Kit>().kit
        assertEquals(CopyKey.KIT_REGISTERED_OPERATOR_ACCOUNT_HELD, kit.notKeptLine)
        assertEquals(CopyKey.KIT_NOT_KEPT_HOLDS_UNTIL_SIGN_IN, kit.notKeptHoldsLine)
        val doc = assertNotNull(d.kit.kitDocument(kit))
        val fresh = device(server)
        toConfirm(fresh, doc)
        assertEquals(KitRecoverResult.DONE, fresh.entry.confirmKitRecovery(fresh.at()), "the kit shown is the account's")
    }

    /**
     * Where a notice names a held operator account as what stands in the way here (the kit's wipe after a registration
     * taken while this device came to hold its server's operator account), the first screen under it offers that
     * account's removal: [EntryScreen.FirstRun.heldAsOperator] is set, also after the notice is dismissed.
     */
    @Test fun aNoticeThatNamesAHeldOperatorAccountAlwaysHasItsRemovalOnTheFirstScreen() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val racing = Racing(server, WireRoute.REGISTER)
        val d = device(racing)
        d.entry.openOwnServer(d.at())
        assertEquals(ServerResult.DONE, d.entry.submitServerAddress(d.at(), "h.example"))
        assertEquals(ServerResult.DONE, d.entry.confirmTrustGate(d.at()))
        assertEquals(ServerResult.DONE, d.entry.createAccountHere(d.at()))
        assertEquals(SignUpStartResult.DONE, d.entry.startSignUp(d.at(), alice, true))
        assertEquals(CodeResult.DONE, d.entry.verifySignUpCode(d.at(), "482915"))
        racing.meanwhile = {
            anotherAccountTaken(d, server.origin)
            d.keeper.holdAsOperator()
        }
        assertEquals(CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD, d.entry.createAccount(d.at(), NewAccountInput("", "Alice", strong, true)))
        d.at<EntryScreen.Kit>()
        d.lock()
        val notice = assertNotNull(d.snapshot.kitWiped)
        assertEquals(CopyKey.KIT_NOT_HERE_WHY_OPERATOR_HELD, notice.whyHere)
        assertEquals(io.silencelen.andvari.core.app.KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT, notice.wayOut)
        assertNotNull(d.at<EntryScreen.FirstRun>().heldAsOperator, "the removal the notice names is on the screen under it")
        d.dismissKitWiped(notice)
        assertNotNull(d.at<EntryScreen.FirstRun>().heldAsOperator, "and stays after the dismissal")
    }
}
