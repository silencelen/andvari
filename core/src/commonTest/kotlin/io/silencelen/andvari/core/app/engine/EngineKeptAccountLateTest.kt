package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.content.KeptStorage
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.devicelink.DeviceLinkServer
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.WireDeviceLinks
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.client.link.LinkAccount
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A sign-in the person left must never cost a kept account. The account's server signed it
 * out (its copy and its waiting changes are kept, design §4.4); the person taps "Sign in again", the server answers
 * slowly, the person goes back, the late answer comes, and the app restarts. The kept account, its copy and its waiting
 * changes are all still there. The same for a device link's pickup and a kit recovery's commit.
 */
class EngineKeptAccountLateTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val email = "alice@example.com"

    /** [inner], whose answer on a route in [held] waits until [gate] is completed (a hostile server chooses when). */
    private class Held(private val inner: WireClient) : WireClient {
        val held = HashSet<WireRoute>()
        var gate: CompletableDeferred<Unit>? = null
        override val origin: String get() = inner.origin
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route in held) gate?.await()
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    /** Cache files that are only recorded. */
    private class Files : VaultCacheFiles {
        val deleted = ArrayList<String>()
        override fun open(fileName: String, userId: String): VaultCache = InMemoryVaultCache()
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            return true
        }
    }

    /** The platform's files for the content's kept records (its waiting changes among them). */
    private class Disk : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        val blobSets = HashMap<String, InMemoryBlobs>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = blobSets.getOrPut(name) { InMemoryBlobs() }
    }

    /** One device's stores, which outlive a process. */
    private class Device(val transport: BearerTransport, val clock: () -> Long) {
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val files = Files()
        val disk = Disk()
    }

    private fun Device.process(): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", transport, state, secure, createCryptoProvider(), clock, baked = null, storeBuild = false, stores = null,
            main = Dispatchers.Unconfined, work = Dispatchers.Unconfined, cacheFiles = files, contentStores = ContentStores(createCryptoProvider(), disk)),
    ).also {
        it.linkPollMs = Long.MAX_VALUE
        it.start()
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun confirmKit(a: EngineAppApi): KitDocument {
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        return doc
    }

    /** Sign-up at h.example through the kit: the vault is open. */
    private suspend fun signUp(a: EngineAppApi): KitDocument {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val doc = confirmKit(a)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        return doc
    }

    /** What the kept account holds on [d]: its kept record of waiting changes, and its cache file's name. */
    private class Copy(val moves: FillSnapshotStore, val cacheFile: String)

    /**
     * The open account's server signs it out (design §4.4: the copy stays), a change waits in its kept records, and the
     * person taps "Sign in again". The journey's first screen is on show.
     */
    private fun Device.serverEndsThenSignInAgain(a: EngineAppApi): Copy {
        val s = assertNotNull(a.keeper.session)
        a.keeper.endedByServer(s.origin)
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        assertTrue(a.snapshot.locked!!.signedOutByServer)
        val moves = disk.record(ItemCacheNames.keptPrefix(crypto, s.origin, s.userId) + ContentStores.MOVES)
        moves.write(byteArrayOf(7))
        files.deleted.clear()
        a.signInAgain(a.snapshot.locked!!)
        a.at<EntryScreen.FirstRun>()
        return Copy(moves, ItemCacheNames.fileName(crypto, s.origin, s.userId))
    }

    /** After the late answer: the kept account is the server-ended one, as it was, and so after a restart. */
    private fun Device.keptAsItWas(a: EngineAppApi, copy: Copy, userId: String) {
        val kept = assertNotNull(a.keeper.session, "the kept account is still kept")
        assertEquals(userId, kept.userId)
        assertTrue(kept.endedByServer, "still as signed out by its server")
        assertNull(a.keeper.established)
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertEquals(email, a.snapshot.keptSignedOut?.email, "the journey still names it")
        a.close()

        val next = process()
        assertEquals(AppPhase.LOCKED, next.snapshot.phase, "the next start finds the account kept")
        assertTrue(assertNotNull(next.snapshot.locked).signedOutByServer)
        assertEquals(emptyList(), files.deleted, "its cache file stays")
        assertNotNull(copy.moves.read(), "its waiting changes stay")
        assertTrue(state.get(EngineAppApi.HELD_KEY).orEmpty().contains(userId), "still listed as held")
    }

    @Test fun aSignInLeftWhileItsServerAnsweredSlowlyKeepsTheServerEndedAccount() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val held = Held(server)
        val d = Device(BearerTransport(mapOf(server.origin to held)), { server.now })
        val a = d.process()
        signUp(a)
        val userId = a.keeper.session!!.userId
        val copy = d.serverEndsThenSignInAgain(a)

        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), server.origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        val form = a.at<EntryScreen.SignIn>()
        held.held += WireRoute.LOGIN
        val gate = CompletableDeferred<Unit>().also { held.gate = it }
        val pending = async(start = CoroutineStart.UNDISPATCHED) { a.entry.submitSignIn(form, email, strong) }
        assertTrue(a.entry.back(), "the person goes back")
        gate.complete(Unit)
        assertEquals(SignInAnswer.STALE, pending.await())
        d.keptAsItWas(a, copy, userId)
    }

    @Test fun aKitRecoveryLeftBeforeItsCommitAnsweredKeepsTheServerEndedAccount() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val held = Held(server)
        val d = Device(BearerTransport(mapOf(server.origin to held)), { server.now })
        val a = d.process()
        val doc = signUp(a)
        val userId = a.keeper.session!!.userId
        val copy = d.serverEndsThenSignInAgain(a)

        a.entry.openSignIn(a.at())
        a.entry.openForgot(a.at())
        a.entry.openKitEntry(a.at())
        assertEquals(KitScanResult.DONE, a.entry.submitKit(a.at(), doc.qrPayload, PayloadSource.SCANNED))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(KitRecoverResult.DONE, a.entry.confirmKitRecovery(a.at()))
        val choose = a.at<EntryScreen.ReplacePassword>()
        held.held += WireRoute.RECOVERY_SELF_COMMIT
        val gate = CompletableDeferred<Unit>().also { held.gate = it }
        val pending = async(start = CoroutineStart.UNDISPATCHED) { a.entry.chooseReplacementPassword(choose, "a brand new Master password 7") }
        a.entry.startOver()
        gate.complete(Unit)
        assertEquals(ReplacePasswordResult.STALE, pending.await())
        d.keptAsItWas(a, copy, userId)
    }

    private class Sink : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
    }

    @Test fun aDeviceLinkLeftBeforeItsPickupAnsweredKeepsTheServerEndedAccount() = runBlocking<Unit> {
        val instance = FakeInstance(crypto)
        val server = DeviceLinkServer(instance)
        // The other device (E): a registered account, which makes and approves the links.
        val eState = MemoryDeviceState()
        val eTrust = instance.pinnedTrust(eState)
        val sink = Sink()
        val onboarding = WireOnboarding(instance.origin, server.client(null), eTrust, KnownDevices(eState, crypto), sink, crypto, eState, "desktop", "Laptop",
            { instance.now }, work = Dispatchers.Unconfined)
        onboarding.signupStart(email, true)
        val ticket = assertIs<SignupVerify.Ticket>(onboarding.signupVerify(email, "482915"))
        val reg = assertIs<Registration.Registered>(onboarding.register(RegistrationAuth.Ticket(ticket),
            RegistrationForm(email, "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Laptop", "desktop")))
        instance.account(email).recoveryConfirmed = true
        val session = sink.sessions.single()
        val acct = LinkAccount.of(session, "Alice", StoredAccountState(reg.userId, session.account.uvk, server.client(reg.userId), crypto, eState))
        val e = WireDeviceLinks({ server.client(reg.userId, it) }, eTrust, eState, crypto, { instance.now }, { acct }, KnownDevices(eState, crypto), sink,
            { _, _ -> }, "Laptop", "desktop")
        val held = Held(server.client(null))
        val d = Device(BearerTransport(mapOf(instance.origin to held)), { instance.now })
        val a = d.process()

        /** A link made on E, scanned here, approved on E: this device is on the password screen. */
        suspend fun toPassword(): EntryScreen.LinkDevicePassword {
            a.entry.openSignIn(a.at())
            a.entry.openLinkDevice(a.at())
            val shown = assertIs<ExistingStep.Shown>(e.create())
            assertEquals(DeviceLinkScanResult.DONE, a.entry.submitDeviceLink(a.at(), shown.url, PayloadSource.SCANNED))
            (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
            val fixed = assertIs<ExistingStep.ClaimFixed>(e.advance(shown))
            assertTrue(a.entryFlow.pollDeviceLink())
            val code = a.at<EntryScreen.LinkDeviceCode>().code
            val type = assertIs<ExistingStep.TypeDigits>(e.advance(fixed))
            assertIs<ExistingStep.Approved>(e.approve(assertIs<ExistingStep.Approvable>(e.typeDigits(type, code))))
            assertTrue(!a.entryFlow.pollDeviceLink())
            return a.at()
        }

        assertEquals(LinkPasswordResult.DONE, a.entry.submitLinkPassword(toPassword(), strong))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        val copy = d.serverEndsThenSignInAgain(a)

        val pw = toPassword()
        held.held += WireRoute.DEVICE_LINK_PICKUP
        val gate = CompletableDeferred<Unit>().also { held.gate = it }
        val pending = async(start = CoroutineStart.UNDISPATCHED) { a.entry.submitLinkPassword(pw, strong) }
        a.entry.startOver()
        gate.complete(Unit)
        assertEquals(LinkPasswordResult.STALE, pending.await())
        d.keptAsItWas(a, copy, reg.userId)
    }

    /**
     * The start deletes an account's data only when its end was the person's own act. A sign-out whose deletion a stop
     * interrupted (the end is recorded durably first) is finished at the next start; an account that is simply no
     * longer kept, with no such record, keeps its data.
     */
    @Test fun theStartDeletesOnlyTheDataOfAnAccountThePersonEnded() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = Device(BearerTransport(mapOf(server.origin to server)), { server.now })
        val a = d.process()
        signUp(a)
        val ownEnds = io.silencelen.andvari.core.client.session.SessionKeeper.OWN_ENDS_KEY
        assertNull(d.state.get(ownEnds), "after the sign-up")
        val s = a.keeper.session!!
        val moves = d.disk.record(ItemCacheNames.keptPrefix(crypto, s.origin, s.userId) + ContentStores.MOVES)
        a.lock()
        a.close()
        assertNull(d.state.get(ownEnds), "after a lock")
        moves.write(byteArrayOf(3))

        // The session record is gone without any act of the person (a store the platform lost): nothing is deleted.
        d.secure.set(io.silencelen.andvari.core.client.session.SessionKeeper.KEY, null)
        d.files.deleted.clear()
        val b = d.process()
        assertEquals(AppPhase.ENTRY, b.snapshot.phase)
        assertEquals(emptyList(), d.files.deleted)
        assertNotNull(moves.read(), "the waiting changes stay")
        b.close()

        // The person's sign-out: its copy goes at once, and nothing is left for the next start to do.
        val other = FakeInstance(crypto)
        val c = Device(BearerTransport(mapOf(other.origin to other)), { other.now }).let { fresh ->
            fresh.process().also { signUp(it) } to fresh
        }
        val (app, dev) = c
        val name = ItemCacheNames.fileName(crypto, app.keeper.session!!.origin, app.keeper.session!!.userId)
        dev.files.deleted.clear()
        assertEquals(PlainResult.DONE, app.signOut())
        assertEquals(listOf(name), dev.files.deleted)
        app.close()
        dev.files.deleted.clear()
        dev.process()
        assertEquals(emptyList(), dev.files.deleted, "the start has nothing left to delete")
    }
}
