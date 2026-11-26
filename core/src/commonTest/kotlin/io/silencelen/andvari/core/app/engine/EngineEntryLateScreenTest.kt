package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.devicelink.DeviceLinkServer
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.WireDeviceLinks
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.LinkAccount
import io.silencelen.andvari.core.client.link.LinkPerson
import io.silencelen.andvari.core.client.link.LinkServer
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
import kotlin.test.assertTrue

/**
 * A late answer never changes the screen. Every change of screen after a wait checks that the
 * person is still on the screen that asked. Each test holds the server's answer, the person goes back, and the answer
 * comes: the screen the person went to stays on show, and the intent answers STALE.
 */
class EngineEntryLateScreenTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /** [inner]; while [gate] is set, every call waits for it (a hostile server chooses when to answer). */
    private class Held(private val inner: () -> WireClient, override val origin: String) : WireClient {
        var gate: CompletableDeferred<Unit>? = null
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            gate?.await()
            return inner().call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private fun app(transport: BearerTransport, clock: () -> Long): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, clock, baked = null, storeBuild = false,
            stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also {
        it.linkPollMs = Long.MAX_VALUE
        it.linksFlow.answersPollMs = Long.MAX_VALUE
        it.start()
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /**
     * [intent] waits on [held]; meanwhile the person goes back. Its late answer must leave the screen the person went
     * to on show, and answer [stale].
     */
    private suspend fun <R> lateAfterBack(a: EngineAppApi, held: Held, stale: R, intent: suspend () -> R) = kotlinx.coroutines.coroutineScope {
        val gate = CompletableDeferred<Unit>().also { held.gate = it }
        val pending = async(start = CoroutineStart.UNDISPATCHED) { intent() }
        assertTrue(a.entry.back(), "the person goes back")
        val there = assertNotNull(a.snapshot.entry)
        held.gate = null
        gate.complete(Unit)
        assertEquals(stale, pending.await())
        assertTrue(a.snapshot.entry === there, "the late answer changed the screen to ${a.snapshot.entry}")
    }

    private class Plain(val server: FakeInstance, val held: Held, val app: EngineAppApi)

    private fun plain(): Plain {
        val server = FakeInstance(crypto)
        val held = Held({ server }, server.origin)
        return Plain(server, held, app(BearerTransport(mapOf(server.origin to held)), { server.now }))
    }

    @Test fun aTypedAddressAnsweredLateShowsNoTrustGate() = runBlocking<Unit> {
        val p = plain()
        val a = p.app
        a.entry.openOwnServer(a.at())
        val own = a.at<EntryScreen.OwnServer>()
        lateAfterBack(a, p.held, ServerResult.STALE) { a.entry.submitServerAddress(own, "h.example") }
        a.at<EntryScreen.FirstRun>()
    }

    @Test fun aConfirmedTrustGateAnsweredLateShowsNoServer() = runBlocking<Unit> {
        val p = plain()
        val a = p.app
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        val gate = a.at<EntryScreen.TrustGate>()
        // The gate gives way to the address screen at once; the server's answer about new accounts comes late.
        lateAfterBack(a, p.held, ServerResult.STALE) { a.entry.confirmTrustGate(gate) }
        a.at<EntryScreen.FirstRun>()
    }

    private suspend fun Plain.toServer(): EntryScreen.Server {
        val a = app
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        return a.at()
    }

    @Test fun createAccountHereAnsweredLateShowsNoSignUp() = runBlocking<Unit> {
        val p = plain()
        val server = p.toServer()
        lateAfterBack(p.app, p.held, ServerResult.STALE) { p.app.entry.createAccountHere(server) }
    }

    @Test fun aSignUpCodeAnsweredLateShowsNoAccountForm() = runBlocking<Unit> {
        val p = plain()
        val a = p.app
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(p.toServer()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        val code = a.at<EntryScreen.SignUpCode>()
        lateAfterBack(a, p.held, CodeResult.STALE) { a.entry.verifySignUpCode(code, "482915") }
        a.at<EntryScreen.SignUpEmail>()
    }

    /** Registered, the kit kept, signed out: the journey's first screen. */
    private suspend fun Plain.registeredThenSignedOut(): KitDocument {
        val a = app
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(toServer()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(PlainResult.DONE, a.signOut())
        a.entry.openSignIn(a.at())
        a.entry.openForgot(a.at())
        a.entry.openKitEntry(a.at())
        return doc
    }

    @Test fun aScannedKitAnsweredLateShowsNoRecovery() = runBlocking<Unit> {
        val p = plain()
        val doc = p.registeredThenSignedOut()
        val entry = p.app.at<EntryScreen.KitEntry>()
        lateAfterBack(p.app, p.held, KitScanResult.STALE) { p.app.entry.submitKit(entry, doc.qrPayload, PayloadSource.SCANNED) }
        p.app.at<EntryScreen.Forgot>()
    }

    @Test fun aKitRecoveryConfirmedLateShowsNoPasswordForm() = runBlocking<Unit> {
        val p = plain()
        val a = p.app
        val doc = p.registeredThenSignedOut()
        assertEquals(KitScanResult.DONE, a.entry.submitKit(a.at(), doc.qrPayload, PayloadSource.SCANNED))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        val recover = a.at<EntryScreen.KitRecover>()
        lateAfterBack(a, p.held, KitRecoverResult.STALE) { a.entry.confirmKitRecovery(recover) }
        a.at<EntryScreen.KitEntry>()
    }

    private class Sink : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
    }

    @Test fun aDeviceLinkAnsweredLateShowsNothingOfIt() = runBlocking<Unit> {
        val email = "alice@example.com"
        val instance = FakeInstance(crypto)
        val server = DeviceLinkServer(instance)
        val eState = MemoryDeviceState()
        val eTrust = instance.pinnedTrust(eState)
        val sink = Sink()
        val onboarding = WireOnboarding(instance.origin, server.client(null), eTrust, KnownDevices(eState, crypto), sink, crypto, eState, "desktop", "Laptop",
            { instance.now }, work = Dispatchers.Unconfined)
        onboarding.signupStart(email, true)
        val ticket = assertIs<SignupVerify.Ticket>(onboarding.signupVerify(email, "482915"))
        val reg = assertIs<Registration.Registered>(onboarding.register(RegistrationAuth.Ticket(ticket),
            RegistrationForm(email, "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Laptop", "desktop")))
        val session = sink.sessions.single()
        val acct = LinkAccount.of(session, "Alice", StoredAccountState(reg.userId, session.account.uvk, server.client(reg.userId), crypto, eState))
        val e = WireDeviceLinks({ server.client(reg.userId, it) }, eTrust, eState, crypto, { instance.now }, { acct }, KnownDevices(eState, crypto), sink,
            { _, _ -> }, "Laptop", "desktop")
        val held = Held({ server.client(null) }, instance.origin)
        val a = app(BearerTransport(mapOf(instance.origin to held)), { instance.now })
        a.entry.openSignIn(a.at())
        a.entry.openLinkDevice(a.at())
        val entry = a.at<EntryScreen.LinkDeviceEntry>()
        val shown = assertIs<ExistingStep.Shown>(e.create())
        lateAfterBack(a, held, DeviceLinkScanResult.STALE) { a.entry.submitDeviceLink(entry, shown.url, PayloadSource.SCANNED) }
        a.at<EntryScreen.SignInChoice>()
    }

    private class Invites(val server: LinkServer, val alice: LinkPerson, val held: Held, val app: EngineAppApi)

    private suspend fun invites(): Invites {
        val server = LinkServer(crypto)
        val alice = LinkPerson(crypto, server, 1, "11111111-1111-4111-8111-111111111111", "Alice").start()
        var self: EngineAppApi? = null
        // The link server knows a caller by its account: the app's own, once it has one.
        val held = Held({ server.client(self?.keeper?.session?.userId) }, server.instance.origin)
        val a = app(BearerTransport(mapOf(server.instance.origin to held)), { server.instance.now })
        self = a
        return Invites(server, alice, held, a)
    }

    private suspend fun Invites.link(kind: String): String =
        assertIs<CreateOutcome.Created>(alice.flows.create(kind, 60 * 60 * 1000L, emptyList())).link.url

    @Test fun anInviteAnsweredLateShowsNothingOfIt() = runBlocking<Unit> {
        val w = invites()
        val a = w.app
        val url = w.link("connect")
        a.entry.openInviteEntry(a.at())
        val entry = a.at<EntryScreen.InviteEntry>()
        lateAfterBack(a, w.held, InviteResult.STALE) { a.entry.submitInvite(entry, url, PayloadSource.SCANNED) }
        a.at<EntryScreen.FirstRun>()
    }

    @Test fun joiningFromAnInviteAnsweredLateShowsNoSignUp() = runBlocking<Unit> {
        val w = invites()
        val a = w.app
        val url = w.link("connect")
        a.entry.openInviteEntry(a.at())
        assertEquals(InviteResult.DONE, a.entry.submitInvite(a.at(), url, PayloadSource.SCANNED))
        val join = a.at<EntryScreen.JoinInvite>()
        lateAfterBack(a, w.held, ServerResult.STALE) { a.entry.joinFromInvite(join) }
        a.at<EntryScreen.InviteEntry>()
    }
}
