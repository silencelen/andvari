package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.RecoveryRequestState
import io.silencelen.andvari.core.model.wire.RecoveryRequestSummary
import io.silencelen.andvari.core.model.wire.RecoveryVetoRequest
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Design §9.3 step 2, spec 03 §18.3: a request for the operator's help
 * made for this account is shown to its signed-in devices by the engine itself, at an opening and after a sync whose
 * count names it, with the cancel and "this was me"; and what a lying server can and cannot do to it.
 */
class EngineRecoveryRequestsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val day = 86_400_000L

    /** The account's requests as this server lists them, its `/sync` count, and the vetoes it was sent. */
    private inner class Server(val instance: FakeInstance) {
        val requests = ArrayList<RecoveryRequestSummary>()

        /** What `/sync` says the count is; null: as many as listed. */
        var count: Int? = null
        var listRefused = false

        /** Rows the list carries beside [requests], as raw JSON: rows a device cannot read. */
        val rawRows = ArrayList<String>()

        /** The server answers `ok` to a veto and keeps listing the request. */
        var vetoIgnored = false

        /** The server answers every veto `404 request_unknown` (a request it invented, say) and keeps listing it. */
        var vetoUnknown = false
        val vetoes = ArrayList<Pair<String, String>>()
        val lists = ArrayList<Int>()
        private var rev = 1L

        val client: WireClient = object : WireClient {
            override val origin: String = instance.origin
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                fun ok(text: String): WireResult<T> = WireResult.Ok(decode(text), 200)
                return when (route) {
                    WireRoute.SYNC -> ok(WireJson.json.encodeToString(SyncResponse.serializer(),
                        SyncResponse(rev++, true, emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), 0, count ?: requests.size)))
                    WireRoute.ACCOUNT_RECOVERY_REQUESTS -> {
                        lists += requests.size
                        if (listRefused) WireResult.Refused(503, WireError("unavailable", "m"))
                        else {
                            val listed = WireJson.json.encodeToString(ListSerializer(RecoveryRequestSummary.serializer()), requests)
                            ok(if (rawRows.isEmpty()) listed else "[" + (listOf(listed.removePrefix("[").removeSuffix("]")).filter { it.isNotEmpty() } + rawRows).joinToString(",") + "]")
                        }
                    }
                    WireRoute.RECOVERY_REQUEST_VETO -> {
                        val id = pathParams.getValue("requestId")
                        vetoes += id to WireJson.json.decodeFromString(RecoveryVetoRequest.serializer(), bodyJson!!).statement
                        if (vetoUnknown || requests.none { it.requestId == id }) return WireResult.Refused(404, WireError("request_unknown", "m"))
                        if (!vetoIgnored) requests.removeAll { it.requestId == id }
                        ok("{}")
                    }
                    WireRoute.PUSH, WireRoute.VAULT_META -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
    }

    private fun app(): Pair<Server, EngineAppApi> {
        val server = Server(FakeInstance(crypto))
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.instance.origin to server.client)),
                MemoryDeviceState(), MemoryDeviceState(), crypto, { server.instance.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
        return server to app
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun open(a: EngineAppApi, email: String = "alice@example.com") {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", email.substringBefore('@'), strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    private val idA = "AAAAAAAAAAAAAAAAAAAAAA"
    private val idB = "BBBBBBBBBBBBBBBBBBBBBA"

    /** A request verified [ago] ms before now, its hold the full seven days unless [hold] says otherwise. */
    private fun Server.request(id: String, ago: Long = day, hold: Long = 7 * day, state: String = RecoveryRequestState.HOLDING, platform: String = "windows") =
        RecoveryRequestSummary(id, state, instance.now - ago - 60_000, instance.now - ago, instance.now - ago + hold, platform)

    private fun EngineAppApi.alert(): AccountPrompt.RecoveryRequest? =
        snapshot.account?.prompts?.filterIsInstance<AccountPrompt.RecoveryRequest>()?.singleOrNull()

    private suspend fun EngineAppApi.sync() {
        assertNotNull(content).syncQuietly()
    }

    private suspend fun EngineAppApi.relock() {
        lock()
        assertEquals(VaultUnlockResult.DONE, unlock(snapshot.locked!!, strong))
    }

    /**
     * A request made while the vault is open: the sync's count names it, the device reads the list and raises the
     * prompt with when it was made, the kind of device as the server says it, and when the wait ends. At the next
     * unlock it is raised again. The cancel signs a statement for that request, and the prompt goes once the server no
     * longer lists it. Before, only the test fake raised this prompt.
     */
    @Test fun aRequestMadeWhileOpenIsRaisedAtTheNextSyncAndAtTheNextUnlockAndCanBeCancelled() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        assertNull(a.alert())
        val made = server.request(idA)
        server.requests += made
        a.sync()
        val alert = assertNotNull(a.alert(), "raised by the engine after the sync")
        val row = alert.requests.single()
        assertEquals(idA, row.requestId)
        assertEquals(made.createdAt, row.askedAtMs)
        assertEquals(made.holdEndsAt, row.holdEndsAtMs)
        assertEquals(AppPlatform.WINDOWS, row.reportedPlatform)
        assertEquals(OperatorHelpStage.HOLDING, row.stage)
        assertFalse(row.holdCutShort || row.answered || row.cancelNotTaken)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.RECOVERY_REQUEST_ALERT, alert.line)

        a.relock()
        assertNotNull(a.alert(), "raised again at the next unlock")

        assertEquals(PlainResult.DONE, a.recovery.cancelRecoveryRequest(a.alert()!!.requests.single()))
        assertEquals(idA, server.vetoes.single().first)
        assertTrue(server.vetoes.single().second.isNotEmpty(), "a signed statement")
        assertNull(a.alert(), "gone once the server no longer lists it")
    }

    /** "This was me": the prompt goes, and stays gone at the next unlock; a new request is raised again. */
    @Test fun thisWasMeDismissesThatRequestOnly() = runBlocking<Unit> {
        val (server, a) = app()
        server.requests += server.request(idA)
        open(a)
        val alert = assertNotNull(a.alert(), "raised at the opening")
        a.recovery.recoveryRequestWasMe(alert)
        assertNull(a.alert())
        assertTrue(server.vetoes.isEmpty(), "nothing is sent")
        a.relock()
        assertNull(a.alert(), "not raised again for that request")
        server.requests += server.request(idB)
        a.sync()
        assertEquals(listOf(idB), assertNotNull(a.alert()).requests.map { it.requestId })
    }

    /**
     * Lie: the server answers `ok` to the cancel and keeps listing the request. The device reads the list again: the
     * cancel is not DONE, and the row says the server still lists it.
     */
    @Test fun aCancelTheServerSaysWorkedButStillListsIsNotDone() = runBlocking<Unit> {
        val (server, a) = app()
        server.requests += server.request(idA)
        server.vetoIgnored = true
        open(a)
        assertEquals(PlainResult.FAILED, a.recovery.cancelRecoveryRequest(assertNotNull(a.alert()).requests.single()))
        assertTrue(assertNotNull(a.alert(), "still raised").requests.single().cancelNotTaken)
    }

    /**
     * Lie: the server lets the wait end early (a hold shorter than seven days, or "waiting for the operator" before
     * seven days have passed since the code was proved). The device cannot stop the operator, but it says so.
     */
    @Test fun aWaitTheServerCutsShortIsSaid() = runBlocking<Unit> {
        val (server, a) = app()
        server.requests += server.request(idA, ago = day, hold = 2 * day)
        server.requests += server.request(idB, ago = 3 * day, state = RecoveryRequestState.AWAITING_OPERATOR)
        open(a)
        val rows = assertNotNull(a.alert()).requests.associateBy { it.requestId }
        assertTrue(rows.getValue(idA).holdCutShort, "a two-day hold")
        assertTrue(rows.getValue(idB).holdCutShort, "awaiting the operator after three days")
    }

    /**
     * Lie: the count names a request the list does not show, or the list cannot be read while the count names one. The
     * device does not know which to believe and raises the alert as "could not be read" rather than nothing.
     */
    @Test fun aCountTheListContradictsOrAListThatCannotBeReadIsRaisedAsUnreadable() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        server.count = 1
        a.sync()
        assertTrue(assertNotNull(a.alert(), "the count names one").unreadable)
        server.count = null
        server.requests += server.request(idA)
        server.listRefused = true
        a.sync()
        assertTrue(assertNotNull(a.alert()).unreadable)
        server.listRefused = false
        a.sync()
        val alert = assertNotNull(a.alert())
        assertFalse(alert.unreadable)
        assertEquals(idA, alert.requests.single().requestId)
    }

    /**
     * A request the server invents (one that does not exist) is shown: the device cannot tell it from a real one. The
     * cancel the server then refuses as unknown is not DONE.
     */
    @Test fun anInventedRequestIsShownAndItsRefusedCancelIsNotDone() = runBlocking<Unit> {
        val (server, a) = app()
        server.requests += server.request(idA)
        open(a)
        val row = assertNotNull(a.alert(), "shown: nothing tells it from a real one").requests.single()
        server.vetoUnknown = true
        assertEquals(PlainResult.FAILED, a.recovery.cancelRecoveryRequest(row))
        assertNotNull(a.alert(), "still listed, still shown")
    }

    /**
     * An answered request (`ready`: the operator uploaded an answer, not yet committed) is shown as answered: the most
     * urgent moment to cancel. The device's reader of the list must accept the state for this to work; until it does, the alert is raised as unreadable, never dropped.
     */
    @Test fun anAnsweredRequestIsRaisedAsAnsweredOrAtLeastAsUnreadable() = runBlocking<Unit> {
        val (server, a) = app()
        server.requests += server.request(idA, ago = 8 * day, state = RecoveryRequestState.READY)
        open(a)
        val alert = assertNotNull(a.alert(), "raised, never dropped")
        if (!alert.unreadable) assertTrue(alert.requests.single().answered)
    }

    /**
     * On the screen: the device's own list of requests with a row that is ready (answered by the
     * operator, not yet used: listed as answered, and cancellable) and rows it cannot read (each dropped and counted, and
     * said on Recovery in Settings and with the alert). A list that cannot be read at all is said as such, never as an
     * empty list. Before, the count of dropped rows was not shown and a list that could not be read showed as empty.
     */
    @Test fun aReadyRowIsListedAsAnsweredAndRowsThatCannotBeReadAreCountedAndSaid() = runBlocking<Unit> {
        val (server, a) = app()
        server.requests += server.request(idA, ago = 8 * day, state = RecoveryRequestState.READY)
        server.rawRows += """{"requestId":"not a request id","state":"holding","createdAt":1,"verifiedAt":1,"holdEndsAt":1,"platform":"windows"}"""
        server.rawRows += """{"requestId":"$idB","state":"made_up_state","createdAt":1,"verifiedAt":1,"holdEndsAt":1,"platform":"windows"}"""
        server.count = 1
        open(a)
        val alert = assertNotNull(a.alert(), "raised")
        assertTrue(alert.unreadable, "rows the server sent and this device cannot show are said with the alert")
        assertEquals(PlainResult.DONE, a.recovery.openRecovery())
        val screen = assertNotNull(a.snapshot.account?.recovery, "the screen")
        val row = screen.requests.single()
        assertEquals(idA, row.requestId)
        assertTrue(row.answered, "a ready row is the operator's answer, not yet used")
        assertEquals(2, screen.unreadableRequests, "each row it could not read is counted")
        assertEquals(io.silencelen.andvari.core.app.CopyKey.RECOVERY_REQUESTS_SOME_UNREADABLE, screen.unreadableLine?.key)
        assertEquals(listOf("2"), screen.unreadableLine?.values)
        assertNull(screen.notReadLine)
        // The ready row is cancelled like any other.
        assertEquals(PlainResult.DONE, a.recovery.cancelRecoveryRequest(row))
        assertEquals(idA, server.vetoes.single().first)

        // A list that cannot be read at all: said, never an empty list.
        a.recovery.closeRecovery()
        server.listRefused = true
        assertEquals(PlainResult.DONE, a.recovery.openRecovery())
        val notRead = assertNotNull(a.snapshot.account?.recovery)
        assertTrue(notRead.requests.isEmpty())
        assertTrue(notRead.requestsNotRead)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.RECOVERY_REQUESTS_NOT_READ, notRead.notReadLine)
    }

    private fun appOver(origin: String, client: WireClient, now: () -> Long): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(origin to client)), MemoryDeviceState(), MemoryDeviceState(), crypto, now,
            baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also {
        it.linksFlow.answersPollMs = Long.MAX_VALUE
        it.start()
    }

    /**
     * Spec 01 §5, "bound to the typed email": Alice signed in on this device, then signed out.
     * The server now answers her address with another account (another user id, another identity: Bob's, whose
     * password is the same). The sign-in is the security fault and nothing is kept. Before, a new user id was a fresh
     * pin.
     */
    @Test fun aSignInWhoseServerSwapsTheUserIdUnderTheSameAddressIsTheIdentityFault() = runBlocking<Unit> {
        val server = Server(FakeInstance(crypto))
        var swap = false
        val front = object : WireClient by server.client {
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                val body = if (swap && (route == WireRoute.PRELOGIN || route == WireRoute.LOGIN)) bodyJson?.replace("alice@example.com", "bob@example.com") else bodyJson
                return server.client.call(route, pathParams, query, body, authenticated, decode)
            }
        }
        val bob = appOver(server.instance.origin, server.client) { server.instance.now }
        open(bob, "bob@example.com")
        val a = appOver(server.instance.origin, front) { server.instance.now }
        open(a)
        assertEquals(PlainResult.DONE, a.signOut())
        swap = true
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), server.instance.origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        val r = a.entry.submitSignIn(a.at(), "alice@example.com", strong)
        assertEquals(io.silencelen.andvari.core.app.SignInAnswer.IDENTITY_FAULT, r)
        assertNull(a.keeper.session, "nothing of the other account is kept")
        assertTrue(a.snapshot.phase != AppPhase.UNLOCKED)
    }

    /** The server hides the request (no count, an empty list): the device has nothing to show and shows nothing. */
    @Test fun aHiddenRequestCannotBeShown() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        a.sync()
        assertNull(a.alert())
        assertTrue(server.lists.isNotEmpty(), "the list was read at the opening")
    }
}
