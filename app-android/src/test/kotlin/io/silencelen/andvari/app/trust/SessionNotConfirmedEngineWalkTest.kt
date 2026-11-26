package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.app.engine.VaultCacheFiles
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A session this phone could not confirm with its server in time, over the shared code's REAL implementation and its
 * test server: the server makes each refresh and the phone never hears back, twice, so no try is left and the phone
 * ends the session itself. The lock screen, a restart's lock screen, the copy opened after it and the first screen after
 * "Sign in again" say that end as this phone's own, never "signed out by its server"; "Sign in again" stays offered.
 */
class SessionNotConfirmedEngineWalkTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Files : VaultCacheFiles {
        val caches = HashMap<String, VaultCache>()
        override fun open(fileName: String, userId: String): VaultCache =
            caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }
        override fun delete(fileName: String): Boolean = caches.remove(fileName) != null
    }

    /** [instance] with an empty item plane (a sync answers the personal vault and no items). */
    private class Server(val instance: FakeInstance) : WireClient by instance {
        val transport = BearerTransport(mapOf(instance.origin to this)).also { it.clock = { instance.now } }

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            if (route == WireRoute.SYNC) {
                val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), SyncResponse(1, true, vaults, emptyList(), emptyList(), emptyList(), emptyList(), 0, 0))), 200)
            } else {
                instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }

        /** The server makes each refresh (the second within its grace) and the phone never hears back; the access token expired. */
        fun refreshAnswersLost() {
            transport.graceMs = 60_000
            transport.loseAnswers = 2
            transport.expired += transport.sent.mapNotNull { it.bearer }
        }
    }

    private class Phone {
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val files = Files()
    }

    private val opened = ArrayList<EngineAppApi>()

    private fun app(server: Server, phone: Phone): EngineAppApi = EngineAppApi(
        AppEngine(
            AppPlatform.ANDROID, "Pixel", server.transport, phone.state, phone.secure, crypto, { server.instance.now },
            baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
            cacheFiles = phone.files, keepsAtRest = { true },
        ),
    ).also { opened += it }

    private fun model(api: AppApi): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }).also {
            it.start()
            it.onSnapshot(api.snapshot)
        }

    private inline fun <reified T : EntryScreen> AppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private fun <R : IntentResult> TrustModel.done(intent: suspend AppApi.() -> R): R {
        var result: R? = null
        runBlocking { run(intent) { result = it }.join() }
        onSnapshot(api.snapshot)
        return assertNotNull(result, "the intent ended without a result: ${wentWrong.value?.text}")
    }

    private fun TrustModel.step(intent: AppApi.() -> Unit) {
        act(intent)
        onSnapshot(api.snapshot)
    }

    private fun TrustModel.register() {
        step { entry.openOwnServer(at()) }
        assertEquals(ServerResult.DONE, done { entry.submitServerAddress(at(), "h.example") })
        (api.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, done { entry.confirmTrustGate(gate) }) }
        assertEquals(ServerResult.DONE, done { entry.createAccountHere(at()) })
        assertEquals(SignUpStartResult.DONE, done { entry.startSignUp(at(), "alice@example.com", true) })
        assertEquals(CodeResult.DONE, done { entry.verifySignUpCode(at(), "482915") })
        assertEquals(CreateAccountResult.DONE, done { entry.createAccount(at(), NewAccountInput("", "P", strong, true)) })
        val reveal = api.at<EntryScreen.Kit>().kit
        val doc = assertNotNull(api.kit.kitDocument(reveal))
        step { kit.proceedToConfirm(reveal) }
        val confirm = api.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, done { kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
    }

    @Test
    fun aSessionThePhoneCouldNotConfirmIsSaidAsThatEndOnEveryScreenNeverAsTheServers() = try {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val phone = Phone()
        val api = app(server, phone)
        val m = model(api)
        m.register()
        m.step { lock() }

        // Every unlock opens the vault and asks the server things with the session; each answer to a refresh is lost.
        server.refreshAnswersLost()
        val trace = ArrayList<String>()
        repeat(4) {
            if (api.snapshot.locked?.sessionNotConfirmed != true) {
                if (api.snapshot.phase == AppPhase.UNLOCKED) m.step { lock() }
                val r = m.done { unlock(assertNotNull(snapshot.locked), strong) }
                trace += "unlock $r: phase ${api.snapshot.phase}, account ended ${api.snapshot.account?.sessionNotConfirmed}, refreshes ${server.transport.refreshTokensReceived.size}"
            }
        }
        if (api.snapshot.phase == AppPhase.UNLOCKED) m.step { lock() }
        val locked = assertNotNull(api.snapshot.locked, "$trace")
        assertTrue(locked.sessionNotConfirmed, "no try left: $trace")
        assertTrue(locked.signedOutByServer, "kept as a session that ended")
        val notConfirmed = UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown()
        val byServer = UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER).shown()
        assertEquals(notConfirmed, lockEndLine(locked, signOutWayOutStands(api.snapshot))?.shown(), "the lock screen")
        assertNotEquals(byServer, lockEndLine(locked)?.shown())

        // A new start of the app on the same phone: the same end, said the same way; the copy opens, saying it as this end.
        val next = app(server, phone)
        val n = model(next)
        val again = assertNotNull(next.snapshot.locked)
        assertTrue(again.sessionNotConfirmed, "kept across a restart")
        assertEquals(notConfirmed, lockEndLine(again)?.shown())
        assertEquals(VaultUnlockResult.DONE, n.done { unlock(again, strong) })
        val account = assertNotNull(next.snapshot.account)
        assertTrue(account.sessionNotConfirmed)
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED_COPY_OPEN).shown(), stoppedLine(n, next.snapshot, account)?.shown(), "the open copy's line")
        assertNotEquals(UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER_OPEN).shown(), stoppedLine(n, next.snapshot, account)?.shown())

        // "Sign in again": the first screen says the same end, never the server's notice.
        n.step { lock() }
        n.step { signInAgain(assertNotNull(snapshot.locked)) }
        val first = assertIs<EntryScreen.FirstRun>(next.snapshot.entry)
        assertEquals(null, first.notice, "never the notice that the server signed this phone out")
        assertEquals(notConfirmed, sessionNotConfirmedLine(first, signOutWayOutStands(next.snapshot))?.shown())
        assertTrue(next.snapshot.keptSignedOutNotConfirmed)
    } finally {
        opened.forEach { runCatching { it.close() } }
    }
}
