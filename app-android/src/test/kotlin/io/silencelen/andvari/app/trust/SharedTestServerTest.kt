package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * This module's unit tests reach the shared code's own test server ([FakeInstance], with [BearerTransport] in front of
 * it, from core's Android unit-test classes): an account is made on it through the app's model ([TrustModel]) over the
 * shared code's REAL implementation ([EngineAppApi] over [AppEngine]), as the screens drive it, from the first screen
 * to the open vault. Only the HTTP stack is replaced; every route the engine sends reaches the test server.
 */
class SharedTestServerTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private inline fun <reified T : EntryScreen> AppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Run one intent through the model as a screen does, to its end, and give its result. */
    private fun <R : IntentResult> TrustModel.done(intent: suspend AppApi.() -> R): R {
        var result: R? = null
        runBlocking { run(intent) { result = it }.join() }
        return assertNotNull(result, "the intent ended without a result: ${wentWrong.value?.text}")
    }

    @Test
    fun anAccountMadeOnTheSharedCodesTestServerThroughTheModelOpensItsVault() {
        val server = FakeInstance(crypto)
        val transport = BearerTransport(mapOf(server.origin to server))
        val api = EngineAppApi(
            AppEngine(
                AppPlatform.ANDROID, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, { server.now },
                baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
            ),
        )
        try {
            val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
            m.start()
            m.onSnapshot(api.snapshot)

            m.act { entry.openOwnServer(at()) }
            assertEquals(ServerResult.DONE, m.done { entry.submitServerAddress(at(), "h.example") })
            val gate = api.at<EntryScreen.TrustGate>()
            assertEquals(server.origin, gate.prompt.origin)
            assertEquals(ServerResult.DONE, m.done { entry.confirmTrustGate(gate) })
            assertEquals(ServerResult.DONE, m.done { entry.createAccountHere(at()) })
            assertEquals(SignUpStartResult.DONE, m.done { entry.startSignUp(at(), "ada@example.com", true) })
            // The code the test server "mailed".
            val code = server.codes.getValue("ada@example.com")
            assertEquals(CodeResult.DONE, m.done { entry.verifySignUpCode(at(), code) })
            assertEquals(CreateAccountResult.DONE, m.done { entry.createAccount(at(), NewAccountInput("", "Ada", strong, true)) })

            val reveal = api.at<EntryScreen.Kit>().kit
            val doc = assertNotNull(api.kit.kitDocument(reveal))
            m.act { kit.proceedToConfirm(reveal) }
            val confirm = api.at<EntryScreen.Kit>().kit
            assertEquals(KitConfirmResult.DONE, m.done { kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
            m.onSnapshot(api.snapshot)

            // Read back: the vault is open on the account the server holds, and the server took the registration and the
            // kit's confirmation, the latter with the new session's bearer.
            assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
            assertEquals("ada@example.com", assertNotNull(api.snapshot.account).email)
            assertEquals(1, server.accounts.size)
            assertTrue(server.account("ada@example.com").recoveryConfirmed)
            assertTrue(WireRoute.REGISTER in server.calls)
            assertTrue(transport.bearersFor(WireRoute.RECOVERY_SELF_CONFIRM).single()!!.startsWith("at-"))
            assertNull(m.wentWrong.value, "nothing went wrong on the way")
        } finally {
            api.close()
        }
    }
}
