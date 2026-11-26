package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitScreen
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
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
 * Walks through the app's own model ([TrustModel]) over the shared code's REAL implementation ([EngineDesktopAppApi] over
 * [AppEngine], on this computer's stores in a temporary directory, as [TrustSeam] builds it) and the shared code's own
 * test server ([FakeInstance] behind [BearerTransport]): what the desktop's tests proved only over the fake so far.
 */
class RealEngineKitTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private inline fun <reified T : EntryScreen> DesktopAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.phase} ${snapshot.entry}")

    private fun <R : IntentResult> TrustModel.done(intent: suspend DesktopAppApi.() -> R): R {
        var result: R? = null
        runBlocking { run(intent) { result = it }.join() }
        return assertNotNull(result, "the intent ended without a result: ${said.value?.text?.shown()}")
    }

    /** One computer's engine over [server], on its own stores in [dir]. */
    private fun engine(server: FakeInstance, transport: BearerTransport, dir: java.io.File): EngineDesktopAppApi {
        val home = DesktopHome(dir, NoKeyStore, log = {}, keyStorePause = {})
        return EngineDesktopAppApi(
            AppEngine(
                platform = TrustSeam.desktopPlatform(), deviceName = "test", transport = transport,
                state = JsonDeviceState(home.stateFile()), secure = JsonDeviceState(home.secureFile), requestStore = JsonDeviceState(home.requestFile),
                crypto = crypto, clock = { server.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = home.cacheFiles, contentStores = home.content.stores, keepsAtRest = home::keepsAtRest,
            ),
        )
    }

    /**
     * A kit that replaces one shown before says so first, on its first step, and no longer on the step where it is typed
     * back: Ada registers, her kit is shown and the window is locked before she types it back (the lock wipes it); the
     * unlock opens her vault with the kit she still owes, a new one, which says first that the kit shown before no longer
     * works; on the step where it is typed back that line is gone; typed back, the vault is open and the server holds
     * the kit confirmed.
     */
    @Test
    fun aKitThatReplacesOneShownBeforeSaysSoOnItsFirstStepOnly() {
        val server = FakeInstance(crypto)
        val transport = BearerTransport(mapOf(server.origin to server))
        val dir = java.nio.file.Files.createTempDirectory("andvari-realkit").toFile()
        val api = engine(server, transport, dir)
        val faults = ArrayList<String>()
        try {
            val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, faultLog = { faults += it })
            m.start()
            m.onSnapshot(api.snapshot)
            m.act { entry.openOwnServer(at()) }
            assertEquals(ServerResult.DONE, m.done { entry.submitServerAddress(at(), "h.example") })
            assertEquals(ServerResult.DONE, m.done { entry.confirmTrustGate(at()) })
            assertEquals(ServerResult.DONE, m.done { entry.createAccountHere(at()) })
            assertEquals(SignUpStartResult.DONE, m.done { entry.startSignUp(at(), "ada@example.com", true) })
            assertEquals(CodeResult.DONE, m.done { entry.verifySignUpCode(at(), server.codes.getValue("ada@example.com")) })
            assertEquals(CreateAccountResult.DONE, m.done { entry.createAccount(at(), NewAccountInput("", "Ada", strong, true)) })

            // The first kit, on show: nothing to replace yet.
            val first = api.at<EntryScreen.Kit>().kit
            assertEquals(KitStep.REVEAL, first.step)
            assertNull(first.earlierKitVoidLine, "the first kit replaces none")
            assertNotNull(api.kit.kitDocument(first))
            // The lock (Ctrl+L, the menu): a kit in the journey is lockable, and the lock wipes it.
            assertTrue(m.lockable())
            m.lockNow()
            m.onSnapshot(api.snapshot)
            assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the kit went with the lock")
            assertTrue(!server.account("ada@example.com").recoveryConfirmed)

            // The unlock: the vault opens with the kit Ada still owes, a new one.
            m.done { unlock(assertNotNull(snapshot.locked), strong) }
            m.onSnapshot(api.snapshot)
            val again: KitScreen = assertNotNull(kitOnShow(api), "a new kit at the opening: ${api.snapshot.phase} ${api.snapshot.entry}")
            assertEquals(KitStep.REVEAL, again.step)
            val void = assertNotNull(again.earlierKitVoidLine, "the new kit says first that the one shown before no longer works")
            // Drawn first on the kit's screen, before anything else of it.
            assertTrue(KIT_VIEW.indexOf("kit.earlierKitVoidLine?.let") in 0 until KIT_VIEW.indexOf("when (kit.step)"))
            val doc = assertNotNull(api.kit.kitDocument(again))
            m.act { kit.proceedToConfirm(again) }
            m.onSnapshot(api.snapshot)
            val confirm = assertNotNull(kitOnShow(api))
            assertEquals(KitStep.CONFIRM, confirm.step)
            assertNull(confirm.earlierKitVoidLine, "not on the step where it is typed back ($void)")
            assertEquals(KitConfirmResult.DONE, m.done { kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
            m.onSnapshot(api.snapshot)
            assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
            assertNull(kitOnShow(api))
            assertTrue(server.account("ada@example.com").recoveryConfirmed, "the server holds the kit confirmed")
            assertEquals(emptyList(), faults, "nothing went wrong on the way")
        } finally {
            api.close()
            dir.deleteRecursively()
        }
    }

    /** The kit on show: in the journey, or over the open vault. */
    private fun kitOnShow(api: DesktopAppApi): KitScreen? =
        (api.snapshot.entry as? EntryScreen.Kit)?.kit?.takeIf { api.snapshot.phase == AppPhase.ENTRY } ?: api.snapshot.account?.kit?.takeIf { api.snapshot.phase == AppPhase.UNLOCKED }

    private companion object {
        val KIT_VIEW: String = java.io.File("src/main/kotlin/io/silencelen/andvari/desktop/trust/KitScreens.kt").readText()
            .substringAfter("internal fun KitScreenView(").substringBefore("\n}\n")
    }
}
