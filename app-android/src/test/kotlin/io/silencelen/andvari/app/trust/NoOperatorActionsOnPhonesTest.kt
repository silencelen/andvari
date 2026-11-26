package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The operator's delete (the server's `reason: under_minimum_age`) and every other
 * operator action belong to the desktop app and the command-line tool. The design refuses the operator account on
 * phones (§9.1, N9), and core makes that a matter of types: the phone apps get an [io.silencelen.andvari.core.app.AppApi],
 * never a [DesktopAppApi], so there is nothing to bind here. This pins that no Android screen offers an operator action.
 */
class NoOperatorActionsOnPhonesTest {
    private val main = File("src/main/kotlin")

    private fun allMain(): Map<String, String> =
        main.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }.associate { it.path to it.readText() }

    @Test
    fun theAppIsHandedAnAppApiThatIsNoDesktopAppApi() {
        assertFalse(DesktopAppApi::class.java.isAssignableFrom(EngineAppApi::class.java), "the engine the phone builds has no operator views")
        val seam = File(main, "io/silencelen/andvari/app/trust/TrustSeam.kt").readText()
        assertTrue(seam.contains("val api: AppApi = EngineAppApi("))
        assertFalse(seam.contains("EngineDesktopAppApi"))
        // The fake the screens are tested on is the phone's too.
        assertFalse(FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS) is DesktopAppApi)
    }

    @Test
    fun noAndroidSourceReachesAnOperatorCall() {
        val names = listOf(
            "DesktopAppApi", "EngineDesktopAppApi", "OperatorApi", "operatorApi", "OperatorConsole",
            "finishServerSetup(", "disableAccount(", "enableAccount(", "openAccountDevices(", "revokeAccountDevice(",
            "setAccountQuota(", "savePolicy(", "loadAudit(", "downloadEscrow(", "takeEscrow(", "fulfilRecovery(",
            "renameInstance(", "moveInstance(", "changeRecoveryKey(", "removeRecoveryKey(", "openConsole(",
            "under_minimum_age", "OperatorDeleteRequest",
        )
        val hits = allMain().flatMap { (path, text) -> names.filter { text.contains(it) }.map { "$path: $it" } }
        assertTrue(hits.isEmpty(), "operator calls on Android: $hits")
    }

    @Test
    fun theOperatorsOwnPromptAndSetupScreenOfferNothingHere() {
        val prompts = File(main, "io/silencelen/andvari/app/trust/PeopleScreens.kt").readText()
        assertTrue(prompts.contains("is AccountPrompt.FinishServerSetup -> {}"), "the server setup is finished on a computer")
        val entry = File(main, "io/silencelen/andvari/app/trust/EntryScreens.kt").readText()
        assertTrue(entry.contains("is EntryScreen.ServerSetup -> NotBuilt(model, s, \"ServerSetup\")"))
    }
}
