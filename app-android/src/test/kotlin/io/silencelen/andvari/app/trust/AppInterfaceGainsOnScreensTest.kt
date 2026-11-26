package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AddressMismatchFor
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the app interface gained, on the screens: a two-step set-up brought back after an unlock, an invite whose
 * server serves another address's card, and device-link screens that advance by themselves and are left only with
 * Start over.
 */
class AppInterfaceGainsOnScreensTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun aTwoStepSetUpLeftForTheAuthenticatorIsBackOnSettingsAfterTheUnlock() {
        val (api, m) = at(FakeScene.VAULTS)
        assertEquals(SignedInPage.VAULT, landingPage(assertNotNull(api.snapshot.account)), "home is the vault")
        m.run({ settings.openTwoStep() })
        m.run({ settings.startTwoStep(assertNotNull(assertNotNull(snapshot.account).twoStep), FakeScenes.PASSWORD) })
        assertNotNull(assertNotNull(api.snapshot.account).twoStep?.enrolment)
        // The person leaves for the authenticator app; the app locks meanwhile.
        m.act { lock() }
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        val account = assertNotNull(api.snapshot.account)
        val enrolment = assertNotNull(account.twoStep?.enrolment, "open again on its confirm step")
        assertEquals(SignedInPage.SETTINGS, landingPage(account), "the unlock lands on Settings")
        assertNotNull(api.settings.twoStepKey(enrolment), "the key is readable again")
        // Closed, the vault is home again and the key is gone.
        m.act { settings.closeTwoStep() }
        assertEquals(SignedInPage.VAULT, landingPage(assertNotNull(api.snapshot.account)))
        assertNull(api.settings.twoStepKey(enrolment))
    }

    @Test
    fun theKeyIsReadAgainWhileShownAndNeverCachedPastTheEngine() {
        val settings = src("SettingsScreens.kt")
        val section = settings.substringAfter("fun TwoStepSection(").substringBefore("// ---- a new kit after")
        // Read through the API, again every second while it is shown; a key the engine dropped leaves the screen,
        // and with it the code field (a confirm could only answer NOT_PENDING).
        assertTrue(section.contains("delay(TWO_STEP_KEY_REREAD_MS)") && section.contains("key = model.api.settings.twoStepKey(enrolment)"))
        assertEquals(1_000L, TWO_STEP_KEY_REREAD_MS)
        val whenGone = section.substringAfter("} else {").substringBefore("}")
        assertTrue(whenGone.contains("Placeholder.TWO_STEP_KEY_GONE"))
        assertFalse(whenGone.contains("confirmTwoStep"))
        val shell = src("AccountScreens.kt").substringAfter("fun AccountShell(").substringBefore("internal enum class SignedInPage")
        // firstPage is the screen images' way in; nothing in the app provides it, so it is null on a phone.
        assertTrue(shell.contains("mutableStateOf(firstPage ?: landingPage(account))") && shell.contains("page = SignedInPage.SETTINGS"))
        assertTrue(src("AccountScreens.kt").contains("LocalFirstPage = androidx.compose.runtime.staticCompositionLocalOf<SignedInPage?> { null }"))
    }

    @Test
    fun anInviteWhoseServerServesAnotherAddresssCardLandsOnTheMismatchScreen() {
        val (api, m) = at(FakeScene.INVITE_ENTRY)
        val lookalike = api.script.addServer("https://vau1t.family.example", "Family", ServerKind.PRIVATE_SERVER)
        lookalike.servesAnotherServersCard = true
        lookalike.cardNamesOrigin = "https://vault.family.example"
        val screen = assertIs<EntryScreen.InviteEntry>(api.snapshot.entry)
        m.run({ entry.submitInvite(screen, api.script.connectInvite(lookalike, "Bo"), PayloadSource.PASTED) })
        val mismatch = assertIs<EntryScreen.AddressMismatch>(api.snapshot.entry)
        assertEquals(AddressMismatchFor.INVITE, mismatch.opening)
        assertFalse(mismatch.canRecoverThere, "an invite is never redirected")
        assertEquals(Placeholder.ADDRESS_MISMATCH_INVITE, addressMismatchNext(mismatch))
        // The screen shows both addresses whole, says what to do next, and offers no recovery for it.
        val body = src("EntryScreens.kt").substringAfter("fun AddressMismatchScreen(").substringBefore("// ---- \"Already have")
        assertTrue(body.contains("screen.dialed") && body.contains("screen.cardNames") && body.contains("addressMismatchNext(screen)"))
        assertTrue(api.entry.back())
        assertIs<EntryScreen.InviteEntry>(api.snapshot.entry)
    }

    @Test
    fun theBackupPassphraseGoesAsCharArraysAndRenameGoesThroughTheContent() {
        val export = src("VaultTransferScreens.kt").substringAfter("fun ExportPanel(")
        assertTrue(export.contains("c.backupFileChars(p, k)"), "the content zeroes both arrays on every path")
        assertFalse(export.contains("c.backupFile("), "the String overload is not used")
        // The fields are emptied before the call, so the screen keeps no copy while the file is made.
        val made = export.substringAfter("val p = passphrase.toCharArray()").substringBefore("c.backupFileChars(p, k)")
        assertTrue(made.contains("passphrase = \"\"") && made.contains("confirm = \"\""))
        // Renaming a shared vault: the content's call is the canonical one.
        val vaults = src("VaultScreens.kt") + src("VaultItemsScreens.kt")
        assertTrue(vaults.contains("renameSharedVault("))
        assertFalse(vaults.contains("sharedVaults.renameVault("))
    }

    @Test
    fun claimedDeviceLinkScreensAreLeftOnlyWithStartOver() {
        for (scene in listOf(FakeScene.LINK_DEVICE_WAITING, FakeScene.LINK_DEVICE_CODE)) {
            val (api, m) = at(scene)
            val screen = assertNotNull(api.snapshot.entry)
            assertFalse(entryBackLeaves(screen), "$scene: the system Back does nothing")
            assertFalse(api.entry.back(), "$scene: the engine refuses Back too")
            m.act { entry.startOver() }
            assertIs<EntryScreen.FirstRun>(api.snapshot.entry, "$scene: Start over leaves it")
        }
        assertTrue(entryBackLeaves(assertNotNull(at(FakeScene.LINK_DEVICE_ENTRY).first.snapshot.entry)))
        // The screens have no Back of their own and no control that advances them: the snapshot does.
        val links = src("LinkAndRecoveryScreens.kt")
        for (fn in listOf("LinkDeviceWaitingScreen", "LinkDeviceCodeScreen")) {
            val body = links.substringAfter("fun $fn(").substringBefore("\n@Composable")
            assertFalse(body.contains("BackRow(") || body.contains("entry.back()"), "$fn has no Back")
            assertTrue(body.contains("entry.startOver()"), "$fn offers Start over")
        }
        val router = src("TrustApp.kt").substringAfter("fun EntryRouter(").substringBefore("\n}")
        assertTrue(router.contains("if (!entryBackLeaves(screen)) return@ActiveBackHandler"))
    }
}
