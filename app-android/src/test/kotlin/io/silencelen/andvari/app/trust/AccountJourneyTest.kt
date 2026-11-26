package io.silencelen.andvari.app.trust

import com.google.zxing.BinaryBitmap
import com.google.zxing.LuminanceSource
import com.google.zxing.common.BitMatrix
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.WhoCanRecover
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
 * Sign-up, account creation with the recovery choice, the kit, sign-in and the lock screen on the new path (slices 5
 * to 7), driven through the state holder against the fake, as the screens drive them.
 */
class AccountJourneyTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private val strong = "a much longer master password, 2026!"

    @Test
    fun anEmailSignUpReachesTheFormAndTheFormReachesTheKit() {
        val (api, m) = at(FakeScene.SIGN_UP_EMAIL)
        val email = assertIs<EntryScreen.SignUpEmail>(api.snapshot.entry)
        m.run({ entry.startSignUp(email, "new@example.com", true) })
        val code = assertIs<EntryScreen.SignUpCode>(api.snapshot.entry, "sign-up result: ${m.said.value?.result}")
        m.run({ entry.verifySignUpCode(code, "000000") })
        assertEquals(CodeResult.WRONG_CODE, m.saidOn(api.snapshot)?.result)
        assertTrue(assertNotNull(m.saidOn(api.snapshot)).text.isPlaceholder)
        m.run({ entry.verifySignUpCode(code, api.script.emailCode) })
        val form = assertIs<EntryScreen.CreateAccount>(api.snapshot.entry)
        assertEquals("new@example.com", form.fixedEmail)
        assertNull(form.recovery, "the public instance offers no recovery choice (variant R)")
        assertTrue(src("AccountEntryScreens.kt").contains("CopyKey.RECOVERY_KIT_ONLY"))

        m.run({ entry.createAccount(form, NewAccountInput("", "New", "short", true)) })
        assertEquals(CreateAccountResult.WEAK_PASSWORD, m.saidOn(api.snapshot)?.result)
        m.run({ entry.createAccount(form, NewAccountInput("", "New", strong, true)) })
        val kit = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitReason.FIRST_KIT, kit.reason)
        assertEquals(KitStep.REVEAL, kit.step)
        assertFalse(api.entry.back(), "no way past the kit")
    }

    @Test
    fun aSignUpThatNeedsTheAgeTickSaysSo() {
        val (api, m) = at(FakeScene.SIGN_UP_EMAIL)
        val email = assertIs<EntryScreen.SignUpEmail>(api.snapshot.entry)
        if (!email.ageConfirmRequired) return
        m.run({ entry.startSignUp(email, "new@example.com", false) })
        assertEquals(SignUpStartResult.AGE_CONFIRMATION_NEEDED, m.saidOn(api.snapshot)?.result)
    }

    @Test
    fun operatorRecoveryIsChosenOnlyThroughTheTickedWarning() {
        val (api, m) = at(FakeScene.CREATE_ACCOUNT_RECOVERY_CHOICE)
        val form = assertIs<EntryScreen.CreateAccount>(api.snapshot.entry)
        val q = assertNotNull(form.recovery)
        assertEquals(WhoCanRecover.ONLY_ME, form.whoCanRecover, "Only me is selected by default")
        assertEquals(CopyKey.RECOVERY_QUESTION, q.question)
        m.act { entry.reviewOperatorRecovery(form) }
        val warning = assertIs<EntryScreen.RecoveryWarning>(api.snapshot.entry)
        assertFalse(api.entry.acceptOperatorRecovery(warning, false), "nothing changes unless the box is ticked")
        assertTrue(api.entry.acceptOperatorRecovery(warning, true))
        assertEquals(WhoCanRecover.ME_OR_OPERATOR, assertIs<EntryScreen.CreateAccount>(api.snapshot.entry).whoCanRecover)
        // The screens show the API's copy for every part of the choice and the warning (§7.7 "the same strings").
        val screens = src("AccountEntryScreens.kt")
        for (part in listOf("q.question", "q.onlyMe", "q.onlyMeDetail", "q.meOrOperator", "q.meOrOperatorDetail", "q.takeoverTitle", "w.title", "w.paragraphs", "w.understand", "w.turnOn", "w.keepPrivate")) {
            assertTrue(screens.contains(part), "the recovery screens show $part")
        }
        assertTrue(screens.contains("enabled = understood && !s.busy"), "Turn on is enabled only once ticked")
    }

    @Test
    fun theKitIsRevealedWithElevenGroupsAndAQrThatReadsBackThenConfirmedByTypingThree() {
        val (api, m) = at(FakeScene.KIT_REVEAL)
        val reveal = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        val doc = assertNotNull(api.kit.kitDocument(reveal))
        assertEquals(11, doc.groups.size)
        assertEquals(doc.qrPayload, decode(qrMatrix(doc.qrPayload, 400)), "the QR carries exactly the kit payload")
        m.act { kit.proceedToConfirm(reveal) }
        val confirm = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitStep.CONFIRM, confirm.step)
        assertNull(api.kit.kitDocument(confirm), "the secret is not readable from the confirm step")
        assertEquals(fillCopy(CopyKey.KIT_TYPE_GROUPS, "2", "7", "10"), assertNotNull(confirm.confirmLine).english)
        m.run({ kit.confirmKit(confirm, listOf("x", "y", "z")) })
        assertEquals(KitConfirmResult.MISMATCH, m.saidOn(api.snapshot)?.result)
        val again = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        m.run({ kit.confirmKit(again, again.groupsToType.map { doc.groups[it - 1] }) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "the vault opens once the kit is confirmed")
    }

    /** §10: no Copy button on the reveal or the confirm step, nothing selectable, nothing written to this app's storage. */
    @Test
    fun theKitHasNoCopyButtonAndPrintsWithoutAFileOfItsOwn() {
        val kit = src("KitScreens.kt").replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "").lines().joinToString("\n") { it.substringBefore("//") }
        for (banned in listOf("Clipboard", "SelectionContainer", "copyToClipboard", "CopyRow", "\"Copy\"", "openFileOutput", "cacheDir", "filesDir", "createTempFile")) {
            assertFalse(kit.contains(banned), "the kit screens must not use $banned")
        }
        assertTrue(kit.contains("FileOutputStream(dest.fileDescriptor)"), "the PDF goes straight to the print framework's destination")
    }

    @Test
    fun aKitThatWasNotMadeIsMadeAgainWithTheMasterPassword() {
        val (api, m) = at(FakeScene.KIT_NOT_MADE)
        val notMade = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitStep.NOT_MADE, notMade.step)
        m.run({ kit.retryKit(notMade, "wrong") })
        assertEquals(KitConfirmResult.WRONG_PASSWORD, m.saidOn(api.snapshot)?.result)
        m.run({ kit.retryKit(assertIs<EntryScreen.Kit>(api.snapshot.entry).kit, FakeScenes.PASSWORD) })
        assertEquals(KitStep.REVEAL, assertIs<EntryScreen.Kit>(api.snapshot.entry).kit.step)
    }

    @Test
    fun theSignInScreenNamesTheAccountAndTheInstanceAndSignsIn() {
        val (api, m) = at(FakeScene.SIGN_IN)
        api.script.publicInstance.addAccount(FakeScenes.EMAIL, FakeScenes.PASSWORD)
        val screen = assertIs<EntryScreen.SignIn>(api.snapshot.entry)
        val label = screen.prompt.instance
        assertEquals("Master password for ${FakeScenes.EMAIL} on ${label.name} (${label.origin})", signInTitle(screen, FakeScenes.EMAIL).shown())
        m.run({ entry.submitSignIn(screen, FakeScenes.EMAIL, FakeScenes.PASSWORD) })
        assertTrue(api.snapshot.phase == AppPhase.UNLOCKED || api.snapshot.entry is EntryScreen.Kit, "signed in: ${m.said.value?.result}")
        assertTrue(UiText.forResult(SignInAnswer.OPERATOR_NEEDS_COMPUTER, 0)!!.isPlaceholder, "GAP: the operator refusal has no sentence yet")
    }

    @Test
    fun linkRequiredShowsTheApprovedWordingWithTheAccountAndTheServer() {
        val (api, _) = at(FakeScene.LINK_REQUIRED)
        val screen = assertIs<EntryScreen.LinkRequired>(api.snapshot.entry)
        assertEquals("This device needs to be linked", UiText.of(screen.title).shown())
        val body = UiText.of(screen.body)
        assertFalse(body.isPlaceholder)
        assertEquals(
            "${screen.email} on ${screen.instance.name} (${screen.instance.origin}) has “New devices must be linked” turned on, and this device is new to it. " +
                "Your master password was right. Link this device from one you already use. If you have none, recover the account with your recovery kit, " +
                "which sets a new master password and turns this setting off.",
            body.shown(),
        )
    }

    @Test
    fun theLockScreenNamesTheAccountAndUnlocksWithThePassword() {
        val (api, m) = at(FakeScene.LOCKED)
        val locked = assertNotNull(api.snapshot.locked)
        val label = locked.prompt.instance
        assertEquals("Master password for ${FakeScenes.EMAIL} on ${label.name} (${label.origin})", lockTitle(locked).shown())
        m.run({ unlock(locked, "wrong") })
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, m.saidOn(api.snapshot)?.result)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
    }

    /** §4.4: a fork stops traffic, not reading. */
    @Test
    fun underAForkTheVaultStillOpensReadOnly() {
        val (api, m) = at(FakeScene.LOCKED_SERVER_STOPPED)
        val locked = assertNotNull(api.snapshot.locked)
        m.run({ unlock(locked, FakeScenes.PASSWORD) })
        val account = assertNotNull(api.snapshot.account, "unlocked: ${m.said.value?.result}")
        assertTrue(account.serverStopped)
        assertTrue(src("AccountScreens.kt").contains("account.serverStopped"))
    }

    /** §12.3: "Forget this server" in Settings removes the pin and the session here, and the app is back at the first screen. */
    @Test
    fun forgettingTheServerInSettingsReturnsToTheFirstScreen() {
        val (api, m) = at(FakeScene.VAULTS)
        val instance = assertNotNull(api.snapshot.instance)
        assertEquals(32, instance.details.operatorKeyShort.length)
        m.run({ this.instance.forgetServer(instance) })
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        val shell = src("AccountScreens.kt")
        // Settings uses the one button that asks first (ForgetServerTwinsTest).
        assertTrue(shell.contains("fun ServerSection(") && shell.contains("ForgetServerButton(model, s, instance, quiet = true)"))
    }

    private fun decode(m: BitMatrix): String {
        val source = object : LuminanceSource(m.width, m.height) {
            override fun getRow(y: Int, row: ByteArray?): ByteArray {
                val out = if (row != null && row.size >= width) row else ByteArray(width)
                for (x in 0 until width) out[x] = if (m[x, y]) 0 else 255.toByte()
                return out
            }

            override fun getMatrix(): ByteArray = ByteArray(width * height) { if (m[it % width, it / width]) 0 else 255.toByte() }
        }
        return QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source))).text
    }
}
