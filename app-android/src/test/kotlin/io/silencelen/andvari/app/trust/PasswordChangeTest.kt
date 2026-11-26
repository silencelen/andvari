package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultUnlockResult
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

/** Settings › Change master password on the real call, each outcome on a line of its own. */
class PasswordChangeTest {
    private val strong = "a much longer master password, 2026!"

    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
    }

    private fun TrustModel.change(current: String, replacement: String) =
        runIn(PASSWORD_CHANGE_SECTION, { settings.changeMasterPassword(current, replacement) }, { passwordChangeWords(it, 0) })

    private fun said(api: FakeAppApi, m: TrustModel): TrustModel.Said = assertNotNull(m.saidIn(api.snapshot, PASSWORD_CHANGE_SECTION))

    @Test
    fun eachRefusalHasItsOwnLineInTheSectionAndNothingUnderTheTop() {
        val (api, m) = at(FakeScene.VAULTS)
        m.change("wrong", strong)
        assertEquals(PasswordChangeResult.WRONG_PASSWORD, said(api, m).result)
        assertEquals(Placeholder.PASSWORD_CHANGE_WRONG, assertIs<UiText.Ph>(said(api, m).text).placeholder)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "a wrong current password is never an expired session")

        m.change(FakeScenes.PASSWORD, "short")
        assertEquals(PasswordChangeResult.WEAK_PASSWORD, said(api, m).result)
        assertEquals(Placeholder.PASSWORD_CHANGE_WEAK, (said(api, m).text as UiText.Ph).placeholder)
        assertTrue(Placeholder.PASSWORD_CHANGE_WEAK.gloss.contains("nothing was sent"))

        api.script.forceNext(PasswordChangeResult.CHANGED_ELSEWHERE)
        m.change(FakeScenes.PASSWORD, strong)
        assertEquals(Placeholder.PASSWORD_CHANGE_CHANGED_ELSEWHERE, (said(api, m).text as UiText.Ph).placeholder)

        api.script.failNext(Trouble.UNREACHABLE)
        m.change(FakeScenes.PASSWORD, strong)
        assertEquals(PasswordChangeResult.UNREACHABLE, said(api, m).result)
        assertEquals(Placeholder.PASSWORD_CHANGE_NO_ANSWER, (said(api, m).text as UiText.Ph).placeholder)

        // The section says it; the line under the top of the screen does not repeat it.
        assertNotNull(m.saidOn(api.snapshot))
        val ui = File("src/main/kotlin/io/silencelen/andvari/app/trust/TrustUi.kt").readText()
        assertTrue(ui.contains("model.saidOn(s)?.takeIf { it.section == null }"))
        // Every outcome is told apart.
        val lines = PasswordChangeResult.entries.mapNotNull { passwordChangeWords(it, 0)?.shown() }
        assertEquals(lines.size, lines.toSet().size)
        assertNull(passwordChangeWords(PasswordChangeResult.DONE, 0))
    }

    @Test
    fun afterTheChangeThePersonIsToldNoKitFollowsAndThisPhoneOpensWithTheNewPasswordOnly() {
        val (api, m) = at(FakeScene.VAULTS)
        m.change(FakeScenes.PASSWORD, strong)
        assertNull(m.saidOn(api.snapshot), "done says nothing in place")
        val account = assertNotNull(api.snapshot.account)
        assertNull(account.kit, "no new kit follows a password change")
        val lines = passwordChangedLines(account)
        assertEquals(
            listOf(Placeholder.PASSWORD_CHANGED, Placeholder.PASSWORD_CHANGED_THIS_PHONE, Placeholder.PASSWORD_CHANGED_NO_KIT, Placeholder.PASSWORD_CHANGED_QUICK_UNLOCK),
            lines.take(4).map { (it as UiText.Ph).placeholder },
        )
        assertEquals(quickUnlockStateLine(account.quickUnlock).shown(), lines.last().shown(), "quick unlock as the app interface reports it")

        m.act { lock() }
        m.runSaying({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) }, { unlockWords(it, 0) })
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the old password no longer opens this phone")
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, m.saidOn(api.snapshot)?.result)
        m.run({ unlock(assertNotNull(snapshot.locked), strong) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "the new password does")
    }

    @Test
    fun thePasswordsNeverEnterSavedStateAndAreClearedAsSoonAsTheIntentHasThem() {
        val section = File("src/main/kotlin/io/silencelen/andvari/app/trust/SettingsScreens.kt").readText()
            .substringAfter("internal fun ChangePasswordSection(").substringBefore("\n}\n")
        assertFalse(section.contains("rememberSaveable"))
        assertTrue(section.contains("var current by remember { mutableStateOf(\"\") }"))
        // The current password is cleared before the intent runs; the new ones after DONE or WEAK.
        assertTrue(section.indexOf("current = \"\"\n        model.runIn(PASSWORD_CHANGE_SECTION") > 0)
        // Also after CHANGED_PREVIOUS_OPENS_HERE, when the new password is in force at the server.
        assertTrue(section.contains("if (result.done || result == PasswordChangeResult.WEAK_PASSWORD || result == PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE) {"))
        // All three when the section leaves the screen.
        assertTrue(section.contains("onDispose {\n            current = \"\"\n            replacement = \"\"\n            again = \"\""))
        assertTrue(section.contains("if (account.serverStopped) return"), "not offered on a copy the server signed out or a stopped server")
        assertTrue(section.contains("MasterPasswordStrengthHints(replacement)"), "the strength answer")
    }
}
