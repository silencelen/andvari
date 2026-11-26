package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.TwoStepResult
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Turning two-step sign-in off, and replacing its key, ask for the master password with a current code (decided on
 * 2026-11-16): the section has the password field in that step and calls the shared code's calls that take it; a wrong
 * password, a wrong code and "too many tries, wait" are each said; the fields are emptied on every path.
 */
class TwoStepWithPasswordTest {
    private val pw = FakeScenes.PASSWORD

    private fun on(): Pair<io.silencelen.andvari.core.app.fake.FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        m.run({ settings.openTwoStep() })
        m.run({ settings.startTwoStep(assertNotNull(api.snapshot.account?.twoStep), pw) })
        val enrolment = assertNotNull(api.snapshot.account?.twoStep?.enrolment)
        m.run({ settings.confirmTwoStep(enrolment, api.script.authenticatorCode) })
        assertTrue(assertNotNull(api.snapshot.account?.twoStep).enabled)
        return api to m
    }

    @Test
    fun eachRefusalIsSaidAsWhatItIsAndTheRightPasswordAndCodeTurnItOff() {
        val (api, m) = on()
        val ts = { assertNotNull(api.snapshot.account?.twoStep) }
        var r: TwoStepResult? = null
        m.run({ settings.turnOffTwoStepWithPassword(ts(), api.script.authenticatorCode, "not the password") }) { r = it }
        assertEquals(TwoStepResult.WRONG_PASSWORD, r)
        val wrongPassword = assertNotNull(m.saidOn(api.snapshot)).text.shown()
        assertTrue(wrongPassword.contains("WRONG_PASSWORD"), wrongPassword)
        m.run({ settings.turnOffTwoStepWithPassword(ts(), "000000", pw) }) { r = it }
        assertEquals(TwoStepResult.WRONG_CODE, r)
        val wrongCode = assertNotNull(m.saidOn(api.snapshot)).text.shown()
        assertTrue(wrongCode.contains("WRONG_CODE") && wrongCode != wrongPassword, wrongCode)
        api.script.twoStepTriesLocked = true
        m.run({ settings.turnOffTwoStepWithPassword(ts(), api.script.authenticatorCode, pw) }) { r = it }
        assertEquals(TwoStepResult.TOO_MANY_TRIES, r)
        val wait = assertNotNull(m.saidOn(api.snapshot)).text
        assertEquals(UiText.of(CopyKey.TWO_STEP_TOO_MANY_TRIES).shown(), wait.shown(), "the shared code's words")
        api.script.twoStepTriesLocked = false
        assertTrue(ts().enabled, "nothing was turned off by a refusal")
        m.run({ settings.turnOffTwoStepWithPassword(ts(), api.script.authenticatorCode, pw) }) { r = it }
        assertEquals(TwoStepResult.DONE, r)
        assertFalse(ts().enabled)
        assertNull(m.saidOn(api.snapshot))
    }

    @Test
    fun aNewKeyTakesTheCodeAndThePasswordAndHoldsAnEnrolmentToConfirm() {
        val (api, m) = on()
        val ts = assertNotNull(api.snapshot.account?.twoStep)
        var r: TwoStepResult? = null
        m.run({ settings.replaceTwoStepKey(ts, api.script.authenticatorCode, pw) }) { r = it }
        assertEquals(TwoStepResult.DONE, r)
        assertNotNull(api.snapshot.account?.twoStep?.enrolment, "the new key waits for its first code, as at set-up")
    }

    @Test
    fun theSectionAsksForThePasswordCallsTheCallsThatTakeItAndEmptiesBothFieldsAsItSends() {
        assertTrue(twoStepStepReady("p", "123456"))
        assertFalse(twoStepStepReady("", "123456"))
        assertFalse(twoStepStepReady("p", "  "))
        val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/SettingsScreens.kt").readText()
        val section = src.substringAfter("internal fun TwoStepSection(").substringBefore("\n}\n")
        val onBranch = section.substringAfter("twoStep.enabled -> {").substringBefore("else -> {")
        assertTrue(onBranch.contains("MasterPasswordField(s, password)") && onBranch.contains("Placeholder.TWO_STEP_CODE_FIELD"))
        assertFalse(section.contains("settings.turnOffTwoStep("), "the code-only call sends nothing now")
        for (call in listOf("settings.turnOffTwoStepWithPassword(twoStep, c, p)", "settings.replaceTwoStepKey(twoStep, c, p)")) {
            val at = onBranch.indexOf(call)
            assertTrue(at > 0, call)
            val before = onBranch.substring(onBranch.lastIndexOf("Quieter(", at), at)
            assertTrue(before.contains("code = \"\"") && before.contains("password = \"\""), "both fields emptied before $call")
        }
    }
}
