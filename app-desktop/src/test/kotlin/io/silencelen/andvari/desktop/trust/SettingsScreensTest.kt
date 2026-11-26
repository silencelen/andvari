package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
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
import kotlin.test.assertTrue

/** The desktop's signed-in Settings over the fake: devices and adding a device, recovery, password, deletion. */
class SettingsScreensTest {
    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
    }

    private val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/SettingsScreens.kt").readText()

    private fun body(fn: String) = src.substringAfter("fun $fn(").substringBefore("\n@Composable")

    /** §17, §8.2 after the pin: the approving side confirms only through six typed digits, and the control waits for six. */
    @Test
    fun theApprovingSideTakesExactlySixTypedDigitsAndNothingElseConfirms() {
        assertFalse(deviceDigitsReady("12345"))
        assertFalse(deviceDigitsReady("1234567"))
        assertFalse(deviceDigitsReady("12345a"))
        assertFalse(deviceDigitsReady("12 456"))
        assertTrue(deviceDigitsReady("123456"))
        val (api, _) = at(FakeScene.HOST_LINK_TYPE_DIGITS)
        assertIs<DeviceLinkHost.TypeDigits>(assertNotNull(api.snapshot.account?.deviceLink))
        val host = body("DeviceLinkHostView")
        assertEquals(1, Regex("devices\\.submitDeviceDigits\\(").findAll(src).count(), "one way to confirm")
        assertTrue(host.contains("enabled = deviceDigitsReady(digits) && !s.busy"))
        assertFalse(host.contains("approveWithBiometrics"), "no quick unlock on desktop")
    }

    @Test
    fun thisDeviceIsListedFirstAndIsNeverRevoked() {
        val (api, m) = at(FakeScene.DEVICES)
        var screen = api.snapshot.account?.devices
        if (screen == null) {
            m.run({ devices.openDevices() })
            screen = api.snapshot.account?.devices
        }
        val rows = devicesInOrder(assertNotNull(screen))
        assertTrue(rows.isNotEmpty())
        assertTrue(rows.first().current, "this device first")
        assertFalse(canRevoke(rows.first()))
    }

    @Test
    fun aDeletionWaitsForEveryFieldAndABlockerStopsIt() {
        val (api, _) = at(FakeScene.DELETION)
        val screen = assertNotNull(api.snapshot.account?.deletion)
        val plan = assertNotNull(screen.plan)
        assertTrue(plan.canProceed)
        val email = screen.email
        assertFalse(deletionReady(screen, "", "pw", "123456"))
        assertFalse(deletionReady(screen, "a@example.com", "pw", "123456"), "the account's own address, typed (design §11 step 4)")
        assertFalse(deletionReady(screen, email, "", "123456"))
        assertEquals(!plan.codeNeeded, deletionReady(screen, email, "pw", ""))
        assertTrue(deletionReady(screen, email, "pw", "123456"))

        val blocked = assertNotNull(at(FakeScene.DELETION_BLOCKED).first.snapshot.account?.deletion)
        assertTrue(assertNotNull(blocked.plan).blockers.isNotEmpty())
        assertFalse(deletionReady(blocked, blocked.email, "pw", "123456"))
        assertTrue(assertNotNull(blocked.plan).blockers.all { (deletionBlockerLine(it) as? UiText.Ph)?.placeholder?.name?.startsWith("DELETION_BLOCKER_") == true }, "each blocker, by its key")

        val unknown = assertNotNull(at(FakeScene.DELETION_OUTCOME_UNKNOWN).first.snapshot.account?.deletion)
        assertTrue(unknown.outcomeUnknown)
        assertFalse(deletionReady(unknown, unknown.email, "pw", "123456"), "an unknown outcome is only checked, never retried blind")
    }

    @Test
    fun aPasswordChangeNeedsAllThreeFieldsAndTheSameNewPasswordTwice() {
        assertFalse(passwordChangeReady("", "new one", "new one"))
        assertFalse(passwordChangeReady("old", "new one", "new 0ne"))
        assertTrue(passwordChangeReady("old", "new one", "new one"))
    }

    @Test
    fun theRecoveryWarningIsTheOnlyWayToTurnOperatorRecoveryOn() {
        val (api, _) = at(FakeScene.RECOVERY_WARNING_IN_SETTINGS)
        assertNotNull(assertNotNull(api.snapshot.account?.recovery).warning)
        assertEquals(1, Regex("recovery\\.turnOnOperatorRecovery\\(").findAll(src).count())
        assertTrue(body("OperatorRecoveryWarningView").contains("enabled = understood && password.isNotEmpty() && !s.busy"), "the tick and the password first")
    }

    /**
     * §17: the comparison screen has no control that confirms without typed digits. This device's own code typed back is
     * the shared code's to judge (as on Android): it answers that the codes do not match and the comparison stays open.
     */
    @Test
    fun theComparisonGoesOnlyThroughTheTypedDigitsOfTheOtherPerson() {
        val (api, m) = at(FakeScene.COMPARE_READY)
        val ready = assertIs<io.silencelen.andvari.core.app.CompareScreen.Ready>(assertNotNull(api.snapshot.account?.comparing))
        assertTrue(comparisonReady(ready, ready.code), "the own code goes to the shared code like any six digits")
        val other = (0 until 6).map { i -> ('0' + ((ready.code.filter { it.isDigit() }[i] - '0' + 1) % 10)) }.joinToString("")
        assertTrue(comparisonReady(ready, other))
        assertFalse(comparisonReady(ready, other.take(5)))
        var answer: io.silencelen.andvari.core.app.ComparisonResult? = null
        m.run({ contacts.submitComparison(ready, ready.code) }) { answer = it }
        assertEquals(io.silencelen.andvari.core.app.ComparisonResult.MISMATCH, answer)
        assertIs<io.silencelen.andvari.core.app.CompareScreen.Ready>(assertNotNull(api.snapshot.account?.comparing), "nothing ends")
        val people = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/PeopleScreens.kt").readText()
        assertEquals(1, Regex("contacts\\.submitComparison\\(").findAll(people).count(), "the only path to a match")
        assertFalse(people.contains("ownCodeTypedBack"), "the desktop refuses nothing by itself")
    }

    @Test
    fun thePolicyLinesSayWhatTheServerSet() {
        val (api, _) = at(FakeScene.VAULTS)
        val policy = assertNotNull(api.snapshot.account).policy
        val lines = policyLines(policy).map { it.shown() }
        assertTrue(lines[0].contains(policy.autoLockSeconds.toString()) && lines[1].contains(policy.clipboardClearSeconds.toString()))
    }
}
