package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceLinkHostEnd
import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.Trouble
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

/** Linking a new device from this phone, the host side, on the real calls. */
class DeviceLinkHostTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
    }

    private fun FakeAppApi.host(): DeviceLinkHost? = snapshot.account?.deviceLink

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun theLinkShowsAsTextWithTheAddressLineAndLeavingTheScreenCancelsIt() {
        val (api, m) = at(FakeScene.HOST_LINK_SHOWN)
        val shown = assertIs<DeviceLinkHost.Shown>(api.host())
        val link = assertNotNull(api.devices.deviceLinkToShow(shown))
        assertTrue(link.contains("/d#v2."), "the link itself, for the QR and as text")
        assertEquals(CopyKey.DEVICE_LINK_SHOW, shown.line.key)
        assertEquals(listOf(shown.instance.name, shown.instance.origin), shown.line.values, "the address to compare")
        assertTrue(api.devices.deviceLinkTimeLeftMs() > 0)
        assertEquals("5:00", countdownText(300_000))
        assertEquals("0:01", countdownText(1))
        assertEquals("0:00", countdownText(-5))
        assertTrue(deviceLinkRunning(shown))

        m.leaveDeviceLink()
        assertNull(api.host(), "cancelled at the server and closed")
        assertNull(m.saidOn(api.snapshot), "leaving says nothing")
    }

    @Test
    fun theDigitsAreTypedHereAndTheApprovalIsByTheMasterPasswordOnly() {
        val (api, m) = at(FakeScene.HOST_LINK_TYPE_DIGITS)
        val typing = assertIs<DeviceLinkHost.TypeDigits>(api.host())
        assertEquals(CopyKey.DEVICE_LINK_ADD, typing.line.key)
        assertTrue(deviceDigitsReady("123 456"), "spaces removed, then six digits (§6.11)")
        assertFalse(deviceDigitsReady("12345"))
        assertFalse(deviceDigitsReady("12345a"))
        assertFalse(deviceDigitsReady("1234567"))
        m.runIn(DEVICE_LINK_SECTION, { devices.submitDeviceDigits(typing, api.script.joiningDeviceCode) }, { deviceDigitsWords(it, 0) })
        val approvable = assertIs<DeviceLinkHost.Approvable>(api.host())

        m.runIn(DEVICE_LINK_SECTION, { devices.approveWithPassword(approvable, "wrong") }, { deviceLinkProofWords(it, 0) })
        val said = assertNotNull(m.saidIn(api.snapshot, DEVICE_LINK_SECTION))
        assertEquals(ProofResult.WRONG_PASSWORD, said.result)
        assertEquals(Placeholder.DEVICE_LINK_WRONG_PASSWORD, (said.text as UiText.Ph).placeholder)
        m.runIn(DEVICE_LINK_SECTION, { devices.approveWithPassword(assertIs(api.host()), FakeScenes.PASSWORD) }, { deviceLinkProofWords(it, 0) })
        val approved = assertIs<DeviceLinkHost.Approved>(api.host())
        assertFalse(deviceLinkRunning(approved))

        // Leaving an approved link closes it; the new device shows in the list once it picked up.
        api.script.joiningDevicePicksUp()
        m.leaveDeviceLink()
        assertNull(api.host())

        val view = src("DevicesScreens.kt").substringAfter("internal fun DeviceLinkHostView(")
        assertFalse(view.contains("QUICK_UNLOCK_BUTTON"), "approving is never worded as an unlock")
        assertTrue(view.contains("if (host.biometricsOffered) {"), "fingerprint or face only where the shared code offers it")
        assertTrue(view.contains("MasterPasswordField(s, password)"), "the password screen names the account and the instance")
    }

    @Test
    fun aMismatchEndsTheLinkAndEachEndHasItsLines() {
        val (api, m) = at(FakeScene.HOST_LINK_TYPE_DIGITS)
        val typing = assertIs<DeviceLinkHost.TypeDigits>(api.host())
        val wrong = if (api.script.joiningDeviceCode == "000000") "111111" else "000000"
        m.runIn(DEVICE_LINK_SECTION, { devices.submitDeviceDigits(typing, wrong) }, { deviceDigitsWords(it, 0) })
        val ended = assertIs<DeviceLinkHost.Ended>(api.host())
        assertEquals(DeviceLinkHostEnd.CODE_MISMATCH, ended.outcome)
        assertNull(m.saidIn(api.snapshot, DEVICE_LINK_SECTION), "the end says it, once")
        assertNull(deviceDigitsWords(DigitsResult.MISMATCH, 0))
        assertEquals(CopyKey.DEVICE_LINK_CANCELLED.english, deviceLinkEndLines(DeviceLinkHostEnd.CANCELLED).single().shown())
        assertEquals(2, deviceLinkEndLines(DeviceLinkHostEnd.CODE_MISMATCH).size)
        assertEquals(Placeholder.DEVICE_LINK_EXPIRED, (deviceLinkEndLines(DeviceLinkHostEnd.EXPIRED).single() as UiText.Ph).placeholder)
        assertEquals(Placeholder.DEVICE_LINK_DID_NOT_CHECK_OUT, (deviceLinkEndLines(DeviceLinkHostEnd.DID_NOT_CHECK_OUT).single() as UiText.Ph).placeholder)
        m.leaveDeviceLink()
        assertNull(api.host())
    }

    @Test
    fun aLockCancelsTheLinkAndACancelThatFailsIsSaid() {
        val (api, m) = at(FakeScene.HOST_LINK_CLAIMED)
        assertIs<DeviceLinkHost.Claimed>(api.host())
        api.script.failNext(Trouble.UNREACHABLE)
        m.leaveDeviceLink()
        assertIs<DeviceLinkHost.Claimed>(api.host(), "not cancelled: still on show")
        assertNotNull(m.saidIn(api.snapshot, DEVICE_LINK_SECTION), "never swallowed")

        // Going to the background locks; the lock is what cancels the link, in core (the engine's
        // aLinkMadeOnThisDeviceIsCancelledByALock). The fake keeps the link across a lock (reported to core), so
        // this pins the app's part only: it locks, and the screen's leave finds no open account to act on.
        m.clearSaid()
        m.backgrounded()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        m.leaveDeviceLink()
        assertNull(m.said.value, "nothing is sent or said once the vault is locked")
    }

    @Test
    fun theScreenIsItsOwnPageNothingOfItIsLoggedAndTheClipboardTakesOnlyATap() {
        val shell = src("AccountScreens.kt")
        assertTrue(shell.contains("account.deviceLink?.let { return DeviceLinkHostPage(model, s, account, it) }"))
        val devices = src("DevicesScreens.kt")
        val page = devices.substringAfter("internal fun DeviceLinkHostPage(").substringBefore("\n}\n")
        assertTrue(page.contains("ActiveBackHandler(model) { model.leaveDeviceLink() }"))
        assertTrue(page.contains("onDispose { model.leaveDeviceLink() }"))
        for (bad in listOf("Log.", "println(", "printStackTrace", "AutofillDebugLog")) assertFalse(devices.contains(bad), bad)
        // The one clipboard write is the Copy button's own tap.
        assertEquals(1, Regex("copyToClipboard\\(").findAll(devices).count())
        assertTrue(devices.contains("Quieter(UiText.ph(Placeholder.DEVICE_LINK_COPY)) {\n                    io.silencelen.andvari.app.copyToClipboard("))
        // The window is FLAG_SECURE for the whole new path, so the link screen is never captured (as the kit's).
        val main = File("src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt").readText()
        assertTrue(main.contains("window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)"))
        assertFalse(devices.contains("clearFlags"))
    }
}
