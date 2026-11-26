package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceLinkHostEnd
import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.ProofResult
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
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Linking a new device from this computer (§8.2, the existing device's side), through every step and every end. */
class DeviceLinkHostTest {
    private fun shown(): Triple<FakeDesktopAppApi, TrustModel, DeviceLinkHost.Shown> {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        m.run({ devices.startDeviceLink() })
        return Triple(api, m, assertIs(api.snapshot.account?.deviceLink))
    }

    private fun link(api: FakeDesktopAppApi): DeviceLinkHost? = api.snapshot.account?.deviceLink

    @Test
    fun theLinkIsShownAsACodeAndAsTextWithTheAddressToCompareAndACountdown() {
        val (api, _, screen) = shown()
        val url = assertNotNull(api.devices.deviceLinkToShow(screen))
        assertTrue(url.contains("/d#v2."), "the device link itself, for the code to scan and as text")
        val instance = assertNotNull(api.snapshot.instance).label
        val line = UiText.of(screen.line).shown()
        assertTrue(line.contains(instance.origin), "the address line names the origin to compare: $line")
        val left = api.devices.deviceLinkTimeLeftMs()
        assertTrue(left in 1..(5 * 60_000L))
        assertEquals("5:00", countdown(5 * 60_000L))
        assertEquals("0:01", countdown(1))
        assertEquals("0:00", countdown(-5))
        val view = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/SettingsScreens.kt").readText().substringAfter("internal fun DeviceLinkHostView(").substringBefore("\n}\n")
        assertTrue(view.contains("QrImage(link)") && view.contains("Text(link,"), "as a code to scan and as text")
        assertTrue(view.contains("Say(host.line)"))
        assertFalse(view.contains("approveWithBiometrics"), "no biometric approval on the desktop")
    }

    @Test
    fun theDigitsAreTypedHereThenTheMasterPasswordApproves() {
        val (api, m, _) = shown()
        api.script.joiningDeviceClaims("Pixel", AppPlatform.ANDROID)
        val claimed = assertIs<DeviceLinkHost.Claimed>(link(api))
        assertEquals("Pixel", claimed.deviceName)
        api.script.joiningDeviceReveals(true)
        val type = assertIs<DeviceLinkHost.TypeDigits>(link(api))
        val code = api.script.joiningDeviceCode
        assertFalse(deviceDigitsReady(code.take(5)), "the control waits for six digits")
        assertTrue(deviceDigitsReady(code.take(3) + " " + code.drop(3)), "spaces do not count, as core compares")
        assertFalse(deviceDigitsReady("12a456"))
        m.run({ devices.submitDeviceDigits(type, code) })
        val approvable = assertIs<DeviceLinkHost.Approvable>(link(api))
        m.runSaying({ devices.approveWithPassword(approvable, "not it") }, { deviceLinkApproveLine(it) })
        assertEquals(Placeholder.DEVICE_LINK_WRONG_PASSWORD, (m.saidOn(api.snapshot)?.text as? UiText.Ph)?.placeholder)
        assertIs<DeviceLinkHost.Approvable>(link(api), "a wrong password approves nothing; the link waits")
        m.runSaying({ devices.approveWithPassword(assertIs(link(api)), FakeScenes.PASSWORD) }, { deviceLinkApproveLine(it) })
        val approved = assertIs<DeviceLinkHost.Approved>(link(api))
        assertEquals("Pixel", approved.deviceName)
        m.act { devices.dismissDeviceLink() }
        assertNull(link(api))
    }

    @Test
    fun everyEndHasItsLine() {
        // Typed digits that do not match cancel the link.
        val (api, m, _) = shown()
        api.script.joiningDeviceClaims("Pixel", AppPlatform.ANDROID)
        api.script.joiningDeviceReveals(true)
        m.run({ devices.submitDeviceDigits(assertIs(link(api)), "000000".takeIf { it != api.script.joiningDeviceCode } ?: "111111") })
        assertEquals(DigitsResult.MISMATCH, m.saidOn(api.snapshot)?.result)
        assertEquals(DeviceLinkHostEnd.CODE_MISMATCH, assertIs<DeviceLinkHost.Ended>(link(api)).outcome)

        // Cancelled here.
        val (api2, m2, _) = shown()
        m2.run({ devices.cancelDeviceLink() })
        assertEquals(DeviceLinkHostEnd.CANCELLED, assertIs<DeviceLinkHost.Ended>(link(api2)).outcome)

        // A reveal that does not check out.
        val (api3, _, _) = shown()
        api3.script.joiningDeviceClaims("Pixel", AppPlatform.ANDROID)
        api3.script.joiningDeviceReveals(false)
        assertEquals(DeviceLinkHostEnd.DID_NOT_CHECK_OUT, assertIs<DeviceLinkHost.Ended>(link(api3)).outcome)

        assertEquals(CopyKey.DEVICE_LINK_CANCELLED.english, deviceLinkEndLine(DeviceLinkHostEnd.CANCELLED).shown())
        assertEquals(CopyKey.DEVICE_LINK_CANCELLED.english, deviceLinkEndLine(DeviceLinkHostEnd.CODE_MISMATCH).shown())
        assertEquals(Placeholder.DEVICE_LINK_EXPIRED, (deviceLinkEndLine(DeviceLinkHostEnd.EXPIRED) as UiText.Ph).placeholder)
        assertEquals(Placeholder.DEVICE_LINK_DID_NOT_CHECK_OUT, (deviceLinkEndLine(DeviceLinkHostEnd.DID_NOT_CHECK_OUT) as UiText.Ph).placeholder)
        assertTrue(DeviceLinkHostEnd.entries.none { deviceLinkEndLine(it).let { t -> t is UiText.Ph && t.placeholder == Placeholder.REFUSAL } })
        assertNull(deviceLinkApproveLine(ProofResult.DONE))
    }

    @Test
    fun leavingTheScreenCancelsALinkStillRunningAndClosesAnEndedOne() {
        val (api, m, _) = shown()
        api.script.joiningDeviceClaims("Pixel", AppPlatform.ANDROID)
        assertNotNull(m.leftDeviceLink(), "a link still running is cancelled")
        assertEquals(DeviceLinkHostEnd.CANCELLED, assertIs<DeviceLinkHost.Ended>(link(api)).outcome)
        assertNull(m.leftDeviceLink(), "an ended one is closed")
        assertNull(link(api))
        assertNull(m.leftDeviceLink(), "nothing to do without a link")

        // Locked: the screen went with the lock, and core cancels a lock's link itself; nothing is sent from here.
        val (api2, m2, _) = shown()
        m2.lockNow()
        assertEquals(AppPhase.LOCKED, api2.snapshot.phase)
        assertNull(m2.leftDeviceLink())

        val section = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/SettingsScreens.kt").readText().substringAfter("internal fun DevicesSection(").substringBefore("\n}\n")
        assertTrue(section.contains("DisposableEffect(Unit) { onDispose { model.leftDeviceLink() } }"))
    }
}
