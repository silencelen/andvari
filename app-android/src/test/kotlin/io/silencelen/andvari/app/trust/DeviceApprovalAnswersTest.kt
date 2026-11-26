package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.ProofResult
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
 * Approving a new device from this phone with the fingerprint or face check (design §8.2 step 6): offered only where
 * the shared code offers it; a cancelled prompt is a result of its own (nothing approved, nothing wrong, the screen
 * stays and the new device still waits); "the check can't be used now" leaves the master password, which is always on
 * the screen; and a lock while the prompt is up approves nothing.
 */
class DeviceApprovalAnswersTest {
    private fun approvable(): Triple<FakeAppApi, TrustModel, DeviceLinkHost.Approvable> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.HOST_LINK_TYPE_DIGITS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        val typing = assertIs<DeviceLinkHost.TypeDigits>(assertNotNull(api.snapshot.account).deviceLink)
        m.run({ devices.submitDeviceDigits(typing, api.script.joiningDeviceCode) })
        return Triple(api, m, assertIs(assertNotNull(api.snapshot.account).deviceLink))
    }

    private fun TrustModel.withBiometrics(host: DeviceLinkHost.Approvable) =
        runIn(DEVICE_LINK_SECTION, { devices.approveWithBiometrics(host, deviceApprovalReason(host)) }, { deviceLinkProofWords(it, 0) })

    private fun TrustModel.withPassword(host: DeviceLinkHost.Approvable, password: String) =
        runIn(DEVICE_LINK_SECTION, { devices.approveWithPassword(host, password) }, { deviceLinkProofWords(it, 0) })

    private fun host(api: FakeAppApi): DeviceLinkHost? = api.snapshot.account?.deviceLink

    @Test
    fun aCancelledPromptSaysSoKeepsTheScreenAndThePasswordStillApproves() {
        val (api, m, host) = approvable()
        api.script.biometricsCancelled = true
        m.withBiometrics(host)
        val said = assertNotNull(m.saidIn(api.snapshot, DEVICE_LINK_SECTION), "said in place, on the approval")
        assertEquals(ProofResult.CANCELLED, said.result)
        assertEquals(UiText.of(CopyKey.DEVICE_APPROVAL_CANCELLED).shown(), said.text.shown(), "the cancelled prompt's own sentence")
        assertTrue(said.text.shown() != deviceLinkProofWords(ProofResult.WRONG_PASSWORD, 0)?.shown(), "never a wrong password")
        val still = assertIs<DeviceLinkHost.Approvable>(host(api), "the new device still waits")
        assertTrue(still.biometricsOffered, "and the check is still offered")
        m.withPassword(still, FakeScenes.PASSWORD)
        assertIs<DeviceLinkHost.Approved>(host(api))
    }

    @Test
    fun whenTheCheckCannotBeUsedNowThePasswordApproves() {
        val (api, m, host) = approvable()
        api.script.biometricsRefused = true
        m.withBiometrics(host)
        assertEquals(ProofResult.BIOMETRICS_NOT_USED, assertNotNull(m.saidIn(api.snapshot, DEVICE_LINK_SECTION)).result)
        val still = assertIs<DeviceLinkHost.Approvable>(host(api))
        // The password field is on the approval whatever the check answered: the password approves.
        val view = File("src/main/kotlin/io/silencelen/andvari/app/trust/DevicesScreens.kt").readText()
            .substringAfter("is DeviceLinkHost.Approvable ->").substringBefore("is DeviceLinkHost.Approved ->")
        assertTrue(view.indexOf("MasterPasswordField(s, password)") in 0 until view.indexOf("if (host.biometricsOffered)"), "the field is drawn before, and apart from, the check's button")
        m.withPassword(still, FakeScenes.PASSWORD)
        assertIs<DeviceLinkHost.Approved>(host(api))
    }

    @Test
    fun aCheckWhoseKeyNoLongerOpensTurnsQuickUnlockOffAndTheButtonGoes() {
        val (api, m, host) = approvable()
        api.script.biometricsChanged = true
        m.withBiometrics(host)
        assertEquals(ProofResult.BIOMETRICS_NOT_USED, assertNotNull(m.saidIn(api.snapshot, DEVICE_LINK_SECTION)).result)
        assertFalse(assertIs<DeviceLinkHost.Approvable>(host(api)).biometricsOffered, "not offered again")
    }

    @Test
    fun aLockWhileThePromptIsUpApprovesNothingAndIsSaidAsTheLock() {
        val (api, m, host) = approvable()
        api.script.lockDuringPresence = true
        m.withBiometrics(host)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertNull(api.snapshot.account?.deviceLink?.takeIf { it is DeviceLinkHost.Approved }, "nothing was approved")
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertEquals(Placeholder.LOCK_OVERTOOK, assertIs<UiText.Ph>(said.text).placeholder, "the lock, not a failure")
    }

    /** Seen in the drawing: the approved "{0} seconds left" read "5:00 seconds left". */
    @Test
    fun aDeviceLinksTimeLeftIsCountedInSeconds() {
        assertEquals("300", secondsLeft(300_000))
        assertEquals("1", secondsLeft(1))
        assertEquals("0", secondsLeft(-5))
        val host = File("src/main/kotlin/io/silencelen/andvari/app/trust/DevicesScreens.kt").readText()
        assertTrue("Quiet(deviceLinkTimeLeftLine(left))" in host)
        assertTrue("counted(secondsLeft(ms).toLong(), Placeholder.DEVICE_LINK_TIME_LEFT, Placeholder.DEVICE_LINK_TIME_LEFT_ONE)" in host)
        assertEquals(Placeholder.DEVICE_LINK_TIME_LEFT_ONE, assertIs<UiText.Ph>(deviceLinkTimeLeftLine(1)).placeholder)
        assertEquals(listOf("300"), assertIs<UiText.Ph>(deviceLinkTimeLeftLine(300_000)).args)
        assertFalse("DEVICE_LINK_TIME_LEFT, countdownText" in host)
        assertFalse("DEVICE_LINK_TIME_LEFT" in File("src/main/kotlin/io/silencelen/andvari/app/trust/LinksScreens.kt").readText(), "a link has its own line")
    }

    @Test
    fun notOfferedWhereQuickUnlockCannotAnswer() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.HOST_LINK_TYPE_DIGITS)
        api.script.quickUnlock = false
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        val typing = assertIs<DeviceLinkHost.TypeDigits>(assertNotNull(api.snapshot.account).deviceLink)
        m.run({ devices.submitDeviceDigits(typing, api.script.joiningDeviceCode) })
        assertFalse(assertIs<DeviceLinkHost.Approvable>(host(api)).biometricsOffered)
    }
}
