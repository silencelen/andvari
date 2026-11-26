package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
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
import kotlin.test.assertTrue

/**
 * The prompt that approves a new device with fingerprint or face says what is approved (design §8.2 steps 5 and 6):
 * the phone's key store answers the shared code's confirmation of presence with the same cipher flow as an unlock,
 * under a title that names the device being added, never "Unlock".
 */
class DeviceApprovalPromptTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun approvable(): Triple<FakeAppApi, TrustModel, DeviceLinkHost.Approvable> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.HOST_LINK_TYPE_DIGITS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        val typing = assertIs<DeviceLinkHost.TypeDigits>(assertNotNull(api.snapshot.account).deviceLink)
        m.run({ devices.submitDeviceDigits(typing, api.script.joiningDeviceCode) })
        return Triple(api, m, assertIs(assertNotNull(api.snapshot.account).deviceLink))
    }

    @Test
    fun theTitleNamesTheDeviceBeingAddedAndItsPlatform() {
        val (_, _, host) = approvable()
        val title = deviceApprovalReason(host)
        assertEquals("Add ${host.deviceName} (${host.platform.wireName})?", title)
        assertFalse(title.contains("Unlock"))
        assertEquals(title, AndroidKeyWrap.confirmTitle(title), "the key store's prompt says the reason it was given")
    }

    @Test
    fun withNoReasonThePromptStillSaysAnApprovalNeverAnUnlock() {
        for (r in listOf(null, "", "   ")) {
            val t = AndroidKeyWrap.confirmTitle(r)
            assertEquals(AndroidKeyWrap.CONFIRM_TITLE, t)
            assertFalse(t == AndroidKeyWrap.UNLOCK_TITLE || t.contains("Unlock"))
        }
    }

    @Test
    fun theConfirmationUsesTheUnlocksOneCipherFlowUnderItsOwnTitle() {
        val wrap = src("AndroidKeyWrap.kt")
        assertTrue(wrap.contains("override suspend fun open(slot: String, sealed: ByteArray, aad: ByteArray): KeyWrapOpen = openUnder(slot, sealed, aad, UNLOCK_TITLE)"))
        assertTrue(
            wrap.contains("override suspend fun openToConfirm(slot: String, sealed: ByteArray, aad: ByteArray, reason: String?): KeyWrapOpen =\n        openUnder(slot, sealed, aad, confirmTitle(reason))"),
            "the shared code's call is answered, not left to its default (which shows the unlock prompt)",
        )
        val flow = wrap.substringAfter("private suspend fun openUnder(").substringBefore("override fun destroy(")
        assertTrue(flow.contains("authenticate(a, cipher, title)"), "the prompt's title is the caller's")
        assertTrue(flow.contains("Cipher.DECRYPT_MODE") && flow.contains("auth.cipher.doFinal(parsed.second)"), "the same cipher opens the same sealed bytes")
        assertEquals(1, Regex("authenticate\\(a, cipher, UNLOCK_TITLE\\)").findAll(wrap).count() + Regex("authenticate\\(a, cipher, title\\)").findAll(wrap).count(), "one prompt for opening")
    }

    @Test
    fun theScreenOffersFingerprintOrFaceOnlyWhereOfferedAndPassesTheTitle() {
        val (api, m, host) = approvable()
        assertTrue(host.biometricsOffered, "the fake's account has quick unlock")
        m.runIn(DEVICE_LINK_SECTION, { devices.approveWithBiometrics(host, deviceApprovalReason(host)) }, { deviceLinkProofWords(it, 0) })
        assertIs<DeviceLinkHost.Approved>(assertNotNull(api.snapshot.account).deviceLink)

        val view = src("DevicesScreens.kt").substringAfter("is DeviceLinkHost.Approvable ->").substringBefore("is DeviceLinkHost.Approved ->")
        assertTrue(view.contains("if (host.biometricsOffered) {"))
        assertTrue(view.contains("devices.approveWithBiometrics(host, deviceApprovalReason(host))"))
        assertTrue(view.indexOf("approveWithPassword") < view.indexOf("approveWithBiometrics"), "the password stays the main way")
    }

    @Test
    fun aCancelledPromptLeavesTheApprovalOpenForThePassword() {
        val (api, m, host) = approvable()
        api.script.biometricsCancelled = true
        m.runIn(DEVICE_LINK_SECTION, { devices.approveWithBiometrics(host, deviceApprovalReason(host)) }, { deviceLinkProofWords(it, 0) })
        // A prompt the person cancelled is its own result: nothing was approved and nothing is wrong with the fingerprint
        // or face check, so the screen says that it was cancelled and the new device still waits.
        assertEquals(ProofResult.CANCELLED, assertNotNull(m.saidIn(api.snapshot, DEVICE_LINK_SECTION)).result)
        assertIs<DeviceLinkHost.Approvable>(assertNotNull(api.snapshot.account).deviceLink)
    }
}
