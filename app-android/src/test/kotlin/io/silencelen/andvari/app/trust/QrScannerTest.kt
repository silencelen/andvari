package io.silencelen.andvari.app.trust

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.datamatrix.DataMatrixWriter
import com.google.zxing.qrcode.QRCodeWriter
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.PayloadSource
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
 * The QR scanner without a camera: what it accepts and refuses, that its analyser keeps no frame, and that a scanned
 * payload and a pasted one reach the same state through the same intent (design §12.1 "three scanners, three jobs").
 */
class QrScannerTest {
    private val decoder = QrFrameDecoder()

    /** A camera-like brightness plane holding [m], with a white quiet zone and [pad] bytes of row padding. */
    private fun plane(m: BitMatrix, scale: Int = 4, quiet: Int = 32, pad: Int = 16): Triple<ByteArray, Int, Pair<Int, Int>> {
        val w = m.width * scale + 2 * quiet
        val h = m.height * scale + 2 * quiet
        val stride = w + pad
        val luma = ByteArray(stride * h) { 0xF0.toByte() }
        for (y in 0 until m.height * scale) for (x in 0 until m.width * scale) {
            if (m.get(x / scale, y / scale)) luma[(y + quiet) * stride + x + quiet] = 0x10
        }
        return Triple(luma, stride, w to h)
    }

    private fun qr(text: String): BitMatrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.MARGIN to 0))

    /** What the camera path hands on for [text]: encoded as a QR code, read back by the scanner's own decoder. */
    private fun scanned(text: String): String? {
        val (luma, stride, size) = plane(qr(text))
        return decoder.decodeAndWipe(luma, stride, size.first, size.second)
    }

    @Test
    fun theScannerAcceptsOneLineOfPlainTextAndRefusesTheRest() {
        assertEquals("https://andvaripass.com/l#abc", ScannedText.accept("  https://andvaripass.com/l#abc \n"))
        assertEquals("andvari-kit:2:x:c1:u:k2", ScannedText.accept("andvari-kit:2:x:c1:u:k2"))
        assertNull(ScannedText.accept(null))
        assertNull(ScannedText.accept(""))
        assertNull(ScannedText.accept("   "))
        assertNull(ScannedText.accept("https://andvaripass.com/l#a\nhttps://evil.example"), "a line break inside")
        assertNull(ScannedText.accept("https://andvaripass.com/l#a" + Char(0) + "b"), "a NUL")
        assertNull(ScannedText.accept("https://andvaripass.com/l#a" + Char(0x202E) + "b"), "a right-to-left override")
        assertNull(ScannedText.accept("https://andvaripass.com/l#a" + Char(0x200B) + "b"), "an invisible zero-width space")
        assertEquals(ScannedText.MAX_CHARS, ScannedText.accept("a".repeat(ScannedText.MAX_CHARS))?.length)
        assertNull(ScannedText.accept("a".repeat(ScannedText.MAX_CHARS + 1)), "longer than any payload the app makes")
    }

    @Test
    fun aQrCodeInACameraFrameIsReadAndTheFrameIsWiped() {
        val link = "https://andvaripass.com/l#k7Qm2-connect-Cy"
        val (luma, stride, size) = plane(qr(link))
        assertEquals(link, decoder.decodeAndWipe(luma, stride, size.first, size.second))
        assertTrue(luma.all { it == 0.toByte() }, "the analyser keeps no frame: the buffer is zeroed after the decode")
    }

    @Test
    fun aFrameWithNothingReadableOrNoQrCodeGivesNothingAndIsStillWiped() {
        val blank = ByteArray(320 * 240) { 0x7F }
        assertNull(decoder.decodeAndWipe(blank, 320, 320, 240))
        assertTrue(blank.all { it == 0.toByte() })

        val dm = DataMatrixWriter().encode("https://andvaripass.com/l#abc", BarcodeFormat.DATA_MATRIX, 0, 0)
        val (luma, stride, size) = plane(dm, scale = 6)
        assertNull(decoder.decodeAndWipe(luma, stride, size.first, size.second), "QR codes only")
        assertTrue(luma.all { it == 0.toByte() })

        val short = ByteArray(10) { 1 }
        assertNull(decoder.decodeAndWipe(short, 320, 320, 240), "a frame shorter than its size says")
        assertTrue(short.all { it == 0.toByte() })
    }

    @Test
    fun aQrCodeTheScannerRefusesIsNotHandedOn() {
        assertNull(scanned("a".repeat(ScannedText.MAX_CHARS + 1)))
        assertNull(scanned("https://andvaripass.com/l#a\nb"))
    }

    // ---- a scanned payload and a pasted payload reach the same state ----

    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
    }

    private data class Reached(val phase: Any?, val entry: Class<*>?, val opened: Class<*>?, val said: Any?, val words: String?)

    private fun reached(api: FakeAppApi, m: TrustModel): Reached {
        val s: AppSnapshot = api.snapshot
        val said = m.saidOn(s)
        return Reached(s.phase, s.entry?.javaClass, s.account?.opened?.javaClass, said?.result, said?.text?.shown())
    }

    /** Runs [scene] twice, once with [payload] pasted and once scanned through the decoder, and returns both ends. */
    private fun bothWays(
        scene: FakeScene,
        payload: (FakeAppApi) -> String,
        send: TrustModel.(FakeAppApi, String, PayloadSource) -> Unit,
    ): Pair<Reached, Reached> {
        val (pastedApi, pastedModel) = at(scene)
        pastedModel.send(pastedApi, payload(pastedApi), PayloadSource.PASTED)
        val (scannedApi, scannedModel) = at(scene)
        val text = assertNotNull(scanned(payload(scannedApi)), "the scanner reads the payload")
        scannedModel.send(scannedApi, text, PayloadSource.SCANNED)
        return reached(pastedApi, pastedModel) to reached(scannedApi, scannedModel)
    }

    @Test
    fun anInviteScannedOrPastedOnScanAnInviteReachesTheSameScreen() {
        val send: TrustModel.(FakeAppApi, String, PayloadSource) -> Unit = { api, text, source ->
            val screen = assertIs<EntryScreen.InviteEntry>(api.snapshot.entry)
            run({ entry.submitInvite(screen, text, source) })
        }
        val (pasted, scanned) = bothWays(FakeScene.INVITE_ENTRY, { it.script.invitation(it.script.publicInstance, "Cy") }, send)
        assertEquals(pasted, scanned)
        assertFalse(pasted.entry == EntryScreen.InviteEntry::class.java, "the invite opened the screen that follows")

        // A kit or a device link scanned here is refused exactly as when pasted (§17): same result, same sentence.
        val (kitPasted, kitScanned) = bothWays(FakeScene.INVITE_ENTRY, { it.script.kitOf(it.script.publicInstance.addAccount("bo@example.com", FakeScenes.PASSWORD)) }, send)
        assertEquals(InviteResult.KIT_NOT_AN_INVITE, kitScanned.said)
        assertEquals(kitPasted, kitScanned)
    }

    @Test
    fun aDeviceLinkScannedOrPastedOnLinkFromYourOtherDeviceReachesTheSameScreen() {
        val send: TrustModel.(FakeAppApi, String, PayloadSource) -> Unit = { api, text, source ->
            val screen = assertIs<EntryScreen.LinkDeviceEntry>(api.snapshot.entry)
            run({ entry.submitDeviceLink(screen, text, source) })
        }
        val link = { api: FakeAppApi -> api.script.deviceLinkFrom(api.script.publicInstance.addAccount("bo@example.com", FakeScenes.PASSWORD), "Laptop") }
        val (pasted, scanned) = bothWays(FakeScene.LINK_DEVICE_ENTRY, link, send)
        assertEquals(pasted, scanned)
        assertFalse(pasted.entry == EntryScreen.LinkDeviceEntry::class.java, "the link was claimed")

        val (invPasted, invScanned) = bothWays(FakeScene.LINK_DEVICE_ENTRY, { it.script.connectInvite(it.script.publicInstance, "Cy") }, send)
        assertEquals(DeviceLinkScanResult.NOT_A_DEVICE_LINK, invScanned.said)
        assertEquals(invPasted, invScanned)
    }

    @Test
    fun aKitScannedOrPastedOnScanYourRecoveryKitReachesTheSameScreen() {
        val send: TrustModel.(FakeAppApi, String, PayloadSource) -> Unit = { api, text, source ->
            val screen = assertIs<EntryScreen.KitEntry>(api.snapshot.entry)
            run({ entry.submitKit(screen, text, source) })
        }
        val (pasted, scanned) = bothWays(FakeScene.KIT_ENTRY, { it.script.kitOf(it.script.publicInstance.addAccount("bo@example.com", FakeScenes.PASSWORD)) }, send)
        assertEquals(EntryScreen.KitRecover::class.java, scanned.entry)
        assertEquals(pasted, scanned)

        val (linkPasted, linkScanned) = bothWays(FakeScene.KIT_ENTRY, { it.script.connectInvite(it.script.publicInstance, "Cy") }, send)
        assertEquals(KitScanResult.NOT_A_KIT, linkScanned.said)
        assertEquals(linkPasted, linkScanned)
    }

    @Test
    fun aLinkScannedOrPastedOnTheLinksPageOpensTheSameLinkAndNothingMore() {
        val send: TrustModel.(FakeAppApi, String, PayloadSource) -> Unit = { _, text, source -> run({ links.openInvite(text, source) }) }
        val (pasted, scanned) = bothWays(FakeScene.LINKS, { it.script.connectInvite(it.script.publicInstance, "Cy") }, send)
        assertEquals(pasted, scanned)
        assertNotNull(scanned.opened, "the opened link is on show; nothing is accepted until the person answers it")
    }

    // ---- the call sites and the component, pinned by source ----

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun scanLine(code: String, fn: String): String =
        code.substringAfter("fun $fn(").substringBefore("\n@Composable").lines().single { it.contains("ScanQrControl(") }

    @Test
    fun eachScannerHandsItsTextToItsOwnEntrysIntentOnlyAsScanned() {
        val entry = src("EntryScreens.kt")
        val invite = entry.substringAfter("fun InviteEntryScreen(").substringBefore("// ---- \"Use your own server\"")
        assertTrue(invite.contains("send(it, PayloadSource.SCANNED)") && invite.contains("send(link, PayloadSource.PASTED)"))
        assertTrue(invite.contains("val send = { text: String, source: PayloadSource -> model.run({ entry.submitInvite(screen, text, source) }) }"))

        val linkAndKit = src("LinkAndRecoveryScreens.kt")
        val device = linkAndKit.substringAfter("fun LinkDeviceEntryScreen(").substringBefore("\n@Composable")
        assertTrue(device.contains("send(it, PayloadSource.SCANNED)") && device.contains("send(link, PayloadSource.PASTED)"))
        assertTrue(device.contains("model.run({ entry.submitDeviceLink(screen, text, source) })"))
        assertEquals(
            "ScanQrControl(enabled = !s.busy) { model.run({ entry.submitKit(screen, it, PayloadSource.SCANNED) }) }",
            scanLine(linkAndKit, "KitEntryScreen").trim(),
        )
        assertEquals(
            "ScanQrControl(enabled = !s.busy) { model.run({ links.openInvite(it, PayloadSource.SCANNED) }) }",
            scanLine(src("LinksScreens.kt"), "LinksSection").trim(),
        )
    }

    @Test
    fun theScannerActsOnNothingKeepsNoPictureAndAsksForTheCameraOnlyWhenOpened() {
        val code = src("QrScanner.kt").lines().filterNot { it.trimStart().startsWith("//") || it.trimStart().startsWith("*") }.joinToString("\n")
        for (call in listOf("entry.", "links.", "model.", "api.")) assertFalse(code.contains(call), "the scanner calls no intent: $call")
        for (write in listOf("ImageCapture", "takePicture", "FileOutputStream", "openFileOutput", "File(", "compress(", "MediaStore")) {
            assertFalse(code.contains(write), "nothing is written: $write")
        }
        assertFalse(code.contains("LaunchedEffect"), "no permission request on show")
        val control = code.substringAfter("fun ScanQrControl(").substringBefore("\n@Composable")
        val launch = control.indexOf("askCamera.launch(Manifest.permission.CAMERA)")
        assertTrue(launch > control.indexOf("Second(UiText.ph(Placeholder.SCAN_OPEN)"), "asked from the button that opens the scanner")
        assertTrue(control.contains("Placeholder.SCAN_NOT_ALLOWED"), "a refusal says the field is the way in")
        assertTrue(control.contains("FEATURE_CAMERA_ANY"), "a phone without a camera gets the field only")
    }

    @Test
    fun theManifestAsksForTheCameraButDoesNotRequireOne() {
        val manifest = File("src/main/AndroidManifest.xml").readText()
        assertTrue(manifest.contains("<uses-permission android:name=\"android.permission.CAMERA\" />"))
        assertTrue(manifest.contains("<uses-feature android:name=\"android.hardware.camera.any\" android:required=\"false\" />"))
        assertTrue(manifest.contains("<uses-feature android:name=\"android.hardware.camera\" android:required=\"false\" />"))
    }
}
