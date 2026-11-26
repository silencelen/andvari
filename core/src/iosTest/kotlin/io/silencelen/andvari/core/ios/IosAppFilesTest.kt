package io.silencelen.andvari.core.ios

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Item 3 of the iPhone's move: the byte calls Swift makes, over the phone fake (no keys, no network). WRITTEN ON LINUX,
 * NEVER RUN. The bridge's own `AndvariBridgeApp.app()` is not called here: in a test process it would build the
 * shipping layout in the simulator's Application Support, and with no protected data to read it answers null anyway.
 */
class IosAppFilesTest {
    private fun chars(s: String) = s.toCharArray()

    private fun zeroed(a: CharArray) = a.all { it == '\u0000' }

    @Test
    fun lockedEverythingAnswersNothingAndThePassphraseIsWipedAnyway() = runBlocking<Unit> {
        val files = IosAppFiles(FakeScenes.at(FakeScene.FIRST_RUN))
        val p = chars("correct horse battery staple")
        val c = chars("correct horse battery staple")
        assertNull(files.exportBackupData(p, c))
        assertTrue(zeroed(p) && zeroed(c), "both arrays are zeroed though no content was open")
        assertIs<ActionResult.NotDone>(files.importCsvData(byteArrayOf(1, 2).toNSData()))
        assertIs<ActionResult.NotDone>(files.addAttachmentData("a.txt", byteArrayOf(1).toNSData()))
        assertNull(files.exportCsvData(true))
        val none = files.openAttachment("i", "a")
        assertNull(none.data)
        assertNull(none.error)
    }

    @Test
    fun unlockedTheCallsReachTheContentOfTheMoment() = runBlocking<Unit> {
        val app = FakeScenes.at(FakeScene.VAULTS)
        val files = IosAppFiles(app)
        val content = assertNotNull(app.content)
        assertIs<ActionResult.NotDone>(files.addAttachmentData("a.txt", byteArrayOf(1, 2, 3).toNSData()), "no editor open")
        content.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, files.addAttachmentData("a.txt", byteArrayOf(1, 2, 3).toNSData()))
        content.closeAttachmentDraft()
        val p = chars("one passphrase")
        val c = chars("another one")
        assertNull(files.exportBackupData(p, c), "two different passphrases make no backup")
        assertTrue(zeroed(p) && zeroed(c))
    }

    @Test
    fun aScanThatIsNotJpegMakesNoPdf() {
        val files = IosAppFiles(FakeScenes.at(FakeScene.FIRST_RUN))
        assertNull(files.scannedPdf(listOf(byteArrayOf(1, 2, 3).toNSData())))
    }
}
