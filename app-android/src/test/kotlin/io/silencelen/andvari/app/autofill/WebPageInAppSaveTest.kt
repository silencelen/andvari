package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.app.trust.AndroidSaveQueue
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * In an app that is not a verified browser, a login typed on a web page inside the app
 * (its fields carry a web domain, or are HTML fields) is offered no save, nothing is queued, and so nothing can replace
 * the app's own stored login. The reviewer's path: the app's login is saved with the person's email; a sign-in page
 * opens in the app's in-app browser; the same email and another password are typed and submitted. Before the fix the
 * capture was filed under `androidapp://com.social.app` and core replaced the app's password by itself at the next
 * unlock. Autofill's only way into the vault is the save queue, so an empty queue leaves the stored password as it was.
 */
class WebPageInAppSaveTest {
    private val base = Files.createTempDirectory("andvari-l5-10-a2").toFile()
    private val crypto = createCryptoProvider()
    private val keys = crypto.boxKeypairFromSeed(ByteArray(32) { 9 })

    @AfterTest
    fun cleanup() {
        base.deleteRecursively()
    }

    private fun queue(): AndroidSaveQueue = AndroidSaveQueue(File(base, "save-queue")).also { q ->
        q.publish("""{"v":1,"origin":"https://vault.example.com","userId":"u-1","identityPub":"${Bytes.toB64(keys.publicKey)}"}""".encodeToByteArray())
    }

    /** What the extractor gives for the in-app browser's page: the page's domain on the fields, HTML fields. */
    private fun typedOnThePage(domain: String?) = SavedCredentials(
        username = "me@example.com", password = "typed-on-the-evil-page", webDomain = domain, appPackage = "com.social.app", webPage = true,
    )

    @Test
    fun aLoginTypedOnAPageInsideAnAppIsNeverQueuedAsTheAppsLogin() {
        val q = queue()
        // The service's path: the app is not a verified browser, so the capture is laundered, then captured.
        for (raw in listOf(typedOnThePage("evil.example"), typedOnThePage(null))) {
            val creds = launderUntrustedCapture(raw, trusted = false)
            assertNull(AutofillSave.captureSite(creds, verifiedBrowser = false), "never androidapp://com.social.app")
            assertEquals(AutofillSave.Outcome.REFUSED, AutofillSave.capture(q, crypto, creds, false, AutofillSave.SaveSession(null, AutofillSave.Outcome.REFUSED), 1_000L))
        }
        assertTrue(q.entries().isEmpty(), "nothing queued: the app's stored password cannot be replaced")

        // The app's own native sign-in screen still saves as the app's login.
        val native = SavedCredentials("me@example.com", "the-real-app-password", null, "com.social.app")
        assertEquals(AutofillSave.Outcome.QUEUED, AutofillSave.capture(q, crypto, native, false, AutofillSave.SaveSession(null, AutofillSave.Outcome.REFUSED), 1_000L))
        assertEquals(1, q.entries().size)
    }

    @Test
    fun noSaveIsOfferedOnAPageInsideAnAppButAVerifiedBrowsersPageStillIs() {
        assertFalse(DatasetBuilder.offersSave("com.social.app", trusted = false, sessionTakes = true, webPage = true))
        assertTrue(DatasetBuilder.offersSave("com.social.app", trusted = false, sessionTakes = true, webPage = false))
        assertTrue(DatasetBuilder.offersSave("com.android.chrome", trusted = true, sessionTakes = true, webPage = true))
        val form = FormOf(listOf(FieldOf(1, io.silencelen.andvari.core.client.autofill.FieldKind.PASSWORD, "evil.example")), "com.social.app")
        assertTrue(DatasetBuilder.isWebPage(form))
        assertFalse(DatasetBuilder.isWebPage(FormOf(listOf(FieldOf(1, io.silencelen.andvari.core.client.autofill.FieldKind.PASSWORD, null)), "com.social.app")))
    }

    @Test
    fun theExtractorMarksAPagesFieldsAndTheLaunderKeepsTheMark() {
        val src = File("src/main/kotlin/io/silencelen/andvari/app/autofill/SaveExtractor.kt").readText()
        assertTrue(src.contains("StructureParser.isNewPassword(node), node.htmlInfo != null)"), "an HTML field is marked")
        assertTrue(src.contains("val webPage = nodes.any { it.value != null && (it.domain != null || it.html) }"))
        val laundered = launderUntrustedCapture(typedOnThePage("evil.example"), trusted = false)
        assertNull(laundered.webDomain)
        assertTrue(laundered.webPage)
    }
}
