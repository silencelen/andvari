package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.app.trust.AndroidSaveQueue
import io.silencelen.andvari.app.trust.BuildConstants
import io.silencelen.andvari.app.trust.TrustModel
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.io.IOException
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * "Save to andvari?" on the new code. A capture is sealed to the account's published key and
 * queued in the content's save queue on disk; its site follows the fill's rule; nothing is queued while the session
 * takes no saves; the old confirm is never launched.
 */
class AutofillSaveTest {
    private val base = Files.createTempDirectory("andvari-l5-8-save").toFile()
    private val crypto = createCryptoProvider()
    private val keys = crypto.boxKeypairFromSeed(ByteArray(32) { 9 })

    /** A signed-in session that takes saves (a key not published there is a plain "not saved", never the policy's). */
    private val signedIn = AutofillSave.SaveSession(null, AutofillSave.Outcome.REFUSED)

    @AfterTest
    fun cleanup() {
        base.deleteRecursively()
    }

    private fun queue(published: Boolean = true): AndroidSaveQueue = AndroidSaveQueue(File(base, "save-queue")).also { q ->
        if (published) {
            val pub = """{"v":1,"origin":"https://vault.example.com","userId":"u-1","identityPub":"${Bytes.toB64(keys.publicKey)}"}"""
            q.publish(pub.encodeToByteArray())
        }
    }

    /** The one entry's inside, opened with the account's key (as the content opens it). */
    private fun opened(q: AndroidSaveQueue): String {
        val entry = q.entries().values.single().decodeToString()
        val sealed = assertNotNull(Regex("\"sealed\":\"([^\"]+)\"").find(entry)).groupValues[1]
        return crypto.sealOpen(keys.publicKey, keys.privateKey, Bytes.fromB64(sealed)).decodeToString()
    }

    private fun creds(pkg: String, domain: String?, password: String? = "hunter2-secret", scheme: String? = null) =
        SavedCredentials(username = "me@example.com", password = password, webDomain = domain, appPackage = pkg, webScheme = scheme)

    @Test
    fun aCaptureIsSealedNotPlaintextAndNamedByItsApp() {
        val q = queue()
        assertEquals(AutofillSave.Outcome.QUEUED, AutofillSave.capture(q, crypto, creds("com.example.app", null), false, signedIn, 1_000L))
        val raw = q.entries().values.single().decodeToString()
        assertFalse(raw.contains("hunter2-secret"), "the entry on disk holds no plaintext password")
        assertFalse(raw.contains("me@example.com"), "nor the user name")
        val inside = opened(q)
        assertTrue(inside.contains("\"site\":\"androidapp://com.example.app\""), inside)
        assertTrue(inside.contains("\"password\":\"hunter2-secret\""))
        assertTrue(inside.contains("\"source\":\"autofill\""))
    }

    @Test
    fun anUntrustedCallersDomainIsLaunderedAndATrustedBrowsersIsKept() {
        val app = queue()
        val claimed = launderUntrustedCapture(creds("com.evil.app", "bank.example").copy(webPage = true), trusted = false)
        assertEquals(null, claimed.webDomain, "an app's claim never names the capture")
        assertTrue(claimed.webPage, "the page's mark survives the launder")
        // A web page inside an app is not the app's own login; nothing is queued.
        assertEquals(AutofillSave.Outcome.REFUSED, AutofillSave.capture(app, crypto, claimed, false, signedIn, 1_000L))
        assertTrue(app.entries().isEmpty())

        base.resolve("save-queue").deleteRecursively()
        val browser = queue()
        val trusted = launderUntrustedCapture(creds("com.android.chrome", "bank.example", scheme = "https"), trusted = true)
        assertEquals(AutofillSave.Outcome.QUEUED, AutofillSave.capture(browser, crypto, trusted, true, signedIn, 1_000L))
        assertTrue(opened(browser).contains("\"site\":\"https://bank.example\""))
    }

    /** The site is made by the content's own helpers, and the content's own call queues it. */
    @Test
    fun theSiteIsTheContentsOwnAppSiteOrWebSite() {
        // A verified browser's domain, with the scheme it reported; none reported is the domain alone (asked first).
        assertEquals("https://bank.example", AutofillSave.captureSite(creds("com.android.chrome", "bank.example", scheme = "https"), true))
        assertEquals("http://router.lan", AutofillSave.captureSite(creds("com.android.chrome", "router.lan", scheme = "http"), true))
        assertEquals("bank.example", AutofillSave.captureSite(creds("com.android.chrome", "bank.example"), true))
        assertEquals(null, AutofillSave.captureSite(creds("com.android.chrome", "bank.example", scheme = "ftp"), true), "a scheme that is neither")
        // A domain from anything but a verified browser never names the capture, even unlaundered: since clients
        // now such a capture is refused outright; an app's own native fields are its own site.
        assertEquals(null, AutofillSave.captureSite(creds("com.evil.app", "bank.example"), false))
        assertEquals("androidapp://com.evil.app", AutofillSave.captureSite(creds("com.evil.app", null), false))
        // Never a browser's own package as an app: verified or a known browser, with no trusted domain.
        assertEquals(null, AutofillSave.captureSite(creds("com.android.chrome", null), true))
        assertEquals(null, AutofillSave.captureSite(creds("com.android.chrome", "bank.example"), false))
        assertEquals(null, AutofillSave.captureSite(creds("com.example.browser", null), true), "a browser trusted on this device")
        // A name that is no package is refused by the content's helper.
        assertEquals(null, AutofillSave.captureSite(creds("not a package", null), false))

        val svc = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AutofillSave.kt").readText()
        assertTrue(svc.contains("ContentCapture.queue(queue, crypto, site, creds.username.orEmpty(), password, nowMs)"))
        assertFalse(svc.contains("SaveQueue.enqueue("), "the service no longer calls the queue itself")
        val service = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AndvariAutofillService.kt").readText()
        assertTrue(service.contains("val creds = launderUntrustedCapture(raw, verifiedBrowser)"))
        assertTrue(service.contains("creds, verifiedBrowser, AutofillSave.session(this)"))

        // A bare domain is queued (the content asks the person before it saves it).
        val q = queue()
        assertEquals(AutofillSave.Outcome.QUEUED, AutofillSave.capture(q, crypto, creds("com.android.chrome", "bank.example"), true, signedIn, 1_000L))
        assertTrue(opened(q).contains("\"site\":\"bank.example\""))
    }

    @Test
    fun aBrowserCaptureWithNoTrustedDomainIsRefusedNeverQueuedAsTheBrowser() {
        val q = queue()
        val untrusted = launderUntrustedCapture(creds("com.android.chrome", "bank.example"), trusted = false)
        assertEquals(AutofillSave.Outcome.REFUSED, AutofillSave.capture(q, crypto, untrusted, false, signedIn, 1_000L))
        assertEquals(AutofillSave.Outcome.REFUSED, AutofillSave.capture(q, crypto, creds("com.android.chrome", null), true, signedIn, 1_000L))
        assertEquals(AutofillSave.Outcome.REFUSED, AutofillSave.capture(q, crypto, creds("com.example.app", null, password = ""), false, signedIn, 1_000L))
        assertTrue(q.entries().isEmpty())
    }

    @Test
    fun nothingIsQueuedWhenTheSessionTakesNoSavesOrNoKeyIsPublished() {
        val q = queue()
        val notNow = AutofillSave.SaveSession(AutofillSave.Outcome.NOT_NOW, AutofillSave.Outcome.NOT_NOW)
        assertEquals(AutofillSave.Outcome.NOT_NOW, AutofillSave.capture(q, crypto, creds("com.example.app", null), false, notNow, 1_000L))
        assertTrue(q.entries().isEmpty())
        val none = AndroidSaveQueue(File(base, "unpublished"))
        assertEquals(AutofillSave.Outcome.REFUSED, AutofillSave.capture(none, crypto, creds("com.example.app", null), false, signedIn, 1_000L))
    }

    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
    }

    @Suppress("UNUSED_PARAMETER")
    private fun takes(api: FakeAppApi, m: TrustModel) = AutofillSave.sessionTakesSaves(api.snapshot)

    @Test
    fun theSessionTakesSavesOnlyWhileItsServerStillServesIt() {
        val (signedOut, so) = at(FakeScene.FIRST_RUN)
        assertFalse(takes(signedOut, so), "signed out")

        val (api, m) = at(FakeScene.LOCKED)
        assertTrue(takes(api, m), "an ordinary lock screen: the content reads the queue at unlock")
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertTrue(takes(api, m), "an open vault")

        // The server ends the session: neither its lock screen nor the copy it opens takes a save.
        api.script.sessionEndedByServer()
        m.onSnapshot(api.snapshot)
        assertFalse(takes(api, m), "a lock screen the server signed out")
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertTrue(m.openedSignedOutByServer())
        assertFalse(takes(api, m), "the copy the server signed out, open read-only")
    }

    @Test
    fun aStoppedServerTakesNoSave() {
        val (api, m) = at(FakeScene.LOCKED)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        api.script.cardForked()
        m.onSnapshot(api.snapshot)
        assertFalse(takes(api, m))
    }

    @Test
    fun theDiskQueueNeverReplacesAnEntryAndThrowsWhenUnreadable() {
        val q = queue()
        assertTrue(q.add("s-1", byteArrayOf(1)))
        assertFalse(q.add("s-1", byteArrayOf(2)), "a taken id is refused")
        assertContentEquals(byteArrayOf(1), q.entries()["s-1"])
        assertFalse(q.add("../escape", byteArrayOf(3)), "an id that is not core's shape is refused")
        assertEquals(setOf("s-1"), q.entries().keys)

        val broken = File(base, "broken").also { it.mkdirs() }
        File(broken, "entries").writeText("not a directory")
        // The strict reader throws (the content reads through it); the plain one keeps its promise.
        assertFailsWith<IOException> { AndroidSaveQueue(broken).entriesOrThrow() }
        assertTrue(AndroidSaveQueue(broken).entries().isEmpty(), "the old reader never throws")
        assertTrue(AndroidSaveQueue(File(base, "empty")).entries().isEmpty(), "absent is empty")
        assertTrue(AndroidSaveQueue(File(base, "empty")).entriesOrThrow().isEmpty(), "absent is empty on the strict reader too")

        // A listed entry that is there and cannot be read (a directory in its place) holds the strict queue as unknown;
        // the plain reader leaves it out.
        File(base, "save-queue/entries/s-2").mkdirs()
        assertFailsWith<IOException> { q.entriesOrThrow() }
        assertEquals(setOf("s-1"), q.entries().keys)
    }

    @Test
    fun theOldConfirmIsNeverLaunched() {
        val svc = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AndvariAutofillService.kt").readText()
        val save = svc.substringAfter("override fun onSaveRequest(").substringBefore("private companion object")
        assertFalse(save.contains("SaveConfirmActivity"))
        assertFalse(save.contains("PendingIntent"))
        assertTrue(save.contains("AutofillSave.capture("))
        assertTrue(OLD_SAVE_CONFIRM_RETIRED)
    }
}
