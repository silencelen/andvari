package io.silencelen.andvari.app

import io.silencelen.andvari.app.autofill.ApprovedBrowsers
import io.silencelen.andvari.app.autofill.TrustedBrowsers
import io.silencelen.andvari.app.trust.BytesFile
import io.silencelen.andvari.app.trust.KeyGone
import io.silencelen.andvari.app.trust.Placeholder
import io.silencelen.andvari.app.trust.SealedStateFile
import io.silencelen.andvari.app.trust.Sealer
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.autofill.BrowserCertPins
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Smaller points of the Android app:
 * 1. a browser is trusted by its current signer, and an approval given to one signer does not cover another that only
 *    appears in the signing history (after a key rotation the person is asked again);
 * 2. a kept session that cannot be opened is "unknown", never "no session", and what was set aside is read back when
 *    the key store answers again;
 * 3. the main activity gets an empty task affinity.
 */
class SignerSessionAndTaskAffinityTest {
    // ---- 1. the current signer ----

    private val brave = "com.brave.browser" // a known browser with no pin: trusted only by an approval on this device
    private val old = "OLD-KEY-DIGEST"
    private val new = "NEW-KEY-DIGEST"

    private fun trusted(pkg: String, history: List<String>, approved: String?): Boolean =
        TrustedBrowsers.decide(pkg, TrustedBrowsers.currentSigners(false, emptyList(), history), approved)

    @Test
    fun anApprovalCoversOnlyTheSignerThatSignsTheBrowserNow() {
        assertTrue(BrowserCertPins.TABLE[brave]!!.isEmpty(), "the case needs a browser with no pin")
        // The review's case: approved before a key rotation; the history now lists the old key first, the new one last.
        assertFalse(trusted(brave, listOf(old, new), approved = old), "an approval of the retired key does not cover the new one")
        assertEquals(new, TrustedBrowsers.observedDigestOf(TrustedBrowsers.currentSigners(false, emptyList(), listOf(old, new))), "the card shows, and approves, the current signer")
        assertEquals(ApprovedBrowsers.Offer.SIGNER_CHANGED, ApprovedBrowsers.offer(brave, new, old), "the person is asked again, with the changed-signer warning")
        // Once approved again, the current signer is trusted; an APK signed with the retired key alone is not.
        assertTrue(trusted(brave, listOf(old, new), approved = new))
        assertFalse(trusted(brave, listOf(old), approved = new))
        // An app signed by several keys at once: its content signers, all of them.
        assertEquals(listOf("a", "b"), TrustedBrowsers.currentSigners(true, listOf("a", "b"), listOf("x")))
        // The pin table is read against the current signer too.
        val chrome = "com.android.chrome"
        val pin = BrowserCertPins.TABLE[chrome]!!.first()
        assertTrue(trusted(chrome, listOf(pin), approved = null))
        assertFalse(trusted(chrome, listOf(pin, "SOMEONE-ELSE"), approved = null), "a pin met only in the history is not the signer now")
        // The live check reads the signing info through currentSigners.
        val src = File("src/main/kotlin/io/silencelen/andvari/app/autofill/TrustedBrowsers.kt").readText()
        assertTrue(src.contains("currentSigners(si.hasMultipleSigners(), si.apkContentsSigners?.toList().orEmpty(), si.signingCertificateHistory?.toList().orEmpty())"))
    }

    // ---- 2. the kept session ----

    private class MemFile : BytesFile {
        var bytes: ByteArray? = null
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(bytes: ByteArray) { this.bytes = bytes.copyOf() }
        override fun delete() { bytes = null }
        override val exists: Boolean get() = bytes != null
    }

    /** A key store that may be busy for a few calls, not answer at all, or have lost its key for good. */
    private class FakeKeyStore : Sealer {
        var busyFor = 0
        var answering = true
        var gone = false
        var opens = 0
        override fun seal(plain: ByteArray): ByteArray = "sealed:".encodeToByteArray() + plain
        override fun open(sealed: ByteArray): ByteArray {
            opens++
            if (gone) throw KeyGone()
            if (busyFor > 0) { busyFor--; throw IllegalStateException("key store busy") }
            if (!answering) throw IllegalStateException("key store not answering")
            return sealed.copyOfRange(7, sealed.size)
        }
    }

    private val session = """{"ovh.session":"the-kept-session"}"""

    @Test
    fun aKeyStoreThatIsBusyIsAskedAgainBeforeItsRefusalIsTaken() {
        val main = MemFile(); val aside = MemFile(); val ks = FakeKeyStore()
        val file = SealedStateFile(main, aside, ks, tries = 3)
        file.replace(session)
        ks.busyFor = 2
        assertEquals(session, file.read(), "two busy answers, then the session")
        assertFalse(file.unreadable, "nothing set aside")
        assertEquals(3, ks.opens)
    }

    @Test
    fun whatWasSetAsideIsReadBackWhenTheKeyStoreAnswersAgain() {
        val main = MemFile(); val aside = MemFile(); val ks = FakeKeyStore()
        val file = SealedStateFile(main, aside, ks, tries = 3)
        file.replace(session)
        // The key store does not answer at this start: core is handed nothing (it cannot yet take "unknown"), the copy waits.
        ks.answering = false
        assertNull(file.read())
        assertTrue(file.unreadable, "the first screen says the saved sign-in can't be read now")
        val setAside = assertNotNull(aside.bytes)
        // Core writes a record meanwhile (it saw no file); the live file is replaced, the copy set aside is untouched.
        file.replace("""{"ovh.other":"written-since"}""")
        assertTrue(setAside.contentEquals(aside.bytes!!))
        // The next start, the key store answers: the session is read back, under what was written since.
        ks.answering = true
        val back = assertNotNull(file.read())
        assertTrue(back.contains("\"ovh.session\":\"the-kept-session\"") && back.contains("\"ovh.other\":\"written-since\""), back)
        assertFalse(file.unreadable, "read back: nothing is set aside any more")
        assertEquals(back, file.read(), "and it is in the live file now")
        // Through core's own reader, as the engine reads it.
        assertEquals("the-kept-session", JsonDeviceState(file).get("ovh.session"))
    }

    @Test
    fun aRecordWrittenSinceWinsAndAKeyGoneForGoodIsNotAskedAgain() {
        val main = MemFile(); val aside = MemFile(); val ks = FakeKeyStore()
        val file = SealedStateFile(main, aside, ks, tries = 3)
        file.replace("""{"ovh.session":"old","ovh.request":"r1"}""")
        ks.gone = true
        assertNull(file.read())
        assertEquals(1, ks.opens, "a key that is gone is not asked again")
        assertTrue(file.unreadable)
        // Still gone at the next start: still kept, never written over by what is read.
        assertNull(file.read())
        assertTrue(file.unreadable)
        ks.gone = false
        file.replace("""{"ovh.request":"r2"}""")
        val back = assertNotNull(file.read())
        assertTrue(back.contains("\"ovh.session\":\"old\"") && back.contains("\"ovh.request\":\"r2\"") && !back.contains("r1"), back)
    }

    @Test
    fun aNewSessionEndsTheCopySetAside() {
        val main = MemFile(); val aside = MemFile(); val ks = FakeKeyStore()
        val file = SealedStateFile(main, aside, ks, tries = 3)
        file.replace(session)
        ks.answering = false
        assertNull(file.read())
        ks.answering = true
        file.replace("""{"ovh.session":"signed-in-again"}""")
        file.newSessionWritten() // the person signed in again, and the new session opened
        assertFalse(file.unreadable)
        assertEquals("""{"ovh.session":"signed-in-again"}""", file.read())
    }

    @Test
    fun theFirstScreenSaysUnknownNotNoSessionAndOpeningNeverMakesAKey() {
        val gloss = Placeholder.SAVED_SIGN_IN_UNREADABLE.gloss
        assertTrue(gloss.contains("right now") && gloss.contains("kept"), gloss)
        val seam = File("src/main/kotlin/io/silencelen/andvari/app/trust/TrustSeam.kt").readText()
        val open = seam.substringAfter("override fun open(sealed: ByteArray): ByteArray {").substringBefore("private const val KEYSTORE")
        assertTrue(open.contains("existingKey()"))
        assertFalse(Regex("(?<![A-Za-z])key\\(\\)").containsMatchIn(open), "opening never makes a key (only seal calls key())")
        assertTrue(seam.contains("KeystoreSealedFile private constructor(private val inner: SealedStateFile)"))
    }

    // ---- 3. the task affinity ----

    @Test
    fun theMainActivityHasAnEmptyTaskAffinity() {
        val manifest = File("src/main/AndroidManifest.xml").readText()
        val main = manifest.substringAfter("android:name=\"io.silencelen.andvari.app.MainActivity\"").substringBefore(">")
        assertTrue(main.contains("android:taskAffinity=\"\""), main)
        assertTrue(main.contains("android:launchMode=\"singleTask\""))
    }
}
