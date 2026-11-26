package io.silencelen.andvari.app

import io.silencelen.andvari.app.trust.AutofillRecords
import io.silencelen.andvari.app.trust.BuildConstants
import io.silencelen.andvari.app.trust.ScannedText
import io.silencelen.andvari.app.trust.TrustModel
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The fill log's and the trust records' stores, the launch link, the scanner's text and smaller Android points. */
class StoresLaunchLinkAndScannerTest {
    private fun src(path: String) = File("src/main/kotlin/io/silencelen/andvari/app/$path").readText()
    private fun code(path: String) = src(path).replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "").lines().joinToString("\n") { it.substringBefore("//") }

    @Test
    fun theOldSessionStoreIsNotConstructedByTheFillLogOrASave() {
        assertFalse(code("autofill/AutofillDebugLog.kt").contains("SessionStore("), "the fill log's armed check")
        val save = code("autofill/SaveConfirmActivity.kt")
        val guard = save.indexOf("if (OLD_SAVE_CONFIRM_RETIRED) { finish(); return }")
        assertTrue(guard in 0 until save.indexOf("SessionStore("), "a save attempt is refused before the old store")
    }

    @Test
    fun theFillLogAndTheTrustRecordsDoNotTravel() {
        val rules = File("src/main/res/xml/data_extraction_rules.xml").readText()
        val backup = File("src/main/res/xml/backup_rules.xml").readText()
        for (exclude in listOf(
            "domain=\"file\" path=\"autofill-last.json\"",
            "domain=\"file\" path=\"autofill-log.jsonl\"",
            "domain=\"sharedpref\" path=\"andvari_trusted_browsers.xml\"",
            "domain=\"sharedpref\" path=\"andvari_autofill_owner.xml\"",
        )) {
            assertEquals(2, Regex(Regex.escape(exclude)).findAll(rules).count(), "cloud backup and device transfer: $exclude")
            assertTrue(backup.contains(exclude), "old auto backup: $exclude")
        }
    }

    private class Records(var kept: String? = null) : AutofillRecords {
        var cleared = 0
        override fun clear() { cleared++; kept = null }
        override fun forgetFills() = Unit
        override fun owner(): String? = kept
        override fun setOwner(accountId: String) { kept = accountId }
    }

    @Test
    fun rememberedAppsAndTrustedBrowsersEndWithThePersonsOwnActs() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val records = Records(kept = "someone-else")
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }, autofillRecords = records)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        val me = assertNotNull(api.snapshot.account).accountId
        assertEquals(1, records.cleared, "another account opening here clears them")
        assertEquals(me, records.kept)
        m.onSnapshot(api.snapshot)
        assertEquals(1, records.cleared, "the same account again does not")
        m.personEnded(PlainResult.FAILED)
        assertEquals(1, records.cleared, "a failed act deletes nothing")
        m.personEnded(PlainResult.DONE)
        assertEquals(2, records.cleared, "a sign-out or a forgotten server")
        m.personEnded(DeletionResult.DONE)
        assertEquals(3, records.cleared, "an account deletion")
        // Wired at the person's acts (sign-out, "Forget this server" on every card and in Settings through the one
        // ForgetServerButton, account deletion), not at a session the server ended.
        val wired = listOf("trust/AccountScreens.kt", "trust/EntryScreens.kt").sumOf { Regex("personEnded").findAll(code(it)).count() }
        assertEquals(1, wired, "Forget this server")
        // The deletion's answer goes through the model, which ends the records on DONE, as does every
        // sign-out (Settings, the lock screen, the kept account from the journey), through the one confirmation.
        assertTrue(code("trust/SettingsScreens.kt").contains("model.deletionAnswered(it)"))
        val model = code("trust/TrustModel.kt")
        assertTrue(model.contains("fun deletionAnswered(r: io.silencelen.andvari.core.app.DeletionResult) {") && model.contains("        personEnded(r)\n"))
        assertTrue(model.contains("fun signOutAsk(): SignOutAsk = SignOutAsk(this, { signOut() }, { signOutConfirmed(it) }) { personEnded(it) }"))
        assertTrue(code("trust/AccountScreens.kt").contains("model.signOutAsk()") && code("trust/KeptAccountScreens.kt").contains("model.signOutAsk()"))
        assertTrue(code("trust/EntryScreens.kt").contains("model.run({ this.instance.forgetServer(instance) }, model::personEnded)"))
        assertTrue(code("trust/AccountScreens.kt").contains("ForgetServerButton(model, s, instance, quiet = true)"))
    }

    @Test
    fun theLaunchLinkIsTakenOnce() {
        val link = "https://andvaripass.com/l#x"
        assertEquals(link, launchLink(link, restored = false, fromHistory = false))
        assertNull(launchLink(link, restored = true, fromHistory = false), "restored after the process died")
        assertNull(launchLink(link, restored = false, fromHistory = true), "reopened from Recents")
        assertTrue(code("MainActivity.kt").contains("launchLink(intent?.dataString, restored = savedInstanceState != null"))
    }

    @Test
    fun theScannerRefusesSeparatorsAndTheHangulFiller() {
        for (cp in listOf(0x2028, 0x2029, 0x3164)) {
            assertNull(ScannedText.accept("https://andvaripass.com/l" + String(Character.toChars(cp)) + "x"), "U+%04X".format(cp))
        }
        assertEquals("https://andvaripass.com/l#ok", ScannedText.accept(" https://andvaripass.com/l#ok "))
    }

    @Test
    fun smallerPoints() {
        assertTrue(code("autofill/AppFillConfirmActivity.kt").contains("LayoutParams.FLAG_SECURE"), "the app-fill confirm is a secure window")
        assertTrue(code("autofill/CardFillConfirmActivity.kt").contains("LayoutParams.FLAG_SECURE"), "so is the card confirm")
        // Notes are not learned, and hold lines.
        assertTrue(code("trust/VaultItemsScreens.kt").contains("LinesField(UiText.ph(Placeholder.ITEM_NOTES), notes)"), "the notes field holds lines")
        assertEquals(androidx.compose.ui.text.input.KeyboardType.Password, io.silencelen.andvari.app.trust.notesKeyboard.keyboardType, "notes are not learned")
        assertEquals(false, io.silencelen.andvari.app.trust.notesKeyboard.autoCorrectEnabled)
        assertEquals(androidx.compose.ui.text.input.ImeAction.Default, io.silencelen.andvari.app.trust.notesKeyboard.imeAction, "Enter adds a line")
        val lines = code("trust/TrustUi.kt").substringAfter("internal fun LinesField(").substringBefore("\n}\n")
        assertTrue(lines.contains("singleLine = false") && lines.contains("keyboardOptions = notesKeyboard"))
        assertTrue(io.silencelen.andvari.app.trust.NOTES_MIN_LINES > 1)
        assertTrue(code("MainActivity.kt").contains("window.decorView.importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS"))
    }
}
