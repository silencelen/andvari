package io.silencelen.andvari.app.autofill

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * "Save to andvari?" was offered and then discarded the login, because the
 * save confirm ran on the old code and found no session in this install. A response carries a `SaveInfo` only while
 * saving runs on the new code (it does now: [AutofillSave] queues the capture) and the session takes saves.
 */
class NoSaveOfferTest {
    private fun code(name: String): String = File("src/main/kotlin/io/silencelen/andvari/app/autofill/$name").readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    @Test
    fun saveIsOfferedOnlyWhereTheSessionTakesSavesAndTheLoginCouldFill() {
        assertTrue(DatasetBuilder.SAVING_RUNS_ON_NEW_CODE)
        // A native app, or a trusted browser, while the session takes saves.
        assertTrue(DatasetBuilder.offersSave("com.example.app", trusted = false, sessionTakes = true))
        assertTrue(DatasetBuilder.offersSave("com.android.chrome", trusted = true, sessionTakes = true))
        // An untrusted known browser: a saved web login could never fill there.
        assertFalse(DatasetBuilder.offersSave("com.android.chrome", trusted = false, sessionTakes = true))
        assertFalse(DatasetBuilder.offersSave("org.mozilla.firefox", trusted = false, sessionTakes = true))
        // Never while the session takes no saves (signed out, a copy the server signed out, a stopped server).
        for (pkg in listOf("com.example.app", "com.android.chrome", "org.mozilla.firefox")) {
            for (trusted in listOf(false, true)) assertFalse(DatasetBuilder.offersSave(pkg, trusted, sessionTakes = false), "$pkg trusted=$trusted")
        }
    }

    @Test
    fun everySaveInfoInTheFillPathIsBehindTheRule() {
        val db = code("DatasetBuilder.kt")
        val svc = code("AndvariAutofillService.kt")
        val sets = Regex("setSaveInfo\\(").findAll(db).count() + Regex("setSaveInfo\\(").findAll(svc).count()
        assertEquals(3, sets, "the unlocked response, its no-match fallback and the locked row")
        assertEquals(2, Regex("if \\(offerSave\\) saveInfoFor\\(form\\)").findAll(db).count())
        assertTrue(db.contains("val offerSave = offersSave(form.appPackage, trusted, AutofillSave.takesSaves(context), isWebPage(form))"))
        assertTrue(svc.contains("if (DatasetBuilder.offersSave(form.appPackage, trusted, AutofillSave.takesSaves(this), DatasetBuilder.isWebPage(form))) DatasetBuilder.saveInfoFor(form)"))
    }
}
