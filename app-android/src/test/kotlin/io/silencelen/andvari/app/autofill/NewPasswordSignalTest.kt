package io.silencelen.andvari.app.autofill

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H04 / H21 — the new-password distinction the classifier discards, restored at
 * the two seams that need it. `AssistStructure` / `Dataset` cannot be built in a JVM unit test,
 * so both rules are pure ([NewPasswordSignal]) and pinned here (the DatasetBuilderCapTest idiom);
 * this is their only red-when-reverted coverage.
 *
 * The defect these exist for: on a real change-password form (current / new / confirm, the
 * current one first and hinted `current-password`) Android SAVED the current password — so the
 * vault silently kept the old one after every change — and FILLED the stored password into the
 * new and confirm boxes. Extension twin: `detect.ts` `isNewPassword`.
 */
class NewPasswordSignalTest {

    private data class F(val name: String, val new: Boolean)

    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-android/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    /** Comment-stripped source (HealthSurfaceTest idiom): the rules are documented in the code they pin. */
    private fun code(relative: String): String = sourceFile(relative).readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    // ---- R10: the production CALL SITES (a pure test stays green when the seam stops calling it) ----

    /** SaveExtractor decides the password over the valued set, and its per-node loop no longer
     *  captures first-wins — reverting either half re-opens H04. */
    @Test
    fun saveExtractorCapturesThroughTheSignalAndNeverFirstWins() {
        val se = code("src/main/kotlin/io/silencelen/andvari/app/autofill/SaveExtractor.kt")
        val extract = se.substringAfter("fun extract(").substringBefore("\n    }\n")
        assertTrue(extract.contains("NewPasswordSignal.capturePassword("), "extract() must decide the password through the signal")
        assertTrue(extract.contains("kinds[i] == FieldKind.PASSWORD && n.value != null"), "…over the form's VALUED password fields")
        assertTrue(extract.contains("FieldKind.PASSWORD -> {}"), "the per-node loop must be a no-op for passwords (decided above)")
        assertFalse(extract.contains("FieldKind.PASSWORD -> if (password == null)"), "first-wins capture is THE BUG")
    }

    /** DatasetBuilder fills only the fillable set, and no other password filter survives outside
     *  the one helper (and saveInfoFor, which counts fields rather than filling them). */
    @Test
    fun datasetBuilderFillsOnlyTheFillablePasswordFields() {
        val db = code("src/main/kotlin/io/silencelen/andvari/app/autofill/DatasetBuilder.kt")
        assertTrue(
            db.contains("private fun fillPasswordFields(form: ParsedForm): List<ParsedField> =\n        NewPasswordSignal.fillablePasswordFields(form.fields.filter { it.kind == FieldKind.PASSWORD }) { it.isNewPassword }"),
            "the ONE password-target helper must go through the signal",
        )
        assertTrue(db.contains("fillPasswordFields(form).filter { UriMatch.matchLogins(login.uris, targetFor(it, form, trusted)) }"), "the dataset's passFields come from the helper")
        assertTrue(db.contains("val fillable = fillPasswordFields(form)"), "the inline-presentation leg reads the same set")
        val filters = Regex("form\\.fields\\.filter \\{ it\\.kind == FieldKind\\.PASSWORD \\}").findAll(db).count()
        assertEquals(2, filters, "exactly two raw password filters: fillPasswordFields (the source) and saveInfoFor (a count, not a fill)")
    }

    /** R19: ONE home for the rule — the Android object delegates to core's FieldClassifier
     *  (hasNewPasswordHint / passwordFillTargetsBy) instead of carrying a second normalizer. */
    @Test
    fun theSignalDelegatesToCoresFieldClassifier() {
        val nps = code("src/main/kotlin/io/silencelen/andvari/app/autofill/NewPasswordSignal.kt")
        assertTrue(nps.contains("if (FieldClassifier.hasNewPasswordHint(hints)) return true"))
        assertTrue(nps.contains("FieldClassifier.hasNewPasswordHint(listOf(it))"), "the raw-attribute belt uses the same normalizer per token")
        assertTrue(nps.contains("FieldClassifier.passwordFillTargetsBy(passwords, isNew)"))
        assertFalse(nps.contains("private fun normalize("), "no second normalizer on Android")
    }

    // ---- the signal ----

    @Test
    fun theHintCountsInEverySpellingTheClassifierNormalizes() {
        // FieldClassifier.classify step 0: lowercase, strip "_" and "-" — the same three spellings.
        for (hint in listOf("newPassword", "new-password", "new_password", "NEW-PASSWORD")) {
            assertTrue(NewPasswordSignal.isNewPassword(listOf(hint), null), hint)
        }
    }

    @Test
    fun theCurrentPasswordHintAndPlainPasswordAreNotNew() {
        assertFalse(NewPasswordSignal.isNewPassword(listOf("current-password"), null))
        assertFalse(NewPasswordSignal.isNewPassword(listOf("password"), null))
        assertFalse(NewPasswordSignal.isNewPassword(emptyList(), null))
    }

    /** Chrome maps `autocomplete` into hints, but a structure that only carries the raw attribute
     *  must read the same — and only as a whole token, never as a substring. */
    @Test
    fun theRawAutocompleteAttributeIsABeltAndMatchesWholeTokensOnly() {
        assertTrue(NewPasswordSignal.isNewPassword(emptyList(), "section-blue new-password"))
        assertFalse(NewPasswordSignal.isNewPassword(emptyList(), "renew-password"))
        assertFalse(NewPasswordSignal.isNewPassword(emptyList(), "current-password"))
    }

    // ---- H04: what a SAVE captures ----

    /** THE BUG: current first (hinted), new second — the capture must be the NEW value. */
    @Test
    fun aHintedChangePasswordFormCapturesTheNewPassword() {
        val fields = listOf(F("current", false), F("new", true), F("confirm", true))
        assertEquals(F("new", true), NewPasswordSignal.capturePassword(fields) { it.new })
    }

    /** The verifier's addition: a hintless three-password form is the same shape without the
     *  hint, and its NEW value sits second — first-wins would again capture the old one. */
    @Test
    fun aHintlessThreePasswordFormCapturesTheSecondField() {
        val fields = listOf(F("current", false), F("new", false), F("confirm", false))
        assertEquals(F("new", false), NewPasswordSignal.capturePassword(fields) { it.new })
    }

    /** Unchanged shapes: a login form, and a signup password + confirm pair (both the same value). */
    @Test
    fun loginAndSignupPairsKeepFirstWins() {
        assertEquals(F("pw", false), NewPasswordSignal.capturePassword(listOf(F("pw", false))) { it.new })
        assertEquals(F("new", true), NewPasswordSignal.capturePassword(listOf(F("new", true), F("confirm", true))) { it.new })
        assertEquals(F("a", false), NewPasswordSignal.capturePassword(listOf(F("a", false), F("b", false))) { it.new })
    }

    @Test
    fun noPasswordFieldCapturesNothing() {
        assertNull(NewPasswordSignal.capturePassword(emptyList<F>()) { it.new })
    }

    // ---- H21: what a FILL writes into ----

    /** THE BUG: the stored password must land in the current box ONLY, never in new/confirm. */
    @Test
    fun aChangePasswordFormFillsOnlyTheCurrentPasswordField() {
        val fields = listOf(F("current", false), F("new", true), F("confirm", true))
        assertEquals(listOf(F("current", false)), NewPasswordSignal.fillablePasswordFields(fields) { it.new })
    }

    /** A bare signup form (every password field hinted new) keeps today's behaviour: all filled. */
    @Test
    fun anAllNewSignupFormStillFillsEveryPasswordField() {
        val fields = listOf(F("new", true), F("confirm", true))
        assertEquals(fields, NewPasswordSignal.fillablePasswordFields(fields) { it.new })
    }

    @Test
    fun aPlainLoginFormIsUntouched() {
        val fields = listOf(F("pw", false))
        assertEquals(fields, NewPasswordSignal.fillablePasswordFields(fields) { it.new })
    }
}
