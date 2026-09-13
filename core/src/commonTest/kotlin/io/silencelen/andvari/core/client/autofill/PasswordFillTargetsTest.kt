package io.silencelen.andvari.core.client.autofill

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit H21: Android broadcast the stored password into EVERY password-classified field, so a
 * login picked on a change-password page landed the OLD password in the new/confirm boxes. The
 * core helper implements the extension's `primary` rule (detect.ts: the first NON-new-password
 * field, else any) as a set, for Android's per-field fill. Pinned here the way the DatasetBuilder
 * pure helpers are (saveTrigger / loginDatasetCap): plain data, no platform types.
 */
class PasswordFillTargetsTest {
    private data class F(val id: String, val hints: List<String>)

    private fun targets(vararg fields: F) = FieldClassifier.passwordFillTargets(fields.toList()) { it.hints }.map { it.id }

    @Test
    fun hasNewPasswordHint_foldsEverySpellingClassifyAccepts() {
        // W3C token, Android View hint, and the underscore/camel variants classify() step 0 folds.
        assertTrue(FieldClassifier.hasNewPasswordHint(listOf("new-password")))
        assertTrue(FieldClassifier.hasNewPasswordHint(listOf("newPassword")))
        assertTrue(FieldClassifier.hasNewPasswordHint(listOf("NEW_PASSWORD")))
        assertTrue(FieldClassifier.hasNewPasswordHint(listOf("username", "new-password")))
        assertFalse(FieldClassifier.hasNewPasswordHint(listOf("password")))
        assertFalse(FieldClassifier.hasNewPasswordHint(listOf("current-password")))
        assertFalse(FieldClassifier.hasNewPasswordHint(emptyList()))
        // Still PASSWORD-classified — the fill-target rule is a second look, not a re-classification.
        assertEquals(FieldKind.PASSWORD, FieldClassifier.classify(FieldSignal(hints = listOf("new-password"))))
    }

    @Test
    fun changePasswordPage_fillsOnlyTheCurrentPasswordBox() {
        // GitHub/Google/Microsoft shape: current-password first, then new + confirm hinted new-password.
        val out = targets(
            F("current", listOf("current-password")),
            F("new", listOf("new-password")),
            F("confirm", listOf("new-password")),
        )
        assertEquals(listOf("current"), out)
    }

    @Test
    fun unhintedCurrentBesideHintedNew_stillFillsOnlyTheCurrent() {
        // The current box often carries no hint at all; the new one is what the site marks.
        assertEquals(listOf("pw"), targets(F("pw", emptyList()), F("new", listOf("newPassword"))))
    }

    @Test
    fun plainLoginForm_isUnchanged_everyPasswordFieldStaysATarget() {
        // No new-password hint anywhere ⇒ today's behaviour, including the odd two-box login.
        assertEquals(listOf("a"), targets(F("a", listOf("password"))))
        assertEquals(listOf("a", "b"), targets(F("a", emptyList()), F("b", listOf("password"))))
    }

    @Test
    fun pureSignupForm_everyFieldHintedNew_keepsTodaysBehaviour() {
        // The extension's `?? passwords[0]` arm: a member re-registering with a password they
        // already hold is not silently refused a fill.
        assertEquals(listOf("new", "confirm"), targets(F("new", listOf("new-password")), F("confirm", listOf("new-password"))))
    }

    @Test
    fun emptyInput_isEmptyOutput() {
        assertEquals(emptyList(), targets())
    }

    /** R19: the hint-keyed entry is the predicate-keyed rule with hasNewPasswordHint plugged in —
     *  Android's NewPasswordSignal delegates to the predicate form, so the two must agree. */
    @Test
    fun theHintEntryIsThePredicateRule() {
        val fields = listOf(F("current", listOf("current-password")), F("new", listOf("new-password")), F("confirm", listOf("new-password")))
        assertEquals(
            FieldClassifier.passwordFillTargets(fields) { it.hints },
            FieldClassifier.passwordFillTargetsBy(fields) { FieldClassifier.hasNewPasswordHint(it.hints) },
        )
        val allNew = listOf(F("a", listOf("new-password")), F("b", listOf("new-password")))
        assertEquals(allNew, FieldClassifier.passwordFillTargetsBy(allNew) { true })
        assertEquals(listOf(allNew[1]), FieldClassifier.passwordFillTargetsBy(allNew) { it.id == "a" })
    }
}
