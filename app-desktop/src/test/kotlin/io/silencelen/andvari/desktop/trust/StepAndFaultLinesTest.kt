package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.model.wire.AdminPolicy
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Two faults in how lines were filled. The console's step for a change named the changed row by another row's gloss
 * (the sign-up mode by a choice's line), and the two "something went wrong" lines passed their values as one list, so
 * the owner's words could not be put in by count. Each slot now gets its own value, and a change names its own row.
 */
class StepAndFaultLinesTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")

    /** The policy the fake's console reads. */
    private fun policy(): AdminPolicy {
        val api = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)
        return assertNotNull(assertNotNull(api.operatorApi.console).policy)
    }

    @Test
    fun aChangeIsNamedByTheRowThePersonChangedAndEachSlotHasItsOwnValue() {
        val panel = body(src("OperatorScreens.kt"), "private fun PolicyInputs(")
        val before = policy()
        val after = before.copy(
            autoLockSeconds = before.autoLockSeconds + 1, clipboardClearSeconds = before.clipboardClearSeconds + 1, offlineCacheAllowed = !before.offlineCacheAllowed,
            signup = before.signup.copy(mode = if (before.signup.mode == "closed") "open" else "closed"),
        )
        val changes = policyChanges(before, after)
        assertTrue(changes.size >= 4, "$changes")
        for ((row, from, to) in changes) {
            // The row is one the policy panel itself shows as a label or a heading, never a choice's own line.
            assertTrue(panel.contains("UiText.ph(Placeholder.${row.name})") || panel.contains("Say(Placeholder.${row.name},"), "${row.name} is a row of the panel")
            val line = assertIs<UiText.Ph>(changeLine(row, from, to))
            assertEquals(Placeholder.OP_STEP_CHANGE, line.placeholder)
            assertEquals(3, line.args.size, "what, from, to: one slot each")
            assertEquals(listOf(from, to), line.args.drop(1))
            // The row's own words as shown, or, while it and the line both await words, its gloss inside the line's mark.
            assertTrue(line.args[0] == UiText.ph(row).shown() || line.args[0] == row.gloss, "${line.args}")
        }
        assertTrue(changes.any { it.first == Placeholder.OP_POLICY_SIGNUP }, "the sign-up mode is named by its row, sign-up")
        assertFalse(changes.any { it.first == Placeholder.OP_SIGNUP_MODE }, "never by one choice's line")
        val check = body(src("OperatorModel.kt"), "fun checkPolicy(")
        assertTrue(check.contains("StepLine(changeLine(what, from, to))") && !check.contains(".gloss"), check)
    }

    @Test
    fun theSomethingWentWrongLinesPassTheirValuesOneByOne() {
        val faulted = body(src("TrustModel.kt"), "fun faulted(")
        assertTrue(faulted.contains("UiText.ph(Placeholder.SOMETHING_WENT_WRONG_IN_VAULT, plainName(vault))"), faulted)
        assertTrue(faulted.contains("UiText.ph(Placeholder.SOMETHING_WENT_WRONG)"), faulted)
        assertFalse(faulted.contains("listOf("), "no list of values")
        // The kind of error still reaches the log, and only there.
        assertTrue(faulted.contains("\"something went wrong :: \$cls\""), faulted)
    }
}
