package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.TwoStepResult
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * A number before a noun that can be 1 has a line of its own for one (copy page, PQ17), and the wait after too many
 * two-step tries is said once, not after a sentence that says the same.
 */
class CountsOfOneTest {
    private fun ph(t: UiText?): UiText.Ph = assertIs<UiText.Ph>(t)

    /** Each line with a count before its noun, and its line for one. */
    private val pairs = listOf(
        Placeholder.TWO_STEP_WAIT to Placeholder.TWO_STEP_WAIT_ONE,
        Placeholder.TROUBLE_RATE_LIMITED to Placeholder.TROUBLE_RATE_LIMITED_ONE,
        Placeholder.HEALTH_REUSED to Placeholder.HEALTH_REUSED_ONE,
        Placeholder.HEALTH_BREACHED to Placeholder.HEALTH_BREACHED_ONE,
        Placeholder.POLICY_AUTO_LOCK to Placeholder.POLICY_AUTO_LOCK_ONE,
        Placeholder.POLICY_CLIPBOARD to Placeholder.POLICY_CLIPBOARD_ONE,
        Placeholder.DELETION_BLOCKER_SHARED to Placeholder.DELETION_BLOCKER_SHARED_ONE,
        Placeholder.DELETION_BLOCKER_SHARED_UNREADABLE to Placeholder.DELETION_BLOCKER_SHARED_UNREADABLE_ONE,
        Placeholder.LINK_KIND_CONNECT to Placeholder.LINK_KIND_CONNECT_ONE,
        Placeholder.LINK_KIND_INVITATION to Placeholder.LINK_KIND_INVITATION_ONE,
        Placeholder.DEVICE_LINK_TIME_LEFT to Placeholder.DEVICE_LINK_TIME_LEFT_ONE,
        Placeholder.MOVE_FINISHED_INTO to Placeholder.MOVE_FINISHED_INTO_ONE,
        Placeholder.ITEM_COPIED_NOTE to Placeholder.ITEM_COPIED_NOTE_ONE,
    )

    @Test
    fun theTwoStepWaitIsOneSentenceAndHasALineForOneSecond() {
        val shared = UiText.of(CopyKey.TWO_STEP_TOO_MANY_TRIES).shown()
        val wait = ph(twoStepWords(TwoStepResult.TOO_MANY_TRIES, 30))
        assertEquals(Placeholder.TWO_STEP_WAIT, wait.placeholder)
        assertEquals(listOf("30"), wait.args)
        assertFalse(wait.shown().contains(shared), "the shared code's sentence is not said before it: ${wait.shown()}")
        assertEquals(Placeholder.TWO_STEP_WAIT_ONE, ph(twoStepWords(TwoStepResult.TOO_MANY_TRIES, 1)).placeholder)
        assertEquals(shared, twoStepWords(TwoStepResult.TOO_MANY_TRIES, 0)?.shown(), "no wait known: the shared code's sentence alone")
    }

    @Test
    fun theServersWaitHasALineForOneSecond() {
        assertEquals(Placeholder.TROUBLE_RATE_LIMITED_ONE, ph(OutcomeWords.trouble(Trouble.RATE_LIMITED, 1)).placeholder)
        assertEquals(Placeholder.TROUBLE_RATE_LIMITED_ONE, ph(OutcomeWords.trouble(Trouble.RATE_LIMITED, 0)).placeholder, "an unknown wait is said as one second")
        val five = ph(OutcomeWords.trouble(Trouble.RATE_LIMITED, 5))
        assertEquals(Placeholder.TROUBLE_RATE_LIMITED, five.placeholder)
        assertEquals(listOf("5"), five.args)
    }

    @Test
    fun countedChoosesTheLineForOneAndPutsTheCountLastOtherwise() {
        for ((many, one) in pairs) {
            assertEquals(one, ph(counted(1, many, one, "x")).placeholder, many.name)
            assertEquals(listOf("x"), ph(counted(1, many, one, "x")).args, "the line for one carries its 1 in its words")
            assertEquals(many, ph(counted(2, many, one, "x")).placeholder, many.name)
            assertEquals(listOf("x", "2"), ph(counted(2, many, one, "x")).args)
            assertEquals(many, ph(counted(0, many, one)).placeholder, "none is not one")
        }
        assertEquals(Placeholder.DEVICE_LINK_TIME_LEFT_ONE, ph(deviceLinkTimeLeftLine(400)).placeholder, "under a second left rounds up to one")
    }

    /** Every place that shows one of these lines goes through [counted]: none is filled with a bare count any more. */
    @Test
    fun noPlaceFillsACountLineWithoutItsLineForOne() {
        val dir = File("src/main/kotlin/io/silencelen/andvari/app/trust")
        val code = dir.listFiles()!!.filter { it.name.endsWith(".kt") && it.name != "UiText.kt" }.joinToString("\n") { it.readText() }
        for ((many, _) in pairs) {
            assertFalse(code.contains("UiText.ph(Placeholder.${many.name},"), "${many.name} is filled without its line for one")
            assertTrue(code.contains("Placeholder.${many.name}, Placeholder.${many.name}_ONE"), "${many.name} goes through counted")
        }
    }
}
