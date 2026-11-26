package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultUnlockResult
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * A server that did not answer, where the shared code hands no sentence for the result: the desktop says that the server
 * did not answer, in a line of its own, never the line without wording. Every result said in place comes through
 * [UiText.forResult], so this one branch holds for every screen.
 */
class ServerSilenceLineTest {
    @Test
    fun everyResultOfAServerThatDidNotAnswerWithoutASentenceIsSaidAsTheServersSilence() {
        val results: List<IntentResult> = (
            VaultUnlockResult.entries + PlainResult.entries + OperatorResult.entries + DigitsResult.entries + SignInAnswer.entries
        ).filter { it.trouble == Trouble.UNREACHABLE && it.sentence == null }
        assertTrue(VaultUnlockResult.UNREACHABLE in results && OperatorResult.UNREACHABLE in results, "$results")
        for (r in results) {
            assertEquals(Placeholder.TROUBLE_UNREACHABLE, assertIs<UiText.Ph>(UiText.forResult(r, 0)).placeholder, "$r")
        }
        // The line without wording is made in one place only, the branch for the other troubles.
        val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/").listFiles()!!.filter { it.name.endsWith(".kt") }.joinToString("\n") { it.readText() }
        assertEquals(1, Regex("""Placeholder\.TROUBLE\b(?!_)""").findAll(src).count(), "made only in UiText.forResult (the plain one; a wait has its own line)")
    }
}
