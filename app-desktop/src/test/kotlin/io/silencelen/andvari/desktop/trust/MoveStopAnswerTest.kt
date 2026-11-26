package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.MoveEverythingScreen
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeScript
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Every answer a move's stop can carry (every value of [VaultActionResult]), and what the window draws under the stop's
 * shared line for it: its sentence, a line of the desktop's own, its trouble, the line without wording that names it,
 * or nothing. Nothing is drawn for exactly one answer at a stop, READ_ONLY under the line that the old vault is frozen
 * on this device, because that line says it; and for DONE, which is never drawn as a refusal. An answer the shared code
 * adds later has no row in [under] and turns this test red until it is given its line here: it never disappears.
 */
class MoveStopAnswerTest {
    /** What is drawn under the stop's shared line. */
    private enum class Under { NOTHING, SENTENCE, OWN_LINE, TROUBLE, WITHOUT_WORDING }

    /** Under the shared line of an ordinary stop ([CopyKey.MOVE_STOPPED]). */
    private val under: Map<VaultActionResult, Under> = mapOf(
        VaultActionResult.DONE to Under.NOTHING,
        VaultActionResult.SENT_PENDING to Under.OWN_LINE,
        VaultActionResult.NEEDS_UNCOMPARED_WARNING to Under.WITHOUT_WORDING,
        VaultActionResult.NOT_OWNER to Under.WITHOUT_WORDING,
        VaultActionResult.NOT_ALLOWED to Under.WITHOUT_WORDING,
        VaultActionResult.READ_ONLY to Under.WITHOUT_WORDING,
        VaultActionResult.CHANGED_MEANWHILE to Under.WITHOUT_WORDING,
        VaultActionResult.CLOCK_AHEAD to Under.SENTENCE,
        VaultActionResult.OFFER_EXPIRED to Under.WITHOUT_WORDING,
        VaultActionResult.NOT_CONNECTED to Under.WITHOUT_WORDING,
        VaultActionResult.NOT_A_CONTACT_HERE to Under.WITHOUT_WORDING,
        VaultActionResult.MEMBER_LIMIT to Under.WITHOUT_WORDING,
        VaultActionResult.OUT_OF_SPACE to Under.SENTENCE,
        VaultActionResult.MOVE_DELETE_WAITING to Under.SENTENCE,
        VaultActionResult.REMOVING_COPY to Under.SENTENCE,
        VaultActionResult.OTHER_CHANGE_WAITS to Under.SENTENCE,
        VaultActionResult.STALE to Under.TROUBLE,
        VaultActionResult.UNREACHABLE to Under.TROUBLE,
        VaultActionResult.RATE_LIMITED to Under.TROUBLE,
        VaultActionResult.UPDATE_REQUIRED to Under.TROUBLE,
        VaultActionResult.FAILED to Under.TROUBLE,
    )

    /** The answers the shared line of a stop at a frozen old vault says itself, so that nothing is drawn under it. */
    private val saidByTheFrozenLine = setOf(VaultActionResult.READ_ONLY)

    private fun model(api: FakeDesktopAppApi) = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })

    /** A real stop of the stand-in: short of space (an ordinary stop), or the old vault found frozen at its deletion. */
    private fun stoppedScreen(frozen: Boolean): MoveEverythingScreen {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = model(api)
        if (frozen) api.script.nextMoveStop = FakeScript.MoveStopAt.OLD_VAULT_FROZEN_AT_RESEND else api.script.noSpaceForVaults = true
        m.run({ vaults.openMoveEverything(assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }) })
        m.run({ vaults.moveEverything(assertNotNull(api.snapshot.account?.moving), "Family 2") })
        val screen = assertNotNull(api.snapshot.account?.moving)
        assertNotNull(screen.stopped)
        return screen
    }

    private fun withAnswer(screen: MoveEverythingScreen, result: VaultActionResult): MoveEverythingScreen =
        rebuilt(screen, "stopped" to rebuilt(assertNotNull(screen.stopped), "result" to result))

    /** The trouble's own line on the desktop: the wait, the update, the server's silence, or the general trouble naming the answer. */
    private fun troubleLine(trouble: Trouble): Placeholder = when (trouble) {
        Trouble.RATE_LIMITED -> Placeholder.TROUBLE_TOO_MANY
        Trouble.UPDATE_REQUIRED -> Placeholder.UPDATE_REQUIRED
        Trouble.UNREACHABLE -> Placeholder.TROUBLE_UNREACHABLE
        else -> Placeholder.TROUBLE
    }

    /** Asserts what [lines] (the stop's step, its shared line, then what is drawn under it) draws for [result]. */
    private fun assertUnder(where: String, result: VaultActionResult, expected: Under, lines: List<UiText>) {
        val drawn = lines.drop(2)
        println("STOP|$where|${result.name}|$expected|${drawn.joinToString(" / ") { it.shown() }.ifEmpty { "(nothing)" }}")
        if (expected == Under.NOTHING) {
            assertTrue(drawn.isEmpty(), "$where, ${result.name}: nothing under the shared line, drew $drawn")
            return
        }
        assertEquals(1, drawn.size, "$where, ${result.name}: one line under the shared line")
        val line = drawn.single()
        when (expected) {
            Under.SENTENCE -> assertEquals(UiText.of(assertNotNull(result.sentence)).shown(), line.shown(), "$where, ${result.name}")
            Under.OWN_LINE -> {
                assertTrue(result.sentence == null && result.trouble == null, "$where, ${result.name}: a line of the desktop's own only where the shared code hands none")
                assertIs<UiText.Plain>(line, "$where, ${result.name}: an approved line, never a placeholder without wording")
                assertTrue(line.shown().isNotBlank())
            }
            Under.TROUBLE -> {
                val trouble = assertNotNull(result.trouble, "$where, ${result.name}")
                assertEquals(troubleLine(trouble), assertIs<UiText.Ph>(line, "$where, ${result.name}").placeholder, "$where, ${result.name}")
            }
            Under.WITHOUT_WORDING -> {
                assertTrue(result.sentence == null && result.trouble == null, "$where, ${result.name}")
                val ph = assertIs<UiText.Ph>(line, "$where, ${result.name}")
                assertEquals(Placeholder.REFUSAL, ph.placeholder, "$where, ${result.name}")
                assertTrue(line.shown().contains("VaultActionResult.${result.name}"), "$where: it names the answer, ${line.shown()}")
            }
            Under.NOTHING -> error("handled above")
        }
    }

    @Test
    fun everyAnswerHasItsRowHereSoThatOneAddedLaterIsGivenALineBeforeThisPasses() {
        assertEquals(
            VaultActionResult.entries.toSet(), under.keys,
            "an answer of the shared code without a row here: give it its line at a move's stop, then its row",
        )
    }

    @Test
    fun underAnOrdinaryStopEveryAnswerButDoneIsDrawn() {
        val screen = stoppedScreen(frozen = false)
        assertEquals(CopyKey.MOVE_STOPPED, screen.stopped?.line)
        for (result in VaultActionResult.entries) {
            val expected = assertNotNull(under[result], "no row for ${result.name}")
            val at = withAnswer(screen, result)
            assertFalse(saidByTheStopLine(assertNotNull(at.stopped)), "${result.name} under the ordinary line")
            assertUnder("ordinary", result, expected, moveStopLines(at, 120))
        }
    }

    @Test
    fun underTheFrozenOldVaultsLineOnlyReadOnlyIsLeftToThatLine() {
        val screen = stoppedScreen(frozen = true)
        assertEquals(CopyKey.MOVE_OLD_VAULT_FROZEN, screen.stopped?.line)
        assertEquals(VaultActionResult.READ_ONLY, screen.stopped?.result, "the stand-in's own stop at a frozen old vault")
        val hidden = HashSet<VaultActionResult>()
        for (result in VaultActionResult.entries) {
            val at = withAnswer(screen, result)
            if (saidByTheStopLine(assertNotNull(at.stopped))) hidden += result
            val expected = if (result in saidByTheFrozenLine) Under.NOTHING else assertNotNull(under[result], "no row for ${result.name}")
            assertUnder("frozen", result, expected, moveStopLines(at, 120))
        }
        assertEquals(saidByTheFrozenLine, hidden, "exactly the answers the frozen line says itself")
    }

    @Test
    fun theWindowDrawsTheStopsLinesAndNothingElseOfItsAnswer() {
        val view = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultScreens.kt").readText()
            .substringAfter("private fun MoveEverythingView(").substringBefore("\n}\n")
        assertTrue(view.contains("for (line in moveStopLines(screen, model.api.retryAfterSeconds())) Say(line"))
        assertFalse(view.contains("stopped?.result") || view.contains("stop.result"), "the answer is drawn through moveStopLines only")
    }
}
