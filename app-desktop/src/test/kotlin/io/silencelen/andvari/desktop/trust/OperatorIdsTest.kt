package io.silencelen.andvari.desktop.trust

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A request's values as recovery-cli assist needs them. In the first run a lowercase l in the request
 * key was read as the digit 1 and recovery-cli refused the code; the values were selectable only, and a selection of a
 * grouped value would carry its spaces into the command. Now: groups of four, every digit marked in three ways (bold,
 * underlined, coloured), and a copy control beside each value that copies it whole.
 */
class OperatorIdsTest {
    private val accent = Color(0xFF8B6914)

    @Test
    fun everyDigitIsMarkedAndNothingElseIsAndTheGroupsAreOfFour() {
        val v = "1i1ookve7Aq4UWJesGL9Zw"
        val shown = groupedValue(v, accent)
        assertEquals("1i1o okve 7Aq4 UWJe sGL9 Zw", shown.text)
        val marked = shown.spanStyles.flatMap { s -> (s.start until s.end).map { it to s.item } }.toMap()
        for ((i, c) in shown.text.withIndex()) {
            val style = marked[i]
            if (c in '0'..'9') {
                assertEquals(accent, style?.color, "digit $c at $i")
                assertEquals(FontWeight.Bold, style?.fontWeight)
                assertEquals(TextDecoration.Underline, style?.textDecoration)
            } else {
                assertEquals(null, style, "$c at $i is not marked")
            }
        }
        // A uuid keeps its own dashes and is not regrouped.
        val uuid = "55e39bb3-ab15-4441-a07a-c016ca964e9d"
        assertEquals(uuid, groupedValue(uuid, accent).text)
    }

    /**
     * The console offered the server's own account ID as something to copy into
     * `recovery-cli assist`, which then said "anchored". A request offers only its id and its key; no sentence tells the
     * operator to copy anything of the account.
     */
    @Test
    fun theServersAccountIdIsNeverOfferedToCopyOrCheckAgainst() {
        val r = io.silencelen.andvari.core.model.wire.AdminRecoveryRequest(
            "req-1", "user-1", "bo@run.example", "a".repeat(32), "k".repeat(43), "cli", 1L, 2L, 3L,
        )
        assertEquals(listOf("request" to "req-1", "request key" to "k".repeat(43)), requestValues(r))
        val screens = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
        assertFalse(screens.contains("r.accountId") || screens.contains("r.userId"), "neither id of the account is drawn")
        for (p in Placeholder.entries.filter { it.name.startsWith("OP_") }) {
            val g = p.gloss.lowercase()
            assertFalse(g.contains("account id") && g.contains("to copy"), p.name)
            assertFalse(g.contains("account's id as the server holds"), p.name)
        }
        assertTrue(Placeholder.OP_REQUEST_IDS.gloss.contains("comes from the person, never from the server"))
    }

    @Test
    fun eachValueHasACopyControlThatCopiesItWhole() {
        val screens = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
        val section = screens.substringAfter("private fun RequestRows(").substringBefore("\n}\n")
        assertTrue(section.contains("for ((what, value) in requestValues(r))"))
        assertTrue(section.contains("CopyableValue(op, r.requestId, what, value)"))
        assertFalse(section.contains("SelectionContainer"), "a selection of a grouped value would carry its spaces")
        val copyable = screens.substringAfter("private fun CopyableValue(").substringBefore("\n}\n")
        assertTrue(copyable.contains("clipboard.setText(AnnotatedString(value))"), "the value as the server holds it, not as shown")
        assertTrue(copyable.contains("Placeholder.OP_COPY"))
    }
}
