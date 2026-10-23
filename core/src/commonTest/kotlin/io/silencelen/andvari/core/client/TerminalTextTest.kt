package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10, A14 (F12): the one sanitizer for text from a decrypted backup or escrow
 * payload that the offline tools print. Co-members author item, attachment and vault names; the
 * server authors userIds and dumps. A terminal must see none of their control characters.
 */
class TerminalTextTest {
    @Test
    fun theControlClassIsC0DelAndC1() {
        for (c in 0x00..0x1F) assertTrue(TerminalText.isControl(c.toChar()), "C0 0x" + c.toString(16))
        assertTrue(TerminalText.isControl('\u007F'), "DEL")
        for (c in 0x80..0x9F) assertTrue(TerminalText.isControl(c.toChar()), "C1 0x" + c.toString(16))
        for (c in listOf(' ', '~', '\u00A0', '\u00E9', '\u2028', '\u4E2D')) assertFalse(TerminalText.isControl(c), "0x" + c.code.toString(16))
    }

    @Test
    fun everyControlBecomesAVisibleEscapeAndTheRestIsVerbatim() {
        assertEquals("GitHub", TerminalText.escape("GitHub"))
        assertEquals("\\u001B[2K\\u001B[1AOK", TerminalText.escape("\u001B[2K\u001B[1AOK"))
        assertEquals("\\u001B]52;c;aGk=\\u0007", TerminalText.escape("\u001B]52;c;aGk=\u0007"), "OSC 52 clipboard write")
        assertEquals("\\u009B2J", TerminalText.escape("\u009B2J"), "the one-byte C1 CSI")
        assertEquals("a\\u0009b\\u000Ac\\u000Dd", TerminalText.escape("a\tb\nc\rd"), "a name is one line: tab and newlines too")
        assertEquals("x\\u007Fy\\u0085z", TerminalText.escape("x\u007Fy\u0085z"))
        assertEquals("Café 中文 🔑", TerminalText.escape("Café 中文 🔑"), "printable text is untouched")
    }

    @Test
    fun noControlCharacterSurvives() {
        val all = buildString { for (c in 0..0x2FF) append(c.toChar()) }
        val out = TerminalText.escape(all)
        assertTrue(out.none(TerminalText::isControl), out)
    }
}
