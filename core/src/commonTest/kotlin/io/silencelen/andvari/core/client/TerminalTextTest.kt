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
        for (c in listOf(' ', '~', '\u00A0', '\u00E9', '\u200B', '\u200D', '\u4E2D')) assertFalse(TerminalText.isControl(c), "0x" + c.code.toString(16))
    }

    @Test
    fun lineSeparatorsAndBidiControlsAreControlsToo() {
        // A14 review Wc/N9: U+2028/U+2029 break a line in many renderers, and the bidi controls reorder what follows them,
        // so a label carrying one can push text onto a fake second line or make "gnp.exe" read as "exe.png".
        val extra = listOf(0x2028, 0x2029, 0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)
        for (c in extra) assertTrue(TerminalText.isControl(c.toChar()), "0x" + c.toString(16))
        assertEquals("gnp.\\u202Eexe", TerminalText.escape("gnp.\u202Eexe"))
        assertEquals("a\\u2028b\\u2029c", TerminalText.escape("a\u2028b\u2029c"))
        assertEquals("\\u2066x\\u2069 \\u200Fy\\u061C", TerminalText.escape("\u2066x\u2069 \u200Fy\u061C"))
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
        val all = buildString { for (c in 0..0x2FF) append(c.toChar()); for (c in 0x2000..0x206F) append(c.toChar()); append('\u061C') }
        val out = TerminalText.escape(all)
        assertTrue(out.none(TerminalText::isControl), out)
    }
}
