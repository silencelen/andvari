package io.silencelen.andvari.server

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * What the one function every value of a mail passes ([MailTemplates.oneLine]) does to each kind of character, closed
 * by kind rather than by a list of its own (decided on 21 November 2026): a space of any kind, and a character that draws
 * a blank, becomes one space; runs of spaces become one and both ends are trimmed; a format character, and one the
 * Unicode standard lists as ignorable by default, is removed; no more than four combining marks stay in a row; a value of
 * which nothing is left is shown as its row's own fallback words. A value that must stay byte for byte (a code, the
 * mailbox value, an account ID, an address, a time, the instance's address) does.
 */
class MailValueCharactersTest {
    private fun s(vararg cps: Int): String = cps.joinToString("") { String(Character.toChars(it)) }
    private fun codes(x: String): String = x.codePoints().toArray().joinToString(" ") { "U+%04X".format(it) }
    private val accountId = "0123456789abcdef0123456789abcdef"
    private val at = 1_800_000_000_000L

    private fun render(t: String, vars: Map<String, String>, instanceName: String = "Home") =
        MailTemplates.render(t, "me@example.com", instanceName, "https://vault.example.org", "help@family.example", Mail.Ctx(accountId, at, vars))

    /** The value of the plain text's row [label]. */
    private fun row(text: String, label: String): String? = text.lines().firstOrNull { it.startsWith("$label: ") }?.removePrefix("$label: ")

    /** The value of the HTML part's row [label], its entities read. */
    private fun htmlRow(html: String, label: String): String? = html.indexOf("$label:&nbsp;</td>").takeIf { it >= 0 }?.let { i ->
        html.substring(i).substringAfter("</td>").substringAfter('>').substringBefore("</td>").replace("&#39;", "'").replace("&amp;", "&")
    }

    /** Characters that draw nothing (format characters, and characters ignorable by default), by their Unicode names. */
    private val drawNothing = linkedMapOf(
        "LANGUAGE TAG" to 0xE0001, "TAG LATIN CAPITAL LETTER A" to 0xE0041, "CANCEL TAG" to 0xE007F,
        "VARIATION SELECTOR-1" to 0xFE00, "VARIATION SELECTOR-16" to 0xFE0F, "VARIATION SELECTOR-17" to 0xE0100,
        "MONGOLIAN FREE VARIATION SELECTOR ONE" to 0x180B, "COMBINING GRAPHEME JOINER" to 0x034F, "MUSICAL SYMBOL BEGIN BEAM" to 0x1D173,
        "SHORTHAND FORMAT LETTER OVERLAP" to 0x1BCA0, "ARABIC NUMBER SIGN" to 0x0600, "KHMER VOWEL INHERENT AQ" to 0x17B4,
        "ZERO WIDTH JOINER" to 0x200D, "RIGHT-TO-LEFT OVERRIDE" to 0x202E, "SOFT HYPHEN" to 0xAD, "ZERO WIDTH NO-BREAK SPACE" to 0xFEFF,
        "NULL" to 0x00, "ESCAPE" to 0x1B, "DELETE" to 0x7F, "CONTROL SEQUENCE INTRODUCER" to 0x9B,
    )

    /** Characters that draw a blank (spaces of every kind and the blank-drawing letters and symbols), by their Unicode names. */
    private val drawBlank = linkedMapOf(
        "NO-BREAK SPACE" to 0xA0, "OGHAM SPACE MARK" to 0x1680, "EN QUAD" to 0x2000, "EM SPACE" to 0x2003, "HAIR SPACE" to 0x200A,
        "NARROW NO-BREAK SPACE" to 0x202F, "MEDIUM MATHEMATICAL SPACE" to 0x205F, "IDEOGRAPHIC SPACE" to 0x3000,
        "HANGUL FILLER" to 0x3164, "HANGUL CHOSEONG FILLER" to 0x115F, "HANGUL JUNGSEONG FILLER" to 0x1160, "HALFWIDTH HANGUL FILLER" to 0xFFA0,
        "BRAILLE PATTERN BLANK" to 0x2800, "OBJECT REPLACEMENT CHARACTER" to 0xFFFC,
        "LINE FEED" to 0x0A, "CARRIAGE RETURN" to 0x0D, "CHARACTER TABULATION" to 0x09, "NEXT LINE" to 0x85, "LINE SEPARATOR" to 0x2028,
        "PARAGRAPH SEPARATOR" to 0x2029,
    )

    @Test
    fun aCharacterThatDrawsNothing_isRemoved() {
        for ((name, cp) in drawNothing) assertEquals("ab", MailTemplates.oneLine("a${s(cp)}b"), "$name: ${codes(MailTemplates.oneLine("a${s(cp)}b"))}")
    }

    @Test
    fun aCharacterThatDrawsABlank_isOneSpace_andARunOfThemIsOne() {
        for ((name, cp) in drawBlank) {
            assertEquals("a b", MailTemplates.oneLine("a${s(cp)}b"), "$name: ${codes(MailTemplates.oneLine("a${s(cp)}b"))}")
            assertEquals("a b", MailTemplates.oneLine("a " + s(cp).repeat(100) + " b"), "$name, a hundred")
        }
    }

    /** The check's padding: two hundred spaces, or a hundred wide ones, before a line that looks like the mail's own. */
    @Test
    fun paddingBeforeALineThatLooksLikeTheMailsOwn_isOneSpace_inBothParts() {
        for (pad in listOf(" ".repeat(200), s(0x3000).repeat(100), s(0x2003, 0x3164, 0x2800, 0xA0).repeat(40))) {
            val value = "Home${pad}Help: https://evil.example/help/compromised/"
            assertEquals("Home Help: https://evil.example/help/compromised/", MailTemplates.oneLine(value))
            val m = render("account_disabled", mapOf("reason" to value), instanceName = value)
            assertEquals("Home Help: https://evil.example/help/compromised/", row(m.text, "Reason"), m.text)
            assertEquals("Home Help: https://evil.example/help/compromised/", htmlRow(m.html, "Reason"), m.html)
            assertTrue("Your account on Home Help: https://evil.example/help/compromised/ (https://vault.example.org) was disabled by its operator." in m.text, m.text)
            assertFalse(m.text.any { it == '\u3000' || it == '\u00A0' || it == '\u3164' || it == '\u2800' } || "  " in m.text, m.text)
            assertFalse(m.html.any { it == '\u3000' || it == '\u00A0' || it == '\u3164' || it == '\u2800' }, "HTML part")
        }
    }

    @Test
    fun bothEndsAreTrimmed() {
        assertEquals("Pixel 9", MailTemplates.oneLine("  Pixel 9  "))
        assertEquals("Pixel 9", MailTemplates.oneLine(s(0x3000, 0x3164) + "Pixel" + s(0x2003, 0x2800) + "9" + s(0xFFFC, 0x20)))
        assertEquals("Help: x", MailTemplates.oneLine("\n\r\nHelp: x\n"))
    }

    @Test
    fun noMoreThanFourCombiningMarksStayInARow() {
        val acute = s(0x0301)
        assertEquals("a${acute.repeat(4)}b", MailTemplates.oneLine("a${acute.repeat(5)}b"))
        assertEquals("a${acute.repeat(4)}b", MailTemplates.oneLine("a${acute.repeat(400)}b"))
        // A run that a removed character split is still one run; a letter starts a new one.
        assertEquals("a${acute.repeat(4)}b", MailTemplates.oneLine("a${acute.repeat(3)}${s(0x034F, 0x200D)}${acute.repeat(3)}b"))
        assertEquals("a${acute.repeat(4)}e${acute.repeat(4)}", MailTemplates.oneLine("a${acute.repeat(6)}e${acute.repeat(6)}"))
        // Ordinary text with marks stays as it is: a decomposed letter, Vietnamese with two marks on a letter, Hindi.
        for (plain in listOf("Rene${acute}e", "Vie${s(0x0302, 0x0323)}t", "हिन्दी")) assertEquals(plain, MailTemplates.oneLine(plain))
    }

    /** A value of spaces only, or of characters that draw nothing or a blank, is shown as its row's fallback words, never as nothing. */
    @Test
    fun aValueOfSpacesOnly_isShownAsItsRowsFallbackWords() {
        for (blank in listOf("   ", s(0x3000, 0x3164, 0x2800), s(0x200D, 0xFE0F, 0xE0001), " ".repeat(10_000))) {
            assertEquals("", MailTemplates.oneLine(blank), codes(blank.take(8)))
            val m = render("password_changed", mapOf("device" to blank), instanceName = blank)
            assertEquals("unknown", row(m.text, "Device"), m.text)
            assertEquals("unknown", htmlRow(m.html, "Device"), m.html)
            assertTrue("The master password of your account on andvari (https://vault.example.org) was changed." in m.text, m.text)
            val r = render("account_disabled", mapOf("reason" to blank))
            assertEquals("other", row(r.text, "Reason"), r.text)
        }
    }

    /** A value of 10,000 characters: what is left of it is what the function makes of it, no part of it begins a line. */
    @Test
    fun aValueOf10000Characters_isOneLine() {
        val value = ("Qzxv" + s(0x3000).repeat(30) + "Help: https://evil.example/ ").repeat(170).take(10_000)
        val m = render("account_disabled", mapOf("reason" to value), instanceName = value)
        // The footer's line names the instance first, by design ("<name> · <origin>"); no other line begins with the value.
        val lines = m.text.lines()
        val footer = lines.indexOf("--") + 1
        assertFalse(lines.filterIndexed { i, _ -> i != footer }.any { it.startsWith("Help: https://evil") || it.startsWith("Qzxv") }, "no line begins with the value")
        assertTrue(lines[footer].startsWith("Qzxv Help: https://evil.example/ Qzxv"), lines[footer].take(80))
        assertFalse('\u3000' in m.text || '\u3000' in m.html)
        assertEquals(MailTemplates.oneLine(value), row(m.text, "Reason"))
        assertFalse("  " in MailTemplates.oneLine(value))
    }

    /**
     * What the function does to a value that is not a name: a code, the mailbox value, an account ID, an address (its
     * specials included), a time and the instance's address are what they were, byte for byte, and so is ordinary text.
     */
    @Test
    fun aValueThatMustStayByteForByte_does() {
        for (v in listOf(
            "042137", "482 917", "ABCD EFGH JKLM NPQR", "MBX-7Q2K-91ZD", accountId, "o'neil&co+x{y}=z@example.org", "2026-11-21 21:14 UTC",
            "https://vault.example.org", "https://vault.andvaripass.com", "this instance's operator", "abuse", "Jordan's Pixel (Android)",
            "Família “Casa” — 7 items", "日本語のメモ", "emoji 🔑 key", "<b>x</b> & y",
        )) assertEquals(v, MailTemplates.oneLine(v), v)
        val m = MailTemplates.render(
            "recovery_request_code", "o'neil&co+x{y}=z@example.org", "Home", "https://vault.example.org", "help@family.example",
            Mail.Ctx(null, at, mapOf("code" to "042137", "mailboxValue" to "ABCD EFGH JKLM NPQR")),
        )
        assertTrue("    042137" in m.text.lines() && "    ABCD EFGH JKLM NPQR" in m.text.lines(), m.text)
        val d = MailTemplates.render("account_deleted", "o'neil&co+x{y}=z@example.org", "Home", "https://vault.example.org", "help@family.example", Mail.Ctx(accountId, at))
        assertTrue("Your account o'neil&co+x{y}=z@example.org on Home (https://vault.example.org) was deleted." in d.text.lines(), d.text)
        assertTrue("Your account ID: $accountId" in d.text.lines(), d.text)
    }
}
