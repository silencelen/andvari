package io.silencelen.andvari.core.client

/**
 * Security review 2026-10, A14 (F12): one line of untrusted text, safe to print.
 *
 * The offline tools print strings that other people authored: item, attachment and vault names in
 * a backup (any co-member of a shared vault writes them, end-to-end encrypted, so the server cannot
 * filter them), and the userIds and dump text in an escrow drill (the server's data). A terminal
 * interprets control characters in that output — cursor movement and erase-line can overwrite the
 * FAIL rows a verify printed, OSC 52 writes the clipboard — so every such string goes through
 * [escape] before it is printed. The same class also drives backup-cli's file-name sanitizer.
 */
object TerminalText {
    /** C0 (tab, LF and CR included — a name is one line), DEL, C1 0x80–0x9F (0x9B is the one-byte
     *  CSI some terminals honour), and since the A14 review (Wc/N9) the line and paragraph separators
     *  U+2028/U+2029, which break a line in many renderers, and the bidi controls (U+061C, U+200E,
     *  U+200F, U+202A–U+202E, U+2066–U+2069), which reorder what follows them on screen. */
    fun isControl(c: Char): Boolean = c.code < 0x20 || c.code in 0x7F..0x9F || c.code in BIDI_AND_SEPARATORS

    private val BIDI_AND_SEPARATORS: Set<Int> =
        setOf(0x061C, 0x200E, 0x200F, 0x2028, 0x2029, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)

    /** Every [isControl] character as a visible `\u001B`-style escape; everything else verbatim.
     *  The form is JSON's own escape, so applying it inside a JSON string literal is lossless. */
    fun escape(s: String): String {
        if (s.none(::isControl)) return s
        val sb = StringBuilder(s.length + 16)
        for (c in s) {
            if (isControl(c)) sb.append("\\u").append(c.code.toString(16).uppercase().padStart(4, '0')) else sb.append(c)
        }
        return sb.toString()
    }
}
