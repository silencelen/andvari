package io.silencelen.andvari.cli

import java.io.PrintStream

/**
 * Text that did not start in this tool, made harmless before a terminal shows it. A server chooses
 * most of what the tool prints: addresses, names, device names and platforms, error codes, audit rows, ids; other people
 * choose names and items through it. None of that may steer the terminal or forge a line of the tool's own.
 */
object Shown {
    /**
     * True for a code point that must never reach a terminal as itself: every control character (C0, DEL and C1, which
     * include the line feed, the carriage return, the tab, the escape that starts a terminal sequence and the 8-bit CSI),
     * the line and paragraph separators, every format character (Unicode `Cf`: the direction overrides, embeddings,
     * isolates and marks, the zero-width space, joiners and no-break space, the word joiner and invisible operators,
     * the byte order mark, the soft hyphen, the interlinear annotation marks, the tag characters), the invisible Hangul
     * fillers, and any lone surrogate.
     */
    fun harmful(cp: Int): Boolean = when {
        cp < 0x20 || cp in 0x7F..0x9F -> true
        cp == 0x2028 || cp == 0x2029 -> true
        cp == 0x115F || cp == 0x1160 || cp == 0x3164 || cp == 0xFFA0 -> true
        cp in 0xD800..0xDFFF -> true
        else -> Character.getType(cp) == Character.FORMAT.toInt()
    }

    /**
     * THE function every printed line goes through ([Term]): [s] with each [harmful] code point written out as an
     * escape, `\n`, `\r` and `\t` for those three and `\u{XXXX}` (hexadecimal, at least four digits) for every other one.
     * One call's result is one line, and it holds nothing a terminal acts on. A backslash already in [s] is left as it
     * is, so a server's text can look like an escape, but never be one.
     */
    fun text(s: String): String {
        var i = 0
        var clean = true
        while (i < s.length) {
            val cp = s.codePointAt(i)
            if (harmful(cp)) { clean = false; break }
            i += Character.charCount(cp)
        }
        if (clean) return s
        val b = StringBuilder(s.length + 16)
        i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            if (harmful(cp)) {
                when (cp) {
                    0x0A -> b.append("\\n")
                    0x0D -> b.append("\\r")
                    0x09 -> b.append("\\t")
                    else -> b.append("\\u{").append(Integer.toHexString(cp).uppercase().padStart(4, '0')).append('}')
                }
            } else b.appendCodePoint(cp)
            i += Character.charCount(cp)
        }
        return b.toString()
    }

    /** The characters a value may hold and still be pasted into a POSIX shell as one word, unquoted. */
    private fun shellSafe(c: Char): Boolean =
        c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '@' || c == '.' || c == '-' || c == '_' || c == '+' || c == '/' || c == ':' || c == '=' || c == ','

    /**
     * [s] as one word a POSIX shell reads back exactly, for a value the person may paste into a command: as it is when every
     * character is plain ([shellSafe]); otherwise in single quotes, each `'` written `'\''`. An address may hold a
     * backtick, `$`, `|` or `&` (they are legal in its local part), and a server's id or name anything at all: printed
     * bare beside a command, such a value would run as part of it. The sink ([Term]) still escapes what is [harmful].
     */
    fun arg(s: String): String = if (s.isNotEmpty() && s.all(::shellSafe)) s else "'" + s.replace("'", "'\\''") + "'"

    /**
     * A JSON document's text with every [harmful] code point but the line feed (which a pretty-printed document's own
     * layout uses, and which an encoder never leaves raw inside a string) written as the JSON escape `\uXXXX` (a code
     * point past U+FFFF as its two surrogate escapes). Outside strings a JSON text holds only ASCII punctuation, digits,
     * letters and spaces, so every code point changed here sits inside a string, and the document means exactly what it
     * meant: a script reads the same values, and a terminal shows nothing it acts on.
     */
    fun json(text: String): String {
        val b = StringBuilder(text.length + 16)
        var i = 0
        while (i < text.length) {
            val cp = text.codePointAt(i)
            if (cp != 0x0A && harmful(cp)) {
                for (unit in String(Character.toChars(cp))) b.append("\\u").append(Integer.toHexString(unit.code).padStart(4, '0'))
            } else b.appendCodePoint(cp)
            i += Character.charCount(cp)
        }
        return b.toString()
    }
}

/**
 * The tool's only way to the terminal: standard output ([say], [json]) for the command's result, standard error ([note],
 * [prompt]) for everything else, and the console for what must be typed. Every line goes through [Shown.text] (a JSON
 * document through [Shown.json]), so no string a server sent can reach the terminal as itself, wherever a command puts
 * it. `TerminalSinkTest` reads the shipped classes and pins that nothing else prints.
 */
class Term(private val stdout: PrintStream) {
    /** One line of the command's result. */
    fun say(line: String) = stdout.println(Shown.text(line))

    /** One JSON document (`--json`), as one or more lines of standard output. */
    fun json(document: String) = stdout.println(Shown.json(document))

    fun flush() = stdout.flush()

    companion object {
        /** Where the result goes when the caller names nothing else. */
        fun standardOutput(): PrintStream = System.out

        /** One line on standard error (read at each call: a test may have replaced it). */
        fun note(line: String) = System.err.println(Shown.text(line))

        /** A prompt on standard error, with no line end. */
        fun prompt(text: String) {
            System.err.print(Shown.text(text))
            System.err.flush()
        }

        /** The console, or null when no terminal is attached. */
        fun console(): java.io.Console? = System.console()

        /** One line typed at the console after [prompt], or null at its end. */
        fun readLine(console: java.io.Console, prompt: String): String? = console.readLine("%s", Shown.text(prompt))

        /** A secret typed at the console after [prompt] without echo, or null at its end. */
        fun readPassword(console: java.io.Console, prompt: String): CharArray? = console.readPassword("%s", Shown.text(prompt))

        /** One line on the console itself, never on standard output (what a script must not capture: the kit's words). */
        fun console(console: java.io.Console, line: String) {
            console.printf("%s%n", Shown.text(line))
            console.flush()
        }

        /** The stack trace of [e] (`ANDVARI_CLI_DEBUG=1`), line by line through [note]: its messages may hold a server's words. */
        fun trace(e: Throwable) = e.stackTraceToString().lines().filter { it.isNotEmpty() }.forEach(::note)
    }
}
