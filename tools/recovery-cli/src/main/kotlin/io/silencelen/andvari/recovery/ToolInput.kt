package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.client.TerminalText
import java.io.ByteArrayOutputStream
import java.io.FileInputStream

/**
 * Everything the tool reads from outside, bounded (spec 04 §4, "The tool's inputs"): a file is read only up to its limit,
 * a typed or piped line only up to [LINE_MAX] characters, and a JSON file is refused when an object repeats a key or the
 * nesting goes deeper than [JSON_DEPTH_MAX]. All of it is decided before any seed is asked for, except the lines typed
 * after a seed, which are bounded the same way. Nothing here ever ends in a stack trace or an out-of-memory error: a file
 * over its limit is never read whole.
 */
internal object ToolInput {
    /** `--identity-file`: a recovery-copy download is four short fields. */
    const val IDENTITY_FILE_MAX = 1 shl 20

    /** `--instance-file`: the server's `GET /api/v1/instance` answer. */
    const val INSTANCE_FILE_MAX = 4 shl 20

    /** The fleet check's dump: one row per account. */
    const val DUMP_MAX = 64 shl 20

    /** The fleet check's seed file: one line of 43 characters. */
    const val SEED_FILE_MAX = 4096

    /** A line typed or piped on standard input: a seed or a confirmation. */
    const val LINE_MAX = 4096

    /** How deep a JSON file may nest; the deepest real one (the dump) nests two levels. */
    const val JSON_DEPTH_MAX = 32

    /** The most cards and rotations an instance file may carry (each is checked; rotations are rare). */
    const val CARDS_MAX = 4096
    const val ROTATIONS_MAX = 64

    /** A file is larger than the limit [cap]: it was not read whole. */
    class TooLarge(val cap: Int) : Exception("larger than ${size(cap)}")

    /** [cap] in words: "1 MiB", "4 KiB". */
    fun size(cap: Int): String = when {
        cap >= (1 shl 20) && cap % (1 shl 20) == 0 -> "${cap shr 20} MiB"
        cap >= 1024 && cap % 1024 == 0 -> "${cap shr 10} KiB"
        else -> "$cap bytes"
    }

    /** The file at [path], read up to [cap] bytes and never further: [TooLarge] when it holds more. */
    fun readFile(path: String, cap: Int): ByteArray = FileInputStream(path).use { s ->
        val out = ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        var total = 0
        while (true) {
            val n = s.read(buf, 0, minOf(buf.size, cap + 1 - total))
            if (n < 0) break
            total += n
            if (total > cap) throw TooLarge(cap)
            out.write(buf, 0, n)
        }
        out.toByteArray()
    }

    /** [bytes] as read by a caller that did not go through [readFile] (a test's own reader): the same limit. */
    fun within(bytes: ByteArray, cap: Int): ByteArray = if (bytes.size > cap) throw TooLarge(cap) else bytes

    private val stdin by lazy { System.`in`.bufferedReader(Charsets.UTF_8) }

    /**
     * One line of standard input without its line ending (LF or CR LF), or null at the end of the input. A line longer
     * than [LINE_MAX] is read to its end and kept only to [LINE_MAX] + 1 characters, so it fails the grammar of whatever was
     * asked (a seed, a confirmation) without ever being held whole.
     */
    fun stdinLine(): String? = lineFrom(stdin)

    /** [stdinLine] from [reader]. */
    fun lineFrom(reader: java.io.Reader): String? {
        val sb = StringBuilder()
        while (true) {
            val c = reader.read()
            if (c < 0) return if (sb.isEmpty()) null else sb.toString()
            if (c == '\n'.code) return if (sb.endsWith("\r")) sb.dropLast(1).toString() else sb.toString()
            if (sb.length <= LINE_MAX) sb.append(c.toChar())
        }
    }

    /**
     * What is wrong with [text] as one of the tool's JSON files, before it is parsed: an object that repeats a key (the
     * parser would keep the last one silently), nesting deeper than [JSON_DEPTH_MAX], or a string or structure that does
     * not end. Keys are compared after their escapes are decoded, so `"a"` and `"a"` are the same key. Null: nothing
     * found here (the parser still checks the rest).
     */
    fun jsonProblem(text: String): String? {
        val stack = ArrayList<HashSet<String>?>() // null: an array level
        var expectKey = false
        var i = 0
        while (i < text.length) {
            when (text[i]) {
                '{', '[' -> {
                    if (stack.size >= JSON_DEPTH_MAX) return "it nests deeper than $JSON_DEPTH_MAX levels"
                    val obj = text[i] == '{'
                    stack.add(if (obj) HashSet() else null)
                    expectKey = obj
                    i++
                }
                '}', ']' -> {
                    if (stack.isEmpty()) return NOT_JSON
                    stack.removeAt(stack.size - 1)
                    expectKey = false
                    i++
                }
                ',' -> { expectKey = stack.isNotEmpty() && stack[stack.size - 1] != null; i++ }
                ':' -> { expectKey = false; i++ }
                '"' -> {
                    val sb = StringBuilder()
                    i++
                    while (true) {
                        if (i >= text.length) return NOT_JSON
                        val d = text[i]
                        if (d == '"') { i++; break }
                        if (d != '\\') { sb.append(d); i++; continue }
                        if (i + 1 >= text.length) return NOT_JSON
                        when (val e = text[i + 1]) {
                            '"', '\\', '/' -> sb.append(e)
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000c')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                val hex = text.substring(i + 2, minOf(i + 6, text.length))
                                if (hex.length != 4 || !hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return NOT_JSON
                                sb.append(hex.toInt(16).toChar())
                                i += 4
                            }
                            else -> return NOT_JSON
                        }
                        i += 2
                    }
                    if (expectKey) {
                        val keys = stack.lastOrNull() ?: return NOT_JSON
                        if (!keys.add(sb.toString())) return "an object in it gives the key \"${TerminalText.escape(sb.toString().take(40))}\" twice"
                        expectKey = false
                    }
                }
                else -> i++
            }
        }
        return if (stack.isEmpty()) null else NOT_JSON
    }

    private const val NOT_JSON = "it is not JSON"
}
