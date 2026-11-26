package io.silencelen.andvari.core.trust

/** A JSON value as [StrictJson] read it. */
internal sealed class JsonNode {
    /** An object's members in source order. A repeated name appears twice: the caller decides what that means. */
    class Obj(val members: List<Pair<String, JsonNode>>) : JsonNode() {
        /** The LAST member named [name], which is what `JSON.parse` keeps for a repeated name. */
        fun last(name: String): JsonNode? = members.lastOrNull { it.first == name }?.second

        val hasRepeatedName: Boolean get() = members.map { it.first }.toSet().size != members.size
    }

    class Arr(val items: List<JsonNode>) : JsonNode()

    /** A string's decoded [value]. [plainEscapes]: it used no escape other than `\"` and `\\`. */
    class Str(val value: String, val plainEscapes: Boolean) : JsonNode()

    /** A number as its exact source token (`2`, `2.0`, `-0`, `1e3`). */
    class Num(val token: String) : JsonNode()

    /** `true`, `false` or `null`. */
    class Lit(val token: String) : JsonNode()
}

/**
 * A JSON reader that accepts exactly the grammar of RFC 8259 and nothing else, for the two places where
 * this package takes JSON that is NOT a canonical statement: recognising a host-minted offer (design
 * 2026-11-15 §2.4 "Host JSON offer": "a JSON object with a string `purpose`") and the device-link
 * `outer` and bundle (§8.3, §2.4: compact JSON, keys in any order, no key twice).
 *
 * It exists because the platform parser is too generous to decide a verdict: kotlinx reads a bare token
 * such as `abc` or `NaN` as a value, where `JSON.parse` and the design's "a JSON object" do not. With
 * this reader the JVM, Android, iOS and the web twin (which uses `JSON.parse`) agree on what is JSON.
 */
internal object StrictJson {
    /**
     * How many objects and arrays may be open at once. The deepest value this package reads sits inside
     * three; the bound keeps the reader's recursion small on every target. The web twin applies the same
     * bound before `JSON.parse`, so both refuse the same texts.
     */
    const val MAX_DEPTH = 32

    /**
     * The value [text] holds, or null when [text] is not exactly one JSON value. With [compact] the
     * text must be COMPACT JSON (§2.4, device links): no white space outside strings, and a string
     * escapes only `"` and `\`. Together with the caller's checks (numbers in the `int` text form, no
     * repeated name) that accepts a text exactly when `JSON.stringify(JSON.parse(text)) === text`.
     */
    fun parse(text: String, compact: Boolean = false): JsonNode? {
        val reader = Reader(text, compact)
        return try {
            reader.skipSpace()
            val value = reader.value(0)
            reader.skipSpace()
            if (reader.atEnd()) value else null
        } catch (e: Malformed) {
            null
        }
    }

    private class Malformed : Exception()

    private class Reader(private val text: String, private val compact: Boolean) {
        private var pos = 0

        fun atEnd(): Boolean = pos == text.length

        fun skipSpace() {
            while (pos < text.length && (text[pos] == ' ' || text[pos] == '\t' || text[pos] == '\n' || text[pos] == '\r')) {
                if (compact) throw Malformed()
                pos++
            }
        }

        private fun peek(): Char = if (pos < text.length) text[pos] else throw Malformed()

        private fun expect(c: Char) {
            if (peek() != c) throw Malformed()
            pos++
        }

        /** [depth] is the number of containers already open around this value. */
        fun value(depth: Int): JsonNode {
            return when (val c = peek()) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> lit("true")
                'f' -> lit("false")
                'n' -> lit("null")
                else -> if (c == '-' || c in '0'..'9') num() else throw Malformed()
            }
        }

        private fun obj(depth: Int): JsonNode {
            if (depth >= MAX_DEPTH) throw Malformed()
            expect('{')
            val members = ArrayList<Pair<String, JsonNode>>()
            skipSpace()
            if (peek() == '}') {
                pos++
                return JsonNode.Obj(members)
            }
            while (true) {
                skipSpace()
                val name = str().value
                skipSpace()
                expect(':')
                skipSpace()
                members += name to value(depth + 1)
                skipSpace()
                when (peek()) {
                    ',' -> pos++
                    '}' -> {
                        pos++
                        return JsonNode.Obj(members)
                    }
                    else -> throw Malformed()
                }
            }
        }

        private fun arr(depth: Int): JsonNode {
            if (depth >= MAX_DEPTH) throw Malformed()
            expect('[')
            val items = ArrayList<JsonNode>()
            skipSpace()
            if (peek() == ']') {
                pos++
                return JsonNode.Arr(items)
            }
            while (true) {
                skipSpace()
                items += value(depth + 1)
                skipSpace()
                when (peek()) {
                    ',' -> pos++
                    ']' -> {
                        pos++
                        return JsonNode.Arr(items)
                    }
                    else -> throw Malformed()
                }
            }
        }

        private fun str(): JsonNode.Str {
            expect('"')
            val out = StringBuilder()
            var plain = true
            while (true) {
                val c = peek()
                pos++
                when {
                    c == '"' -> return JsonNode.Str(out.toString(), plain)
                    c.code < 0x20 -> throw Malformed() // a raw control character is never allowed in a string
                    c != '\\' -> out.append(c)
                    else -> {
                        val e = peek()
                        pos++
                        if (compact && e != '"' && e != '\\') throw Malformed()
                        when (e) {
                            '"' -> out.append('"')
                            '\\' -> out.append('\\')
                            '/' -> {
                                out.append('/')
                                plain = false
                            }
                            'b' -> {
                                out.append('\b')
                                plain = false
                            }
                            'f' -> {
                                out.append('\u000C')
                                plain = false
                            }
                            'n' -> {
                                out.append('\n')
                                plain = false
                            }
                            'r' -> {
                                out.append('\r')
                                plain = false
                            }
                            't' -> {
                                out.append('\t')
                                plain = false
                            }
                            'u' -> {
                                if (pos + 4 > text.length) throw Malformed()
                                var unit = 0
                                for (i in 0 until 4) {
                                    val h = text[pos + i]
                                    val d = when (h) {
                                        in '0'..'9' -> h - '0'
                                        in 'a'..'f' -> h - 'a' + 10
                                        in 'A'..'F' -> h - 'A' + 10
                                        else -> throw Malformed()
                                    }
                                    unit = unit * 16 + d
                                }
                                pos += 4
                                out.append(unit.toChar())
                                plain = false
                            }
                            else -> throw Malformed()
                        }
                    }
                }
            }
        }

        /** `number = [ "-" ] int [ frac ] [ exp ]`, `int = "0" / ( digit1-9 *DIGIT )`. */
        private fun num(): JsonNode {
            val start = pos
            if (peek() == '-') pos++
            when (peek()) {
                '0' -> pos++
                in '1'..'9' -> digits()
                else -> throw Malformed()
            }
            if (pos < text.length && text[pos] == '.') {
                pos++
                digits()
            }
            if (pos < text.length && (text[pos] == 'e' || text[pos] == 'E')) {
                pos++
                if (pos < text.length && (text[pos] == '+' || text[pos] == '-')) pos++
                digits()
            }
            return JsonNode.Num(text.substring(start, pos))
        }

        private fun digits() {
            val start = pos
            while (pos < text.length && text[pos] in '0'..'9') pos++
            if (pos == start) throw Malformed()
        }

        private fun lit(word: String): JsonNode {
            if (!text.startsWith(word, pos)) throw Malformed()
            pos += word.length
            return JsonNode.Lit(word)
        }
    }
}
