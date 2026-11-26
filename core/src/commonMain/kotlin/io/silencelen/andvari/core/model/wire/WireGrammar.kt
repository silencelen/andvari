package io.silencelen.andvari.core.model.wire

import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The value grammar the wire's strict decoders need (spec 01 §5.1 and design §2.2): `uuid`, `hex64`,
 * `b64_16`, `b64_32`, `int`/`ms`, `origin` and `emailNorm`. Total functions: false or null on any
 * malformed input, never a throw.
 *
 * The value checks delegate to the shared verifiers' [TrustGrammar], the one grammar for frames and the wire; this
 * object adds only what JSON decoding needs (typed JSON numbers and strings, exact key sets, repeated keys).
 */
object WireGrammar {
    /** `2^53`: every `int` and `ms` is below it (design §2.2). */
    const val INT_LIMIT: Long = TrustGrammar.INT_CEILING

    /** Canonical lowercase UUID text (spec 05 R18). Delegates to the shared verifiers' [TrustGrammar], the one grammar. */
    fun isUuid(s: String): Boolean = TrustGrammar.isUuid(s)

    /** 64 lowercase hex characters. */
    fun isHex64(s: String): Boolean = TrustGrammar.isHex64(s)

    /** `hex64`, or the literal `none`. */
    fun isHex64n(s: String): Boolean = TrustGrammar.isHex64n(s)

    fun isB64_16(s: String): Boolean = TrustGrammar.isB64_16(s)
    fun isB64_32(s: String): Boolean = TrustGrammar.isB64_32(s)

    /** The `name` type (design §2.2): base64url of 1..64 UTF-8 bytes with the refused code points excluded. */
    fun isName(s: String): Boolean = TrustGrammar.isName(s)

    /** A JSON number in the `int` grammar: `0` or `[1-9][0-9]*`, below 2^53. Not a string, not a fraction. */
    fun intOf(e: JsonElement?): Long? {
        val p = e as? JsonPrimitive ?: return null
        if (p.isString) return null
        val t = p.content
        if (t.isEmpty() || t.length > 16) return null
        if (t != "0" && (t[0] !in '1'..'9' || t.any { it !in '0'..'9' })) return null
        val v = t.toLongOrNull() ?: return null
        return if (v in 0 until INT_LIMIT) v else null
    }

    /** A JSON string, or null when the element is anything else. */
    fun stringOf(e: JsonElement?): String? {
        val p = e as? JsonPrimitive ?: return null
        return if (p.isString) p.content else null
    }

    /** The `origin` grammar (design §2.2, §2.4): the shared verifiers' [TrustGrammar.isOrigin], the single source. */
    fun isOrigin(s: String): Boolean = TrustGrammar.isOrigin(s)

    /** `emailNorm` (spec 03 §0.3, design §2.4): the shared verifiers' [TrustGrammar.emailNorm]; null means `invalid_email`. */
    fun emailNorm(typed: String): String? = TrustGrammar.emailNorm(typed)

    /** True when [s] is already an `emailNorm` (a normalised address re-normalises to itself). */
    fun isEmailNorm(s: String): Boolean = emailNorm(s) == s

    /** True when [obj] has exactly the key set [keys]. */
    fun hasExactKeys(obj: JsonObject, keys: Set<String>): Boolean = obj.keys == keys

    /**
     * True when [text] is compact JSON as design §2.4 defines it for the device-link `outer` and bundle: no
     * white space outside strings, and inside strings no control character and no escape but `\"` and
     * `\\`. With escapes this narrow, a key has one spelling, so [noDuplicateKeys] compares exactly.
     */
    fun isCompactJson(text: String): Boolean {
        var inString = false
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (inString) {
                when {
                    c == '\\' -> { if (i + 1 >= text.length || (text[i + 1] != '"' && text[i + 1] != '\\')) return false; i += 2; continue }
                    c == '"' -> inString = false
                    c.code < 0x20 -> return false
                }
            } else {
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') return false
                if (c == '"') inString = true
            }
            i++
        }
        return !inString
    }

    /**
     * True when no JSON object anywhere in [text] repeats a key. `kotlinx.serialization` keeps the last of
     * two equal keys silently, which a strict "exactly these keys" decoder must not allow. Assumes [text]
     * is otherwise well-formed JSON (the caller parses it as well); returns false on what it cannot follow.
     */
    fun noDuplicateKeys(text: String): Boolean {
        val stack = ArrayList<MutableSet<String>?>() // null entry = an array level
        var i = 0
        var expectKey = false
        while (i < text.length) {
            when (val c = text[i]) {
                '{' -> { stack.add(HashSet()); expectKey = true; i++ }
                '[' -> { stack.add(null); expectKey = false; i++ }
                '}', ']' -> { if (stack.isEmpty()) return false; stack.removeAt(stack.size - 1); expectKey = false; i++ }
                ',' -> { expectKey = stack.lastOrNull() != null; i++ }
                ':' -> { expectKey = false; i++ }
                '"' -> {
                    val sb = StringBuilder()
                    i++
                    while (true) {
                        if (i >= text.length) return false
                        val d = text[i]
                        if (d == '\\') {
                            if (i + 1 >= text.length) return false
                            sb.append(d).append(text[i + 1]); i += 2; continue
                        }
                        if (d == '"') { i++; break }
                        sb.append(d); i++
                    }
                    if (expectKey) {
                        val keys = stack.lastOrNull() ?: return false
                        if (!keys.add(sb.toString())) return false
                        expectKey = false
                    }
                }
                else -> { if (c == '\\') return false; i++ }
            }
        }
        return stack.isEmpty()
    }
}
